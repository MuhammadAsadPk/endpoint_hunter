# -*- coding: utf-8 -*-
#
# endpoint_hunter.py
# ---------------------------------------------------------------------------
# Created by asad0x0  (Tech6 Solutions)
# ---------------------------------------------------------------------------
# Burp Suite extension that PASSIVELY harvests path-like API endpoints and
# GraphQL operation names from JavaScript (and optionally HTML) responses that
# flow through Burp. It is the Burp-native port of the endpoint_extractor.py
# CLI recon tool: same PATH regex, HTTP-method guessing, parameter-name
# detection and GraphQL-op extraction, but fed by live proxy traffic instead
# of files/URLs fetched with `requests`.
#
# What it does
#   - Watches in-scope responses (Proxy by default; all tools optional).
#   - For every JS response (and HTML, if enabled) it extracts:
#       * path-like endpoints        e.g. /api/v1/users/{id}
#       * best-effort HTTP method    e.g. [POST] from xhr.open("POST", ...)
#       * nearby parameter names     e.g. (params: id, token)
#       * GraphQL operation names    e.g. query GetUser / mutation Login
#   - Deduplicates across the whole session.
#   - Shows results in two tables (Endpoints / GraphQL) in a suite tab.
#   - Right-click any endpoint -> craft a request to it and Send to Repeater.
#   - Right-click an HTML item in Proxy/history -> actively fetch & scan all
#     linked <script src> files from that page (the CLI's --crawl).
#   - Export to CSV or a flat Burp-friendly URL list.
#
# Compatibility: Burp Suite (legacy extender API), Jython 2.7 (Python 2 only
# -- no f-strings, use % formatting).
# ---------------------------------------------------------------------------

import sys
import re
import time
import threading
import Queue
import urlparse

# --- Burp API ---------------------------------------------------------------
from burp import IBurpExtender
from burp import IHttpListener
from burp import IContextMenuFactory
from burp import IExtensionStateListener
from burp import ITab

# --- Java / Swing -----------------------------------------------------------
from java.io import PrintWriter, File
from java.net import URL as JURL
from java.awt import BorderLayout, GridLayout, FlowLayout, Font, Color
from java.awt import Toolkit
from java.awt.datatransfer import StringSelection
from java.awt.event import MouseAdapter, ActionListener
from java.util import ArrayList, Comparator

from javax.swing import (JPanel, JScrollPane, JTable, JCheckBox, JTextField,
                         JLabel, JButton, JSplitPane, JTextArea, JPopupMenu,
                         JMenuItem, JFileChooser, SwingUtilities, BorderFactory,
                         JTabbedPane, ListSelectionModel)
from javax.swing.table import AbstractTableModel, TableRowSorter


# ===========================================================================
#  Regex patterns + heuristics  (ported verbatim from endpoint_extractor.py)
# ===========================================================================

# Path-like endpoints wrapped in a JS string literal: "/api/v1/users/{id}",
# '/graphql', `/api/download.php?tempFilePath=` (query strings included).
PATH_REGEX = re.compile(
    r"""
    (?:["'`])
    (
        /(?!/)                                   # single leading slash
        [A-Za-z0-9_\-./{}\[\]:%$#@?&=+,;~]*       # allowed chars incl. querystring
        (?:[A-Za-z0-9_\-\}]|=|&)                  # must not end on a bare slash
    )
    (?:["'`])
    """,
    re.VERBOSE,
)

# GraphQL query/mutation/subscription operation names.
GRAPHQL_REGEX = re.compile(
    r"""\b(query|mutation|subscription)\s+([A-Za-z0-9_]+)\s*[({]""",
    re.IGNORECASE,
)

# --- HTTP method detection heuristics ---
# Case A: name("/path", ...) where the function name hints the method
METHOD_FROM_CALL_NAME_REGEX = re.compile(r"""([A-Za-z_$][A-Za-z0-9_$.]*)\s*\(\s*$""")
# Case B: xhr.open("POST", "/path" ...) -> method literal precedes the path
METHOD_FROM_OPEN_REGEX = re.compile(
    r"""\.open\s*\(\s*["'`](GET|POST|PUT|PATCH|DELETE|HEAD|OPTIONS)["'`]\s*,\s*$""",
    re.IGNORECASE,
)
# Case C: fetch(url, {method: "POST"}) / $.ajax({method:"POST"})
METHOD_FROM_KEY_REGEX = re.compile(
    r"""method\s*[:=]\s*["'`](GET|POST|PUT|PATCH|DELETE|HEAD|OPTIONS)["'`]""",
    re.IGNORECASE,
)
METHOD_NAME_HINTS = ("post", "get", "put", "patch", "delete", "head", "options")


def guess_http_method(text, match_start, back_window=60, fwd_window=200):
    """Best-effort guess of the HTTP method for a path literal at match_start."""
    back_ctx = text[max(0, match_start - back_window):match_start]
    fwd_ctx = text[match_start:match_start + fwd_window]

    m = METHOD_FROM_OPEN_REGEX.search(back_ctx)       # xhr.open("METHOD", "<path>")
    if m:
        return m.group(1).upper()

    m = METHOD_FROM_CALL_NAME_REGEX.search(back_ctx)  # someName("<path>", ...)
    if m:
        fname = m.group(1).lower()
        for hint in METHOD_NAME_HINTS:
            if hint in fname:
                return hint.upper()
        if "axios" in fname and fname.endswith((".get", ".post", ".put",
                                                 ".patch", ".delete")):
            return fname.rsplit(".", 1)[-1].upper()

    m = METHOD_FROM_KEY_REGEX.search(fwd_ctx)          # method: "X" shortly after
    if m:
        return m.group(1).upper()
    return None


# --- Parameter name detection ---
PARAM_KEY_BLOCKLIST = set([
    "method", "headers", "mode", "credentials", "cache", "redirect",
    "referrer", "referrerpolicy", "integrity", "keepalive", "signal",
    "type", "url", "endpoint", "path", "contenttype", "async", "timeout",
    "datatype", "processdata", "success", "error", "complete",
    "beforesend", "xhrfields", "responsetype", "body",
])
KEY_REGEX = re.compile(r"""["']?([A-Za-z_$][A-Za-z0-9_$]*)["']?\s*:""")


def extract_params_near(text, match_end, window=400):
    """Pull top-level key names from the first {...} object after a path literal."""
    fwd_ctx = text[match_end:match_end + window]

    brace_start = None
    for i, ch in enumerate(fwd_ctx):
        if ch == "{":
            brace_start = i
            break
        if ch == ";":        # left the call's argument list before any '{'
            return None
    if brace_start is None:
        return None

    depth = 0
    brace_end = None
    for i in range(brace_start, len(fwd_ctx)):
        if fwd_ctx[i] == "{":
            depth += 1
        elif fwd_ctx[i] == "}":
            depth -= 1
            if depth == 0:
                brace_end = i
                break
    if brace_end is None:
        return None

    block = fwd_ctx[brace_start:brace_end + 1]
    keys, seen = [], set()
    for m in KEY_REGEX.finditer(block):
        key = m.group(1)
        if key.lower() in PARAM_KEY_BLOCKLIST:
            continue
        if key not in seen:
            seen.add(key)
            keys.append(key)
    return keys if keys else None


# --- Noise filtering ---
NOISE_PATTERNS = [
    re.compile(r"^\s*$"),
    re.compile(r"^/\*"),
    re.compile(r"\.(png|jpe?g|gif|svg|woff2?|ttf|eot|css|map)(\?|$)", re.IGNORECASE),
    re.compile(r"^//"),
    re.compile(r"^/\$\{"),
    re.compile(r"^\s*[<>]"),
]
EXTENSIONS_TO_SKIP_AS_STATIC = (".png", ".jpg", ".jpeg", ".gif", ".svg", ".css",
                                 ".woff", ".woff2", ".ttf", ".eot", ".map", ".ico")


def is_noise(candidate):
    if len(candidate) < 2:
        return True
    if candidate.lower().endswith(EXTENSIONS_TO_SKIP_AS_STATIC):
        return True
    for pat in NOISE_PATTERNS:
        if pat.search(candidate):
            return True
    if candidate.count("/") == 0:
        return True
    return False


# --- Secrets / sensitive-data patterns (scanned in the same JS/HTML/JSON bodies) ---
SECRET_PATTERNS = [
    ("AWS Access Key",       re.compile(r"\b(AKIA|ASIA|AGPA|AIDA|AROA)[A-Z0-9]{16}\b")),
    ("AWS Secret Key",       re.compile(r"""(?i)aws.{0,20}?(secret|private).{0,20}?["'`]([A-Za-z0-9/+=]{40})["'`]""")),
    ("Google API Key",       re.compile(r"\bAIza[0-9A-Za-z\-_]{35}\b")),
    ("Google OAuth",         re.compile(r"\b[0-9]+-[0-9A-Za-z_]{32}\.apps\.googleusercontent\.com\b")),
    ("Stripe Live Key",      re.compile(r"\b(sk|rk)_live_[0-9A-Za-z]{10,}\b")),
    ("Stripe Pub Key",       re.compile(r"\bpk_live_[0-9A-Za-z]{10,}\b")),
    ("GitHub Token",         re.compile(r"\b(ghp|gho|ghu|ghs|ghr|github_pat)_[0-9A-Za-z_]{20,}\b")),
    ("Slack Token",          re.compile(r"\bxox[baprs]-[0-9A-Za-z\-]{10,}\b")),
    ("Slack Webhook",        re.compile(r"https://hooks\.slack\.com/services/[A-Za-z0-9/]+")),
    ("Twilio SID",           re.compile(r"\bAC[0-9a-fA-F]{32}\b")),
    ("SendGrid Key",         re.compile(r"\bSG\.[0-9A-Za-z\-_]{22}\.[0-9A-Za-z\-_]{43}\b")),
    ("Mailgun Key",          re.compile(r"\bkey-[0-9a-f]{32}\b")),
    ("Firebase DB",          re.compile(r"https://[a-z0-9\-]+\.firebaseio\.com")),
    ("S3 Bucket",            re.compile(r"\b[a-z0-9.\-]+\.s3[.\-][a-z0-9\-]*\.amazonaws\.com\b")),
    ("Private Key Block",    re.compile(r"-----BEGIN (?:RSA |EC |DSA |OPENSSH |PGP )?PRIVATE KEY-----")),
    ("JWT",                  re.compile(r"\beyJ[A-Za-z0-9_\-]{10,}\.[A-Za-z0-9_\-]{10,}\.[A-Za-z0-9_\-]{10,}\b")),
    ("Authorization Hdr",    re.compile(r"""(?i)authorization["'`]?\s*[:=]\s*["'`](bearer|basic)\s+[A-Za-z0-9+/=._\-]{8,}["'`]""")),
    ("Generic API Key",      re.compile(r"""(?i)\b(api[_-]?key|apikey|client[_-]?secret|access[_-]?token|auth[_-]?token)\b["'`]?\s*[:=]\s*["'`]([A-Za-z0-9_\-]{16,})["'`]""")),
    ("Private IP",           re.compile(r"\b(?:10|127|192\.168|172\.(?:1[6-9]|2[0-9]|3[01]))(?:\.\d{1,3}){2,3}\b")),
]
# tokens that mean the "match" is almost certainly a placeholder, not a real secret
SECRET_NOISE = ("xxxx", "0000", "example", "your_", "placeholder", "<", "dummy",
                "test_", "sample", "changeme", "null", "undefined")


def extract_secrets(text):
    """Return a set of (kind, matched_snippet) secrets found in one text blob."""
    found = set()
    if not text:
        return found
    for kind, pat in SECRET_PATTERNS:
        for m in pat.finditer(text):
            snippet = m.group(0).strip()
            if len(snippet) > 120:
                snippet = snippet[:117] + "..."
            low = snippet.lower()
            if any(n in low for n in SECRET_NOISE):
                continue
            found.add((kind, snippet))
    return found


def extract_from_text(text, want_graphql=True, want_method=True, want_params=True,
                      want_secrets=True):
    """
    Return structured results for one blob of JS/HTML text:
        {"paths": set of (method_or_None, path, params_csv),
         "gql":   set of (optype, name),
         "secrets": set of (kind, snippet)}
    """
    paths = set()
    for m in PATH_REGEX.finditer(text):
        candidate = m.group(1).strip()
        if is_noise(candidate):
            continue
        method = guess_http_method(text, m.start()) if want_method else None
        params = extract_params_near(text, m.end()) if want_params else None
        params_csv = ", ".join(params) if params else ""
        paths.add((method, candidate, params_csv))

    gql = set()
    if want_graphql:
        for m in GRAPHQL_REGEX.finditer(text):
            gql.add((m.group(1).lower(), m.group(2)))

    secrets = extract_secrets(text) if want_secrets else set()

    return {"paths": paths, "gql": gql, "secrets": secrets}


# --- Login / auth-wall detection (keeps dual-probe from false-flagging) ---
LOGIN_HINTS = re.compile(
    r"(?i)(please\s+log\s*in|sign\s*in|signin|log\s*in|login[_-]?form|"
    r"j_username|j_password|name=[\"']password[\"']|"
    r"\"error\"\s*:\s*\"(unauthorized|forbidden|not\s*authenticated|login)|"
    r"window\.location[^;]{0,40}(login|signin|auth)|"
    r"<form[^>]*(login|signin|auth))")


def looks_like_login(body, ctype):
    """True if a 200 body is really a login wall / auth redirect, not real data."""
    if not body:
        return False
    head = body[:6000]
    if LOGIN_HINTS.search(head):
        return True
    return False


def find_script_srcs(html, base_url):
    """Absolute URLs of every <script src> in an HTML page."""
    srcs = re.findall(r'<script[^>]+src=["\']([^"\']+)["\']', html, re.IGNORECASE)
    return [urlparse.urljoin(base_url, s) for s in srcs]


# href / src / action attributes -> crawlable links (for the active spider)
LINK_REGEX = re.compile(r"""(?:href|src|action)\s*=\s*["']([^"']+)["']""",
                        re.IGNORECASE)


def extract_links(html, base_url):
    """Absolute, crawlable URLs from an HTML page (skips mailto/js/anchors)."""
    out = []
    for raw in LINK_REGEX.findall(html):
        raw = raw.strip()
        if not raw:
            continue
        low = raw.lower()
        if low.startswith(("javascript:", "mailto:", "tel:", "data:", "#")):
            continue
        out.append(urlparse.urljoin(base_url, raw))
    return out


# ===========================================================================
#  Config
# ===========================================================================
class Config(object):
    def __init__(self):
        self.enabled = True
        self.scan_js = True             # scan application/javascript responses
        self.scan_html = True           # also scan text/html bodies (inline JS, hrefs)
        self.in_scope_only = True       # ignore out-of-scope responses
        self.all_tools = False          # False = Proxy only; True = every tool
        self.guess_method = True        # [GET]/[POST] prefixes
        self.detect_params = True       # (params: ...) annotations
        self.extract_graphql = True     # GraphQL op names
        self.extract_secrets = True     # scan bodies for keys/tokens/secrets
        self.highlight = True           # highlight source items in history
        self.enable_logging = True
        self.base_url = ""              # override base for full-URL resolution;
                                        # empty = resolve against source host
        self.max_scan_mb = 15           # skip bodies larger than this (safety)
        self.max_threads = 2            # regex workers
        # --- active crawler ---
        self.crawl_max_depth = 3        # link-hops from the seed
        self.crawl_max_pages = 300      # hard cap on pages fetched
        self.crawl_delay_ms = 150       # politeness delay between fetches
        self.crawl_same_host_only = True
        self.crawl_threads = 3
        self.extra_headers = {}         # Cookie/custom headers for crawl fetches
        # --- status / auth probing ---
        self.auto_check = True          # auto-probe every new endpoint (default ON)
        self.auth_headers = {}          # Cookie/headers for the AUTHENTICATED probe
        self.probe_delay_ms = 120       # delay between probe requests
        self.soft404_calibrate = True   # baseline a junk path per host -> kill FPs
        self.soft404_tolerance = 0.03   # size within 3% of baseline == soft-404


# ===========================================================================
#  Utilities
# ===========================================================================
class Utilities(object):
    def __init__(self, helpers):
        self._helpers = helpers

    def now(self):
        return time.strftime("%H:%M:%S")

    def response_body_str(self, response):
        if response is None:
            return ""
        info = self._helpers.analyzeResponse(response)
        return self._helpers.bytesToString(response)[info.getBodyOffset():]

    def response_content_type(self, response):
        try:
            info = self._helpers.analyzeResponse(response)
            for h in info.getHeaders():
                if h.lower().startswith("content-type:"):
                    return h.split(":", 1)[1].strip().lower()
            return (info.getStatedMimeType() or "").lower()
        except Exception:
            return ""

    def copy_to_clipboard(self, text):
        try:
            Toolkit.getDefaultToolkit().getSystemClipboard().setContents(
                StringSelection(text), None)
        except Exception:
            pass


# ===========================================================================
#  Logger
# ===========================================================================
class Logger(object):
    def __init__(self, stdout_writer, config):
        self._out = stdout_writer
        self._cfg = config
        self._ui = None

    def attach_ui(self, ui):
        self._ui = ui

    def _emit(self, text):
        try:
            self._out.println(text)
        except Exception:
            pass
        if self._ui is not None:
            self._ui.append_log(text)

    def info(self, text):
        if self._cfg.enable_logging:
            self._emit("[*] " + text)

    def found(self, source, n_paths, n_gql):
        if self._cfg.enable_logging:
            self._emit("[+] %s  ->  %d endpoint(s), %d graphql op(s)"
                       % (source, n_paths, n_gql))

    def error(self, where, exc_info=None):
        self._emit("[!] Error in %s: %s" % (where, exc_info[1] if exc_info else "?"))


# ===========================================================================
#  Table model (generic: cells for display + payload object for actions)
# ===========================================================================
class GridModel(AbstractTableModel):
    def __init__(self, columns):
        self._columns = columns
        self._rows = []       # list of [cell, cell, ...]
        self._payload = []    # parallel list of arbitrary objects

    def getRowCount(self):
        return len(self._rows)

    def getColumnCount(self):
        return len(self._columns)

    def getColumnName(self, col):
        return self._columns[col]

    def getValueAt(self, row, col):
        return self._rows[row][col]

    def isCellEditable(self, row, col):
        return False

    def add_row(self, cells, payload=None):
        self._rows.append(cells)
        self._payload.append(payload)
        idx = len(self._rows) - 1
        self.fireTableRowsInserted(idx, idx)

    def set_cell(self, row, col, value):
        if 0 <= row < len(self._rows):
            self._rows[row][col] = value
            def _fire():
                self.fireTableCellUpdated(row, col)
            SwingUtilities.invokeLater(_fire)

    def payload_at(self, idx):
        return self._payload[idx] if 0 <= idx < len(self._payload) else None

    def row_of_payload(self, payload):
        for i, p in enumerate(self._payload):
            if p is payload:
                return i
        return -1

    def cells_at(self, idx):
        return self._rows[idx]

    def all_cells(self):
        return list(self._rows)

    def clear(self):
        self._rows = []
        self._payload = []
        self.fireTableDataChanged()


class EndpointPayload(object):
    """Everything needed to craft a Repeater request for an endpoint."""
    def __init__(self, method, path, params, source, full_url):
        self.method = method
        self.path = path
        self.params = params
        self.source = source
        self.full_url = full_url


# ===========================================================================
#  ExtensionUI  (ITab)
# ===========================================================================
class ExtensionUI(ITab):

    EP_COLS = ["Time", "Method", "Path", "Params", "Full URL", "Source (JS)",
               "NA-Status", "NA-CType", "NA-Size",
               "A-Status", "A-CType", "A-Size", "Flag"]
    GQL_COLS = ["Time", "Type", "Operation", "Source (JS)"]
    SEC_COLS = ["Time", "Type", "Match", "Source (JS)"]
    # column indices: NA = no-auth probe, A = authenticated probe
    COL_NA_STATUS = 6
    COL_NA_CTYPE = 7
    COL_NA_SIZE = 8
    COL_A_STATUS = 9
    COL_A_CTYPE = 10
    COL_A_SIZE = 11
    COL_FLAG = 12

    def __init__(self, callbacks, helpers, config, utils, logger):
        self._callbacks = callbacks
        self._helpers = helpers
        self._cfg = config
        self._utils = utils
        self._logger = logger
        self.model_ep = GridModel(self.EP_COLS)
        self.model_gql = GridModel(self.GQL_COLS)
        self.model_sec = GridModel(self.SEC_COLS)
        self._repeater_counter = 0
        self._count_sources = 0
        self._status_queue = Queue.Queue()
        self._status_running = True
        self._baseline = {}             # host -> soft-404 baseline probe result
        self._baseline_lock = threading.Lock()
        self._build()
        self._start_status_worker()

    # ---- background auto-probe worker (default ON) ----
    def _start_status_worker(self):
        def loop():
            while self._status_running:
                try:
                    payload = self._status_queue.get(True, 1.0)
                except Queue.Empty:
                    continue
                try:
                    if payload is not None:
                        self._probe_and_fill(payload)
                except Exception:
                    self._logger.error("status worker", sys.exc_info())
                finally:
                    self._status_queue.task_done()
                if self._cfg.probe_delay_ms > 0:
                    time.sleep(self._cfg.probe_delay_ms / 1000.0)
        t = threading.Thread(target=loop, name="ephunter-autostatus")
        t.setDaemon(True)
        t.start()

    def stop_status_worker(self):
        self._status_running = False

    # ---- ITab ----
    def getTabCaption(self):
        return "Endpoint Hunter"

    def getUiComponent(self):
        return self._root

    # ---- build ----
    def _build(self):
        self._root = JPanel(BorderLayout())

        settings = self._build_settings()

        self.table_ep, ep_scroll = self._make_table(self.model_ep, url_col=4)
        self.table_gql, gql_scroll = self._make_table(self.model_gql, url_col=None)
        self.table_sec, sec_scroll = self._make_table(self.model_sec, url_col=None)

        self.tabs = JTabbedPane()
        self.tabs.addTab("Endpoints", ep_scroll)
        self.tabs.addTab("GraphQL", gql_scroll)
        self.tabs.addTab("Secrets", sec_scroll)

        self.log_area = JTextArea()
        self.log_area.setEditable(False)
        self.log_area.setFont(Font("Monospaced", Font.PLAIN, 12))
        log_scroll = JScrollPane(self.log_area)

        split = JSplitPane(JSplitPane.VERTICAL_SPLIT, self.tabs, log_scroll)
        split.setResizeWeight(0.75)

        north = JPanel(BorderLayout())
        north.add(settings, BorderLayout.CENTER)
        north.add(self._build_crawl_bar(), BorderLayout.SOUTH)

        self._root.add(north, BorderLayout.NORTH)
        self._root.add(split, BorderLayout.CENTER)
        self._root.add(self._build_statusbar(), BorderLayout.SOUTH)

    def _make_table(self, model, url_col):
        table = JTable(model)
        table.setSelectionMode(ListSelectionModel.MULTIPLE_INTERVAL_SELECTION)
        table.setAutoResizeMode(JTable.AUTO_RESIZE_OFF)
        # widen the useful columns
        try:
            table.getColumnModel().getColumn(2).setPreferredWidth(320)  # Path/Op
            if url_col is not None:
                table.getColumnModel().getColumn(url_col).setPreferredWidth(320)
            table.getColumnModel().getColumn(model.getColumnCount() - 1)\
                .setPreferredWidth(260)                                  # Source
        except Exception:
            pass
        table.setRowSorter(TableRowSorter(model))
        table.addMouseListener(self._TableMouse(self, table, model))
        return table, JScrollPane(table)

    def _build_settings(self):
        panel = JPanel(BorderLayout())
        panel.setBorder(BorderFactory.createTitledBorder(
            "Endpoint Hunter settings  (created by asad0x0)"))

        checks = JPanel(GridLayout(0, 4, 6, 4))
        self.cb_enabled = self._cb("Enable Extension", self._cfg.enabled)
        self.cb_js = self._cb("Scan JS responses", self._cfg.scan_js)
        self.cb_html = self._cb("Scan HTML responses", self._cfg.scan_html)
        self.cb_scope = self._cb("In-scope only", self._cfg.in_scope_only)
        self.cb_alltools = self._cb("All tools (not just Proxy)", self._cfg.all_tools)
        self.cb_method = self._cb("Guess HTTP method", self._cfg.guess_method)
        self.cb_params = self._cb("Detect params", self._cfg.detect_params)
        self.cb_gql = self._cb("Extract GraphQL ops", self._cfg.extract_graphql)
        self.cb_highlight = self._cb("Highlight sources", self._cfg.highlight)
        self.cb_logging = self._cb("Enable logging", self._cfg.enable_logging)
        self.cb_autocheck = self._cb("Auto status-check (default)", self._cfg.auto_check)
        self.cb_secrets = self._cb("Scan secrets/keys", self._cfg.extract_secrets)
        self.cb_soft404 = self._cb("Soft-404 calibrate", self._cfg.soft404_calibrate)
        for cb in (self.cb_enabled, self.cb_js, self.cb_html, self.cb_scope,
                   self.cb_alltools, self.cb_method, self.cb_params, self.cb_gql,
                   self.cb_highlight, self.cb_logging, self.cb_autocheck,
                   self.cb_secrets, self.cb_soft404):
            checks.add(cb)

        fields = JPanel(GridLayout(0, 2, 6, 4))
        fields.add(JLabel("Base URL (empty = source host):"))
        self.tf_base = JTextField(self._cfg.base_url)
        fields.add(self.tf_base)
        fields.add(JLabel("Max body size to scan (MB):"))
        self.tf_maxmb = JTextField(str(self._cfg.max_scan_mb))
        fields.add(self.tf_maxmb)

        buttons = JPanel(FlowLayout(FlowLayout.LEFT))
        buttons.add(JButton("Apply Settings", actionPerformed=self._apply))
        buttons.add(JButton("Clear Results", actionPerformed=self._clear))
        buttons.add(JButton("Check All Status", actionPerformed=self._check_all_status))
        buttons.add(JButton("Export CSV", actionPerformed=self._export_csv))
        buttons.add(JButton("Export URL list", actionPerformed=self._export_urls))

        inner = JPanel(BorderLayout())
        inner.add(checks, BorderLayout.NORTH)
        inner.add(fields, BorderLayout.CENTER)
        inner.add(buttons, BorderLayout.SOUTH)
        panel.add(inner, BorderLayout.CENTER)
        return panel

    def _cb(self, label, state):
        cb = JCheckBox(label, state)
        cb.addActionListener(self._LiveToggle(self))
        return cb

    # ---- active-crawl toolbar ----
    def _build_crawl_bar(self):
        row = JPanel(FlowLayout(FlowLayout.LEFT))
        row.setBorder(BorderFactory.createTitledBorder(
            "Active Crawl  (leave Seed empty = crawl Burp Target scope automatically)"))
        row.add(JLabel("Seed URL (empty = scope):"))
        self.tf_seed = JTextField(self._cfg.base_url, 20)
        row.add(self.tf_seed)
        row.add(JLabel("Depth:"))
        self.tf_depth = JTextField(str(self._cfg.crawl_max_depth), 2)
        row.add(self.tf_depth)
        row.add(JLabel("Pages:"))
        self.tf_maxpages = JTextField(str(self._cfg.crawl_max_pages), 4)
        row.add(self.tf_maxpages)
        row.add(JLabel("Delay ms:"))
        self.tf_delay = JTextField(str(self._cfg.crawl_delay_ms), 3)
        row.add(self.tf_delay)
        row.add(JButton("Start Crawl", actionPerformed=self._start_crawl))
        row.add(JButton("Stop Crawl", actionPerformed=self._stop_crawl))

        hdr_row = JPanel(FlowLayout(FlowLayout.LEFT))
        hdr_row.add(JLabel("Crawl headers (Name: val | Cookie: a=b):"))
        self.tf_headers = JTextField("", 40)
        hdr_row.add(self.tf_headers)

        auth_row = JPanel(FlowLayout(FlowLayout.LEFT))
        auth_row.add(JLabel("Auth probe cookie/headers (Cookie: a=b | X-Token: ..):"))
        self.tf_auth = JTextField("", 40)
        auth_row.add(self.tf_auth)
        auth_row.add(JButton("Apply Auth", actionPerformed=self._apply))

        mid = JPanel(BorderLayout())
        mid.add(hdr_row, BorderLayout.NORTH)
        mid.add(auth_row, BorderLayout.SOUTH)

        wrap = JPanel(BorderLayout())
        wrap.add(row, BorderLayout.NORTH)
        wrap.add(mid, BorderLayout.SOUTH)
        return wrap

    @staticmethod
    def _parse_headers(raw):
        """'Name: val | Cookie: a=b; c=d' -> {Name: val, Cookie: 'a=b; c=d'}."""
        hdrs = {}
        raw = (raw or "").strip()
        if raw:
            for part in raw.split("|"):
                if ":" in part:
                    n, v = part.split(":", 1)
                    n, v = n.strip(), v.strip()
                    if n:
                        hdrs[n] = v
        return hdrs

    def set_crawler(self, crawler):
        self._crawler = crawler

    def _start_crawl(self, event=None):
        if getattr(self, "_crawler", None) is None:
            return
        self._sync_config()
        for tf, attr in ((self.tf_depth, "crawl_max_depth"),
                         (self.tf_maxpages, "crawl_max_pages"),
                         (self.tf_delay, "crawl_delay_ms")):
            try:
                val = int(tf.getText().strip())
                floor = 1 if attr == "crawl_max_pages" else 0
                setattr(self._cfg, attr, max(floor, val))
            except Exception:
                pass
        self._cfg.extra_headers = self._parse_headers(self.tf_headers.getText())

        seed = self.tf_seed.getText().strip()
        if not seed:
            self._crawler.start_scope()      # auto-seed from Burp scope
            return
        if not seed.lower().startswith("http"):
            seed = "https://" + seed
        self._crawler.start(seed)

    def _stop_crawl(self, event=None):
        if getattr(self, "_crawler", None) is not None:
            self._crawler.stop()

    def _build_statusbar(self):
        bar = JPanel(BorderLayout())
        self.stats_label = JLabel(" Sources: 0   Endpoints: 0   GraphQL: 0 ")
        author = JLabel("Endpoint Hunter  -  created by asad0x0   ")
        author.setFont(Font("SansSerif", Font.BOLD, 12))
        left = JPanel(FlowLayout(FlowLayout.LEFT))
        left.add(self.stats_label)
        bar.add(left, BorderLayout.WEST)
        bar.add(author, BorderLayout.EAST)
        bar.setBorder(BorderFactory.createEmptyBorder(2, 6, 2, 6))
        return bar

    def _refresh_stats(self):
        self.stats_label.setText(
            " Sources: %d   Endpoints: %d   GraphQL: %d   Secrets: %d "
            % (self._count_sources, self.model_ep.getRowCount(),
               self.model_gql.getRowCount(), self.model_sec.getRowCount()))

    # ---- settings sync ----
    def _apply(self, event=None):
        self._sync_config()
        self._logger.info("Settings applied.")

    def _sync_config(self):
        self._cfg.enabled = self.cb_enabled.isSelected()
        self._cfg.scan_js = self.cb_js.isSelected()
        self._cfg.scan_html = self.cb_html.isSelected()
        self._cfg.in_scope_only = self.cb_scope.isSelected()
        self._cfg.all_tools = self.cb_alltools.isSelected()
        self._cfg.guess_method = self.cb_method.isSelected()
        self._cfg.detect_params = self.cb_params.isSelected()
        self._cfg.extract_graphql = self.cb_gql.isSelected()
        self._cfg.highlight = self.cb_highlight.isSelected()
        self._cfg.enable_logging = self.cb_logging.isSelected()
        self._cfg.auto_check = self.cb_autocheck.isSelected()
        self._cfg.extract_secrets = self.cb_secrets.isSelected()
        self._cfg.soft404_calibrate = self.cb_soft404.isSelected()
        self._cfg.base_url = self.tf_base.getText().strip()
        try:
            self._cfg.max_scan_mb = max(1, int(self.tf_maxmb.getText().strip()))
        except Exception:
            pass
        # auth-probe headers (used for the 2nd, authenticated probe)
        if hasattr(self, "tf_auth"):
            self._cfg.auth_headers = self._parse_headers(self.tf_auth.getText())

    class _LiveToggle(ActionListener):
        def __init__(self, ui):
            self.ui = ui
        def actionPerformed(self, event):
            self.ui._sync_config()

    # ---- row ingestion (thread-safe) ----
    def add_source_result(self, source_url, host, port, https, result):
        def _do():
            now = self._utils.now()
            for (method, path, params_csv) in sorted(result["paths"]):
                full = self._resolve_full(path, source_url)
                payload = EndpointPayload(method, path, params_csv,
                                          source_url, full)
                self.model_ep.add_row(
                    [now, method or "", path, params_csv, full, source_url,
                     "", "", "", "", "", "", ""],   # NA / A probe cols + Flag
                    payload)
                if self._cfg.auto_check:
                    self._status_queue.put(payload)
            if self._cfg.extract_graphql:
                for (optype, name) in sorted(result["gql"]):
                    self.model_gql.add_row([now, optype, name, source_url], None)
            for (kind, snippet) in sorted(result.get("secrets", ())):
                self.model_sec.add_row([now, kind, snippet, source_url], None)
                self._logger.info("  [SECRET] %s : %s  (%s)"
                                  % (kind, snippet, source_url))
            self._count_sources += 1
            self._refresh_stats()
        SwingUtilities.invokeLater(_do)

    def _resolve_full(self, path, source_url):
        if path.startswith("http"):
            return path
        base = self._cfg.base_url or source_url
        try:
            return urlparse.urljoin(base, path)
        except Exception:
            return path

    def append_log(self, text):
        def _do():
            self.log_area.append(text + "\n")
            self.log_area.setCaretPosition(self.log_area.getDocument().getLength())
        SwingUtilities.invokeLater(_do)

    # ---- actions ----
    def _active_table_model(self):
        idx = self.tabs.getSelectedIndex()
        if idx == 1:
            return self.table_gql, self.model_gql
        if idx == 2:
            return self.table_sec, self.model_sec
        return self.table_ep, self.model_ep

    def _clear(self, event=None):
        self.model_ep.clear()
        self.model_gql.clear()
        self.model_sec.clear()
        self._count_sources = 0
        self._refresh_stats()

    def _export_csv(self, event=None):
        table, model = self._active_table_model()
        if model is self.model_gql:
            default, cols = "graphql_ops.csv", self.GQL_COLS
        elif model is self.model_sec:
            default, cols = "secrets.csv", self.SEC_COLS
        else:
            default, cols = "endpoints.csv", self.EP_COLS
        path = self._choose_save(default)
        if not path:
            return
        try:
            f = open(path, "w")
            try:
                f.write(",".join(cols) + "\n")
                for cells in model.all_cells():
                    esc = ['"%s"' % ("" if c is None else str(c)).replace('"', '""')
                           for c in cells]
                    f.write(",".join(esc) + "\n")
            finally:
                f.close()
            self._logger.info("Exported %d row(s) to %s"
                              % (model.getRowCount(), path))
        except Exception:
            self._logger.error("export_csv", sys.exc_info())

    def _export_urls(self, event=None):
        """Flat list of full endpoint URLs (one per line) for Burp/ffuf import."""
        path = self._choose_save("endpoints_urls.txt")
        if not path:
            return
        seen, lines = set(), []
        for i in range(self.model_ep.getRowCount()):
            full = self.model_ep.cells_at(i)[4]
            if full and full not in seen:
                seen.add(full)
                lines.append(full)
        try:
            f = open(path, "w")
            try:
                f.write("\n".join(sorted(lines)) + "\n")
            finally:
                f.close()
            self._logger.info("Exported %d URL(s) to %s" % (len(lines), path))
        except Exception:
            self._logger.error("export_urls", sys.exc_info())

    def _choose_save(self, default_name):
        chooser = JFileChooser()
        chooser.setSelectedFile(File(default_name))
        if chooser.showSaveDialog(self._root) != JFileChooser.APPROVE_OPTION:
            return None
        return chooser.getSelectedFile().getAbsolutePath()

    # ---- send selected endpoints to Repeater ----
    def _send_to_repeater(self, payloads):
        for p in payloads:
            if p is None or not p.full_url:
                continue
            built = self._build_request_for_url(p.full_url, p.method)
            if built is None:
                continue
            req, host, port, https = built
            self._repeater_counter += 1
            self._callbacks.sendToRepeater(host, port, https, req,
                                           "EP-%d" % self._repeater_counter)

    def _build_request_for_url(self, full_url, method, headers_dict=None):
        """Build a raw request. headers_dict=None -> use crawl extra_headers
        (default, preserves crawl auth). Pass an explicit dict (even {}) to
        control exactly which extra headers go out -- {} means NO cookies."""
        try:
            ju = JURL(full_url)
        except Exception:
            return None
        host = ju.getHost()
        if not host:
            return None
        proto = (ju.getProtocol() or "http").lower()
        https = (proto == "https")
        port = ju.getPort()
        if port == -1:
            port = 443 if https else 80
        path = ju.getPath() or "/"
        if ju.getQuery():
            path = path + "?" + ju.getQuery()
        verb = method if method in ("GET", "POST", "PUT", "PATCH",
                                    "DELETE", "HEAD", "OPTIONS") else "GET"
        extra = self._cfg.extra_headers if headers_dict is None else headers_dict
        headers = ArrayList()
        headers.add("%s %s HTTP/1.1" % (verb, path))
        headers.add("Host: " + host)
        headers.add("User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
                    "AppleWebKit/537.36 (KHTML, like Gecko) "
                    "Chrome/125.0.0.0 Safari/537.36")
        headers.add("Accept: text/html,application/xhtml+xml,application/xml;"
                    "q=0.9,application/javascript,*/*;q=0.8")
        headers.add("Accept-Language: en-US,en;q=0.9")
        # NOTE: deliberately no Accept-Encoding -> avoid gzip (Burp won't gunzip
        # makeHttpRequest responses, which would break regex extraction).
        for hname, hval in extra.items():
            headers.add("%s: %s" % (hname, hval))
        headers.add("Connection: close")
        try:
            req = self._helpers.buildHttpMessage(headers, None)
        except Exception:
            return None
        return req, host, port, https

    def _copy_full_urls(self, payloads):
        urls = [p.full_url for p in payloads if p and p.full_url]
        self._utils.copy_to_clipboard("\n".join(urls))

    def _check_all_status(self, event=None):
        """Re-queue every endpoint for a (re)probe."""
        n = self.model_ep.getRowCount()
        for i in range(n):
            p = self.model_ep.payload_at(i)
            if p is not None:
                self._status_queue.put(p)
        self._logger.info("Queued %d endpoint(s) for status check." % n)

    def _check_status(self, payloads):
        """Manual (right-click) re-probe: just enqueue -> the worker handles it."""
        for p in payloads:
            if p and p.full_url:
                self._status_queue.put(p)

    # ---- dual probe: no-auth vs authenticated (broken-auth hunting) ----
    def _probe_and_fill(self, payload):
        """Probe an endpoint with NO cookies, and (if auth headers are set) WITH
        them, fill both column groups and compute a broken-auth Flag. Uses a
        per-host soft-404 baseline + login-page detection to kill false flags."""
        url = payload.full_url
        if not url:
            return
        row = self.model_ep.row_of_payload(payload)
        if row < 0:
            return

        base = self._baseline_for(url)   # per-host junk-path baseline (or None)

        # --- no-auth probe (always) : explicit empty headers = clean request ---
        self.model_ep.set_cell(row, self.COL_NA_STATUS, "...")
        na = self._probe_once(url, headers={})
        self._fill_group(row, self.COL_NA_STATUS, na)

        # --- authenticated probe (only if the user supplied auth headers) ---
        a = None
        if self._cfg.auth_headers:
            self.model_ep.set_cell(row, self.COL_A_STATUS, "...")
            a = self._probe_once(url, headers=self._cfg.auth_headers)
            self._fill_group(row, self.COL_A_STATUS, a)

        flag = self._flag_for(na, a, base)
        self.model_ep.set_cell(row, self.COL_FLAG, flag)
        if flag.startswith("BROKEN") or flag.startswith("PUBLIC-DATA"):
            self._logger.info("  [!] %s  ->  %s" % (url, flag))

    # ---- soft-404 baseline (one junk-path probe per host, cached) ----
    def _baseline_for(self, full_url):
        if not self._cfg.soft404_calibrate:
            return None
        try:
            ju = JURL(full_url)
            host = ju.getHost()
            proto = (ju.getProtocol() or "http").lower()
            port = ju.getPort()
        except Exception:
            return None
        if not host:
            return None
        key = "%s://%s:%s" % (proto, host, port)
        with self._baseline_lock:
            if key in self._baseline:
                return self._baseline[key]
            self._baseline[key] = None        # reserve so other threads skip
        portpart = "" if port == -1 else (":" + str(port))
        junk = "%s://%s%s/ephunter_%d_notreal" % (proto, host, portpart,
                                                  int(time.time()))
        res = self._probe_once(junk, headers={})
        with self._baseline_lock:
            self._baseline[key] = res
        if res is not None:
            self._logger.info("  baseline[%s] = %s %s %sb (soft-404 ref)"
                              % (host, res[0], res[1], res[2]))
        return res

    def _matches_baseline(self, res, base):
        """True if res looks like the host's soft-404 (same status+ctype+~size)."""
        if res is None or base is None:
            return False
        if res[0] != base[0]:
            return False
        rct = (res[1] or "").split(";")[0].strip()
        bct = (base[1] or "").split(";")[0].strip()
        if rct != bct:
            return False
        rsz, bsz = res[2] or 0, base[2] or 0
        tol = max(64, int(bsz * self._cfg.soft404_tolerance))
        return abs(rsz - bsz) <= tol

    def _fill_group(self, row, base_col, res):
        if res is None:
            self.model_ep.set_cell(row, base_col, "ERR")
            self.model_ep.set_cell(row, base_col + 1, "")
            self.model_ep.set_cell(row, base_col + 2, "")
            return
        self.model_ep.set_cell(row, base_col, str(res[0]))
        self.model_ep.set_cell(row, base_col + 1, res[1])
        self.model_ep.set_cell(row, base_col + 2,
                               "" if res[2] is None else str(res[2]))

    def _flag_for(self, na, a, base=None):
        """Interpret no-auth (na) and auth (a) probe results.
        Each is (status, ctype, size, login) or None."""
        if na is None:
            return ""
        na_status, na_ctype, na_size, na_login = na
        na_data = ("json" in na_ctype.lower() or "xml" in na_ctype.lower())

        # 1) soft-404: no-auth looks exactly like the host's junk-path baseline
        if self._matches_baseline(na, base):
            return "soft-404 (baseline)"

        # 2) login wall: 200 but body is really a login page / auth redirect
        if na_status == 200 and na_login:
            return "login-page (soft-auth)"

        # 3) no-auth returns real data -> endpoint not enforcing auth
        if na_status == 200 and na_data and na_size:
            if a is None:
                return "PUBLIC-DATA (200 no-auth)"    # no creds to compare
            a_status, a_ctype, a_size, a_login = a
            if a_status == 200 and a_size == na_size:
                return "BROKEN-AUTH (same w/ & w/o cookie)"
            return "BROKEN-AUTH (200 no-auth)"

        # 4) no-auth blocked, auth works -> access control enforced (good)
        if a is not None:
            a_status = a[0]
            if na_status in (401, 403) and a_status == 200:
                return "OK enforced"
            if na_status == 200 and a_status == 200 and na_size == a[2]:
                return "same (maybe public)"
        if na_status in (401, 403):
            return "auth-required"
        return ""

    def _probe_once(self, full_url, headers):
        """Return (status, ctype, size, login). HEAD first; GET on 405/501/empty.
        login = body looks like a login/auth wall (only detectable on GET)."""
        res = self._do_request(full_url, "HEAD", headers)
        if res is None:
            return None
        status, ctype, size, login = res
        # HEAD has no body -> re-GET to inspect size + login wall, or on 405/501
        if status in (405, 501) or size == 0:
            res2 = self._do_request(full_url, "GET", headers)
            if res2 is not None:
                status, ctype, size, login = res2
        return (status, ctype, size, login)

    def _do_request(self, full_url, method, headers):
        built = self._build_request_for_url(full_url, method, headers_dict=headers)
        if built is None:
            return None
        req, host, port, https = built
        try:
            svc = self._helpers.buildHttpService(host, port, https)
            rr = self._callbacks.makeHttpRequest(svc, req)
        except Exception:
            return None
        resp = rr.getResponse() if rr is not None else None
        if resp is None:
            return None
        try:
            info = self._helpers.analyzeResponse(resp)
            status = info.getStatusCode()
            ctype = self._utils.response_content_type(resp)
            body = self._utils.response_body_str(resp)
            login = looks_like_login(body, ctype)
            return (status, ctype, len(body or ""), login)
        except Exception:
            return None

    # ---- right-click menu per table ----
    class _TableMouse(MouseAdapter):
        def __init__(self, ui, table, model):
            self.ui = ui
            self.table = table
            self.model = model

        def _payloads(self):
            out = []
            for v in self.table.getSelectedRows():
                out.append(self.model.payload_at(
                    self.table.convertRowIndexToModel(v)))
            return out

        def mousePressed(self, event):
            self._maybe(event)

        def mouseReleased(self, event):
            self._maybe(event)

        def _maybe(self, event):
            if not event.isPopupTrigger():
                return
            row = self.table.rowAtPoint(event.getPoint())
            if row >= 0 and not self.table.isRowSelected(row):
                self.table.setRowSelectionInterval(row, row)
            self._menu().show(event.getComponent(), event.getX(), event.getY())

        def _menu(self):
            ui, mouse = self.ui, self
            menu = JPopupMenu()

            def item(label, fn):
                mi = JMenuItem(label)
                mi.addActionListener(mouse._Handler(mouse, fn))
                return mi

            # Repeater/copy only make sense for the Endpoints table (has payloads)
            if self.model is ui.model_ep:
                menu.add(item("Re-check status (no-auth + auth probe)",
                              lambda ps: ui._check_status(ps)))
                menu.add(item("Send to Repeater",
                              lambda ps: ui._send_to_repeater(ps)))
                menu.add(item("Copy full URL(s)",
                              lambda ps: ui._copy_full_urls(ps)))
                menu.addSeparator()
            menu.add(item("Clear Results", lambda ps: ui._clear()))
            menu.add(item("Export CSV", lambda ps: ui._export_csv()))
            return menu

        class _Handler(ActionListener):
            def __init__(self, mouse, fn):
                self.mouse = mouse
                self.fn = fn
            def actionPerformed(self, event):
                self.fn(self.mouse._payloads())


# ===========================================================================
#  Scanner : background worker pool (keeps regex off the proxy thread)
# ===========================================================================
class Scanner(object):
    def __init__(self, callbacks, helpers, config, utils, logger, ui):
        self._callbacks = callbacks
        self._helpers = helpers
        self._cfg = config
        self._utils = utils
        self._logger = logger
        self._ui = ui
        self._queue = Queue.Queue()
        self._workers = []
        self._running = True
        # dedup: scanned sources, and seen endpoints / gql across the session
        self._seen_sources = set()
        self._seen_paths = set()
        self._seen_gql = set()
        self._seen_secrets = set()
        self._lock = threading.Lock()

    def start(self):
        for i in range(self._cfg.max_threads):
            t = threading.Thread(target=self._loop, name="ephunter-worker-%d" % i)
            t.setDaemon(True)
            t.start()
            self._workers.append(t)
        self._logger.info("Started %d worker(s)." % len(self._workers))

    def stop(self):
        self._running = False
        for _ in self._workers:
            self._queue.put(None)

    # ---- called from the HTTP listener (response path) ----
    def schedule_message(self, message_info):
        try:
            request = message_info.getRequest()
            response = message_info.getResponse()
            if request is None or response is None:
                return
            url = self._helpers.analyzeRequest(message_info).getUrl()
            if self._cfg.in_scope_only and not self._callbacks.isInScope(url):
                return

            ctype = self._utils.response_content_type(response)
            is_js = ("javascript" in ctype or "ecmascript" in ctype
                     or url.getPath().lower().endswith((".js", ".mjs")))
            is_html = "html" in ctype
            if is_js and not self._cfg.scan_js:
                return
            if (not is_js) and is_html and not self._cfg.scan_html:
                return
            if not (is_js or is_html):
                return

            source = url.toString()
            body = self._utils.response_body_str(response)
            if not body:
                return
            if len(body) > self._cfg.max_scan_mb * 1024 * 1024:
                self._logger.info("Skipped (too large): " + source)
                return

            # dedup identical source payloads (same url + body length)
            sig = source + "|" + str(len(body))
            with self._lock:
                if sig in self._seen_sources:
                    return
                self._seen_sources.add(sig)

            svc = message_info.getHttpService()
            self._queue.put({
                "body": body, "source": source,
                "host": svc.getHost(), "port": svc.getPort(),
                "https": svc.getProtocol() == "https",
                "message_info": message_info,
            })
        except Exception:
            self._logger.error("schedule_message", sys.exc_info())

    # ---- actively fetch + scan linked scripts from an HTML page ----
    def crawl_scripts(self, message_info):
        def job():
            try:
                self._crawl_scripts_impl(message_info)
            except Exception:
                self._logger.error("crawl_scripts", sys.exc_info())
        t = threading.Thread(target=job, name="ephunter-crawl")
        t.setDaemon(True)
        t.start()

    def _crawl_scripts_impl(self, message_info):
        response = message_info.getResponse()
        if response is None:
            self._logger.info("Crawl: selected item has no response.")
            return
        page_url = self._helpers.analyzeRequest(message_info).getUrl().toString()
        html = self._utils.response_body_str(response)
        srcs = find_script_srcs(html, page_url)
        if not srcs:
            self._logger.info("Crawl: no <script src> found on " + page_url)
            return
        self._logger.info("Crawl: fetching %d script(s) from %s"
                          % (len(srcs), page_url))
        for js_url in srcs:
            try:
                built = self._ui._build_request_for_url(js_url, "GET")
                if built is None:
                    continue
                req, host, port, https = built
                svc = self._helpers.buildHttpService(host, port, https)
                rr = self._callbacks.makeHttpRequest(svc, req)
                resp = rr.getResponse() if rr is not None else None
                body = self._utils.response_body_str(resp)
                if not body:
                    continue
                result = self._run_extract(body)
                n_new = self._emit_new(result, js_url, host, port, https)
                if n_new[0] or n_new[1]:
                    self._logger.found(js_url, n_new[0], n_new[1])
            except Exception:
                self._logger.error("crawl fetch " + js_url, sys.exc_info())

    # ---- worker loop ----
    def _loop(self):
        while self._running:
            job = self._queue.get()
            try:
                if job is None:
                    break
                result = self._run_extract(job["body"])
                n_paths, n_gql = self._emit_new(result, job["source"],
                                                job["host"], job["port"],
                                                job["https"])
                if n_paths or n_gql:
                    self._logger.found(job["source"], n_paths, n_gql)
                    if self._cfg.highlight:
                        try:
                            mi = job["message_info"]
                            mi.setHighlight("cyan")
                            mi.setComment("Endpoint Hunter: %d endpoint(s), "
                                          "%d gql" % (n_paths, n_gql))
                        except Exception:
                            pass
            except Exception:
                self._logger.error("worker", sys.exc_info())
            finally:
                self._queue.task_done()

    def _run_extract(self, body):
        return extract_from_text(body,
                                 want_graphql=self._cfg.extract_graphql,
                                 want_method=self._cfg.guess_method,
                                 want_params=self._cfg.detect_params,
                                 want_secrets=self._cfg.extract_secrets)

    def _emit_new(self, result, source, host, port, https):
        """Filter out already-seen findings, push the rest to the UI."""
        new_paths = set()
        with self._lock:
            for item in result["paths"]:
                key = "%s|%s|%s" % (item[0], item[1], item[2])
                if key not in self._seen_paths:
                    self._seen_paths.add(key)
                    new_paths.add(item)
            new_gql = set()
            for item in result["gql"]:
                key = "%s|%s" % item
                if key not in self._seen_gql:
                    self._seen_gql.add(key)
                    new_gql.add(item)
            new_secrets = set()
            for item in result.get("secrets", ()):
                key = "%s|%s" % item
                if key not in self._seen_secrets:
                    self._seen_secrets.add(key)
                    new_secrets.add(item)
        if new_paths or new_gql or new_secrets:
            self._ui.add_source_result(source, host, port, https,
                                       {"paths": new_paths, "gql": new_gql,
                                        "secrets": new_secrets})
        return len(new_paths), len(new_gql)


# ===========================================================================
#  Crawler : active spider -- fetches the target itself (CLI-style --crawl)
# ===========================================================================
class Crawler(object):
    """
    Self-driven crawler. Given a seed URL it spiders same-host (and, if the
    toggle is on, in-scope) pages breadth-first up to a depth/page cap, fetching
    every HTML page and linked JS with callbacks.makeHttpRequest(), then feeds
    each body to the shared extractor. Runs on its own worker threads so the UI
    stays responsive. The crawler's own requests do NOT pass through the Proxy,
    so the passive listener never fires on them (no feedback loop).
    """

    def __init__(self, callbacks, helpers, config, utils, logger, ui, scanner):
        self._callbacks = callbacks
        self._helpers = helpers
        self._cfg = config
        self._utils = utils
        self._logger = logger
        self._ui = ui
        self._scanner = scanner
        self._queue = Queue.Queue()
        self._visited = set()
        self._lock = threading.Lock()
        self._running = False
        self._pages = 0
        self._pending = 0
        self._seed_hosts = set()
        self._workers = []

    def is_running(self):
        return self._running

    def start(self, seed_url):
        """Crawl from a single user-supplied seed; boundary = the seed's host."""
        if self._guard_running():
            return
        host = self._host_of(seed_url)
        if not host:
            self._logger.info("Crawl: invalid seed URL.")
            return
        self._begin([seed_url], set([host]), "seed " + seed_url)

    def start_scope(self):
        """Auto-seed the crawl from everything currently in Burp's Target scope."""
        if self._guard_running():
            return
        seeds, hosts = set(), set()
        try:
            entries = self._callbacks.getSiteMap(None)
        except Exception:
            entries = None
        for e in (entries or []):
            try:
                u = self._helpers.analyzeRequest(e).getUrl()
            except Exception:
                continue
            try:
                in_scope = self._callbacks.isInScope(u)
            except Exception:
                in_scope = False
            if in_scope and u.getHost():
                hosts.add(u.getHost())
                seeds.add(u.getProtocol() + "://" + u.getHost() + "/")  # host root
                seeds.add(u.toString())                                 # the URL itself
        if not seeds:
            self._logger.info("Crawl scope: nothing is in Burp scope yet. Add the "
                              "target under Target > Scope (visit it once so it is "
                              "in the site map), or type a Seed URL.")
            return
        self._begin(sorted(seeds), hosts, "Burp scope")

    def _guard_running(self):
        if self._running:
            self._logger.info("Crawl already running - stop it first.")
            return True
        return False

    def _host_of(self, url):
        try:
            return JURL(url).getHost()
        except Exception:
            return None

    def _begin(self, seeds, hosts, what):
        self._queue = Queue.Queue()
        self._visited = set()
        self._seed_hosts = set(hosts)
        self._pages = 0
        self._pending = 0
        self._running = True
        for s in seeds:
            s = s.split("#")[0]
            if s not in self._visited:
                self._visited.add(s)
                self._pending += 1
                self._queue.put((s, 0, "page"))
        if self._pending == 0:
            self._running = False
            self._logger.info("Crawl: no valid seed to start from.")
            return
        self._workers = []
        for i in range(max(1, self._cfg.crawl_threads)):
            t = threading.Thread(target=self._loop, name="ephunter-crawl-%d" % i)
            t.setDaemon(True)
            t.start()
            self._workers.append(t)
        self._logger.info("Crawl started: %s  (depth<=%d, max %d pages, hosts=%s)"
                          % (what, self._cfg.crawl_max_depth,
                             self._cfg.crawl_max_pages,
                             ", ".join(sorted(hosts)) if hosts else "any"))

    def stop(self):
        if self._running:
            self._running = False
            self._logger.info("Crawl stopped by user (%d page(s) fetched)."
                              % self._pages)

    # ---- queueing ----
    def _enqueue(self, url, depth, kind, force=False):
        """Queue a URL. force=True (used for <script src> and redirect targets)
        bypasses the same-host filter so cross-host JS bundles / redirect hops
        are still fetched -- matching the CLI, which fetched every script src."""
        if not self._running:
            return
        url = url.split("#")[0]
        low = url.lower()
        if not low.startswith("http"):
            return
        if low.startswith(("javascript:", "mailto:", "tel:", "data:")):
            return
        if not force:
            host = self._host_of(url)
            if not host:
                return
            if (self._cfg.crawl_same_host_only and self._seed_hosts
                    and host not in self._seed_hosts):
                return
        with self._lock:
            if url in self._visited:
                return
            self._visited.add(url)
            self._pending += 1
        self._queue.put((url, depth, kind))

    # ---- worker loop ----
    def _loop(self):
        while self._running:
            try:
                item = self._queue.get(True, 1.0)
            except Queue.Empty:
                continue
            try:
                self._process(item[0], item[1], item[2])
            except Exception:
                self._logger.error("crawl worker", sys.exc_info())
            finally:
                self._queue.task_done()
                with self._lock:
                    self._pending -= 1
                    drained = (self._pending <= 0)
                if drained and self._running:
                    self._running = False
                    self._logger.info("Crawl complete (%d page(s) fetched)."
                                      % self._pages)

    def _process(self, url, depth, kind):
        if not self._running:
            return
        with self._lock:
            if self._pages >= self._cfg.crawl_max_pages:
                if self._running:
                    self._running = False
                    self._logger.info("Crawl: hit max pages (%d)."
                                      % self._cfg.crawl_max_pages)
                return
            self._pages += 1

        if self._cfg.crawl_delay_ms > 0:
            time.sleep(self._cfg.crawl_delay_ms / 1000.0)

        built = self._ui._build_request_for_url(url, "GET")
        if built is None:
            return
        req, host, port, https = built
        try:
            svc = self._helpers.buildHttpService(host, port, https)
            rr = self._callbacks.makeHttpRequest(svc, req)
        except Exception:
            self._logger.error("crawl fetch " + url, sys.exc_info())
            return
        resp = rr.getResponse() if rr is not None else None
        if resp is None:
            self._logger.info("  x no response: " + url)
            return

        info = self._helpers.analyzeResponse(resp)
        status = info.getStatusCode()
        ctype = self._utils.response_content_type(resp)
        body = self._utils.response_body_str(resp)

        path_l = url.lower().split("?")[0]
        is_js = ("javascript" in ctype or "ecmascript" in ctype
                 or path_l.endswith((".js", ".mjs")))
        is_json = "json" in ctype
        is_html = "html" in ctype

        # extract endpoints from JS / JSON / HTML bodies (shared extractor + dedup)
        n_paths = n_gql = 0
        if body and (is_js or is_json or is_html):
            if len(body) <= self._cfg.max_scan_mb * 1024 * 1024:
                result = self._scanner._run_extract(body)
                n_paths, n_gql = self._scanner._emit_new(result, url, host,
                                                         port, https)

        # follow a redirect (same depth, any host)
        if status in (301, 302, 303, 307, 308):
            loc = self._header(info, "location")
            if loc:
                self._enqueue(urlparse.urljoin(url, loc), depth, "page", force=True)

        # follow HTML links (same host) + linked scripts (ANY host, like the CLI)
        n_links = n_scripts = 0
        if is_html and body and depth < self._cfg.crawl_max_depth:
            scripts = find_script_srcs(body, url)
            links = extract_links(body, url)
            n_scripts, n_links = len(scripts), len(links)
            for s in scripts:
                self._enqueue(s, depth + 1, "script", force=True)
            for link in links:
                self._enqueue(link, depth + 1, "page")

        # per-page diagnostic line -> shows exactly why a page did/didn't yield
        self._logger.info(
            "  [%s] %s -> %s %s (%db)  ep+%d gql+%d  links=%d scripts=%d"
            % (kind, url, status, ctype or "?", len(body or ""),
               n_paths, n_gql, n_links, n_scripts))

    def _header(self, info, name):
        name = name.lower()
        for h in info.getHeaders():
            if h.lower().startswith(name + ":"):
                return h.split(":", 1)[1].strip()
        return ""


# ===========================================================================
#  BurpExtender : entry point
# ===========================================================================
class BurpExtender(IBurpExtender, IHttpListener, IContextMenuFactory,
                   IExtensionStateListener):

    def registerExtenderCallbacks(self, callbacks):
        self._callbacks = callbacks
        self._helpers = callbacks.getHelpers()
        callbacks.setExtensionName("Endpoint Hunter")

        stdout = PrintWriter(callbacks.getStdout(), True)

        self._cfg = Config()
        self._utils = Utilities(self._helpers)
        self._logger = Logger(stdout, self._cfg)
        self._ui = ExtensionUI(callbacks, self._helpers, self._cfg,
                               self._utils, self._logger)
        self._logger.attach_ui(self._ui)
        self._scanner = Scanner(callbacks, self._helpers, self._cfg,
                                self._utils, self._logger, self._ui)
        self._crawler = Crawler(callbacks, self._helpers, self._cfg,
                                self._utils, self._logger, self._ui, self._scanner)
        self._ui.set_crawler(self._crawler)

        callbacks.addSuiteTab(self._ui)
        callbacks.registerHttpListener(self)
        callbacks.registerContextMenuFactory(self)
        callbacks.registerExtensionStateListener(self)

        self._scanner.start()
        self._logger.info("Endpoint Hunter loaded (created by asad0x0). "
                          "Browse the target - JS endpoints will appear here.")

    # ---- IHttpListener ----
    def processHttpMessage(self, tool_flag, message_is_request, message_info):
        try:
            if message_is_request or not self._cfg.enabled:
                return
            if not self._cfg.all_tools and tool_flag != self._callbacks.TOOL_PROXY:
                return
            self._scanner.schedule_message(message_info)
        except Exception:
            self._logger.error("processHttpMessage", sys.exc_info())

    # ---- IContextMenuFactory ----
    def createMenuItems(self, invocation):
        try:
            selected = invocation.getSelectedMessages()
            if not selected:
                return None
            items = ArrayList()

            mi1 = JMenuItem("Endpoint Hunter: scan this response")
            mi1.addActionListener(self._MenuAction(self, selected, "scan"))
            items.add(mi1)

            mi2 = JMenuItem("Endpoint Hunter: crawl linked <script src>")
            mi2.addActionListener(self._MenuAction(self, selected, "crawl"))
            items.add(mi2)
            return items
        except Exception:
            self._logger.error("createMenuItems", sys.exc_info())
            return None

    class _MenuAction(ActionListener):
        def __init__(self, ext, messages, mode):
            self.ext = ext
            self.messages = messages
            self.mode = mode
        def actionPerformed(self, event):
            for mi in self.messages:
                if self.mode == "scan":
                    self.ext._scanner.schedule_message(mi)
                else:
                    self.ext._scanner.crawl_scripts(mi)

    # ---- IExtensionStateListener ----
    def extensionUnloaded(self):
        try:
            self._crawler.stop()
            self._scanner.stop()
            self._ui.stop_status_worker()
            self._logger.info("Endpoint Hunter unloaded.")
        except Exception:
            pass
