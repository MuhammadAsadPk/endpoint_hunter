# 🎯 Endpoint Hunter — Burp Suite Extension

> A passive **+** active recon extension for Burp Suite that harvests API endpoints, GraphQL operations and leaked secrets from JavaScript, then **auto-probes every endpoint for broken access control** (missing authentication / BOLA-style exposure).

Built by **asad0x0** · Tech6 Solutions · Jython 2.7 (legacy Burp Extender API)

---

## ✨ Why this exists

Modern web apps are JavaScript SPAs — the real attack surface (API routes, internal endpoints, GraphQL ops) lives inside minified JS bundles, **not** in the HTML. Endpoint Hunter pulls that surface out of live traffic *and* by actively spidering the target, then immediately checks each endpoint for the single most common high-impact bug class: **endpoints that return data without enforcing auth.**

It is the Burp-native port of my `endpoint_extractor.py` CLI — same extraction brains, but fed by live proxy traffic + an in-Burp crawler, with a broken-auth detection engine bolted on top.

---

## 🧩 Features at a glance

| Module | What it does |
| --- | --- |
| 📡 Passive harvesting | Scans every in-scope JS/HTML response flowing through Burp |
| 🕷️ Active crawler | Spiders the target itself (or auto-seeds from Burp scope) |
| 🔗 Endpoint extraction | Path-like routes, query strings, with HTTP-method + param guessing |
| 🧬 GraphQL extraction | `query` / `mutation` / `subscription` operation names |
| 🔑 Secrets scanner | 19 high-signal patterns (AWS, Google, Stripe, GitHub, JWT…) |
| 🛡️ Dual-probe auth check | No-auth **vs** authenticated probe → broken-access-control flag |
| 🎯 Soft-404 baseline | Per-host junk-path calibration to kill false positives |
| 🚪 Login-wall detection | Stops `200`-but-really-a-login-page false flags |
| 📤 Exports | CSV per tab + flat URL list for ffuf / Intruder |

---

## 🔬 Methodology — how each module works

### 📡 1. Passive harvesting
Registers an `IHttpListener` and watches **responses** (Proxy tool by default; a checkbox enables *all* tools). For every in-scope response whose content-type is JavaScript (or HTML, toggle-able), the body is queued to a background worker pool so the regex work never blocks the proxy thread. Identical sources (same URL + body length) are de-duplicated so re-visits don't re-scan.

👉 *Just browse the target — endpoints populate the tab on their own.*

### 🔗 2. Endpoint (path) extraction
A tuned regex pulls path-like string literals out of JS/HTML — anything starting with a single `/`, including query strings (`/api/download?file=`), while a noise filter drops static assets (`.png`, `.css`, `.woff`, source maps), protocol-relative `//cdn` URLs and template-literal junk (`/${x}`). Everything is de-duplicated across the whole session.

### 🧭 3. HTTP-method guessing
For each path literal the surrounding code is inspected to best-effort guess the verb:
- `xhr.open("POST", "/path")` → reads the method literal 🟢
- `axios.post("/path")`, `httpGet("/path")` → infers from the function name 🟢
- `fetch(url, { method: "PUT" })` → reads the `method:` key 🟢

### 🏷️ 4. Parameter detection
After a path literal, the first `{ … }` object is brace-matched and its top-level keys are extracted as likely request params — with a blocklist that strips framework noise (`headers`, `credentials`, `mode`, `signal`…) so you see real data fields, not fetch options.

### 🧬 5. GraphQL operation extraction
Separate regex captures `query` / `mutation` / `subscription` **operation names**, surfaced in their own **GraphQL** tab — handy for spotting introspection targets and sensitive mutations.

### 🔑 6. Secrets / sensitive-data scanner
The **same** JS/HTML/JSON bodies are swept for 19 high-signal secret patterns, shown in a dedicated **Secrets** tab:

> AWS access/secret keys · Google API key & OAuth · Stripe live keys · GitHub tokens · Slack tokens & webhooks · Twilio SID · SendGrid · Mailgun · Firebase DB URLs · S3 buckets · private-key blocks · JWTs · hardcoded `Authorization` headers · generic `api_key`/`client_secret` assignments · private IPs.

A placeholder filter drops obvious decoys (`xxxx`, `example`, `dummy`, `changeme`) to keep false positives down.

### 🕷️ 7. Active crawler (self-spider)
Give it a **seed URL**, or leave it blank to **auto-seed from Burp's Target scope** (every in-scope host root **and** every in-scope URL already in the site map). From there it breadth-first spiders:
- Fetches each HTML page + every linked `<script src>` via `makeHttpRequest` 🟢
- Follows `href` / `src` / `action` links and `301/302/307` redirects 🟢
- Linked scripts & redirects are fetched **cross-host** (CDN bundles still get scanned) 🟢
- **Boundary = host**, with `Depth`, `Max pages` (runaway cap) and `Delay ms` (politeness) controls 🟢
- Custom **crawl headers** field → drop in a session `Cookie` for an authenticated crawl 🟢
- A per-page diagnostic log line shows status / content-type / size / links / scripts so you can see *exactly* why a page did or didn't yield

The crawler's own requests bypass the Proxy, so the passive listener never loops on them.

### 🛡️ 8. Dual-probe — broken-auth hunting (the money module)
**On by default**, every discovered endpoint is auto-probed in the background:
- **No-auth probe** — sent with *zero* cookies (clean request)
- **Authenticated probe** — sent with your `Auth probe cookie/headers` (only if provided)
- Each probe is **HEAD-first, GET-on-fallback** (405/501/empty) — safe, no state-changing verbs

Results land in side-by-side columns — `NA-Status / NA-CType / NA-Size` vs `A-Status / A-CType / A-Size` — plus an interpreted **Flag**.

### 🎯 9. Soft-404 baseline calibration
SPAs love returning `200` for *everything*. Before flagging, Endpoint Hunter probes a random junk path (`/ephunter_<ts>_notreal`) **per host**, caches the response, and treats any endpoint whose status + content-type + size (within a 3% tolerance) matches that baseline as a **soft-404** — not a finding. This single step kills the biggest source of false positives.

### 🚪 10. Login-wall detection
A `200` body that is really a login form or auth redirect (`j_password`, `window.location → /login`, `{"error":"unauthorized"}`, `<form … login>`) is detected and flagged as `login-page (soft-auth)` instead of a broken-auth hit.

### 🚩 11. Flag interpretation (priority order)
```
soft-404 (baseline)        → looks like the host's junk-path response, ignore
login-page (soft-auth)     → 200 but it's really a login wall
BROKEN-AUTH (same w/ & w/o cookie) → 🔥 identical data with and without auth
BROKEN-AUTH (200 no-auth)  → 🔥 returns JSON/XML data with no cookie
PUBLIC-DATA (200 no-auth)  → 200 data, no creds supplied to compare
OK enforced                → 401/403 without auth, 200 with → access control works ✅
auth-required              → 401/403, enforced
```

### 🖱️ 12. Right-click actions
- On an **endpoint row**: *Re-check status (no-auth + auth probe)*, *Send to Repeater* (crafts the request), *Copy full URL(s)*
- On any **Proxy/history item**: *scan this response*, *crawl linked `<script src>`*

### 📤 13. Exports
- **CSV** per tab (Endpoints / GraphQL / Secrets)
- **Flat URL list** — clean one-per-line endpoints, ready for ffuf / Burp Intruder / nuclei

### ⚙️ 14. Threading model
Separate daemon worker pools for regex extraction, crawling, and status-probing keep the Burp UI fully responsive even on large bundles (configurable max body size, default 15 MB).

---

## 🚀 Installation

1. Burp Suite → **Extensions** → **Installed** → **Add**
2. Extension type: **Python** (requires a standalone **Jython 2.7** JAR configured under *Extensions → Settings → Python environment*)
3. Select `endpoint_hunter.py`
4. The **Endpoint Hunter** tab appears 🎉

---

## 🧪 Typical workflow

1. Add the target to **Target → Scope**
2. Open **Endpoint Hunter** → leave *Seed URL* blank → **Start Crawl** (auto-seeds from scope)
3. Watch endpoints, GraphQL ops and secrets fill their tabs; `NA-*` columns auto-populate
4. Scan the **Flag** column for `BROKEN-AUTH` / `PUBLIC-DATA` 🚩
5. Paste a session cookie into **Auth probe cookie/headers** → **Check All Status** to fill `A-*` and confirm
6. Right-click a red-flag row → **Send to Repeater** → build your PoC
7. **Export URL list** for further fuzzing

---

## ⚠️ Disclaimer

For authorized security testing only — bug bounty programs and engagements you have **explicit written permission** to test. The active crawler and probes send real requests to the target; use the `Delay ms` control on rate-limited or sensitive targets. You are responsible for staying in scope.

---

## 📜 License

MIT — see `LICENSE`.

---

*Made with ☕ by [asad0x0](https://github.com/MuhammadAsadPk) · Tech6 Solutions*
