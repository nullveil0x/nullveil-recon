# Read-Only Vulnerability Verification (module 50)

> **Authorisation first.** This module sends benign probe markers at a live
> target. Only ever run it against systems you own or have **written
> permission** to test. See [`AUTHORIZATION.md`](AUTHORIZATION.md).

NULLVEIL is **defensive / report-only**: it never sends an exploit and never
extracts data. `vulnverify` (module 50) keeps that promise while still doing the
thing a report reader actually needs — **proving that a vulnerability class is
reachable** rather than merely guessing from a version banner.

```bash
python3 nullveil_recon.py example.com -a vulnverify
python3 nullveil_recon.py example.com -a param,vulnverify --deep   # richer param inventory first
```

It runs in the deferred pass (it needs the discovered parameter surface) and
before the reporting modules, so its findings flow into CVSS, ATT&CK,
remediation, the HTML/PDF report and webhooks like any other finding.

---

## What it proves — and how

### 1. Reflected-XSS sink

A parameter is set to a benign value made of an **alphanumeric marker plus a
quote/bracket pair** (`nvx9zq7"<b>`).

* If the response echoes that value **raw** — the bracket survives — the value
  reaches an **unencoded HTML output sink**. That is the finding.
* If the app **HTML-escapes** the output, the raw form is absent (only the
  entity `&lt;b&gt;` appears) and nothing is reported.

There is **no `<script>` tag, no event handler, no `javascript:`** — just enough
structure to tell "reflected safely" from "reflected into a sink". The marker
also ensures a value the page already contained cannot be mistaken for a
reflection (a control request without the marker is compared first).

### 2. SQL-injection surface

A parameter is set to a **marker plus a single quote** (`nvq9z7'`).

A hit requires **both**:

1. the unique marker echoed in the body, **and**
2. a recognised **database-error signature** (`You have an error in your SQL
   syntax`, `pg_query()`, `ORA-…`, `SQLSTATE[…]`, `sqlite3 … error`, …).

The marker requirement means a page that *already* showed a SQL error cannot
match. **No data is read**, no `UNION`, no boolean-blind loop — the module only
establishes that the parameter reaches a query layer.

### 3. Path traversal

Traversal sequences (`/etc/passwd`, `….//….//etc/passwd`, `..%2f…`, win.ini,
`/proc/self/environ`) are appended **only to file-ish parameters**, and a hit is
confirmed when the body matches a **known system-file signature**
(`root:…:0:0:`, `[fonts]`) **and** a **control request without the sequence does
not**. No file contents are extracted or stored — only the signature match is
recorded.

---

## The design rules

| Rule | Why |
|------|-----|
| **Benign markers only** | Never an executable payload; safe to run on production with authorisation. |
| **Marker + signature (SQLi)** | Kills the classic "pre-existing error page" false positive. |
| **Control request (XSS, traversal)** | A value already on the page, or a body that matches anyway, can never be reported. |
| **Skip when authenticated** | If the scan carries a session the parameter surface may hold user data — verification stays conservative. |
| **Rate-limited** | Every probe passes through the shared concurrency semaphore. |
| **Capped** | At most 20 parameters (40 with `--deep`) are probed. |

---

## Output

```json
"vuln_verify": {
  "tested": 9,
  "xss": [
    {"url": "https://app.example.com/search", "param": "q", "method": "GET",
     "reflected": true, "encoded": false,
     "context": "…<h1>Results for nvx9zq7\"<b>…",
     "note": "probe reflected RAW (bracket survived) — parameter reaches an HTML output sink unencoded"}
  ],
  "sqli": [
    {"url": "https://app.example.com/item", "param": "id", "method": "GET",
     "signature": "You have an error in your SQL syntax",
     "note": "marker + DB error string in response — parameter reaches a query layer"}
  ],
  "traversal": [
    {"url": "https://app.example.com/download", "param": "file", "method": "GET",
     "payload": "/etc/passwd",
     "note": "system-file signature returned (control did not) — traversal reaches the filesystem"}
  ]
}
```

Each hit is also emitted as a standard finding, so it appears in every
downstream engine:

| Class | Severity | Check |
|-------|----------|-------|
| Reflected XSS sink | `HIGH` | `Reflected XSS sink · <param>` |
| SQL injection surface | `CRITICAL` | `SQL injection surface · <param>` |
| Path traversal | `CRITICAL` | `Path traversal · <param>` |

The scan-level summary carries `vuln_verify_xss`, `vuln_verify_sqli` and
`vuln_verify_traversal` counts.

---

## What it deliberately does **not** do

* No exploit payloads (no `<script>`, no `UNION SELECT`, no shell metacharacters).
* No data extraction — traversal returns a **signature match**, not file contents;
  SQLi returns a **surface**, not rows.
* No blind/boolean/time-based brute forcing.
* No writes, no POST bodies that mutate state, no uploads.

If you need to go further than reachability (e.g. confirm exploitability in a
lab), do it **manually and in an authorised lab environment** — the report gives
your team the exact parameter to start from.
