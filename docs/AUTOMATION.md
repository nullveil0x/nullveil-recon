# Automation: Plugins & Headless JSON API

Two v3.9.0 features that let NULLVEIL drop into an existing pipeline instead of
being a tool you run by hand.

> **Authorisation first.** Both features scan live targets. Only ever point them
> at systems you own or have **written permission** to test. See
> [`AUTHORIZATION.md`](AUTHORIZATION.md).

---

## 1. Plugins (`--plugin`)

A **plugin** is a plain Python file that runs **after** the scan finishes and can
turn organisation-specific logic into first-class findings.

```bash
python3 nullveil_recon.py example.com -a all --plugin my_policy.py
python3 nullveil_recon.py example.com -a all \
  --plugin policy/a.py --plugin policy/b.py      # repeatable
```

### Writing a plugin

The file must define a module-level ``run(ctx)``. It may optionally define
``NAME`` and ``VERSION``. ``run`` returns an iterable of
``(severity, check, detail)`` tuples (or plain strings, promoted to `INFO`):

```python
NAME = "org-policy"
VERSION = "1.0.0"

def run(ctx):
    findings = []
    tech = {t.lower() for t in (ctx.get("tech_stack") or [])}
    if "wordpress" in tech:
        findings.append(("MEDIUM", "Policy: WordPress in use",
                         "Org policy prefers a managed CMS."))
    ctx.log(f"inspected {ctx.target}")
    return findings
```

See [`examples/plugin_example.py`](../examples/plugin_example.py) for a complete,
runnable example.

### The `ctx` object

| Member | Meaning |
|--------|---------|
| `ctx.target` | The scanned domain. |
| `ctx.base_url` | The scan's base URL. |
| `ctx.version` | NULLVEIL version. |
| `ctx.results` | The raw results mapping (`defaultdict(list)`) — read anything. |
| `ctx.get(key, default)` | Shorthand for `ctx.results.get(...)`. |
| `ctx.summary()` | The report summary (counts, tech stack, WAF…). |
| `ctx.findings()` | The flat, normalised finding list every reporting module sees. |
| `ctx.log(msg)` | Print a line to the console. |
| `ctx.recon` | The live `WebsiteRecon` object (advanced use). |

### What happens to a plugin's findings

Each returned tuple is appended to `plugin_findings`, which is a normal finding
source — so it flows into **CVSS scoring, the ATT&CK map, the remediation
engine, the JSON/HTML/PDF report, the dashboard and any `--webhook-*`
summary**, exactly like a built-in finding.

Plugins are also inventoried in the report:

```json
"plugins": {"files": ["org-policy"], "loaded": 1, "findings": 2, "errors": []},
"plugin_runs": [{"plugin": "org-policy", "findings": 2, "ok": true}]
```

### Safety

* A plugin is **arbitrary local code** — only load plugins you trust, exactly
  like a build script.
* A **crashing plugin never aborts the scan**: the error is recorded in
  `plugins.errors` and `plugin_runs`, and every other plugin still runs.
* Keep plugins **read-only and non-destructive** — they must never attack the
  target or exfiltrate data. They receive a scan that is already finished; they
  do not make HTTP requests themselves.

---

## 2. Headless JSON API (`--serve-api`)

Run NULLVEIL as a service so CI/CD, a ticketing system or another tool can
request scans and consume the JSON report.

```bash
python3 nullveil_recon.py --serve-api            # default port 8900, localhost
python3 nullveil_recon.py --serve-api 9100 --api-host 127.0.0.1
```

### Endpoints

| Method | Path | Purpose |
|--------|------|---------|
| `GET`  | `/health` | Liveness + version. |
| `POST` | `/scan` | Run a scan, return the **full report JSON**. |
| `GET`  | `/report?id=SCAN_ID` | A saved history report. |
| `GET`  | `/` | Self-describing endpoint list. |

### `POST /scan`

Request body (only `target` is required):

```json
{
  "target": "example.com",
  "modules": "all",
  "deep": false,
  "timeout": 10,
  "concurrency": 100,
  "verify": false,
  "evade": "none",
  "retries": 2,
  "ports": "80,443,8080",
  "wordlist": "subs.txt",
  "rules": "rules/",
  "plugin": "policy.py",
  "cve_live": false
}
```

The response is the same report dict the CLI writes with `-o`, so every consumer
already understands it.

```bash
curl -s -X POST http://127.0.0.1:8900/scan \
  -H 'Content-Type: application/json' \
  -d '{"target":"example.com","modules":"all","verify":true}' \
  | jq '.summary, .verification'
```

### Behaviour & safety

* **One scan at a time.** Scans are network-heavy; a concurrent `POST /scan`
  gets `429` while one is running. Read-only endpoints stay available.
* **JSON everywhere, including errors** — a `400` returns
  `{"error": "bad JSON: …"}`, a missing target returns
  `{"error": "target is required"}`.
* **`id` is validated** against `[A-Za-z0-9-]+` before it is used to build a
  history path — a traversal attempt in `?id=` is rejected with `400`.
* **Bind to localhost by default** (`127.0.0.1`). This is a *scanning* API —
  only expose it (`--api-host`) on a trusted network, and put auth in front of
  it if it is reachable by anything else.
* **Authentication is off by default** in the API. There are no `auth_*`
  request fields, so a caller cannot silently make the scan touch private data.

### A CI gate example

```bash
set -e
REPORT=$(curl -s -X POST http://127.0.0.1:8900/scan \
  -H 'Content-Type: application/json' \
  -d "{\"target\":\"$TARGET\",\"modules\":\"all\",\"verify\":true}")
SCORE=$(echo "$REPORT" | jq '.summary | .dedupe_removed')      # or any metric
echo "$REPORT" | jq '.errors'
# fail the build on a CRITICAL finding, for example:
echo "$REPORT" | jq -e '[.cvss.findings[]? | select(.severity=="CRITICAL")] | length == 0'
```

Combine with `--watch` (module 49) for scheduled drift scans, or with the
plugin system to enforce organisation policy on every build.

---

## Putting it together

```bash
# a service that enforces your policy plugin and returns verified reports
python3 nullveil_recon.py --serve-api 8900 &

curl -s -X POST http://127.0.0.1:8900/scan \
  -H 'Content-Type: application/json' \
  -d '{"target":"app.example.com","modules":"all","verify":true,
       "evade":"light","retries":4,"plugin":"policy.py"}' | jq .
```

* `--serve-api` — the tool becomes a component, not a CLI you babysit.
* `--plugin` — your policy, your findings, in the same report.
* `--verify` + `--evade` + `--retries` — a report you would sign your name to.
