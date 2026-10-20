# Plugin Rule Engine

NULLVEIL ships with a curated set of CVE and misconfiguration rules compiled
into the binary (see `CVE_RULES` and `MISCONFIG_PROBES` in the source). The
**plugin rule engine** lets you extend that knowledge from the outside —
without editing a single line of Python — so a team can keep its own,
org-specific rule set under version control.

```bash
python3 nullveil_recon.py example.com -a cve --rules rules/
python3 nullveil_recon.py example.com -a cve --rules my-cves.json
python3 nullveil_recon.py example.com -a cve --rules ./mine/ --rules ./vendor/   # repeatable
```

`--rules` accepts a **file** or a **directory**. Directories are scanned
recursively for `*.yml`, `*.yaml` and `*.json`. The flag is **repeatable**, so
you can layer your own rules over a vendor set.

> **JSON needs nothing extra.** YAML requires the optional `PyYAML` package
> (`pip install pyyaml`). If YAML is requested without PyYAML the loader raises
> a clear, actionable error and the rest of the scan is unaffected.

---

## Rule file format

A rule file is either **a single object** or **a list** (a bare list is treated
as `cve` rules). Both rule kinds can coexist in one file:

```yaml
cve:
  - product: nginx
    major: null            # optional: restrict to a major version
    mode: lt               # lt | le | eq | ge | gt
    version: [1, 20, 1]    # boundary — list or string ("1.20.1")
    id: CVE-2021-23017
    severity: HIGH
    title: Resolver off-by-one (nginx < 1.20.1)

misconfig:
  - path: /.git/config
    match: "(?i)\\[core\\]"   # optional regex; null = any 200/403 counts
    severity: HIGH
    id: Exposed .git config
    title: Git config is public
```

### CVE / version rules

| Field | Required | Meaning |
|-------|----------|---------|
| `product` | ✅ | Product name as the tool fingerprints it (`nginx`, `apache`, `php`, `tomcat`, `wordpress`, `jquery`, `openssh`, `express` …). Lower-cased before matching. |
| `mode` | – | Comparison operator: `lt` (default), `le`, `eq`, `ge`, `gt`. |
| `version` | ✅ | Boundary version. `[1, 20, 1]` or `"1.20.1"`. Trailing non-numeric parts are ignored. |
| `major` | – | Integer; if set, the rule only applies when the detected major matches. Use it to split CVE lines (`tomcat` 8.x vs 9.x). |
| `id` | ✅ | The CVE id (also accepts the key `cve`). |
| `severity` | – | `CRITICAL` / `HIGH` / `MEDIUM` / `LOW` / `INFO` (default `MEDIUM`). |
| `title` | – | Human description. Defaults to the id. |

A rule **fires** when the detected version satisfies the comparison. For the
usual "fixed in X" advisory, use `mode: lt` — vulnerable means *below* the fix:

```yaml
- product: openssh
  mode: lt
  version: [7, 4]           # OpenSSH < 7.4 is vulnerable
  id: CVE-2016-10708
  severity: MEDIUM
  title: OpenSSH < 7.4 — sshd NULL-pointer dereference DoS
```

Version comparison is zero-padded, so `1.20` equals `1.20.0` and
`8.5` > `8.5.0.1` never trips unexpectedly.

### Misconfiguration probes

| Field | Required | Meaning |
|-------|----------|---------|
| `path` | ✅ | URL path requested with **GET only** (read-only — probes never mutate state). |
| `match` | – | Regex the **response body** must match. Omit/`null` → any `200`/`403` counts. A malformed regex is dropped (the rule still runs as a presence check). |
| `severity` | – | As above (default `MEDIUM`). |
| `id` | – | Stable id (defaults to the path). |
| `title` | – | Human description (defaults to the id). |

### Safety

* Probes **only** issue `GET` requests. Nothing is uploaded, modified or deleted.
* `match` is compiled once, up front — an invalid pattern can never crash a scan.
* On a quick (non-`--deep`) scan the built-in probe list is trimmed, but **your
  external rules always run in full**.

---

## Behaviour & precedence

External rules are **merged** with the built-ins — they never replace them:

* `cve_scan` (module 15) matches every detected product version against
  `CVE_RULES + <external cve rules>`.
* The active misconfig probes are `MISCONFIG_PROBES + <external probes>`.

Duplicates are not de-duplicated against the built-ins by design (a CVE may be
listed with a tighter boundary in your set); the smart-dedup pass later
collapses identical findings in the report.

Loaded rules are reported in the JSON/HTML/PDF output under the top-level
`ruleset` key:

```json
"ruleset": {
  "files": ["rules/example.yaml", "rules/example.json"],
  "cve_rules": 5,
  "misconfig_rules": 5,
  "errors": []
}
```

Any file that fails to load is **skipped** and its reason is recorded in
`ruleset.errors` and printed to the console — one bad rule file never aborts a
scan.

---

## Worked example

```bash
# A team keeps org-specific rules in ./rules
python3 nullveil_recon.py client.example.com -a cve --rules ./rules -o report.json
```

If `./rules/org.yaml` contains a rule for a product the tool fingerprints, it
becomes a first-class finding: it appears in the CLI panel, the JSON report
(`cve_findings`), the HTML/PDF report, the dashboard, the CVSS register, the
ATT&CK mapping and the webhook summary — exactly like a built-in CVE.

See [`rules/example.yaml`](../rules/example.yaml) and
[`rules/example.json`](../rules/example.json) for complete, NVD-verified
examples.
