# Advanced Scanning: Mass Targets · WAF Evasion · Deep Accuracy

Three v3.9.0 features aimed at the operator who runs NULLVEIL at scale, against
real targets behind real defences. All three stay **read-only / defensive** —
nothing here exploits, authenticates illegitimately, or mutates a target.

> **Authorisation first.** Scanning many hosts or hiding your traffic raises the
> bar for authorisation, not lowers it. Only ever scan systems you own or have
> **written permission** to test. See [`AUTHORIZATION.md`](AUTHORIZATION.md).

---

## 1. Mass scanning

Run the full pipeline across many targets in a single invocation.

```bash
# a file of targets (one per line; '#' comments and blank lines ignored)
python3 nullveil_recon.py --targets-file targets.txt -a all -o fleet.json

# an inline, comma-separated list — CIDR blocks expand to host IPs
python3 nullveil_recon.py --targets-list 'a.com,b.com,10.0.0.0/29' -a http

# combine both (the file first, then the inline list)
python3 nullveil_recon.py --target dom1.com --targets-file more.txt -a cve
```

| Flag | Meaning |
|------|---------|
| `--targets-file FILE` | Read targets from a file — one per line, `#` comments allowed. |
| `--targets-list LIST` | Comma/space-separated targets inline; CIDR expands to hosts. |
| `--max-hosts N` | Safety cap on expanded hosts (default **1024**) so an accidental `/8` never launches a million scans. |

### Output layout

Each target produces the **same** reports a single scan would, with the target
name appended before the extension:

```
$ python3 nullveil_recon.py --targets-file targets.txt -a all -o fleet.json -H fleet.html
fleet.a.com.json
fleet.a.com.html
fleet.b.com.json
fleet.b.com.html
fleet.index.json      ← combined summary
```

`fleet.index.json` carries the per-target outcome so a CI job can gate on it:

```json
{
  "tool": "NULLVEIL Recon", "version": "3.9.0", "mode": "batch", "count": 2,
  "targets": [
    {"target": "a.com", "ok": true, "exposure": 36, "verdict": "CAUTION"},
    {"target": "b.com", "ok": false, "error": "…"}
  ]
}
```

A failing target is **recorded, not fatal** — the batch keeps going. (In batch
mode `--dashboard` is ignored, since it is a long-lived process; the per-target
HTML reports are the deliverable.)

### CIDR expansion

`--targets-list '10.0.0.0/29'` expands to the **usable hosts** (`10.0.0.1` …
`10.0.0.6`), always capped by `--max-hosts`. URLs with a path
(`https://x.com/api`) are left intact — only bare CIDR specs expand.

---

## 2. WAF evasion

```bash
python3 nullveil_recon.py example.com -a all --evade light
python3 nullveil_recon.py example.com -a all --evade stealth --evade-rotate-every 3
```

| Level | Behaviour |
|-------|-----------|
| `none` *(default)* | No evasion — fastest, most obviously automated. |
| `light` | Rotate a coherent browser profile **every request** + small jitter (0–0.25 s). |
| `stealth` | Rotate + wider jitter (0–0.8 s) — slower, smoother signature. |

### What it actually does

The evasion layer sits **closest to the wire**, below the retry layer. For each
request it swaps the whole request to one of four **self-consistent** browser
profiles:

* Chrome / Windows, Chrome / macOS, Firefox / Windows, Safari / macOS

A real Chrome sends `Sec-Ch-Ua`, `Sec-Ch-Ua-Platform`, `Sec-Fetch-*` and a
matching `Accept-Language`; a Firefox UA never ships Chrome's client hints. The
profiles preserve that coherence, which is exactly what naive evasion scripts
get wrong (they paste a random UA onto a mismatched header set and are
trivially fingerprinted).

### What it does **not** do

* It never forges authentication, tampers with payloads, or mutates target state.
* It preserves any session header the auth layer injected
  (`Authorization`, `Cookie`, `X-Api-Key`, `X-Auth-Token`).
* It is **not** a WAF-bypass engine — it only makes the scan's own traffic look
  like an ordinary visitor's so it is not the *first* thing rate-limited.

A small jitter also smooths the machine-gun request pattern that trips naive
rate-limits. Combined with the retry layer (see [`RESILIENCE.md`](RESILIENCE.md))
this keeps a large scan both **effective and polite**.

The number of rewritten requests is exported at the top level:

```json
"evasion": {"level": "light", "requests_rewritten": 363, "rotate_every": 1}
```

---

## 3. Deep accuracy (`--verify`)

False positives are the tax on aggressive discovery. `--verify` pays it down by
re-checking the findings most likely to be wrong:

```bash
python3 nullveil_recon.py example.com -a paths --verify
```

For the **false-positive-prone classes** — flagged paths, and `.git` / `.env` /
config / backup / swagger exposures — it issues a **second, independent request
from a fresh connection**. A finding is kept only when the re-probe agrees with
the first one; anything that does not reproduce is removed from the report and
recorded under `verify_dropped`, so nothing is ever hidden from the operator.

### The safety rule

A **network hiccup is treated as inconclusive**, never as a "drop". If every
probe fails (target down, connection reset), the pass keeps everything and marks
the results `unknown` — so a flaky link can never silently delete a real
finding.

Results are exported under `verification`:

```json
"verification": {"tested": 12, "kept": 9, "dropped": 3, "unknown": 0, "paths_removed": 3}
```

`--verify` is intentionally scoped to the highest-yield classes rather than
every finding, to keep the extra request volume modest. It composes cleanly with
the rest of the pipeline (CVSS, ATT&CK, remediation all run afterwards on the
verified set).

---

## Putting it together

A large, polite, low-noise fleet scan against a real client surface:

```bash
python3 nullveil_recon.py \
  --targets-file client_assets.txt \
  -a all --deep \
  --evade light --retries 4 --verify \
  -o reports/scan.json -H reports/scan.html --pdf reports/scan.pdf
```

* `--evade light` — look like a browser, not a scanner.
* `--retries 4` — survive real throttling without dropping data.
* `--verify` — ship a report you would sign your name to.
* `--targets-file` — the whole external surface in one pass, with a combined index.
