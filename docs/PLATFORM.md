# Platform: Scan Timeline & Multi-Worker Scanning

Two v3.9.0 features that turn a pile of one-off reports into something you can
query over time and run at fleet scale.

> **Authorisation first.** Both features scan live targets. Only ever point them
> at systems you own or have **written permission** to test. See
> [`AUTHORIZATION.md`](AUTHORIZATION.md).

---

## 1. Scan timeline (`--timeline`)

Every scan already auto-saves a JSON entry to `~/.nullveil/history`. The
**timeline** adds a small **SQLite** index *next to* that history (it never
replaces it) so questions a folder of JSON files cannot answer become a single
query:

* How has this target's exposure score moved over time?
* When did `api.example.com` first appear?
* Which run introduced this finding?

```bash
python3 nullveil_recon.py example.com -a all --timeline
```

Each completed scan is appended, and the console confirms it:

```
✓ Timeline DB — ~/.nullveil/history/timeline.db (12 scan(s), 4 domain(s))
Timeline: scan #13 indexed (~/.nullveil/history/timeline.db)
```

### Querying the timeline

```bash
python3 nullveil_recon.py --timeline-query example.com
```

```
                    example.com — 6 scan(s)
  #   When               Score   Verdict   High/ Crit   Subs   Ports
  ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
  6   2026-03-14T09:12      41   CAUTION         3/1      7      4
  5   2026-03-07T09:11      38   CAUTION         2/1      7      4
  ...

▲ Exposure trend: 34 → 41 (+7) over 6 scan(s)

              First seen (subdomains / ports)
  Kind       Asset                     Scan #   First seen
  ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
  subdomain  api.example.com                4   2026-02-21T08:03
  port       8443                           5   2026-02-28T08:05
```

### Options

| Flag | Meaning |
|------|---------|
| `--timeline` | Index this scan into the DB (in addition to the JSON history). |
| `--timeline-db FILE` | Use a specific DB path (default `~/.nullveil/history/timeline.db`). |
| `--timeline-query TARGET` | Print the trend + first-seen table for `TARGET` and exit. |

### Schema (v1)

```
scans(id, scanned_at, target, domain, version, duration_s, score, verdict,
      mode, modules, high, critical, secrets, subdomains, ports, paths, report_json)
findings(scan_id, severity, check_name, detail, source)
assets(scan_id, kind, value)
meta(key, value)                      -- schema_version
```

`assets` is what makes drift queries cheap: one row per discovered asset, so
"when did X first appear" is an indexed lookup rather than a full-scan diff.
`findings` mirrors the flattened finding list every reporting module sees.

### Safety / robustness

* **Append-only and additive** — the JSON history is untouched.
* **Never a dependency.** If the DB is missing or unwritable, every timeline
  method swallows the error; the scan runs exactly as it would without
  `--timeline`, and the report simply shows
  `"timeline": {"enabled": false}`.
* The DB lives beside the history in `~/.nullveil/` — your data, on your disk.

---

## 2. Multi-worker scanning (`--workers N`)

`--targets-file`/`--targets-list` already let one invocation scan many targets.
`--workers N` runs up to **N targets concurrently**, each through the full
pipeline.

```bash
python3 nullveil_recon.py --targets-file assets.txt -a all --workers 4 -o fleet.json
```

```
◆ Batch mode — 12 target(s) queued
4 worker(s) — reports never overlap (per-target suffix)
```

### How it stays safe

* **One report per target, no collisions.** Each target writes its own
  name-suffixed report (`fleet.<target>.json`), and the combined
  `fleet.index.json` is always assembled in **target order**, so output is
  deterministic regardless of which worker finished first.
* **A failing target is recorded, not fatal** — the batch completes and the
  index shows `"ok": false` plus the error for that target.
* **`--workers 1` (the default) is fully sequential** — the behaviour you had
  before, unchanged.
* Workers are capped at the number of targets, so asking for `--workers 8` on
  3 targets runs 3.

### Choosing a worker count

Workers multiply the **request rate** you present to your targets. Combine
`--workers` with the polite defaults:

```bash
python3 nullveil_recon.py --targets-file assets.txt -a all \
  --workers 4 --evade light --retries 4 -o fleet.json
```

* `--workers 4` — four targets in flight.
* `--evade light` — each worker looks like a browser (see [`ADVANCED.md`](ADVANCED.md)).
* `--retries 4` — survive throttling (see [`RESILIENCE.md`](RESILIENCE.md)).

Only raise `--workers` when your **authorisation** covers that request volume,
and remember each worker already opens its own concurrency pool (default 100) —
`--workers 4 -c 100` is up to 400 in-flight requests.

---

## Putting it all together

A nightly fleet scan that keeps a queryable history:

```bash
python3 nullveil_recon.py \
  --targets-file client_assets.txt \
  -a all --deep --workers 4 --evade light --retries 4 --verify \
  --timeline \
  -o reports/scan.json -H reports/scan.html
```

Then, any time:

```bash
python3 nullveil_recon.py --timeline-query app.client.com   # how is it trending?
```

* `--workers 4` — the whole surface in one pass.
* `--timeline` — every run indexed, ready to trend.
* `--verify` + `--evade` + `--retries` — a report you would sign your name to.
