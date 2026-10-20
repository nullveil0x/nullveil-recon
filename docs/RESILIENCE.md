# Resilience & Rate-Limiting

Real targets throttle. A `429 Too Many Requests`, a `503 Service Unavailable`
or a dropped connection in the middle of a large scan should not silently lose
data or make the tool look broken. NULLVEIL wraps its entire HTTP stack in a
**transparent retry / backoff layer** so scans stay effective *and* polite.

---

## How it works

The retrying layer sits at the **transport** level, below every call site.
Every request the scan makes — discovery, audit, fuzzing, and any subprocess
tool that uses the shared configuration — benefits automatically, with **zero**
changes to individual modules.

For each request it will:

1. Retry on **`429`**, **`502`**, **`503`**, **`504`**.
2. Retry on transient **connection** errors (`ConnectError`, `ConnectTimeout`,
   `ReadTimeout`, `PoolTimeout`, `RemoteProtocolError`).
3. Wait **exponentially** between attempts (`base × 2ⁿ`) with added **jitter**
   to avoid thundering-herd retries, capped at 8 s.
4. Honour a server's **`Retry-After`** header (capped at 10 s) when present.

Successful responses and definitive client errors (`4xx` other than `429`) are
returned immediately — the layer only engages on genuinely transient failures.

---

## Tuning

| Flag | Default | Effect |
|------|---------|--------|
| `--retries N` | `2` | Maximum transparent retries **per request**. |
| `--no-retry` | off | Disable the layer entirely (single attempt per request). |

```bash
# More patient against an aggressive rate-limiter
python3 nullveil_recon.py example.com -a all --retries 5

# Maximum speed against a target you know is relaxed
python3 nullveil_recon.py example.com -a all --no-retry
```

The **total number of retried requests** is exported at the top level of the
report as `retries` — a quick signal of how throttled a target was during the
scan.

```json
"retries": 48
```

---

## What was retried — a note on externals

Some modules talk to **third-party** services (crt.sh CT logs, the Wayback
Machine, CommonCrawl, NVD/EPSS/KEV). Those are governed by *their* rate limits,
not the target's, and occasionally return `502`/timeouts of their own. NULLVEIL
handles that in two layers:

* the transport retries the transient failures above, and
* each external module **degrades gracefully** — a failure is recorded in the
  top-level `errors` list and the module returns partial/empty results instead
  of aborting the scan.

You will see this as entries such as:

```
CT logs (crt.sh): RuntimeError: crt.sh returned HTTP 502 (try again later)
Wayback CDX: ReadTimeout
```

These do **not** fail the scan — the report is still produced and every other
module's findings are intact.

---

## Related: per-module timeouts

Independent of retries, every module has a hard timeout so a single slow module
can never hang the whole run:

| Flag | Default | Scope |
|------|---------|-------|
| `--module-timeout SEC` | `180` | Normal modules. |
| `--module-timeout-heavy SEC` | `300` | Crawl / fuzz / subprocess / network-heavy modules. |

A module that exceeds its budget is aborted with its **partial results kept**,
and an entry is added to `errors` — the scan continues.
