# Consulting & Assessments — NULLVEIL Recon

Turn NULLVEIL Recon into a **delivery engine** for paid security assessments.
This is the fastest path to revenue: the tool is free to use, you sell the
*outcome* (an assessment + report).

> Everything here is **authorization-first**. Never assess a system without
> written permission from its owner. See [`AUTHORIZATION.md`](AUTHORIZATION.md).

---

## Service catalog

| Service | What you deliver | Indicative price |
|---|---|---|
| **External Recon Snapshot** | Read-only external attack-surface report for one domain | $500–$1,500 |
| **Full External Assessment** | Recon + risk scoring (CVSS/CWE) + ATT&CK view + exec report + findings | $1,500–$5,000 |
| **Continuous Monitoring** | Recurring drift reports (`--watch`) with change alerting | $300–$1,000 / month |
| **Compliance Evidence Pack** | PCI-DSS / ISO 27001 / SOC 2 mapping + exec report | $1,000–$3,000 |
| **Remediation Retainer** | Patch guidance + re-validation after fixes | $500–$2,000 / month |

Prices are indicative; scope drives the quote.

---

## Delivery workflow

1. **Scope & authorize** — sign a scope letter + authorization
   ([template below](#scope-letter-template)).
2. **Recon** — run the tool inside the agreed window and rate limits:
   ```bash
   python nullveil_recon.py https://client.example.com -a all --deep \
       --exec-report client-exec.html -o client-scan.json
   ```
3. **Analyse** — CVSS/CWE register, ATT&CK coverage, CVE intel (KEV/EPSS),
   takeover checks, drift vs. prior scans.
4. **Report** — deliver the executive HTML/PDF plus the JSON appendix.
5. **Disclose & remediate** — report findings responsibly; offer a retainer for
   fixes and re-validation.
6. **Re-scan** — prove the fixes:
   ```bash
   python nullveil_recon.py https://client.example.com -a all --watch 1 --interval 0
   ```

## Report pack

The built-in exporter produces a client-ready report:

- **Executive HTML / PDF** — `--exec-report FILE` (or `--pdf FILE`) with exposure
  KPIs, top risks, compliance highlights, and remediation priorities.
- **JSON** — `-o FILE` full machine-readable evidence.
- **Dashboard** — `--dashboard PORT` for a live, filterable view and 1-click
  exec HTML/PDF download.

## A copy-paste engagement scope

- **Target:** (list domains/hosts)
- **Out of scope:** (list exclusions)
- **Actions:** passive + active read-only recon; no exploitation.
- **Window:** (start → end, timezone)
- **Rate limit:** (e.g. ≤ 5 req/s)
- **Contact:** (name, email, emergency stop)

## Scope-letter template

```
AUTHORIZATION TO TEST

Client:            ______________________________
Authorized by:     ______________________________  (name, title)
Date:              ______________________________
Valid window:      ______________________________  →  ______________________

Assets IN SCOPE:
  ______________________________________________________________

Assets OUT OF SCOPE:
  ______________________________________________________________

Permitted activities:
  [x] Passive reconnaissance
  [x] Active read-only reconnaissance (no exploitation)
  [ ] Authenticated testing (credentials to follow)
  Rate limit: ______________________

Instructions/notes:
  ______________________________________________________________

Signature:         ______________________________
```

Keep the signed letter on file. It is your legal defense.

## Positioning

- **You sell the report and the judgement**, not the binary.
- The tool is the engine; your expertise is the product.
- Lead with *defensive, read-only, legal-safe* — it is easy for clients to say
  yes to.
