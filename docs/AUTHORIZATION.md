# Authorization — Before You Scan

> **Read this before running NULLVEIL Recon against anything you do not own.**

NULLVEIL Recon is a defensive, read-only reconnaissance tool. It is **only**
lawful to use against systems you own or are **explicitly authorized** to test.
This page is a practical checklist, not legal advice.

---

## 1. Get written authorization

Before scanning any third-party system you **must** have authorization that is:

- **Written** (email is fine; a signed scope letter is better).
- **From someone who can grant it** (the asset owner, or their authorized
  representative — not just a developer who "doesn't mind").
- **Specific** about what is in scope.
- **Dated** with a clear validity window.

A bug-bounty program page or a responsible-disclosure policy **is** written
authorization — but only for the assets and actions it actually permits. Read it
carefully.

## 2. Confirm the scope

Record and confirm, in writing:

| Item | Example |
|---|---|
| **In-scope hosts / domains** | `app.example.com`, `api.example.com` |
| **Out-of-scope** | `*.corp.example.com`, third-party SaaS |
| **Allowed actions** | "passive + active recon, no exploitation" |
| **Time window** | "2026-01-01 00:00 → 2026-01-07 23:59 UTC" |
| **Rate limits** | "≤ 5 req/s" |
| **Point of contact** | `security@example.com` |
| **Emergency stop** | who to call, how |

## 3. Match tool settings to the authorization

- Honor the **time window** and **rate limits**.
- Do **not** enable authenticated scanning unless credentials were provided for
  that purpose.
- Do **not** point modules at out-of-scope hosts, even indirectly (e.g. via a
  discovered third-party API). The shared HTTP client blocks redirects and
  browser requests outside the target host/subdomains; use `--allow-host` only
  for hosts the authorization explicitly covers.
- Set `--rps` to the rate limit in your authorization (default: 25 req/s;
  `0` disables the limiter).
- Keep everything **read-only** — NULLVEIL Recon performs no exploitation by
  design; do not bolt on exploit tooling.

## 4. Bug-bounty specific notes

- Only test assets the program lists as **in scope**.
- Respect the program's **safe-harbor** and **disclosure** terms.
- Automated scanning may be prohibited or rate-limited — check first.
- If you find something sensitive, report it **privately** and do not exfiltrate
  more data than necessary to prove the issue.

## 5. If you are unsure — stop and ask

It is always correct to pause and get written clarification. The cost of asking
is zero; the cost of an unauthorized scan can be criminal liability.

## 6. Keep your records

Retain, for the life of the engagement and beyond:

- The written authorization.
- The agreed scope and time window.
- Your scan logs and timestamps.
- Your disclosure correspondence.

These documents are your defense if your activity is ever questioned.

---

## Quick pre-scan checklist

- [ ] I have **written authorization** from the owner (or the program is a
      lawful bug-bounty scope).
- [ ] The target is **within scope** and inside the allowed **time window**.
- [ ] I am respecting **rate limits** and any prohibited-action list.
- [ ] I will keep the scan **read-only** and handle data lawfully.
- [ ] I have a **point of contact** and an **emergency-stop** procedure.
- [ ] I will **report** findings responsibly.

**Authorized targets only.** 🥷
