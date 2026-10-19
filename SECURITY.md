# Security Policy — NULLVEIL Recon

## Reporting a vulnerability

If you believe you have found a security issue **in NULLVEIL Recon itself**
(the tool), please report it privately:

- Open a **private security advisory** on GitHub:
  `https://github.com/nullveil0x/nullveil-recon/security/advisories/new`
- Or open a normal issue **without** sensitive details and ask for a private
  channel.

Please include:

- Affected version (`nullveil_recon.py -V`).
- A minimal reproduction (command line + what happened).
- The impact and any suggested fix.
- Whether the issue is exploitable without user interaction.

**Please do not** open a public issue with a working exploit before a fix is
available. We aim to acknowledge reports within a few days.

## Scope

In scope:

- The tool's own code and dependencies.
- Anything that could make the tool unsafe to run (e.g. a crafted target that
  causes command injection, arbitrary file write, or remote code execution in the
  scanner).
- Secret-handling bugs (e.g. leaking credentials from your environment).

Out of scope:

- Findings produced **about scanned targets** — those are the target owner's
  issue, not the tool's.
- Issues in third-party binaries (nuclei, katana, ffuf, amass, nmap, playwright).
  Report those upstream.
- Scanning targets without authorization — that is a user-policy matter, not a
  vulnerability in the tool.

## Design principles (why the tool is defensive)

NULLVEIL Recon is built to be safe to run:

- **Read-only.** Modules perform discovery, fingerprinting and reporting. There
  are **no exploit payloads** and **no active exploitation**.
- **No writes to targets.** Cloud-storage enumeration uses HEAD/GET only — no
  uploads or bucket creation.
- **Report-only PoCs.** The verification module emits non-destructive `curl`/`dig`
  commands that *demonstrate* a finding; it does not exploit it.
- **Authorization-first.** The tool prints an authorization banner and presumes
  you are permitted to test the target.

## Safe operation guidelines for users

1. Only scan targets you own or are authorized to test.
2. Prefer a reasonable rate limit on production systems.
3. Treat any data discovered as sensitive; handle it lawfully.
4. Keep authorization records for every engagement.

## Dependency security

Keep dependencies current:

```bash
pip install -U "httpx[http2]" dnspython rich
```

Optional tools (nuclei, katana, ffuf, amass, nmap, playwright) should be kept
updated from their upstream sources.
