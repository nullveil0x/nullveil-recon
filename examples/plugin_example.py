"""Example NULLVEIL plugin — shows the plugin API.

Load with::

    python3 nullveil_recon.py example.com -a all --plugin examples/plugin_example.py

A plugin is a plain Python file that defines ``run(ctx)`` and returns an
iterable of ``(severity, check, detail)`` tuples (or plain strings). Every
returned finding becomes a first-class finding: it appears in the CLI panel,
JSON/HTML/PDF report, CVSS register, ATT&CK map, remediation engine and any
``--webhook-*`` summary — exactly like a built-in finding.

The ``ctx`` object is read-only-ish: it exposes the finished results, the
target, the summary and a ``findings()`` helper, and only ever *reads*.

Safety: a plugin is arbitrary local code. Only ever load plugins you trust, and
keep them **read-only / non-destructive** — a plugin must never attack the
target or exfiltrate data.
"""

NAME = "example-policy-plugin"
VERSION = "1.0.0"


def run(ctx):
    findings = []

    # --- example 1: enforce an org policy on the tech stack -----------------
    tech = {t.lower() for t in (ctx.get("tech_stack") or [])}
    if "wordpress" in tech:
        findings.append(("MEDIUM", "Policy: WordPress in use",
                         "Org policy prefers a managed CMS; WordPress found in the "
                         "fingerprinted tech stack — review update/patch cadence."))

    # --- example 2: flag a cloud storage bucket you consider sensitive ------
    for bucket in ((ctx.get("cloud") or {}).get("buckets") or [])[:5]:
        name = bucket.get("bucket") if isinstance(bucket, dict) else str(bucket)
        if name and "backup" in name.lower():
            findings.append(("HIGH", "Policy: backup bucket exposed",
                             f"Bucket matching policy keyword 'backup' is enumerated: {name}"))

    # --- example 3: read the report summary the engine already built --------
    summ = ctx.summary()
    if summ.get("missing_security_headers", 0) == 0:
        findings.append(("INFO", "Policy: header baseline met",
                         "No missing security headers — meets the org baseline."))

    # ctx.log writes to the console; handy for debugging a policy plugin
    ctx.log(f"{NAME}: inspected {ctx.target} "
            f"({len(ctx.findings())} upstream finding(s))")
    return findings
