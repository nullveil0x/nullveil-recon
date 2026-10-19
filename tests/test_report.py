"""Tests for the report/export contract and the diff engine.

Guards the JSON schema the dashboard, notifications and CI consumers rely on —
a broken export silently breaks every downstream integration.
"""
import json


def test_export_dict_shape(nv, recon):
    rep = nv.WebsiteRecon.export_dict(recon)
    assert isinstance(rep, dict)
    for key in ("version", "target", "summary", "errors", "tool", "owner"):
        assert key in rep, key
    assert rep["version"] == nv.__version__
    # must be JSON-serialisable with the same default=str policy the tool uses
    json.dumps(rep, default=str)


def test_export_has_tier2_sections(nv, recon):
    rep = nv.WebsiteRecon.export_dict(recon)
    # Tier-2 keys exist even before the modules run (empty defaults)
    for key in ("cvss", "mitre_attack", "cve_intel", "takeover_v3", "watch",
                "scan_diff"):
        assert key in rep, f"missing export section: {key}"


def test_summary_counts_are_numeric(nv, recon):
    rep = nv.WebsiteRecon.export_dict(recon)
    # count-style keys must be numeric; a couple of keys legitimately hold lists
    non_count = {"tech_stack", "waf"}
    for k, v in rep["summary"].items():
        if k in non_count:
            continue
        assert isinstance(v, (int, float)), f"summary[{k}] is {type(v)}"


def test_collect_findings_handles_seeded_modules(nv, recon):
    recon.results["versions"] = [("nginx", "1.24.0", "header")]
    recon.results["cve_findings"] = [("HIGH", "CVE-2021-1234", "detail", "src")]
    rows = nv.WebsiteRecon._collect_findings(recon)
    assert isinstance(rows, list)
    for row in rows:
        assert len(row) == 4, row  # (severity, check, detail, source)


def test_compute_diff_first_scan(nv, recon):
    recon.no_history = False
    report = nv.WebsiteRecon.export_dict(recon)
    nv.WebsiteRecon._compute_diff(recon, report)
    d = recon.results.get("diff")
    assert d and d.get("available") is False
    assert "baseline" in d.get("note", "").lower()
