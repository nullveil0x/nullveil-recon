"""Unit tests for the risk-scoring logic (CVSS 4.0 / CVSS 3.1 / CWE, module 45)."""
import pytest


def test_cvss31_known_vector(nv, recon):
    """A canonical CVSS:3.1 vector must match the published base score (9.8)."""
    # CVE-2021-44228-style: network, low complexity, no privs, no UI, full impact
    vec = "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"
    assert nv.WebsiteRecon._cvss31_score(recon, vec) == pytest.approx(9.8, abs=0.05)


def test_cvss31_zero_impact(nv, recon):
    vec = "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:N"
    assert nv.WebsiteRecon._cvss31_score(recon, vec) == 0.0


def test_cvss31_scope_changed_ceil(nv, recon):
    vec = "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H"
    score = nv.WebsiteRecon._cvss31_score(recon, vec)
    assert score == pytest.approx(10.0, abs=0.1)


def test_cvss31_bad_vector_returns_zero(nv, recon):
    assert nv.WebsiteRecon._cvss31_score(recon, "not-a-vector") == 0.0


def test_cvss4_score_range(nv, recon):
    macro = "AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H"
    score = nv.WebsiteRecon._cvss4_score(recon, macro)
    assert 0.0 <= score <= 10.0


def test_cvss4_unknown_class_falls_back(nv, recon):
    # an exotic macro class not in the table must not raise
    score = nv.WebsiteRecon._cvss4_score(recon, "AV:A/AC:H/AT:P/PR:H/UI:A/VC:L")
    assert 0.0 <= score <= 10.0


def test_cvss_category_classification(nv, recon):
    assert nv.WebsiteRecon._cvss_category(recon, "SQL Injection in /login", "") == "sqli"
    assert nv.WebsiteRecon._cvss_category(recon, "XSS", "reflected input") == "xss"
    assert nv.WebsiteRecon._cvss_category(recon, "exposed .env", "CWE") == "info_disclosure"
    assert nv.WebsiteRecon._cvss_category(recon, "zzz", "qqq") == "generic"


def test_profiles_well_formed(nv):
    """Every CVSS profile is a 4-tuple (macro, 3.1 vector, cwe, name)."""
    assert len(nv.WebsiteRecon.CVSS_PROFILES) >= 20
    for name, prof in nv.WebsiteRecon.CVSS_PROFILES.items():
        assert len(prof) == 4, name
        macro, vec31, cwe, cwe_name = prof
        assert macro.startswith("AV:") or macro.startswith("CVSS")
        assert vec31.startswith("CVSS:3.1/"), name
        assert cwe.startswith("CWE"), name
        assert cwe_name, name


async def test_cvss_score_findings_populates(nv, recon):
    recon.results["cve_findings"] = [
        ("HIGH", "SQL Injection in /login", "sql injection", "http"),
        ("LOW", "Missing security header", "no CSP", "headers"),
    ]
    await nv.WebsiteRecon.cvss_score_findings(recon)
    cv = recon.results.get("cvss")
    assert isinstance(cv, dict) and cv.get("available") is True
    assert cv["count"] >= 1
    for row in cv["top"]:
        assert row["cwe"].startswith("CWE")
        assert 0.0 <= row["score"] <= 10.0
        assert row["severity"] in ("CRITICAL", "HIGH", "MEDIUM", "LOW")
