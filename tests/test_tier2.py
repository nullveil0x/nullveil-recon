"""Unit tests for the Tier-2 intelligence modules (46-49).

These exercise the pure/heuristic logic without any real network traffic:
ATT&CK mapping, CVE offline intel, the takeover fingerprint table and the
change-monitor asset/diff helpers.
"""


# ---------------------------------------------------------------- ATT&CK (46)
def test_attack_map_well_formed(nv):
    am = nv.WebsiteRecon.ATTACK_MAP
    assert len(am) >= 20
    for cat, techs in am.items():
        assert techs, cat
        for tid, tname, tactic in techs:
            assert tid.startswith("T"), (cat, tid)
            assert tname and tactic


async def test_attack_mapping_output(nv, recon):
    recon.results["cve_findings"] = [
        ("HIGH", "SQL Injection in /login", "sql injection", "http"),
        ("MEDIUM", "Exposed API key", "hardcoded secret", "js"),
    ]
    await nv.WebsiteRecon.attack_mapping(recon)
    am = recon.results.get("attack_map")
    assert am and am["available"] is True
    assert am["technique_count"] >= 1
    ids = {t["id"] for t in am["techniques"]}
    assert "T1190" in ids  # SQLi → Exploit Public-Facing Application
    layer = am["layer"]
    assert layer["domain"] == "enterprise-attack"
    assert layer["techniques"]


# ---------------------------------------------------------------- CVE intel (47)
def test_cve_intel_table(nv):
    ci = nv.WebsiteRecon.CVE_INTEL
    assert len(ci) >= 10
    for cid, info in ci.items():
        assert cid.startswith("CVE-"), cid
        assert isinstance(info, dict)


async def test_cve_intel_offline_enrich(nv, recon):
    # the module pulls CVE ids from the collected evidence blob
    recon.results["cve_findings"] = [
        ("CRITICAL", "Apache 2.4.49", "CVE-2021-41773 path traversal", "cve"),
    ]
    await nv.WebsiteRecon.cve_intel_enrich(recon)
    ci = recon.results.get("cve_intel")
    assert ci and ci["available"] is True
    ids = {r["cve"] for r in ci["cves"]}
    assert "CVE-2021-41773" in ids  # Apache 2.4.49 traversal
    row = next(r for r in ci["cves"] if r["cve"] == "CVE-2021-41773")
    assert row["priority"].startswith("P1")
    assert ci["live"] is False


async def test_cve_intel_no_cves(nv, recon):
    # no CVE ids in evidence → empty result, no live fetch attempted
    recon.cve_live = True
    recon.results["versions"] = [("nginx", "1.24.0", "server-header")]
    await nv.WebsiteRecon.cve_intel_enrich(recon)
    ci = recon.results.get("cve_intel")
    assert ci and ci["count"] == 0
    assert ci["live"] is False


# ---------------------------------------------------------------- takeover (48)
def test_takeover_v3_fingerprints(nv):
    fp = nv.WebsiteRecon.TAKEOVER_V3
    assert len(fp) >= 40
    providers = [p for p, _s, _r in fp]
    assert len(providers) == len(set(providers)), "duplicate provider names"
    import re
    for prov, suffixes, sig in fp:
        assert suffixes, prov
        re.compile(sig)  # each signature must be a valid regex


def test_takeover_signature_matches_unclaimed(nv):
    """The provider signatures must actually match their 'unclaimed' pages."""
    import re
    table = {p: rx for p, _s, rx in nv.WebsiteRecon.TAKEOVER_V3}
    cases = {
        "AWS S3": "The specified bucket does not exist",
        "GitHub Pages": "There isn't a GitHub Pages site here.",
        "Heroku": "No such app",
        "Netlify": "Not found - request ID",
        "Vercel": "404: NOT_FOUND",
    }
    for prov, body in cases.items():
        assert re.search(table[prov], body), f"{prov} signature did not match"


# ---------------------------------------------------------------- watch (49)
def test_asset_sets_normalisation(nv):
    report = {
        "open_ports": [80, 443],
        "subdomains": ["www.example.com"],
        "api": {"endpoints": ["/api/x"]},
        "summary": {},
    }
    sets = nv.WebsiteRecon._asset_sets(report)
    assert "ports" in sets and "443" in sets["ports"]
    assert "www.example.com" in sets["subdomains"]


async def test_change_monitor_baseline(nv, recon, tmp_path, monkeypatch):
    # no history → establishes baseline
    recon.results["subdomains"] = ["a.example.com"]
    await nv.WebsiteRecon.change_monitor(recon)
    w = recon.results.get("watch")
    assert w and w["available"] is True
    assert w["baseline"] is False
    assert "baseline" in w["note"].lower()
