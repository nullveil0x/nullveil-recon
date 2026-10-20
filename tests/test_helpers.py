"""Unit tests for the pure helper functions (normalisation, scoring, dedupe).

These are the low-level building blocks the dashboard, diff engine and HTML/PDF
reporters all depend on, so they are worth pinning down precisely.
"""


# ---------------------------------------------------------------- _norm_ports
def test_norm_ports_accepts_mixed_shapes(nv):
    out = nv._norm_ports([443, "80", "8080/tcp", {"port": 22}, {"number": "3306"},
                          None, "", "abc"])
    assert out == [22, 80, 443, 3306, 8080]


def test_norm_ports_dedupes_and_sorts(nv):
    assert nv._norm_ports(["443", 443, "443/tcp"]) == [443]


def test_norm_ports_empty(nv):
    assert nv._norm_ports(None) == []
    assert nv._norm_ports([]) == []


# ---------------------------------------------------------------- _norm_paths
def test_norm_paths_from_strings_and_dicts(nv):
    out = nv._norm_paths(["/a", {"path": "/b", "status": 200, "source": "crawl"},
                          {"url": "/c"}, "/a"])
    paths = [r["path"] for r in out]
    assert paths == ["/a", "/b", "/c"]
    assert out[1]["status"] == 200
    assert out[1]["source"] == "crawl"


def test_norm_paths_drops_blanks(nv):
    assert nv._norm_paths(["", None, "  ", "/ok"]) == [{"path": "/ok"}]


# ---------------------------------------------------------------- _wrap
def test_wrap_splits_long_text(nv):
    lines = nv._wrap("one two three four five six", 10)
    assert all(len(ln) <= 10 or " " not in ln for ln in lines)
    assert "".join(lines).replace(" ", "") == "onetwothreefourfivesix"


def test_wrap_empty_returns_one_line(nv):
    assert nv._wrap("", 20) == [""]


# ---------------------------------------------------------------- _risk_meter
def test_risk_meter_bands(nv):
    score, level, color, verdict, bar = nv._risk_meter([], 0, [])
    assert score == 0 and level == "LOW" and verdict == "SECURE"
    score2, level2, color2, verdict2, _ = nv._risk_meter(["a"] * 5, 5, ["/x"] * 5)
    assert score2 == 100 and level2 == "HIGH" and color2 == "red"


def test_risk_meter_caps_at_100(nv):
    score = nv._risk_meter(["s"] * 100, 100, ["/p"] * 100)[0]
    assert score == 100


# ---------------------------------------------------------------- _dedupe_findings
def test_dedupe_removes_exact_duplicates(nv, recon):
    rows = [("HIGH", "X", "boom", "src"), ("HIGH", "X", "boom", "src")]
    out = nv.WebsiteRecon._dedupe_findings(recon, rows)
    assert len(out) == 1


def test_dedupe_normalises_numbers_and_paths(nv, recon):
    rows = [("MEDIUM", "Open port", "port 80 open", "scan"),
            ("MEDIUM", "Open port", "port 443 open", "scan")]
    out = nv.WebsiteRecon._dedupe_findings(recon, rows)
    # numbers masked → same normalised detail → collapsed with count
    assert len(out) == 1
    assert "×2" in out[0][2]


def test_dedupe_records_stats(nv, recon):
    rows = [("LOW", "A", "d", ""), ("LOW", "A", "d", "")]
    nv.WebsiteRecon._dedupe_findings(recon, rows)
    st = recon.results.get("dedupe_stats", {})
    assert st.get("before") == 2 and st.get("after") == 1 and st.get("removed") == 1


def test_dedupe_respects_no_dedupe(nv, recon):
    recon.no_dedupe = True
    rows = [("LOW", "A", "d", ""), ("LOW", "A", "d", "")]
    assert nv.WebsiteRecon._dedupe_findings(recon, rows) == rows


def test_dedupe_accepts_3_tuples(nv, recon):
    rows = [("LOW", "A", "d"), ("LOW", "A", "d")]
    out = nv.WebsiteRecon._dedupe_findings(recon, rows)
    assert len(out) == 1 and len(out[0]) == 4


# ---------------------------------------------------------------- _asset_sets
def test_asset_sets_full_report(nv):
    report = {
        "subdomains": ["A.example.com", "b.example.com"],
        "open_ports": [{"port": 443, "service": "https"}, 80],
        "paths": [{"path": "/x"}, "/y"],
        "api": {"live_endpoints": ["/api/a"], "cookies": ["sid"], "forms": []},
        "users": ["admin"],
        "summary": {},
    }
    sets = nv.WebsiteRecon._asset_sets(report)
    assert sets["subdomains"] == {"a.example.com", "b.example.com"}
    assert "443" in sets["ports"] and "80" in sets["ports"]
    assert "/x" in sets["paths"] and "/y" in sets["paths"]
    assert "admin" in sets["users"]


def test_asset_sets_unwraps_history_entry(nv):
    entry = {"report": {"subdomains": ["z.example.com"], "summary": {}}}
    sets = nv.WebsiteRecon._asset_sets(entry)
    assert "z.example.com" in sets["subdomains"]


# ---------------------------------------------------------------- CVE cache
def test_cve_cache_roundtrip(nv, tmp_path, monkeypatch):
    monkeypatch.setattr(nv.WebsiteRecon, "CVE_CACHE_DIR", str(tmp_path / "cve"), raising=False)
    nv.WebsiteRecon._cve_cache_write("CVE-2021-44228", {"cvss": 10.0, "kev": True})
    got = nv.WebsiteRecon._cve_cache_read("CVE-2021-44228")
    assert got == {"cvss": 10.0, "kev": True}


def test_cve_cache_missing_returns_none(nv, tmp_path, monkeypatch):
    monkeypatch.setattr(nv.WebsiteRecon, "CVE_CACHE_DIR", str(tmp_path / "cve2"), raising=False)
    assert nv.WebsiteRecon._cve_cache_read("CVE-0000-0000") is None
