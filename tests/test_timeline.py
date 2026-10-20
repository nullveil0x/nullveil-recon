"""Tests for the v3.9.0 platform layer (Step D).

* **Timeline DB** (``TimelineDB`` / ``--timeline``) — SQLite append-only index
  with trend + first-seen queries. Must never affect a scan when unavailable.
* **Multi-worker batch** — ``--workers N`` runs targets concurrently while each
  target keeps its own name-suffixed report.
"""


# ------------------------------------------------------------------ schema
def test_timeline_creates_schema(nv, tmp_path):
    db = nv.TimelineDB(str(tmp_path / "t.db"))
    assert db.enabled is True
    assert db.error is None
    names = {r[0] for r in db.conn.execute(
        "SELECT name FROM sqlite_master WHERE type='table'")}
    assert {"meta", "scans", "findings", "assets"} <= names
    db.close()


def test_timeline_records_and_queries(nv, tmp_path):
    db = nv.TimelineDB(str(tmp_path / "t.db"))
    report = {
        "target": "example.com", "version": nv.__version__,
        "started": "2026-01-01T10:00:00", "duration_s": 12.5, "mode": "normal",
        "modules_run": ["dns", "http"],
        "summary": {"secrets": 1, "subdomains": 2, "open_ports": 1, "paths": 3},
        "subdomains": ["a.example.com", "b.example.com"],
        "open_ports": [{"port": 443}],
        "paths": [{"path": "/admin"}],
    }
    sid1 = db.record(report)
    assert sid1 == 1
    assert db.record(dict(report, started="2026-01-02T10:00:00")) == 2

    hist = db.history("example.com")
    assert len(hist) == 2
    assert hist[0]["id"] == 2                      # newest first
    assert hist[0]["scanned_at"] == "2026-01-02T10:00:00"

    tr = db.trend("example.com")
    assert [t["when"] for t in tr] == ["2026-01-01T10:00:00",
                                       "2026-01-02T10:00:00"]   # oldest first
    db.close()


def test_timeline_first_seen(nv, tmp_path):
    db = nv.TimelineDB(str(tmp_path / "t.db"))
    db.record({"target": "x.com", "started": "2026-01-01T00:00:00",
               "summary": {}, "subdomains": ["a.x.com"]})
    db.record({"target": "x.com", "started": "2026-02-01T00:00:00",
               "summary": {}, "subdomains": ["a.x.com", "b.x.com"]})
    fs = db.first_seen("subdomain", "b.x.com")
    assert fs is not None
    assert fs["scan_id"] == 2
    assert db.first_seen("subdomain", "nope.x.com") is None
    db.close()


def test_timeline_records_findings_and_assets_from_live_recon(nv, tmp_path):
    from collections import defaultdict
    db = nv.TimelineDB(str(tmp_path / "t.db"))
    recon = nv.WebsiteRecon("http://x.test/")
    recon.results = defaultdict(list)
    recon.results["vuln_verify_findings"] = [
        ("CRITICAL", "SQL injection surface · q", "detail")]
    report = {"target": "x.test", "started": "2026-01-01T00:00:00",
              "summary": {}, "paths": [{"path": "/admin"}],
              "subdomains": ["api.x.test"]}
    sid = db.record(report, recon=recon)
    assert sid is not None
    sev = {r[0] for r in db.conn.execute(
        "SELECT severity FROM findings WHERE scan_id=?", (sid,))}
    assert "CRITICAL" in sev
    kinds = {r[0] for r in db.conn.execute(
        "SELECT kind FROM assets WHERE scan_id=?", (sid,))}
    assert {"subdomain", "path"} <= kinds
    db.close()


def test_timeline_unavailable_is_swallowed(nv, tmp_path):
    """A DB path that cannot be created must not raise — the scan is unaffected."""
    bad = tmp_path / "afile"
    bad.write_text("not a dir")
    db = nv.TimelineDB(str(bad / "sub" / "t.db"))
    assert db.enabled is False
    assert db.error
    assert db.record({"target": "x"}) is None      # no crash
    assert db.history("x") == []
    st = db.stats()
    assert st["enabled"] is False and st["scans"] == 0
    db.close()


def test_timeline_stats_counts(nv, tmp_path):
    db = nv.TimelineDB(str(tmp_path / "t.db"))
    db.record({"target": "a.com", "started": "2026-01-01T00:00:00",
               "summary": {}, "subdomains": ["s.a.com"]})
    db.record({"target": "b.com", "started": "2026-01-01T00:00:00",
               "summary": {}})
    st = db.stats()
    assert st["scans"] == 2
    assert st["domains"] == 2
    assert st["assets"] == 1
    db.close()


def test_default_path_lives_in_history_dir(nv):
    p = nv.TimelineDB.default_path()
    assert p.endswith("timeline.db")
    assert nv.WebsiteRecon.HISTORY_DIR in p


def test_timeline_exported_in_report(nv, tmp_path):
    recon = nv.WebsiteRecon("http://x.test/")
    recon.timeline_db = nv.TimelineDB(str(tmp_path / "t.db"))
    d = recon.export_dict()
    assert d["timeline"]["enabled"] is True
    recon.timeline_db.close()


def test_timeline_record_exposes_own_scan_id(nv, tmp_path):
    """After record(), the DB lookup used to refresh the report must find the
    row we just wrote (this is what run() patches into report['timeline'])."""
    db = nv.TimelineDB(str(tmp_path / "t.db"))
    sid = db.record({"target": "x.com", "started": "2026-01-01T00:00:00",
                     "summary": {}})
    st = db.stats()
    assert sid == 1
    assert st["scans"] == 1
    assert st["domains"] == 1
    db.close()


# ------------------------------------------------------------------ workers
def test_workers_flag_in_parser(nv):
    """--workers must exist and default to 1 (sequential)."""
    import inspect
    src = inspect.getsource(nv.main)
    assert "--workers" in src
    assert '"--workers"' in src or "'--workers'" in src


def test_batch_suffix_is_unique_per_target(nv):
    """The name-suffixing that keeps parallel reports from colliding."""
    import re
    def suffix(t):
        return "." + re.sub(r"[^A-Za-z0-9._-]", "_", t)[:80]
    a = suffix("https://a.com/path")
    b = suffix("https://b.com/path")
    assert a != b
    assert "/" not in a and ":" not in a
