"""Tests for the v3.9.0 automation layer (Step C).

* **Plugin system** (``--plugin``) — load external Python modules and fold
  their findings into the scan.
* **Headless JSON API** (``--serve-api``) — ``_api_scan`` argument building +
  the request handler's contract (health, errors, validation).
"""
import json


# ------------------------------------------------------------------ plugins
def test_plugin_manager_loads_and_runs(nv, tmp_path):
    p = tmp_path / "myplug.py"
    p.write_text(
        "NAME = 't'\n"
        "VERSION = '1'\n"
        "def run(ctx):\n"
        "    return [('HIGH', 'custom-check', 'plugin found something')]\n"
    )
    pm = nv.PluginManager().load_paths([str(p)])
    assert pm.summary()["loaded"] == 1
    assert pm.summary()["errors"] == []

    from collections import defaultdict
    recon = nv.WebsiteRecon("http://x.test/")
    recon.results = defaultdict(list)
    ctx = nv.PluginContext(recon)
    pm.run_all(ctx)
    assert len(recon.results["plugin_findings"]) == 1
    assert recon.results["plugin_findings"][0][0] == "HIGH"
    assert pm.summary()["findings"] == 1
    assert recon.results["plugin_runs"][0]["ok"] is True


def test_plugin_manager_missing_file_records_error(nv):
    pm = nv.PluginManager().load_paths(["/nonexistent/plugin.py"])
    assert pm.summary()["loaded"] == 0
    assert "not found" in pm.summary()["errors"][0]


def test_plugin_manager_rejects_module_without_run(nv, tmp_path):
    p = tmp_path / "norun.py"
    p.write_text("X = 1\n")
    pm = nv.PluginManager().load_paths([str(p)])
    assert pm.summary()["loaded"] == 0
    assert "no callable run" in pm.summary()["errors"][0]


def test_plugin_run_error_is_isolated(nv, tmp_path):
    """A crashing plugin must not abort the scan — it is recorded and skipped."""
    p = tmp_path / "boom.py"
    p.write_text("def run(ctx):\n    raise RuntimeError('kaboom')\n")
    pm = nv.PluginManager().load_paths([str(p)])

    from collections import defaultdict
    recon = nv.WebsiteRecon("http://x.test/")
    recon.results = defaultdict(list)
    pm.run_all(nv.PluginContext(recon))
    assert recon.results["plugin_runs"][0]["ok"] is False
    assert "kaboom" in recon.results["plugin_runs"][0]["error"]
    assert pm.summary()["errors"]


def test_plugin_string_findings_become_info(nv, tmp_path):
    p = tmp_path / "strplug.py"
    p.write_text("def run(ctx):\n    return ['just a note']\n")
    pm = nv.PluginManager().load_paths([str(p)])
    from collections import defaultdict
    recon = nv.WebsiteRecon("http://x.test/")
    recon.results = defaultdict(list)
    pm.run_all(nv.PluginContext(recon))
    assert recon.results["plugin_findings"][0][0] == "INFO"


def test_bundled_example_plugin_loads(nv):
    import os
    root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    pm = nv.PluginManager().load_paths([os.path.join(root, "examples", "plugin_example.py")])
    assert pm.summary()["loaded"] == 1
    assert pm.summary()["errors"] == []


def test_plugin_findings_reach_collect(nv):
    """plugin_findings must be picked up by the reporting pipeline."""
    from collections import defaultdict
    recon = nv.WebsiteRecon("http://x.test/")
    recon.results = defaultdict(list)
    recon.results["plugin_findings"] = [("HIGH", "custom-check", "hi")]
    F = recon._collect_findings()
    assert any(f[1] == "custom-check" for f in F)
    assert any(f[3] == "plugin" for f in F)


# -------------------------------------------------------------- JSON API
def test_api_scan_returns_full_report(nv, monkeypatch):
    captured = {}

    def _fake_scan_target(args, indices, ports, target, out_suffix=""):
        captured["modules"] = indices
        captured["verify"] = args.verify
        captured["evade"] = args.evade
        captured["retries"] = args.retries
        return {"target": target, "ok": True, "score": {}, "report": {"target": target, "ok": 1}}

    monkeypatch.setattr(nv, "_scan_target", _fake_scan_target)
    out = nv._api_scan({"target": "example.com", "modules": "http,paths",
                        "verify": True, "evade": "light", "retries": 5}, "example.com")
    assert out == {"target": "example.com", "ok": 1}
    assert captured["modules"] == sorted(nv.parse_attack_list("http,paths"))
    assert captured["verify"] is True
    assert captured["evade"] == "light"
    assert captured["retries"] == 5


def test_api_scan_defaults_modules_to_all(nv, monkeypatch):
    captured = {}

    def _fake(args, indices, ports, target, out_suffix=""):
        captured["modules"] = indices
        return {"report": {"ok": 1}}

    monkeypatch.setattr(nv, "_scan_target", _fake)
    nv._api_scan({"target": "x.com"}, "x.com")
    assert captured["modules"] == list(nv.ALL_MODULE_NUMS)


def test_api_scan_parses_ports_and_wordlist(nv, monkeypatch):
    captured = {}

    def _fake(args, indices, ports, target, out_suffix=""):
        captured["ports"] = ports
        captured["wordlist"] = args.wordlist
        return {"report": {}}

    monkeypatch.setattr(nv, "_scan_target", _fake)
    nv._api_scan({"target": "x.com", "ports": "80,443,8080",
                  "wordlist": "w.txt"}, "x.com")
    assert captured["ports"] == [80, 443, 8080]
    assert captured["wordlist"] == "w.txt"


def test_api_server_end_to_end(nv, monkeypatch):
    """Boot the real handler and exercise health + validation + a mocked scan."""
    import socket
    import threading
    import time
    from http.client import HTTPConnection
    from http.server import ThreadingHTTPServer

    monkeypatch.setattr(nv, "_scan_target",
                        lambda *a, **k: {"report": {"target": "x.com", "ok": 1}})

    captured = {}
    real_server = ThreadingHTTPServer

    class _Capture(real_server):
        def __init__(self, addr, handler):
            super().__init__(addr, handler)
            captured["httpd"] = self

    monkeypatch.setattr(nv, "ThreadingHTTPServer", _Capture, raising=False)
    # serve_api imports ThreadingHTTPServer locally inside the function, so patch
    # the import source too.
    import http.server as _hs
    monkeypatch.setattr(_hs, "ThreadingHTTPServer", _Capture)

    s = socket.socket()
    s.bind(("127.0.0.1", 0))
    port = s.getsockname()[1]
    s.close()

    def _run():
        nv.serve_api(host="127.0.0.1", port=port)

    t = threading.Thread(target=_run, daemon=True)
    t.start()
    for _ in range(60):
        if "httpd" in captured:
            break
        time.sleep(0.05)
    assert "httpd" in captured, "API server did not start"
    httpd = captured["httpd"]

    try:
        conn = HTTPConnection("127.0.0.1", port, timeout=5)
        conn.request("GET", "/health")
        r = conn.getresponse()
        assert r.status == 200
        assert json.loads(r.read())["version"] == nv.__version__

        conn.request("POST", "/scan", body=json.dumps({"target": "x.com"}),
                     headers={"Content-Type": "application/json"})
        r = conn.getresponse()
        assert r.status == 200
        assert json.loads(r.read())["ok"] == 1

        conn.request("POST", "/scan", body=json.dumps({}),
                     headers={"Content-Type": "application/json"})
        r = conn.getresponse()
        assert r.status == 400

        conn.request("GET", "/report?id=../../etc/passwd")
        r = conn.getresponse()
        assert r.status == 400, "path traversal in id must be rejected"
    finally:
        httpd.shutdown()
        httpd.server_close()
