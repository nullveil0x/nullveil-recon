"""Tests for module 50 — read-only vulnerability verification.

The engine proves *reachability* of a vulnerability class with benign markers;
it never sends an executable payload or extracts data. These tests pin both the
positive detections and — critically — the **false-positive behaviour**.
"""
import http.server
import threading

import pytest


# --------------------------------------------------------------- mock targets
class _VulnHandler(http.server.BaseHTTPRequestHandler):
    """A deliberately vulnerable target: raw reflection, SQL error leak, traversal."""

    def log_message(self, *a):
        pass

    def do_GET(self):
        from urllib.parse import urlparse, parse_qs
        qs = parse_qs(urlparse(self.path).query)
        q = (qs.get("q") or [""])[0]
        f = (qs.get("file") or [""])[0]
        if f:
            if "etc/passwd" in f or "etc%2fpasswd" in f:
                body = b"root:x:0:0:root:/root:/bin/bash\n"
                self.send_response(200)
                self.send_header("Content-Type", "text/plain")
                self.end_headers()
                self.wfile.write(body)
                return
            self.send_response(404)
            self.end_headers()
            return
        if "'" in q:
            body = f"Error: You have an error in your SQL syntax near '{q}' at line 1"
        else:
            body = f"<html><body>Search results for {q}</body></html>"   # RAW reflection
        self.send_response(200)
        self.send_header("Content-Type", "text/html")
        self.end_headers()
        self.wfile.write(body.encode())


class _SafeHandler(http.server.BaseHTTPRequestHandler):
    """A hardened target: HTML-escaped reflection, no SQL errors, no traversal."""

    def log_message(self, *a):
        pass

    def do_GET(self):
        import html
        from urllib.parse import urlparse, parse_qs
        qs = parse_qs(urlparse(self.path).query)
        q = (qs.get("q") or [""])[0]
        body = f"<html><body>Search results for {html.escape(q)}</body></html>"
        self.send_response(200)
        self.send_header("Content-Type", "text/html")
        self.end_headers()
        self.wfile.write(body.encode())


def _serve(handler):
    import socket
    s = socket.socket()
    s.bind(("127.0.0.1", 0))
    port = s.getsockname()[1]
    s.close()
    httpd = http.server.ThreadingHTTPServer(("127.0.0.1", port), handler)
    threading.Thread(target=httpd.serve_forever, daemon=True).start()
    return httpd, f"http://127.0.0.1:{port}"


@pytest.fixture()
def vuln_target():
    httpd, url = _serve(_VulnHandler)
    try:
        yield url
    finally:
        httpd.shutdown()
        httpd.server_close()


@pytest.fixture()
def safe_target():
    httpd, url = _serve(_SafeHandler)
    try:
        yield url
    finally:
        httpd.shutdown()
        httpd.server_close()


async def _run(nv, url):
    from collections import defaultdict
    r = nv.WebsiteRecon(url + "/", timeout=6)
    r.results = defaultdict(list)
    r.results["param"] = {"params": [
        {"url": url + "/", "method": "GET", "params": ["q", "file"]}]}
    r._ensure_sem()
    await r.vuln_verify()
    out = dict(r.results["vuln_verify"])
    findings = list(r.results["vuln_verify_findings"])
    await r.client.aclose()
    return out, findings


# --------------------------------------------------------------- detections
async def test_detects_all_three_classes(nv, vuln_target):
    vv, findings = await _run(nv, vuln_target)
    assert len(vv["xss"]) == 1, "raw reflection must be flagged as an XSS sink"
    assert len(vv["sqli"]) == 1, "marker + DB error must be flagged"
    assert len(vv["traversal"]) == 1, "system-file signature must be flagged"
    sevs = {f[0] for f in findings}
    assert "CRITICAL" in sevs


async def test_no_payload_is_ever_sent(nv, vuln_target):
    """The probe must be a benign marker, never a script tag or event handler."""
    probe = nv.WebsiteRecon.XSS_PROBE
    assert "<script" not in probe.lower()
    assert "onerror" not in probe.lower()
    assert "onload" not in probe.lower()
    assert "javascript:" not in probe.lower()
    assert nv.WebsiteRecon.XSS_MARKER in probe


# ------------------------------------------------------- false positives
async def test_safe_target_yields_no_findings(nv, safe_target):
    """HTML-encoded reflection and no SQL/traversal leak must produce nothing."""
    vv, findings = await _run(nv, safe_target)
    assert vv["xss"] == [], "encoded reflection must NOT be reported as a sink"
    assert vv["sqli"] == [], "no DB error => no SQL finding"
    assert vv["traversal"] == [], "no system-file signature => no traversal finding"
    assert findings == []


async def test_no_params_records_clean_note(nv):
    from collections import defaultdict
    r = nv.WebsiteRecon("http://noparams.test/", timeout=3)
    r.results = defaultdict(list)
    r.results["param"] = {"params": []}
    # avoid real network: patch the param-target collector to return nothing
    r._param_targets = lambda: []
    await r.vuln_verify()
    vv = r.results["vuln_verify"]
    assert vv["tested"] == 0
    assert "note" in vv
    await r.client.aclose()


def test_param_targets_prefers_discovered_inventory(nv):
    from collections import defaultdict
    r = nv.WebsiteRecon("http://x.test/", timeout=3)
    r.results = defaultdict(list)
    r.results["param"] = {"params": [
        {"url": "http://x.test/api", "method": "GET", "params": ["id", "next"]}]}
    got = r._param_targets()
    assert ("http://x.test/api", "id", "GET") in got
    assert ("http://x.test/api", "next", "GET") in got


def test_module_50_registered(nv):
    assert 50 in nv.MODULE_BY_NUM
    name, num, title, _desc = nv.MODULE_BY_NUM[50]
    assert name == "vulnverify"
    assert 50 in nv.parse_attack_list("vulnverify")
    assert 50 in nv.parse_attack_list("xss")
