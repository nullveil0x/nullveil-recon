"""Tests for the plugin rule engine (--rules) and the retrying transport.

These pin down the behaviours that let external YAML/JSON rules extend the
built-in CVE + misconfig knowledge, and the transparent 429/503 retry layer.
"""
import asyncio
import json

import httpx


# ---------------------------------------------------------------- RuleSet loading
def test_ruleset_loads_json_cve_and_misconfig(nv, tmp_path):
    f = tmp_path / "r.json"
    f.write_text(json.dumps({
        "cve": [{"product": "nginx", "mode": "lt", "version": [1, 21, 0],
                 "id": "CVE-X", "severity": "high", "title": "t"}],
        "misconfig": [{"path": "/x", "match": "ok", "severity": "LOW",
                       "id": "id-x", "title": "tx"}],
    }))
    rs = nv.RuleSet().load_paths([str(f)])
    assert len(rs.cve) == 1 and len(rs.misconfig) == 1
    prod, major, mode, boundary, cid, sev, title = rs.cve[0]
    assert (prod, mode, boundary, cid, sev) == ("nginx", "lt", (1, 21, 0), "CVE-X", "HIGH")
    assert rs.summary()["files"] == [str(f)]


def test_ruleset_loads_directory_recursively(nv, tmp_path):
    (tmp_path / "sub").mkdir()
    (tmp_path / "a.json").write_text(json.dumps({"cve": [
        {"product": "php", "mode": "lt", "version": "7.4.30", "id": "C1"}]}))
    (tmp_path / "sub" / "b.json").write_text(json.dumps({"misconfig": [
        {"path": "/b"}]}))
    rs = nv.RuleSet().load_paths([str(tmp_path)])
    assert len(rs.cve) == 1 and len(rs.misconfig) == 1


def test_ruleset_accepts_bare_list(nv, tmp_path):
    f = tmp_path / "l.json"
    f.write_text(json.dumps([{"product": "apache", "mode": "eq", "version": [2, 4, 49],
                              "id": "C2", "severity": "CRITICAL"}]))
    rs = nv.RuleSet().load_paths([str(f)])
    assert len(rs.cve) == 1 and rs.cve[0][5] == "CRITICAL"


def test_ruleset_skips_malformed_and_records_errors(nv, tmp_path):
    f = tmp_path / "bad.json"
    f.write_text(json.dumps({"cve": [{"product": "x"}],          # no version/id
                             "misconfig": [{"title": "no path"}]}))
    rs = nv.RuleSet().load_paths([str(f)])
    assert rs.cve == [] and rs.misconfig == []
    assert any("malformed" in e for e in rs.errors)


def test_ruleset_bad_regex_is_dropped_not_fatal(nv, tmp_path):
    f = tmp_path / "rx.json"
    f.write_text(json.dumps({"misconfig": [{"path": "/x", "match": "([unclosed"}]}))
    rs = nv.RuleSet().load_paths([str(f)])
    assert len(rs.misconfig) == 1
    assert rs.misconfig[0][1] is None      # bad regex silently cleared


def test_ruleset_missing_path_reports_error(nv):
    rs = nv.RuleSet().load_paths(["/definitely/not/here-zzz"])
    assert any("not found" in e for e in rs.errors)


def test_ruleset_version_parsing_variants(nv, tmp_path):
    f = tmp_path / "v.json"
    f.write_text(json.dumps({"cve": [
        {"product": "a", "mode": "lt", "version": "2.4.49", "id": "A"},
        {"product": "b", "mode": "lt", "version": [2, "4", "49"], "id": "B"},
        {"product": "c", "mode": "lt", "version": "1.x", "id": "C"},
    ]}))
    rs = nv.RuleSet().load_paths([str(f)])
    by = {r[0]: r[3] for r in rs.cve}
    assert by["a"] == (2, 4, 49) and by["b"] == (2, 4, 49) and by["c"] == (1,)


# ---------------------------------------------------------------- rule merging
def test_active_rules_merge_builtins_and_external(nv, recon):
    rs = nv.RuleSet()
    rs.cve = [(("ext"), None, "lt", (1, 0), "CVE-EXT", "LOW", "t")]
    rs.misconfig = [("/ext", None, "LOW", "ext-id", "tx")]
    recon.ruleset = rs
    assert len(recon._active_cve_rules()) == len(recon.CVE_RULES) + 1
    assert len(recon._active_misconfig_probes()) == len(recon.MISCONFIG_PROBES) + 1


def test_active_rules_without_ruleset_is_builtin_only(nv, recon):
    recon.ruleset = None
    assert recon._active_cve_rules() == list(recon.CVE_RULES)
    assert recon._active_misconfig_probes() == list(recon.MISCONFIG_PROBES)


# ---------------------------------------------------------------- retrying transport
class _Flaky(httpx.AsyncBaseTransport):
    """Returns 429 for the first N requests, then 200."""
    def __init__(self, fails, status=429, retry_after=None):
        self.fails = fails
        self.status = status
        self.calls = 0
        self.retry_after = retry_after

    async def handle_async_request(self, request):
        self.calls += 1
        if self.calls <= self.fails:
            h = {}
            if self.retry_after is not None:
                h["retry-after"] = str(self.retry_after)
            return httpx.Response(self.status, headers=h, request=request)
        return httpx.Response(200, request=request)


def _run(coro):
    return asyncio.get_event_loop().run_until_complete(coro) if False else asyncio.run(coro)


def test_retry_transport_recovers_after_429(nv):
    async def go():
        base = _Flaky(fails=2)
        tr = nv.RetryingTransport(base, max_retries=3, base=0.001)
        c = httpx.AsyncClient(transport=tr)
        r = await c.get("http://x.test/")
        await c.aclose()
        return r, base, tr
    r, base, tr = asyncio.run(go())
    assert r.status_code == 200
    assert base.calls == 3 and tr.retries == 2


def test_retry_transport_gives_up_after_budget(nv):
    async def go():
        base = _Flaky(fails=99)
        tr = nv.RetryingTransport(base, max_retries=2, base=0.001)
        c = httpx.AsyncClient(transport=tr)
        r = await c.get("http://x.test/")
        await c.aclose()
        return r, base
    r, base = asyncio.run(go())
    assert r.status_code == 429        # returns the last response, no exception
    assert base.calls == 3             # 1 + 2 retries


def test_retry_transport_honours_retry_after_header(nv):
    async def go():
        base = _Flaky(fails=1, retry_after=0)
        tr = nv.RetryingTransport(base, max_retries=2, base=5.0)   # big base
        c = httpx.AsyncClient(transport=tr)
        r = await c.get("http://x.test/")
        await c.aclose()
        return r, base
    # retry-after: 0 overrides the 5s base delay → test stays fast
    r, base = asyncio.run(go())
    assert r.status_code == 200 and base.calls == 2


def test_retry_transport_disabled_when_zero_retries(nv):
    async def go():
        base = _Flaky(fails=1)
        tr = nv.RetryingTransport(base, max_retries=0, base=0.001)
        c = httpx.AsyncClient(transport=tr)
        r = await c.get("http://x.test/")
        await c.aclose()
        return r, base
    r, base = asyncio.run(go())
    assert r.status_code == 429 and base.calls == 1
