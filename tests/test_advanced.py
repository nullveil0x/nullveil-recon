"""Tests for the v3.9.0 advanced-scanning features.

Covers three additive capabilities, all read-only / defensive by design:

* **WAF evasion** (``EvasionTransport``) — coherent browser-profile rotation
  + request jitter, honouring injected auth headers.
* **Mass scanning** (``_expand_targets`` / ``_load_targets_file``) — target
  lists and CIDR expansion with a safety cap.
* **Deep-accuracy verification** (``--verify``) — a second, independent probe
  drops non-reproducing path findings.
"""
import httpx
import pytest


# ----------------------------------------------------------------- evasion
class _Spy(httpx.AsyncBaseTransport):
    """Capture the headers of every request that reaches the wire."""

    def __init__(self):
        self.seen = []

    async def handle_async_request(self, request):
        self.seen.append(dict(request.headers))
        return httpx.Response(200, text="ok")


def test_evasion_profiles_are_coherent(nv):
    """Every built-in profile pairs a UA with a matching Accept-Language and
    Sec-Ch-Ua, so rotation never produces an obvious header mish-mash."""
    for prof in nv._EVASION_PROFILES:
        assert "User-Agent" in prof
        assert "Accept" in prof
        ua = prof["User-Agent"]
        if "Chrome" in ua:
            assert "Sec-Ch-Ua" in prof, "Chrome profile must carry Sec-Ch-Ua"
            assert "Sec-Ch-Ua-Platform" in prof


def test_evasion_levels_table(nv):
    for level in ("none", "light", "stealth"):
        assert level in nv._EVASION_LEVELS
    assert nv._EVASION_LEVELS["none"]["rotate"] is False
    assert nv._EVASION_LEVELS["light"]["rotate"] is True
    assert nv._EVASION_LEVELS["stealth"]["jitter"] > nv._EVASION_LEVELS["light"]["jitter"]


async def test_evasion_rotates_and_keeps_auth(nv):
    """Rotation produces distinct, coherent profiles and never strips the
    session header the auth layer injected."""
    spy = _Spy()
    t = nv.EvasionTransport(spy, level="light", rotate_every=1)
    async with httpx.AsyncClient(transport=t, base_url="http://x.test") as c:
        await c.get("/", headers={"Authorization": "Bearer secret"})
        await c.get("/a", headers={"Authorization": "Bearer secret"})

    assert t.requests == 2
    uas = {h.get("user-agent") for h in spy.seen}
    assert len(uas) == 2, "profile should rotate every request"
    for h in spy.seen:
        assert h.get("authorization") == "Bearer secret"
        assert h.get("accept-language"), "coherent profile must set Accept-Language"


async def test_evasion_none_is_pass_through(nv):
    """Level 'none' must not touch the request at all."""
    spy = _Spy()
    t = nv.EvasionTransport(spy, level="none")
    async with httpx.AsyncClient(transport=t, base_url="http://x.test",
                                 headers={"User-Agent": "NULLVEIL-test"}) as c:
        await c.get("/")
    assert spy.seen[0].get("user-agent") == "NULLVEIL-test"


class _StopLoop(httpx.AsyncBaseTransport):
    async def handle_async_request(self, request):
        raise httpx.ConnectError("stop")


async def test_evasion_composes_under_retry(nv):
    """The evasion layer must sit *below* the retry layer: retries re-enter it."""
    inner = _Spy()
    ev = nv.EvasionTransport(inner, level="light")
    rt = nv.RetryingTransport(ev, max_retries=2, base=0.0)
    async with httpx.AsyncClient(transport=rt, base_url="http://x.test") as c:
        await c.get("/")
    assert ev.requests == 1
    assert rt.retries == 0


# ------------------------------------------------------------ mass scanning
def test_expand_targets_dedupes_and_ignores_comments(nv):
    out = nv._expand_targets(["a.com, b.com", "a.com", "# comment", ""])
    assert out == ["a.com", "b.com"]


def test_expand_targets_cidr(nv):
    out = nv._expand_targets(["10.0.0.0/30"])
    assert out == ["10.0.0.1", "10.0.0.2"]


def test_expand_targets_keeps_urls_intact(nv):
    out = nv._expand_targets(["https://example.com/path"])
    assert out == ["https://example.com/path"]


def test_load_targets_file_and_cap(nv, tmp_path):
    p = tmp_path / "t.txt"
    p.write_text("# header\nexample.com\n10.0.0.0/29\n")
    out = nv._load_targets_file(str(p), max_hosts=100)
    assert "example.com" in out
    assert "10.0.0.1" in out        # /29 expands to 6 usable hosts
    assert len(out) == 7

    capped = nv._load_targets_file(str(p), max_hosts=3)
    assert len(capped) == 3


def test_load_targets_file_missing_exits(nv):
    with pytest.raises(SystemExit):
        nv._load_targets_file("/nonexistent/targets.txt")


# ----------------------------------------------------------- deep verify
class _VerifyMock(httpx.AsyncBaseTransport):
    """Root returns 200; everything else 404 — so any seeded 'flagged' path is
    a false positive that verification must drop."""

    async def handle_async_request(self, request):
        if request.url.path == "/":
            return httpx.Response(200, text="home")
        return httpx.Response(404)


async def test_verify_drops_false_positives(nv):
    r = nv.WebsiteRecon("http://verify.test/", timeout=5)
    r.client = httpx.AsyncClient(transport=_VerifyMock(),
                                 base_url="http://verify.test")
    r._ensure_sem()
    r.deep_verify = True
    r.results["paths"] = [
        {"path": "/admin", "status": 200, "flagged": True},
        {"path": "/backup.sql", "status": 200, "flagged": True},
    ]
    await r._verify_findings_pass()
    stats = r.results["verify_stats"]
    assert stats["tested"] == 2
    assert stats["dropped"] == 2
    assert stats["paths_removed"] == 2
    assert r.results["paths"] == []
    assert len(r.results["verify_dropped"]) == 2
    await r.client.aclose()


async def test_verify_keeps_reproducing_findings(nv):
    class _Keep(httpx.AsyncBaseTransport):
        async def handle_async_request(self, request):
            return httpx.Response(200, text="ok")   # nothing ever 404s

    r = nv.WebsiteRecon("http://keep.test/", timeout=5)
    r.client = httpx.AsyncClient(transport=_Keep(), base_url="http://keep.test")
    r._ensure_sem()
    r.results["paths"] = [{"path": "/admin", "status": 200, "flagged": True}]
    await r._verify_findings_pass()
    assert r.results["verify_stats"]["kept"] == 1
    assert len(r.results["paths"]) == 1


async def test_verify_does_not_drop_on_network_error(nv):
    """A network hiccup is inconclusive — findings must be kept, never hidden."""
    r = nv.WebsiteRecon("http://down.test/", timeout=2)
    r.client = httpx.AsyncClient(transport=_StopLoop(), base_url="http://down.test")
    r._ensure_sem()
    r.results["paths"] = [{"path": "/admin", "status": 200, "flagged": True}]
    await r._verify_findings_pass()
    assert r.results["verify_stats"]["unknown"] == 1
    assert len(r.results["paths"]) == 1, "inconclusive must not drop findings"


def test_batch_score_matches_risk_meter(nv):
    report = {
        "secrets": [], "missing_security_headers": [], "paths": [],
        "summary": {},
    }
    out = nv._batch_score(report)
    assert isinstance(out, dict)
    assert 0 <= out["score"] <= 100
    assert nv._batch_score(None) is None
