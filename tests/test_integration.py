"""Integration tests: run real (read-only) modules against the in-process mock.

Modules are pointed at the bundled mock target; anything that shells out to
external binaries is avoided so the suite is deterministic and offline. This is
what makes the suite usable as a CI gate.
"""
import asyncio

import httpx


async def _run(nv, url, method, **attrs):
    r = nv.WebsiteRecon(url)
    r.no_history = True
    r.deep = False
    r.timeout = 5
    for k, v in attrs.items():
        setattr(r, k, v)
    try:
        await getattr(r, method)()
    finally:
        try:
            await r.client.aclose()
        except Exception:
            pass
    return r


def test_mock_target_is_reachable(mock_target):
    from tests.mock_target import _FAKE
    resp = httpx.get(mock_target + "/", timeout=5)
    assert resp.status_code == 200
    assert "Mock App" in resp.text
    js = httpx.get(mock_target + "/static/app.js", timeout=5).text
    assert _FAKE["aws"] in js  # masked AWS key the miner should catch


def test_http_recon_against_mock(nv, mock_target):
    r = asyncio.run(_run(nv, mock_target, "http_recon"))
    # module must complete without a crash recorded in errors
    assert not [e for e in r.results.get("errors", []) if "crashed" in e]
    assert r.results.get("http") is not None or r.scalar_results


def test_js_secret_miner_finds_keys_and_redacts(nv, mock_target):
    from tests.mock_target import _FAKE
    r = asyncio.run(_run(nv, mock_target, "js_secret_miner"))
    # The mock JS bundle is fetched from the page's <script src>.
    data = r.results.get("js_secret") or {}
    blob = str(data)
    assert data.get("secret_count", 0) >= 1, blob[:400]
    # detection succeeded, but raw credential values must never be retained
    assert not any(secret in blob for secret in _FAKE.values()), blob[:400]
    assert "…" in blob
    # masked JS secrets feed the same cross-module counter used by the report;
    # duplicate occurrences of one credential collapse to one row
    assert 1 <= len(r.results.get("secrets") or []) <= data.get("secret_count", 1)


def test_cloud_storage_enum_no_crash(nv, mock_target):
    r = asyncio.run(_run(nv, mock_target, "cloud_storage_enum"))
    assert not [e for e in r.results.get("errors", []) if "crashed" in e]
