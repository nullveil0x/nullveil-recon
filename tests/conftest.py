"""Shared pytest fixtures for the NULLVEIL Recon test suite.

The whole tool lives in a single ``nullveil_recon.py`` module, so we load it by
path with ``importlib`` — no install step required for unit tests. Network is
never touched: modules are exercised against an in-process mock HTTP server or
with their pure helpers called directly.
"""
import importlib.util
import os
import socket
import sys
import threading

import pytest

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
MODULE_PATH = os.path.join(ROOT, "nullveil_recon.py")


def pytest_collection_modifyitems(items):
    """Run ``async def`` tests without requiring pytest-asyncio.

    Each coroutine test is wrapped so pytest sees a normal callable; the body
    runs under a fresh ``asyncio.run()`` event loop."""
    import asyncio
    import inspect

    for item in items:
        fn = getattr(item, "obj", None)
        if fn is not None and inspect.iscoroutinefunction(fn):
            def _make(coro_fn):
                def _sync(*args, **kwargs):
                    return asyncio.run(coro_fn(*args, **kwargs))
                return _sync
            item.obj = _make(fn)


def _load_module():
    spec = importlib.util.spec_from_file_location("nullveil_recon", MODULE_PATH)
    mod = importlib.util.module_from_spec(spec)
    sys.modules["nullveil_recon"] = mod
    spec.loader.exec_module(mod)
    return mod


@pytest.fixture(scope="session")
def nv():
    """The loaded nullveil_recon module (session-scoped, imported once)."""
    return _load_module()


@pytest.fixture()
def recon(nv, tmp_path, monkeypatch):
    """A WebsiteRecon instance pointed at the local mock, with history redirected
    to a temp dir so tests never touch the real ~/.nullveil/history."""
    monkeypatch.setattr(nv.WebsiteRecon, "HISTORY_DIR",
                        str(tmp_path / "history"), raising=False)
    monkeypatch.setattr(nv.WebsiteRecon, "CVE_CACHE_DIR",
                        str(tmp_path / "cve_cache"), raising=False)
    r = nv.WebsiteRecon("http://127.0.0.1:1/")
    r.no_history = True
    return r


def _free_port():
    s = socket.socket()
    s.bind(("127.0.0.1", 0))
    port = s.getsockname()[1]
    s.close()
    return port


@pytest.fixture(scope="session")
def mock_target():
    """Start the bundled mock target on a free port; yield its base URL."""
    from tests.mock_target import make_server

    port = _free_port()
    httpd = make_server("127.0.0.1", port)
    t = threading.Thread(target=httpd.serve_forever, daemon=True)
    t.start()
    try:
        yield f"http://127.0.0.1:{port}"
    finally:
        httpd.shutdown()
        httpd.server_close()
