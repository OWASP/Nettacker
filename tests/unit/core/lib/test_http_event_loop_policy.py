import asyncio
import importlib
import sys
import types
from unittest.mock import MagicMock


def test_http_module_skips_uvloop_on_win32(monkeypatch):
    """On win32, importing http.py must never import uvloop or touch the event loop policy."""
    monkeypatch.setattr(sys, "platform", "win32")
    monkeypatch.delitem(sys.modules, "nettacker.core.lib.http", raising=False)
    monkeypatch.delitem(sys.modules, "uvloop", raising=False)

    policy_calls = []
    monkeypatch.setattr(
        asyncio, "set_event_loop_policy", lambda policy: policy_calls.append(policy)
    )

    importlib.import_module("nettacker.core.lib.http")

    assert policy_calls == []
    assert "uvloop" not in sys.modules


def test_http_module_sets_uvloop_policy_on_posix(monkeypatch):
    """Control test for the branch above: on a non-Windows platform, importing http.py
    must import uvloop and install its event loop policy. Uses a fake uvloop module
    since the real uvloop package is not installable on the Windows machine running
    this suite."""
    fake_policy = object()
    fake_uvloop = types.ModuleType("uvloop")
    fake_uvloop.EventLoopPolicy = MagicMock(return_value=fake_policy)
    monkeypatch.setitem(sys.modules, "uvloop", fake_uvloop)
    monkeypatch.setattr(sys, "platform", "linux")
    monkeypatch.delitem(sys.modules, "nettacker.core.lib.http", raising=False)

    policy_calls = []
    monkeypatch.setattr(
        asyncio, "set_event_loop_policy", lambda policy: policy_calls.append(policy)
    )

    importlib.import_module("nettacker.core.lib.http")

    fake_uvloop.EventLoopPolicy.assert_called_once()
    assert policy_calls == [fake_policy]
