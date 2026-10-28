import os
import socket
from types import SimpleNamespace
from unittest.mock import MagicMock

import pytest

from nettacker.config import Config
from nettacker.core import app as app_module
from nettacker.core.app import Nettacker


def _make_nettacker():
    """Build a Nettacker instance without running __init__, to unit-test methods in isolation."""
    return Nettacker.__new__(Nettacker)


def test_check_dependencies_accepts_win32(monkeypatch):
    """win32 must not trigger die_failure() -- this is the Windows-compat fix under test."""
    monkeypatch.setattr(app_module.sys, "platform", "win32")
    mock_die_failure = MagicMock(side_effect=SystemExit)
    monkeypatch.setattr(app_module, "die_failure", mock_die_failure)
    monkeypatch.setattr(Config.path, "tmp_dir", MagicMock())
    monkeypatch.setattr(Config.path, "results_dir", MagicMock())
    monkeypatch.setattr(Config.db, "engine", "sqlite")
    monkeypatch.setattr(Config.path, "new_database_file", MagicMock(exists=lambda: True))

    _make_nettacker().check_dependencies()

    mock_die_failure.assert_not_called()


def test_check_dependencies_rejects_unsupported_platform(monkeypatch):
    """Sanity check: an unsupported platform still dies, proving the win32 test above
    is actually exercising the platform allow-list rather than passing vacuously."""
    monkeypatch.setattr(app_module.sys, "platform", "not-a-real-platform")
    mock_die_failure = MagicMock(side_effect=SystemExit)
    monkeypatch.setattr(app_module, "die_failure", mock_die_failure)

    with pytest.raises(SystemExit):
        _make_nettacker().check_dependencies()

    mock_die_failure.assert_called_once()


def test_scan_target_completes_without_os_ex_ok(monkeypatch):
    """Simulates the real Windows condition (os.EX_OK does not exist) end-to-end
    through scan_target(). Would fail with AttributeError if os.EX_OK were ever
    reintroduced there instead of the plain 0 literal."""
    monkeypatch.delattr(os, "EX_OK", raising=False)

    real_socket_cls = socket.socket
    real_getaddrinfo = socket.getaddrinfo
    monkeypatch.setattr(
        app_module, "set_socks_proxy", lambda proxy: (real_socket_cls, real_getaddrinfo)
    )
    fake_module = MagicMock()
    monkeypatch.setattr(app_module, "Module", MagicMock(return_value=fake_module))
    monkeypatch.setattr(app_module, "log", MagicMock())

    nettacker = _make_nettacker()
    nettacker.arguments = SimpleNamespace(socks_proxy=None)

    result = nettacker.scan_target(
        target="127.0.0.1",
        module_name="port_scan",
        scan_id="scan-id",
        process_number=0,
        thread_number=0,
        total_number_threads=1,
    )

    assert result == 0
    fake_module.load.assert_called_once()
    fake_module.generate_loops.assert_called_once()
    fake_module.sort_loops.assert_called_once()
    fake_module.start.assert_called_once()
