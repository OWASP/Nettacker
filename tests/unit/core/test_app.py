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
