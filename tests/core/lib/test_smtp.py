from unittest.mock import MagicMock, patch

from nettacker.core.lib.smtp import SmtpEngine, SmtpLibrary
from nettacker.core.lib.smtps import SmtpsEngine, SmtpsLibrary


def test_smtp_engine_has_library():
    engine = SmtpEngine()
    assert engine.library == SmtpLibrary


def test_smtp_library_is_defined():
    lib = SmtpLibrary()
    assert hasattr(lib, "brute_force")
    assert callable(lib.brute_force)


def test_smtps_engine_has_library():
    engine = SmtpsEngine()
    assert engine.library == SmtpsLibrary


def test_smtps_library_is_defined():
    lib = SmtpsLibrary()
    assert hasattr(lib, "brute_force")
    assert callable(lib.brute_force)
