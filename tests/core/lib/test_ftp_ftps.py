from unittest.mock import MagicMock, patch

from nettacker.core.lib.ftp import FtpEngine, FtpLibrary
from nettacker.core.lib.ftps import FtpsEngine, FtpsLibrary


def test_ftp_engine_has_library():
    engine = FtpEngine()
    assert engine.library == FtpLibrary


def test_ftp_library_is_defined():
    lib = FtpLibrary()
    assert hasattr(lib, "brute_force")
    assert callable(lib.brute_force)


def test_ftps_engine_inherits_ftp():
    engine = FtpsEngine()
    assert engine.library == FtpsLibrary


def test_ftps_library_is_defined():
    lib = FtpsLibrary()
    assert hasattr(lib, "brute_force")
    assert callable(lib.brute_force)
