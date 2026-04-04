from unittest.mock import MagicMock, patch

from nettacker.core.lib.telnet import TelnetEngine, TelnetLibrary


def test_telnet_engine_has_library():
    engine = TelnetEngine()
    assert engine.library == TelnetLibrary


def test_telnet_library_is_defined():
    lib = TelnetLibrary()
    assert hasattr(lib, "brute_force")
    assert callable(lib.brute_force)
