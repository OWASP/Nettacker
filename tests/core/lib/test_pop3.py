from unittest.mock import MagicMock, patch

from nettacker.core.lib.pop3 import Pop3Engine, Pop3Library
from nettacker.core.lib.pop3s import Pop3sEngine, Pop3sLibrary


def test_pop3_engine_has_library():
    engine = Pop3Engine()
    assert engine.library == Pop3Library


def test_pop3_library_is_defined():
    lib = Pop3Library()
    assert hasattr(lib, "brute_force")
    assert callable(lib.brute_force)


def test_pop3s_engine_has_library():
    engine = Pop3sEngine()
    assert engine.library == Pop3sLibrary


def test_pop3s_library_is_defined():
    lib = Pop3sLibrary()
    assert hasattr(lib, "brute_force")
    assert callable(lib.brute_force)
