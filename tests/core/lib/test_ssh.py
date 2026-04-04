from unittest.mock import MagicMock, patch

from nettacker.core.lib.ssh import SshEngine, SshLibrary


def test_ssh_engine_has_library():
    engine = SshEngine()
    assert engine.library == SshLibrary


def test_ssh_library_is_defined():
    lib = SshLibrary()
    assert hasattr(lib, "brute_force")
    assert callable(lib.brute_force)
