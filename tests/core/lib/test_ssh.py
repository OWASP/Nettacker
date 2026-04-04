from unittest.mock import MagicMock, patch

import pytest
from paramiko import AutoAddPolicy
from paramiko.auth_strategy import NoneAuth, Password

from nettacker.core.lib.ssh import SshEngine, SshLibrary

HOST = "ssh.example.com"
PORT = 22
USERNAME = "admin"
PASSWORD = "secret"  # noqa: S105


class TestSshLibrary:
    @patch.object(SshLibrary, "client")
    def test_brute_force_with_password(self, mock_ssh_cls):
        mock_conn = MagicMock()
        mock_ssh_cls.return_value = mock_conn

        library = SshLibrary()
        result = library.brute_force(host=HOST, port=PORT, username=USERNAME, password=PASSWORD)

        mock_ssh_cls.assert_called_once()
        mock_conn.set_missing_host_key_policy.assert_called_once()

        connect_kwargs = mock_conn.connect.call_args
        assert connect_kwargs.kwargs["hostname"] == HOST
        assert connect_kwargs.kwargs["port"] == PORT
        assert isinstance(connect_kwargs.kwargs["auth_strategy"], Password)

        assert result == {
            "host": HOST,
            "port": PORT,
            "username": USERNAME,
            "password": PASSWORD,
        }

    @patch.object(SshLibrary, "client")
    def test_brute_force_without_password(self, mock_ssh_cls):
        mock_conn = MagicMock()
        mock_ssh_cls.return_value = mock_conn

        library = SshLibrary()
        result = library.brute_force(host=HOST, port=PORT, username=USERNAME, password="")

        connect_kwargs = mock_conn.connect.call_args
        assert isinstance(connect_kwargs.kwargs["auth_strategy"], NoneAuth)

        assert result == {
            "host": HOST,
            "port": PORT,
            "username": USERNAME,
            "password": "",
        }

    @patch.object(SshLibrary, "client")
    def test_brute_force_none_password_uses_none_auth(self, mock_ssh_cls):
        mock_conn = MagicMock()
        mock_ssh_cls.return_value = mock_conn

        library = SshLibrary()
        result = library.brute_force(host=HOST, port=PORT, username=USERNAME, password=None)

        connect_kwargs = mock_conn.connect.call_args
        assert isinstance(connect_kwargs.kwargs["auth_strategy"], NoneAuth)

    @patch.object(SshLibrary, "client")
    def test_brute_force_connection_refused(self, mock_ssh_cls):
        mock_conn = MagicMock()
        mock_ssh_cls.return_value = mock_conn
        mock_conn.connect.side_effect = ConnectionRefusedError("Connection refused")

        library = SshLibrary()
        with pytest.raises(ConnectionRefusedError):
            library.brute_force(host=HOST, port=PORT, username=USERNAME, password=PASSWORD)

    @patch.object(SshLibrary, "client")
    def test_brute_force_sets_auto_add_policy(self, mock_ssh_cls):
        mock_conn = MagicMock()
        mock_ssh_cls.return_value = mock_conn

        library = SshLibrary()
        library.brute_force(host=HOST, port=PORT, username=USERNAME, password=PASSWORD)

        policy_arg = mock_conn.set_missing_host_key_policy.call_args[0][0]
        assert isinstance(policy_arg, AutoAddPolicy)


class TestSshEngine:
    def test_engine_uses_ssh_library(self):
        assert SshEngine.library is SshLibrary
