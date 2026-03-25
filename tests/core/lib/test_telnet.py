from unittest.mock import MagicMock, patch

import pytest

from nettacker.core.lib.telnet import TelnetEngine, TelnetLibrary

HOST = "192.168.1.1"
PORT = 23
USERNAME = "admin"
PASSWORD = "secret"
TIMEOUT = 10


class TestTelnetLibrary:
    @patch.object(TelnetLibrary, "client")
    def test_brute_force_success(self, mock_telnet_cls):
        mock_conn = MagicMock()
        mock_telnet_cls.return_value = mock_conn

        library = TelnetLibrary()
        result = library.brute_force(
            host=HOST, port=PORT, username=USERNAME, password=PASSWORD, timeout=TIMEOUT
        )

        mock_telnet_cls.assert_called_once_with(HOST, PORT, TIMEOUT)
        mock_conn.read_until.assert_any_call(b"login: ")
        mock_conn.write.assert_any_call(USERNAME.encode("utf-8") + b"\n")
        mock_conn.read_until.assert_any_call(b"Password: ")
        mock_conn.write.assert_any_call(PASSWORD.encode("utf-8") + b"\n")
        mock_conn.close.assert_called_once()

        assert result == {
            "host": HOST,
            "port": PORT,
            "username": USERNAME,
            "password": PASSWORD,
        }

    @patch.object(TelnetLibrary, "client")
    def test_brute_force_connection_refused(self, mock_telnet_cls):
        mock_telnet_cls.side_effect = ConnectionRefusedError("Connection refused")

        library = TelnetLibrary()
        with pytest.raises(ConnectionRefusedError):
            library.brute_force(
                host=HOST, port=PORT, username=USERNAME, password=PASSWORD, timeout=TIMEOUT
            )

    @patch.object(TelnetLibrary, "client")
    def test_brute_force_timeout(self, mock_telnet_cls):
        mock_telnet_cls.side_effect = TimeoutError("Connection timed out")

        library = TelnetLibrary()
        with pytest.raises(TimeoutError):
            library.brute_force(
                host=HOST, port=PORT, username=USERNAME, password=PASSWORD, timeout=TIMEOUT
            )


class TestTelnetEngine:
    def test_engine_uses_telnet_library(self):
        assert TelnetEngine.library is TelnetLibrary
