import poplib
from unittest.mock import MagicMock, patch

import pytest

from nettacker.core.lib.pop3 import Pop3Engine, Pop3Library
from nettacker.core.lib.pop3s import Pop3sEngine, Pop3sLibrary

HOST = "mail.example.com"
PORT = 110
USERNAME = "user@example.com"
PASSWORD = "secret"  # noqa: S105
TIMEOUT = 10


class TestPop3Library:
    @patch.object(Pop3Library, "client")
    def test_brute_force_success(self, mock_pop3_cls):
        mock_conn = MagicMock()
        mock_pop3_cls.return_value = mock_conn

        library = Pop3Library()
        result = library.brute_force(
            host=HOST, port=PORT, username=USERNAME, password=PASSWORD, timeout=TIMEOUT
        )

        mock_pop3_cls.assert_called_once_with(HOST, port=PORT, timeout=TIMEOUT)
        mock_conn.user.assert_called_once_with(USERNAME)
        mock_conn.pass_.assert_called_once_with(PASSWORD)
        mock_conn.quit.assert_called_once()

        assert result == {
            "host": HOST,
            "port": PORT,
            "username": USERNAME,
            "password": PASSWORD,
        }

    @patch.object(Pop3Library, "client")
    def test_brute_force_auth_error(self, mock_pop3_cls):
        mock_conn = MagicMock()
        mock_pop3_cls.return_value = mock_conn
        mock_conn.pass_.side_effect = poplib.error_proto("-ERR Authentication failed")

        library = Pop3Library()
        with pytest.raises(poplib.error_proto):
            library.brute_force(
                host=HOST, port=PORT, username=USERNAME, password=PASSWORD, timeout=TIMEOUT
            )

    @patch.object(Pop3Library, "client")
    def test_brute_force_connection_refused(self, mock_pop3_cls):
        mock_pop3_cls.side_effect = ConnectionRefusedError("Connection refused")

        library = Pop3Library()
        with pytest.raises(ConnectionRefusedError):
            library.brute_force(
                host=HOST, port=PORT, username=USERNAME, password=PASSWORD, timeout=TIMEOUT
            )


class TestPop3Engine:
    def test_engine_uses_pop3_library(self):
        assert Pop3Engine.library is Pop3Library


class TestPop3sLibrary:
    def test_inherits_from_pop3_library(self):
        assert issubclass(Pop3sLibrary, Pop3Library)

    def test_uses_pop3_ssl_client(self):
        assert Pop3sLibrary.client is poplib.POP3_SSL

    @patch.object(Pop3sLibrary, "client")
    def test_brute_force_success(self, mock_pop3s_cls):
        mock_conn = MagicMock()
        mock_pop3s_cls.return_value = mock_conn

        library = Pop3sLibrary()
        result = library.brute_force(
            host=HOST, port=995, username=USERNAME, password=PASSWORD, timeout=TIMEOUT
        )

        mock_pop3s_cls.assert_called_once_with(HOST, port=995, timeout=TIMEOUT)
        mock_conn.user.assert_called_once_with(USERNAME)
        mock_conn.pass_.assert_called_once_with(PASSWORD)
        mock_conn.quit.assert_called_once()

        assert result == {
            "host": HOST,
            "port": 995,
            "username": USERNAME,
            "password": PASSWORD,
        }


class TestPop3sEngine:
    def test_inherits_from_pop3_engine(self):
        assert issubclass(Pop3sEngine, Pop3Engine)

    def test_engine_uses_pop3s_library(self):
        assert Pop3sEngine.library is Pop3sLibrary
