import smtplib
from unittest.mock import MagicMock, call, patch

import pytest

from nettacker.core.lib.smtp import SmtpEngine, SmtpLibrary
from nettacker.core.lib.smtps import SmtpsEngine, SmtpsLibrary

HOST = "smtp.example.com"
PORT = 25
USERNAME = "user@example.com"
PASSWORD = "secret"  # noqa: S105
TIMEOUT = 10


class TestSmtpLibrary:
    @patch.object(SmtpLibrary, "client")
    def test_brute_force_success(self, mock_smtp_cls):
        mock_conn = MagicMock()
        mock_smtp_cls.return_value = mock_conn

        library = SmtpLibrary()
        result = library.brute_force(
            host=HOST, port=PORT, username=USERNAME, password=PASSWORD, timeout=TIMEOUT
        )

        mock_smtp_cls.assert_called_once_with(HOST, PORT, timeout=TIMEOUT)
        mock_conn.login.assert_called_once_with(USERNAME, PASSWORD)
        mock_conn.close.assert_called_once()

        assert result == {
            "host": HOST,
            "port": PORT,
            "username": USERNAME,
            "password": PASSWORD,
        }

    @patch.object(SmtpLibrary, "client")
    def test_brute_force_auth_error(self, mock_smtp_cls):
        mock_conn = MagicMock()
        mock_smtp_cls.return_value = mock_conn
        mock_conn.login.side_effect = smtplib.SMTPAuthenticationError(
            535, b"Authentication failed"
        )

        library = SmtpLibrary()
        with pytest.raises(smtplib.SMTPAuthenticationError):
            library.brute_force(
                host=HOST, port=PORT, username=USERNAME, password=PASSWORD, timeout=TIMEOUT
            )

    @patch.object(SmtpLibrary, "client")
    def test_brute_force_connection_refused(self, mock_smtp_cls):
        mock_smtp_cls.side_effect = ConnectionRefusedError("Connection refused")

        library = SmtpLibrary()
        with pytest.raises(ConnectionRefusedError):
            library.brute_force(
                host=HOST, port=PORT, username=USERNAME, password=PASSWORD, timeout=TIMEOUT
            )


class TestSmtpEngine:
    def test_engine_uses_smtp_library(self):
        assert SmtpEngine.library is SmtpLibrary


class TestSmtpsLibrary:
    @patch.object(SmtpsLibrary, "client")
    def test_brute_force_success(self, mock_smtp_cls):
        mock_conn = MagicMock()
        mock_smtp_cls.return_value = mock_conn

        library = SmtpsLibrary()
        result = library.brute_force(
            host=HOST, port=587, username=USERNAME, password=PASSWORD, timeout=TIMEOUT
        )

        mock_smtp_cls.assert_called_once_with(HOST, 587, timeout=TIMEOUT)
        mock_conn.starttls.assert_called_once()
        mock_conn.login.assert_called_once_with(USERNAME, PASSWORD)
        mock_conn.close.assert_called_once()

        assert result == {
            "host": HOST,
            "port": 587,
            "username": USERNAME,
            "password": PASSWORD,
        }

    @patch.object(SmtpsLibrary, "client")
    def test_starttls_called_before_login(self, mock_smtp_cls):
        mock_conn = MagicMock()
        mock_smtp_cls.return_value = mock_conn

        manager = MagicMock()
        mock_conn.starttls = manager.starttls
        mock_conn.login = manager.login

        library = SmtpsLibrary()
        library.brute_force(
            host=HOST, port=587, username=USERNAME, password=PASSWORD, timeout=TIMEOUT
        )

        expected_calls = [call.starttls(), call.login(USERNAME, PASSWORD)]
        assert manager.mock_calls[:2] == expected_calls

    @patch.object(SmtpsLibrary, "client")
    def test_brute_force_starttls_failure(self, mock_smtp_cls):
        mock_conn = MagicMock()
        mock_smtp_cls.return_value = mock_conn
        mock_conn.starttls.side_effect = smtplib.SMTPException("STARTTLS extension not supported")

        library = SmtpsLibrary()
        with pytest.raises(smtplib.SMTPException):
            library.brute_force(
                host=HOST, port=587, username=USERNAME, password=PASSWORD, timeout=TIMEOUT
            )


class TestSmtpsEngine:
    def test_engine_uses_smtps_library(self):
        assert SmtpsEngine.library is SmtpsLibrary
