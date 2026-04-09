import ftplib
from unittest.mock import MagicMock, patch

import pytest

from nettacker.core.lib.ftp import FtpEngine, FtpLibrary
from nettacker.core.lib.ftps import FtpsEngine, FtpsLibrary

HOST = "ftp.example.com"
PORT = 21
USERNAME = "admin"
PASSWORD = "secret"  # noqa: S105
TIMEOUT = 10


class TestFtpLibrary:
    @patch.object(FtpLibrary, "client")
    def test_brute_force_success(self, mock_ftp_cls):
        mock_conn = MagicMock()
        mock_ftp_cls.return_value = mock_conn

        library = FtpLibrary()
        result = library.brute_force(
            host=HOST, port=PORT, username=USERNAME, password=PASSWORD, timeout=TIMEOUT
        )

        mock_ftp_cls.assert_called_once_with(timeout=TIMEOUT)
        mock_conn.connect.assert_called_once_with(HOST, PORT)
        mock_conn.login.assert_called_once_with(USERNAME, PASSWORD)
        mock_conn.close.assert_called_once()

        assert result == {
            "host": HOST,
            "port": PORT,
            "username": USERNAME,
            "password": PASSWORD,
        }

    @patch.object(FtpLibrary, "client")
    def test_brute_force_login_failure(self, mock_ftp_cls):
        mock_conn = MagicMock()
        mock_ftp_cls.return_value = mock_conn
        mock_conn.login.side_effect = ftplib.error_perm("530 Login incorrect")

        library = FtpLibrary()
        with pytest.raises(ftplib.error_perm):
            library.brute_force(
                host=HOST, port=PORT, username=USERNAME, password=PASSWORD, timeout=TIMEOUT
            )

    @patch.object(FtpLibrary, "client")
    def test_brute_force_connection_refused(self, mock_ftp_cls):
        mock_conn = MagicMock()
        mock_ftp_cls.return_value = mock_conn
        mock_conn.connect.side_effect = ConnectionRefusedError("Connection refused")

        library = FtpLibrary()
        with pytest.raises(ConnectionRefusedError):
            library.brute_force(
                host=HOST, port=PORT, username=USERNAME, password=PASSWORD, timeout=TIMEOUT
            )


class TestFtpEngine:
    def test_engine_uses_ftp_library(self):
        assert FtpEngine.library is FtpLibrary


class TestFtpsLibrary:
    def test_inherits_from_ftp_library(self):
        assert issubclass(FtpsLibrary, FtpLibrary)

    def test_uses_ftp_tls_client(self):
        assert FtpsLibrary.client is ftplib.FTP_TLS

    @patch.object(FtpsLibrary, "client")
    def test_brute_force_success(self, mock_ftps_cls):
        mock_conn = MagicMock()
        mock_ftps_cls.return_value = mock_conn

        library = FtpsLibrary()
        result = library.brute_force(
            host=HOST, port=PORT, username=USERNAME, password=PASSWORD, timeout=TIMEOUT
        )

        mock_ftps_cls.assert_called_once_with(timeout=TIMEOUT)
        mock_conn.connect.assert_called_once_with(HOST, PORT)
        mock_conn.login.assert_called_once_with(USERNAME, PASSWORD)
        mock_conn.close.assert_called_once()

        assert result == {
            "host": HOST,
            "port": PORT,
            "username": USERNAME,
            "password": PASSWORD,
        }


class TestFtpsEngine:
    def test_inherits_from_ftp_engine(self):
        assert issubclass(FtpsEngine, FtpEngine)

    def test_engine_uses_ftps_library(self):
        assert FtpsEngine.library is FtpsLibrary
