import ftplib
from unittest.mock import MagicMock, patch

import pytest

from nettacker.core.lib.ftp import FtpEngine, FtpLibrary


class TestFtpLibraryBruteForce:
    """
    Tests for FtpLibrary.brute_force().
    FtpLibrary uses self.client (= ftplib.FTP) to create connections.
    We patch FtpLibrary.client directly to avoid real network calls.
    """

    def test_successful_login_returns_dict(self):
        with patch.object(FtpLibrary, "client") as mock_ftp_class:
            mock_connection = MagicMock()
            mock_ftp_class.return_value = mock_connection

            lib = FtpLibrary()
            result = lib.brute_force(
                host="192.168.1.1",
                port=21,
                username="admin",
                password="admin123",
                timeout=10,
            )

            assert result["host"] == "192.168.1.1"
            assert result["port"] == 21
            assert result["username"] == "admin"
            assert result["password"] == "admin123"

    def test_successful_login_calls_connect(self):
        with patch.object(FtpLibrary, "client") as mock_ftp_class:
            mock_connection = MagicMock()
            mock_ftp_class.return_value = mock_connection

            lib = FtpLibrary()
            lib.brute_force("10.0.0.1", 21, "user", "pass", 5)

            mock_connection.connect.assert_called_once_with("10.0.0.1", 21)

    def test_successful_login_calls_login(self):
        with patch.object(FtpLibrary, "client") as mock_ftp_class:
            mock_connection = MagicMock()
            mock_ftp_class.return_value = mock_connection

            lib = FtpLibrary()
            lib.brute_force("10.0.0.1", 21, "user", "pass", 5)

            mock_connection.login.assert_called_once_with("user", "pass")

    def test_successful_login_calls_close(self):
        with patch.object(FtpLibrary, "client") as mock_ftp_class:
            mock_connection = MagicMock()
            mock_ftp_class.return_value = mock_connection

            lib = FtpLibrary()
            lib.brute_force("10.0.0.1", 21, "user", "pass", 5)

            mock_connection.close.assert_called_once()

    def test_result_contains_all_keys(self):
        with patch.object(FtpLibrary, "client") as mock_ftp_class:
            mock_ftp_class.return_value = MagicMock()

            lib = FtpLibrary()
            result = lib.brute_force("10.0.0.1", 21, "user", "pass", 5)

            assert "host" in result
            assert "port" in result
            assert "username" in result
            assert "password" in result

    def test_wrong_password_raises_error_perm(self):
        with patch.object(FtpLibrary, "client") as mock_ftp_class:
            mock_connection = MagicMock()
            mock_connection.login.side_effect = ftplib.error_perm("530 Login incorrect")
            mock_ftp_class.return_value = mock_connection

            lib = FtpLibrary()
            with pytest.raises(ftplib.error_perm):
                lib.brute_force("10.0.0.1", 21, "user", "wrongpass", 5)

    def test_connection_timeout_raises_exception(self):
        with patch.object(FtpLibrary, "client") as mock_ftp_class:
            mock_connection = MagicMock()
            mock_connection.connect.side_effect = TimeoutError("Connection timed out")
            mock_ftp_class.return_value = mock_connection

            lib = FtpLibrary()
            with pytest.raises(TimeoutError):
                lib.brute_force("10.0.0.1", 21, "user", "pass", 1)

    def test_timeout_passed_to_ftp_constructor(self):
        with patch.object(FtpLibrary, "client") as mock_ftp_class:
            mock_ftp_class.return_value = MagicMock()

            lib = FtpLibrary()
            lib.brute_force("10.0.0.1", 21, "user", "pass", timeout=30)

            mock_ftp_class.assert_called_once_with(timeout=30)


class TestFtpEngine:
    """
    FtpEngine inherits from BaseEngine and sets library = FtpLibrary.
    """

    def test_engine_has_correct_library(self):
        assert FtpEngine.library == FtpLibrary

    def test_engine_instantiates(self):
        engine = FtpEngine()
        assert engine is not None
