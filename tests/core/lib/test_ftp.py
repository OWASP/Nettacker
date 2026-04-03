import ftplib
from unittest.mock import MagicMock, patch

import pytest

from nettacker.core.lib.ftp import FtpEngine, FtpLibrary

HOST = "10.0.0.1"
PORT = 21
USER = "user"
PASS = "pass"
TIMEOUT = 5
TIMEOUT_CONNECT_FAIL = 1
TIMEOUT_CLIENT = 30
WRONG_PASS = "wrongpass"


@pytest.fixture
def ftp_client_mocks():
    with patch.object(FtpLibrary, "client") as mock_ftp_class:
        mock_connection = MagicMock(spec=ftplib.FTP)
        mock_ftp_class.return_value = mock_connection
        yield mock_ftp_class, mock_connection


class TestFtpEngine:
    def test_engine_has_correct_library(self):
        assert FtpEngine.library == FtpLibrary

    def test_engine_instantiates(self):
        engine = FtpEngine()
        assert engine is not None


class TestFtpLibrary:
    @pytest.mark.parametrize(
        "host,port,username,password,timeout",
        [
            (HOST, PORT, USER, PASS, TIMEOUT),
            ("192.168.1.1", 2121, "admin", "x", 60),
        ],
    )
    def test_successful_login_returns_dict(
        self, ftp_client_mocks, host, port, username, password, timeout
    ):
        _, _ = ftp_client_mocks
        lib = FtpLibrary()
        result = lib.brute_force(host, port, username, password, timeout)
        assert result == {
            "host": host,
            "port": port,
            "username": username,
            "password": password,
        }

    def test_successful_login_calls_connect(self, ftp_client_mocks):
        _, mock_connection = ftp_client_mocks
        lib = FtpLibrary()
        lib.brute_force(HOST, PORT, USER, PASS, TIMEOUT)

        mock_connection.connect.assert_called_once_with(HOST, PORT)

    def test_successful_login_calls_login(self, ftp_client_mocks):
        _, mock_connection = ftp_client_mocks
        lib = FtpLibrary()
        lib.brute_force(HOST, PORT, USER, PASS, TIMEOUT)

        mock_connection.login.assert_called_once_with(USER, PASS)

    def test_successful_login_calls_close(self, ftp_client_mocks):
        _, mock_connection = ftp_client_mocks
        lib = FtpLibrary()
        lib.brute_force(HOST, PORT, USER, PASS, TIMEOUT)

        mock_connection.close.assert_called_once()

    @pytest.mark.parametrize(
        "exc",
        [
            pytest.param(TimeoutError("Connection timed out"), id="timeout_error"),
            pytest.param(OSError(51, "Network unreachable"), id="oserror"),
        ],
    )
    def test_connect_failure_propagates(self, ftp_client_mocks, exc):
        _, mock_connection = ftp_client_mocks
        mock_connection.connect.side_effect = exc

        lib = FtpLibrary()
        with pytest.raises(type(exc)):
            lib.brute_force(HOST, PORT, USER, PASS, TIMEOUT_CONNECT_FAIL)

        mock_connection.close.assert_called_once()

    @pytest.mark.parametrize(
        "exc",
        [
            pytest.param(ftplib.error_perm("530 Login incorrect"), id="error_perm"),
            pytest.param(ftplib.error_temp("421 Service not available"), id="error_temp"),
        ],
    )
    def test_login_ftp_error_propagates(self, ftp_client_mocks, exc):
        _, mock_connection = ftp_client_mocks
        mock_connection.login.side_effect = exc

        lib = FtpLibrary()
        with pytest.raises(type(exc)):
            lib.brute_force(HOST, PORT, USER, WRONG_PASS, TIMEOUT)

        mock_connection.close.assert_called_once()

    def test_timeout_passed_to_ftp_constructor(self, ftp_client_mocks):
        mock_ftp_class, _ = ftp_client_mocks
        lib = FtpLibrary()
        lib.brute_force(HOST, PORT, USER, PASS, timeout=TIMEOUT_CLIENT)

        mock_ftp_class.assert_called_once_with(timeout=TIMEOUT_CLIENT)
