from unittest.mock import MagicMock, patch
import pytest

from nettacker.core.lib.pop3 import Pop3Engine, Pop3Library

HOST = "10.0.0.1"
PORT = 110
USER = "testuser"
PASS = "testpass"
TIMEOUT = 5


@pytest.fixture
def pop3_client_mocks():
    with patch.object(Pop3Library, "client") as mock_pop3_class:
        mock_connection = MagicMock()
        mock_pop3_class.return_value = mock_connection
        yield mock_pop3_class, mock_connection


class TestPop3Engine:
    def test_engine_has_correct_library(self):
        assert Pop3Engine.library == Pop3Library

    def test_engine_instantiates(self):
        engine = Pop3Engine()
        assert engine is not None


class TestPop3Library:
    def test_successful_login_returns_dict(self, pop3_client_mocks):
        _, _ = pop3_client_mocks
        lib = Pop3Library()
        result = lib.brute_force(HOST, PORT, USER, PASS, TIMEOUT)

        assert result == {
            "host": HOST,
            "port": PORT,
            "username": USER,
            "password": PASS,
        }

    def test_successful_login_calls_user_pass_quit(self, pop3_client_mocks):
        _, mock_connection = pop3_client_mocks
        lib = Pop3Library()
        lib.brute_force(HOST, PORT, USER, PASS, TIMEOUT)

        mock_connection.user.assert_called_once_with(USER)
        mock_connection.pass_.assert_called_once_with(PASS)
        mock_connection.quit.assert_called_once()