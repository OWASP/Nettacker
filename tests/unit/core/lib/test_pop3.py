import poplib
from unittest.mock import call, MagicMock, patch


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
        mock_connection = MagicMock(spec=poplib.POP3)
        mock_pop3_class.return_value = mock_connection
        yield mock_pop3_class, mock_connection


class TestPop3Engine:
    def test_engine_has_correct_library(self):
        assert Pop3Engine.library == Pop3Library

    def test_engine_instantiates(self):
        engine = Pop3Engine()
        assert engine.library == Pop3Library


class TestPop3Library:
    def test_successful_login_returns_dict(self, pop3_client_mocks):
        mock_pop3_class, _ = pop3_client_mocks
        lib = Pop3Library()
        result = lib.brute_force(HOST, PORT, USER, PASS, TIMEOUT)

        mock_pop3_class.assert_called_once_with(HOST, port=PORT, timeout=TIMEOUT)
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

        mock_connection.assert_has_calls(
            [
                call.user(USER),
                call.pass_(PASS),
                call.quit(),
            ],
            any_order=False,
        )