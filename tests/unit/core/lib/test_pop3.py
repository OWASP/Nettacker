from unittest.mock import patch

from nettacker.core.lib.pop3 import Pop3Library
from tests.unit.common import TestCase

POP3_SESSION_PORT = 110


class MockPop3ConnectionObject:
    def __init__(self, *args, **kwargs):
        pass

    def user(self, username):
        pass

    def pass_(self, password):
        pass

    def quit(self):
        pass


class TestPop3Method(TestCase):
    @patch("nettacker.core.lib.pop3.Pop3Library.client")
    def test_brute_force_password(self, mock_pop3_client):
        library = Pop3Library()
        HOST = "dc-01"
        PORT = POP3_SESSION_PORT
        USERNAME = "root"
        PASSWORD = "Password@123"
        TIMEOUT = 5

        mock_pop3_client.return_value = MockPop3ConnectionObject()

        self.assertEqual(
            library.brute_force(
                host=HOST,
                port=PORT,
                username=USERNAME,
                password=PASSWORD,
                timeout=TIMEOUT,
            ),
            {
                "host": HOST,
                "port": PORT,
                "username": USERNAME,
                "password": PASSWORD,
            },
        )

    @patch("nettacker.core.lib.pop3.Pop3Library.client")
    def test_brute_force_no_password(self, mock_pop3_client):
        library = Pop3Library()
        HOST = "dc-01"
        PORT = POP3_SESSION_PORT
        USERNAME = "root"
        PASSWORD = ""
        TIMEOUT = 5

        mock_pop3_client.return_value = MockPop3ConnectionObject()

        self.assertEqual(
            library.brute_force(
                host=HOST,
                port=PORT,
                username=USERNAME,
                password=PASSWORD,
                timeout=TIMEOUT,
            ),
            {
                "host": HOST,
                "port": PORT,
                "username": USERNAME,
                "password": PASSWORD,
            },
        )
