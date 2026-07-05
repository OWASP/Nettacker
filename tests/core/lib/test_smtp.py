from unittest.mock import patch

from nettacker.core.lib.smtp import SmtpLibrary
from tests.common import TestCase

SMTP_SESSION_PORT = 25


class MockSmtpConnectionObject:
    def __init__(self, *args, **kwargs):
        pass

    def login(self, user, password):
        return None

    def close(self):
        return None


class TestSmtpMethod(TestCase):
    @patch("nettacker.core.lib.smtp.SmtpLibrary.client")
    def test_brute_force_password(self, mock_smtp_client):
        library = SmtpLibrary()
        host = "mail.example.com"
        port = SMTP_SESSION_PORT
        username = "admin"
        password = "Password@123"
        timeout = 5

        mock_smtp_client.return_value = MockSmtpConnectionObject()

        self.assertEqual(
            library.brute_force(
                host=host,
                port=port,
                username=username,
                password=password,
                timeout=timeout,
            ),
            {
                "host": host,
                "port": port,
                "username": username,
                "password": password,
            },
        )

        mock_smtp_client.assert_called_once_with(host, port, timeout=timeout)
