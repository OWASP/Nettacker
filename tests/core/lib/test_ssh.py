from unittest.mock import patch

from nettacker.core.lib.ssh import SshLibrary
from tests.common import TestCase

SSH_SESSION_PORT = 22


class MockSshConnectionObject:
    def __init__(self, *args, **kwargs):
        pass

    def set_missing_host_key_policy(self, policy):
        return None

    def connect(self, **kwargs):
        return None


class TestSshMethod(TestCase):
    @patch("nettacker.core.lib.ssh.SshLibrary.client")
    def test_brute_force_password(self, mock_ssh_client):
        library = SshLibrary()
        HOST = "dc-01"
        PORT = SSH_SESSION_PORT
        USERNAME = "root"
        PASSWORD = "Password@123"

        mock_ssh_client.return_value = MockSshConnectionObject()

        self.assertEqual(
            library.brute_force(
                host=HOST,
                port=PORT,
                username=USERNAME,
                password=PASSWORD,
            ),
            {
                "host": HOST,
                "port": PORT,
                "username": USERNAME,
                "password": PASSWORD,
            },
        )

    @patch("nettacker.core.lib.ssh.SshLibrary.client")
    def test_brute_force_no_password(self, mock_ssh_client):
        library = SshLibrary()
        HOST = "dc-01"
        PORT = SSH_SESSION_PORT
        USERNAME = "root"
        PASSWORD = ""

        mock_ssh_client.return_value = MockSshConnectionObject()

        self.assertEqual(
            library.brute_force(
                host=HOST,
                port=PORT,
                username=USERNAME,
                password=PASSWORD,
            ),
            {
                "host": HOST,
                "port": PORT,
                "username": USERNAME,
                "password": PASSWORD,
            },
        )
