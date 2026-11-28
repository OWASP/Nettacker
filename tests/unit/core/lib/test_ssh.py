from unittest.mock import patch

from paramiko.auth_strategy import Password
from paramiko.ssh_exception import AuthenticationException

from nettacker.core.lib.ssh import SshLibrary
from tests.unit.common import TestCase

SSH_SESSION_PORT = 22


class MockSshConnectionObject:
    def __init__(self, *args, **kwargs):
        self.connect_kwargs = None
        self.closed = False

    def set_missing_host_key_policy(self, policy):
        return None

    def connect(self, **kwargs):
        self.connect_kwargs = kwargs
        return None

    def close(self):
        self.closed = True


class MockRetryingTransport:
    def __init__(self):
        self.password_attempts = []

    def auth_password(self, username, password):
        self.password_attempts.append((username, password))
        if len(self.password_attempts) == 1:
            raise AuthenticationException("First password attempt rejected")
        return []


class MockRetryingSshConnectionObject(MockSshConnectionObject):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.transport = MockRetryingTransport()

    def connect(self, **kwargs):
        self.connect_kwargs = kwargs
        return kwargs["auth_strategy"].authenticate(self.transport)


class MockFailingSshConnectionObject(MockSshConnectionObject):
    def connect(self, **kwargs):
        self.connect_kwargs = kwargs
        raise AuthenticationException("Authentication failed")


class TestSshMethod(TestCase):
    @patch("nettacker.core.lib.ssh.SshLibrary.client")
    def test_brute_force_password(self, mock_ssh_client):
        library = SshLibrary()
        HOST = "dc-01"
        PORT = SSH_SESSION_PORT
        USERNAME = "root"
        PASSWORD = "Password@123"

        connection = MockSshConnectionObject()
        mock_ssh_client.return_value = connection

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
        self.assertIsInstance(connection.connect_kwargs["auth_strategy"], Password)
        self.assertNotIn("timeout", connection.connect_kwargs)
        self.assertTrue(connection.closed)

    @patch("nettacker.core.lib.ssh.SshLibrary.client")
    def test_brute_force_no_password(self, mock_ssh_client):
        library = SshLibrary()
        HOST = "dc-01"
        PORT = SSH_SESSION_PORT
        USERNAME = "root"
        PASSWORD = ""

        connection = MockSshConnectionObject()
        mock_ssh_client.return_value = connection

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
        self.assertTrue(connection.closed)

    def test_brute_force_rejects_invalid_authentication_attempts(self):
        library = SshLibrary()

        with self.assertRaises(ValueError):
            library.brute_force(
                host="dc-01",
                port=SSH_SESSION_PORT,
                username="root",
                password="Password@123",
                authentication_attempts=0,
            )

        with self.assertRaises(ValueError):
            library.brute_force(
                host="dc-01",
                port=SSH_SESSION_PORT,
                username="root",
                password="Password@123",
                authentication_attempts=-1,
            )

    @patch("nettacker.core.lib.ssh.SshLibrary.client")
    def test_brute_force_closes_connection_on_auth_failure(self, mock_ssh_client):
        connection = MockFailingSshConnectionObject()
        mock_ssh_client.return_value = connection

        with self.assertRaises(AuthenticationException):
            SshLibrary().brute_force(
                host="dc-01",
                port=SSH_SESSION_PORT,
                username="root",
                password="Password@123",
            )

        self.assertTrue(connection.closed)

    @patch("nettacker.core.lib.ssh.SshLibrary.client")
    def test_brute_force_retries_password_in_same_connection(self, mock_ssh_client):
        connection = MockRetryingSshConnectionObject()
        mock_ssh_client.return_value = connection

        result = SshLibrary().brute_force(
            host="dc-01",
            port=SSH_SESSION_PORT,
            username="alpine",
            password="A" * 257,
            authentication_attempts=2,
        )

        self.assertEqual(
            connection.transport.password_attempts,
            [("alpine", "A" * 257), ("alpine", "A" * 257)],
        )
        self.assertEqual(result["username"], "alpine")
        self.assertTrue(connection.closed)

    @patch("nettacker.core.lib.ssh.SshLibrary.client")
    def test_brute_force_enforces_timeout(self, mock_ssh_client):
        connection = MockSshConnectionObject()
        mock_ssh_client.return_value = connection

        SshLibrary().brute_force(
            host="dc-01",
            port=SSH_SESSION_PORT,
            username="root",
            password="Password@123",
            timeout=3,
        )

        self.assertEqual(connection.connect_kwargs["timeout"], 3)
        self.assertEqual(connection.connect_kwargs["banner_timeout"], 3)
        self.assertEqual(connection.connect_kwargs["auth_timeout"], 3)
        self.assertIsInstance(connection.connect_kwargs["auth_strategy"], Password)
        self.assertTrue(connection.closed)
