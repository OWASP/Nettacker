from unittest.mock import patch

from nettacker.core.lib.smb import SmbLibrary
from tests.common import TestCase

SMB_SESSION_PORT = 445


class MockSmbConnectionObject:
    def __init__(self, remoteName="", remoteHost="", sess_port=SMB_SESSION_PORT):
        self._sess_port = sess_port
        self._remoteHost = remoteHost
        self._remoteName = remoteName

    def login(self, user, password, domain="", lmhash="", nthash=""):
        return None


class TestSmbMethod(TestCase):
    @patch("nettacker.core.lib.smb.create_connection")
    def test_brute_force_password(self, mock_smb_connection):
        library = SmbLibrary()
        HOST = "dc-01"
        PORT = 445
        USERNAME = "Administrator"
        PASSWORD = "Password@123"

        mock_smb_connection.return_value = MockSmbConnectionObject(
            HOST, remoteHost=HOST, sess_port=PORT
        )
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
