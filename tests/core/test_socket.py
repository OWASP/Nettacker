from unittest.mock import patch

from core.lib.socket import create_tcp_socket, SocketLibrary

from tests.common import TestCase


class MockConnectionObject:
    def __init__(self, peername, version=None):
        self.Peername = peername
        self.Version = version

    def getpeername(self):
        return self.Peername

    def version(self):
        return self.Version


class Mockx509Object:
    def __init__(self, issuer, subject, is_expired, expire_date, signing_algo):
        self.issuer = issuer
        self.subject = subject
        self.expired = is_expired
        self.expire_date = expire_date
        self.signature_algorithm = signing_algo

    def get_issuer(self):
        return self.issuer

    def get_subject(self):
        return self.subject

    def has_expired(self):
        return self.expired

    def get_notAfter(self):
        return self.expire_date

    def get_signature_algorithm(self):
        return self.signature_algorithm


class TestSSLMethods(TestCase):
    @patch("socket.socket")
    @patch("ssl.wrap_socket")
    def test_create_tcp_socket(self, mock_wrap, mock_socket):
        HOST = "example.com"
        PORT = 80
        TIMEOUT = 60

        create_tcp_socket(HOST, PORT, TIMEOUT)
        socket_instance = mock_socket.return_value
        socket_instance.settimeout.assert_called_with(TIMEOUT)
        socket_instance.connect.assert_called_with((HOST, PORT))
        mock_wrap.assert_called_with(socket_instance)

    @patch("core.lib.socket.is_weak_cipher_suite")
    @patch("core.lib.socket.create_tcp_socket")
    def test_ssl_version_scan_good(self, mock_connection, mock_cipher_check):
        library = SocketLibrary()
        HOST = "example.com"
        PORT = 80
        TIMEOUT = 60

        mock_connection.return_value = (MockConnectionObject(HOST, "TLSv1.3"), True)
        mock_cipher_check.return_value = False
        self.assertEqual(
            library.ssl_version_scan(HOST, PORT, TIMEOUT),
            {
                "ssl_flag": True,
                "service": "http",
                "weak_version": False,
                "ssl_version": "TLSv1.3",
                "peer_name": "example.com",
                "weak_cipher_suite": False,
            },
        )

        mock_connection.return_value = (MockConnectionObject(HOST), False)
        self.assertEqual(
            library.ssl_version_scan(HOST, PORT, TIMEOUT),
            {
                "ssl_flag": False,
                "service": "http",
                "peer_name": "example.com",
            },
        )

    @patch("core.lib.socket.is_weak_cipher_suite")
    @patch("core.lib.socket.create_tcp_socket")
    def test_ssl_version_scan_bad(self, mock_connection, mock_cipher_check):
        library = SocketLibrary()
        HOST = "example.com"
        PORT = 80
        TIMEOUT = 60

        mock_connection.return_value = (MockConnectionObject(HOST, "TLSv1.1"), True)
        mock_cipher_check.return_value = True
        self.assertEqual(
            library.ssl_version_scan(HOST, PORT, TIMEOUT),
            {
                "ssl_flag": True,
                "service": "http",
                "weak_version": True,
                "ssl_version": "TLSv1.1",
                "weak_cipher_suite": True,
                "peer_name": "example.com",
            },
        )

    @patch("core.lib.socket.create_tcp_socket")
    @patch("core.lib.socket.crypto.load_certificate")
    @patch("core.lib.socket.ssl.get_server_certificate")
    def test_ssl_certificate_scan_good(self, mock_certificate, mock_x509, mock_connection):
        library = SocketLibrary()
        HOST = "example.com"
        PORT = 80
        TIMEOUT = 60

        mock_connection.return_value = (MockConnectionObject(HOST, "TLSv1.3"), True)
        mock_x509.return_value = Mockx509Object(
            is_expired=False,
            issuer="test_issuer",
            subject="test_subject",
            signing_algo="test_algo",
            expire_date=b"20250619153045Z",
        )
        self.assertEqual(
            library.ssl_certificate_scan(HOST, PORT, TIMEOUT),
            {
                "expired": False,
                "ssl_flag": True,
                "service": "http",
                "self_signed": False,
                "expiring_soon": False,
                "weak_signing_algo": False,
                "peer_name": "example.com",
            },
        )

        mock_connection.return_value = (MockConnectionObject(HOST), False)
        self.assertEqual(
            library.ssl_certificate_scan(HOST, PORT, TIMEOUT),
            {
                "service": "http",
                "ssl_flag": False,
                "peer_name": "example.com",
            },
        )
        mock_certificate.assert_called_with((HOST, PORT))

    @patch("core.lib.socket.create_tcp_socket")
    @patch("core.lib.socket.crypto.load_certificate")
    @patch("core.lib.socket.ssl.get_server_certificate")
    def test_ssl_certificate_scan_bad(self, mock_certificate, mock_x509, mock_connection):
        library = SocketLibrary()
        HOST = "example.com"
        PORT = 80
        TIMEOUT = 60

        mock_connection.return_value = (MockConnectionObject(HOST, "TLSv1.3"), True)
        mock_x509.return_value = Mockx509Object(
            is_expired=True,
            issuer="test_issuer_subject",
            subject="test_issuer_subject",
            signing_algo="sha1",
            expire_date=b"20240619153045Z",
        )
        self.assertEqual(
            library.ssl_certificate_scan(HOST, PORT, TIMEOUT),
            {
                "expired": True,
                "ssl_flag": True,
                "service": "http",
                "self_signed": True,
                "expiring_soon": True,
                "weak_signing_algo": True,
                "peer_name": "example.com",
            },
        )
