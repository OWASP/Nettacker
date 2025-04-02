#!/usr/bin/env python

import ssl
from unittest.mock import patch, MagicMock
from nettacker.core.lib.ssl import (
    SslEngine,
    SslLibrary,
    create_tcp_socket,
    is_weak_hash_algo,
    is_weak_ssl_version,
    is_weak_cipher_suite,
)
from tests.common import TestCase


class MockConnectionObject:
    def __init__(self, peername, version=None):
        self.Peername = peername
        self.Version = version

    def getpeername(self):
        return self.Peername

    def version(self):
        return self.Version


class SubjectObject:
    def __init__(self, subject="subject"):
        self.subject = subject

    def get_components(self):
        return [(b"component", str.encode(self.subject))]


class IssuerObject:
    def __init__(self, issuer="issuer"):
        self.issuer = issuer

    def get_components(self):
        return [(b"component", str.encode(self.issuer))]


class Mockx509Object:
    def __init__(self, issuer, subject, is_expired, expire_date, activation_date, signing_algo):
        self.issuer = IssuerObject(issuer)
        self.subject = SubjectObject(subject)
        self.expired = is_expired
        self.expire_date = expire_date
        self.activation_date = activation_date
        self.signature_algorithm = signing_algo

    def get_issuer(self): return self.issuer
    def get_subject(self): return self.subject
    def has_expired(self): return self.expired
    def get_notAfter(self): return self.expire_date
    def get_notBefore(self): return self.activation_date
    def get_signature_algorithm(self): return self.signature_algorithm


class Responses:
    ssl_weak_version_vuln = {
        "ssl_version": ["TLSv1"],
        "weak_version": True,
        "ssl_flag": True,
        "issuer": "NA",
        "subject": "NA",
        "expiration_date": "NA",
    }

    ssl_certificate_expired = {
        "expired": True,
        "expiration_date": "2100-12-07 15:30:45",
        "subject": "component=subject",
        "not_activated": False,
        "activation_date": "2023-12-07 15:30:45",
        "expiring_soon": True,
        "ssl_flag": True,
    }

    ssl_certificate_deactivated = {
        "expired": False,
        "expiration_date": "2100-12-07 15:30:45",
        "expiring_soon": False,
        "not_activated": True,
        "activation_date": "2100-12-07 15:30:45",
        "subject": "component=subject",
        "ssl_flag": True,
    }

    ssl_off = {"ssl_flag": False}


class Substeps:
    ssl_weak_version_vuln = {
        "method": "ssl_version_and_cipher_scan",
        "response": {
            "condition_type": "or",
            "conditions": {
                "grouped_conditions": {
                    "condition_type": "and",
                    "conditions": {
                        "weak_version": {"reverse": False},
                        "ssl_version": {"reverse": False},
                        "issuer": {"reverse": False},
                        "subject": {"reverse": False},
                        "expiration_date": {"reverse": False},
                    },
                }
            },
        },
    }

    ssl_certificate_expired_vuln = {
        "method": "ssl_certificate_scan",
        "response": {
            "condition_type": "or",
            "conditions": {
                "grouped_conditions_1": {
                    "condition_type": "and",
                    "conditions": {
                        "expired": {"reverse": False},
                        "expiration_date": {"reverse": False},
                        "subject": {"reverse": False},
                    },
                },
                "grouped_conditions_2": {
                    "condition_type": "and",
                    "conditions": {
                        "not_activated": {"reverse": False},
                        "activation_date": {"reverse": False},
                        "subject": {"reverse": False},
                    },
                },
            },
        },
    }


class TestSocketMethod(TestCase):
    @patch("socket.socket")
    def test_create_tcp_socket(self, mock_socket):
        """Test TCP socket creation with SSL"""
        HOST = "example.com"
        PORT = 443
        TIMEOUT = 60

        mock_sock_instance = MagicMock()
        mock_socket.return_value = mock_sock_instance

        # Mock SSL context
        mock_context = MagicMock()
        mock_wrapped = MagicMock()
        mock_context.wrap_socket.return_value = mock_wrapped
        
        with patch('ssl.create_default_context', return_value=mock_context):
            result = create_tcp_socket(HOST, PORT, TIMEOUT)
            
            # Verify SSL wrapping was called
            mock_context.wrap_socket.assert_called_with(
                mock_sock_instance,
                server_hostname=HOST
            )
            self.assertEqual(result, (mock_wrapped, True))

        # Verify common socket operations
        mock_sock_instance.settimeout.assert_called_with(TIMEOUT)
        mock_sock_instance.connect.assert_called_with((HOST, PORT))

    @patch("nettacker.core.lib.ssl.is_weak_cipher_suite")
    @patch("nettacker.core.lib.ssl.is_weak_ssl_version")
    @patch("nettacker.core.lib.ssl.create_tcp_socket")
    def test_ssl_version_and_cipher_scan(self, mock_connection, mock_ssl_check, mock_cipher_check):
        library = SslLibrary()
        HOST = "example.com"
        PORT = 443
        TIMEOUT = 60

        # Test modern protocol
        mock_connection.return_value = (MockConnectionObject(HOST, "TLSv1.3"), True)
        mock_ssl_check.return_value = ("TLSv1.3", False)
        mock_cipher_check.return_value = (["HIGH"], False)
        result = library.ssl_version_and_cipher_scan(HOST, PORT, TIMEOUT)
        self.assertEqual(result['ssl_version'], "TLSv1.3")
        self.assertFalse(result['weak_version'])

        # Test weak protocol
        mock_connection.return_value = (MockConnectionObject(HOST, "TLSv1.1"), True)
        mock_ssl_check.return_value = ("TLSv1.1", True)
        mock_cipher_check.return_value = (["LOW"], True)
        result = library.ssl_version_and_cipher_scan(HOST, PORT, TIMEOUT)
        self.assertEqual(result['ssl_version'], "TLSv1.1")
        self.assertTrue(result['weak_version'])

        # Test non-SSL connection
        mock_connection.return_value = (MockConnectionObject(HOST), False)
        result = library.ssl_version_and_cipher_scan(HOST, PORT, TIMEOUT)
        self.assertFalse(result['ssl_flag'])

    @patch("nettacker.core.lib.ssl.create_tcp_socket")
    @patch("nettacker.core.lib.ssl.is_weak_hash_algo")
    @patch("nettacker.core.lib.ssl.crypto.load_certificate")
    @patch("nettacker.core.lib.ssl.ssl.get_server_certificate")
    def test_ssl_certificate_scan(self, mock_cert, mock_x509, mock_hash, mock_conn):
        library = SslLibrary()
        HOST = "example.com"
        PORT = 443
        TIMEOUT = 60

        # Test valid certificate
        mock_conn.return_value = (MockConnectionObject(HOST), True)
        mock_x509.return_value = Mockx509Object(
            "issuer", "subject", False, b"21001207153045Z", b"20231207153045Z", "SHA256"
        )
        mock_hash.return_value = False
        result = library.ssl_certificate_scan(HOST, PORT, TIMEOUT)
        self.assertEqual(result['expiration_date'], "2100-12-07 15:30:45")
        self.assertEqual(result['activation_date'], "2023-12-07 15:30:45")
        self.assertFalse(result['expired'])

        # Test expired certificate
        mock_x509.return_value = Mockx509Object(
            "issuer", "subject", True, b"20231207153045Z", b"20221207153045Z", "SHA1"
        )
        mock_hash.return_value = True
        result = library.ssl_certificate_scan(HOST, PORT, TIMEOUT)
        self.assertTrue(result['expired'])
        self.assertTrue(result['weak_signing_algo'])

        # Test non-SSL connection
        mock_conn.return_value = (MockConnectionObject(HOST), False)
        result = library.ssl_certificate_scan(HOST, PORT, TIMEOUT)
        self.assertFalse(result['ssl_flag'])

    @patch("socket.socket")
    @patch("ssl.create_default_context")
    def test_is_weak_cipher_suite(self, mock_ctx, mock_sock):
        HOST = "example.com"
        PORT = 443
        TIMEOUT = 60

        mock_sock.return_value = MagicMock()
        mock_ctx.return_value = MagicMock()

        # Test successful connection
        mock_ctx.return_value.wrap_socket.return_value = MockConnectionObject(HOST)
        ciphers, is_weak = is_weak_cipher_suite(HOST, PORT, TIMEOUT)
        self.assertIsInstance(ciphers, list)
        
        # Test SSL error
        mock_ctx.return_value.wrap_socket.side_effect = ssl.SSLError
        ciphers, is_weak = is_weak_cipher_suite(HOST, PORT, TIMEOUT)
        self.assertEqual(ciphers, [])

    def test_is_weak_hash_algo(self):
        weak_algos = ["md2", "md4", "md5", "sha1"]
        strong_algos = ["sha256", "sha384", "sha512"]
        
        for algo in weak_algos:
            self.assertTrue(is_weak_hash_algo(algo))
        
        for algo in strong_algos:
            self.assertFalse(is_weak_hash_algo(algo))

    @patch("socket.socket")
    @patch("ssl.SSLContext")
    def test_is_weak_ssl_version(self, mock_ctx, mock_sock):
        HOST = "example.com"
        PORT = 443
        TIMEOUT = 60

        mock_sock.return_value = MagicMock()
        mock_ctx.return_value = MagicMock()

        # Test modern protocol
        mock_ctx.return_value.wrap_socket.return_value = MockConnectionObject(HOST, "TLSv1.3")
        versions, is_weak = is_weak_ssl_version(HOST, PORT, TIMEOUT)
        self.assertFalse(is_weak)

        # Test weak protocol
        mock_ctx.return_value.wrap_socket.return_value = MockConnectionObject(HOST, "TLSv1.1")
        versions, is_weak = is_weak_ssl_version(HOST, PORT, TIMEOUT)
        self.assertTrue(is_weak)

        # Test SSL error
        mock_ctx.return_value.wrap_socket.side_effect = ssl.SSLError
        versions, is_weak = is_weak_ssl_version(HOST, PORT, TIMEOUT)
        self.assertTrue(is_weak)

    def test_response_conditions_matched(self):
        engine = SslEngine()
        Substep = Substeps()
        Response = Responses()

        # Test SSL weak version
        result = engine.response_conditions_matched(
            Substep.ssl_weak_version_vuln, 
            Response.ssl_weak_version_vuln
        )
        self.assertTrue(result['weak_version'])

        # Test expired certificate
        result = engine.response_conditions_matched(
            Substep.ssl_certificate_expired_vuln,
            Response.ssl_certificate_expired
        )
        self.assertTrue(result['expired'])

        # Test non-SSL connection
        result = engine.response_conditions_matched(
            Substep.ssl_weak_version_vuln,
            Response.ssl_off
        )
        self.assertEqual(result, [])