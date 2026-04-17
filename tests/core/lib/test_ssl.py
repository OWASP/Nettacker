import ssl
from unittest.mock import patch

import pytest
from OpenSSL import crypto

from nettacker.core.lib.ssl import (
    SslEngine,
    SslLibrary,
    create_tcp_socket,
    get_cert_info,
    is_weak_cipher_suite,
    is_weak_hash_algo,
    is_weak_ssl_version,
)


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
        return [
            (b"component", str.encode(self.subject)),
        ]


class IssuerObject:
    def __init__(self, issuer="issuer"):
        self.issuer = issuer

    def get_components(self):
        return [
            (b"component", str.encode(self.issuer)),
        ]


class Mockx509Object:
    def __init__(self, issuer, subject, is_expired, expire_date, activation_date, signing_algo):
        self.issuer = IssuerObject(issuer)
        self.subject = SubjectObject(subject)
        self.expired = is_expired
        self.expire_date = expire_date
        self.activation_date = activation_date
        self.signature_algorithm = signing_algo

    def get_issuer(self):
        return self.issuer

    def get_subject(self):
        return self.subject

    def has_expired(self):
        return self.expired

    def get_notAfter(self):
        return self.expire_date

    def get_notBefore(self):
        return self.activation_date

    def get_signature_algorithm(self):
        return self.signature_algorithm


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
        "expiration_date": "2023-12-07",
        "subject": "component=subject",
        "not_activated": False,
        "activation_date": "2023-12-07",
        "expiring_soon": True,
        "ssl_flag": True,
    }

    ssl_certificate_deactivated = {
        "expired": False,
        "expiration_date": "2100-12-07",
        "expiring_soon": False,
        "not_activated": True,
        "activation_date": "2100-12-07",
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


@pytest.fixture(scope="module")
def ssl_engine():
    return SslEngine()


@pytest.fixture(scope="module")
def ssl_library():
    return SslLibrary()


@pytest.fixture(scope="module")
def substeps():
    return Substeps()


@pytest.fixture(scope="module")
def responses():
    return Responses()


@pytest.fixture(scope="module")
def connection_params():
    return {"HOST": "example.com", "PORT": 80, "TIMEOUT": 60}


class TestSslMethod:
    @patch("socket.socket")
    @patch("ssl.wrap_socket")
    def test_create_tcp_socket(self, mock_wrap, mock_socket, connection_params):
        create_tcp_socket(
            connection_params["HOST"], connection_params["PORT"], connection_params["TIMEOUT"]
        )

        socket_instance = mock_socket.return_value
        socket_instance.settimeout.assert_called_with(connection_params["TIMEOUT"])
        socket_instance.connect.assert_called_with(
            (connection_params["HOST"], connection_params["PORT"])
        )
        mock_wrap.assert_called_with(socket_instance)

    @patch("nettacker.core.lib.ssl.is_weak_cipher_suite")
    @patch("nettacker.core.lib.ssl.is_weak_ssl_version")
    @patch("nettacker.core.lib.ssl.create_tcp_socket")
    def test_ssl_version_and_cipher_scan_secure(
        self, mock_connection, mock_ssl_check, mock_cipher_check, ssl_library, connection_params
    ):
        mock_connection.return_value = (
            MockConnectionObject(connection_params["HOST"], "TLSv1.3"),
            True,
        )
        mock_ssl_check.return_value = ("TLSv1.3", False)
        mock_cipher_check.return_value = (["HIGH"], False)

        result = ssl_library.ssl_version_and_cipher_scan(
            connection_params["HOST"], connection_params["PORT"], connection_params["TIMEOUT"]
        )

        expected = {
            "ssl_flag": True,
            "service": "http",
            "weak_version": False,
            "ssl_version": "TLSv1.3",
            "peer_name": "example.com",
            "cipher_suite": ["HIGH"],
            "weak_cipher_suite": False,
            "issuer": "NA",
            "subject": "NA",
            "expiration_date": "NA",
        }

        assert result == expected

    @patch("nettacker.core.lib.ssl.is_weak_cipher_suite")
    @patch("nettacker.core.lib.ssl.is_weak_ssl_version")
    @patch("nettacker.core.lib.ssl.create_tcp_socket")
    def test_ssl_version_and_cipher_scan_weak(
        self, mock_connection, mock_ssl_check, mock_cipher_check, ssl_library, connection_params
    ):
        mock_connection.return_value = (
            MockConnectionObject(connection_params["HOST"], "TLSv1.1"),
            True,
        )
        mock_ssl_check.return_value = ("TLSv1.1", True)
        mock_cipher_check.return_value = (["LOW"], True)

        result = ssl_library.ssl_version_and_cipher_scan(
            connection_params["HOST"], connection_params["PORT"], connection_params["TIMEOUT"]
        )

        expected = {
            "ssl_flag": True,
            "service": "http",
            "weak_version": True,
            "ssl_version": "TLSv1.1",
            "peer_name": "example.com",
            "cipher_suite": ["LOW"],
            "weak_cipher_suite": True,
            "issuer": "NA",
            "subject": "NA",
            "expiration_date": "NA",
        }

        assert result == expected

    @patch("nettacker.core.lib.ssl.is_weak_cipher_suite")
    @patch("nettacker.core.lib.ssl.is_weak_ssl_version")
    @patch("nettacker.core.lib.ssl.create_tcp_socket")
    def test_ssl_version_and_cipher_scan_no_ssl(
        self, mock_connection, mock_ssl_check, mock_cipher_check, ssl_library, connection_params
    ):
        mock_connection.return_value = (MockConnectionObject(connection_params["HOST"]), False)

        result = ssl_library.ssl_version_and_cipher_scan(
            connection_params["HOST"], connection_params["PORT"], connection_params["TIMEOUT"]
        )

        expected = {
            "ssl_flag": False,
            "service": "http",
            "peer_name": "example.com",
        }

        assert result == expected

    @patch("nettacker.core.lib.ssl.create_tcp_socket")
    @patch("nettacker.core.lib.ssl.is_weak_hash_algo")
    @patch("nettacker.core.lib.ssl.crypto.load_certificate")
    @patch("nettacker.core.lib.ssl.ssl.get_server_certificate")
    def test_ssl_certificate_scan_valid_cert(
        self,
        mock_certificate,
        mock_x509,
        mock_hash_check,
        mock_connection,
        ssl_library,
        connection_params,
    ):
        mock_hash_check.return_value = False
        mock_connection.return_value = (
            MockConnectionObject(connection_params["HOST"], "TLSv1.3"),
            True,
        )
        mock_x509.return_value = Mockx509Object(
            is_expired=False,
            issuer="test_issuer",
            subject="test_subject",
            signing_algo="test_algo",
            expire_date=b"21001207153045Z",
            activation_date=b"20231207153045Z",
        )

        result = ssl_library.ssl_certificate_scan(
            connection_params["HOST"], connection_params["PORT"], connection_params["TIMEOUT"]
        )

        expected = {
            "expired": False,
            "ssl_flag": True,
            "service": "http",
            "self_signed": False,
            "issuer": "component=test_issuer",
            "subject": "component=test_subject",
            "expiring_soon": False,
            "expiration_date": "2100-12-07",
            "not_activated": False,
            "activation_date": "2023-12-07",
            "signing_algo": "test_algo",
            "weak_signing_algo": False,
            "peer_name": "example.com",
        }

        assert result == expected

    @patch("nettacker.core.lib.ssl.create_tcp_socket")
    @patch("nettacker.core.lib.ssl.is_weak_hash_algo")
    @patch("nettacker.core.lib.ssl.crypto.load_certificate")
    @patch("nettacker.core.lib.ssl.ssl.get_server_certificate")
    def test_ssl_certificate_scan_self_signed(
        self,
        mock_certificate,
        mock_x509,
        mock_hash_check,
        mock_connection,
        ssl_library,
        connection_params,
    ):
        mock_hash_check.return_value = True
        mock_connection.return_value = (
            MockConnectionObject(connection_params["HOST"], "TLSv1.3"),
            True,
        )
        mock_x509.return_value = Mockx509Object(
            is_expired=True,
            issuer="test_issuer_subject",
            subject="test_issuer_subject",
            signing_algo="test_algo",
            expire_date=b"21001207153045Z",
            activation_date=b"21001207153045Z",
        )

        result = ssl_library.ssl_certificate_scan(
            connection_params["HOST"], connection_params["PORT"], connection_params["TIMEOUT"]
        )

        expected = {
            "expired": True,
            "ssl_flag": True,
            "service": "http",
            "self_signed": True,
            "issuer": "component=test_issuer_subject",
            "subject": "component=test_issuer_subject",
            "expiring_soon": False,
            "expiration_date": "2100-12-07",
            "not_activated": True,
            "activation_date": "2100-12-07",
            "signing_algo": "test_algo",
            "weak_signing_algo": True,
            "peer_name": "example.com",
        }

        assert result == expected

    @patch("nettacker.core.lib.ssl.create_tcp_socket")
    @patch("nettacker.core.lib.ssl.is_weak_hash_algo")
    @patch("nettacker.core.lib.ssl.crypto.load_certificate")
    @patch("nettacker.core.lib.ssl.ssl.get_server_certificate")
    def test_ssl_certificate_scan_no_ssl(
        self,
        mock_certificate,
        mock_x509,
        mock_hash_check,
        mock_connection,
        ssl_library,
        connection_params,
    ):
        mock_connection.return_value = (MockConnectionObject(connection_params["HOST"]), False)

        result = ssl_library.ssl_certificate_scan(
            connection_params["HOST"], connection_params["PORT"], connection_params["TIMEOUT"]
        )

        expected = {
            "service": "http",
            "ssl_flag": False,
            "peer_name": "example.com",
        }

        assert result == expected

    @patch("socket.socket")
    @patch("ssl.create_default_context")
    def test_is_weak_cipher_suite_success(self, mock_context, mock_socket, connection_params):
        socket_instance = mock_socket.return_value
        context_instance = mock_context.return_value

        cipher_list = [
            "HIGH",
            "MEDIUM",
            "LOW",
            "EXP",
            "eNULL",
            "aNULL",
            "RC4",
            "DES",
            "MD5",
            "SHA1",
            "DH",
            "ADH",
            "DHE",
            "ECDH",
            "ECDHE",
            "TLSv1",
            "TLSv1.1",
            "TLSv1.2",
            "TLSv1.3",
        ]

        result = is_weak_cipher_suite(
            connection_params["HOST"], connection_params["PORT"], connection_params["TIMEOUT"]
        )

        assert result == (cipher_list, True)
        context_instance.wrap_socket.assert_called_with(
            socket_instance, server_hostname=connection_params["HOST"]
        )
        socket_instance.settimeout.assert_called_with(connection_params["TIMEOUT"])
        socket_instance.connect.assert_called_with(
            (connection_params["HOST"], connection_params["PORT"])
        )

    @patch("socket.socket")
    @patch("ssl.create_default_context")
    def test_is_weak_cipher_suite_ssl_error(self, mock_context, mock_socket, connection_params):
        context_instance = mock_context.return_value
        context_instance.wrap_socket.side_effect = ssl.SSLError

        result = is_weak_cipher_suite(
            connection_params["HOST"], connection_params["PORT"], connection_params["TIMEOUT"]
        )

        assert result == ([], False)

    @pytest.mark.parametrize(
        "algo,expected",
        [
            ("md2", True),
            ("md4", True),
            ("md5", True),
            ("sha1", True),
            ("test_algo", False),
            ("sha256", False),
        ],
    )
    def test_is_weak_hash_algo(self, algo, expected):
        assert is_weak_hash_algo(algo) == expected

    @patch("socket.socket")
    @patch("ssl.SSLContext")
    def test_is_weak_ssl_version_secure(self, mock_context, mock_socket, connection_params):
        context_instance = mock_context.return_value
        context_instance.wrap_socket.return_value = MockConnectionObject(
            connection_params["HOST"], "TLSv1.3"
        )

        result = is_weak_ssl_version(
            connection_params["HOST"], connection_params["PORT"], connection_params["TIMEOUT"]
        )

        assert result == (["TLSv1.3", "TLSv1.3", "TLSv1.3", "TLSv1.3"], False)

    @patch("socket.socket")
    @patch("ssl.SSLContext")
    def test_is_weak_ssl_version_weak(self, mock_context, mock_socket, connection_params):
        context_instance = mock_context.return_value
        context_instance.wrap_socket.return_value = MockConnectionObject(
            connection_params["HOST"], "TLSv1.1"
        )

        result = is_weak_ssl_version(
            connection_params["HOST"], connection_params["PORT"], connection_params["TIMEOUT"]
        )

        assert result == (["TLSv1.1", "TLSv1.1", "TLSv1.1", "TLSv1.1"], True)

    @pytest.mark.parametrize("exception", [ssl.SSLError, ConnectionRefusedError])
    @patch("socket.socket")
    @patch("ssl.SSLContext")
    def test_is_weak_ssl_version_exceptions(
        self, mock_context, mock_socket, exception, connection_params
    ):
        socket_instance = mock_socket.return_value
        context_instance = mock_context.return_value
        context_instance.wrap_socket.side_effect = exception

        result = is_weak_ssl_version(
            connection_params["HOST"], connection_params["PORT"], connection_params["TIMEOUT"]
        )

        assert result == ([], True)
        socket_instance.settimeout.assert_called_with(connection_params["TIMEOUT"])
        socket_instance.connect.assert_called_with(
            (connection_params["HOST"], connection_params["PORT"])
        )
        context_instance.wrap_socket.assert_called_with(
            socket_instance, server_hostname=connection_params["HOST"]
        )

    def test_response_conditions_matched_expired_cert(self, ssl_engine, substeps, responses):
        result = ssl_engine.response_conditions_matched(
            substeps.ssl_certificate_expired_vuln, responses.ssl_certificate_expired
        )

        expected = {
            "subject": "component=subject",
            "expired": True,
            "expiration_date": "2023-12-07",
        }

        assert result == expected

    def test_response_conditions_matched_deactivated_cert(self, ssl_engine, substeps, responses):
        result = ssl_engine.response_conditions_matched(
            substeps.ssl_certificate_expired_vuln,
            responses.ssl_certificate_deactivated,
        )

        expected = {
            "subject": "component=subject",
            "not_activated": True,
            "activation_date": "2100-12-07",
        }

        assert result == expected

    def test_response_conditions_matched_weak_version(self, ssl_engine, substeps, responses):
        result = ssl_engine.response_conditions_matched(
            substeps.ssl_weak_version_vuln, responses.ssl_weak_version_vuln
        )

        expected = {
            "weak_version": True,
            "ssl_version": ["TLSv1"],
            "issuer": "NA",
            "subject": "NA",
            "expiration_date": "NA",
        }

        assert result == expected

    def test_response_conditions_matched_ssl_off(self, ssl_engine, substeps, responses):
        result = ssl_engine.response_conditions_matched(
            substeps.ssl_weak_version_vuln, responses.ssl_off
        )

        assert result == []

    def test_response_conditions_matched_none_response(self, ssl_engine, substeps):
        result = ssl_engine.response_conditions_matched(substeps.ssl_weak_version_vuln, None)

        assert result == []


class TestGetCertInfo:
    """
    Tests for get_cert_info(cert).

    Uses a runtime-generated self-signed certificate so tests never rely on a hardcoded certificate that could expire. Certificate is created fresh for each test run using
    pyOpenSSL with a 10-year validity window.
    """

    @pytest.fixture(scope="module")
    def self_signed_cert_pem(self):
        """Generate a fresh self-signed certificate valid for 10 years."""
        k = crypto.PKey()
        k.generate_key(crypto.TYPE_RSA, 2048)
        cert = crypto.X509()
        cert.get_subject().C = "US"
        cert.get_subject().CN = "test.example.com"
        cert.set_issuer(cert.get_subject())
        cert.set_pubkey(k)
        cert.gmtime_adj_notBefore(0)
        cert.gmtime_adj_notAfter(10 * 365 * 24 * 60 * 60)
        cert.sign(k, "sha256")
        return crypto.dump_certificate(crypto.FILETYPE_PEM, cert).decode()

    def test_returns_dict(self, self_signed_cert_pem):
        result = get_cert_info(self_signed_cert_pem)
        assert isinstance(result, dict)

    def test_required_keys_present(self, self_signed_cert_pem):
        result = get_cert_info(self_signed_cert_pem)
        expected_keys = [
            "expired",
            "self_signed",
            "issuer",
            "subject",
            "signing_algo",
            "weak_signing_algo",
            "activation_date",
            "expiration_date",
            "not_activated",
            "expiring_soon",
        ]
        for key in expected_keys:
            assert key in result, f"Missing key: {key}"

    def test_self_signed_is_true(self, self_signed_cert_pem):
        result = get_cert_info(self_signed_cert_pem)
        assert result["self_signed"] is True

    def test_not_expired(self, self_signed_cert_pem):
        result = get_cert_info(self_signed_cert_pem)
        assert result["expired"] is False

    def test_subject_contains_cn(self, self_signed_cert_pem):
        result = get_cert_info(self_signed_cert_pem)
        assert "test.example.com" in result["subject"]

    def test_signing_algo_is_string(self, self_signed_cert_pem):
        result = get_cert_info(self_signed_cert_pem)
        assert isinstance(result["signing_algo"], str)

    def test_activation_date_format(self, self_signed_cert_pem):
        result = get_cert_info(self_signed_cert_pem)
        assert len(result["activation_date"]) == 10
        assert result["activation_date"][4] == "-"
        assert result["activation_date"][7] == "-"

    def test_expiration_date_format(self, self_signed_cert_pem):
        result = get_cert_info(self_signed_cert_pem)
        assert len(result["expiration_date"]) == 10
        assert result["expiration_date"][4] == "-"
        assert result["expiration_date"][7] == "-"

    def test_weak_signing_algo_false_for_sha256(self, self_signed_cert_pem):
        result = get_cert_info(self_signed_cert_pem)
        assert result["weak_signing_algo"] is False

    def test_weak_signing_algo_mocked_true(self, self_signed_cert_pem):
        with patch("nettacker.core.lib.ssl.is_weak_hash_algo", return_value=True):
            result = get_cert_info(self_signed_cert_pem)
            assert result["weak_signing_algo"] is True

    def test_weak_signing_algo_mocked_false(self, self_signed_cert_pem):
        with patch("nettacker.core.lib.ssl.is_weak_hash_algo", return_value=False):
            result = get_cert_info(self_signed_cert_pem)
            assert result["weak_signing_algo"] is False

    def test_not_activated_is_bool(self, self_signed_cert_pem):
        result = get_cert_info(self_signed_cert_pem)
        assert isinstance(result["not_activated"], bool)

    def test_expiring_soon_is_bool(self, self_signed_cert_pem):
        result = get_cert_info(self_signed_cert_pem)
        assert isinstance(result["expiring_soon"], bool)
