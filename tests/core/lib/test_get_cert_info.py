# tests/core/lib/test_get_cert_info.py
# Tests for get_cert_info() in nettacker/core/lib/ssl.py

import datetime
import pytest
from cryptography import x509
from cryptography.x509.oid import NameOID
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
import cryptography.hazmat.backends as backends

from nettacker.core.lib.ssl import get_cert_info


def generate_test_cert(
    days_valid=365,
    days_offset=0,
    signing_algo=hashes.SHA256(),
    self_signed=True,
):
    """
    Generates a fake self-signed certificate for testing.
    days_valid: how many days the cert is valid for
    days_offset: shift the start date (negative = already expired)
    signing_algo: hash algorithm to sign with
    self_signed: if True, issuer == subject
    """
    key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048,
    )

    subject = x509.Name([
        x509.NameAttribute(NameOID.COMMON_NAME, "test.example.com"),
        x509.NameAttribute(NameOID.ORGANIZATION_NAME, "Test Org"),
    ])

    if self_signed:
        issuer = subject
    else:
        issuer = x509.Name([
            x509.NameAttribute(NameOID.COMMON_NAME, "Real CA"),
            x509.NameAttribute(NameOID.ORGANIZATION_NAME, "Real CA Org"),
        ])

    now = datetime.datetime.now(datetime.timezone.utc)
    start = now + datetime.timedelta(days=days_offset)
    end = start + datetime.timedelta(days=days_valid)

    cert = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(issuer)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(start)
        .not_valid_after(end)
        .sign(key, signing_algo)
    )

    return cert.public_bytes(serialization.Encoding.PEM).decode("utf-8")


class TestGetCertInfo:
    """
    Tests for get_cert_info() in nettacker/core/lib/ssl.py.
    Uses locally generated self-signed certificates — no network required.
    """

    def test_valid_cert_not_expired(self):
        cert = generate_test_cert(days_valid=365)
        info = get_cert_info(cert)
        assert info["expired"] is False

    def test_expired_cert_detected(self):
        # Start 400 days ago, valid for 365 days = expired 35 days ago
        cert = generate_test_cert(days_valid=365, days_offset=-400)
        info = get_cert_info(cert)
        assert info["expired"] is True

    def test_self_signed_cert_detected(self):
        cert = generate_test_cert(self_signed=True)
        info = get_cert_info(cert)
        assert info["self_signed"] is True

    def test_non_self_signed_cert(self):
        cert = generate_test_cert(self_signed=False)
        info = get_cert_info(cert)
        assert info["self_signed"] is False

    def test_expiration_date_format(self):
        # expiration_date should be in YYYY-MM-DD format
        cert = generate_test_cert(days_valid=365)
        info = get_cert_info(cert)
        datetime.datetime.strptime(info["expiration_date"], "%Y-%m-%d")

    def test_activation_date_format(self):
        cert = generate_test_cert(days_valid=365)
        info = get_cert_info(cert)
        datetime.datetime.strptime(info["activation_date"], "%Y-%m-%d")

    def test_subject_is_string(self):
        cert = generate_test_cert()
        info = get_cert_info(cert)
        assert isinstance(info["subject"], str)
        assert len(info["subject"]) > 0

    def test_issuer_is_string(self):
        cert = generate_test_cert()
        info = get_cert_info(cert)
        assert isinstance(info["issuer"], str)
        assert len(info["issuer"]) > 0

    def test_weak_signing_algo_sha256_is_false(self):
        cert = generate_test_cert(signing_algo=hashes.SHA256())
        info = get_cert_info(cert)
        assert info["weak_signing_algo"] is False

    def test_expiring_soon_false_for_long_validity(self):
        cert = generate_test_cert(days_valid=365)
        info = get_cert_info(cert)
        assert info["expiring_soon"] is False

    def test_expiring_soon_true_when_under_30_days(self):
        # Valid for only 10 more days
        cert = generate_test_cert(days_valid=10)
        info = get_cert_info(cert)
        assert info["expiring_soon"] is True

    def test_not_activated_false_for_current_cert(self):
        cert = generate_test_cert(days_valid=365, days_offset=0)
        info = get_cert_info(cert)
        assert info["not_activated"] is False

    def test_return_type_is_dict(self):
        cert = generate_test_cert()
        info = get_cert_info(cert)
        assert isinstance(info, dict)

    def test_all_expected_keys_present(self):
        cert = generate_test_cert()
        info = get_cert_info(cert)
        expected_keys = {
            "expired", "self_signed", "issuer", "subject",
            "signing_algo", "weak_signing_algo", "activation_date",
            "not_activated", "expiration_date", "expiring_soon"
        }
        assert expected_keys.issubset(info.keys())
        