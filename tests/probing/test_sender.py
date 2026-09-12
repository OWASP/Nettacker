import socket
import ssl
import threading
import time

import pytest

from nettacker.probing.sender import raw_to_bytes, tcp_probe, tcp_probe_ssl, udp_probe


def _free_port():
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.bind(("127.0.0.1", 0))
    port = s.getsockname()[1]
    s.close()
    return port


class TestRawToBytes:
    def test_empty_payload_returns_empty_bytes(self):
        assert raw_to_bytes("") == b""
        assert raw_to_bytes(None) == b""

    def test_plain_text_payload(self):
        assert raw_to_bytes("PING") == b"PING"

    def test_escape_sequences_are_decoded(self):
        assert raw_to_bytes("\\r\\n\\x00") == b"\r\n\x00"


class TestTcpProbe:
    def test_connect_refused_returns_empty_response(self):
        port = _free_port()
        result = tcp_probe("127.0.0.1", port, payload="", timeout_ms=500)
        assert result["raw_bytes"] == b""
        assert result["peer_name"] == ""
        assert result["ssl_flag"] is False

    def test_receives_banner_from_server(self):
        port = _free_port()

        def server():
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            s.bind(("127.0.0.1", port))
            s.listen(1)
            conn, _addr = s.accept()
            conn.sendall(b"HELLO-BANNER\r\n")
            conn.close()
            s.close()

        t = threading.Thread(target=server, daemon=True)
        t.start()
        time.sleep(0.2)

        result = tcp_probe("127.0.0.1", port, payload="", timeout_ms=2000)
        assert result["raw_bytes"] == b"HELLO-BANNER\r\n"
        assert result["peer_name"] != ""
        assert result["ssl_flag"] is False

    def test_sends_payload_to_server(self):
        port = _free_port()
        received = {}

        def server():
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            s.bind(("127.0.0.1", port))
            s.listen(1)
            conn, _addr = s.accept()
            received["data"] = conn.recv(1024)
            conn.close()
            s.close()

        t = threading.Thread(target=server, daemon=True)
        t.start()
        time.sleep(0.2)

        tcp_probe("127.0.0.1", port, payload="PING\\r\\n", timeout_ms=2000)
        time.sleep(0.2)
        assert received["data"] == b"PING\r\n"


class TestTcpProbeSsl:
    def test_connect_refused_returns_empty_response(self):
        port = _free_port()
        result = tcp_probe_ssl("127.0.0.1", port, payload="", timeout_ms=500)
        assert result["raw_bytes"] == b""
        assert result["ssl_flag"] is True

    def test_receives_banner_over_tls(self, tmp_path):
        pytest.importorskip("cryptography")
        cert_path = tmp_path / "cert.pem"
        key_path = tmp_path / "key.pem"
        _generate_self_signed_cert(cert_path, key_path)

        port = _free_port()

        def server():
            context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
            context.minimum_version = ssl.TLSVersion.TLSv1_2
            context.load_cert_chain(str(cert_path), str(key_path))
            raw = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            raw.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            raw.bind(("127.0.0.1", port))
            raw.listen(1)
            conn, _addr = raw.accept()
            tls_conn = context.wrap_socket(conn, server_side=True)
            tls_conn.sendall(b"TLS-BANNER\r\n")
            tls_conn.close()
            raw.close()

        t = threading.Thread(target=server, daemon=True)
        t.start()
        time.sleep(0.3)

        result = tcp_probe_ssl("127.0.0.1", port, payload="", timeout_ms=2000)
        assert result["raw_bytes"] == b"TLS-BANNER\r\n"
        assert result["ssl_flag"] is True
        assert result["cipher"] is not None


class TestUdpProbe:
    def test_no_response_returns_empty_bytes(self):
        port = _free_port()
        result = udp_probe("127.0.0.1", port, payload="PING", timeout_ms=300)
        assert result["raw_bytes"] == b""
        assert result["response"] == ""

    def test_receives_datagram_from_server(self):
        port = _free_port()

        def server():
            s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            s.bind(("127.0.0.1", port))
            data, addr = s.recvfrom(4096)
            s.sendto(b"UDP-BANNER", addr)
            s.close()

        t = threading.Thread(target=server, daemon=True)
        t.start()
        time.sleep(0.2)

        result = udp_probe("127.0.0.1", port, payload="PING", timeout_ms=2000)
        assert result["raw_bytes"] == b"UDP-BANNER"
        assert result["response"] == "UDP-BANNER"


def _generate_self_signed_cert(cert_path, key_path):
    """Generate a throwaway self-signed cert for local TLS tests without external deps."""
    import datetime
    import ipaddress

    from cryptography import x509
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import rsa
    from cryptography.x509.oid import NameOID

    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    subject = issuer = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "localhost")])
    cert = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(issuer)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(datetime.datetime.utcnow())
        .not_valid_after(datetime.datetime.utcnow() + datetime.timedelta(days=1))
        .add_extension(
            x509.SubjectAlternativeName([x509.IPAddress(ipaddress.ip_address("127.0.0.1"))]),
            critical=False,
        )
        .sign(key, hashes.SHA256())
    )
    key_path.write_bytes(
        key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.TraditionalOpenSSL,
            encryption_algorithm=serialization.NoEncryption(),
        )
    )
    cert_path.write_bytes(cert.public_bytes(serialization.Encoding.PEM))
