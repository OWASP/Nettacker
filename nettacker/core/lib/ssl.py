import logging
import socket
import ssl
from datetime import datetime, timezone

from OpenSSL import crypto

from nettacker.core.lib.base import BaseEngine, BaseLibrary

log = logging.getLogger(__name__)


def is_weak_hash_algo(algo):
    algo = algo.lower()
    for unsafe_algo in ("md2", "md4", "md5", "sha1"):
        if unsafe_algo in algo:
            return True
    return False


def create_socket_connection(context, host, port, timeout):
    socket_connection = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    socket_connection.settimeout(timeout)
    socket_connection.connect((host, port))
    socket_connection = context.wrap_socket(socket_connection, server_hostname=host)
    return socket_connection


def is_weak_ssl_version(host, port, timeout):
    def test_ssl_version(host, port, timeout, ssl_version=None):
        try:
            context = ssl.SSLContext(ssl_version)
            socket_connection = create_socket_connection(context, host, port, timeout)
            return socket_connection.version()

        except ssl.SSLError:
            return False

        except (socket.timeout, ConnectionRefusedError, ConnectionResetError):
            return None

    ssl_versions = (
        ssl.PROTOCOL_TLS_CLIENT,  # TLS 1.3
        ssl.PROTOCOL_TLSv1_2,
        ssl.PROTOCOL_TLSv1_1,
        ssl.PROTOCOL_TLSv1,
    )
    supported_versions = []
    lowest_version = ""
    for ssl_version in ssl_versions:
        version = test_ssl_version(host, port, timeout, ssl_version=ssl_version)
        if version:
            lowest_version = version
            supported_versions.append(version)

    return supported_versions, lowest_version not in {"TLSv1.2", "TLSv1.3"}


def is_weak_cipher_suite(host, port, timeout):
    def test_single_cipher(host, port, cipher, timeout):
        try:
            context = ssl.create_default_context()
            context.check_hostname = False
            context.verify_mode = ssl.CERT_NONE
            context.set_ciphers(cipher)
            create_socket_connection(context, host, port, timeout)
            return True

        except ssl.SSLError:
            return False

        except (socket.timeout, ConnectionRefusedError, ConnectionResetError):
            return None

    cipher_suites = [
        "HIGH",  # OpenSSL cipher strings
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

    supported_ciphers = []
    for cipher in cipher_suites:
        if test_single_cipher(host, port, cipher, timeout):
            supported_ciphers.append(cipher)

    weak_ciphers = {"LOW", "EXP", "eNULL", "aNULL", "RC4", "DES", "MD5", "DH", "ADH"}
    for cipher in supported_ciphers:
        if cipher in weak_ciphers:
            return supported_ciphers, True

    return supported_ciphers, False


def create_tcp_socket(host, port, timeout):
    try:
        socket_connection = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        socket_connection.settimeout(timeout)
        socket_connection.connect((host, port))
        ssl_flag = False
    except ConnectionRefusedError:
        return None

    try:
        socket_connection = ssl.wrap_socket(socket_connection)
        ssl_flag = True
    except Exception:
        socket_connection = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        socket_connection.settimeout(timeout)
        socket_connection.connect((host, port))

    return socket_connection, ssl_flag


def get_cert_info(cert):
    x509 = crypto.load_certificate(crypto.FILETYPE_PEM, cert)
    weak_signing_algo = is_weak_hash_algo(str(x509.get_signature_algorithm()))
    cert_expires = datetime.strptime(x509.get_notAfter().decode("utf-8"), "%Y%m%d%H%M%S%z")
    cert_activation = datetime.strptime(x509.get_notBefore().decode("utf-8"), "%Y%m%d%H%M%S%z")
    issuer_str = ", ".join(
        f"{name.decode()}={value.decode()}" for name, value in x509.get_issuer().get_components()
    )
    subject_str = ", ".join(
        f"{name.decode()}={value.decode()}" for name, value in x509.get_subject().get_components()
    )
    return {
        "expired": x509.has_expired(),
        "self_signed": issuer_str == subject_str,
        "issuer": issuer_str,
        "subject": subject_str,
        "signing_algo": str(x509.get_signature_algorithm()),
        "weak_signing_algo": weak_signing_algo,
        "activation_date": cert_activation.strftime("%Y-%m-%d"),
        "not_activated": (cert_activation - datetime.now(timezone.utc)).days > 0,
        "expiration_date": cert_expires.strftime("%Y-%m-%d"),
        "expiring_soon": (cert_expires - datetime.now(timezone.utc)).days < 30,
    }


class SslLibrary(BaseLibrary):
    def ssl_certificate_scan(self, host, port, timeout):
        tcp_socket = create_tcp_socket(host, port, timeout)
        if tcp_socket is None:
            return None

        socket_connection, ssl_flag = tcp_socket
        peer_name = socket_connection.getpeername()
        scan_info = {
            "ssl_flag": ssl_flag,
            "peer_name": peer_name,
            "service": socket.getservbyport(int(port)),
        }

        if ssl_flag:
            cert = ssl.get_server_certificate((host, port))
            cert_info = get_cert_info(cert)
            scan_info = cert_info | scan_info
            return scan_info

        return scan_info

    def ssl_version_and_cipher_scan(self, host, port, timeout):
        tcp_socket = create_tcp_socket(host, port, timeout)
        if tcp_socket is None:
            return None

        socket_connection, ssl_flag = tcp_socket
        peer_name = socket_connection.getpeername()

        if ssl_flag:
            try:
                cert = ssl.get_server_certificate((host, port))
            except ssl.SSLError:
                cert = None
            cert_info = get_cert_info(cert) if cert else None
            ssl_ver, weak_version = is_weak_ssl_version(host, port, timeout)
            cipher_suite, weak_cipher_suite = is_weak_cipher_suite(host, port, timeout)

            return {
                "ssl_version": ssl_ver,
                "weak_version": weak_version,
                "cipher_suite": cipher_suite,
                "weak_cipher_suite": weak_cipher_suite,
                "issuer": cert_info["issuer"] if cert_info else "NA",
                "subject": cert_info["subject"] if cert_info else "NA",
                "expiration_date": cert_info["expiration_date"] if cert_info else "NA",
                "ssl_flag": ssl_flag,
                "peer_name": peer_name,
                "service": socket.getservbyport(int(port)),
            }

        return {
            "ssl_flag": ssl_flag,
            "service": socket.getservbyport(int(port)),
            "peer_name": peer_name,
        }


class SslEngine(BaseEngine):
    library = SslLibrary

    def response_conditions_matched(self, sub_step, response):
        conditions = sub_step["response"]["conditions"]
        condition_type = sub_step["response"]["condition_type"]
        condition_results = {}
        if sub_step["method"] in {
            "ssl_certificate_scan",
            "ssl_version_and_cipher_scan",
        }:
            if response and response["ssl_flag"]:
                for condition in conditions:
                    if "grouped_conditions" in condition:
                        gc_type = conditions[condition]["condition_type"]
                        gc_conditions = conditions[condition]["conditions"]
                        gc_condition_results = {}
                        for gc_condition in gc_conditions:
                            if (
                                gc_conditions[gc_condition]["reverse"]
                                and not response[gc_condition]
                            ):
                                gc_condition_results[gc_condition] = not response[gc_condition]

                            elif (
                                not gc_conditions[gc_condition]["reverse"]
                                and response[gc_condition]
                            ):
                                gc_condition_results[gc_condition] = response[gc_condition]

                        if gc_type == "and":
                            gc_condition_results = (
                                gc_condition_results
                                if len(gc_condition_results) == len(gc_conditions)
                                else {}
                            )

                        condition_results.update(gc_condition_results)

                    elif (conditions[condition]["reverse"] and not response[condition]) or (
                        not conditions[condition]["reverse"] and response[condition]
                    ):
                        condition_results[condition] = True

                if condition_type == "and":
                    return condition_results if len(condition_results) == len(conditions) else []
                if condition_type == "or":
                    return condition_results if condition_results else []
                return []

        return []

    def apply_extra_data(self, sub_step, response):
        sub_step["response"]["ssl_flag"] = (
            response["ssl_flag"] if isinstance(response, dict) else False
        )
        sub_step["response"]["conditions_results"] = self.response_conditions_matched(
            sub_step, response
        )
