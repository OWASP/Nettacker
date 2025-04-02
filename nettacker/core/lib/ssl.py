#!/usr/bin/env python

import logging
import socket
import ssl
import sys
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
    return context.wrap_socket(socket_connection, server_hostname=host)


def is_weak_ssl_version(host, port, timeout):
    def test_ssl_version(host, port, timeout, ssl_version):
        try:
            context = ssl.SSLContext(ssl_version)
            socket_connection = create_socket_connection(context, host, port, timeout)
            return socket_connection.version()
        except (ssl.SSLError, socket.timeout, ConnectionRefusedError, ConnectionResetError):
            return None

    ssl_versions = [
        ssl.PROTOCOL_TLS_CLIENT,  # TLS 1.3
        ssl.PROTOCOL_TLSv1_2,
        ssl.PROTOCOL_TLSv1_1,
    ]
    
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
        except (ssl.SSLError, socket.timeout, ConnectionRefusedError, ConnectionResetError):
            return False

    cipher_suites = [
        "HIGH", "MEDIUM", "LOW", "EXP", "eNULL", "aNULL",
        "RC4", "DES", "MD5", "SHA1", "DH", "ADH",
        "DHE", "ECDH", "ECDHE"
    ]

    supported_ciphers = [
        cipher for cipher in cipher_suites 
        if test_single_cipher(host, port, cipher, timeout)
    ]

    weak_ciphers = {"LOW", "EXP", "eNULL", "aNULL", "RC4", "DES", "MD5", "DH", "ADH"}
    is_weak = any(cipher in weak_ciphers for cipher in supported_ciphers)
    return supported_ciphers, is_weak


def create_tcp_socket(host, port, timeout):
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(timeout)
        sock.connect((host, port))
        ssl_flag = False
    except ConnectionRefusedError:
        return None

    try:
        context = ssl.create_default_context()
        wrapped_sock = context.wrap_socket(sock, server_hostname=host)
        return wrapped_sock, True
    except Exception as e:
        log.debug(f"SSL wrapping failed: {str(e)}")
        try:
            # Fallback to plain socket
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(timeout)
            sock.connect((host, port))
            return sock, False
        except Exception:
            return None


def get_cert_info(cert):
    try:
        x509 = crypto.load_certificate(crypto.FILETYPE_PEM, cert)
        weak_signing_algo = is_weak_hash_algo(str(x509.get_signature_algorithm()))
        
        def parse_cert_date(date_bytes):
            date_str = date_bytes.decode("ascii")
            return datetime.strptime(date_str, "%Y%m%d%H%M%SZ").replace(tzinfo=timezone.utc)

        cert_expires = parse_cert_date(x509.get_notAfter())
        cert_activation = parse_cert_date(x509.get_notBefore())
        
        issuer_str = ", ".join(
            f"{name.decode()}={value.decode()}"
            for name, value in x509.get_issuer().get_components()
        )
        subject_str = ", ".join(
            f"{name.decode()}={value.decode()}"
            for name, value in x509.get_subject().get_components()
        )
        
        now = datetime.now(timezone.utc)
        return {
            "expired": x509.has_expired(),
            "self_signed": issuer_str == subject_str,
            "issuer": issuer_str,
            "subject": subject_str,
            "signing_algo": str(x509.get_signature_algorithm()),
            "weak_signing_algo": weak_signing_algo,
            "activation_date": cert_activation.strftime("%Y-%m-%d %H:%M:%S"),
            "not_activated": (cert_activation - now).total_seconds() > 0,
            "expiration_date": cert_expires.strftime("%Y-%m-%d %H:%M:%S"),
            "expiring_soon": (cert_expires - now).total_seconds() < 30 * 24 * 3600,
        }
    except Exception as e:
        log.error(f"Error parsing certificate: {str(e)}")
        return None


class SslLibrary(BaseLibrary):
    def ssl_certificate_scan(self, host, port, timeout):
        tcp_socket = create_tcp_socket(host, port, timeout)
        if not tcp_socket:
            return None

        socket_connection, ssl_flag = tcp_socket
        scan_info = {
            "ssl_flag": ssl_flag,
            "peer_name": socket_connection.getpeername(),
            "service": socket.getservbyport(int(port)),
        }

        if ssl_flag:
            try:
                cert = ssl.get_server_certificate((host, port))
                cert_info = get_cert_info(cert)
                if cert_info:
                    scan_info.update(cert_info)
            except Exception as e:
                log.debug(f"Certificate scan failed: {str(e)}")

        return scan_info

    def ssl_version_and_cipher_scan(self, host, port, timeout):
        tcp_socket = create_tcp_socket(host, port, timeout)
        if not tcp_socket:
            return None

        socket_connection, ssl_flag = tcp_socket
        scan_info = {
            "ssl_flag": ssl_flag,
            "peer_name": socket_connection.getpeername(),
            "service": socket.getservbyport(int(port)),
            "ssl_version": [],
            "weak_version": False,
            "cipher_suite": [],
            "weak_cipher_suite": False,
            "issuer": "NA",
            "subject": "NA",
            "expiration_date": "NA",
        }

        if ssl_flag:
            try:
                # Get certificate info if available
                cert = ssl.get_server_certificate((host, port))
                cert_info = get_cert_info(cert)
                if cert_info:
                    scan_info.update({
                        "issuer": cert_info["issuer"],
                        "subject": cert_info["subject"],
                        "expiration_date": cert_info["expiration_date"],
                    })

                # Check SSL versions and ciphers
                ssl_ver, weak_version = is_weak_ssl_version(host, port, timeout)
                cipher_suite, weak_cipher_suite = is_weak_cipher_suite(host, port, timeout)
                
                scan_info.update({
                    "ssl_version": ssl_ver,
                    "weak_version": weak_version,
                    "cipher_suite": cipher_suite,
                    "weak_cipher_suite": weak_cipher_suite,
                })
            except Exception as e:
                log.debug(f"SSL version/cipher scan failed: {str(e)}")

        return scan_info


class SslEngine(BaseEngine):
    library = SslLibrary

    def response_conditions_matched(self, sub_step, response):
        if not response or not isinstance(response, dict):
            return []

        conditions = sub_step["response"]["conditions"]
        condition_type = sub_step["response"]["condition_type"]
        condition_results = {}

        if sub_step["method"] in {"ssl_certificate_scan", "ssl_version_and_cipher_scan"}:
            for condition_name, condition_config in conditions.items():
                if isinstance(condition_config, dict) and "condition_type" in condition_config:
                    # Handle grouped conditions
                    group_type = condition_config["condition_type"]
                    group_conditions = condition_config["conditions"]
                    group_results = {}

                    for gc_name, gc_config in group_conditions.items():
                        value = response.get(gc_name)
                        reverse = gc_config.get("reverse", False)
                        
                        if (reverse and not value) or (not reverse and value):
                            group_results[gc_name] = True

                    if group_type == "and" and len(group_results) == len(group_conditions):
                        condition_results.update(group_results)
                    elif group_type == "or" and group_results:
                        condition_results.update(group_results)
                else:
                    # Handle simple conditions
                    value = response.get(condition_name)
                    reverse = condition_config.get("reverse", False)
                    
                    if (reverse and not value) or (not reverse and value):
                        condition_results[condition_name] = True

        if condition_type == "and":
            return condition_results if len(condition_results) == len(conditions) else []
        elif condition_type == "or":
            return condition_results if condition_results else []
        
        return []

    def apply_extra_data(self, sub_step, response):
        sub_step["response"]["ssl_flag"] = response.get("ssl_flag", False) if isinstance(response, dict) else False
        sub_step["response"]["conditions_results"] = self.response_conditions_matched(sub_step, response)