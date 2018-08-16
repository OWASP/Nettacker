#!/usr/bin/python

import socket
import errno
import struct
import os
import time
import re
from core.alert import *

try:
    from enum import Enum  # supported from Python v3.4
except ImportError:
    error("You need to support Enum (Python >= v3.4)")

result = {}


class Target(object):
    def __init__(self, host, port):
        self.host = host
        self.port = port


class TargetParser:

    # RFC3986 (section 3.2.2)
    ipv6_notation_regex = '^\[(.*?)\]:+([0-9]{1,5})$'
    ipv4_hostname_notation_regex = '^(.*)[:]+([0-9]{1,5})$'

    def __init__(self, input_string):
        self.string = input_string
        self.host = None
        self.port = None

        if self.is_ipv6_notation:
            self._parse_ipv6_notation()
        elif self.is_ipv4_hostname_notation:
            self._parse_ipv4_hostname_notation()
        else:
            raise ValueError("Not a valid address/hostname")

    @property
    def is_ipv6_notation(self):
        if re.match(TargetParser.ipv6_notation_regex, self.string):
            return True

    @property
    def is_ipv4_hostname_notation(self):
        if re.match(TargetParser.ipv4_hostname_notation_regex, self.string):
            return True

    @staticmethod  # https://stackoverflow.com/questions/2532053/validate-a-hostname-string
    def is_valid_hostname(hostname):
        if len(hostname) > 255:
            return False
        if hostname[-1] == ".":
            hostname = hostname[:-1]
        allowed = re.compile('(?!-)[A-Z\d-]{1,63}(?<!-)$', re.IGNORECASE)
        return all(allowed.match(x) for x in hostname.split("."))

    def _parse_ipv6_notation(self):
        m = re.match(TargetParser.ipv6_notation_regex, self.string)
        if TCP.get_address_type(m.group(1)) == socket.AF_INET6:
            self.host = m.group(1)
            self.port = m.group(2)
        else:
            raise ValueError("Invalid IPv6 address: {0}".format(m.group(1)))

    def _parse_ipv4_hostname_notation(self):
        m = re.match(TargetParser.ipv4_hostname_notation_regex, self.string)
        if TCP.get_address_type(m.group(1)) == socket.AF_INET or TargetParser.is_valid_hostname(m.group(1)):
            self.host = m.group(1)
            self.port = m.group(2)
        else:
            raise ValueError(
                "Invalid format for IPv4 or hostname: {0}".format(m.group(1)))

    def get_target(self):
        """
        returns the Target object
        :return: Target object
        """
        return Target(self.host, self.port)


class TCP(object):

    def __init__(self, host, port):
        self.timeout = 5
        self.retries = 1  # Not used ATM
        self.host = host
        self.port = port
        self.socket = None

    def connect(self):
        try:
            self.socket = socket.create_connection(
                (self.host, int(self.port)), self.timeout)
            # return self.socket
            return self
        except socket.gaierror:
            error("Invalid/unknown host ({0})".format(self.host))
        except (socket.timeout, ConnectionRefusedError):
            error("Unable to connect to the remote host/service")
        except socket.error as e:
            if e.errno == errno.EHOSTDOWN or e.errno == errno.EHOSTUNREACH:
                error("The host provided is down/unreachable")
            else:
                raise e
        except:
            raise

    def send_all(self, data):  # Just a wrapper
        self.socket.sendall(data)

    def receive_buffer(self, length):
        data = b''
        timeout_retries = 0
        total_received = 0
        empty_buffer_count = 0
        to_receive = length
        self.socket.settimeout(0.2)
        while total_received < length and empty_buffer_count < 2:
            try:
                new_data = self.socket.recv(to_receive)
                if new_data:
                    data += new_data
                    total_received = len(data)
                    to_receive = length - total_received if length > total_received else 0
                    del new_data
                else:
                    empty_buffer_count += 1
            except socket.timeout:
                if len(data) == 0 and timeout_retries == 2:
                    break
                timeout_retries += 1
                if timeout_retries == 2:
                    break
        self.socket.settimeout(self.timeout)
        return data

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        self.socket.close()

    @staticmethod
    def get_address_type(address):
        try:
            socket.inet_pton(socket.AF_INET, address)
        except socket.error:
            try:
                socket.inet_pton(socket.AF_INET6, address)
            except socket.error:
                return None  # not a valid IP address
            return socket.AF_INET6
        return socket.AF_INET


class Helpers:

    @staticmethod
    def chunk_string(input_string, length):
        return (input_string[0 + i:length + i] for i in range(0, len(input_string), length))


class Cipher(object):

    def __init__(self, cipher: tuple):
        self.bytes = cipher[0]
        self.name = cipher[1]

    @property
    def bits(self):  # This covers most usual ciphers
        if re.search('WITH_NULL', self.name):
            return None
        elif re.search('(_40_|DES40)', self.name):
            return 40
        elif re.search('(_56_|DES_CBC_(?!40))', self.name):
            return 56
        elif re.search('3DES', self.name):
            return 112  # theoretically 168
        elif re.search('(IDEA_CBC|SEED_CBC|^TLS.*?_128_)', self.name):
            return 128
        elif re.search('(_256_|CHACHA20)', self.name):
            return 256
        else:
            return None


class Extension(object):
    """
    rfc6066
    """

    def __init__(self, extension_type):
        self.extension_type = extension_type
        self.length = 0

    def get_bytes(self):
        extension_data = b''
        if self.extension_data:
            extension_data = self.extension_data
        extension_parts = [
            struct.pack("!H", self.extension_type),
            struct.pack("!H", self.length),
            extension_data,
        ]
        return b''.join(extension_parts)


class EllipticCurves(Extension):
    """
    rfc4492
    """

    def __init__(self, elliptic_curve_list):
        super(self.__class__, self).__init__(TLS.ExtensionType.elliptic_curves)
        self.elliptic_curve_list = elliptic_curve_list
        # include a length field of 2 bytes
        self.length = len(self.curves_bytes) + 2

    @property
    def extension_data(self):
        data = [
            struct.pack("!H", len(self.curves_bytes)),  # LENGTH
            self.curves_bytes
        ]
        return b''.join(data)

    @property
    def curves_bytes(self):
        curve_bytes = b''
        for curve in self.elliptic_curve_list:
            curve_bytes += struct.pack('!H', curve.value)
        return curve_bytes


class ECPointFormats(Extension):
    """
    rfc4492
    """

    def __init__(self, ec_point_format_list):
        super(self.__class__, self).__init__(
            TLS.ExtensionType.ec_point_formats)
        self.ec_point_format_list = ec_point_format_list
        self.length = len(self.ec_point_format_list) + \
            1  # include a length field of 1 byte

    @property
    def extension_data(self):
        data = [
            bytes([len(self.ec_point_format_list)]),
            bytes(self.get_point_format_values),
        ]
        return b''.join(data)

    @property  # this should not be a property
    def get_point_format_values(self):
        point_format = []
        for ec_point_format in self.ec_point_format_list:
            point_format.append(ec_point_format.value)
        return point_format


class SignatureAlgorithms(Extension):
    """
    rfc5246
    """

    def __init__(self, signature_hash_list):
        super(self.__class__, self).__init__(
            TLS.ExtensionType.signature_algorithms)
        self.signature_hash_list = signature_hash_list
        self.length = len(self.hash_signature_bytes) + \
            2  # include a length field

    @property
    def extension_data(self):
        data = [
            struct.pack('!H', len(self.hash_signature_bytes)),
            self.hash_signature_bytes
        ]
        return b''.join(data)

    @property
    def hash_signature_bytes(self):
        hs_bytes = b''
        for hs in self.signature_hash_list:
            hs_bytes += bytes([hs[0].value]) + bytes([hs[1].value])
        return hs_bytes


class SessionTicketTLS(Extension):
    """
    rfc4507
    """

    def __init__(self):
        super(self.__class__, self).__init__(
            TLS.ExtensionType.session_ticket_tls)
        self.length = len(self.extension_data)

    @property
    def extension_data(self):
        return b''


class ServerName(Extension):

    def __init__(self, server_name):
        super(self.__class__, self).__init__(TLS.ExtensionType.server_name)
        self.server_name = server_name
        self.length = len(self.server_name) + 5

    @property
    def extension_data(self):
        data = [
            struct.pack('!H', len(self.server_name) + 3),
            b'\x00',  # Name type "host_name"
            struct.pack('!H', len(self.server_name)),
            bytes(self.server_name, 'utf-8'),
        ]
        return b''.join(data)


class HeartBeat(Extension):
    """
    rfc6520
    """

    def __init__(self, allowed):
        super(self.__class__, self).__init__(TLS.ExtensionType.heartbeat)
        if allowed:
            self.allowed = True
        else:
            self.allowed = False
        self.length = len(self.extension_data)

    @property
    def extension_data(self):
        allowed = 2  # peer_not_allowed_to_send
        if self.allowed:
            allowed = 1  # peer_allowed_to_send
        data = [
            bytes([allowed]),
        ]
        return b''.join(data)


class Record(object):

    def __init__(self, version, content_type, body=b''):
        self.content_type = content_type
        self.version = version
        self.length = 0
        self.body = body
        self.body_info = {}  # To hold details about the body

    def get_bytes(self):
        record_parts = []
        if TLS.is_ssl3_tls(self.version):
            record_parts = [  # TLS/SSLv3 record: TYPE, LENGTH, VERSION, BODY (content)
                bytes([self.content_type]),
                bytes(self.version),
                struct.pack("!H", self.length),
                self.body
            ]
        elif TLS.is_ssl2(self.version) and self.content_type == TLS.HandshakeTypeSsl2.client_hello:
            record_parts = [  # SSLv2 record : LENGTH, TYPE, VERSION, BODY (content)
                struct.pack("!H", self.length),
                bytes([self.content_type]),
                bytes(self.version),  # tuple -> bytes
                self.body
            ]
        elif TLS.is_ssl2(self.version) and self.content_type == TLS.HandshakeTypeSsl2.server_hello:
            error("The byte representation of SSL2 server_hello is not implemented")
        else:
            error("Unknown record type")
        return b''.join(record_parts)


class ClientHello(Record):

    def __init__(self, version, ciphers_dict):
        self.cipher_suites = ciphers_dict
        self.extension_list = []
        try:
            if TLS.is_ssl3_tls(version):
                super(self.__class__, self).__init__(
                    (3, 1), TLS.ContentType.handshake)  # Record version set to TLSv1_0
                self.handshake_version = version
                self.compression = b'\x00'
                # 32 random + 4 length + ..
                self.length = len(self.cipher_spec) + \
                    len(self.compression) + 42
                self.set_tls_hello_body_bytes()

            elif TLS.is_ssl2(version):
                super(self.__class__, self).__init__(
                    version, TLS.HandshakeTypeSsl2.client_hello)
                self.challenge = b'\x6a\x61\x6e\x73\x65\x6e\x6f\x66\x6c\x6f\x72\x6b\x65\x65\x72\x73'
                record_length = len(self.cipher_spec) + len(self.challenge) + 9
                self.length = TLS.get_ssl2_record_len(
                    record_length, True)  # Set MSB (no padding)

                self.set_ssl2_hello_body_bytes()
        except Exception:
            error("Failed to craft ClientHello")

    def set_tls_hello_body_bytes(self):
        extension_list_bytes = self.get_extension_list_bytes()
        extension_length = b''
        if extension_list_bytes:
            self.length = len(
                self.cipher_spec) + len(self.compression) + 42 + len(extension_list_bytes) + 2
            extension_length = struct.pack('!H', len(extension_list_bytes))
        body_len = self.length - 4
        body_parts = [  # Humor?
            bytes([TLS.HandshakeType.client_hello]),  # Non human body type
            struct.pack("!L", body_len)[1:],
            bytes(self.handshake_version),
            self.hello_rand,
            b'\x00',
            struct.pack("!H", len(self.cipher_spec)),
            self.cipher_spec,
            struct.pack('!B', len(self.compression)),
            self.compression,
            extension_length,
            extension_list_bytes,
        ]
        self.body = b''.join(body_parts)

    def set_ssl2_hello_body_bytes(self):
        body_parts = [
            struct.pack("!H", len(self.cipher_spec)),
            b'\x00\x00',
            struct.pack("!H", len(self.challenge)),
            self.cipher_spec,
            self.challenge
        ]
        self.body = b''.join(body_parts)

    def add_extension(self, extension):
        if TLS.is_ssl3_tls(self.version) and isinstance(extension, Extension):
            try:
                self.extension_list.append(extension)
                self.set_tls_hello_body_bytes()  # We need to update the hello_body
            except:
                error("Something went wrong adding extension type: {0}".format(
                    extension.extension_type))
        # else:
         #   sys.exit("Cannot add extension to the protocol!")

    def set_compression(self, compression: bytearray):
        if TLS.is_ssl3_tls(self.version):
            self.compression = compression
            self.set_tls_hello_body_bytes()

    def get_extension_list_bytes(self):
        """
        Converts the extension_list to their respective bytes
        :return: bytes
        """
        list_bytes = b''
        if self.extension_list:
            for extension in self.extension_list:
                list_bytes += extension.get_bytes()
        return list_bytes

    @property
    def cipher_spec(self):
        return b''.join(self.cipher_suites)

    @property
    def hello_rand(self):
        rand = [
            struct.pack("!L", int(time.time())),  # 4 bytes
            os.urandom(28)
        ]
        return b''.join(rand)


class ServerHello(Record):

    def __init__(self, version, body):
        if TLS.is_ssl3_tls(version):
            super(self.__class__, self).__init__(
                version, TLS.ContentType.handshake)
        elif TLS.is_ssl2(version):
            super(self.__class__, self).__init__(
                version, TLS.HandshakeTypeSsl2.server_hello)
  #      else:
   #         sys.exit("Unsupported protocol")
        self.length = len(body)
        self.body = body
        self.create_server_hello_body()  # Not really useful atm

    def create_server_hello_body(self):  # Check if applicable for SSL2
        self.body_info['type'] = self.body[0]
        #self.body_info['length'] = self.length - 4

    @property
    def response_cipher(self):
        # TYPE(1), LENGTH(3), VERSION(2), RANDOM(32), SID_LENGTH(1) <-- 39 Bytes
        start = struct.unpack('!b', self.body[38:39])[
            0] + 39  # SID_LENGTH + 39 Bytes
        cipher = self.body[start:start+2]
        if cipher in TLS.ciphers_tls:
            return Cipher((cipher, TLS.ciphers_tls[cipher]))
        else:
            return Cipher((cipher, 'UNKNOWN_CIPHER'))

    @property
    def ssl2_response_ciphers(self):  # Add check to see if version is SSLv2
        ciphers = []
        cert_length = struct.unpack('!H', self.body[4:6])[
            0]  # Body starts at SessionID
        cipher_spec_length = struct.unpack('!H', self.body[6:8])[0]
        if cipher_spec_length % 3 == 0:
            start = 10 + cert_length
            cipher_spec = self.body[start:start + cipher_spec_length]
            ciphers = list(Helpers.chunk_string(cipher_spec, 3))
            for i in range(0, len(ciphers), 1):
                ciphers[i] = ciphers[i], TLS.ciphers_ssl2[ciphers[i]]
        else:
            error("Something wrong with cipher length")
        return ciphers

    @property
    def handshake_protocol(self):
        if TLS.is_ssl3_tls(self.version):
            version = TLS.get_version_from_bytes(self.body[4:6])
        else:
            version = self.version
        return version

    @property
    def compression_method(self):
        if TLS.is_ssl3_tls(self.version):
            start = struct.unpack('!b', self.body[38:39])[0] + 41
            compression = self.body[start:start+1]
            return TLS.CompressionMethod(struct.unpack('!B', compression)[0])


class TLS(object):

    def __init__(self, tcp):
        self.verbose = False
        self.TCP = tcp

    max_record_length = 4096

    class Protocols:
        TLS = 'TLS'  # All TLS versions an SSLv3
        SSL2 = 'SSLv2'

    versions = {
        'SSLv2': (0, 2),
        'SSLv3': (3, 0),
        'TLSv1_0': (3, 1),
        'TLSv1_1': (3, 2),
        'TLSv1_2': (3, 3),
        'TLSv1_3': (3, 4),
    }

    # Look into creating an Enum for this
    ciphers_ssl2 = {
        b'\x01\x00\x80': 'SSL2_RC4_128_WITH_MD5',
        b'\x02\x00\x80': 'SSL2_RC4_128_EXPORT40_WITH_MD5',
        b'\x03\x00\x80': 'SSL2_RC2_CBC_128_CBC_WITH_MD5',
        b'\x04\x00\x80': 'SSL2_RC2_CBC_128_CBC_WITH_MD5',
        b'\x05\x00\x80': 'SSL2_IDEA_128_CBC_WITH_MD5',
        b'\x06\x00\x40': 'SSL2_DES_64_CBC_WITH_MD5',
        b'\x07\x00\xC0': 'SSL2_DES_192_EDE3_CBC_WITH_MD5',
        b'\x08\x00\x80': 'SSL2_RC4_64_WITH_MD5'
    }

    @staticmethod
    def get_cipher_list(protocol):
        if protocol == TLS.Protocols.TLS:
            return list(TLS.ciphers_tls)
        elif protocol == TLS.Protocols.SSL2:
            return list(TLS.ciphers_ssl2)

    ciphers_tls = {  # This should be kept up to date
        b'\x00\x00': 'TLS_NULL_WITH_NULL_NULL',
        b'\x00\x01': 'TLS_RSA_WITH_NULL_MD5',
        b'\x00\x02': 'TLS_RSA_WITH_NULL_SHA',
        b'\x00\x03': 'TLS_RSA_EXPORT_WITH_RC4_40_MD5',
        b'\x00\x04': 'TLS_RSA_WITH_RC4_128_MD5',
        b'\x00\x05': 'TLS_RSA_WITH_RC4_128_SHA',
        b'\x00\x06': 'TLS_RSA_EXPORT_WITH_RC2_CBC_40_MD5',
        b'\x00\x07': 'TLS_RSA_WITH_IDEA_CBC_SHA',
        b'\x00\x08': 'TLS_RSA_EXPORT_WITH_DES40_CBC_SHA',
        b'\x00\x09': 'TLS_RSA_WITH_DES_CBC_SHA',
        b'\x00\x0A': 'TLS_RSA_WITH_3DES_EDE_CBC_SHA',
        b'\x00\x0B': 'TLS_DH_DSS_EXPORT_WITH_DES40_CBC_SHA',
        b'\x00\x0C': 'TLS_DH_DSS_WITH_DES_CBC_SHA',
        b'\x00\x0D': 'TLS_DH_DSS_WITH_3DES_EDE_CBC_SHA',
        b'\x00\x0E': 'TLS_DH_RSA_EXPORT_WITH_DES40_CBC_SHA',
        b'\x00\x0F': 'TLS_DH_RSA_WITH_DES_CBC_SHA',
        b'\x00\x10': 'TLS_DH_RSA_WITH_3DES_EDE_CBC_SHA',
        b'\x00\x11': 'TLS_DHE_DSS_EXPORT_WITH_DES40_CBC_SHA',
        b'\x00\x12': 'TLS_DHE_DSS_WITH_DES_CBC_SHA',
        b'\x00\x13': 'TLS_DHE_DSS_WITH_3DES_EDE_CBC_SHA',
        b'\x00\x14': 'TLS_DHE_RSA_EXPORT_WITH_DES40_CBC_SHA',
        b'\x00\x15': 'TLS_DHE_RSA_WITH_DES_CBC_SHA',
        b'\x00\x16': 'TLS_DHE_RSA_WITH_3DES_EDE_CBC_SHA',
        b'\x00\x17': 'TLS_DH_anon_EXPORT_WITH_RC4_40_MD5',
        b'\x00\x18': 'TLS_DH_anon_WITH_RC4_128_MD5',
        b'\x00\x19': 'TLS_DH_anon_EXPORT_WITH_DES40_CBC_SHA',
        b'\x00\x1A': 'TLS_DH_anon_WITH_DES_CBC_SHA',
        b'\x00\x1B': 'TLS_DH_anon_WITH_3DES_EDE_CBC_SHA',
        b'\x00\x1E': 'TLS_KRB5_WITH_DES_CBC_SHA',
        b'\x00\x1F': 'TLS_KRB5_WITH_3DES_EDE_CBC_SHA',
        b'\x00\x20': 'TLS_KRB5_WITH_RC4_128_SHA',
        b'\x00\x21': 'TLS_KRB5_WITH_IDEA_CBC_SHA',
        b'\x00\x22': 'TLS_KRB5_WITH_DES_CBC_MD5',
        b'\x00\x23': 'TLS_KRB5_WITH_3DES_EDE_CBC_MD5',
        b'\x00\x24': 'TLS_KRB5_WITH_RC4_128_MD5',
        b'\x00\x25': 'TLS_KRB5_WITH_IDEA_CBC_MD5',
        b'\x00\x26': 'TLS_KRB5_EXPORT_WITH_DES_CBC_40_SHA',
        b'\x00\x27': 'TLS_KRB5_EXPORT_WITH_RC2_CBC_40_SHA',
        b'\x00\x28': 'TLS_KRB5_EXPORT_WITH_RC4_40_SHA',
        b'\x00\x29': 'TLS_KRB5_EXPORT_WITH_DES_CBC_40_MD5',
        b'\x00\x2A': 'TLS_KRB5_EXPORT_WITH_RC2_CBC_40_MD5',
        b'\x00\x2B': 'TLS_KRB5_EXPORT_WITH_RC4_40_MD5',
        b'\x00\x2C': 'TLS_PSK_WITH_NULL_SHA',
        b'\x00\x2D': 'TLS_DHE_PSK_WITH_NULL_SHA',
        b'\x00\x2E': 'TLS_RSA_PSK_WITH_NULL_SHA',
        b'\x00\x2F': 'TLS_RSA_WITH_AES_128_CBC_SHA',  # TLS1_2 mandatory cipher
        b'\x00\x30': 'TLS_DH_DSS_WITH_AES_128_CBC_SHA',
        b'\x00\x31': 'TLS_DH_RSA_WITH_AES_128_CBC_SHA',
        b'\x00\x32': 'TLS_DHE_DSS_WITH_AES_128_CBC_SHA',
        b'\x00\x33': 'TLS_DHE_RSA_WITH_AES_128_CBC_SHA',
        b'\x00\x34': 'TLS_DH_anon_WITH_AES_128_CBC_SHA',
        b'\x00\x35': 'TLS_RSA_WITH_AES_256_CBC_SHA',
        b'\x00\x36': 'TLS_DH_DSS_WITH_AES_256_CBC_SHA',
        b'\x00\x37': 'TLS_DH_RSA_WITH_AES_256_CBC_SHA',
        b'\x00\x38': 'TLS_DHE_DSS_WITH_AES_256_CBC_SHA',
        b'\x00\x39': 'TLS_DHE_RSA_WITH_AES_256_CBC_SHA',
        b'\x00\x3A': 'TLS_DH_anon_WITH_AES_256_CBC_SHA',
        b'\x00\x3B': 'TLS_RSA_WITH_NULL_SHA256',
        b'\x00\x3C': 'TLS_RSA_WITH_AES_128_CBC_SHA256',
        b'\x00\x3D': 'TLS_RSA_WITH_AES_256_CBC_SHA256',
        b'\x00\x3E': 'TLS_DH_DSS_WITH_AES_128_CBC_SHA256',
        b'\x00\x3F': 'TLS_DH_RSA_WITH_AES_128_CBC_SHA256',
        b'\x00\x40': 'TLS_DHE_DSS_WITH_AES_128_CBC_SHA256',
        b'\x00\x41': 'TLS_RSA_WITH_CAMELLIA_128_CBC_SHA',
        b'\x00\x42': 'TLS_DH_DSS_WITH_CAMELLIA_128_CBC_SHA',
        b'\x00\x43': 'TLS_DH_RSA_WITH_CAMELLIA_128_CBC_SHA',
        b'\x00\x44': 'TLS_DHE_DSS_WITH_CAMELLIA_128_CBC_SHA',
        b'\x00\x45': 'TLS_DHE_RSA_WITH_CAMELLIA_128_CBC_SHA',
        b'\x00\x46': 'TLS_DH_anon_WITH_CAMELLIA_128_CBC_SHA',
        b'\x00\x60': 'TLS_RSA_EXPORT1024_WITH_RC4_56_MD5',
        b'\x00\x61': 'TLS_RSA_EXPORT1024_WITH_RC2_CBC_56_MD5',
        # http://tools.ietf.org/html/draft-ietf-tls-56-bit-ciphersuites-01 (next 5)
        b'\x00\x62': 'TLS_RSA_EXPORT1024_WITH_DES_CBC_SHA',
        b'\x00\x63': 'TLS_DHE_DSS_EXPORT1024_WITH_DES_CBC_SHA',
        b'\x00\x64': 'TLS_RSA_EXPORT1024_WITH_RC4_56_SHA',
        b'\x00\x65': 'TLS_DHE_DSS_EXPORT1024_WITH_RC4_56_SHA',
        b'\x00\x66': 'TLS_DHE_DSS_WITH_RC4_128_SHA',
        b'\x00\x67': 'TLS_DHE_RSA_WITH_AES_128_CBC_SHA256',
        b'\x00\x68': 'TLS_DH_DSS_WITH_AES_256_CBC_SHA256',
        b'\x00\x69': 'TLS_DH_RSA_WITH_AES_256_CBC_SHA256',
        b'\x00\x6A': 'TLS_DHE_DSS_WITH_AES_256_CBC_SHA256',
        b'\x00\x6B': 'TLS_DHE_RSA_WITH_AES_256_CBC_SHA256',
        b'\x00\x6C': 'TLS_DH_anon_WITH_AES_128_CBC_SHA256',
        b'\x00\x6D': 'TLS_DH_anon_WITH_AES_256_CBC_SHA256',
        # http://tools.ietf.org/html/draft-chudov-cryptopro-cptls-04 (next 4)
        b'\x00\x80': 'TLS_GOSTR341094_WITH_28147_CNT_IMIT',
        b'\x00\x81': 'TLS_GOSTR341001_WITH_28147_CNT_IMIT',
        b'\x00\x82': 'TLS_GOSTR341094_WITH_NULL_GOSTR3411',
        b'\x00\x83': 'TLS_GOSTR341001_WITH_NULL_GOSTR3411',
        b'\x00\x84': 'TLS_RSA_WITH_CAMELLIA_256_CBC_SHA',
        b'\x00\x85': 'TLS_DH_DSS_WITH_CAMELLIA_256_CBC_SHA',
        b'\x00\x86': 'TLS_DH_RSA_WITH_CAMELLIA_256_CBC_SHA',
        b'\x00\x87': 'TLS_DHE_DSS_WITH_CAMELLIA_256_CBC_SHA',
        b'\x00\x88': 'TLS_DHE_RSA_WITH_CAMELLIA_256_CBC_SHA',
        b'\x00\x89': 'TLS_DH_anon_WITH_CAMELLIA_256_CBC_SHA',
        b'\x00\x8A': 'TLS_PSK_WITH_RC4_128_SHA',
        b'\x00\x8B': 'TLS_PSK_WITH_3DES_EDE_CBC_SHA',
        b'\x00\x8C': 'TLS_PSK_WITH_AES_128_CBC_SHA',
        b'\x00\x8D': 'TLS_PSK_WITH_AES_256_CBC_SHA',
        b'\x00\x8E': 'TLS_DHE_PSK_WITH_RC4_128_SHA',
        b'\x00\x8F': 'TLS_DHE_PSK_WITH_3DES_EDE_CBC_SHA',
        b'\x00\x90': 'TLS_DHE_PSK_WITH_AES_128_CBC_SHA',
        b'\x00\x91': 'TLS_DHE_PSK_WITH_AES_256_CBC_SHA',
        b'\x00\x92': 'TLS_RSA_PSK_WITH_RC4_128_SHA',
        b'\x00\x93': 'TLS_RSA_PSK_WITH_3DES_EDE_CBC_SHA',
        b'\x00\x94': 'TLS_RSA_PSK_WITH_AES_128_CBC_SHA',
        b'\x00\x95': 'TLS_RSA_PSK_WITH_AES_256_CBC_SHA',
        b'\x00\x96': 'TLS_RSA_WITH_SEED_CBC_SHA',
        b'\x00\x97': 'TLS_DH_DSS_WITH_SEED_CBC_SHA',
        b'\x00\x98': 'TLS_DH_RSA_WITH_SEED_CBC_SHA',
        b'\x00\x99': 'TLS_DHE_DSS_WITH_SEED_CBC_SHA',
        b'\x00\x9A': 'TLS_DHE_RSA_WITH_SEED_CBC_SHA',
        b'\x00\x9B': 'TLS_DH_anon_WITH_SEED_CBC_SHA',
        b'\x00\x9C': 'TLS_RSA_WITH_AES_128_GCM_SHA256',
        b'\x00\x9D': 'TLS_RSA_WITH_AES_256_GCM_SHA384',
        b'\x00\x9E': 'TLS_DHE_RSA_WITH_AES_128_GCM_SHA256',
        b'\x00\x9F': 'TLS_DHE_RSA_WITH_AES_256_GCM_SHA384',
        b'\x00\xA0': 'TLS_DH_RSA_WITH_AES_128_GCM_SHA256',
        b'\x00\xA1': 'TLS_DH_RSA_WITH_AES_256_GCM_SHA384',
        b'\x00\xA2': 'TLS_DHE_DSS_WITH_AES_128_GCM_SHA256',
        b'\x00\xA3': 'TLS_DHE_DSS_WITH_AES_256_GCM_SHA384',
        b'\x00\xA4': 'TLS_DH_DSS_WITH_AES_128_GCM_SHA256',
        b'\x00\xA5': 'TLS_DH_DSS_WITH_AES_256_GCM_SHA384',
        b'\x00\xA6': 'TLS_DH_anon_WITH_AES_128_GCM_SHA256',
        b'\x00\xA7': 'TLS_DH_anon_WITH_AES_256_GCM_SHA384',
        b'\x00\xA8': 'TLS_PSK_WITH_AES_128_GCM_SHA256',
        b'\x00\xA9': 'TLS_PSK_WITH_AES_256_GCM_SHA384',
        b'\x00\xAA': 'TLS_DHE_PSK_WITH_AES_128_GCM_SHA256',
        b'\x00\xAB': 'TLS_DHE_PSK_WITH_AES_256_GCM_SHA384',
        b'\x00\xAC': 'TLS_RSA_PSK_WITH_AES_128_GCM_SHA256',
        b'\x00\xAD': 'TLS_RSA_PSK_WITH_AES_256_GCM_SHA384',
        b'\x00\xAE': 'TLS_PSK_WITH_AES_128_CBC_SHA256',
        b'\x00\xAF': 'TLS_PSK_WITH_AES_256_CBC_SHA384',
        b'\x00\xB0': 'TLS_PSK_WITH_NULL_SHA256',
        b'\x00\xB1': 'TLS_PSK_WITH_NULL_SHA384',
        b'\x00\xB2': 'TLS_DHE_PSK_WITH_AES_128_CBC_SHA256',
        b'\x00\xB3': 'TLS_DHE_PSK_WITH_AES_256_CBC_SHA384',
        b'\x00\xB4': 'TLS_DHE_PSK_WITH_NULL_SHA256',
        b'\x00\xB5': 'TLS_DHE_PSK_WITH_NULL_SHA384',
        b'\x00\xB6': 'TLS_RSA_PSK_WITH_AES_128_CBC_SHA256',
        b'\x00\xB7': 'TLS_RSA_PSK_WITH_AES_256_CBC_SHA384',
        b'\x00\xB8': 'TLS_RSA_PSK_WITH_NULL_SHA256',
        b'\x00\xB9': 'TLS_RSA_PSK_WITH_NULL_SHA384',
        b'\x00\xBA': 'TLS_RSA_WITH_CAMELLIA_128_CBC_SHA256',
        b'\x00\xBB': 'TLS_DH_DSS_WITH_CAMELLIA_128_CBC_SHA256',
        b'\x00\xBC': 'TLS_DH_RSA_WITH_CAMELLIA_128_CBC_SHA256',
        b'\x00\xBD': 'TLS_DHE_DSS_WITH_CAMELLIA_128_CBC_SHA256',
        b'\x00\xBE': 'TLS_DHE_RSA_WITH_CAMELLIA_128_CBC_SHA256',
        b'\x00\xBF': 'TLS_DH_anon_WITH_CAMELLIA_128_CBC_SHA256',
        b'\x00\xC0': 'TLS_RSA_WITH_CAMELLIA_256_CBC_SHA256',
        b'\x00\xC1': 'TLS_DH_DSS_WITH_CAMELLIA_256_CBC_SHA256',
        b'\x00\xC2': 'TLS_DH_RSA_WITH_CAMELLIA_256_CBC_SHA256',
        b'\x00\xC3': 'TLS_DHE_DSS_WITH_CAMELLIA_256_CBC_SHA256',
        b'\x00\xC4': 'TLS_DHE_RSA_WITH_CAMELLIA_256_CBC_SHA256',
        b'\x00\xC5': 'TLS_DH_anon_WITH_CAMELLIA_256_CBC_SHA256',
        b'\x00\xFF': 'TLS_EMPTY_RENEGOTIATION_INFO_SCSV',  # Special purpose
        b'\xC0\x01': 'TLS_ECDH_ECDSA_WITH_NULL_SHA',
        b'\xC0\x02': 'TLS_ECDH_ECDSA_WITH_RC4_128_SHA',
        b'\xC0\x03': 'TLS_ECDH_ECDSA_WITH_3DES_EDE_CBC_SHA',
        b'\xC0\x04': 'TLS_ECDH_ECDSA_WITH_AES_128_CBC_SHA',
        b'\xC0\x05': 'TLS_ECDH_ECDSA_WITH_AES_256_CBC_SHA',
        b'\xC0\x06': 'TLS_ECDHE_ECDSA_WITH_NULL_SHA',
        b'\xC0\x07': 'TLS_ECDHE_ECDSA_WITH_RC4_128_SHA',
        b'\xC0\x08': 'TLS_ECDHE_ECDSA_WITH_3DES_EDE_CBC_SHA',
        b'\xC0\x09': 'TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA',
        b'\xC0\x0A': 'TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA',
        b'\xC0\x0B': 'TLS_ECDH_RSA_WITH_NULL_SHA',
        b'\xC0\x0C': 'TLS_ECDH_RSA_WITH_RC4_128_SHA',
        b'\xC0\x0D': 'TLS_ECDH_RSA_WITH_3DES_EDE_CBC_SHA',
        b'\xC0\x0E': 'TLS_ECDH_RSA_WITH_AES_128_CBC_SHA',
        b'\xC0\x0F': 'TLS_ECDH_RSA_WITH_AES_256_CBC_SHA',
        b'\xC0\x10': 'TLS_ECDHE_RSA_WITH_NULL_SHA',
        b'\xC0\x11': 'TLS_ECDHE_RSA_WITH_RC4_128_SHA',
        b'\xC0\x12': 'TLS_ECDHE_RSA_WITH_3DES_EDE_CBC_SHA',
        b'\xC0\x13': 'TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA',
        b'\xC0\x14': 'TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA',
        b'\xC0\x15': 'TLS_ECDH_anon_WITH_NULL_SHA',
        b'\xC0\x16': 'TLS_ECDH_anon_WITH_RC4_128_SHA',
        b'\xC0\x17': 'TLS_ECDH_anon_WITH_3DES_EDE_CBC_SHA',
        b'\xC0\x18': 'TLS_ECDH_anon_WITH_AES_128_CBC_SHA',
        b'\xC0\x19': 'TLS_ECDH_anon_WITH_AES_256_CBC_SHA',
        b'\xC0\x1A': 'TLS_SRP_SHA_WITH_3DES_EDE_CBC_SHA',
        b'\xC0\x1B': 'TLS_SRP_SHA_RSA_WITH_3DES_EDE_CBC_SHA',
        b'\xC0\x1C': 'TLS_SRP_SHA_DSS_WITH_3DES_EDE_CBC_SHA',
        b'\xC0\x1D': 'TLS_SRP_SHA_WITH_AES_128_CBC_SHA',
        b'\xC0\x1E': 'TLS_SRP_SHA_RSA_WITH_AES_128_CBC_SHA',
        b'\xC0\x1F': 'TLS_SRP_SHA_DSS_WITH_AES_128_CBC_SHA',
        b'\xC0\x20': 'TLS_SRP_SHA_WITH_AES_256_CBC_SHA',
        b'\xC0\x21': 'TLS_SRP_SHA_RSA_WITH_AES_256_CBC_SHA',
        b'\xC0\x22': 'TLS_SRP_SHA_DSS_WITH_AES_256_CBC_SHA',
        b'\xC0\x23': 'TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA256',
        b'\xC0\x24': 'TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA384',
        b'\xC0\x25': 'TLS_ECDH_ECDSA_WITH_AES_128_CBC_SHA256',
        b'\xC0\x26': 'TLS_ECDH_ECDSA_WITH_AES_256_CBC_SHA384',
        b'\xC0\x27': 'TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA256',
        b'\xC0\x28': 'TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA384',
        b'\xC0\x29': 'TLS_ECDH_RSA_WITH_AES_128_CBC_SHA256',
        b'\xC0\x2A': 'TLS_ECDH_RSA_WITH_AES_256_CBC_SHA384',
        b'\xC0\x2B': 'TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256',
        b'\xC0\x2C': 'TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384',
        b'\xC0\x2D': 'TLS_ECDH_ECDSA_WITH_AES_128_GCM_SHA256',
        b'\xC0\x2E': 'TLS_ECDH_ECDSA_WITH_AES_256_GCM_SHA384',
        b'\xC0\x2F': 'TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256',
        b'\xC0\x30': 'TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384',
        b'\xC0\x31': 'TLS_ECDH_RSA_WITH_AES_128_GCM_SHA256',
        b'\xC0\x32': 'TLS_ECDH_RSA_WITH_AES_256_GCM_SHA384',
        b'\xC0\x33': 'TLS_ECDHE_PSK_WITH_RC4_128_SHA',
        b'\xC0\x34': 'TLS_ECDHE_PSK_WITH_3DES_EDE_CBC_SHA',
        b'\xC0\x35': 'TLS_ECDHE_PSK_WITH_AES_128_CBC_SHA',
        b'\xC0\x36': 'TLS_ECDHE_PSK_WITH_AES_256_CBC_SHA',
        b'\xC0\x37': 'TLS_ECDHE_PSK_WITH_AES_128_CBC_SHA256',
        b'\xC0\x38': 'TLS_ECDHE_PSK_WITH_AES_256_CBC_SHA384',
        b'\xC0\x39': 'TLS_ECDHE_PSK_WITH_NULL_SHA',
        b'\xC0\x3A': 'TLS_ECDHE_PSK_WITH_NULL_SHA256',
        b'\xC0\x3B': 'TLS_ECDHE_PSK_WITH_NULL_SHA384',
        b'\xC0\x3C': 'TLS_RSA_WITH_ARIA_128_CBC_SHA256',
        b'\xC0\x3D': 'TLS_RSA_WITH_ARIA_256_CBC_SHA384',
        b'\xC0\x3E': 'TLS_DH_DSS_WITH_ARIA_128_CBC_SHA256',
        b'\xC0\x3F': 'TLS_DH_DSS_WITH_ARIA_256_CBC_SHA384',
        b'\xC0\x40': 'TLS_DH_RSA_WITH_ARIA_128_CBC_SHA256',
        b'\xC0\x41': 'TLS_DH_RSA_WITH_ARIA_256_CBC_SHA384',
        b'\xC0\x42': 'TLS_DHE_DSS_WITH_ARIA_128_CBC_SHA256',
        b'\xC0\x43': 'TLS_DHE_DSS_WITH_ARIA_256_CBC_SHA384',
        b'\xC0\x44': 'TLS_DHE_RSA_WITH_ARIA_128_CBC_SHA256',
        b'\xC0\x45': 'TLS_DHE_RSA_WITH_ARIA_256_CBC_SHA384',
        b'\xC0\x46': 'TLS_DH_anon_WITH_ARIA_128_CBC_SHA256',
        b'\xC0\x47': 'TLS_DH_anon_WITH_ARIA_256_CBC_SHA384',
        b'\xC0\x48': 'TLS_ECDHE_ECDSA_WITH_ARIA_128_CBC_SHA256',
        b'\xC0\x49': 'TLS_ECDHE_ECDSA_WITH_ARIA_256_CBC_SHA384',
        b'\xC0\x4A': 'TLS_ECDH_ECDSA_WITH_ARIA_128_CBC_SHA256',
        b'\xC0\x4B': 'TLS_ECDH_ECDSA_WITH_ARIA_256_CBC_SHA384',
        b'\xC0\x4C': 'TLS_ECDHE_RSA_WITH_ARIA_128_CBC_SHA256',
        b'\xC0\x4D': 'TLS_ECDHE_RSA_WITH_ARIA_256_CBC_SHA384',
        b'\xC0\x4E': 'TLS_ECDH_RSA_WITH_ARIA_128_CBC_SHA256',
        b'\xC0\x4F': 'TLS_ECDH_RSA_WITH_ARIA_256_CBC_SHA384',
        b'\xC0\x50': 'TLS_RSA_WITH_ARIA_128_GCM_SHA256',
        b'\xC0\x51': 'TLS_RSA_WITH_ARIA_256_GCM_SHA384',
        b'\xC0\x52': 'TLS_DHE_RSA_WITH_ARIA_128_GCM_SHA256',
        b'\xC0\x53': 'TLS_DHE_RSA_WITH_ARIA_256_GCM_SHA384',
        b'\xC0\x54': 'TLS_DH_RSA_WITH_ARIA_128_GCM_SHA256',
        b'\xC0\x55': 'TLS_DH_RSA_WITH_ARIA_256_GCM_SHA384',
        b'\xC0\x56': 'TLS_DHE_DSS_WITH_ARIA_128_GCM_SHA256',
        b'\xC0\x57': 'TLS_DHE_DSS_WITH_ARIA_256_GCM_SHA384',
        b'\xC0\x58': 'TLS_DH_DSS_WITH_ARIA_128_GCM_SHA256',
        b'\xC0\x59': 'TLS_DH_DSS_WITH_ARIA_256_GCM_SHA384',
        b'\xC0\x5A': 'TLS_DH_anon_WITH_ARIA_128_GCM_SHA256',
        b'\xC0\x5B': 'TLS_DH_anon_WITH_ARIA_256_GCM_SHA384',
        b'\xC0\x5C': 'TLS_ECDHE_ECDSA_WITH_ARIA_128_GCM_SHA256',
        b'\xC0\x5D': 'TLS_ECDHE_ECDSA_WITH_ARIA_256_GCM_SHA384',
        b'\xC0\x5E': 'TLS_ECDH_ECDSA_WITH_ARIA_128_GCM_SHA256',
        b'\xC0\x5F': 'TLS_ECDH_ECDSA_WITH_ARIA_256_GCM_SHA384',
        b'\xC0\x60': 'TLS_ECDHE_RSA_WITH_ARIA_128_GCM_SHA256',
        b'\xC0\x61': 'TLS_ECDHE_RSA_WITH_ARIA_256_GCM_SHA384',
        b'\xC0\x62': 'TLS_ECDH_RSA_WITH_ARIA_128_GCM_SHA256',
        b'\xC0\x63': 'TLS_ECDH_RSA_WITH_ARIA_256_GCM_SHA384',
        b'\xC0\x64': 'TLS_PSK_WITH_ARIA_128_CBC_SHA256',
        b'\xC0\x65': 'TLS_PSK_WITH_ARIA_256_CBC_SHA384',
        b'\xC0\x66': 'TLS_DHE_PSK_WITH_ARIA_128_CBC_SHA256',
        b'\xC0\x67': 'TLS_DHE_PSK_WITH_ARIA_256_CBC_SHA384',
        b'\xC0\x68': 'TLS_RSA_PSK_WITH_ARIA_128_CBC_SHA256',
        b'\xC0\x69': 'TLS_RSA_PSK_WITH_ARIA_256_CBC_SHA384',
        b'\xC0\x6A': 'TLS_PSK_WITH_ARIA_128_GCM_SHA256',
        b'\xC0\x6B': 'TLS_PSK_WITH_ARIA_256_GCM_SHA384',
        b'\xC0\x6C': 'TLS_DHE_PSK_WITH_ARIA_128_GCM_SHA256',
        b'\xC0\x6D': 'TLS_DHE_PSK_WITH_ARIA_256_GCM_SHA384',
        b'\xC0\x6E': 'TLS_RSA_PSK_WITH_ARIA_128_GCM_SHA256',
        b'\xC0\x6F': 'TLS_RSA_PSK_WITH_ARIA_256_GCM_SHA384',
        b'\xC0\x70': 'TLS_ECDHE_PSK_WITH_ARIA_128_CBC_SHA256',
        b'\xC0\x71': 'TLS_ECDHE_PSK_WITH_ARIA_256_CBC_SHA384',
        b'\xC0\x72': 'TLS_ECDHE_ECDSA_WITH_CAMELLIA_128_CBC_SHA256',
        b'\xC0\x73': 'TLS_ECDHE_ECDSA_WITH_CAMELLIA_256_CBC_SHA384',
        b'\xC0\x74': 'TLS_ECDH_ECDSA_WITH_CAMELLIA_128_CBC_SHA256',
        b'\xC0\x75': 'TLS_ECDH_ECDSA_WITH_CAMELLIA_256_CBC_SHA384',
        b'\xC0\x76': 'TLS_ECDHE_RSA_WITH_CAMELLIA_128_CBC_SHA256',
        b'\xC0\x77': 'TLS_ECDHE_RSA_WITH_CAMELLIA_256_CBC_SHA384',
        b'\xC0\x78': 'TLS_ECDH_RSA_WITH_CAMELLIA_128_CBC_SHA256',
        b'\xC0\x79': 'TLS_ECDH_RSA_WITH_CAMELLIA_256_CBC_SHA384',
        b'\xC0\x7A': 'TLS_RSA_WITH_CAMELLIA_128_GCM_SHA256',
        b'\xC0\x7B': 'TLS_RSA_WITH_CAMELLIA_256_GCM_SHA384',
        b'\xC0\x7C': 'TLS_DHE_RSA_WITH_CAMELLIA_128_GCM_SHA256',
        b'\xC0\x7D': 'TLS_DHE_RSA_WITH_CAMELLIA_256_GCM_SHA384',
        b'\xC0\x7E': 'TLS_DH_RSA_WITH_CAMELLIA_128_GCM_SHA256',
        b'\xC0\x7F': 'TLS_DH_RSA_WITH_CAMELLIA_256_GCM_SHA384',
        b'\xC0\x80': 'TLS_DHE_DSS_WITH_CAMELLIA_128_GCM_SHA256',
        b'\xC0\x81': 'TLS_DHE_DSS_WITH_CAMELLIA_256_GCM_SHA384',
        b'\xC0\x82': 'TLS_DH_DSS_WITH_CAMELLIA_128_GCM_SHA256',
        b'\xC0\x83': 'TLS_DH_DSS_WITH_CAMELLIA_256_GCM_SHA384',
        b'\xC0\x84': 'TLS_DH_anon_WITH_CAMELLIA_128_GCM_SHA256',
        b'\xC0\x85': 'TLS_DH_anon_WITH_CAMELLIA_256_GCM_SHA384',
        b'\xC0\x86': 'TLS_ECDHE_ECDSA_WITH_CAMELLIA_128_GCM_SHA256',
        b'\xC0\x87': 'TLS_ECDHE_ECDSA_WITH_CAMELLIA_256_GCM_SHA384',
        b'\xC0\x88': 'TLS_ECDH_ECDSA_WITH_CAMELLIA_128_GCM_SHA256',
        b'\xC0\x89': 'TLS_ECDH_ECDSA_WITH_CAMELLIA_256_GCM_SHA384',
        b'\xC0\x8A': 'TLS_ECDHE_RSA_WITH_CAMELLIA_128_GCM_SHA256',
        b'\xC0\x8B': 'TLS_ECDHE_RSA_WITH_CAMELLIA_256_GCM_SHA384',
        b'\xC0\x8C': 'TLS_ECDH_RSA_WITH_CAMELLIA_128_GCM_SHA256',
        b'\xC0\x8D': 'TLS_ECDH_RSA_WITH_CAMELLIA_256_GCM_SHA384',
        b'\xC0\x8E': 'TLS_PSK_WITH_CAMELLIA_128_GCM_SHA256',
        b'\xC0\x8F': 'TLS_PSK_WITH_CAMELLIA_256_GCM_SHA384',
        b'\xC0\x90': 'TLS_DHE_PSK_WITH_CAMELLIA_128_GCM_SHA256',
        b'\xC0\x91': 'TLS_DHE_PSK_WITH_CAMELLIA_256_GCM_SHA384',
        b'\xC0\x92': 'TLS_RSA_PSK_WITH_CAMELLIA_128_GCM_SHA256',
        b'\xC0\x93': 'TLS_RSA_PSK_WITH_CAMELLIA_256_GCM_SHA384',
        b'\xC0\x94': 'TLS_PSK_WITH_CAMELLIA_128_CBC_SHA256',
        b'\xC0\x95': 'TLS_PSK_WITH_CAMELLIA_256_CBC_SHA384',
        b'\xC0\x96': 'TLS_DHE_PSK_WITH_CAMELLIA_128_CBC_SHA256',
        b'\xC0\x97': 'TLS_DHE_PSK_WITH_CAMELLIA_256_CBC_SHA384',
        b'\xC0\x98': 'TLS_RSA_PSK_WITH_CAMELLIA_128_CBC_SHA256',
        b'\xC0\x99': 'TLS_RSA_PSK_WITH_CAMELLIA_256_CBC_SHA384',
        b'\xC0\x9A': 'TLS_ECDHE_PSK_WITH_CAMELLIA_128_CBC_SHA256',
        b'\xC0\x9B': 'TLS_ECDHE_PSK_WITH_CAMELLIA_256_CBC_SHA384',
        b'\xC0\x9C': 'TLS_RSA_WITH_AES_128_CCM',
        b'\xC0\x9D': 'TLS_RSA_WITH_AES_256_CCM',
        b'\xC0\x9E': 'TLS_DHE_RSA_WITH_AES_128_CCM',
        b'\xC0\x9F': 'TLS_DHE_RSA_WITH_AES_256_CCM',
        b'\xC0\xA0': 'TLS_RSA_WITH_AES_128_CCM_8',
        b'\xC0\xA1': 'TLS_RSA_WITH_AES_256_CCM_8',
        b'\xC0\xA2': 'TLS_DHE_RSA_WITH_AES_128_CCM_8',
        b'\xC0\xA3': 'TLS_DHE_RSA_WITH_AES_256_CCM_8',
        b'\xC0\xA4': 'TLS_PSK_WITH_AES_128_CCM',
        b'\xC0\xA5': 'TLS_PSK_WITH_AES_256_CCM',
        b'\xC0\xA6': 'TLS_DHE_PSK_WITH_AES_128_CCM',
        b'\xC0\xA7': 'TLS_DHE_PSK_WITH_AES_256_CCM',
        b'\xC0\xA8': 'TLS_PSK_WITH_AES_128_CCM_8',
        b'\xC0\xA9': 'TLS_PSK_WITH_AES_256_CCM_8',
        b'\xC0\xAA': 'TLS_PSK_DHE_WITH_AES_128_CCM_8',
        b'\xC0\xAB': 'TLS_PSK_DHE_WITH_AES_256_CCM_8',
        b'\xC0\xAC': 'TLS_ECDHE_ECDSA_WITH_AES_128_CCM',
        b'\xC0\xAD': 'TLS_ECDHE_ECDSA_WITH_AES_256_CCM',
        b'\xC0\xAE': 'TLS_ECDHE_ECDSA_WITH_AES_128_CCM_8',
        b'\xC0\xAF': 'TLS_ECDHE_ECDSA_WITH_AES_256_CCM_8',
        # draft-mavrogiannopoulos-chacha-tls-01
        b'\xCC\x12': 'TLS_RSA_WITH_CHACHA20_POLY1305_NON_IANA',
        b'\xCC\x13': 'TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256_NON_IANA',
        b'\xCC\x14': 'TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256_NON_IANA',
        b'\xCC\x15': 'TLS_DHE_RSA_WITH_CHACHA20_POLY1305_SHA256_NON_IANA',
        b'\xCC\x16': 'TLS_DHE_PSK_WITH_CHACHA20_POLY1305_SHA256_NON_IANA',
        b'\xCC\x17': 'TLS_PSK_WITH_CHACHA20_POLY1305_SHA256_NON_IANA',
        b'\xCC\x18': 'TLS_ECDHE_PSK_WITH_CHACHA20_POLY1305_SHA256_NON_IANA',
        b'\xCC\x19': 'TLS_RSA_PSK_WITH_CHACHA20_POLY1305_SHA256_NON_IANA',
        # rfc7905
        b'\xCC\xA8': 'TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256',
        b'\xCC\xA9': 'TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256',
        b'\xCC\xAA': 'TLS_DHE_RSA_WITH_CHACHA20_POLY1305_SHA256',
        b'\xCC\xAB': 'TLS_PSK_WITH_CHACHA20_POLY1305_SHA256',
        b'\xCC\xAC': 'TLS_ECDHE_PSK_WITH_CHACHA20_POLY1305_SHA256',
        b'\xCC\xAD': 'TLS_DHE_PSK_WITH_CHACHA20_POLY1305_SHA256',
        b'\xCC\xAE': 'TLS_RSA_PSK_WITH_CHACHA20_POLY1305_SHA256',
        b'\xFF\x01': 'TLS_RSA_WITH_28147_CNT_GOST94',
        b'\xFF\x02': 'TLS_RSA_GOST89MAC',  # Official name unknow
        b'\xFF\x03': 'TLS_RSA_GOST89STREAM',  # Official name unknown
        # http://www.mozilla.org/projects/security/pki/nss/ssl/fips-ssl-ciphersuites.html
        b'\xFE\xFE': 'SSL_RSA_FIPS_WITH_DES_CBC_SHA',
        b'\xFE\xFF': 'SSL_RSA_FIPS_WITH_3DES_EDE_CBC_SHA',
        b'\xFF\xE0': 'SSL_RSA_FIPS_WITH_3DES_EDE_CBC_SHA',
        b'\xFF\xE1': 'SSL_RSA_FIPS_WITH_DES_CBC_SHA',
        # Special one to indicate client's support for downgrade prevention - rfc7507
        # b'\x56\x00': 'TLS_FALLBACK_SCSV',  # Make a ClientHello property
    }

    class NamedCurve(Enum):
        sect163k1 = 1
        sect163r1 = 2
        sect163r2 = 3
        sect193r1 = 4
        sect193r2 = 5
        sect233k1 = 6
        sect233r1 = 7
        sect239k1 = 8
        sect283k1 = 9
        sect283r1 = 10
        sect409k1 = 11
        sect409r1 = 12
        sect571k1 = 13
        sect571r1 = 14
        secp160k1 = 15
        secp160r1 = 16
        secp160r2 = 17
        secp192k1 = 18
        secp192r1 = 19
        secp224k1 = 20
        secp224r1 = 21
        secp256k1 = 22
        secp256r1 = 23
        secp384r1 = 24
        secp521r1 = 25
        # rfc7027
        brainpoolP256r1 = 26
        brainpoolP384r1 = 27
        brainpoolP512r1 = 28
        ecdh_x25519 = 29  # Temp
        ecdh_x448 = 30  # Temp
        # rfc7919
        ffdhe2048 = 256
        ffdhe3072 = 257
        ffdhe4096 = 258
        ffdhe6144 = 259
        ffdhe8192 = 260
        arbitrary_explicit_prime_curves = 65281
        arbitrary_explicit_char2_curves = 65282

    class ECPointFormat(Enum):
        uncompressed = 0
        ansiX962_compressed_prime = 1
        ansiX962_compressed_char2 = 2

    class HashAlgorithm(Enum):
        none = 0
        md5 = 1
        sha1 = 2
        sha224 = 3
        sha256 = 4
        sha384 = 5
        sha512 = 6

    class SignatureAlgorithm(Enum):
        anonymous = 0
        rsa = 1
        dsa = 2
        ecdsa = 3

    class CompressionMethod(Enum):
        null = 0
        DEFLATE = 1  # RFC3749
        LZS = 64  # RFC3943

    class HandshakeType:
        hello_request = 0
        client_hello = 1
        server_hello = 2
        certificate = 11
        server_key_exchange = 12
        server_hello_done = 14
        certificate_status = 22

    class HandshakeTypeSsl2:
        client_hello = 1
        server_hello = 4

    class ContentType:
        handshake = 22
        alert = 21
        heartbeat = 24

    class AlertDescription:
        unexpected_message = 10
        handshake_failure = 40
        inappropriate_fallback = 86

    class ExtensionType:
        # http://www.iana.org/assignments/tls-extensiontype-values/tls-extensiontype-values.xhtml
        server_name = 0
        elliptic_curves = 10  # rfc4492
        ec_point_formats = 11  # rfc4492
        signature_algorithms = 13  # rfc5246
        heartbeat = 15
        encrypt_then_mac = 22
        session_ticket_tls = 35

    @staticmethod
    def is_ssl2(version):
        if version == TLS.versions['SSLv2']:
            return True

    @staticmethod
    def is_ssl3_tls(version):
        if version in TLS.versions.values() and not TLS.is_ssl2(version):
            return True

    @staticmethod
    def get_ssl2_record_len(value, msb=False):  # most significant bit
        if isinstance(value, int):
            if not msb:  # Clear msb
                value &= ~ (1 << 15)
            elif msb:  # Set msb
                value |= (1 << 15)
            return value
        else:
            error("get_ssl2_record_len needs an Integer")

    @staticmethod
    def get_version_from_bytes(version_bytes):
        version = ()
        if TLS.is_ssl3_tls((version_bytes[0], version_bytes[1])) or TLS.is_ssl2((version_bytes[0], version_bytes[1])):
            version = version_bytes[0], version_bytes[1]
        else:
            warn("Version not recognized {0}".format(version_bytes))
        return version

    def send_record(self, record_instance):
        response = []  # Create a list of record objects
     #   if not isinstance(record_instance, Record):
      #      sys.exit("send_record (TLS) was not passed a Record instance")
        try:
            # Sending the byte representation of the object
            self.TCP.send_all(record_instance.get_bytes())
            if TLS.is_ssl3_tls(record_instance.version):  # TLS/SSL
                # TYPE(1), VERSION(2), LENGTH(2)
                header = self.TCP.receive_buffer(5)
                while header:
                    if header and len(header) == 5:
                        rec = Record(TLS.get_version_from_bytes(
                            header[1:3]), struct.unpack('!B', header[0:1])[0])
                        rec.length = struct.unpack('!H', header[3:5])[0]
                        if 0 < rec.length:
                            response.append(self.get_response_record(rec))
                    next_header = self.TCP.receive_buffer(5)
                    if next_header:
                        header = next_header
                        del next_header
                    else:
                        break
            elif TLS.is_ssl2(record_instance.version):
                header = self.TCP.receive_buffer(3)  # LENGTH(2), TYPE(1)
                if header and len(header) == 3:
                    rec = Record(record_instance.version, struct.unpack(
                        '!B', header[2:3])[0])  # Version is assumed
                    rec.length = TLS.get_ssl2_record_len(
                        struct.unpack('!H', header[0:2])[0] - 3)
                    if 0 < rec.length:
                        response.append(self.get_response_record(rec))
        except socket.error as e:
            if e.errno == errno.ECONNRESET:  # 54; Microsoft sometimes just resets the connection
                msg = "Connection reset"  # Usually means: not supported or not an acceptable offer
                pass
            elif e.errno == errno.ECONNREFUSED:  # 61
                msg = "Connection refused"
            else:
                raise e
        return response

    def get_response_record(self, record):
        response = record
        buffer = self.TCP.receive_buffer(record.length)
        if buffer:
            record.body = buffer
            if TLS.is_ssl3_tls(record.version):
                if record.content_type == TLS.ContentType.handshake and \
                        record.body[0] == TLS.HandshakeType.server_hello:
                    response = ServerHello(record.version, record.body)
               # elif record.content_type == TLS.ContentType.alert:
                #    warn("Received an alert!")
                # else:
                #    warn("Unhandled response for TLS request record")
            elif TLS.is_ssl2(record.version):
                if record.content_type == TLS.HandshakeTypeSsl2.server_hello:  # server hello
                    # For SSL2 version is part of the 'body'
                    version = TLS.get_version_from_bytes(response.body[2:4])
                    response = ServerHello(version, record.body)
                    response.length = record.length
               # else:
                #    warn("Unhandled response for SSL2 request record")
        else:
            warn("No body received")
        return response


class Enumerator(object):

    def __init__(self, target: Target):
        self.target = target
        self.verbose = False
        self.clear_text_layer = None

    def set_clear_text_layer(self, string):
        self.clear_text_layer = string

    def get_version_support(self, version_list):
        supported = []
        for v in version_list:
            try:
                with TCP(self.target.host, self.target.port).connect() as tcp:
                    # Pass a socket object (connection) to start a TLS instance
                    tls = TLS(tcp)
                    if TLS.is_ssl3_tls(TLS.versions[v]):
                        client_hello = self.get_ecc_extended_client_hello(
                            TLS.versions[v], TLS.ciphers_tls)
                        client_hello.set_compression(
                            bytearray(b'\x01\x00'))  # DEFLATE, null
                        response = tls.send_record(client_hello)
                    elif TLS.is_ssl2(TLS.versions[v]):
                        response = tls.send_record(ClientHello(
                            TLS.versions[v], TLS.ciphers_ssl2))
                    if len(response) > 0:
                        s_hello = None  # Bug-fix: the ServerHello is not always the first Record received
                        for record in response:
                            if isinstance(record, ServerHello):
                                s_hello = record
                                break
                        if s_hello:
                            if s_hello.handshake_protocol == TLS.versions[v]:
                                supported.append(v)
                                #info("  [+]: {0}".format(v))
                                # if s_hello.compression_method is not None:
                                #    info("      Compression: {0}".format(s_hello.compression_method.name))
                                #result[v] = (s_hello.compression_method.name)
            except AttributeError:
                break
            except:
                raise
        #print (result)
        return supported

    def get_cipher_support(self, version):
        supported = []
        retries = 0
        if TLS.is_ssl3_tls(TLS.versions[version]):
            cipher_list = TLS.get_cipher_list(TLS.Protocols.TLS)
        elif TLS.is_ssl2(TLS.versions[version]):
            cipher_list = TLS.get_cipher_list(TLS.Protocols.SSL2)
        server_hello_cipher = True
        while server_hello_cipher:
            for c in cipher_list:
                try:
                    with TCP(self.target.host, self.target.port).connect() as tcp:
                        tls = TLS(tcp)
                        if TLS.is_ssl3_tls(TLS.versions[version]):
                            response = tls.send_record(self.get_ecc_extended_client_hello(
                                TLS.versions[version], cipher_list))
                            if len(response) > 0:
                                s_hello = None
                                for record in response:
                                    if isinstance(record, ServerHello):
                                        s_hello = record
                                        break
                                if s_hello:
                                    hello_cipher = s_hello.response_cipher
                                    if hello_cipher and hello_cipher in supported:
                                        server_hello_cipher = False
                                        break
                                    elif hello_cipher:
                                        supported.append(hello_cipher)
                                        # info("  [+] {0} ({1} bits)".format(hello_cipher.name,
                                        #                                                hello_cipher.bits))
                                        cipher_list.remove(hello_cipher.bytes)
                                        retries = 0
                                else:  # No hello received, could be an alert
                                    server_hello_cipher = False
                                    break
                            else:  # Bug-fix
                                if retries < 3:
                                    retries += 1
                                else:
                                    server_hello_cipher = False
                                    break
                        elif TLS.is_ssl2(TLS.versions[version]):
                            response = tls.send_record(ClientHello(
                                TLS.versions[version], cipher_list))
                            if len(response) > 0:
                                if isinstance(response[0], ServerHello):
                                    # ssl2 returns all ciphers at once
                                    supported = response[0].ssl2_response_ciphers
                                    if self.verbose:
                                        [info("  [+] {0}".format(s[1]))
                                         for s in supported]
                                server_hello_cipher = False
                                break
                            else:
                                server_hello_cipher = False
                                break
                except AttributeError:
                    break
                except:
                    raise
        return supported

    def get_ecc_extended_client_hello(self, version, cipher_list):
        client_hello = ClientHello(version, cipher_list)
        # Extensions required for ECC cipher detection
        client_hello.add_extension(EllipticCurves(TLS.NamedCurve))
        client_hello.add_extension(ECPointFormats(TLS.ECPointFormat))
        client_hello.add_extension(
            SignatureAlgorithms(Enumerator.get_hash_sig_list()))
        client_hello.add_extension(ServerName(self.target.host))
        client_hello.add_extension(HeartBeat(True))
        return client_hello

    @staticmethod
    def get_hash_sig_list():
        h_s_list = []
        for h in TLS.HashAlgorithm:
            for s in TLS.SignatureAlgorithm:
                h_s_list.append((h, s))
        return h_s_list


def processTarget(host, port=443):
    t = TargetParser(host + ":" + str(port)).get_target()
    versions = [  # High to low
        'TLSv1_2',
        'TLSv1_1',
        'TLSv1_0',
        'SSLv3',
        'SSLv2'
    ]
    enum = Enumerator(t)
    enum.verbose = True  # Enumerator will print in verbose mode

    supported_protocols = enum.get_version_support(versions)
    # print(supported_protocols)
    for p in supported_protocols:
        cipher_list = []
        ciphers = enum.get_cipher_support(p)
        for cipher in ciphers:
            cipher_list.append(cipher.name)
        result[p] = cipher_list
    return result
