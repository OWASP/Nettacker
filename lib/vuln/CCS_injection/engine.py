#!/usr/bin/env python
# -*- coding: utf-8 -*-
# Author: Pradeep Jairamani , github.com/pradeepjairamani

import socket
import socks
import time
import json
import threading
import string
import random
import sys
import struct
import re
import os
from OpenSSL import crypto
import ssl
from core.alert import *
from core.targets import target_type
from core.targets import target_to_host
from core.load_modules import load_file_path
from lib.socks_resolver.engine import getaddrinfo
from core._time import now
from core.log import __log_into_file


def extra_requirements_dict():
    return {
        "CCS_injection_vuln_ports": [21, 25, 110, 143, 443, 587, 990, 1080, 8080]
    }

dSSL = {
    "SSLv3": "\x03\x00",
    "TLSv1": "\x03\x01",
    "TLSv1.1": "\x03\x02",
    "TLSv1.2": "\x03\x03",
}

ssl3_cipher = dict()
ssl3_cipher['\x00\x00'] = "TLS_NULL_WITH_NULL_NULL"
ssl3_cipher['\x00\x01'] = "TLS_RSA_WITH_NULL_MD5"
ssl3_cipher['\x00\x02'] = "TLS_RSA_WITH_NULL_SHA"
ssl3_cipher['\x00\x03'] = "TLS_RSA_EXPORT_WITH_RC4_40_MD5"
ssl3_cipher['\x00\x04'] = "TLS_RSA_WITH_RC4_128_MD5"
ssl3_cipher['\x00\x05'] = "TLS_RSA_WITH_RC4_128_SHA"
ssl3_cipher['\x00\x06'] = "TLS_RSA_EXPORT_WITH_RC2_CBC_40_MD5"
ssl3_cipher['\x00\x07'] = "TLS_RSA_WITH_IDEA_CBC_SHA"
ssl3_cipher['\x00\x08'] = "TLS_RSA_EXPORT_WITH_DES40_CBC_SHA"
ssl3_cipher['\x00\x09'] = "TLS_RSA_WITH_DES_CBC_SHA"
ssl3_cipher['\x00\x0a'] = "TLS_RSA_WITH_3DES_EDE_CBC_SHA"
ssl3_cipher['\x00\x0b'] = "TLS_DH_DSS_EXPORT_WITH_DES40_CBC_SHA"
ssl3_cipher['\x00\x0c'] = "TLS_DH_DSS_WITH_DES_CBC_SHA"
ssl3_cipher['\x00\x0d'] = "TLS_DH_DSS_WITH_3DES_EDE_CBC_SHA"
ssl3_cipher['\x00\x0e'] = "TLS_DH_RSA_EXPORT_WITH_DES40_CBC_SHA"
ssl3_cipher['\x00\x0f'] = "TLS_DH_RSA_WITH_DES_CBC_SHA"
ssl3_cipher['\x00\x10'] = "TLS_DH_RSA_WITH_3DES_EDE_CBC_SHA"
ssl3_cipher['\x00\x11'] = "TLS_DHE_DSS_EXPORT_WITH_DES40_CBC_SHA"
ssl3_cipher['\x00\x12'] = "TLS_DHE_DSS_WITH_DES_CBC_SHA"
ssl3_cipher['\x00\x13'] = "TLS_DHE_DSS_WITH_3DES_EDE_CBC_SHA"
ssl3_cipher['\x00\x14'] = "TLS_DHE_RSA_EXPORT_WITH_DES40_CBC_SHA"
ssl3_cipher['\x00\x15'] = "TLS_DHE_RSA_WITH_DES_CBC_SHA"
ssl3_cipher['\x00\x16'] = "TLS_DHE_RSA_WITH_3DES_EDE_CBC_SHA"
ssl3_cipher['\x00\x17'] = "TLS_DH_anon_EXPORT_WITH_RC4_40_MD5"
ssl3_cipher['\x00\x18'] = "TLS_DH_anon_WITH_RC4_128_MD5"
ssl3_cipher['\x00\x19'] = "TLS_DH_anon_EXPORT_WITH_DES40_CBC_SHA"
ssl3_cipher['\x00\x1a'] = "TLS_DH_anon_WITH_DES_CBC_SHA"
ssl3_cipher['\x00\x1b'] = "TLS_DH_anon_WITH_3DES_EDE_CBC_SHA"
ssl3_cipher['\x00\x1c'] = "SSL_FORTEZZA_KEA_WITH_NULL_SHA"
ssl3_cipher['\x00\x1d'] = "SSL_FORTEZZA_KEA_WITH_FORTEZZA_CBC_SHA"
ssl3_cipher['\x00\x1e'] = "SSL_FORTEZZA_KEA_WITH_RC4_128_SHA"
ssl3_cipher['\x00\x1E'] = "TLS_KRB5_WITH_DES_CBC_SHA"
ssl3_cipher['\x00\x1F'] = "TLS_KRB5_WITH_3DES_EDE_CBC_SHA"
ssl3_cipher['\x00\x20'] = "TLS_KRB5_WITH_RC4_128_SHA"
ssl3_cipher['\x00\x21'] = "TLS_KRB5_WITH_IDEA_CBC_SHA"
ssl3_cipher['\x00\x22'] = "TLS_KRB5_WITH_DES_CBC_MD5"
ssl3_cipher['\x00\x23'] = "TLS_KRB5_WITH_3DES_EDE_CBC_MD5"
ssl3_cipher['\x00\x24'] = "TLS_KRB5_WITH_RC4_128_MD5"
ssl3_cipher['\x00\x25'] = "TLS_KRB5_WITH_IDEA_CBC_MD5"
ssl3_cipher['\x00\x26'] = "TLS_KRB5_EXPORT_WITH_DES_CBC_40_SHA"
ssl3_cipher['\x00\x27'] = "TLS_KRB5_EXPORT_WITH_RC2_CBC_40_SHA"
ssl3_cipher['\x00\x28'] = "TLS_KRB5_EXPORT_WITH_RC4_40_SHA"
ssl3_cipher['\x00\x29'] = "TLS_KRB5_EXPORT_WITH_DES_CBC_40_MD5"
ssl3_cipher['\x00\x2A'] = "TLS_KRB5_EXPORT_WITH_RC2_CBC_40_MD5"
ssl3_cipher['\x00\x2B'] = "TLS_KRB5_EXPORT_WITH_RC4_40_MD5"
ssl3_cipher['\x00\x2C'] = "TLS_PSK_WITH_NULL_SHA"
ssl3_cipher['\x00\x2D'] = "TLS_DHE_PSK_WITH_NULL_SHA"
ssl3_cipher['\x00\x2E'] = "TLS_RSA_PSK_WITH_NULL_SHA"
ssl3_cipher['\x00\x2F'] = "TLS_RSA_WITH_AES_128_CBC_SHA"
ssl3_cipher['\x00\x30'] = "TLS_DH_DSS_WITH_AES_128_CBC_SHA"
ssl3_cipher['\x00\x31'] = "TLS_DH_RSA_WITH_AES_128_CBC_SHA"
ssl3_cipher['\x00\x32'] = "TLS_DHE_DSS_WITH_AES_128_CBC_SHA"
ssl3_cipher['\x00\x33'] = "TLS_DHE_RSA_WITH_AES_128_CBC_SHA"
ssl3_cipher['\x00\x34'] = "TLS_DH_anon_WITH_AES_128_CBC_SHA"
ssl3_cipher['\x00\x35'] = "TLS_RSA_WITH_AES_256_CBC_SHA"
ssl3_cipher['\x00\x36'] = "TLS_DH_DSS_WITH_AES_256_CBC_SHA"
ssl3_cipher['\x00\x37'] = "TLS_DH_RSA_WITH_AES_256_CBC_SHA"
ssl3_cipher['\x00\x38'] = "TLS_DHE_DSS_WITH_AES_256_CBC_SHA"
ssl3_cipher['\x00\x39'] = "TLS_DHE_RSA_WITH_AES_256_CBC_SHA"
ssl3_cipher['\x00\x3A'] = "TLS_DH_anon_WITH_AES_256_CBC_SHA"
ssl3_cipher['\x00\x3B'] = "TLS_RSA_WITH_NULL_SHA256"
ssl3_cipher['\x00\x3C'] = "TLS_RSA_WITH_AES_128_CBC_SHA256"
ssl3_cipher['\x00\x3D'] = "TLS_RSA_WITH_AES_256_CBC_SHA256"
ssl3_cipher['\x00\x3E'] = "TLS_DH_DSS_WITH_AES_128_CBC_SHA256"
ssl3_cipher['\x00\x3F'] = "TLS_DH_RSA_WITH_AES_128_CBC_SHA256"
ssl3_cipher['\x00\x40'] = "TLS_DHE_DSS_WITH_AES_128_CBC_SHA256"
ssl3_cipher['\x00\x41'] = "TLS_RSA_WITH_CAMELLIA_128_CBC_SHA"
ssl3_cipher['\x00\x42'] = "TLS_DH_DSS_WITH_CAMELLIA_128_CBC_SHA"
ssl3_cipher['\x00\x43'] = "TLS_DH_RSA_WITH_CAMELLIA_128_CBC_SHA"
ssl3_cipher['\x00\x44'] = "TLS_DHE_DSS_WITH_CAMELLIA_128_CBC_SHA"
ssl3_cipher['\x00\x45'] = "TLS_DHE_RSA_WITH_CAMELLIA_128_CBC_SHA"
ssl3_cipher['\x00\x46'] = "TLS_DH_anon_WITH_CAMELLIA_128_CBC_SHA"
ssl3_cipher['\x00\x60'] = "TLS_RSA_EXPORT1024_WITH_RC4_56_MD5"
ssl3_cipher['\x00\x61'] = "TLS_RSA_EXPORT1024_WITH_RC2_CBC_56_MD5"
ssl3_cipher['\x00\x62'] = "TLS_RSA_EXPORT1024_WITH_DES_CBC_SHA"
ssl3_cipher['\x00\x63'] = "TLS_DHE_DSS_EXPORT1024_WITH_DES_CBC_SHA"
ssl3_cipher['\x00\x64'] = "TLS_RSA_EXPORT1024_WITH_RC4_56_SHA"
ssl3_cipher['\x00\x65'] = "TLS_DHE_DSS_EXPORT1024_WITH_RC4_56_SHA"
ssl3_cipher['\x00\x66'] = "TLS_DHE_DSS_WITH_RC4_128_SHA"
ssl3_cipher['\x00\x67'] = "TLS_DHE_RSA_WITH_AES_128_CBC_SHA256"
ssl3_cipher['\x00\x68'] = "TLS_DH_DSS_WITH_AES_256_CBC_SHA256"
ssl3_cipher['\x00\x69'] = "TLS_DH_RSA_WITH_AES_256_CBC_SHA256"
ssl3_cipher['\x00\x6A'] = "TLS_DHE_DSS_WITH_AES_256_CBC_SHA256"
ssl3_cipher['\x00\x6B'] = "TLS_DHE_RSA_WITH_AES_256_CBC_SHA256"
ssl3_cipher['\x00\x6C'] = "TLS_DH_anon_WITH_AES_128_CBC_SHA256"
ssl3_cipher['\x00\x6D'] = "TLS_DH_anon_WITH_AES_256_CBC_SHA256"
ssl3_cipher['\x00\x80'] = "TLS_GOSTR341094_WITH_28147_CNT_IMIT"
ssl3_cipher['\x00\x81'] = "TLS_GOSTR341001_WITH_28147_CNT_IMIT"
ssl3_cipher['\x00\x82'] = "TLS_GOSTR341094_WITH_NULL_GOSTR3411"
ssl3_cipher['\x00\x83'] = "TLS_GOSTR341001_WITH_NULL_GOSTR3411"
ssl3_cipher['\x00\x84'] = "TLS_RSA_WITH_CAMELLIA_256_CBC_SHA"
ssl3_cipher['\x00\x85'] = "TLS_DH_DSS_WITH_CAMELLIA_256_CBC_SHA"
ssl3_cipher['\x00\x86'] = "TLS_DH_RSA_WITH_CAMELLIA_256_CBC_SHA"
ssl3_cipher['\x00\x87'] = "TLS_DHE_DSS_WITH_CAMELLIA_256_CBC_SHA"
ssl3_cipher['\x00\x88'] = "TLS_DHE_RSA_WITH_CAMELLIA_256_CBC_SHA"
ssl3_cipher['\x00\x89'] = "TLS_DH_anon_WITH_CAMELLIA_256_CBC_SHA"
ssl3_cipher['\x00\x8A'] = "TLS_PSK_WITH_RC4_128_SHA"
ssl3_cipher['\x00\x8B'] = "TLS_PSK_WITH_3DES_EDE_CBC_SHA"
ssl3_cipher['\x00\x8C'] = "TLS_PSK_WITH_AES_128_CBC_SHA"
ssl3_cipher['\x00\x8D'] = "TLS_PSK_WITH_AES_256_CBC_SHA"
ssl3_cipher['\x00\x8E'] = "TLS_DHE_PSK_WITH_RC4_128_SHA"
ssl3_cipher['\x00\x8F'] = "TLS_DHE_PSK_WITH_3DES_EDE_CBC_SHA"
ssl3_cipher['\x00\x90'] = "TLS_DHE_PSK_WITH_AES_128_CBC_SHA"
ssl3_cipher['\x00\x91'] = "TLS_DHE_PSK_WITH_AES_256_CBC_SHA"
ssl3_cipher['\x00\x92'] = "TLS_RSA_PSK_WITH_RC4_128_SHA"
ssl3_cipher['\x00\x93'] = "TLS_RSA_PSK_WITH_3DES_EDE_CBC_SHA"
ssl3_cipher['\x00\x94'] = "TLS_RSA_PSK_WITH_AES_128_CBC_SHA"
ssl3_cipher['\x00\x95'] = "TLS_RSA_PSK_WITH_AES_256_CBC_SHA"
ssl3_cipher['\x00\x96'] = "TLS_RSA_WITH_SEED_CBC_SHA"
ssl3_cipher['\x00\x97'] = "TLS_DH_DSS_WITH_SEED_CBC_SHA"
ssl3_cipher['\x00\x98'] = "TLS_DH_RSA_WITH_SEED_CBC_SHA"
ssl3_cipher['\x00\x99'] = "TLS_DHE_DSS_WITH_SEED_CBC_SHA"
ssl3_cipher['\x00\x9A'] = "TLS_DHE_RSA_WITH_SEED_CBC_SHA"
ssl3_cipher['\x00\x9B'] = "TLS_DH_anon_WITH_SEED_CBC_SHA"
ssl3_cipher['\x00\x9C'] = "TLS_RSA_WITH_AES_128_GCM_SHA256"
ssl3_cipher['\x00\x9D'] = "TLS_RSA_WITH_AES_256_GCM_SHA384"
ssl3_cipher['\x00\x9E'] = "TLS_DHE_RSA_WITH_AES_128_GCM_SHA256"
ssl3_cipher['\x00\x9F'] = "TLS_DHE_RSA_WITH_AES_256_GCM_SHA384"
ssl3_cipher['\x00\xA0'] = "TLS_DH_RSA_WITH_AES_128_GCM_SHA256"
ssl3_cipher['\x00\xA1'] = "TLS_DH_RSA_WITH_AES_256_GCM_SHA384"
ssl3_cipher['\x00\xA2'] = "TLS_DHE_DSS_WITH_AES_128_GCM_SHA256"
ssl3_cipher['\x00\xA3'] = "TLS_DHE_DSS_WITH_AES_256_GCM_SHA384"
ssl3_cipher['\x00\xA4'] = "TLS_DH_DSS_WITH_AES_128_GCM_SHA256"
ssl3_cipher['\x00\xA5'] = "TLS_DH_DSS_WITH_AES_256_GCM_SHA384"
ssl3_cipher['\x00\xA6'] = "TLS_DH_anon_WITH_AES_128_GCM_SHA256"
ssl3_cipher['\x00\xA7'] = "TLS_DH_anon_WITH_AES_256_GCM_SHA384"
ssl3_cipher['\x00\xA8'] = "TLS_PSK_WITH_AES_128_GCM_SHA256"
ssl3_cipher['\x00\xA9'] = "TLS_PSK_WITH_AES_256_GCM_SHA384"
ssl3_cipher['\x00\xAA'] = "TLS_DHE_PSK_WITH_AES_128_GCM_SHA256"
ssl3_cipher['\x00\xAB'] = "TLS_DHE_PSK_WITH_AES_256_GCM_SHA384"
ssl3_cipher['\x00\xAC'] = "TLS_RSA_PSK_WITH_AES_128_GCM_SHA256"
ssl3_cipher['\x00\xAD'] = "TLS_RSA_PSK_WITH_AES_256_GCM_SHA384"
ssl3_cipher['\x00\xAE'] = "TLS_PSK_WITH_AES_128_CBC_SHA256"
ssl3_cipher['\x00\xAF'] = "TLS_PSK_WITH_AES_256_CBC_SHA384"
ssl3_cipher['\x00\xB0'] = "TLS_PSK_WITH_NULL_SHA256"
ssl3_cipher['\x00\xB1'] = "TLS_PSK_WITH_NULL_SHA384"
ssl3_cipher['\x00\xB2'] = "TLS_DHE_PSK_WITH_AES_128_CBC_SHA256"
ssl3_cipher['\x00\xB3'] = "TLS_DHE_PSK_WITH_AES_256_CBC_SHA384"
ssl3_cipher['\x00\xB4'] = "TLS_DHE_PSK_WITH_NULL_SHA256"
ssl3_cipher['\x00\xB5'] = "TLS_DHE_PSK_WITH_NULL_SHA384"
ssl3_cipher['\x00\xB6'] = "TLS_RSA_PSK_WITH_AES_128_CBC_SHA256"
ssl3_cipher['\x00\xB7'] = "TLS_RSA_PSK_WITH_AES_256_CBC_SHA384"
ssl3_cipher['\x00\xB8'] = "TLS_RSA_PSK_WITH_NULL_SHA256"
ssl3_cipher['\x00\xB9'] = "TLS_RSA_PSK_WITH_NULL_SHA384"
ssl3_cipher['\x00\xBA'] = "TLS_RSA_WITH_CAMELLIA_128_CBC_SHA256"
ssl3_cipher['\x00\xBB'] = "TLS_DH_DSS_WITH_CAMELLIA_128_CBC_SHA256"
ssl3_cipher['\x00\xBC'] = "TLS_DH_RSA_WITH_CAMELLIA_128_CBC_SHA256"
ssl3_cipher['\x00\xBD'] = "TLS_DHE_DSS_WITH_CAMELLIA_128_CBC_SHA256"
ssl3_cipher['\x00\xBE'] = "TLS_DHE_RSA_WITH_CAMELLIA_128_CBC_SHA256"
ssl3_cipher['\x00\xBF'] = "TLS_DH_anon_WITH_CAMELLIA_128_CBC_SHA256"
ssl3_cipher['\x00\xC0'] = "TLS_RSA_WITH_CAMELLIA_256_CBC_SHA256"
ssl3_cipher['\x00\xC1'] = "TLS_DH_DSS_WITH_CAMELLIA_256_CBC_SHA256"
ssl3_cipher['\x00\xC2'] = "TLS_DH_RSA_WITH_CAMELLIA_256_CBC_SHA256"
ssl3_cipher['\x00\xC3'] = "TLS_DHE_DSS_WITH_CAMELLIA_256_CBC_SHA256"
ssl3_cipher['\x00\xC4'] = "TLS_DHE_RSA_WITH_CAMELLIA_256_CBC_SHA256"
ssl3_cipher['\x00\xC5'] = "TLS_DH_anon_WITH_CAMELLIA_256_CBC_SHA256"
ssl3_cipher['\x00\x00'] = "TLS_EMPTY_RENEGOTIATION_INFO_SCSV"
ssl3_cipher['\xc0\x01'] = "TLS_ECDH_ECDSA_WITH_NULL_SHA"
ssl3_cipher['\xc0\x02'] = "TLS_ECDH_ECDSA_WITH_RC4_128_SHA"
ssl3_cipher['\xc0\x03'] = "TLS_ECDH_ECDSA_WITH_3DES_EDE_CBC_SHA"
ssl3_cipher['\xc0\x04'] = "TLS_ECDH_ECDSA_WITH_AES_128_CBC_SHA"
ssl3_cipher['\xc0\x05'] = "TLS_ECDH_ECDSA_WITH_AES_256_CBC_SHA"
ssl3_cipher['\xc0\x06'] = "TLS_ECDHE_ECDSA_WITH_NULL_SHA"
ssl3_cipher['\xc0\x07'] = "TLS_ECDHE_ECDSA_WITH_RC4_128_SHA"
ssl3_cipher['\xc0\x08'] = "TLS_ECDHE_ECDSA_WITH_3DES_EDE_CBC_SHA"
ssl3_cipher['\xc0\x09'] = "TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA"
ssl3_cipher['\xc0\x0a'] = "TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA"
ssl3_cipher['\xc0\x0b'] = "TLS_ECDH_RSA_WITH_NULL_SHA"
ssl3_cipher['\xc0\x0c'] = "TLS_ECDH_RSA_WITH_RC4_128_SHA"
ssl3_cipher['\xc0\x0d'] = "TLS_ECDH_RSA_WITH_3DES_EDE_CBC_SHA"
ssl3_cipher['\xc0\x0e'] = "TLS_ECDH_RSA_WITH_AES_128_CBC_SHA"
ssl3_cipher['\xc0\x0f'] = "TLS_ECDH_RSA_WITH_AES_256_CBC_SHA"
ssl3_cipher['\xc0\x10'] = "TLS_ECDHE_RSA_WITH_NULL_SHA"
ssl3_cipher['\xc0\x11'] = "TLS_ECDHE_RSA_WITH_RC4_128_SHA"
ssl3_cipher['\xc0\x12'] = "TLS_ECDHE_RSA_WITH_3DES_EDE_CBC_SHA"
ssl3_cipher['\xc0\x13'] = "TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA"
ssl3_cipher['\xc0\x14'] = "TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA"
ssl3_cipher['\xc0\x15'] = "TLS_ECDH_anon_WITH_NULL_SHA"
ssl3_cipher['\xc0\x16'] = "TLS_ECDH_anon_WITH_RC4_128_SHA"
ssl3_cipher['\xc0\x17'] = "TLS_ECDH_anon_WITH_3DES_EDE_CBC_SHA"
ssl3_cipher['\xc0\x18'] = "TLS_ECDH_anon_WITH_AES_128_CBC_SHA"
ssl3_cipher['\xc0\x19'] = "TLS_ECDH_anon_WITH_AES_256_CBC_SHA"
ssl3_cipher['\xC0\x1A'] = "TLS_SRP_SHA_WITH_3DES_EDE_CBC_SHA"
ssl3_cipher['\xC0\x1B'] = "TLS_SRP_SHA_RSA_WITH_3DES_EDE_CBC_SHA"
ssl3_cipher['\xC0\x1C'] = "TLS_SRP_SHA_DSS_WITH_3DES_EDE_CBC_SHA"
ssl3_cipher['\xC0\x1D'] = "TLS_SRP_SHA_WITH_AES_128_CBC_SHA"
ssl3_cipher['\xC0\x1E'] = "TLS_SRP_SHA_RSA_WITH_AES_128_CBC_SHA"
ssl3_cipher['\xC0\x1F'] = "TLS_SRP_SHA_DSS_WITH_AES_128_CBC_SHA"
ssl3_cipher['\xC0\x20'] = "TLS_SRP_SHA_WITH_AES_256_CBC_SHA"
ssl3_cipher['\xC0\x21'] = "TLS_SRP_SHA_RSA_WITH_AES_256_CBC_SHA"
ssl3_cipher['\xC0\x22'] = "TLS_SRP_SHA_DSS_WITH_AES_256_CBC_SHA"
ssl3_cipher['\xC0\x23'] = "TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA256"
ssl3_cipher['\xC0\x24'] = "TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA384"
ssl3_cipher['\xC0\x25'] = "TLS_ECDH_ECDSA_WITH_AES_128_CBC_SHA256"
ssl3_cipher['\xC0\x26'] = "TLS_ECDH_ECDSA_WITH_AES_256_CBC_SHA384"
ssl3_cipher['\xC0\x27'] = "TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA256"
ssl3_cipher['\xC0\x28'] = "TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA384"
ssl3_cipher['\xC0\x29'] = "TLS_ECDH_RSA_WITH_AES_128_CBC_SHA256"
ssl3_cipher['\xC0\x2A'] = "TLS_ECDH_RSA_WITH_AES_256_CBC_SHA384"
ssl3_cipher['\xC0\x2B'] = "TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256"
ssl3_cipher['\xC0\x2C'] = "TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384"
ssl3_cipher['\xC0\x2D'] = "TLS_ECDH_ECDSA_WITH_AES_128_GCM_SHA256"
ssl3_cipher['\xC0\x2E'] = "TLS_ECDH_ECDSA_WITH_AES_256_GCM_SHA384"
ssl3_cipher['\xC0\x2F'] = "TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256"
ssl3_cipher['\xC0\x30'] = "TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384"
ssl3_cipher['\xC0\x31'] = "TLS_ECDH_RSA_WITH_AES_128_GCM_SHA256"
ssl3_cipher['\xC0\x32'] = "TLS_ECDH_RSA_WITH_AES_256_GCM_SHA384"
ssl3_cipher['\xC0\x33'] = "TLS_ECDHE_PSK_WITH_RC4_128_SHA"
ssl3_cipher['\xC0\x34'] = "TLS_ECDHE_PSK_WITH_3DES_EDE_CBC_SHA"
ssl3_cipher['\xC0\x35'] = "TLS_ECDHE_PSK_WITH_AES_128_CBC_SHA"
ssl3_cipher['\xC0\x36'] = "TLS_ECDHE_PSK_WITH_AES_256_CBC_SHA"
ssl3_cipher['\xC0\x37'] = "TLS_ECDHE_PSK_WITH_AES_128_CBC_SHA256"
ssl3_cipher['\xC0\x38'] = "TLS_ECDHE_PSK_WITH_AES_256_CBC_SHA384"
ssl3_cipher['\xC0\x39'] = "TLS_ECDHE_PSK_WITH_NULL_SHA"
ssl3_cipher['\xC0\x3A'] = "TLS_ECDHE_PSK_WITH_NULL_SHA256"
ssl3_cipher['\xC0\x3B'] = "TLS_ECDHE_PSK_WITH_NULL_SHA384"
ssl3_cipher['\xfe\xfe'] = "SSL_RSA_FIPS_WITH_DES_CBC_SHA"
ssl3_cipher['\xfe\xff'] = "SSL_RSA_FIPS_WITH_3DES_EDE_CBC_SHA"
ssl3_cipher['\xff\xe0'] = "SSL_RSA_FIPS_WITH_3DES_EDE_CBC_SHA"
ssl3_cipher['\xff\xe1'] = "SSL_RSA_FIPS_WITH_DES_CBC_SHA"


def getSSLRecords(strBuf):
    lstRecords = []
    if len(strBuf) >= 9:
        sslStatus = struct.unpack('>BHHI', strBuf[0:9])
        iType = (sslStatus[3] & (0xFF000000)) >> 24
        iRecordLen = sslStatus[3] & (0x00FFFFFF)
        iShakeProtocol = sslStatus[0]
        iSSLLen = sslStatus[2]
        if (iRecordLen + 5 < iSSLLen):
            lstRecords.append((iShakeProtocol, iType))
            iLoopStopper = 0
            iNextOffset = iRecordLen + 9
            while iNextOffset < len(strBuf):
                iLoopStopper += 1
                iCount = 0
                while ((iNextOffset + 4) > len(strBuf) and iCount < 5):
                    iCount += 1
                    rule.waitForData()
                    if len(rule.buffer) > 0:
                        strBuf += rule.buffer
                if ((iNextOffset + 4) > len(strBuf)):
                    break
                iTypeAndLen = struct.unpack(
                    ">I", strBuf[iNextOffset:iNextOffset + 4])[0]
                iRecordLen = iTypeAndLen & (0x00FFFFFF)
                iType = (iTypeAndLen & (0xFF000000)) >> 24
                lstRecords.append((iShakeProtocol, iType))
                iNextOffset += (iRecordLen + 4)
                if iLoopStopper > 8:
                    break
            return lstRecords
        elif (iRecordLen + 9 < len(strBuf)):
            lstRecords.append((iShakeProtocol, iType))
            iNextOffset = iRecordLen + 9
            iLoopStopper = 0
            while iNextOffset + 6 < len(strBuf):
                iLoopStopper += 1
                iShakeProtocol = struct.unpack(">B", strBuf[iNextOffset])[0]
                iRecordLen = struct.unpack(
                    ">H", strBuf[iNextOffset + 3:iNextOffset + 5])[0]
                iType = struct.unpack(">B", strBuf[iNextOffset + 5])[0]
                lstRecords.append((iShakeProtocol, iType))
                iNextOffset += iRecordLen + 5
                if iLoopStopper > 8:
                    break
            return lstRecords
        elif (iRecordLen + 9 == len(strBuf)):
            sslStatus = checkSSLHeader(strBuf)
            lstRecords.append((sslStatus[0], sslStatus[2]))
            return lstRecords
    return None


def checkSSLHeader(strBuf):
    if len(strBuf) >= 6:
        sslStatus = struct.unpack('>BHHI', strBuf[0:9])
        iType = (sslStatus[3] & (0xFF000000)) >> 24
        iRecordLen = sslStatus[3] & (0x00FFFFFF)
        iShakeProtocol = sslStatus[0]
        iSSLLen = sslStatus[2]
        return (iShakeProtocol, iSSLLen, iType, iRecordLen)
    return None


def makeHello(strSSLVer):
    r = "\x16"  # Message Type 22
    r += dSSL[strSSLVer]
    strCiphers = ""
    for c in list(ssl3_cipher.keys()):
        strCiphers += c
    dLen = 43 + len(strCiphers)
    r += str(struct.pack("!H", dLen))
    h = "\x01"
    strPlen = struct.pack("!L", dLen - 4)
    h += str(strPlen[1:])
    h += dSSL[strSSLVer]
    rand = str(struct.pack("!L", int(time.time())))
    rand += str("\x36\x24\x34\x16\x27\x09\x22\x07\xd7\xbe\xef\x69\xa1\xb2")
    rand += str("\x37\x23\x14\x96\x27\xa9\x12\x04\xe7\xce\xff\xd9\xae\xbb")
    h += rand
    h += "\x00"  # No Session ID
    h += str(struct.pack("!H", len(strCiphers)))
    h += strCiphers
    h += "\x01\x00"
    return r + h


def conn(targ, port, timeout_sec, socks_proxy):
    try:
        if socks_proxy is not None:
            socks_version = socks.SOCKS5 if socks_proxy.startswith(
                'socks5://') else socks.SOCKS4
            socks_proxy = socks_proxy.rsplit('://')[1]
            if '@' in socks_proxy:
                socks_username = socks_proxy.rsplit(':')[0]
                socks_password = socks_proxy.rsplit(':')[1].rsplit('@')[0]
                socks.set_default_proxy(socks_version, str(socks_proxy.rsplit('@')[1].rsplit(':')[0]),
                                        int(socks_proxy.rsplit(':')[-1]), username=socks_username,
                                        password=socks_password)
                socket.socket = socks.socksocket
                socket.getaddrinfo = getaddrinfo
            else:
                socks.set_default_proxy(socks_version, str(socks_proxy.rsplit(':')[0]),
                                        int(socks_proxy.rsplit(':')[1]))
                socket.socket = socks.socksocket
                socket.getaddrinfo = getaddrinfo()
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sys.stdout.flush()
        s.settimeout(timeout_sec)
        s.connect((targ, port))
        return s
    except Exception as e:
        return None


def CCS_injection(target, port, timeout_sec, log_in_file, language, time_sleep,
                  thread_tmp_filename, socks_proxy, scan_id, scan_cmd):
    try:
        s = conn(target, port, timeout_sec, socks_proxy)
        if not s:
            return False
        else:
            iVulnCount = 0
            for strVer in ["TLSv1.2", "TLSv1.1", "TLSv1", "SSLv3"]:
                strHello = makeHello(strVer)
                strLogPre = "[%s] %s:%d" % (strVer, target, port)
                if sys.version[0] == "2":
                    s.send(strHello)
                else:
                    s.send(str.encode(strHello))
                iCount = 0
                fServerHello = False
                fCert = False
                fKex = False
                fHelloDone = False
                while iCount < 5:
                    iCount += 1
                    try:
                        recv = s.recv(2048)
                    except Exception:
                        continue
                    lstRecords = getSSLRecords(recv)
                    if lstRecords != None and len(lstRecords) > 0:
                        for (iShakeProtocol, iType) in lstRecords:
                            if iShakeProtocol == 22:
                                if iType == 2:
                                    fServerHello = True
                                elif iType == 11:
                                    fCert = True
                                elif iType == 12:
                                    fKex = True
                                elif iType == 14:
                                    fHelloDone = True
                        if (fServerHello and fCert):
                            break
                    else:
                        continue
                if not (fServerHello and fCert):
                    pass
                elif len(recv) > 0:
                    if ord(recv[0]) == 22:
                        iCount = 0
                        strChangeCipherSpec = "\x14"
                        strChangeCipherSpec += dSSL[strVer]
                        strChangeCipherSpec += "\x00\x01"  # Len
                        strChangeCipherSpec += "\x01"  # Payload CCS
                        s.send(strChangeCipherSpec)
                        fVuln = True
                        strLastMessage = ""
                        while iCount < 5:
                            iCount += 1
                            s.settimeout(0.5)
                            try:
                                recv = s.recv(2048)
                            except socket.timeout:
                                continue
                            except socket.error:
                                fVuln = False
                                break
                            if (len(recv) > 0):
                                strLastMessage = recv
                                if (ord(recv[0]) == 21):
                                    fVuln = False
                                    break
                        try:
                            # Check if an alert was at the end of the last
                            # message.
                            if ord(strLastMessage[-7]) == 21:
                                fVuln = False
                        except IndexError:
                            pass
                        if fVuln:
                            try:
                                s.send(
                                    '\x15' + dSSL[strVer] + '\x00\x02\x01\x00')
                                f = s.recv(1024)
                                if len(f) == 0:
                                    fVuln = False
                            except socket.error:
                                fVuln = False
                        if fVuln:
                            iVulnCount += 1
                        else:
                            pass
                else:
                    pass
                try:
                    s.close()
                except Exception:
                    pass
            if iVulnCount > 0:
                return True
            else:
                return False
    except Exception as e:
        # some error warning
        return False


def __CCS_injection(target, port, timeout_sec, log_in_file, language, time_sleep,
                    thread_tmp_filename, socks_proxy, scan_id, scan_cmd):
    if CCS_injection(target, port, timeout_sec, log_in_file, language, time_sleep,
                     thread_tmp_filename, socks_proxy, scan_id, scan_cmd):
        info(messages(language, "target_vulnerable").format(
            target, port, 'CCS Injection'))
        __log_into_file(thread_tmp_filename, 'w', '0', language)
        data = json.dumps({'HOST': target, 'USERNAME': '', 'PASSWORD': '', 'PORT': port, 'TYPE': 'CCS_injection_vuln',
                           'DESCRIPTION': messages(language, "vulnerable").format('CCS Injection'), 'TIME': now(),
                           'CATEGORY': "vuln",
                           'SCAN_ID': scan_id, 'SCAN_CMD': scan_cmd})
        __log_into_file(log_in_file, 'a', data, language)
        return True
    else:
        return False


def start(target, users, passwds, ports, timeout_sec, thread_number, num, total, log_in_file, time_sleep, language,
          verbose_level, socks_proxy, retries, methods_args, scan_id, scan_cmd):  # Main function
    if target_type(target) != 'SINGLE_IPv4' or target_type(target) != 'DOMAIN' or target_type(target) != 'HTTP':
        # requirements check
        new_extra_requirements = extra_requirements_dict()
        if methods_args is not None:
            for extra_requirement in extra_requirements_dict():
                if extra_requirement in methods_args:
                    new_extra_requirements[
                        extra_requirement] = methods_args[extra_requirement]
        extra_requirements = new_extra_requirements
        if ports is None:
            ports = extra_requirements["CCS_injection_vuln_ports"]
        if target_type(target) == 'HTTP':
            target = target_to_host(target)
        threads = []
        total_req = len(ports)
        thread_tmp_filename = '{}/tmp/thread_tmp_'.format(load_file_path()) + ''.join(
            random.choice(string.ascii_letters + string.digits) for _ in range(20))
        __log_into_file(thread_tmp_filename, 'w', '1', language)
        trying = 0
        keyboard_interrupt_flag = False
        for port in ports:
            port = int(port)
            t = threading.Thread(target=__CCS_injection,
                                 args=(target, int(port), timeout_sec, log_in_file, language, time_sleep,
                                       thread_tmp_filename, socks_proxy, scan_id, scan_cmd))
            threads.append(t)
            t.start()
            trying += 1
            if verbose_level > 3:
                info(
                    messages(language, "trying_message").format(trying, total_req, num, total, target, port, 'CCS_injection_vuln'))
            while 1:
                try:
                    if threading.activeCount() >= thread_number:
                        time.sleep(0.01)
                    else:
                        break
                except KeyboardInterrupt:
                    keyboard_interrupt_flag = True
                    break
            if keyboard_interrupt_flag:
                break
        kill_switch = 0
        kill_time = int(
            timeout_sec / 0.1) if int(timeout_sec / 0.1) is not 0 else 1
        while 1:
            time.sleep(0.1)
            kill_switch += 1
            try:
                if threading.activeCount() is 1 or kill_switch is kill_time:
                    break
            except KeyboardInterrupt:
                break
        thread_write = int(open(thread_tmp_filename).read().rsplit()[0])
        if thread_write is 1 and verbose_level is not 0:
            info(messages(language, "no_vulnerability_found").format('CCS injection'))
            data = json.dumps({'HOST': target, 'USERNAME': '', 'PASSWORD': '', 'PORT': '', 'TYPE': 'CCS_injection_vuln',
                               'DESCRIPTION': messages(language, "no_vulnerability_found").format('CCS injection'), 'TIME': now(),
                               'CATEGORY': "scan", 'SCAN_ID': scan_id, 'SCAN_CMD': scan_cmd})
            __log_into_file(log_in_file, 'a', data, language)
        os.remove(thread_tmp_filename)

    else:
        warn(messages(language, "input_target_error").format(
            'CCS_injection_vuln', target))
