import sys, os, time
import socket
import struct
import re
from sets import Set

class TLS:
    def __init__(self, host = "", port = 0):
        self.host = host
        self.port = port
        self.protocols = {}
        self.protocols['SSLv2'] = "\x00\x02"
        self.protocols['SSLv3'] = "\x03\x00"
        self.protocols['TLSv1.0'] = "\x03\x01"
        self.protocols['TLSv1.1'] = "\x03\x02"
        self.protocols['TLSv1.2'] = "\x03\x03"
        self.protocols['TLSv1.3'] = "\x03\x04" # Assumption
        self.serverHelloDone = "\x0e\x00\x00\x00"
    # Cipher lists retrieved IANA and multiple RFCs
    def ssl2Ciphers(self): 
        cipher = dict()
        cipher['\x01\x00\x80'] = 'SSL2_RC4_128_WITH_MD5'
        cipher['\x02\x00\x80'] = 'SSL2_RC4_128_EXPORT40_WITH_MD5'
        cipher['\x03\x00\x80'] = 'SSL2_RC2_CBC_128_CBC_WITH_MD5'
        cipher['\x04\x00\x80'] = 'SSL2_RC2_CBC_128_CBC_WITH_MD5'
        cipher['\x05\x00\x80'] = 'SSL2_IDEA_128_CBC_WITH_MD5'
        cipher['\x06\x00\x40'] = 'SSL2_DES_64_CBC_WITH_MD5'
        cipher['\x07\x00\xC0'] = 'SSL2_DES_192_EDE3_CBC_WITH_MD5'
        cipher['\x08\x00\x80'] = 'SSL2_RC4_64_WITH_MD5'
        return cipher

    def tlsCiphers(self):
        cipher = dict()
        cipher['\x00\x00'] = 'TLS_NULL_WITH_NULL_NULL' # Initial handshake state    
        cipher['\x00\x01'] = 'TLS_RSA_WITH_NULL_MD5'
        cipher['\x00\x02'] = 'TLS_RSA_WITH_NULL_SHA'
        cipher['\x00\x03'] = 'TLS_RSA_EXPORT_WITH_RC4_40_MD5'
        cipher['\x00\x04'] = 'TLS_RSA_WITH_RC4_128_MD5'
        cipher['\x00\x05'] = 'TLS_RSA_WITH_RC4_128_SHA'
        cipher['\x00\x06'] = 'TLS_RSA_EXPORT_WITH_RC2_CBC_40_MD5'
        cipher['\x00\x07'] = 'TLS_RSA_WITH_IDEA_CBC_SHA'
        cipher['\x00\x08'] = 'TLS_RSA_EXPORT_WITH_DES40_CBC_SHA'
        cipher['\x00\x09'] = 'TLS_RSA_WITH_DES_CBC_SHA'
        cipher['\x00\x0A'] = 'TLS_RSA_WITH_3DES_EDE_CBC_SHA'
        cipher['\x00\x0B'] = 'TLS_DH_DSS_EXPORT_WITH_DES40_CBC_SHA'
        cipher['\x00\x0C'] = 'TLS_DH_DSS_WITH_DES_CBC_SHA'
        cipher['\x00\x0D'] = 'TLS_DH_DSS_WITH_3DES_EDE_CBC_SHA'
        cipher['\x00\x0E'] = 'TLS_DH_RSA_EXPORT_WITH_DES40_CBC_SHA'
        cipher['\x00\x0F'] = 'TLS_DH_RSA_WITH_DES_CBC_SHA'
        cipher['\x00\x10'] = 'TLS_DH_RSA_WITH_3DES_EDE_CBC_SHA'
        cipher['\x00\x11'] = 'TLS_DHE_DSS_EXPORT_WITH_DES40_CBC_SHA'
        cipher['\x00\x12'] = 'TLS_DHE_DSS_WITH_DES_CBC_SHA'
        cipher['\x00\x13'] = 'TLS_DHE_DSS_WITH_3DES_EDE_CBC_SHA'
        cipher['\x00\x14'] = 'TLS_DHE_RSA_EXPORT_WITH_DES40_CBC_SHA'
        cipher['\x00\x15'] = 'TLS_DHE_RSA_WITH_DES_CBC_SHA'
        cipher['\x00\x16'] = 'TLS_DHE_RSA_WITH_3DES_EDE_CBC_SHA'
        cipher['\x00\x17'] = 'TLS_DH_anon_EXPORT_WITH_RC4_40_MD5'
        cipher['\x00\x18'] = 'TLS_DH_anon_WITH_RC4_128_MD5'
        cipher['\x00\x19'] = 'TLS_DH_anon_EXPORT_WITH_DES40_CBC_SHA'
        cipher['\x00\x1A'] = 'TLS_DH_anon_WITH_DES_CBC_SHA'
        cipher['\x00\x1B'] = 'TLS_DH_anon_WITH_3DES_EDE_CBC_SHA'
        cipher['\x00\x1E'] = 'TLS_KRB5_WITH_DES_CBC_SHA'
        cipher['\x00\x1F'] = 'TLS_KRB5_WITH_3DES_EDE_CBC_SHA'
        cipher['\x00\x20'] = 'TLS_KRB5_WITH_RC4_128_SHA'
        cipher['\x00\x21'] = 'TLS_KRB5_WITH_IDEA_CBC_SHA'
        cipher['\x00\x22'] = 'TLS_KRB5_WITH_DES_CBC_MD5'
        cipher['\x00\x23'] = 'TLS_KRB5_WITH_3DES_EDE_CBC_MD5'
        cipher['\x00\x24'] = 'TLS_KRB5_WITH_RC4_128_MD5'
        cipher['\x00\x25'] = 'TLS_KRB5_WITH_IDEA_CBC_MD5'
        cipher['\x00\x26'] = 'TLS_KRB5_EXPORT_WITH_DES_CBC_40_SHA'
        cipher['\x00\x27'] = 'TLS_KRB5_EXPORT_WITH_RC2_CBC_40_SHA'
        cipher['\x00\x28'] = 'TLS_KRB5_EXPORT_WITH_RC4_40_SHA'
        cipher['\x00\x29'] = 'TLS_KRB5_EXPORT_WITH_DES_CBC_40_MD5'
        cipher['\x00\x2A'] = 'TLS_KRB5_EXPORT_WITH_RC2_CBC_40_MD5'
        cipher['\x00\x2B'] = 'TLS_KRB5_EXPORT_WITH_RC4_40_MD5'
        cipher['\x00\x2C'] = 'TLS_PSK_WITH_NULL_SHA'
        cipher['\x00\x2D'] = 'TLS_DHE_PSK_WITH_NULL_SHA'
        cipher['\x00\x2E'] = 'TLS_RSA_PSK_WITH_NULL_SHA'
        cipher['\x00\x2F'] = 'TLS_RSA_WITH_AES_128_CBC_SHA'
        cipher['\x00\x30'] = 'TLS_DH_DSS_WITH_AES_128_CBC_SHA'
        cipher['\x00\x31'] = 'TLS_DH_RSA_WITH_AES_128_CBC_SHA'
        cipher['\x00\x32'] = 'TLS_DHE_DSS_WITH_AES_128_CBC_SHA'
        cipher['\x00\x33'] = 'TLS_DHE_RSA_WITH_AES_128_CBC_SHA'
        cipher['\x00\x34'] = 'TLS_DH_anon_WITH_AES_128_CBC_SHA'
        cipher['\x00\x35'] = 'TLS_RSA_WITH_AES_256_CBC_SHA'
        cipher['\x00\x36'] = 'TLS_DH_DSS_WITH_AES_256_CBC_SHA'
        cipher['\x00\x37'] = 'TLS_DH_RSA_WITH_AES_256_CBC_SHA'
        cipher['\x00\x38'] = 'TLS_DHE_DSS_WITH_AES_256_CBC_SHA'
        cipher['\x00\x39'] = 'TLS_DHE_RSA_WITH_AES_256_CBC_SHA'
        cipher['\x00\x3A'] = 'TLS_DH_anon_WITH_AES_256_CBC_SHA'
        cipher['\x00\x3B'] = 'TLS_RSA_WITH_NULL_SHA256'
        cipher['\x00\x3C'] = 'TLS_RSA_WITH_AES_128_CBC_SHA256'
        cipher['\x00\x3D'] = 'TLS_RSA_WITH_AES_256_CBC_SHA256'
        cipher['\x00\x3E'] = 'TLS_DH_DSS_WITH_AES_128_CBC_SHA256'
        cipher['\x00\x3F'] = 'TLS_DH_RSA_WITH_AES_128_CBC_SHA256'
        cipher['\x00\x40'] = 'TLS_DHE_DSS_WITH_AES_128_CBC_SHA256'
        cipher['\x00\x41'] = 'TLS_RSA_WITH_CAMELLIA_128_CBC_SHA'
        cipher['\x00\x42'] = 'TLS_DH_DSS_WITH_CAMELLIA_128_CBC_SHA'
        cipher['\x00\x43'] = 'TLS_DH_RSA_WITH_CAMELLIA_128_CBC_SHA'
        cipher['\x00\x44'] = 'TLS_DHE_DSS_WITH_CAMELLIA_128_CBC_SHA'
        cipher['\x00\x45'] = 'TLS_DHE_RSA_WITH_CAMELLIA_128_CBC_SHA'
        cipher['\x00\x46'] = 'TLS_DH_anon_WITH_CAMELLIA_128_CBC_SHA'
        # http://tools.ietf.org/html/draft-ietf-tls-56-bit-ciphersuites-01 (next 5)
        cipher['\x00\x62'] = 'TLS_RSA_EXPORT1024_WITH_DES_CBC_SHA'     
        cipher['\x00\x63'] = 'TLS_DHE_DSS_EXPORT1024_WITH_DES_CBC_SHA'
        cipher['\x00\x64'] = 'TLS_RSA_EXPORT1024_WITH_RC4_56_SHA'
        cipher['\x00\x65'] = 'TLS_DHE_DSS_EXPORT1024_WITH_RC4_56_SHA'
        cipher['\x00\x66'] = 'TLS_DHE_DSS_WITH_RC4_128_SHA'
        cipher['\x00\x67'] = 'TLS_DHE_RSA_WITH_AES_128_CBC_SHA256'
        cipher['\x00\x68'] = 'TLS_DH_DSS_WITH_AES_256_CBC_SHA256'
        cipher['\x00\x69'] = 'TLS_DH_RSA_WITH_AES_256_CBC_SHA256'
        cipher['\x00\x6A'] = 'TLS_DHE_DSS_WITH_AES_256_CBC_SHA256'
        cipher['\x00\x6B'] = 'TLS_DHE_RSA_WITH_AES_256_CBC_SHA256'
        cipher['\x00\x6C'] = 'TLS_DH_anon_WITH_AES_128_CBC_SHA256'
        cipher['\x00\x6D'] = 'TLS_DH_anon_WITH_AES_256_CBC_SHA256'
        # http://tools.ietf.org/html/draft-chudov-cryptopro-cptls-04 (next 4)
        cipher['\x00\x80'] = 'TLS_GOSTR341094_WITH_28147_CNT_IMIT'
        cipher['\x00\x81'] = 'TLS_GOSTR341001_WITH_28147_CNT_IMIT'
        cipher['\x00\x82'] = 'TLS_GOSTR341094_WITH_NULL_GOSTR3411'
        cipher['\x00\x83'] = 'TLS_GOSTR341001_WITH_NULL_GOSTR3411'
        cipher['\x00\x84'] = 'TLS_RSA_WITH_CAMELLIA_256_CBC_SHA'
        cipher['\x00\x85'] = 'TLS_DH_DSS_WITH_CAMELLIA_256_CBC_SHA'
        cipher['\x00\x86'] = 'TLS_DH_RSA_WITH_CAMELLIA_256_CBC_SHA'
        cipher['\x00\x87'] = 'TLS_DHE_DSS_WITH_CAMELLIA_256_CBC_SHA'
        cipher['\x00\x88'] = 'TLS_DHE_RSA_WITH_CAMELLIA_256_CBC_SHA'
        cipher['\x00\x89'] = 'TLS_DH_anon_WITH_CAMELLIA_256_CBC_SHA'
        cipher['\x00\x8A'] = 'TLS_PSK_WITH_RC4_128_SHA'
        cipher['\x00\x8B'] = 'TLS_PSK_WITH_3DES_EDE_CBC_SHA'
        cipher['\x00\x8C'] = 'TLS_PSK_WITH_AES_128_CBC_SHA'
        cipher['\x00\x8D'] = 'TLS_PSK_WITH_AES_256_CBC_SHA'
        cipher['\x00\x8E'] = 'TLS_DHE_PSK_WITH_RC4_128_SHA'
        cipher['\x00\x8F'] = 'TLS_DHE_PSK_WITH_3DES_EDE_CBC_SHA'
        cipher['\x00\x90'] = 'TLS_DHE_PSK_WITH_AES_128_CBC_SHA'
        cipher['\x00\x91'] = 'TLS_DHE_PSK_WITH_AES_256_CBC_SHA'
        cipher['\x00\x92'] = 'TLS_RSA_PSK_WITH_RC4_128_SHA'
        cipher['\x00\x93'] = 'TLS_RSA_PSK_WITH_3DES_EDE_CBC_SHA'
        cipher['\x00\x94'] = 'TLS_RSA_PSK_WITH_AES_128_CBC_SHA'
        cipher['\x00\x95'] = 'TLS_RSA_PSK_WITH_AES_256_CBC_SHA'
        cipher['\x00\x96'] = 'TLS_RSA_WITH_SEED_CBC_SHA'
        cipher['\x00\x97'] = 'TLS_DH_DSS_WITH_SEED_CBC_SHA'
        cipher['\x00\x98'] = 'TLS_DH_RSA_WITH_SEED_CBC_SHA'
        cipher['\x00\x99'] = 'TLS_DHE_DSS_WITH_SEED_CBC_SHA'
        cipher['\x00\x9A'] = 'TLS_DHE_RSA_WITH_SEED_CBC_SHA'
        cipher['\x00\x9B'] = 'TLS_DH_anon_WITH_SEED_CBC_SHA'
        cipher['\x00\x9C'] = 'TLS_RSA_WITH_AES_128_GCM_SHA256'
        cipher['\x00\x9D'] = 'TLS_RSA_WITH_AES_256_GCM_SHA384'
        cipher['\x00\x9E'] = 'TLS_DHE_RSA_WITH_AES_128_GCM_SHA256'
        cipher['\x00\x9F'] = 'TLS_DHE_RSA_WITH_AES_256_GCM_SHA384'
        cipher['\x00\xA0'] = 'TLS_DH_RSA_WITH_AES_128_GCM_SHA256'
        cipher['\x00\xA1'] = 'TLS_DH_RSA_WITH_AES_256_GCM_SHA384'
        cipher['\x00\xA2'] = 'TLS_DHE_DSS_WITH_AES_128_GCM_SHA256'
        cipher['\x00\xA3'] = 'TLS_DHE_DSS_WITH_AES_256_GCM_SHA384'
        cipher['\x00\xA4'] = 'TLS_DH_DSS_WITH_AES_128_GCM_SHA256'
        cipher['\x00\xA5'] = 'TLS_DH_DSS_WITH_AES_256_GCM_SHA384'
        cipher['\x00\xA6'] = 'TLS_DH_anon_WITH_AES_128_GCM_SHA256'
        cipher['\x00\xA7'] = 'TLS_DH_anon_WITH_AES_256_GCM_SHA384'
        cipher['\x00\xA8'] = 'TLS_PSK_WITH_AES_128_GCM_SHA256'
        cipher['\x00\xA9'] = 'TLS_PSK_WITH_AES_256_GCM_SHA384'
        cipher['\x00\xAA'] = 'TLS_DHE_PSK_WITH_AES_128_GCM_SHA256'
        cipher['\x00\xAB'] = 'TLS_DHE_PSK_WITH_AES_256_GCM_SHA384'
        cipher['\x00\xAC'] = 'TLS_RSA_PSK_WITH_AES_128_GCM_SHA256'
        cipher['\x00\xAD'] = 'TLS_RSA_PSK_WITH_AES_256_GCM_SHA384'
        cipher['\x00\xAE'] = 'TLS_PSK_WITH_AES_128_CBC_SHA256'
        cipher['\x00\xAF'] = 'TLS_PSK_WITH_AES_256_CBC_SHA384'
        cipher['\x00\xB0'] = 'TLS_PSK_WITH_NULL_SHA256'
        cipher['\x00\xB1'] = 'TLS_PSK_WITH_NULL_SHA384'
        cipher['\x00\xB2'] = 'TLS_DHE_PSK_WITH_AES_128_CBC_SHA256'
        cipher['\x00\xB3'] = 'TLS_DHE_PSK_WITH_AES_256_CBC_SHA384'
        cipher['\x00\xB4'] = 'TLS_DHE_PSK_WITH_NULL_SHA256'
        cipher['\x00\xB5'] = 'TLS_DHE_PSK_WITH_NULL_SHA384'
        cipher['\x00\xB6'] = 'TLS_RSA_PSK_WITH_AES_128_CBC_SHA256'
        cipher['\x00\xB7'] = 'TLS_RSA_PSK_WITH_AES_256_CBC_SHA384'
        cipher['\x00\xB8'] = 'TLS_RSA_PSK_WITH_NULL_SHA256'
        cipher['\x00\xB9'] = 'TLS_RSA_PSK_WITH_NULL_SHA384'
        cipher['\x00\xBA'] = 'TLS_RSA_WITH_CAMELLIA_128_CBC_SHA256'
        cipher['\x00\xBB'] = 'TLS_DH_DSS_WITH_CAMELLIA_128_CBC_SHA256'
        cipher['\x00\xBC'] = 'TLS_DH_RSA_WITH_CAMELLIA_128_CBC_SHA256'
        cipher['\x00\xBD'] = 'TLS_DHE_DSS_WITH_CAMELLIA_128_CBC_SHA256'
        cipher['\x00\xBE'] = 'TLS_DHE_RSA_WITH_CAMELLIA_128_CBC_SHA256'
        cipher['\x00\xBF'] = 'TLS_DH_anon_WITH_CAMELLIA_128_CBC_SHA256'
        cipher['\x00\xC0'] = 'TLS_RSA_WITH_CAMELLIA_256_CBC_SHA256'
        cipher['\x00\xC1'] = 'TLS_DH_DSS_WITH_CAMELLIA_256_CBC_SHA256'
        cipher['\x00\xC2'] = 'TLS_DH_RSA_WITH_CAMELLIA_256_CBC_SHA256'
        cipher['\x00\xC3'] = 'TLS_DHE_DSS_WITH_CAMELLIA_256_CBC_SHA256'
        cipher['\x00\xC4'] = 'TLS_DHE_RSA_WITH_CAMELLIA_256_CBC_SHA256'
        cipher['\x00\xC5'] = 'TLS_DH_anon_WITH_CAMELLIA_256_CBC_SHA256'
        #cipher['\x00\xFF'] = 'TLS_EMPTY_RENEGOTIATION_INFO_SCSV'
        cipher['\xC0\x01'] = 'TLS_ECDH_ECDSA_WITH_NULL_SHA'
        cipher['\xC0\x02'] = 'TLS_ECDH_ECDSA_WITH_RC4_128_SHA'
        cipher['\xC0\x03'] = 'TLS_ECDH_ECDSA_WITH_3DES_EDE_CBC_SHA'
        cipher['\xC0\x04'] = 'TLS_ECDH_ECDSA_WITH_AES_128_CBC_SHA'
        cipher['\xC0\x05'] = 'TLS_ECDH_ECDSA_WITH_AES_256_CBC_SHA'
        cipher['\xC0\x06'] = 'TLS_ECDHE_ECDSA_WITH_NULL_SHA'
        cipher['\xC0\x07'] = 'TLS_ECDHE_ECDSA_WITH_RC4_128_SHA'
        cipher['\xC0\x08'] = 'TLS_ECDHE_ECDSA_WITH_3DES_EDE_CBC_SHA'
        cipher['\xC0\x09'] = 'TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA'
        cipher['\xC0\x0A'] = 'TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA'
        cipher['\xC0\x0B'] = 'TLS_ECDH_RSA_WITH_NULL_SHA'
        cipher['\xC0\x0C'] = 'TLS_ECDH_RSA_WITH_RC4_128_SHA'
        cipher['\xC0\x0D'] = 'TLS_ECDH_RSA_WITH_3DES_EDE_CBC_SHA'
        cipher['\xC0\x0E'] = 'TLS_ECDH_RSA_WITH_AES_128_CBC_SHA'
        cipher['\xC0\x0F'] = 'TLS_ECDH_RSA_WITH_AES_256_CBC_SHA'
        cipher['\xC0\x10'] = 'TLS_ECDHE_RSA_WITH_NULL_SHA'
        cipher['\xC0\x11'] = 'TLS_ECDHE_RSA_WITH_RC4_128_SHA'
        cipher['\xC0\x12'] = 'TLS_ECDHE_RSA_WITH_3DES_EDE_CBC_SHA'
        cipher['\xC0\x13'] = 'TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA'
        cipher['\xC0\x14'] = 'TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA'
        cipher['\xC0\x15'] = 'TLS_ECDH_anon_WITH_NULL_SHA'
        cipher['\xC0\x16'] = 'TLS_ECDH_anon_WITH_RC4_128_SHA'
        cipher['\xC0\x17'] = 'TLS_ECDH_anon_WITH_3DES_EDE_CBC_SHA'
        cipher['\xC0\x18'] = 'TLS_ECDH_anon_WITH_AES_128_CBC_SHA'
        cipher['\xC0\x19'] = 'TLS_ECDH_anon_WITH_AES_256_CBC_SHA'
        cipher['\xC0\x1A'] = 'TLS_SRP_SHA_WITH_3DES_EDE_CBC_SHA'
        cipher['\xC0\x1B'] = 'TLS_SRP_SHA_RSA_WITH_3DES_EDE_CBC_SHA'
        cipher['\xC0\x1C'] = 'TLS_SRP_SHA_DSS_WITH_3DES_EDE_CBC_SHA'
        cipher['\xC0\x1D'] = 'TLS_SRP_SHA_WITH_AES_128_CBC_SHA'
        cipher['\xC0\x1E'] = 'TLS_SRP_SHA_RSA_WITH_AES_128_CBC_SHA'
        cipher['\xC0\x1F'] = 'TLS_SRP_SHA_DSS_WITH_AES_128_CBC_SHA'
        cipher['\xC0\x20'] = 'TLS_SRP_SHA_WITH_AES_256_CBC_SHA'
        cipher['\xC0\x21'] = 'TLS_SRP_SHA_RSA_WITH_AES_256_CBC_SHA'
        cipher['\xC0\x22'] = 'TLS_SRP_SHA_DSS_WITH_AES_256_CBC_SHA'
        cipher['\xC0\x23'] = 'TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA256'
        cipher['\xC0\x24'] = 'TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA384'
        cipher['\xC0\x25'] = 'TLS_ECDH_ECDSA_WITH_AES_128_CBC_SHA256'
        cipher['\xC0\x26'] = 'TLS_ECDH_ECDSA_WITH_AES_256_CBC_SHA384'
        cipher['\xC0\x27'] = 'TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA256'
        cipher['\xC0\x28'] = 'TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA384'
        cipher['\xC0\x29'] = 'TLS_ECDH_RSA_WITH_AES_128_CBC_SHA256'
        cipher['\xC0\x2A'] = 'TLS_ECDH_RSA_WITH_AES_256_CBC_SHA384'
        cipher['\xC0\x2B'] = 'TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256'
        cipher['\xC0\x2C'] = 'TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384'
        cipher['\xC0\x2D'] = 'TLS_ECDH_ECDSA_WITH_AES_128_GCM_SHA256'
        cipher['\xC0\x2E'] = 'TLS_ECDH_ECDSA_WITH_AES_256_GCM_SHA384'
        cipher['\xC0\x2F'] = 'TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256'
        cipher['\xC0\x30'] = 'TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384'
        cipher['\xC0\x31'] = 'TLS_ECDH_RSA_WITH_AES_128_GCM_SHA256'
        cipher['\xC0\x32'] = 'TLS_ECDH_RSA_WITH_AES_256_GCM_SHA384'
        cipher['\xC0\x33'] = 'TLS_ECDHE_PSK_WITH_RC4_128_SHA'
        cipher['\xC0\x34'] = 'TLS_ECDHE_PSK_WITH_3DES_EDE_CBC_SHA'
        cipher['\xC0\x35'] = 'TLS_ECDHE_PSK_WITH_AES_128_CBC_SHA'
        cipher['\xC0\x36'] = 'TLS_ECDHE_PSK_WITH_AES_256_CBC_SHA'
        cipher['\xC0\x37'] = 'TLS_ECDHE_PSK_WITH_AES_128_CBC_SHA256'
        cipher['\xC0\x38'] = 'TLS_ECDHE_PSK_WITH_AES_256_CBC_SHA384'
        cipher['\xC0\x39'] = 'TLS_ECDHE_PSK_WITH_NULL_SHA'
        cipher['\xC0\x3A'] = 'TLS_ECDHE_PSK_WITH_NULL_SHA256'
        cipher['\xC0\x3B'] = 'TLS_ECDHE_PSK_WITH_NULL_SHA384'
        cipher['\xC0\x3C'] = 'TLS_RSA_WITH_ARIA_128_CBC_SHA256'
        cipher['\xC0\x3D'] = 'TLS_RSA_WITH_ARIA_256_CBC_SHA384'
        cipher['\xC0\x3E'] = 'TLS_DH_DSS_WITH_ARIA_128_CBC_SHA256'
        cipher['\xC0\x3F'] = 'TLS_DH_DSS_WITH_ARIA_256_CBC_SHA384'
        cipher['\xC0\x40'] = 'TLS_DH_RSA_WITH_ARIA_128_CBC_SHA256'
        cipher['\xC0\x41'] = 'TLS_DH_RSA_WITH_ARIA_256_CBC_SHA384'
        cipher['\xC0\x42'] = 'TLS_DHE_DSS_WITH_ARIA_128_CBC_SHA256'
        cipher['\xC0\x43'] = 'TLS_DHE_DSS_WITH_ARIA_256_CBC_SHA384'
        cipher['\xC0\x44'] = 'TLS_DHE_RSA_WITH_ARIA_128_CBC_SHA256'
        cipher['\xC0\x45'] = 'TLS_DHE_RSA_WITH_ARIA_256_CBC_SHA384'
        cipher['\xC0\x46'] = 'TLS_DH_anon_WITH_ARIA_128_CBC_SHA256'
        cipher['\xC0\x47'] = 'TLS_DH_anon_WITH_ARIA_256_CBC_SHA384'
        cipher['\xC0\x48'] = 'TLS_ECDHE_ECDSA_WITH_ARIA_128_CBC_SHA256'
        cipher['\xC0\x49'] = 'TLS_ECDHE_ECDSA_WITH_ARIA_256_CBC_SHA384'
        cipher['\xC0\x4A'] = 'TLS_ECDH_ECDSA_WITH_ARIA_128_CBC_SHA256'
        cipher['\xC0\x4B'] = 'TLS_ECDH_ECDSA_WITH_ARIA_256_CBC_SHA384'
        cipher['\xC0\x4C'] = 'TLS_ECDHE_RSA_WITH_ARIA_128_CBC_SHA256'
        cipher['\xC0\x4D'] = 'TLS_ECDHE_RSA_WITH_ARIA_256_CBC_SHA384'
        cipher['\xC0\x4E'] = 'TLS_ECDH_RSA_WITH_ARIA_128_CBC_SHA256'
        cipher['\xC0\x4F'] = 'TLS_ECDH_RSA_WITH_ARIA_256_CBC_SHA384'
        cipher['\xC0\x50'] = 'TLS_RSA_WITH_ARIA_128_GCM_SHA256'
        cipher['\xC0\x51'] = 'TLS_RSA_WITH_ARIA_256_GCM_SHA384'
        cipher['\xC0\x52'] = 'TLS_DHE_RSA_WITH_ARIA_128_GCM_SHA256'
        cipher['\xC0\x53'] = 'TLS_DHE_RSA_WITH_ARIA_256_GCM_SHA384'
        cipher['\xC0\x54'] = 'TLS_DH_RSA_WITH_ARIA_128_GCM_SHA256'
        cipher['\xC0\x55'] = 'TLS_DH_RSA_WITH_ARIA_256_GCM_SHA384'
        cipher['\xC0\x56'] = 'TLS_DHE_DSS_WITH_ARIA_128_GCM_SHA256'
        cipher['\xC0\x57'] = 'TLS_DHE_DSS_WITH_ARIA_256_GCM_SHA384'
        cipher['\xC0\x58'] = 'TLS_DH_DSS_WITH_ARIA_128_GCM_SHA256'
        cipher['\xC0\x59'] = 'TLS_DH_DSS_WITH_ARIA_256_GCM_SHA384'
        cipher['\xC0\x5A'] = 'TLS_DH_anon_WITH_ARIA_128_GCM_SHA256'
        cipher['\xC0\x5B'] = 'TLS_DH_anon_WITH_ARIA_256_GCM_SHA384'
        cipher['\xC0\x5C'] = 'TLS_ECDHE_ECDSA_WITH_ARIA_128_GCM_SHA256'
        cipher['\xC0\x5D'] = 'TLS_ECDHE_ECDSA_WITH_ARIA_256_GCM_SHA384'
        cipher['\xC0\x5E'] = 'TLS_ECDH_ECDSA_WITH_ARIA_128_GCM_SHA256'
        cipher['\xC0\x5F'] = 'TLS_ECDH_ECDSA_WITH_ARIA_256_GCM_SHA384'
        cipher['\xC0\x60'] = 'TLS_ECDHE_RSA_WITH_ARIA_128_GCM_SHA256'
        cipher['\xC0\x61'] = 'TLS_ECDHE_RSA_WITH_ARIA_256_GCM_SHA384'
        cipher['\xC0\x62'] = 'TLS_ECDH_RSA_WITH_ARIA_128_GCM_SHA256'
        cipher['\xC0\x63'] = 'TLS_ECDH_RSA_WITH_ARIA_256_GCM_SHA384'
        cipher['\xC0\x64'] = 'TLS_PSK_WITH_ARIA_128_CBC_SHA256'
        cipher['\xC0\x65'] = 'TLS_PSK_WITH_ARIA_256_CBC_SHA384'
        cipher['\xC0\x66'] = 'TLS_DHE_PSK_WITH_ARIA_128_CBC_SHA256'
        cipher['\xC0\x67'] = 'TLS_DHE_PSK_WITH_ARIA_256_CBC_SHA384'
        cipher['\xC0\x68'] = 'TLS_RSA_PSK_WITH_ARIA_128_CBC_SHA256'
        cipher['\xC0\x69'] = 'TLS_RSA_PSK_WITH_ARIA_256_CBC_SHA384'
        cipher['\xC0\x6A'] = 'TLS_PSK_WITH_ARIA_128_GCM_SHA256'
        cipher['\xC0\x6B'] = 'TLS_PSK_WITH_ARIA_256_GCM_SHA384'
        cipher['\xC0\x6C'] = 'TLS_DHE_PSK_WITH_ARIA_128_GCM_SHA256'
        cipher['\xC0\x6D'] = 'TLS_DHE_PSK_WITH_ARIA_256_GCM_SHA384'
        cipher['\xC0\x6E'] = 'TLS_RSA_PSK_WITH_ARIA_128_GCM_SHA256'
        cipher['\xC0\x6F'] = 'TLS_RSA_PSK_WITH_ARIA_256_GCM_SHA384'
        cipher['\xC0\x70'] = 'TLS_ECDHE_PSK_WITH_ARIA_128_CBC_SHA256'
        cipher['\xC0\x71'] = 'TLS_ECDHE_PSK_WITH_ARIA_256_CBC_SHA384'
        cipher['\xC0\x72'] = 'TLS_ECDHE_ECDSA_WITH_CAMELLIA_128_CBC_SHA256'
        cipher['\xC0\x73'] = 'TLS_ECDHE_ECDSA_WITH_CAMELLIA_256_CBC_SHA384'
        cipher['\xC0\x74'] = 'TLS_ECDH_ECDSA_WITH_CAMELLIA_128_CBC_SHA256'
        cipher['\xC0\x75'] = 'TLS_ECDH_ECDSA_WITH_CAMELLIA_256_CBC_SHA384'
        cipher['\xC0\x76'] = 'TLS_ECDHE_RSA_WITH_CAMELLIA_128_CBC_SHA256'
        cipher['\xC0\x77'] = 'TLS_ECDHE_RSA_WITH_CAMELLIA_256_CBC_SHA384'
        cipher['\xC0\x78'] = 'TLS_ECDH_RSA_WITH_CAMELLIA_128_CBC_SHA256'
        cipher['\xC0\x79'] = 'TLS_ECDH_RSA_WITH_CAMELLIA_256_CBC_SHA384'
        cipher['\xC0\x7A'] = 'TLS_RSA_WITH_CAMELLIA_128_GCM_SHA256'
        cipher['\xC0\x7B'] = 'TLS_RSA_WITH_CAMELLIA_256_GCM_SHA384'
        cipher['\xC0\x7C'] = 'TLS_DHE_RSA_WITH_CAMELLIA_128_GCM_SHA256'
        cipher['\xC0\x7D'] = 'TLS_DHE_RSA_WITH_CAMELLIA_256_GCM_SHA384'
        cipher['\xC0\x7E'] = 'TLS_DH_RSA_WITH_CAMELLIA_128_GCM_SHA256'
        cipher['\xC0\x7F'] = 'TLS_DH_RSA_WITH_CAMELLIA_256_GCM_SHA384'
        cipher['\xC0\x80'] = 'TLS_DHE_DSS_WITH_CAMELLIA_128_GCM_SHA256'
        cipher['\xC0\x81'] = 'TLS_DHE_DSS_WITH_CAMELLIA_256_GCM_SHA384'
        cipher['\xC0\x82'] = 'TLS_DH_DSS_WITH_CAMELLIA_128_GCM_SHA256'
        cipher['\xC0\x83'] = 'TLS_DH_DSS_WITH_CAMELLIA_256_GCM_SHA384'
        cipher['\xC0\x84'] = 'TLS_DH_anon_WITH_CAMELLIA_128_GCM_SHA256'
        cipher['\xC0\x85'] = 'TLS_DH_anon_WITH_CAMELLIA_256_GCM_SHA384'
        cipher['\xC0\x86'] = 'TLS_ECDHE_ECDSA_WITH_CAMELLIA_128_GCM_SHA256'
        cipher['\xC0\x87'] = 'TLS_ECDHE_ECDSA_WITH_CAMELLIA_256_GCM_SHA384'
        cipher['\xC0\x88'] = 'TLS_ECDH_ECDSA_WITH_CAMELLIA_128_GCM_SHA256'
        cipher['\xC0\x89'] = 'TLS_ECDH_ECDSA_WITH_CAMELLIA_256_GCM_SHA384'
        cipher['\xC0\x8A'] = 'TLS_ECDHE_RSA_WITH_CAMELLIA_128_GCM_SHA256'
        cipher['\xC0\x8B'] = 'TLS_ECDHE_RSA_WITH_CAMELLIA_256_GCM_SHA384'
        cipher['\xC0\x8C'] = 'TLS_ECDH_RSA_WITH_CAMELLIA_128_GCM_SHA256'
        cipher['\xC0\x8D'] = 'TLS_ECDH_RSA_WITH_CAMELLIA_256_GCM_SHA384'
        cipher['\xC0\x8E'] = 'TLS_PSK_WITH_CAMELLIA_128_GCM_SHA256'
        cipher['\xC0\x8F'] = 'TLS_PSK_WITH_CAMELLIA_256_GCM_SHA384'
        cipher['\xC0\x90'] = 'TLS_DHE_PSK_WITH_CAMELLIA_128_GCM_SHA256'
        cipher['\xC0\x91'] = 'TLS_DHE_PSK_WITH_CAMELLIA_256_GCM_SHA384'
        cipher['\xC0\x92'] = 'TLS_RSA_PSK_WITH_CAMELLIA_128_GCM_SHA256'
        cipher['\xC0\x93'] = 'TLS_RSA_PSK_WITH_CAMELLIA_256_GCM_SHA384'
        cipher['\xC0\x94'] = 'TLS_PSK_WITH_CAMELLIA_128_CBC_SHA256'
        cipher['\xC0\x95'] = 'TLS_PSK_WITH_CAMELLIA_256_CBC_SHA384'
        cipher['\xC0\x96'] = 'TLS_DHE_PSK_WITH_CAMELLIA_128_CBC_SHA256'
        cipher['\xC0\x97'] = 'TLS_DHE_PSK_WITH_CAMELLIA_256_CBC_SHA384'
        cipher['\xC0\x98'] = 'TLS_RSA_PSK_WITH_CAMELLIA_128_CBC_SHA256'
        cipher['\xC0\x99'] = 'TLS_RSA_PSK_WITH_CAMELLIA_256_CBC_SHA384'
        cipher['\xC0\x9A'] = 'TLS_ECDHE_PSK_WITH_CAMELLIA_128_CBC_SHA256'
        cipher['\xC0\x9B'] = 'TLS_ECDHE_PSK_WITH_CAMELLIA_256_CBC_SHA384'
        cipher['\xC0\x9C'] = 'TLS_RSA_WITH_AES_128_CCM'
        cipher['\xC0\x9D'] = 'TLS_RSA_WITH_AES_256_CCM'
        cipher['\xC0\x9E'] = 'TLS_DHE_RSA_WITH_AES_128_CCM'
        cipher['\xC0\x9F'] = 'TLS_DHE_RSA_WITH_AES_256_CCM'
        cipher['\xC0\xA0'] = 'TLS_RSA_WITH_AES_128_CCM_8'
        cipher['\xC0\xA1'] = 'TLS_RSA_WITH_AES_256_CCM_8'
        cipher['\xC0\xA2'] = 'TLS_DHE_RSA_WITH_AES_128_CCM_8'
        cipher['\xC0\xA3'] = 'TLS_DHE_RSA_WITH_AES_256_CCM_8'
        cipher['\xC0\xA4'] = 'TLS_PSK_WITH_AES_128_CCM'
        cipher['\xC0\xA5'] = 'TLS_PSK_WITH_AES_256_CCM'
        cipher['\xC0\xA6'] = 'TLS_DHE_PSK_WITH_AES_128_CCM'
        cipher['\xC0\xA7'] = 'TLS_DHE_PSK_WITH_AES_256_CCM'
        cipher['\xC0\xA8'] = 'TLS_PSK_WITH_AES_128_CCM_8'
        cipher['\xC0\xA9'] = 'TLS_PSK_WITH_AES_256_CCM_8'
        cipher['\xC0\xAA'] = 'TLS_PSK_DHE_WITH_AES_128_CCM_8'
        cipher['\xC0\xAB'] = 'TLS_PSK_DHE_WITH_AES_256_CCM_8'
        cipher['\xC0\xAC'] = 'TLS_ECDHE_ECDSA_WITH_AES_128_CCM'
        cipher['\xC0\xAD'] = 'TLS_ECDHE_ECDSA_WITH_AES_256_CCM'
        cipher['\xC0\xAE'] = 'TLS_ECDHE_ECDSA_WITH_AES_128_CCM_8'
        cipher['\xC0\xAF'] = 'TLS_ECDHE_ECDSA_WITH_AES_256_CCM_8'
        cipher['\xCC\x13'] = 'TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256'
        cipher['\xCC\x14'] = 'TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256'
        cipher['\xCC\x15'] = 'TLS_DHE_RSA_WITH_CHACHA20_POLY1305_SHA256'
        # http://www.mozilla.org/projects/security/pki/nss/ssl/fips-ssl-ciphersuites.html
        cipher['\xFE\xFE'] = 'SSL_RSA_FIPS_WITH_DES_CBC_SHA'
        cipher['\xFE\xFF'] = 'SSL_RSA_FIPS_WITH_3DES_EDE_CBC_SHA'
        cipher['\xFF\xE0'] = 'SSL_RSA_FIPS_WITH_3DES_EDE_CBC_SHA'
        cipher['\xFF\xE1'] = 'SSL_RSA_FIPS_WITH_DES_CBC_SHA'
        # Special one to indicate client's support for downgrade prevention
        cipher['\x56\x00'] = 'TLS_FALLBACK_SCSV'
        return cipher

    def __helloRand(self):
        rand = struct.pack("!L", int(time.time()))
        rand += os.urandom(28)
        return rand

    def ssl2Hello(self, cipher = 0):
        cipher_spec = ""
        if cipher == 0:
            cipher_list = self.ssl2Ciphers()
            for c in cipher_list.keys():
                cipher_spec += c
        else:
            for c in cipher.keys():
                cipher_spec += c
        challenge = "\x6a\x61\x6e\x73\x65\x6e\x6f\x66\x6c\x6f\x72\x6b\x65\x65\x72\x73"
        p_len = len(cipher_spec) + len(challenge) + 9

        mask = bin(0x8000) # Most significant bit should be set to indicate no padding
        bin_plen = bin(p_len)

        packet = ""
        packet = struct.pack("!H", int(mask,2) + int(bin_plen,2))  # Length of record
        packet += "\x01" 
        packet += "\x00\x02"
        packet += struct.pack("!H", len(cipher_spec))
        packet += "\x00\x00"
        packet += "\x00\x10" 
        packet += cipher_spec
        packet += challenge
        return packet

    def tlsHello(self, protocol, cipher = 0):
        record = "\x16" # Message Type 22
        record += self.protocols[protocol]
        cipher_suites = ""
        if cipher == 0:
            cipher_list = self.tlsCiphers()
            for c in cipher_list.keys():
                cipher_suites += c
        else:
            for c in cipher.keys():
                cipher_suites += c
        if (len(cipher_suites) % 2) == 0:
            compression = "\x02\x01\x00"
            hp_len = len(cipher_suites) + len(compression) + 41
            record += struct.pack("!H", hp_len)
            handshake = "\x01" # Client Hello Message
            h_len = struct.pack("!L", hp_len-4)
            handshake += h_len[1:]
            handshake += self.protocols[protocol]
            handshake += self.__helloRand()
            handshake += "\x00"
            handshake += struct.pack("!H", len(cipher_suites))
            handshake += cipher_suites
            handshake += compression
            return record+handshake
        else:
            #Error in cipher length!
            return False
            #sys.exit(2)

    def doClientHello(self, protocol, cipher = 0):
        response = False
        try:
            if protocol == "SSLv2": # Special case for SSLv2
                helloMsg = self.ssl2Hello(cipher)
                self.TCP.sendall(helloMsg)
                buffer = self.TCP.recv(1024)
                if buffer:
                    tmp = bytearray(buffer)
                    length = hex(tmp[0])[3:]+hex(tmp[1])[2:]
                    length = int(length, 16) + 2
                    buffering = True
                    while buffering:
                        if len(buffer) == length:
                            buffering = False
                            break
                        more = self.TCP.recv(1024)
                        if not more:
                            buffering = False
                        else:
                            buffer += more
                    response = buffer
            else: # SSLv3 and all TLS versions
                helloMsg = self.tlsHello(protocol, cipher)
                self.TCP.sendall(helloMsg)
                buffer = self.TCP.recv(1024)
                if buffer:
                    if not self.contentType(buffer)[0] == 'alert' and not self.contentType(buffer)[1] == 'handshake_failure':
                        buffering = True
                        while buffering:
                            if self.serverHelloDone in buffer:
                                buffering = False
                                break
                            more = self.TCP.recv(1024)
                            if not more:
                                buffering = False
                            else:
                                buffer += more
                        response = buffer
        except socket.error as e:
            if e.errno == 54:
                response = False
            elif e.errno == 61:
                response = False
            elif socket.timeout:
                return False
                #The connection timed out, due to a missing or unexpected response
            else:
                return False
                #An unexpected error occurred
        return response

    def connect(self):
        try:
            self.TCP = socket.create_connection((self.host, int(self.port)), 5)
            return self.TCP
        except:
            #Unable to connect to remote host, please check it is up
            pass

    def closeConnection(self):
        self.TCP.close()

    def contentType(self, response):
        response = bytearray(response)
        if int(response[0]) == 22:
            contentType = 'handshake'
            if int(response[5]) == 2:
                handshakeType = 'server_hello'
            elif int(response[5]) == 11:
                handshakeType = 'certificate'
            elif int(response[5]) == 11:
                handshakeType = 'server_key_exchange'
            elif int(response[5]) == 14:
                handshakeType = 'server_hello_done'
            else:
                handshakeType = 'unknown'
            return (contentType, handshakeType)
        elif int(response[0]) == 21:
            contentType = 'alert'
            if int(response[6]) == 40:
                alertDescription = 'handshake_failure'
            elif int(response[6]) == 10:
                alertDescription = 'unexpected_message'
            elif int(response[6]) == 86:
                alertDescription = 'inappropriate_fallback'
            else:
                alertDescription = 'unknown'
            return (contentType, alertDescription)
        elif int(response[0]) == 24:
            contentType = 'heartbeat'
            if int(response[5]) == 2:
                heartbeatMessage = 'response'
            else:
                heartbeatMessage = 'unknown'
            return (contentType, heartbeatMessage)
        else:
            return ('not_implemented', 'not_implemented')

    def responseProtocol(self, response): # For SSLv3 and TLS1.#
        response = bytearray(response)
        protocol = response[1:3]
        for p in self.protocols:
            if self.protocols[p] == protocol:
                return p

    def serverHelloCipher(self, response):
        if struct.unpack('!b', response[0:1])[0] == 22 and struct.unpack('!b', response[5:6])[0] == 2:
            start = (struct.unpack('!b', response[43:44])[0] + 44)
            cipher = response[start:start+2]
            return cipher
        else:
            return ""


def removeFromCipherList(cipherList, cipher):
    cipherList.pop(cipher, None)
    return cipherList

def chunks(s, n):
    # chunk generator from string
    for start in range(0, len(s), n):
        yield s[start:start+n]

def reachable(host, port): # a quick reachability check
    reachable = True
    try:
        conn = socket.create_connection((host, int(port)), 1)
        conn.close()
    except:
        reachable = False
        pass # prevent from dying
    return reachable

def enumProtocols():
    global supportedProtocols
    supportedProtocols = []
    protocols = ["TLSv1.3", "TLSv1.2", "TLSv1.1", "TLSv1.0", "SSLv3", "SSLv2"] # High to low 
    for p in protocols:
        sock = tls.connect() # first connect
        response = tls.doClientHello(p) # then send hello
        if response:
            if p == 'SSLv2':
                if bytearray(response)[2] == 4:
                    supportedProtocols.append(p)
                    #Remote service supports sslv2
            else:
                responseProtocol = tls.responseProtocol(response)
                contentType = tls.contentType(response)
                if (contentType[0] == 'handshake' and contentType[1] == 'server_hello') and (responseProtocol == p):
                    supportedProtocols.append(p)
                    #Remote service supports: TLS1, TLS1.1,TLS1.2, SSLV3
        tls.closeConnection()
    return supportedProtocols

def enumCiphers(protocol):
    supportedCiphers = Set()
    if protocol == 'SSLv2':
        cipherList = tls.ssl2Ciphers()
        sock = tls.connect()
        response = tls.doClientHello(protocol, cipherList)
        if response:
            cert_len = struct.unpack('!H', response[7:9])[0]
            cipher_spec_len = struct.unpack('!H', response[9:11])[0]
            start = 13 + cert_len
            cipher_spec = response[start:start+cipher_spec_len]
            for cipher in chunks(cipher_spec, 3):
                supportedCiphers.add(cipher)
        else:
            pass
            #No server hello received for SSLv2! (check client hello)
        tls.closeConnection()
    else:
        cipherList = tls.tlsCiphers()
    serverHelloCipher = 1
    while serverHelloCipher > 0:
        for c in tls.tlsCiphers():
            sock = tls.connect()
            response = tls.doClientHello(protocol, cipherList)
            if response:
                contentType = tls.contentType(response)
                if contentType[0] == 'handshake' and contentType[1] == 'server_hello':
                    helloCipher = tls.serverHelloCipher(response)
                    if helloCipher != "":
                        if helloCipher in supportedCiphers:
                            serverHelloCipher = 0
                            break
                        else:
                            supportedCiphers.add(helloCipher)
                            cipherList = removeFromCipherList(cipherList, helloCipher)
                elif contentType[0] == 'alert' and contentType[1] == 'handshake_failure':
                    serverHelloCipher = 0
                    break
                else:
                    serverHelloCipher = 0
                    break
            else:
                serverHelloCipher = 0
                break
            tls.closeConnection()
    return supportedCiphers

def processTarget(target, internal=False):
    global tls
    SSLdata = dict()
    if not re.match(r'^.*[:]+[0-9]{1,5}$', target):
        target = target + ":443"
        #No port specified, setting a default one 443"
    host = target.split(':')
    if not internal:
        pass
        #Processing target
    if reachable(host[0], host[1]):
        tls = TLS(host[0], host[1])
        protocols = enumProtocols()
    #    print protocols
        if protocols:
            for p in protocols:
                ciphers = list()
                if p == 'SSLv2': # Special case for SSL2
                    cipherList = tls.ssl2Ciphers()
                else:
                    cipherList = tls.tlsCiphers()
                supportedCiphers = enumCiphers(p)
                for c in supportedCiphers:
                    ciphers.append(cipherList[c])
                SSLdata[p] = ciphers
            return SSLdata
                      #print ("%s" %(cipherList[c])) # Print Cipher
        else:
            return False
            #The service does not appear to be supporting SSL/TLS using current settings
    else:
        return False
        #An error occurred while connecting, skipping service/target
