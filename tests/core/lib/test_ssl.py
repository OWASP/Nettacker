# tests/core/lib/test_ssl.py
# Tests for nettacker/core/lib/ssl.py
# Author: Parneet Kaur
# GSoC 2026 - OWASP Nettacker

import pytest
from nettacker.core.lib.ssl import is_weak_hash_algo


class TestIsWeakHashAlgo:
    """
    Tests for is_weak_hash_algo(algo).
    This function returns True if the algorithm is considered weak
    (md2, md4, md5, sha1), and False if it is safe (sha256, sha512 etc.)
    """

    # --- WEAK algorithms — should return True ---

    def test_sha1_is_weak(self):
        assert is_weak_hash_algo("sha1WithRSAEncryption") is True

    def test_md5_is_weak(self):
        assert is_weak_hash_algo("md5WithRSAEncryption") is True

    def test_md2_is_weak(self):
        assert is_weak_hash_algo("md2WithRSAEncryption") is True

    def test_md4_is_weak(self):
        assert is_weak_hash_algo("md4WithRSAEncryption") is True

    # --- Case insensitivity — function lowercases input, so these must also work ---

    def test_sha1_uppercase_is_weak(self):
        # The function does algo.lower() so uppercase should still be caught
        assert is_weak_hash_algo("SHA1WithRSAEncryption") is True

    def test_md5_uppercase_is_weak(self):
        assert is_weak_hash_algo("MD5WithRSAEncryption") is True

    # --- SAFE algorithms — should return False ---

    def test_sha256_is_safe(self):
        assert is_weak_hash_algo("sha256WithRSAEncryption") is False

    def test_sha512_is_safe(self):
        assert is_weak_hash_algo("sha512WithRSAEncryption") is False

    def test_sha384_is_safe(self):
        assert is_weak_hash_algo("sha384WithRSAEncryption") is False

    # --- Edge cases ---

    def test_empty_string_does_not_crash(self):
        # Empty string should return False, not raise an exception
        assert is_weak_hash_algo("") is False

    def test_random_string_is_not_weak(self):
        assert is_weak_hash_algo("someRandomAlgorithm") is False