from unittest.mock import patch

import pytest

from nettacker.core.ip import (
    generate_ip_range,
    get_ip_range,
    is_single_ipv4,
    is_ipv4_range,
    is_ipv4_cidr,
    is_single_ipv6,
    is_ipv6_range,
    is_ipv6_cidr,
)


class TestIsSingleIPv4:
    """
    is_single_ipv4() uses netaddr.valid_ipv4(str(ip))
    Returns True for valid IPv4 addresses, False for everything else.
    Note: it wraps input in str(), so None becomes "None" — which is
    not a valid IP, so it safely returns False.
    """

    def test_standard_private_ip(self):
        assert is_single_ipv4("192.168.1.1") is True

    def test_loopback(self):
        assert is_single_ipv4("127.0.0.1") is True

    def test_public_ip(self):
        assert is_single_ipv4("8.8.8.8") is True

    def test_all_zeros(self):
        assert is_single_ipv4("0.0.0.0") is True

    def test_broadcast(self):
        assert is_single_ipv4("255.255.255.255") is True

    def test_cidr_returns_false(self):
        # A CIDR is not a single IP
        assert is_single_ipv4("192.168.1.0/24") is False

    def test_dash_range_returns_false(self):
        assert is_single_ipv4("10.0.0.1-10.0.0.5") is False

    def test_empty_string(self):
        assert is_single_ipv4("") is False

    def test_octet_out_of_range(self):
        assert is_single_ipv4("256.0.0.1") is False

    def test_ipv6_returns_false(self):
        assert is_single_ipv4("::1") is False

    def test_hostname_returns_false(self):
        assert is_single_ipv4("example.com") is False

    def test_none_input(self):
        # str(None) = "None" — not a valid IP, should be False
        assert is_single_ipv4(None) is False


class TestIsSingleIPv6:
    """
    is_single_ipv6() uses netaddr.valid_ipv6(ip)
    IMPORTANT: Unlike is_single_ipv4, there is NO str() wrapper here.
    Passing None will raise a TypeError inside netaddr.
    This is a real bug in the source — our test documents it.
    """

    def test_loopback(self):
        assert is_single_ipv6("::1") is True

    def test_full_address(self):
        assert is_single_ipv6("2001:0db8:85a3:0000:0000:8a2e:0370:7334") is True

    def test_compressed(self):
        assert is_single_ipv6("2001:db8::1") is True

    def test_all_zeros(self):
        assert is_single_ipv6("::") is True

    def test_link_local(self):
        assert is_single_ipv6("fe80::1") is True

    def test_ipv4_returns_false(self):
        assert is_single_ipv6("192.168.1.1") is False

    def test_cidr_returns_false(self):
        assert is_single_ipv6("2001:db8::/32") is False

    def test_empty_string(self):
        assert is_single_ipv6("") is False

    def test_hostname_returns_false(self):
        assert is_single_ipv6("example.com") is False

    def test_none_raises(self):
        # No str() wrapper in source — None causes TypeError
        # We document this bug with pytest.raises
        with pytest.raises((TypeError, Exception)):
            is_single_ipv6(None)


class TestIsIPv4Range:
    """
    IMPORTANT: is_ipv4_range() actually checks for CIDR notation (has "/").
    The function name is misleading — it detects 192.168.1.0/24 style input.
    This appears to be a naming bug in the source code.
    Tests reflect actual behaviour, not the name.
    """

    def test_cidr_slash_24(self):
        # This is what the function ACTUALLY accepts
        assert is_ipv4_range("192.168.1.0/24") is True

    def test_cidr_slash_8(self):
        assert is_ipv4_range("10.0.0.0/8") is True

    def test_cidr_slash_16(self):
        assert is_ipv4_range("172.16.0.0/16") is True

    def test_cidr_slash_32(self):
        assert is_ipv4_range("192.168.1.1/32") is True

    def test_dash_range_returns_false(self):
        # A real IP range with dash — this function rejects it
        assert is_ipv4_range("10.0.0.1-10.0.0.5") is False

    def test_single_ip_returns_false(self):
        assert is_ipv4_range("192.168.1.1") is False

    def test_ipv6_cidr_returns_false(self):
        # Has "/" but also ":" not "." — rejected
        assert is_ipv4_range("2001:db8::/32") is False

    def test_empty_string_returns_false(self):
        assert is_ipv4_range("") is False


class TestIsIPv4CIDR:
    """
    IMPORTANT: is_ipv4_cidr() actually checks for dash-range notation.
    It detects 10.0.0.1-10.0.0.5 style input, despite being named "cidr".
    Same naming bug as is_ipv4_range, consistent throughout the file.
    Tests reflect actual behaviour.
    """

    def test_dash_range_basic(self):
        # This is what the function ACTUALLY accepts
        assert is_ipv4_cidr("10.0.0.1-10.0.0.5") is True

    def test_dash_range_same_subnet(self):
        assert is_ipv4_cidr("192.168.1.1-192.168.1.100") is True

    def test_dash_range_wide(self):
        assert is_ipv4_cidr("10.0.0.1-10.0.1.255") is True

    def test_cidr_returns_false(self):
        # Has "/" not "-" — this function rejects it
        assert is_ipv4_cidr("192.168.1.0/24") is False

    def test_single_ip_returns_false(self):
        assert is_ipv4_cidr("192.168.1.1") is False

    def test_ipv6_range_returns_false(self):
        # Has "-" but also ":" not "." — rejected
        assert is_ipv4_cidr("::1-::5") is False

    def test_empty_string_returns_false(self):
        assert is_ipv4_cidr("") is False


class TestIsIPv6Range:
    """
    is_ipv6_range() checks for IPv6 DASH-RANGE notation (no "/", has ":", has "-").
    Same naming swap as IPv4 — despite the name, this detects dash ranges like ::1-::5.
    is_ipv6_cidr() is the one that actually detects CIDR notation.
    """

    def test_basic_dash_range(self):
        assert is_ipv6_range("::1-::5") is True

    def test_full_address_dash_range(self):
        assert is_ipv6_range("2001:db8::1-2001:db8::ff") is True

    def test_cidr_returns_false(self):
        # Has "/" — rejected by this function
        assert is_ipv6_range("2001:db8::/32") is False

    def test_single_ipv6_returns_false(self):
        assert is_ipv6_range("::1") is False

    def test_ipv4_range_returns_false(self):
        # Has "-" and "." but no ":" — rejected
        assert is_ipv6_range("10.0.0.1-10.0.0.5") is False

    def test_empty_string_returns_false(self):
        assert is_ipv6_range("") is False


class TestIsIPv6CIDR:
    """
    is_ipv6_cidr() checks for IPv6 CIDR notation (has "/", has ":", no "-").
    Despite the name, this is the actual CIDR checker for IPv6.
    """

    def test_documentation_prefix(self):
        assert is_ipv6_cidr("2001:db8::/32") is True

    def test_link_local_subnet(self):
        assert is_ipv6_cidr("fe80::/10") is True

    def test_loopback_host(self):
        assert is_ipv6_cidr("::1/128") is True

    def test_default_route(self):
        assert is_ipv6_cidr("::/0") is True

    def test_dash_range_returns_false(self):
        assert is_ipv6_cidr("::1-::5") is False

    def test_single_ipv6_returns_false(self):
        assert is_ipv6_cidr("::1") is False

    def test_ipv4_cidr_returns_false(self):
        assert is_ipv6_cidr("192.168.1.0/24") is False

    def test_empty_string_returns_false(self):
        assert is_ipv6_cidr("") is False


class TestGenerateIPRange:
    """
    generate_ip_range() returns a list of IP strings.
    Two code paths:
      1. CIDR input (has "/") — uses netaddr.IPNetwork
      2. Dash range input — uses netaddr.iprange_to_cidrs + iter_hosts
    Both paths must be tested to achieve branch coverage.
    """

    # --- CIDR path (the "if" branch) ---

    def test_cidr_slash_30(self):
        # /30 gives 4 IPs including network and broadcast
        result = generate_ip_range("10.0.0.0/30")
        assert "10.0.0.1" in result
        assert "10.0.0.2" in result

    def test_cidr_returns_list(self):
        result = generate_ip_range("192.168.1.0/30")
        assert isinstance(result, list)

    def test_cidr_all_items_are_strings(self):
        result = generate_ip_range("10.0.0.0/30")
        for ip in result:
            assert isinstance(ip, str)

    # --- Dash range path (the "else" branch) ---

    def test_dash_range_three_ips(self):
        result = generate_ip_range("10.0.0.1-10.0.0.3")
        assert result == ["10.0.0.1", "10.0.0.2", "10.0.0.3"]

    def test_dash_range_single_ip(self):
        result = generate_ip_range("10.0.0.5-10.0.0.5")
        assert result == ["10.0.0.5"]

    def test_dash_range_order_is_ascending(self):
        result = generate_ip_range("10.0.0.1-10.0.0.5")
        assert result == sorted(result)


class TestGetIPRange:
    """
    get_ip_range() makes a live HTTP request to RIPE's API.
    We mock requests.get to avoid network calls in tests.
    Two behaviours to test:
      1. Successful API response — returns generate_ip_range() result
      2. Any failure (network down, bad JSON, missing key) — returns [ip]
    """

    def test_exception_returns_ip_as_list(self):
        # When anything goes wrong, function returns [ip] as fallback
        # We simulate failure by making requests.get raise an exception
        with patch("nettacker.core.ip.requests.get") as mock_get:
            mock_get.side_effect = Exception("network error")
            result = get_ip_range("8.8.8.8")
            assert result == ["8.8.8.8"]

    def test_invalid_json_returns_ip_as_list(self):
        # Bad JSON response — json.loads will fail, fallback kicks in
        with patch("nettacker.core.ip.requests.get") as mock_get:
            mock_get.return_value.content = b"not valid json"
            result = get_ip_range("1.1.1.1")
            assert result == ["1.1.1.1"]

    def test_missing_key_returns_ip_as_list(self):
        # Valid JSON but wrong structure — KeyError triggers fallback
        with patch("nettacker.core.ip.requests.get") as mock_get:
            mock_get.return_value.content = b'{"unexpected": "structure"}'
            result = get_ip_range("9.9.9.9")
            assert result == ["9.9.9.9"]

    def test_returns_list_type(self):
        # Whatever happens, result must always be a list
        with patch("nettacker.core.ip.requests.get") as mock_get:
            mock_get.side_effect = Exception("timeout")
            result = get_ip_range("8.8.8.8")
            assert isinstance(result, list)
