import json
from unittest.mock import patch

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


class Responses:
    get_ip_range_valid_response = {
        "objects": {
            "object": [
                {
                    "primary-key": {
                        "attribute": [
                            {"name": "inetnum", "value": "223.27.114.0 - 223.27.114.127"}
                        ]
                    }
                }
            ]
        }
    }

    validate_ip_range = [f"223.27.114.{i}" for i in range(1, 127)]

    get_ip_range_invalid_response = {
        "link": {},
        "errormessages": {
            "errormessage": [
                {
                    "severity": "Error",
                    "text": "ERROR:101: no entries found\n\nNo entries found in source %s.\n",
                    "args": [{"value": "RIPE"}],
                }
            ]
        },
    }


def test_generate_ip_range():
    assert generate_ip_range("192.168.1.0/30") == [
        "192.168.1.0",
        "192.168.1.1",
        "192.168.1.2",
        "192.168.1.3",
    ]
    assert generate_ip_range("192.168.1.1-192.168.1.3") == [
        "192.168.1.1",
        "192.168.1.2",
        "192.168.1.3",
    ]


@patch("requests.get")
def test_get_ip_range(mock_get):
    test_ip = "223.27.115.10"
    invalid_test_ip = "223.27.115.10.21"

    mock_get.return_value.content = json.dumps(Responses.get_ip_range_valid_response).encode(
        "utf-8"
    )
    assert get_ip_range(test_ip) == Responses.validate_ip_range

    mock_get.return_value.content = json.dumps(Responses.get_ip_range_invalid_response).encode(
        "utf-8"
    )
    assert get_ip_range(invalid_test_ip) == [invalid_test_ip]


def test_is_single_ipv4():
    assert is_single_ipv4("127.0.0.1") is True
    assert is_single_ipv4("2001:0DC8:E004:0001:0000:0000:0000:F00A") is False
    assert is_single_ipv4("256.0.0.1") is False


def test_is_ipv4_range():
    assert is_ipv4_range("192.168.1.0/24") is True
    assert is_ipv4_range("127.0.0.1") is False
    assert is_ipv4_range("192.168.1.0/100") is False


def test_is_ipv4_cidr():
    assert is_ipv4_cidr("192.168.1.1-192.168.1.100") is True
    assert is_ipv4_cidr("192.168.1.1/24") is False
    assert is_ipv4_cidr("192.168.1.1-192.168.1.256") is False


def test_is_single_ipv6():
    assert is_single_ipv6("2001:0db8:85a3:0000:0000:8a2e:0370:7334") is True
    assert is_single_ipv6("127.0.0.1") is False
    assert is_single_ipv6("2001:db8:3333:4444:5555:6666:7777:88g8") is False


def test_is_ipv6_range():
    assert is_ipv6_range("2001:db8::1-2001:db8::100") is True
    assert is_ipv6_range("2001:db8::/64") is False
    assert is_ipv6_range("2001:db8::1-2001:db8::1g0") is False


def test_is_ipv6_cidr():
    assert is_ipv6_cidr("2001:db8:abcd:0012::/64") is True
    assert is_ipv6_cidr("2001:db8::/129") is False
    assert is_ipv6_cidr("2001:dg8:abcd:0012::/64") is False
