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
from tests.common import TestCase


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

    validate_ip_range = [
        "223.27.114.1",
        "223.27.114.2",
        "223.27.114.3",
        "223.27.114.4",
        "223.27.114.5",
        "223.27.114.6",
        "223.27.114.7",
        "223.27.114.8",
        "223.27.114.9",
        "223.27.114.10",
        "223.27.114.11",
        "223.27.114.12",
        "223.27.114.13",
        "223.27.114.14",
        "223.27.114.15",
        "223.27.114.16",
        "223.27.114.17",
        "223.27.114.18",
        "223.27.114.19",
        "223.27.114.20",
        "223.27.114.21",
        "223.27.114.22",
        "223.27.114.23",
        "223.27.114.24",
        "223.27.114.25",
        "223.27.114.26",
        "223.27.114.27",
        "223.27.114.28",
        "223.27.114.29",
        "223.27.114.30",
        "223.27.114.31",
        "223.27.114.32",
        "223.27.114.33",
        "223.27.114.34",
        "223.27.114.35",
        "223.27.114.36",
        "223.27.114.37",
        "223.27.114.38",
        "223.27.114.39",
        "223.27.114.40",
        "223.27.114.41",
        "223.27.114.42",
        "223.27.114.43",
        "223.27.114.44",
        "223.27.114.45",
        "223.27.114.46",
        "223.27.114.47",
        "223.27.114.48",
        "223.27.114.49",
        "223.27.114.50",
        "223.27.114.51",
        "223.27.114.52",
        "223.27.114.53",
        "223.27.114.54",
        "223.27.114.55",
        "223.27.114.56",
        "223.27.114.57",
        "223.27.114.58",
        "223.27.114.59",
        "223.27.114.60",
        "223.27.114.61",
        "223.27.114.62",
        "223.27.114.63",
        "223.27.114.64",
        "223.27.114.65",
        "223.27.114.66",
        "223.27.114.67",
        "223.27.114.68",
        "223.27.114.69",
        "223.27.114.70",
        "223.27.114.71",
        "223.27.114.72",
        "223.27.114.73",
        "223.27.114.74",
        "223.27.114.75",
        "223.27.114.76",
        "223.27.114.77",
        "223.27.114.78",
        "223.27.114.79",
        "223.27.114.80",
        "223.27.114.81",
        "223.27.114.82",
        "223.27.114.83",
        "223.27.114.84",
        "223.27.114.85",
        "223.27.114.86",
        "223.27.114.87",
        "223.27.114.88",
        "223.27.114.89",
        "223.27.114.90",
        "223.27.114.91",
        "223.27.114.92",
        "223.27.114.93",
        "223.27.114.94",
        "223.27.114.95",
        "223.27.114.96",
        "223.27.114.97",
        "223.27.114.98",
        "223.27.114.99",
        "223.27.114.100",
        "223.27.114.101",
        "223.27.114.102",
        "223.27.114.103",
        "223.27.114.104",
        "223.27.114.105",
        "223.27.114.106",
        "223.27.114.107",
        "223.27.114.108",
        "223.27.114.109",
        "223.27.114.110",
        "223.27.114.111",
        "223.27.114.112",
        "223.27.114.113",
        "223.27.114.114",
        "223.27.114.115",
        "223.27.114.116",
        "223.27.114.117",
        "223.27.114.118",
        "223.27.114.119",
        "223.27.114.120",
        "223.27.114.121",
        "223.27.114.122",
        "223.27.114.123",
        "223.27.114.124",
        "223.27.114.125",
        "223.27.114.126",
    ]

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


class TestIP(TestCase):
    def test_generate_ip_range(self):
        ip_range_with_cidr = "192.168.1.0/30"
        ip_range_without_cidr = "192.168.1.1-192.168.1.3"
        with_cidr_output = generate_ip_range(ip_range_with_cidr)
        without_cidr_output = generate_ip_range(ip_range_without_cidr)

        self.assertEqual(
            with_cidr_output, ["192.168.1.0", "192.168.1.1", "192.168.1.2", "192.168.1.3"]
        )
        self.assertEqual(without_cidr_output, ["192.168.1.1", "192.168.1.2", "192.168.1.3"])

    @patch("requests.get")
    def test_get_ip_range(self, mock_get):
        test_ip = "223.27.115.10"
        invalid_test_ip = "223.27.115.10.21"

        mock_get.return_value.content = json.dumps(Responses.get_ip_range_valid_response).encode(
            "UTF-8"
        )
        valid_ip_result = get_ip_range(test_ip)

        # invalid ip raises a KeyError and returns the ip itself
        mock_get.return_value.content = json.dumps(Responses.get_ip_range_invalid_response).encode(
            "utf-8"
        )
        invalid_ip_result = get_ip_range(invalid_test_ip)

        self.assertEqual(valid_ip_result, Responses.validate_ip_range)
        self.assertEqual(invalid_ip_result, [invalid_test_ip])

    def test_is_single_ipv4(self):
        single_ipv4 = "127.0.0.1"
        single_ipv6 = "2001:0DC8:E004:0001:0000:0000:0000:F00A"
        invalid_ipv4 = "256.0.0.1"

        self.assertEqual(is_single_ipv4(single_ipv4), True)
        self.assertEqual(is_single_ipv4(single_ipv6), False)
        self.assertEqual(is_single_ipv4(invalid_ipv4), False)

    def test_is_ipv4_range(self):
        valid_ipv4_range = "192.168.1.0/24"
        invalid_ipv4_range = "127.0.0.1"
        exception_case_ipv4_range = "192.168.1.0/100"

        self.assertEqual(is_ipv4_range(valid_ipv4_range), True)
        self.assertEqual(is_ipv4_range(invalid_ipv4_range), False)
        self.assertEqual(is_ipv4_range(exception_case_ipv4_range), False)

    def test_is_ipv4_cidr(self):
        valid_ipv4_cidr = "192.168.1.1-192.168.1.100"
        invalid_ipv4_cidr = "192.168.1.1/24"
        exception_case_ipv4_cidr = "192.168.1.1-192.168.1.256"

        self.assertEqual(is_ipv4_cidr(valid_ipv4_cidr), True)
        self.assertEqual(is_ipv4_cidr(invalid_ipv4_cidr), False)
        self.assertEqual(is_ipv4_cidr(exception_case_ipv4_cidr), False)

    def test_is_single_ipv6(self):
        single_ipv6 = "2001:0db8:85a3:0000:0000:8a2e:0370:7334"
        single_ipv4 = "127.0.0.1"
        invalid_ipv6 = "2001:db8:3333:4444:5555:6666:7777:88g8"

        self.assertEqual(is_single_ipv6(single_ipv6), True)
        self.assertEqual(is_single_ipv6(single_ipv4), False)
        self.assertEqual(is_single_ipv6(invalid_ipv6), False)

    def test_is_ipv6_range(self):
        valid_ipv6_range = "2001:db8::1-2001:db8::100"
        invalid_ipv6_range = "2001:db8::/64"
        exception_case_ipv6_range = "2001:db8::1-2001:db8::1g0"

        self.assertEqual(is_ipv6_range(valid_ipv6_range), True)
        self.assertEqual(is_ipv6_range(invalid_ipv6_range), False)
        self.assertEqual(is_ipv6_range(exception_case_ipv6_range), False)

    def test_is_ipv6_cidr(self):
        valid_ipv6_cidr = "2001:db8:abcd:0012::/64"
        invalid_ipv6_cidr = "2001:db8::/129"
        exception_case_ipv6_cidr = "2001:dg8:abcd:0012::/64"

        self.assertEqual(is_ipv6_cidr(valid_ipv6_cidr), True)
        self.assertEqual(is_ipv6_cidr(invalid_ipv6_cidr), False)
        self.assertEqual(is_ipv6_cidr(exception_case_ipv6_cidr), False)
