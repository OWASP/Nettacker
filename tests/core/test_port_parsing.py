"""
Unit tests for port range parsing in arg_parser module.
Tests the regex-based validation for --ports and --excluded-ports.
"""

import pytest

from nettacker.core.arg_parser import validate_and_parse_ports


class TestPortParsing:
    """Test suite for port range parsing (--ports and --excluded-ports)."""

    @pytest.mark.parametrize(
        "port_value",
        [
            "80-90-100",
            "80-",
            "-80",
            "90-80",
            "70000",
            "0",
            "80 90",
            "135-139-445",
            "",
            "   ",
            "abc",
            "65530-70000",
        ],
    )
    def test_invalid_port_formats(self, port_value):
        """Test that invalid port specifications are rejected."""
        with pytest.raises(SystemExit):
            validate_and_parse_ports(port_value)

    @pytest.mark.parametrize(
        ("port_value", "expected"),
        [
            ("80", {80}),
            ("80-82", {80, 81, 82}),
            (
                "22,80-90,443,8080-8090",
                set([22, 443]) | set(range(80, 91)) | set(range(8080, 8091)),
            ),
        ],
    )
    def test_valid_ports(self, port_value, expected):
        """Test that valid port specifications are parsed correctly."""
        assert validate_and_parse_ports(port_value) == expected
