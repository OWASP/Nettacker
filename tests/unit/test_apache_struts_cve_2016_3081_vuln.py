"""Tests for the apache_struts_cve_2016_3081_vuln module.

The payload prints a marker string through the servlet response writer, so a
vulnerable Struts instance echoes the marker in the response body.
"""

import re
from pathlib import Path

import pytest
import yaml

from nettacker.core.lib.http import response_conditions_matched

MODULE_PATH = (
    Path(__file__).resolve().parents[2]
    / "nettacker"
    / "modules"
    / "vuln"
    / "apache_struts_cve_2016_3081.yaml"
)

MARKER = "nettacker-cve-2016-3081"


@pytest.fixture(scope="module")
def module():
    with open(MODULE_PATH, encoding="utf-8") as handle:
        return yaml.safe_load(handle)


@pytest.fixture(scope="module")
def step(module):
    return module["payloads"][0]["steps"][0]


def test_module_metadata(module):
    assert module["info"]["name"] == "apache_struts_cve_2016_3081_vuln"
    assert "vuln" in module["info"]["profiles"]
    assert "cve" in module["info"]["profiles"]


def test_payload_char_array_decodes_to_marker(step):
    url = step["url"]["nettacker_fuzzer"]["input_format"]
    codes = re.search(r"new\+char\[\]%7b([\d,]+)%7d", url).group(1)
    assert "".join(chr(int(c)) for c in codes.split(",")) == MARKER


def test_payload_uses_method_prefix_and_response_writer(step):
    url = step["url"]["nettacker_fuzzer"]["input_format"]
    assert "?method:" in url
    assert "ServletActionContext" in url
    assert "getWriter()" in url


def test_fuzzer_covers_schemes_ports_and_paths(step):
    data = step["url"]["nettacker_fuzzer"]["data"]
    assert data["schema"] == ["http", "https"]
    assert data["ports"] == [80, 443]
    assert "index.action" in data["paths"]


def test_matches_response_containing_marker(step):
    body = f"<html>{MARKER}</html>"
    assert response_conditions_matched(step, {"content": body})


@pytest.mark.parametrize(
    "body",
    [
        "",
        "<html>Struts Problem Report</html>",
        # The request carries the marker only as char codes, so a server that
        # merely reflects the URL must not be reported as vulnerable.
        "GET /index.action?method:...new char[]{110,101,116,116,97,99,107,101,114}",
        "nettacker-cve-2016-0000",
    ],
)
def test_ignores_responses_without_marker(step, body):
    assert not response_conditions_matched(step, {"content": body})
