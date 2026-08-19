"""
Tests for the CVE-2024-0012 PAN-OS authentication bypass detection module.

Validates three scenarios:
  1. True positive — vulnerable target returns HTTP 200 + ZTP page
  2. True negative — patched target returns HTTP 302 redirect
  3. True negative — non-PAN-OS host returns HTTP 200 but no ZTP content
"""

import os

import pytest
import yaml

from nettacker.core.lib import http

MODULE_PATH = os.path.join(
    os.path.dirname(__file__),
    "..",
    "..",
    "nettacker",
    "modules",
    "vuln",
    "paloalto_panos_cve_2024_0012.yaml",
)


EXPECTED_PROBE_PATH = "php/ztp_gate.php/.js.map"


@pytest.fixture(scope="module")
def module_step():
    """Load the module YAML and return the first payload step.

    Also verifies probe request invariants:
      - The expected probe path is present in the URL fuzzer data.
      - The X-PAN-AUTHCHECK bypass header is set to 'off'.
    """
    with open(MODULE_PATH) as f:
        data = yaml.safe_load(f)
    step = data["payloads"][0]["steps"][0]

    # Verify probe path is configured correctly
    paths = step["url"]["nettacker_fuzzer"]["data"]["paths"]
    assert EXPECTED_PROBE_PATH in paths, (
        f"Expected probe path '{EXPECTED_PROBE_PATH}' not found in module paths: {paths}"
    )

    # Verify bypass header is present (case-insensitive lookup)
    headers = {k.lower(): v for k, v in step["headers"].items()}
    assert headers.get("x-pan-authcheck") == "off", (
        "X-PAN-AUTHCHECK header must be set to 'off' for the bypass to work"
    )

    return step


class TestCVE20240012TruePositive:
    """Vulnerable PAN-OS target: HTTP 200 with ZTP page title."""

    def test_vulnerable_target_matches(self, module_step):
        """
        Test that the module successfully triggers on a vulnerable PAN-OS target.

        A true positive is defined as an HTTP 200 response containing the exact
        'Zero Touch Provisioning' string in its body.
        """
        response = {
            "status_code": "200",
            "url": "https://10.0.0.1:443/php/ztp_gate.php/.js.map",
            "reason": "OK",
            "headers": {
                "Content-Type": "text/html; charset=UTF-8",
                "X-Content-Type-Options": "nosniff",
                "Strict-Transport-Security": "max-age=31536000",
            },
            "responsetime": 0.15,
            "content": (
                "<html><head><title>Zero Touch Provisioning</title></head>"
                "<body><h1>Device Registered</h1></body></html>"
            ),
        }
        result = http.response_conditions_matched(module_step, response)
        assert result != {}, "Module must fire on a vulnerable PAN-OS target"
        assert result["status_code"] == ["200"]
        assert "Zero Touch Provisioning" in result["content"][0]


class TestCVE20240012PatchedTarget:
    """Patched PAN-OS target: HTTP 302 redirect to login page."""

    def test_patched_target_does_not_match(self, module_step):
        """
        Test that the module safely ignores a patched PAN-OS target.

        A patched system redirects the unauthenticated user back to the login
        page via an HTTP 302 response, which must not trigger the module.
        """
        response = {
            "status_code": "302",
            "url": "https://10.0.0.1:443/php/ztp_gate.php/.js.map",
            "reason": "Found",
            "headers": {
                "Location": "/php/login.php?",
                "Content-Type": "text/html; charset=UTF-8",
                "Set-Cookie": "PHPSESSID=abc123; path=/; HttpOnly",
            },
            "responsetime": 0.12,
            "content": "",
        }
        result = http.response_conditions_matched(module_step, response)
        assert result == {}, "Module must NOT fire on a patched PAN-OS target"


class TestCVE20240012NonTarget:
    """Non-PAN-OS host returning HTTP 200 but without ZTP content."""

    def test_generic_webserver_does_not_match(self, module_step):
        """
        Test that the module does not trigger on a generic webserver.

        Even if the server returns an HTTP 200 OK, the absence of the
        specific Zero Touch Provisioning title must prevent a match.
        """
        response = {
            "status_code": "200",
            "url": "https://10.0.0.2:443/php/ztp_gate.php/.js.map",
            "reason": "OK",
            "headers": {
                "Content-Type": "text/html",
                "Server": "nginx/1.25.3",
            },
            "responsetime": 0.05,
            "content": (
                "<html><head><title>Welcome to nginx!</title></head>"
                "<body><h1>Welcome to nginx!</h1></body></html>"
            ),
        }
        result = http.response_conditions_matched(module_step, response)
        assert result == {}, "Module must NOT fire on a non-PAN-OS generic web server"

    def test_404_does_not_match(self, module_step):
        """
        Test that the module does not trigger on HTTP 404 Not Found responses.

        Requests to non-existent PAN-OS management ports or arbitrary generic
        servers returning 404 must be safely ignored.
        """
        response = {
            "status_code": "404",
            "url": "https://10.0.0.3:8443/php/ztp_gate.php/.js.map",
            "reason": "Not Found",
            "headers": {"Content-Type": "text/html"},
            "responsetime": 0.03,
            "content": "<html><body><h1>404 Not Found</h1></body></html>",
        }
        result = http.response_conditions_matched(module_step, response)
        assert result == {}, "Module must NOT fire on a 404 response"

    def test_200_with_partial_ztp_string_does_not_match(self, module_step):
        """
        Ensure regex doesn't match partial strings that aren't actually ZTP.

        Validates that the specific regex pattern correctly requires the full
        'Zero Touch Provisioning' string and won't false positive on substrings.
        The content includes 'Zero Touch' (partial) but NOT the full
        'Zero Touch Provisioning' title required by the detection regex.
        """
        response = {
            "status_code": "200",
            "url": "https://10.0.0.4:443/php/ztp_gate.php/.js.map",
            "reason": "OK",
            "headers": {"Content-Type": "text/html"},
            "responsetime": 0.08,
            "content": (
                "<html><head><title>Zero Touch</title></head>"
                "<body>Not full ZTP title.</body></html>"
            ),
        }
        result = http.response_conditions_matched(module_step, response)
        assert result == {}, "Module must NOT fire when content lacks ZTP title"
