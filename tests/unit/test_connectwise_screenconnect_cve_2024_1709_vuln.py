"""Unit tests for the connectwise_screenconnect_cve_2024_1709_vuln module.

Covers module metadata, request definitions, and behavioural detection logic
for ConnectWise ScreenConnect unauthenticated authentication bypass (CVE-2024-1709)
via the SetupWizard.aspx/ endpoint.
"""

from pathlib import Path

import pytest
import yaml

from nettacker.core.lib.http import response_conditions_matched

MODULE_PATH = (
    Path(__file__).resolve().parents[2]
    / "nettacker"
    / "modules"
    / "vuln"
    / "connectwise_screenconnect_cve_2024_1709.yaml"
)


@pytest.fixture(scope="module")
def module():
    with open(MODULE_PATH, "r", encoding="utf-8") as handle:
        return yaml.safe_load(handle)


@pytest.fixture(scope="module")
def step(module):
    return module["payloads"][0]["steps"][0]


# ---------------------------------------------------------------------------
# Module metadata & configuration
# ---------------------------------------------------------------------------


def test_module_metadata(module):
    info = module["info"]
    assert info["name"] == "connectwise_screenconnect_cve_2024_1709_vuln"
    assert info["severity"] == 10.0
    assert "vuln" in info["profiles"]
    assert "http" in info["profiles"]
    assert "critical_severity" in info["profiles"]
    assert "cve" in info["profiles"]
    assert "cve2024" in info["profiles"]
    assert "cisa_kev" in info["profiles"]
    assert "connectwise" in info["profiles"]
    assert "screenconnect" in info["profiles"]
    assert "auth_bypass" in info["profiles"]


def test_targets_expected_paths_and_ports(step):
    assert step["method"] == "get"
    fuzzer = step["url"]["nettacker_fuzzer"]
    data = fuzzer["data"]

    assert set(data["schema"]) == {"http", "https"}
    assert {80, 443, 8040, 8041}.issubset(set(data["ports"]))
    assert "/SetupWizard.aspx/" in data["paths"]
    assert "/SetupWizard.aspx" in data["paths"]


def test_response_conditions_structure(step):
    response = step["response"]
    assert response["condition_type"] == "and"

    conditions = response["conditions"]
    assert conditions["status_code"]["regex"] == "200"
    assert conditions["status_code"]["reverse"] is False
    assert "SetupWizard" in conditions["content"]["regex"]
    assert "ScreenConnect" in conditions["content"]["regex"]
    assert conditions["content"]["reverse"] is False


# ---------------------------------------------------------------------------
# Behavioural detection: vulnerable responses (ScreenConnect < 23.9.8)
# ---------------------------------------------------------------------------


def test_matches_standard_vulnerable_setup_wizard_response(step):
    """Standard HTTP 200 response returned by unauthenticated exposed SetupWizard."""
    body = """<!DOCTYPE html>
<html>
<head>
    <title>ScreenConnect Setup Wizard</title>
</head>
<body>
    <form method="post" action="SetupWizard.aspx" id="ctl00">
        <h1>ConnectWise ScreenConnect Setup</h1>
    </form>
</body>
</html>"""
    response = {
        "status_code": "200",
        "headers": {"content-type": "text/html; charset=utf-8"},
        "content": body,
    }
    assert response_conditions_matched(step, response)


def test_matches_vulnerable_response_with_varied_whitespace(step):
    """Vulnerable setup wizard response with varied whitespaces and attributes."""
    body = """<html>
<head><title>Setup Wizard - ScreenConnect</title></head>
<body>
<div class="SetupWizardContainer">
  <span>Welcome to ScreenConnect Setup</span>
</div>
</body>
</html>"""
    response = {
        "status_code": "200",
        "headers": {"content-type": "text/html"},
        "content": body,
    }
    assert response_conditions_matched(step, response)


# ---------------------------------------------------------------------------
# False-positive avoidance: patched, forbidden, redirected, or unrelated responses
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    "status_code, headers, body",
    [
        # Patched ScreenConnect (>= 23.9.8) returning 403 Forbidden
        (
            "403",
            {"content-type": "text/html; charset=utf-8"},
            "<html><head><title>Access Denied</title></head><body>Access to the path is denied.</body></html>",
        ),
        # 404 Not Found (ScreenConnect not installed or path disabled)
        (
            "404",
            {"content-type": "text/html"},
            "<html><head><title>404 Not Found</title></head><body>Resource not found.</body></html>",
        ),
        # 302 Redirect to Login page (setup already completed and protected)
        (
            "302",
            {"location": "/Login", "content-type": "text/html"},
            "<html><body>Object Moved to <a href='/Login'>here</a>.</body></html>",
        ),
        # 200 OK from generic or non-ScreenConnect web application
        (
            "200",
            {"content-type": "text/html; charset=utf-8"},
            "<html><head><title>Welcome</title></head><body>Default Web Page</body></html>",
        ),
        # 200 OK mentioning ScreenConnect but not SetupWizard (e.g. login portal)
        (
            "200",
            {"content-type": "text/html"},
            "<html><head><title>ScreenConnect Login</title></head><body>Please enter your credentials</body></html>",
        ),
        # 500 Internal Server Error
        (
            "500",
            {"content-type": "text/html"},
            "<html><head><title>Runtime Error</title></head><body>An application error occurred.</body></html>",
        ),
    ],
)
def test_ignores_non_vulnerable_and_unrelated_responses(step, status_code, headers, body):
    response = {
        "status_code": status_code,
        "headers": headers,
        "content": body,
    }
    assert not response_conditions_matched(step, response)
