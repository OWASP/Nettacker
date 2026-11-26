"""Unit tests for the cve_2024_25600_vuln module.

Covers module metadata, request definitions, and behavioural detection logic
for WordPress Bricks Builder unauthenticated RCE (CVE-2024-25600) via the
exposed render_element REST API route.
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
    / "cve_2024_25600.yaml"
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
    assert info["name"] == "cve_2024_25600_vuln"
    assert info["severity"] == 9.8
    assert "vuln" in info["profiles"]
    assert "http" in info["profiles"]
    assert "wordpress" in info["profiles"]
    assert "cve" in info["profiles"]
    assert "cve2024" in info["profiles"]
    assert "cisa_kev" in info["profiles"]
    assert "critical_severity" in info["profiles"]


def test_targets_expected_paths_and_ports(step):
    assert step["method"] == "get"
    fuzzer = step["url"]["nettacker_fuzzer"]
    data = fuzzer["data"]

    assert set(data["schema"]) == {"http", "https"}
    assert {80, 443, 8080, 8443}.issubset(set(data["ports"]))
    assert "/wp-json/bricks/v1/render_element" in data["paths"]
    assert "/?rest_route=/bricks/v1/render_element" in data["paths"]


def test_response_conditions_structure(step):
    response = step["response"]
    assert response["condition_type"] == "and"

    conditions = response["conditions"]
    assert conditions["status_code"]["regex"] == "400"
    assert conditions["status_code"]["reverse"] is False
    assert conditions["headers"]["content-type"]["regex"] == "application/json"
    assert conditions["headers"]["content-type"]["reverse"] is False
    assert "rest_missing_callback_param" in conditions["content"]["regex"]
    assert conditions["content"]["reverse"] is False


# ---------------------------------------------------------------------------
# Behavioural detection: vulnerable responses (Bricks Builder <= 1.9.6)
# ---------------------------------------------------------------------------


def test_matches_standard_vulnerable_bricks_response(step):
    """Standard HTTP 400 response returned by unauthenticated vulnerable Bricks."""
    body = (
        '{"code":"rest_missing_callback_param",'
        '"message":"Missing parameter(s): postId",'
        '"data":{"status":400,"params":["postId"]}}'
    )
    response = {
        "status_code": "400",
        "headers": {"content-type": "application/json; charset=UTF-8"},
        "content": body,
    }
    assert response_conditions_matched(step, response)


def test_matches_pretty_printed_vulnerable_response(step):
    """Pretty-printed JSON response with formatting whitespaces/newlines."""
    body = """{
  "code": "rest_missing_callback_param",
  "message": "Missing parameter(s): postId",
  "data": {
    "status": 400,
    "params": [
      "postId"
    ]
  }
}"""
    response = {
        "status_code": "400",
        "headers": {"content-type": "application/json"},
        "content": body,
    }
    assert response_conditions_matched(step, response)


def test_matches_vulnerable_response_with_additional_fields(step):
    """Vulnerable response containing extra diagnostic or plugin fields."""
    body = (
        '{"code":"rest_missing_callback_param",'
        '"message":"Missing parameter(s): postId",'
        '"data":{"status":400,"params":["postId"],"details":"extra"}}'
    )
    response = {
        "status_code": "400",
        "headers": {"content-type": "application/json; charset=utf-8"},
        "content": body,
    }
    assert response_conditions_matched(step, response)


# ---------------------------------------------------------------------------
# False-positive avoidance: patched, unauthorized, or unrelated responses
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    "status_code, headers, body",
    [
        # Patched Bricks (>= 1.9.7) requiring authentication/permission check
        (
            "401",
            {"content-type": "application/json; charset=UTF-8"},
            '{"code":"rest_forbidden","message":"Sorry, you are not allowed to do that.","data":{"status":401}}',
        ),
        (
            "401",
            {"content-type": "application/json"},
            '{"code":"rest_cannot_access","message":"Only authenticated users can access.","data":{"status":401}}',
        ),
        # Route not found (Bricks not installed)
        (
            "404",
            {"content-type": "application/json"},
            '{"code":"rest_no_route","message":"No route was found matching the URL and request method.","data":{"status":404}}',
        ),
        # Normal 200 OK page
        (
            "200",
            {"content-type": "text/html; charset=UTF-8"},
            "<html><body>Welcome to WordPress</body></html>",
        ),
        # HTTP 400 from unrelated endpoint with different missing param
        (
            "400",
            {"content-type": "application/json"},
            '{"code":"rest_missing_callback_param","message":"Missing parameter(s): id","data":{"status":400,"params":["id"]}}',
        ),
        # HTTP 400 with generic HTML error (e.g. proxy / web server error)
        (
            "400",
            {"content-type": "text/html"},
            "<html><head><title>400 Bad Request</title></head><body>Bad Request</body></html>",
        ),
        # Internal server error
        (
            "500",
            {"content-type": "application/json"},
            '{"code":"internal_error","message":"Fatal error","data":{"status":500}}',
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
