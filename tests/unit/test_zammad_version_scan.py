"""Behavioral regression tests for the zammad_version_scan module.

These tests execute the module's HTTP response conditions exactly as the
engine does (response_conditions_matched) and assert the module's outcome
matrix, including the false-positive control required by issue #1810:
a non-Zammad target must produce no Zammad event.
"""

from pathlib import Path

import yaml

from nettacker.core.lib.http import response_conditions_matched

MODULE_PATH = (
    Path(__file__).resolve().parents[2] / "nettacker" / "modules" / "scan" / "zammad_version.yaml"
)

ZAMMAD_BRAND = '<meta name="csrf-token" content="z">'


def _steps():
    module = yaml.safe_load(MODULE_PATH.read_text(encoding="utf-8"))
    steps = module["payloads"][0]["steps"]
    return steps[0], steps[1]


def _response(status_code, content):
    return {
        "reason": "OK",
        "url": "http://127.0.0.1:8080/",
        "status_code": str(status_code),
        "content": content,
        "headers": {"Server": "Mock"},
        "responsetime": 0.1,
    }


def _branded_root_html(title):
    """A page whose title element is set to `title`, plus CSRF meta."""
    return f"<html><head><title>{title}</title>{ZAMMAD_BRAND}</head><body></body></html>"


ZAMMAD_ROOT = _branded_root_html("Zammad")
WORDPRESS_ROOT = (
    "<html><head><title>My WordPress Site</title></head>"
    "<body><p>Welcome to WordPress. This is your first post.</p></body></html>"
)
MENTIONS_ZAMMAD_ROOT = (
    "<html><head><title>Hosting Blog</title></head>"
    "<body><p>Zammad is a popular open-source helpdesk platform.</p></body></html>"
)
ZAMMAD_AUTH_JSON = '{"error":"Authentication required","error_human":"Authentication required"}'
GENERIC_403_HTML = (
    "<html><head><title>403 Forbidden</title></head><body><h1>403 Forbidden</h1></body></html>"
)
VERSION_JSON = '{"version":"6.5.4"}'


def test_step1_detects_zammad_root_page():
    branding_step, _ = _steps()
    result = response_conditions_matched(branding_step, _response(200, ZAMMAD_ROOT))
    assert result, "Zammad root page must match the branding step"
    assert "Zammad helpdesk detected" in result["log"]


def test_step1_rejects_non_zammad_page():
    branding_step, _ = _steps()
    assert not response_conditions_matched(branding_step, _response(200, WORDPRESS_ROOT))


def test_step1_rejects_page_merely_mentioning_zammad():
    branding_step, _ = _steps()
    assert not response_conditions_matched(branding_step, _response(200, MENTIONS_ZAMMAD_ROOT))


def test_step1_rejects_wrong_status_code():
    branding_step, _ = _steps()
    assert not response_conditions_matched(branding_step, _response(403, ZAMMAD_ROOT))


def test_step2_matches_zammad_auth_required_json():
    _, version_step = _steps()
    for status in ("401", "403"):
        result = response_conditions_matched(version_step, _response(status, ZAMMAD_AUTH_JSON))
        assert result, f"Zammad {status} auth JSON must match the version step"
        assert "version unknown" in result["log"]


def test_step2_rejects_non_zammad_403_page():
    """Reverse proxies and other products reject the request with HTML, not Zammad JSON."""
    _, version_step = _steps()
    assert not response_conditions_matched(version_step, _response(403, GENERIC_403_HTML))


def test_step2_rejects_exposed_version_json_without_auth():
    """A 200 response can never trigger the protected-version outcome."""
    _, version_step = _steps()
    assert not response_conditions_matched(version_step, _response(200, VERSION_JSON))
