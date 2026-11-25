"""Behavioural tests for the owncloud_cve_2023_49103_vuln module.

CVE-2023-49103: ownCloud's graphapi app ships a third-party test file that calls
``phpinfo()`` and is reachable unauthenticated, disclosing the PHP configuration
and every environment variable. These tests load the shipped module definition
and exercise its detection regex the way the HTTP engine does (``re.findall`` on
the response body), using realistically shaped ``phpinfo()`` output.
"""

import re
import time
from pathlib import Path

import pytest
import yaml

from nettacker.core.template import TemplateLoader

MODULE_PATH = (
    Path(__file__).resolve().parents[2]
    / "nettacker"
    / "modules"
    / "vuln"
    / "owncloud_cve_2023_49103.yaml"
)

TEMPLATE_INPUTS = {
    "target": "t",
    "user_agent": "UA",
    "schema": None,
    "ports": None,
    "timeout": 3.0,
}

VULNERABLE_PATH = "apps/graphapi/vendor/microsoft/microsoft-graph/tests/GetPhpInfo.php"

# phpinfo() emits a sizeable CSS block before the title, so fixtures mimic that.
CSS = "body {background-color: #fff; color: #222;}\n" * 40


def phpinfo_body(version, css=CSS, title=None):
    """Build a realistically shaped phpinfo() HTML response.

    Current PHP builds put the version in the title - ``<title>PHP 8.1.34 -
    phpinfo()</title>``, verified against ``php:8.1-apache`` - while other
    builds emit a bare ``<title>phpinfo()</title>``. Both must be detected.
    """
    page_title = title if title is not None else "PHP " + version + " - phpinfo()"
    return (
        '<!DOCTYPE html PUBLIC "-//W3C//DTD XHTML 1.0 Transitional//EN">'
        '<html xmlns="http://www.w3.org/1999/xhtml"><head>\n'
        '<style type="text/css">\n' + css + "</style>\n"
        "<title>" + page_title + "</title>"
        '<meta name="ROBOTS" content="NOINDEX,NOFOLLOW,NOARCHIVE" /></head>\n'
        '<body><div class="center">\n'
        '<h1 class="p">PHP Version ' + version + "</h1>\n"
        '<table><tr><td class="e">System </td><td class="v">Linux 5.15 </td></tr>\n'
        '<tr><td class="e">OWNCLOUD_ADMIN_PASSWORD </td><td class="v">s3cr3t </td></tr>'
        "</table></div></body></html>"
    )


@pytest.fixture(scope="module")
def module():
    with open(MODULE_PATH, "r", encoding="utf-8") as handle:
        return yaml.safe_load(handle)


@pytest.fixture(scope="module")
def step(module):
    return module["payloads"][0]["steps"][0]


@pytest.fixture(scope="module")
def content_regex():
    # Load through the engine so the regex is the one actually used at runtime.
    content = TemplateLoader("owncloud_cve_2023_49103_vuln", TEMPLATE_INPUTS).load()
    return re.compile(
        content["payloads"][0]["steps"][0]["response"]["conditions"]["content"]["regex"]
    )


def test_module_loads_through_template_engine():
    """TemplateLoader.load() runs str.format() over the raw YAML before parsing,
    so every literal brace in the file - in the regex *and* in any comment - must
    be doubled. Loading through the real engine guards against a KeyError that
    plain yaml.safe_load would not surface.
    """
    content = TemplateLoader("owncloud_cve_2023_49103_vuln", TEMPLATE_INPUTS).load()
    regex = content["payloads"][0]["steps"][0]["response"]["conditions"]["content"]["regex"]
    assert re.compile(regex).findall(phpinfo_body("8.1.2")) == ["8.1.2"]


# ---------------------------------------------------------------------------
# Module metadata / structure
# ---------------------------------------------------------------------------


def test_module_metadata(module):
    info = module["info"]
    assert info["name"] == "owncloud_cve_2023_49103_vuln"
    assert info["severity"] == 9
    for profile in ("vuln", "http", "critical_severity", "cve", "cve2023", "cisa_kev", "owncloud"):
        assert profile in info["profiles"], f"missing profile {profile}"


def test_targets_the_graphapi_test_file(step):
    """The vulnerable file is the bundled microsoft-graph test script; a patched
    install deletes it.
    """
    fuzzer = step["url"]["nettacker_fuzzer"]
    data = fuzzer["data"]
    assert VULNERABLE_PATH in data["paths"]
    # also covers ownCloud served from a /owncloud subdirectory
    assert any(p.startswith("owncloud/") for p in data["paths"])
    assert data["schema"] == ["http", "https"]
    assert set(data["ports"]) == {80, 443, 8080}


def test_requires_http_200(step):
    """A patched or unaffected host removes the file and returns 404."""
    assert step["response"]["conditions"]["status_code"]["regex"] == "200"
    assert step["response"]["condition_type"] == "and"


def test_content_regex_has_single_capture_group(content_regex):
    """The engine joins findall() results with ' '.join(...), which raises
    TypeError on tuples.
    """
    assert content_regex.groups == 1


# ---------------------------------------------------------------------------
# Detection
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    "version, expected",
    [
        ("8.1.2", "8.1.2"),
        ("7.4.33", "7.4.33"),
        # Distro-suffixed builds: the numeric version is captured.
        ("8.1.2-1ubuntu2.14", "8.1.2"),
        ("8.3.0", "8.3.0"),
    ],
)
def test_reports_the_leaked_php_version(content_regex, version, expected):
    assert " ".join(content_regex.findall(phpinfo_body(version))) == expected


def test_matches_when_the_css_block_is_large(content_regex):
    """Different PHP builds ship differently sized phpinfo stylesheets."""
    assert content_regex.findall(phpinfo_body("8.2.1", css=CSS * 4)) == ["8.2.1"]


def test_matches_a_bare_phpinfo_title(content_regex):
    """Builds that emit ``<title>phpinfo()</title>`` with no version prefix must
    still be detected.
    """
    assert content_regex.findall(phpinfo_body("8.3.0", title="phpinfo()")) == ["8.3.0"]


def test_matches_the_body_observed_from_php_8_1_apache(content_regex):
    """Regression guard for the title format emitted by real PHP: the version is
    embedded in the title element, which an exact ``<title>phpinfo()</title>``
    match would miss entirely.
    """
    body = phpinfo_body("8.1.34")
    assert "<title>PHP 8.1.34 - phpinfo()</title>" in body
    assert content_regex.findall(body) == ["8.1.34"]


# ---------------------------------------------------------------------------
# False positives
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    "body",
    [
        # Patched/unaffected host: ownCloud's own 404 page.
        "<!DOCTYPE html><html><head><title>ownCloud</title></head>"
        "<body><h1>404</h1><p>File not found</p></body></html>",
        # A page that merely mentions a PHP version but is not phpinfo output.
        "<html><head><title>Server Info</title></head><body>PHP Version 8.1.2</body></html>",
        # phpinfo title present but no version disclosed.
        "<html><head><title>phpinfo()</title></head><body>nothing here</body></html>",
        # Ordinary ownCloud login page.
        "<!DOCTYPE html><html><head><title>ownCloud</title></head><body>Login</body></html>",
        # A JSON API response.
        '{"status":"success","data":{"version":"2.45.0"}}',
        # Empty body / plain 404 text.
        "",
        "Not Found",
    ],
)
def test_no_false_positive_match(content_regex, body):
    assert re.findall(content_regex, body) == []


# ---------------------------------------------------------------------------
# Performance
# ---------------------------------------------------------------------------


def test_large_hostile_body_is_rejected_quickly(content_regex):
    """The pattern is anchored to the start of the body, so the engine makes a
    single match attempt: a large response full of decoy titles cannot drive
    repeated rescans.
    """
    body = "<title>phpinfo()</title>" * 40000
    start = time.perf_counter()
    result = content_regex.findall(body)
    elapsed = time.perf_counter() - start
    assert result == []
    assert elapsed < 1.0, f"regex took {elapsed:.3f}s"


def test_megabyte_of_junk_is_rejected_quickly(content_regex):
    body = "a" * 1_000_000
    start = time.perf_counter()
    result = content_regex.findall(body)
    elapsed = time.perf_counter() - start
    assert result == []
    assert elapsed < 1.0, f"regex took {elapsed:.3f}s"
