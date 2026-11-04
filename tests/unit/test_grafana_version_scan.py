"""Behavioural tests for the grafana_version_scan module.

These tests load the shipped module definition and exercise its version
detection regex exactly the way the HTTP engine does (``re.findall`` on the
response body, then joined into the log line). They cover the detection and
false-positive scenarios described in the module's issue: old and new Grafana
``/api/health`` key orderings, enterprise builds, pretty-printed JSON, the
``hide_version`` case, and unrelated ``/api/health`` endpoints.
"""

import re
from pathlib import Path

import pytest
import yaml

MODULE_PATH = (
    Path(__file__).resolve().parents[2] / "nettacker" / "modules" / "scan" / "grafana_version.yaml"
)


@pytest.fixture(scope="module")
def module():
    with open(MODULE_PATH, "r", encoding="utf-8") as handle:
        return yaml.safe_load(handle)


@pytest.fixture(scope="module")
def step(module):
    return module["payloads"][0]["steps"][0]


@pytest.fixture(scope="module")
def content_regex(step):
    return re.compile(step["response"]["conditions"]["content"]["regex"])


def extract_version(content_regex, body):
    """Reproduce how the engine turns the content condition into a log value.

    ``http.response_conditions_matched`` runs ``re.findall`` over the body and
    ``base`` joins the (de-duplicated) matches with spaces for the log line, so
    a single-capture-group regex logs just the captured version string.
    """
    matches = re.findall(content_regex, body)
    return " ".join(sorted(set(matches)))


# ---------------------------------------------------------------------------
# Module metadata / structure
# ---------------------------------------------------------------------------


def test_module_metadata(module):
    info = module["info"]
    assert info["name"] == "grafana_version_scan"
    # Must live in the `grafana` profile so `-p grafana` runs it with the CVE module.
    assert "grafana" in info["profiles"]
    assert "scan" in info["profiles"]


def test_targets_health_endpoint_on_expected_ports(step):
    fuzzer = step["url"]["nettacker_fuzzer"]
    assert fuzzer["input_format"].endswith("/api/health")
    data = fuzzer["data"]
    assert data["schema"] == ["http", "https"]
    # Grafana's default port (3000) plus the common web ports.
    assert set(data["ports"]) == {80, 443, 3000}


def test_requires_http_200(step):
    conditions = step["response"]["conditions"]
    assert conditions["status_code"]["regex"] == "200"
    assert step["response"]["condition_type"] == "and"
    assert step["response"]["log"] == "response_dependent['content']"


# ---------------------------------------------------------------------------
# Detection: the version is captured for every documented response shape
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    "body, expected",
    [
        # Real Grafana OSS response, hide_version=false
        # (grafana pkg/api/health_test.go TestHealthAPI_Version).
        ('{"database":"ok","version":"7.4.0","commit":"59906ab1bf"}', "7.4.0"),
        # Real Grafana Enterprise response: enterpriseCommit sits between database
        # and version (grafana pkg/api/health_test.go TestHealthAPI_VersionEnterprise).
        (
            '{"database":"ok","enterpriseCommit":"22206ab1be","version":"7.4.0","commit":"59906ab1bf"}',
            "7.4.0",
        ),
        # Old, alphabetically sorted JSON (commit, database, version) — e.g. 8.x.
        ('{"commit":"abc123","database":"ok","version":"8.3.0"}', "8.3.0"),
        # Current struct-ordered JSON (database, version, commit) — e.g. 13.x.
        ('{"database":"ok","version":"13.0.1","commit":"deadbeef"}', "13.0.1"),
        # Pretty-printed JSON (whitespace between tokens).
        ('{\n  "database": "ok",\n  "version": "9.5.0"\n}', "9.5.0"),
        # Pre-release / build-suffixed version strings.
        ('{"database":"ok","version":"11.2.0-beta1","commit":"abc"}', "11.2.0-beta1"),
    ],
)
def test_logs_only_the_version_string(content_regex, body, expected):
    assert extract_version(content_regex, body) == expected


# ---------------------------------------------------------------------------
# False positives: nothing is captured for unrelated or version-hidden responses
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    "body",
    [
        # hide_version = true: Grafana returns ONLY the database key, omitting
        # version (and commit) entirely — not an empty version. Verified in grafana
        # pkg/api/health_test.go (TestHealthAPI_AnonymousHideVersion -> {"database":"ok"}).
        '{"database":"ok"}',
        # Defensive: even an empty version value must not match.
        '{"commit":"","database":"ok","version":""}',
        # Database unhealthy (served as HTTP 503 in practice; body must not match).
        '{"database":"failing"}',
        # Generic health endpoints from other applications.
        '{"status":"ok"}',
        '{"status":"UP","checks":[]}',
        # A version field with no adjacent database key (not Grafana's shape).
        '{"version":"1.2.3","status":"ok"}',
        # database and version present but not adjacent.
        '{"database":"ok","foo":"bar","version":"1.0.0"}',
        # Empty body.
        "",
    ],
)
def test_no_false_positive_match(content_regex, body):
    assert re.findall(content_regex, body) == []
