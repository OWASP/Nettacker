"""Behavioural tests for the vault_version_scan module.

These load the shipped module definition and exercise its version-detection
regex the way the HTTP engine does (``re.findall`` on the response body, then
joined into the log line). Fixtures use the real shape of HashiCorp Vault's
``/v1/sys/health`` response (documented at
https://developer.hashicorp.com/vault/api-docs/system/health), including the
sealed, standby and uninitialized states, which all disclose the version.
"""

import re
import time
from pathlib import Path

import pytest
import yaml

from nettacker.core.template import TemplateLoader

MODULE_PATH = (
    Path(__file__).resolve().parents[2] / "nettacker" / "modules" / "scan" / "vault_version.yaml"
)

TEMPLATE_INPUTS = {
    "target": "t",
    "user_agent": "UA",
    "schema": None,
    "ports": None,
    "timeout": 3.0,
}


@pytest.fixture(scope="module")
def module():
    with open(MODULE_PATH, "r", encoding="utf-8") as handle:
        return yaml.safe_load(handle)


@pytest.fixture(scope="module")
def step(module):
    return module["payloads"][0]["steps"][0]


@pytest.fixture(scope="module")
def content_regex():
    # Load through the engine so the regex is the one actually used at runtime
    # (TemplateLoader runs str.format() over the YAML, collapsing the doubled
    # braces back to single ones).
    content = TemplateLoader("vault_version_scan", TEMPLATE_INPUTS).load()
    return re.compile(
        content["payloads"][0]["steps"][0]["response"]["conditions"]["content"]["regex"]
    )


def test_module_loads_through_template_engine():
    """TemplateLoader.load() runs str.format() over the raw YAML before parsing,
    so every literal brace in the file - in the regex *and* in any comment - must
    be doubled. Loading through the real engine guards against a KeyError that
    plain yaml.safe_load would not surface.
    """
    content = TemplateLoader("vault_version_scan", TEMPLATE_INPUTS).load()
    regex = content["payloads"][0]["steps"][0]["response"]["conditions"]["content"]["regex"]
    body = '{"initialized":true,"sealed":false,"version":"1.15.2"}'
    assert re.compile(regex).findall(body) == ["1.15.2"]


def extract_version(content_regex, body):
    """Reproduce how the engine turns the content condition into a log value."""
    matches = re.findall(content_regex, body)
    # The engine joins findall() results with " "; a single-group regex returns
    # plain strings, so this must not raise.
    return " ".join(matches)


# ---------------------------------------------------------------------------
# Module metadata / structure
# ---------------------------------------------------------------------------


def test_module_metadata(module):
    info = module["info"]
    assert info["name"] == "vault_version_scan"
    assert info["severity"] == 3
    for profile in ("scan", "http", "vault", "info_severity"):
        assert profile in info["profiles"]


def test_targets_health_endpoint_on_expected_ports(step):
    fuzzer = step["url"]["nettacker_fuzzer"]
    assert fuzzer["input_format"].endswith("/v1/sys/health")
    data = fuzzer["data"]
    assert data["schema"] == ["http", "https"]
    # Vault's default API port (8200) plus the common web ports for proxied setups.
    assert set(data["ports"]) == {80, 443, 8200}


def test_accepts_every_documented_health_status_code(step):
    """Vault returns the version in all node states, so gating on 200 alone would
    miss sealed (503), standby (429), replication secondary (472), performance
    standby (473), uninitialized (501), a standby that cannot reach the active
    node and is therefore out of the HA cluster (474, ``haunhealthycode``) and a
    node removed from the HA cluster (530, ``removedcode``).
    """
    status_regex = step["response"]["conditions"]["status_code"]["regex"]
    compiled = re.compile(status_regex)
    for code in ("200", "429", "472", "473", "474", "501", "503", "530"):
        assert compiled.search(code), f"status code {code} should be accepted"
    assert step["response"]["condition_type"] == "and"
    assert step["response"]["log"] == "response_dependent['content']"


def test_content_regex_has_single_capture_group(content_regex):
    """The engine joins findall() results with ' '.join(...), which raises
    TypeError on tuples. Guard against regressing to multiple capture groups.
    """
    assert content_regex.groups == 1


# ---------------------------------------------------------------------------
# Detection: the version is captured in every node state
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    "body, expected",
    [
        # Initialized, unsealed, active node (HTTP 200).
        (
            '{"initialized":true,"sealed":false,"standby":false,"performance_standby":false,'
            '"replication_performance_mode":"disabled","replication_dr_mode":"disabled",'
            '"server_time_utc":1700000000,"version":"1.15.2",'
            '"cluster_name":"vault-cluster-5515c810","cluster_id":"3b7f1a2c"}',
            "1.15.2",
        ),
        # Sealed node (HTTP 503) - no cluster_name/cluster_id are returned.
        (
            '{"initialized":true,"sealed":true,"standby":true,"performance_standby":false,'
            '"replication_performance_mode":"unknown","replication_dr_mode":"unknown",'
            '"server_time_utc":1700000000,"version":"1.15.2"}',
            "1.15.2",
        ),
        # Uninitialized node (HTTP 501).
        (
            '{"initialized":false,"sealed":true,"standby":true,'
            '"server_time_utc":1700000000,"version":"1.16.1"}',
            "1.16.1",
        ),
        # Verbatim body observed from hashicorp/vault:1.16.1 while uninitialized
        # (HTTP 501). Newer builds add enterprise/echo_duration_ms/clock_skew_ms
        # fields, which must not affect the capture.
        (
            '{"initialized":false,"sealed":true,"standby":true,"performance_standby":false,'
            '"replication_performance_mode":"unknown","replication_dr_mode":"unknown",'
            '"server_time_utc":1795595086,"version":"1.16.1","enterprise":false,'
            '"echo_duration_ms":0,"clock_skew_ms":0}',
            "1.16.1",
        ),
        # Standby node (HTTP 429).
        (
            '{"initialized":true,"sealed":false,"standby":true,"server_time_utc":1,'
            '"version":"1.14.8","cluster_name":"vault-cluster-x"}',
            "1.14.8",
        ),
        # Standby that cannot reach the active node, so it is out of the HA
        # cluster (HTTP 474). Newer builds add an ha_connection_healthy field.
        (
            '{"initialized":true,"sealed":false,"standby":true,'
            '"ha_connection_healthy":false,"last_request_forwarding_heartbeat_ms":815,'
            '"server_time_utc":1795595086,"version":"1.19.0",'
            '"cluster_name":"vault-cluster-ha"}',
            "1.19.0",
        ),
        # Node removed from the HA cluster (HTTP 530).
        (
            '{"initialized":true,"sealed":false,"standby":true,'
            '"removed_from_cluster":true,"server_time_utc":1795595086,'
            '"version":"1.19.0"}',
            "1.19.0",
        ),
        # Key order is not guaranteed: version ahead of the signature keys.
        ('{"version":"1.17.0","initialized":true,"sealed":false,"standby":false}', "1.17.0"),
        # Pretty-printed JSON (whitespace between tokens).
        ('{\n  "initialized": true,\n  "sealed": false,\n  "version": "1.13.3"\n}', "1.13.3"),
        # Vault Enterprise build string.
        (
            '{"initialized":true,"sealed":false,"version":"1.15.2+ent","cluster_name":"c"}',
            "1.15.2+ent",
        ),
        # A brace inside a string value must be treated as string content, not as
        # an object boundary.
        (
            '{"initialized":true,"sealed":false,"cluster_name":"vault-{prod}",'
            '"version":"1.18.0"}',
            "1.18.0",
        ),
    ],
)
def test_logs_only_the_version_string(content_regex, body, expected):
    assert extract_version(content_regex, body) == expected


# ---------------------------------------------------------------------------
# False positives: other responses must not match
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    "body",
    [
        # Vault signature but no version field.
        '{"initialized":true,"sealed":false}',
        # A version with no Vault signature at all.
        '{"version":"1.2.3"}',
        '{"status":"ok","version":"1.0"}',
        # Only one of the two signature keys is present.
        '{"initialized":true,"version":"1.0"}',
        '{"sealed":false,"version":"1.0"}',
        # Another product's API response that also reports a version.
        '{"status":"success","data":{"version":"2.45.0","revision":"a"}}',
        # The signature appears only inside a nested object, not at the top level.
        '{"data":{"initialized":true,"sealed":false,"version":"1.0"}}',
        # Signature keys present but not booleans.
        '{"initialized":"yes","sealed":"no","version":"1.0"}',
        # Empty body (connection reset mid-read, etc.).
        "",
        # HTML (WAF block page, auth gateway, non-Vault proxy).
        "<html><body>Vault</body></html>",
        # Vault signature with an empty version string.
        '{"initialized":true,"sealed":false,"version":""}',
    ],
)
def test_no_false_positive_match(content_regex, body):
    assert re.findall(content_regex, body) == []


# ---------------------------------------------------------------------------
# Performance: a crafted response must not slow the scan down
# ---------------------------------------------------------------------------


def test_large_non_matching_body_is_rejected_quickly(content_regex):
    """A large health-shaped object with no version key must fail fast."""
    body = (
        '{"initialized":true,"sealed":false,'
        + ",".join(f'"k{i}":"v{i}"' for i in range(5000))
        + "}"
    )
    start = time.perf_counter()
    result = content_regex.findall(body)
    elapsed = time.perf_counter() - start
    assert result == []
    assert elapsed < 1.0, f"regex took {elapsed:.3f}s"


def test_unterminated_string_is_rejected_quickly(content_regex):
    """An unterminated JSON string must not cause catastrophic backtracking."""
    body = '{"initialized":true,"sealed":false,"x":"' + ("a" * 200000)
    start = time.perf_counter()
    result = content_regex.findall(body)
    elapsed = time.perf_counter() - start
    assert result == []
    assert elapsed < 1.0, f"regex took {elapsed:.3f}s"


def test_many_brace_bearing_strings_rejected_quickly(content_regex):
    """Thousands of string values containing braces must still be rejected in
    near-linear time: braces inside strings are consumed as string content and
    never re-trigger a rescan.
    """
    body = (
        '{"initialized":true,"sealed":false,'
        + ",".join('"k%d":"v{%d}"' % (i, i) for i in range(3000))
        + "}"
    )
    start = time.perf_counter()
    result = content_regex.findall(body)
    elapsed = time.perf_counter() - start
    assert result == []
    assert elapsed < 1.0, f"regex took {elapsed:.3f}s"
