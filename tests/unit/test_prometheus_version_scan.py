"""Behavioural tests for the prometheus_version_scan module.

These load the shipped module definition and exercise its version-detection
regex the way the HTTP engine does (``re.findall`` on the response body, then
joined into the log line). Fixtures use the real shape of Prometheus'
``/api/v1/status/buildinfo`` response (documented at
https://prometheus.io/docs/prometheus/latest/querying/api/#build-information),
and the false-positive cases cover other Prometheus API responses that also
report ``"status":"success"`` but are not build information.
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
    / "scan"
    / "prometheus_version.yaml"
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
    # Load through the engine so the regex is the one actually used at runtime
    # (TemplateLoader runs str.format() over the YAML, collapsing the doubled
    # braces back to single ones).
    content = TemplateLoader(
        "prometheus_version_scan",
        {"target": "t", "user_agent": "UA", "schema": None, "ports": None, "timeout": 3.0},
    ).load()
    return re.compile(
        content["payloads"][0]["steps"][0]["response"]["conditions"]["content"]["regex"]
    )


def test_module_loads_through_template_engine():
    """TemplateLoader.load() runs str.format() over the raw YAML before parsing,
    so every literal brace in the regex (the quantifiers, the ``\\{`` anchor) must
    be doubled. Loading through the real engine guards against a KeyError that
    plain yaml.safe_load would not surface.
    """
    content = TemplateLoader(
        "prometheus_version_scan",
        {"target": "t", "user_agent": "UA", "schema": None, "ports": None, "timeout": 3.0},
    ).load()
    regex = content["payloads"][0]["steps"][0]["response"]["conditions"]["content"]["regex"]
    body = '{"status":"success","data":{"version":"3.0.0","revision":"abc"}}'
    assert re.compile(regex).findall(body) == ["3.0.0"]


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
    assert info["name"] == "prometheus_version_scan"
    assert info["severity"] == 3
    assert "prometheus" in info["profiles"]
    assert "scan" in info["profiles"]
    assert "http" in info["profiles"]
    assert "info_severity" in info["profiles"]


def test_targets_buildinfo_endpoint_on_expected_ports(step):
    fuzzer = step["url"]["nettacker_fuzzer"]
    assert fuzzer["input_format"].endswith("/api/v1/status/buildinfo")
    data = fuzzer["data"]
    assert data["schema"] == ["http", "https"]
    # Prometheus default port (9090) plus the common web ports for proxied setups.
    assert set(data["ports"]) == {80, 443, 9090}


def test_requires_http_200(step):
    conditions = step["response"]["conditions"]
    assert conditions["status_code"]["regex"] == "200"
    assert step["response"]["condition_type"] == "and"
    assert step["response"]["log"] == "response_dependent['content']"


def test_content_regex_has_single_capture_group(content_regex):
    """The engine joins findall() results with ' '.join(...), which raises
    TypeError on tuples. Guard against regressing to multiple capture groups.
    """
    assert content_regex.groups == 1


# ---------------------------------------------------------------------------
# Detection: the version is captured for real buildinfo responses
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    "body, expected",
    [
        # Verbatim example from the Prometheus HTTP API docs (version 2.13.1).
        (
            '{"status":"success","data":{"version":"2.13.1","revision":"cb7cbad5",'
            '"branch":"master","buildUser":"julius@desktop","buildDate":"20191102-16:19:59",'
            '"goVersion":"go1.13.1"}}',
            "2.13.1",
        ),
        # Modern 2.x build, keys in the usual order.
        (
            '{"status":"success","data":{"version":"2.45.0","revision":"abc","branch":"HEAD",'
            '"buildUser":"root@host","buildDate":"20230623","goVersion":"go1.20.5"}}',
            "2.45.0",
        ),
        # Prometheus 3.x, shorter payload.
        (
            '{"status":"success","data":{"version":"3.1.0","revision":"def","goVersion":"go1.23"}}',
            "3.1.0",
        ),
        # Key order reversed: Prometheus does not guarantee JSON key order, so
        # revision-first must match too.
        (
            '{"status":"success","data":{"revision":"def","version":"3.0.0","goVersion":"go1.23"}}',
            "3.0.0",
        ),
        # Pretty-printed JSON (whitespace between tokens).
        (
            '{\n  "status": "success",\n  "data": {\n'
            '    "version": "2.50.1",\n    "revision": "r1"\n  }\n}',
            "2.50.1",
        ),
        # Release-candidate tag in the version string.
        (
            '{"status":"success","data":{"version":"2.52.0-rc.1","revision":"x"}}',
            "2.52.0-rc.1",
        ),
        # Older long-form 2.x with a full build metadata set.
        (
            '{"status":"success","data":{"version":"2.37.9","revision":"f2a1b2","branch":"release-2.37",'
            '"buildUser":"root@build","buildDate":"20230801-10:00:00","goVersion":"go1.19.12"}}',
            "2.37.9",
        ),
        # A brace *inside* a JSON string value (e.g. a branch name) must be treated
        # as string content, not an object boundary -- both required keys are still
        # in the same data object, so the version is captured.
        (
            '{"status":"success","data":{"branch":"release/{next}","revision":"abc","version":"3.1.0"}}',
            "3.1.0",
        ),
        # Escaped quotes inside a string value before the version must not break it.
        (
            '{"status":"success","data":{"buildUser":"he said \\"hi\\"","revision":"r","version":"2.9.9"}}',
            "2.9.9",
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
        # Another Prometheus API success response (a query result, not buildinfo).
        '{"status":"success","data":{"resultType":"vector","result":[]}}',
        # Query result whose metric labels happen to include a "version" key.
        # buildinfo is identified by the "revision" sibling, which is absent here.
        '{"status":"success","data":{"resultType":"vector",'
        '"result":[{"metric":{"__name__":"up","version":"1.0"}}]}}',
        # Success response whose data is an array.
        '{"status":"success","data":[]}',
        # Success response with an empty data object.
        '{"status":"success","data":{}}',
        # Prometheus runtime info endpoint (same /api/v1 base, no version at all).
        '{"status":"success","data":{"startTime":"2024-05-01T12:00:00Z","CWD":"/prometheus"}}',
        # Prometheus error response.
        '{"status":"error","errorType":"bad_data","error":"invalid parameter"}',
        # A different product's health endpoint that also exposes a version.
        '{"database":"ok","version":"11.1.0"}',
        # Generic health endpoints.
        '{"status":"ok"}',
        # Empty body (connection reset mid-read, etc.).
        "",
        # HTML (WAF block page, auth gateway, non-Prometheus proxy).
        "<html><head><title>Prometheus</title></head><body>Unauthorized</body></html>",
        # buildinfo signature with an empty version string.
        '{"status":"success","data":{"version":"","revision":"x"}}',
        # A sibling object (not data) carries both keys: the search must not
        # cross data's closing brace into a following "metadata" object.
        '{"status":"success","data":{},"metadata":{"revision":"abc","version":"1.0"}}',
        # Query result whose nested metric labels include BOTH "revision" and
        # "version": the search must stop at the nested object's opening brace
        # and not treat metric labels as the build-info signature.
        '{"status":"success","data":{"result":[{"metric":{"revision":"x","version":"1.0"}}]}}',
        # data object followed by sibling revision/version at the top level.
        '{"status":"success","data":{"foo":"bar"},"revision":"x","version":"9.9"}',
        # A data object whose only brace-in-string field has no revision, with the
        # real revision/version in a *sibling* object, must still be rejected.
        '{"status":"success","data":{"branch":"release/{next}"},"other":{"revision":"a","version":"1.1"}}',
    ],
)
def test_no_false_positive_match(content_regex, body):
    assert re.findall(content_regex, body) == []


# ---------------------------------------------------------------------------
# Performance: a crafted response must not slow the scan down
# ---------------------------------------------------------------------------


def test_hostile_body_is_matched_quickly(content_regex):
    """A long non-matching prefix followed by a real buildinfo payload must not
    cause catastrophic backtracking: the regex uses bounded ``[^{}]{0,N}?``
    with lazy quantifiers.
    """
    body = ('{"a":"1",' * 5000) + ('"status":"success","data":{"version":"9.9.9","revision":"x"}}')
    start = time.perf_counter()
    result = content_regex.findall(body)
    elapsed = time.perf_counter() - start
    assert result == ["9.9.9"]
    assert elapsed < 1.0, f"regex took {elapsed:.3f}s"


def test_long_non_matching_body_is_rejected_quickly(content_regex):
    """A large success body whose data has neither "revision" nor "version"
    keys must fail fast.
    """
    body = '{"status":"success","data":{' + ",".join(f'"k{i}":"v{i}"' for i in range(2000)) + "}}"
    start = time.perf_counter()
    result = content_regex.findall(body)
    elapsed = time.perf_counter() - start
    assert result == []
    assert elapsed < 1.0, f"regex took {elapsed:.3f}s"


def test_many_repeated_near_match_objects_rejected_quickly(content_regex):
    """A hostile body packed with thousands of partial buildinfo signatures
    (``"status":"success"`` wrapping an empty ``data`` object, no ``revision``
    or ``version``) must be rejected in ~linear time.

    The content condition is matched synchronously after the HTTP response is
    read and is not bounded by the step ``timeout``, so an unbounded wildcard
    that rescanned each following object would let a modest response stall scan
    workers. The ``[^{}]`` wildcards keep every search inside the current JSON
    object, so each candidate fails its lookahead immediately instead of
    scanning ahead across the rest of the body. With the previous ``[\\s\\S]``
    wildcards this body took several seconds; it now completes in milliseconds.
    """
    body = "[" + ",".join('{"status":"success","data":{}}' for _ in range(10000)) + "]"
    assert len(body) > 300_000
    start = time.perf_counter()
    result = content_regex.findall(body)
    elapsed = time.perf_counter() - start
    assert result == []
    assert elapsed < 1.0, f"regex took {elapsed:.3f}s"
