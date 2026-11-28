"""Behavioural tests for the docker_api_exposed_vuln module.

These tests load the shipped module definition through Nettacker's
``TemplateLoader`` (matching runtime behaviour) and exercise its HTTP transport
mapping, metadata, and detection conditions via ``response_conditions_matched``.
All JSON payloads in this file are synthetic test fixtures modeled after
documented Docker Engine ``/version`` schemas, not captured daemon output.
"""

import json
import re
import time
from pathlib import Path

import pytest
import yaml

from nettacker.core.lib.http import response_conditions_matched
from nettacker.core.template import TemplateLoader
from nettacker.core.utils.common import expand_module_steps

MODULE_PATH = (
    Path(__file__).resolve().parents[2]
    / "nettacker"
    / "modules"
    / "vuln"
    / "docker_api_exposed.yaml"
)


@pytest.fixture(scope="module")
def raw_module():
    with open(MODULE_PATH, "r", encoding="utf-8") as handle:
        return yaml.safe_load(handle)


@pytest.fixture(scope="module")
def loaded_module():
    return TemplateLoader(
        "docker_api_exposed_vuln",
        {"target": "example.com", "user_agent": "Nettacker-Test"},
    ).load()


@pytest.fixture(scope="module")
def steps(loaded_module):
    return [payload["steps"][0] for payload in loaded_module["payloads"]]


def make_response(status_code, content):
    return {
        "status_code": str(status_code),
        "reason": "OK" if str(status_code) == "200" else "Error",
        "content": content,
        "url": "http://example.com:2375/version",
        "headers": {"Content-Type": "application/json"},
        "responsetime": 0.05,
    }


# ---------------------------------------------------------------------------
# Module metadata & transport-to-port mapping
# ---------------------------------------------------------------------------


def test_module_metadata(raw_module):
    info = raw_module["info"]
    assert info["name"] == f"{MODULE_PATH.stem}_{MODULE_PATH.parent.name}"
    assert info["name"] == "docker_api_exposed_vuln"
    assert info["severity"] == 8
    assert set(info["profiles"]) == {
        "vuln",
        "http",
        "high_severity",
        "docker",
        "container",
        "misconfiguration",
    }
    assert "rce" not in info["profiles"]
    assert "CVE-2019-5736" not in info["description"]
    assert all("CVE-2019-5736" not in ref for ref in info["reference"])


def test_transport_to_port_mapping_and_request_safety(loaded_module, steps):
    assert len(loaded_module["payloads"]) == 2
    assert all(payload["library"] == "http" for payload in loaded_module["payloads"])

    observed_pairs = []
    for step in steps:
        assert step["method"] == "get"
        assert isinstance(step["timeout"], (int, float)) and step["timeout"] > 0
        assert step["allow_redirects"] is False
        assert step["ssl"] is False
        assert "cert" not in step
        headers = {k.lower(): v for k, v in step["headers"].items()}
        assert "authorization" not in headers

        fuzzer = step["url"]["nettacker_fuzzer"]
        assert fuzzer["input_format"].endswith("/version")
        data = fuzzer["data"]
        assert len(data["schema"]) == 1
        assert len(data["ports"]) == 1
        observed_pairs.append((data["schema"][0], data["ports"][0]))

    assert observed_pairs == [("http", 2375), ("https", 2376)]

    expanded = expand_module_steps(loaded_module["payloads"])
    expanded_urls = [
        sub_step["url"]
        for payload in expanded
        for step_group in payload["steps"]
        for sub_step in step_group
    ]
    assert expanded_urls == [
        "http://example.com:2375/version",
        "https://example.com:2376/version",
    ]


def test_response_conditions_require_exact_200_and_capture_only_api_version(steps):
    for step in steps:
        response_cfg = step["response"]
        conditions = response_cfg["conditions"]
        assert response_cfg["condition_type"] == "and"
        assert response_cfg["log"] == "response_dependent['content']"
        assert conditions["status_code"]["reverse"] is False
        assert conditions["content"]["reverse"] is False

        status_rx = re.compile(conditions["status_code"]["regex"])
        assert status_rx.findall("200") == ["200"]
        for non_exact in ("2000", "5200", "200 OK", "200\n"):
            assert status_rx.findall(non_exact) == []


# ---------------------------------------------------------------------------
# Positive detections (synthetic fixtures based on Docker /version schemas)
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    "payload, expected_api_version",
    [
        # Synthetic Docker Engine CE modern /version payload (pretty-printed).
        (
            json.dumps(
                {
                    "Platform": {"Name": "Docker Engine - Community"},
                    "Components": [
                        {
                            "Name": "Engine",
                            "Version": "24.0.7",
                            "Details": {
                                "ApiVersion": "1.43",
                                "Arch": "amd64",
                                "GitCommit": "311b9ff",
                                "GoVersion": "go1.20.10",
                                "MinAPIVersion": "1.24",
                                "Os": "linux",
                            },
                        },
                        {
                            "Name": "containerd",
                            "Version": "1.6.24",
                        },
                    ],
                    "Version": "24.0.7",
                    "ApiVersion": "1.43",
                    "MinAPIVersion": "1.24",
                    "GitCommit": "311b9ff",
                    "GoVersion": "go1.20.10",
                    "Os": "linux",
                    "Arch": "amd64",
                },
                indent=2,
            ),
            "1.43",
        ),
        # Synthetic Mirantis / Enterprise-style modern payload (compact JSON).
        (
            json.dumps(
                {
                    "Platform": {"Name": "Mirantis Container Runtime"},
                    "Components": [
                        {"Name": "Engine", "Version": "23.0.10"},
                    ],
                    "Version": "23.0.10",
                    "ApiVersion": "1.42",
                    "MinAPIVersion": "1.12",
                    "Os": "linux",
                    "Arch": "amd64",
                },
                separators=(",", ":"),
            ),
            "1.42",
        ),
        # Synthetic modern payload with reversed key orderings: ApiVersion first,
        # Engine second in Components, Details & Version before Name inside Engine.
        (
            json.dumps(
                {
                    "ApiVersion": "1.45",
                    "Components": [
                        {"Name": "containerd", "Version": "1.7.13"},
                        {
                            "Details": {"Os": "linux", "Arch": "arm64"},
                            "Version": "26.0.0",
                            "Name": "Engine",
                        },
                    ],
                }
            ),
            "1.45",
        ),
        # Synthetic legacy-style Docker Engine response without Components array.
        (
            json.dumps(
                {
                    "Version": "17.03.2-ce",
                    "ApiVersion": "1.27",
                    "MinAPIVersion": "1.12",
                    "GitCommit": "f5ec1e2",
                    "GoVersion": "go1.7.5",
                    "Os": "linux",
                    "Arch": "amd64",
                }
            ),
            "1.27",
        ),
    ],
)
def test_detects_exposed_docker_api_and_logs_only_api_version(
    steps, payload, expected_api_version
):
    for step in steps:
        result = response_conditions_matched(step, make_response(200, payload))
        assert result
        assert result["content"] == [expected_api_version]
        assert result["log"] == expected_api_version


# ---------------------------------------------------------------------------
# Negative detections (false-positive and error rejections)
# ---------------------------------------------------------------------------


SYNTHETIC_VALID_DOCKER_BODY = json.dumps(
    {
        "Components": [{"Name": "Engine", "Version": "24.0.7"}],
        "ApiVersion": "1.43",
    }
)


@pytest.mark.parametrize(
    "status_code, content",
    [
        # Generic web API returning version.
        (200, '{"version":"1.2.3"}'),
        # Generic health-check endpoint.
        (200, '{"status":"ok"}'),
        # ApiVersion alone.
        (200, '{"ApiVersion":"1.43"}'),
        # ApiVersion + MinAPIVersion without remaining legacy markers.
        (200, '{"ApiVersion":"1.43","MinAPIVersion":"1.24"}'),
        # Platform-only or Docker-looking Platform without Engine or full legacy markers.
        (200, '{"Platform":{"Name":"Docker Engine - Community"},"ApiVersion":"1.43"}'),
        (200, '{"Platform":{"Name":"Docker Engine - Community"}}'),
        # Components array with only a non-Engine component.
        (200, '{"Components":[{"Name":"Proxy","Version":"1.0.0"}],"ApiVersion":"1.43"}'),
        # Name: Engine in one object (Platform/Service) and Version at top level or another object.
        (
            200,
            json.dumps(
                {
                    "Platform": {"Name": "Engine"},
                    "Components": [{"Name": "Proxy", "Version": "1.0.0"}],
                    "ApiVersion": "1.43",
                    "Version": "9.9.9",
                }
            ),
        ),
        (
            200,
            json.dumps(
                {
                    "Components": [{"Name": "Engine"}],
                    "ApiVersion": "1.43",
                    "Version": "1.0.0",
                }
            ),
        ),
        (
            200,
            json.dumps(
                {
                    "Components": [
                        {"Name": "Proxy", "Details": {"Name": "Engine", "Version": "1.0.0"}}
                    ],
                    "ApiVersion": "1.43",
                }
            ),
        ),
        # Malformed JSON-like text (missing closing brace), HTML, and empty body.
        (200, '{"Components":[{"Name":"Engine","Version":"24.0.7"}],"ApiVersion":"1.43"'),
        (200, "<html><head><title>Docker</title></head><body>Unauthorized</body></html>"),
        (200, ""),
        # Non-200 status codes (including substring-200 codes) even with a Docker-like body.
        (401, SYNTHETIC_VALID_DOCKER_BODY),
        (403, SYNTHETIC_VALID_DOCKER_BODY),
        (404, SYNTHETIC_VALID_DOCKER_BODY),
        (500, SYNTHETIC_VALID_DOCKER_BODY),
        (2000, SYNTHETIC_VALID_DOCKER_BODY),
        (5200, SYNTHETIC_VALID_DOCKER_BODY),
    ],
)
def test_rejects_non_docker_and_error_responses(steps, status_code, content):
    for step in steps:
        assert response_conditions_matched(step, make_response(status_code, content)) == {}


def test_rejects_missing_or_failed_response(steps):
    for step in steps:
        assert response_conditions_matched(step, {}) == {}
        assert response_conditions_matched(step, None) == {}


def test_large_non_docker_body_avoids_catastrophic_backtracking(steps):
    """Verify anchored matching stays sub-second on large non-matching JSON bodies.

    A 4,000-element Components array (~212 KiB) with nested Details objects and no
    Engine component exercises the prefix-skipping quantifier at scale. Locally it
    completes in ~50 ms; a 2.0 s bound guards against catastrophic backtracking
    without introducing flakiness on slower CI runners.
    """
    content_regex = re.compile(steps[0]["response"]["conditions"]["content"]["regex"])
    component = '{"Name":"Proxy","Version":"1.0","Details":{"x":"y"}}'
    body = '{"Components":[' + ",".join([component] * 4000) + '],"ApiVersion":"1.43"}'
    start = time.perf_counter()
    assert content_regex.findall(body) == []
    assert time.perf_counter() - start < 2.0
