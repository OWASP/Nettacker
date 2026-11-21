"""Read-only Kestra bypass checks, including pre-edition configuration responses."""

from pathlib import Path

import pytest
import yaml

from nettacker.core.lib.http import response_conditions_matched

MODULE_PATH = (
    Path(__file__).resolve().parents[2]
    / "nettacker"
    / "modules"
    / "vuln"
    / "kestra_cve_2026_49869.yaml"
)

# Minimal excerpts of the field ordering observed in real local release binaries.
OLD_CONFIG = (
    '{"version":"0.24.0","commitId":"9859ea5",'
    '"commitDate":"2025-08-05T12:01:23Z","isTaskRunEnabled":false,'
    '"systemNamespace":"system"}'
)
NEW_CONFIG = '{"version":"1.3.20","edition":"OSS","commitId":"945f162"}'


@pytest.fixture(scope="module", params=[0, 1, 2])
def steps(request):
    with MODULE_PATH.open(encoding="utf-8") as handle:
        return yaml.safe_load(handle)["payloads"][request.param]["steps"]


def response(status, content="", url=""):
    return {"status_code": str(status), "content": content, "url": url}


def test_only_read_only_requests_without_redirects(steps):
    assert len(steps) == 3
    assert all(step["method"] == "get" for step in steps)
    assert all(step["allow_redirects"] is False for step in steps)
    assert all("data" not in step and "json" not in step for step in steps)


def test_dependencies_are_isolated_per_payload():
    with MODULE_PATH.open(encoding="utf-8") as handle:
        payloads = yaml.safe_load(handle)["payloads"]
    names = []
    for payload in payloads:
        first, second, third = payload["steps"]
        auth = first["response"]["save_to_temp_events_only"]
        bypass = second["response"]["save_to_temp_events_only"]
        assert second["response"]["dependent_on_temp_event"] == auth
        assert third["response"]["dependent_on_temp_event"] == bypass
        names.extend([auth, bypass])
    assert len(names) == len(set(names))


@pytest.mark.parametrize("status", [200, 301, 302, 403, 404, 500])
def test_control_requires_unauthorized(steps, status):
    assert not response_conditions_matched(steps[0], response(status))
    assert response_conditions_matched(steps[0], response(401))


@pytest.mark.parametrize("status", [200, 404])
def test_bypass_accepts_existing_or_missing_resource(steps, status):
    # An existing workflow can return 200; a missing workflow returns 404.
    assert response_conditions_matched(steps[1], response(status, url="/configs?s=401"))


@pytest.mark.parametrize("status", [301, 302, 400, 401, 403, 500])
def test_patched_or_unexpected_bypass_response_is_rejected(steps, status):
    assert not response_conditions_matched(steps[1], response(status, url="/configs?s=401"))


@pytest.mark.parametrize("url", ["/configs", "/configs?s=200", "/configs?s=404"])
def test_bypass_requires_successful_control_dependency(steps, url):
    assert not response_conditions_matched(steps[1], response(404, url=url))


@pytest.mark.parametrize("body", [OLD_CONFIG, NEW_CONFIG])
@pytest.mark.parametrize("status", [200, 404])
def test_old_and_new_config_fingerprints_after_bypass(steps, body, status):
    assert response_conditions_matched(
        steps[2], response(200, body, url=f"/api/v1/configs?s={status}")
    )


@pytest.mark.parametrize(
    "body",
    [
        "",
        "<html>login</html>",
        '{"message":"Not Found","logref":null,"path":null}',
        '{"version":"0.24.0","commitId":"abc"}',
        '{"version":"0.24.0","commitId":"abc","commitDate":"2025-01-01"}',
        '{"status":"ok"}',
    ],
)
def test_generic_gateway_responses_do_not_fingerprint_as_kestra(steps, body):
    assert not response_conditions_matched(
        steps[2], response(200, body, url="/api/v1/configs?s=404")
    )


@pytest.mark.parametrize("status", [301, 302, 401, 403, 404, 500])
def test_fingerprint_requires_http_200(steps, status):
    assert not response_conditions_matched(
        steps[2], response(status, OLD_CONFIG, url="/api/v1/configs?s=404")
    )


@pytest.mark.parametrize("url", ["/api/v1/configs", "/api/v1/configs?s=401"])
def test_fingerprint_requires_successful_bypass_dependency(steps, url):
    assert not response_conditions_matched(steps[2], response(200, OLD_CONFIG, url=url))
