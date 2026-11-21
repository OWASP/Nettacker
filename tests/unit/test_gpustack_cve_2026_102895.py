"""Tests for the gpustack_cve_2026_102895 module."""

from copy import deepcopy
from pathlib import Path

import pytest
import yaml

from nettacker.core.lib.http import response_conditions_matched

MODULE_PATH = (
    Path(__file__).resolve().parents[2]
    / "nettacker"
    / "modules"
    / "vuln"
    / "gpustack_cve_2026_102895.yaml"
)


@pytest.fixture(scope="module")
def step():
    with open(MODULE_PATH, encoding="utf-8") as handle:
        return yaml.safe_load(handle)["payloads"][0]["steps"][0]


def response(status="200", content='{"is_admin":true}', content_type="application/json"):
    return {
        "status_code": status,
        "content": content,
        "headers": {"content-type": content_type},
    }


def test_admin_json_response_matches(step):
    assert response_conditions_matched(step, deepcopy(response()))


def test_admin_flag_with_other_fields_matches(step):
    reply = response(content='{"id":1,"username":"admin","is_admin":true}')
    assert response_conditions_matched(step, reply)


@pytest.mark.parametrize("status", ["401", "403", "302", "500"])
def test_non_200_status_does_not_match(step, status):
    assert not response_conditions_matched(step, response(status=status))


@pytest.mark.parametrize(
    "content",
    ['{"is_admin":false}', '{"id":1}', "", "not json"],
)
def test_body_without_admin_flag_does_not_match(step, content):
    assert not response_conditions_matched(step, response(content=content))


def test_html_content_type_does_not_match(step):
    assert not response_conditions_matched(step, response(content_type="text/html"))
