"""Tests for the wp_xmlrpc_pingback_vuln module.

The response bodies follow the XML-RPC fault format returned by WordPress 3.5
and 3.5.1 for pingback.ping.
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
    / "wp_xmlrpc_pingback.yaml"
)


@pytest.fixture(scope="module")
def step():
    with open(MODULE_PATH, encoding="utf-8") as handle:
        return yaml.safe_load(handle)["payloads"][0]["steps"][0]


def fault(code, message=""):
    return f"""<?xml version="1.0" encoding="UTF-8"?>
<methodResponse>
  <fault>
    <value>
      <struct>
        <member>
          <name>faultCode</name>
          <value><int>{code}</int></value>
        </member>
        <member>
          <name>faultString</name>
          <value><string>{message}</string></value>
        </member>
      </struct>
    </value>
  </fault>
</methodResponse>
"""


def test_pingback_targets_a_post(step):
    # A bare host is rejected with fault 0 before the source URL is fetched.
    assert "<string>http://{target}/?p=1</string>" in step["data"]


def test_matches_source_url_error_from_3_5(step):
    body = fault(16, "The source URL does not exist.")
    assert response_conditions_matched(step, {"content": body})


@pytest.mark.parametrize(
    "body",
    [
        fault(0),  # 3.5.1+ masks every pingback error except 48
        fault(0, "Is there no link to us?"),
        fault(
            17,
            "The source URL does not contain a link to the target URL, "
            "and so cannot be used as a source.",
        ),
        fault(32, "We cannot find a title on that page."),
        fault(
            33,
            "The specified target URL cannot be used as a target. It either "
            "doesn&#8217;t exist, or it is not a pingback-enabled resource.",
        ),
    ],
)
def test_ignores_other_responses(step, body):
    assert not response_conditions_matched(step, {"content": body})
