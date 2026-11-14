"""Tests for the wp_xmlrpc_pingback_vuln module.

The fault bodies follow the XML-RPC fault format returned by WordPress 3.5
and 3.5.1 for pingback.ping. The other responses follow what WordPress 3.5 to
7.1 return.
"""

import copy
from pathlib import Path

import pytest
import yaml

from nettacker.core.lib.base import BaseEngine
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


# Sites that accept pingbacks (payloads 1 and 2: http and https).
# Step 0 asks system.listMethods, step 1 reads the feed, step 2 requests the latest post.

LIST_METHODS_BODY = (
    "<methodResponse><params><param><value><array><data>"
    "<value><string>system.multicall</string></value>"
    "<value><string>system.listMethods</string></value>"
    "{pingback}"
    "<value><string>demo.sayHello</string></value>"
    "</data></array></value></param></params></methodResponse>"
)
PINGBACK_METHOD = "<value><string>pingback.ping</string></value>"
FEED_BODY = (
    '<rss version="2.0"><channel><title>Blog</title>'
    "<item><title>Newer post</title>"
    '<guid isPermaLink="false">http://example.com/?p=42</guid></item>'
    "<item><title>Hello world!</title>"
    '<guid isPermaLink="false">http://example.com/?p=1</guid></item>'
    "</channel></rss>"
)
EMPTY_FEED_BODY = '<rss version="2.0"><channel><title>Blog</title></channel></rss>'
PINGBACK_HEADER = {"X-Pingback": "http://example.com/xmlrpc.php"}


@pytest.fixture(scope="module", params=[1, 2], ids=["http", "https"])
def accepted_steps(request):
    with open(MODULE_PATH, encoding="utf-8") as handle:
        return yaml.safe_load(handle)["payloads"][request.param]["steps"]


def filled_url(step, temp_event):
    step = BaseEngine().replace_dependent_values(copy.deepcopy(step), temp_event)
    return step["url"]["nettacker_fuzzer"]["input_format"]


def test_list_methods_step_matches_when_pingback_is_listed(accepted_steps):
    body = LIST_METHODS_BODY.format(pingback=PINGBACK_METHOD)
    assert response_conditions_matched(accepted_steps[0], {"status_code": "200", "content": body})


@pytest.mark.parametrize(
    "status_code, body",
    [
        ("200", LIST_METHODS_BODY.format(pingback="")),  # method removed by a filter
        ("403", "Forbidden"),  # xmlrpc.php blocked by the web server
    ],
)
def test_list_methods_step_ignores_other_responses(accepted_steps, status_code, body):
    response = {"status_code": status_code, "content": body}
    assert not response_conditions_matched(accepted_steps[0], response)


def test_each_step_waits_for_the_previous_one(accepted_steps):
    listed = accepted_steps[0]["response"]["save_to_temp_events_only"]
    latest_post = accepted_steps[1]["response"]["save_to_temp_events_only"]
    assert accepted_steps[1]["response"]["dependent_on_temp_event"] == listed
    assert accepted_steps[2]["response"]["dependent_on_temp_event"] == latest_post


@pytest.mark.parametrize(
    "temp_event, expected",
    [
        ([{"status_code": ["200"], "content": ["pingback.ping"]}], "&listed=pingback.ping"),
        ([{}], "&listed=error"),  # the listMethods step did not match
    ],
)
def test_feed_step_url_carries_the_list_methods_result(accepted_steps, temp_event, expected):
    assert filled_url(accepted_steps[1], temp_event).endswith("/?feed=rss2" + expected)


def test_feed_step_finds_only_the_latest_post_id(accepted_steps):
    # Matches are stored as an unordered set, so the regex must match one post only.
    response = {
        "url": "http://example.com:80/?feed=rss2&listed=pingback.ping",
        "content": FEED_BODY,
    }
    assert response_conditions_matched(accepted_steps[1], response)["content"] == ["42"]


@pytest.mark.parametrize(
    "url, body",
    [
        ("http://example.com:80/?feed=rss2&listed=error", FEED_BODY),  # method not listed
        ("http://example.com:80/?feed=rss2&listed=pingback.ping", EMPTY_FEED_BODY),  # no posts
    ],
)
def test_feed_step_ignores_other_responses(accepted_steps, url, body):
    assert not response_conditions_matched(accepted_steps[1], {"url": url, "content": body})


@pytest.mark.parametrize(
    "temp_event, expected",
    [
        ([{"url": ["listed=pingback.ping"], "content": ["42"]}], "/?p=42"),
        ([{}], "/?p=error"),  # the feed step did not match
    ],
)
def test_post_step_requests_the_latest_post(accepted_steps, temp_event, expected):
    assert filled_url(accepted_steps[2], temp_event).endswith(expected)


def test_post_step_matches_the_pingback_header(accepted_steps):
    response = {"url": "http://example.com:80/?p=42", "headers": dict(PINGBACK_HEADER)}
    assert response_conditions_matched(accepted_steps[2], response)


@pytest.mark.parametrize(
    "url, headers",
    [
        # pings closed on 4.4 and later: no header on the post
        ("http://example.com:80/?p=42", {"Content-Type": "text/html"}),
        # no post was found: /?p=error loads the home page, which sends the
        # header on a site with a static front page
        ("http://example.com:80/?p=error", dict(PINGBACK_HEADER)),
    ],
)
def test_post_step_ignores_other_responses(accepted_steps, url, headers):
    assert not response_conditions_matched(accepted_steps[2], {"url": url, "headers": headers})
