"""Behavioural tests for the gitea_version_scan module.

The module is loaded through ``TemplateLoader``, the same path the engine uses, so
the regexes are tested after ``str.format`` has turned the ``{{``/``}}`` escapes
into literal braces. Each regex is then applied with ``re.findall``, as
``http.response_conditions_matched`` does, so a single capture group logs just the
version string.

The response bodies come from official Gitea container images (1.21.11 and
28.4.0) and from a Forgejo instance (Codeberg).
"""

import re

import pytest

from nettacker.core.template import TemplateLoader

API_STEP = 0
FOOTER_STEP = 1


@pytest.fixture(scope="module")
def module():
    return TemplateLoader(
        "gitea_version_scan", {"target": "127.0.0.1", "user_agent": "Nettacker"}
    ).load()


@pytest.fixture(scope="module")
def steps(module):
    return module["payloads"][0]["steps"]


def content_regex(steps, index):
    return re.compile(steps[index]["response"]["conditions"]["content"]["regex"])


def extract_version(regex, body):
    return " ".join(sorted(set(re.findall(regex, body))))


# ---------------------------------------------------------------------------
# Module metadata / structure
# ---------------------------------------------------------------------------


def test_module_metadata(module):
    info = module["info"]
    assert info["name"] == "gitea_version_scan"
    assert "gitea" in info["profiles"]
    assert "scan" in info["profiles"]


@pytest.mark.parametrize("index, path", [(API_STEP, "/api/v1/version"), (FOOTER_STEP, "/")])
def test_steps_target_expected_paths_and_ports(steps, index, path):
    fuzzer = steps[index]["url"]["nettacker_fuzzer"]
    assert fuzzer["input_format"].endswith(path)
    assert fuzzer["data"]["schema"] == ["http", "https"]
    # Gitea's default HTTP_PORT (3000) plus the common web ports.
    assert set(fuzzer["data"]["ports"]) == {80, 443, 3000}


@pytest.mark.parametrize("index", [API_STEP, FOOTER_STEP])
def test_steps_require_http_200_and_log_content(steps, index):
    response = steps[index]["response"]
    assert response["condition_type"] == "and"
    assert response["conditions"]["status_code"]["regex"] == "200"
    assert response["log"] == "response_dependent['content']"


# ---------------------------------------------------------------------------
# /api/v1/version step
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    "body, expected",
    [
        # gitea/gitea:latest (28.4.0)
        ('{"version":"28.4.0"}', "28.4.0"),
        # gitea/gitea:1.21 appends a trailing newline
        ('{"version":"1.21.11"}\n', "1.21.11"),
        # gitea.com development build
        ('{"version":"29.0.0+dev-160-g55186ca39b"}', "29.0.0+dev-160-g55186ca39b"),
        # pretty-printed JSON
        ('{\n  "version": "1.22.0"\n}', "1.22.0"),
    ],
)
def test_api_logs_only_the_version(steps, body, expected):
    assert extract_version(content_regex(steps, API_STEP), body) == expected


@pytest.mark.parametrize(
    "body",
    [
        # Forgejo (Codeberg) reports its own version with a +gitea- suffix
        '{"version":"17.0.0-100-2254cb0+gitea-1.22.0"}',
        # REQUIRE_SIGNIN_VIEW = true: the API returns 403 with this body
        '{"message":"Only signed in user is allowed to call APIs."}',
        # other applications with a version field but a different shape
        '{"version":"1.0.0","name":"other"}',
        '{"status":"ok"}',
        '{"version":""}',
        "",
    ],
)
def test_api_no_false_positive(steps, body):
    assert re.findall(content_regex(steps, API_STEP), body) == []


# ---------------------------------------------------------------------------
# Page footer step
# ---------------------------------------------------------------------------

FOOTER_28 = (
    '<div class="left-links" role="contentinfo" aria-label="About Software">\n\t\t\n'
    '\t\t\t<a target="_blank" href="https://about.gitea.com">Powered by Gitea</a>\n'
    "\t\t\n\t\t\n\t\t\t<span>\n\t\t\tVersion:\n\t\t\t\n\t\t\t\t28.4.0\n\t\t\t\n\t\t\t</span>\n"
    "\t\t\n\t\t\n\t\t\t<span>\n\t\t\t\tPage: <strong>21ms</strong>\n"
    "\t\t\t\tTemplate: <strong>21ms</strong>\n\t\t\t</span>\n\t\t\n\t\t\n\t</div>"
)
# 1.21.11: extra rel attribute on the link and no <span> around the version
FOOTER_121 = (
    '<div class="left-links" role="contentinfo" aria-label="About Software">\n'
    '\t\t<a target="_blank" rel="noopener noreferrer" href="https://about.gitea.com">'
    "Powered by Gitea</a>\n\t\t\n\t\t\tVersion:\n\t\t\t\n\t\t\t\t1.21.11\n\t\t\t\n\t\t\n\t\t\n"
    "\t\t\tPage: <strong>5ms</strong>\n\t\t\tTemplate: <strong>5ms</strong>\n\t\t\n\t</div>"
)
# SHOW_FOOTER_VERSION = false: the link stays, the version is removed
FOOTER_HIDDEN = (
    '<div class="left-links" role="contentinfo" aria-label="About Software">\n\t\t\n'
    '\t\t\t<a target="_blank" href="https://about.gitea.com">Powered by Gitea</a>\n'
    "\t\t\n\t\t\n\t\t\n\t\t\t<span>\n\t\t\t\tPage: <strong>23ms</strong>\n"
    "\t\t\t\tTemplate: <strong>22ms</strong>\n\t\t\t</span>\n\t\t\n\t\t\n\t</div>"
)


@pytest.mark.parametrize("body, expected", [(FOOTER_28, "28.4.0"), (FOOTER_121, "1.21.11")])
def test_footer_logs_only_the_version(steps, body, expected):
    assert extract_version(content_regex(steps, FOOTER_STEP), body) == expected


@pytest.mark.parametrize(
    "body",
    [
        FOOTER_HIDDEN,
        # a Version label without the Gitea link
        "<footer>Version: 2.4.1</footer>",
        '<footer><a href="https://example.org">Other app</a> Version: 2.4.1</footer>',
        # an about.gitea.com link outside Gitea's footer container
        '<main><a href="https://about.gitea.com">Gitea</a>Dependency Version: 2.4.1</main>',
        '<p>Built with <a href="https://about.gitea.com">Gitea</a></p>'
        "<footer><div>Version: 9.9.9</div></footer>",
        # the link inside left-links, but the version in a later element
        '<div class="left-links"><a href="https://about.gitea.com">Powered by Gitea</a></div>'
        "<div>Version: 9.9.9</div>",
        "",
    ],
)
def test_footer_no_false_positive(steps, body):
    assert re.findall(content_regex(steps, FOOTER_STEP), body) == []
