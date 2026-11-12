"""Behavioural tests for the plex_version_scan module.

These tests load the shipped module definition and exercise its version
detection regex exactly the way the HTTP engine does (``re.findall`` on the
response body, then joined into the log line). Plex Media Server answers its
unauthenticated ``/identity`` endpoint with
``<MediaContainer ... version="X.Y.Z.B-hash">``; the module reports that
version string and nothing else. Like the other ``*_version_scan`` modules this
is a fingerprint only - it makes no claim about whether the build is vulnerable.
"""

import re
from pathlib import Path

import pytest
import yaml

MODULE_PATH = (
    Path(__file__).resolve().parents[2] / "nettacker" / "modules" / "scan" / "plex_version.yaml"
)

MACHINE_ID = "6a646027a56abb6dbdf72484564db8567c737430"
XML_PROLOG = '<?xml version="1.0" encoding="UTF-8"?>\n'


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
    # ArgParser.load_modules derives the module id as "<file stem>_<parent dir>".
    assert info["name"] == f"{MODULE_PATH.stem}_{MODULE_PATH.parent.name}"
    assert info["name"] == "plex_version_scan"
    assert "scan" in info["profiles"]
    assert "plex" in info["profiles"]


def test_targets_identity_endpoint_on_expected_ports(step):
    fuzzer = step["url"]["nettacker_fuzzer"]
    assert fuzzer["input_format"].endswith("/identity")
    data = fuzzer["data"]
    assert data["schema"] == ["http", "https"]
    # Plex's default port (32400) plus the common reverse-proxied web ports.
    assert set(data["ports"]) == {80, 443, 32400}


def test_requires_http_200(step):
    conditions = step["response"]["conditions"]
    assert conditions["status_code"]["regex"] == "200"
    assert step["response"]["condition_type"] == "and"
    assert step["response"]["log"] == "response_dependent['content']"


# ---------------------------------------------------------------------------
# Detection: the version is captured for every observed /identity shape
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    "body, expected",
    [
        # Response captured from plexinc/pms-docker:1.43.5.11079-b3b13e506 during a
        # fresh start. ``apiVersion`` precedes ``version`` and must not be captured.
        (
            XML_PROLOG
            + '<MediaContainer size="0" apiVersion="1.2.3" claimed="0" '
            + f'machineIdentifier="{MACHINE_ID}" startState="startingPlugins" '
            + 'version="1.43.5.11079-b3b13e506">\n</MediaContainer>',
            "1.43.5.11079-b3b13e506",
        ),
        # Claimed server after start-up has completed (no startState attribute).
        (
            XML_PROLOG
            + '<MediaContainer size="0" apiVersion="1.2.3" claimed="1" '
            + f'machineIdentifier="{MACHINE_ID}" version="1.42.2.10156-f737b826c">\n'
            + "</MediaContainer>",
            "1.42.2.10156-f737b826c",
        ),
        # Older builds without apiVersion (shape documented on plexopedia.com).
        (
            XML_PROLOG
            + f'<MediaContainer size="0" claimed="1" machineIdentifier="{MACHINE_ID}" '
            + 'version="1.29.1.6316-f4cdfea9c">\n</MediaContainer>',
            "1.29.1.6316-f4cdfea9c",
        ),
        # Attribute order must not matter.
        (
            '<MediaContainer version="1.40.2.8806-abcdef0" size="0" claimed="1"/>',
            "1.40.2.8806-abcdef0",
        ),
        # Attributes split over several lines.
        (
            '<MediaContainer\n  size="0"\n  version="1.41.0.8992-8463ad060"\n></MediaContainer>',
            "1.41.0.8992-8463ad060",
        ),
    ],
)
def test_logs_only_the_version_string(content_regex, body, expected):
    assert extract_version(content_regex, body) == expected


# ---------------------------------------------------------------------------
# False positives: nothing is captured for unrelated or version-less responses
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    "body",
    [
        # MediaContainer with no version attribute.
        f'<MediaContainer size="0" claimed="1" machineIdentifier="{MACHINE_ID}"></MediaContainer>',
        # Defensive: an empty version value must not match.
        '<MediaContainer size="0" version=""></MediaContainer>',
        # apiVersion alone is not the server version.
        '<MediaContainer size="0" apiVersion="1.2.3"></MediaContainer>',
        # A version attribute on a child element must not be attributed to the server.
        '<MediaContainer size="1"><Video version="2"/></MediaContainer>',
        # A different element whose name merely starts with MediaContainer.
        '<MediaContainerList version="1.2.3"/>',
        # Other products that expose a version field.
        '{"database":"ok","version":"1.29.1"}',
        # Plex's HTML web app / error pages.
        "<html><head><title>Plex</title></head><body>Unauthorized</body></html>",
        # Empty body.
        "",
    ],
)
def test_no_false_positive_match(content_regex, body):
    assert re.findall(content_regex, body) == []
