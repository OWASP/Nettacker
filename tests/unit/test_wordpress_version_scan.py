"""Tests for the wordpress_version_scan module.

The stylesheet lines follow what /wp-admin/install.php prints on a default
WordPress install.
"""

from pathlib import Path

import pytest
import yaml

from nettacker.core.lib.http import response_conditions_matched

MODULE_PATH = (
    Path(__file__).resolve().parents[2]
    / "nettacker"
    / "modules"
    / "scan"
    / "wordpress_version.yaml"
)


@pytest.fixture(scope="module")
def step():
    with open(MODULE_PATH, encoding="utf-8") as handle:
        return yaml.safe_load(handle)["payloads"][0]["steps"][0]


def install_page(version):
    return (
        "<link rel='stylesheet' id='buttons-css' "
        f"href='http://127.0.0.1/wp-includes/css/buttons.min.css?ver={version}' media='all' />\n"
        "<link rel='stylesheet' id='install-css' "
        f"href='http://127.0.0.1/wp-admin/css/install.min.css?ver={version}' media='all' />\n"
    )


@pytest.mark.parametrize(
    "version",
    [
        # x.y releases, these were missed before
        "3.5",
        "4.0",
        "6.9",
        "7.1",
        # x.y.z releases
        "3.5.1",
        "4.9.35",
        "7.1.4",
        # a two digit major version
        "10.0",
        "10.0.1",
    ],
)
def test_logs_the_version(step, version):
    result = response_conditions_matched(step, {"content": install_page(version)})
    assert result["log"] == version


@pytest.mark.parametrize(
    "body",
    [
        "",
        "<html><body>It works!</body></html>",
        # a stylesheet without a version
        "<link rel='stylesheet' href='/wp-admin/css/install.min.css' />",
        # a version that is not on a stylesheet
        "<script src='/wp-includes/js/jquery/jquery.min.js?ver=3.7.1'></script>",
        # a cache-busting number is not a version
        "<link rel='stylesheet' href='/css/site.css?ver=20240101' />",
    ],
)
def test_no_event_without_a_stylesheet_version(step, body):
    assert response_conditions_matched(step, {"content": body}) == {}
