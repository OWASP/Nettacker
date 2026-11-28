"""Tests for vuln modules whose content check needs two strings in the body.

These modules used to join the two strings with ``&``
(e.g. ``foo&bar``), which ``re`` treats as a literal ampersand, so the
condition could never match a real response. Each test loads the shipped
module definition and runs it through the HTTP engine's
``response_conditions_matched`` with a response shaped like the one a
vulnerable (or non-vulnerable) target sends back.
"""

from pathlib import Path

import pytest
import yaml

from nettacker.core.lib.http import response_conditions_matched

VULN_MODULES = Path(__file__).resolve().parents[2] / "nettacker" / "modules" / "vuln"


def load_step(file_name):
    with open(VULN_MODULES / file_name, encoding="utf-8") as handle:
        return yaml.safe_load(handle)["payloads"][0]["steps"][0]


def response(content, status_code="200", content_type="text/html; charset=UTF-8"):
    return {
        "reason": "OK",
        "url": "http://127.0.0.1/",
        "status_code": status_code,
        "content": content,
        "headers": {"Content-Type": content_type},
        "responsetime": 0.1,
    }


# ---------------------------------------------------------------------------
# puneethreddyhc_sqli_cve_2021_41648 / 41649
# ---------------------------------------------------------------------------

XDEBUG_MYSQLI_WARNING = (
    "<br />\n<font size='1'><table class='xdebug-error xe-warning' dir='ltr' border='1' "
    "cellspacing='0' cellpadding='1'>\n"
    "<tr><th align='left' bgcolor='#f57900' colspan=\"5\"><span style='background-color: "
    "#cc0000; color: #fce94f; font-size: x-large;'>( ! )</span> Warning: mysqli_num_rows() "
    "expects parameter 1 to be mysqli_result, boolean given in /var/www/html/action.php on "
    "line <i>21</i></th></tr>\n</table></font>\n"
)


@pytest.mark.parametrize(
    "file_name",
    ["puneethreddyhc_sqli_cve_2021_41648.yaml", "puneethreddyhc_sqli_cve_2021_41649.yaml"],
)
class TestPuneethreddyhcSqli:
    def test_sends_a_form_encoded_body(self, file_name):
        # PHP only fills $_POST for form-encoded bodies. Without this header
        # aiohttp sends the string body as text/plain and the injected
        # parameter never reaches the vulnerable query.
        step = load_step(file_name)
        assert step["headers"]["Content-Type"] == "application/x-www-form-urlencoded"

    def test_matches_xdebug_mysqli_warning(self, file_name):
        assert response_conditions_matched(load_step(file_name), response(XDEBUG_MYSQLI_WARNING))

    @pytest.mark.parametrize(
        "body",
        [
            # Same warning without Xdebug: plain PHP output.
            "<br />\n<b>Warning</b>:  mysqli_num_rows() expects parameter 1 to be "
            "mysqli_result, boolean given in <b>/var/www/html/action.php</b>",
            # Xdebug enabled but a different warning.
            "<table class='xdebug-error xe-warning'>Warning: Undefined variable $x</table>",
            "<html><body>Product added to cart</body></html>",
        ],
    )
    def test_ignores_other_pages(self, file_name, body):
        assert not response_conditions_matched(load_step(file_name), response(body))


# ---------------------------------------------------------------------------
# payara_cve_2021_41381
# ---------------------------------------------------------------------------


def test_payara_matches_leaked_microprofile_config():
    body = (
        "payara.security.openid.default.providerURI=\n"
        "payara.security.openid.clientId=client\n"
        "payara.security.openid.sessionScopedConfiguration=true\n"
    )
    assert response_conditions_matched(
        load_step("payara_cve_2021_41381.yaml"), response(body, content_type="text/plain")
    )


@pytest.mark.parametrize(
    "body",
    [
        "payara.security.openid.default.providerURI=\n",
        "payara.security.openid.sessionScopedConfiguration=true\n",
        "<html><body>404 Not Found</body></html>",
    ],
)
def test_payara_ignores_partial_or_unrelated_bodies(body):
    assert not response_conditions_matched(load_step("payara_cve_2021_41381.yaml"), response(body))


# ---------------------------------------------------------------------------
# tieline_cve_2021_35336
# ---------------------------------------------------------------------------


def test_tieline_matches_device_details():
    body = (
        '<?xml version="1.0" encoding="UTF-8"?>\n<DEVICE>\n'
        "  <SERIAL>A1B2C3D4</SERIAL>\n  <VERSION>2.18.2</VERSION>\n</DEVICE>\n"
    )
    assert response_conditions_matched(
        load_step("tieline_cve_2021_35336.yaml"), response(body, content_type="text/xml")
    )


def test_tieline_ignores_xml_without_both_fields():
    body = '<?xml version="1.0"?><error><VERSION>1</VERSION></error>'
    assert not response_conditions_matched(
        load_step("tieline_cve_2021_35336.yaml"), response(body, content_type="text/xml")
    )


# ---------------------------------------------------------------------------
# wp_xmlrpc_dos_vuln
# ---------------------------------------------------------------------------


def list_methods(*methods):
    values = "\n".join(f"  <value><string>{method}</string></value>" for method in methods)
    return (
        '<?xml version="1.0" encoding="UTF-8"?>\n<methodResponse>\n  <params>\n    <param>\n'
        f"      <value>\n      <array><data>\n{values}\n</data></array>\n      </value>\n"
        "    </param>\n  </params>\n</methodResponse>\n"
    )


def test_xmlrpc_dos_matches_when_multicall_is_exposed():
    body = list_methods(
        "system.multicall",
        "system.listMethods",
        "system.getCapabilities",
        "demo.addTwoNumbers",
        "demo.sayHello",
        "pingback.ping",
    )
    assert response_conditions_matched(
        load_step("wp_xmlrpc_dos.yaml"), response(body, content_type="text/xml; charset=UTF-8")
    )


@pytest.mark.parametrize(
    "body",
    [
        # system.multicall removed (e.g. through the xmlrpc_methods filter).
        list_methods("system.listMethods", "system.getCapabilities", "demo.sayHello"),
        # Any other page served with HTTP 200 for POST /xmlrpc.php.
        "<html><body>Welcome</body></html>",
        "",
    ],
)
def test_xmlrpc_dos_ignores_200_without_multicall(body):
    assert not response_conditions_matched(load_step("wp_xmlrpc_dos.yaml"), response(body))
