"""Tests for the omigod_cve_2021_38647_vuln module.

The module runs ``id`` through the SCX_OperatingSystem ExecuteScript method
without an Authorization header. A vulnerable OMI agent answers with a SOAP
envelope whose ``<p:StdOut>`` holds the command output.
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
    / "omigod_cve_2021_38647.yaml"
)


@pytest.fixture(scope="module")
def step():
    with open(MODULE_PATH, encoding="utf-8") as handle:
        return yaml.safe_load(handle)["payloads"][0]["steps"][0]


def envelope(body):
    return (
        '<SOAP-ENV:Envelope xmlns:SOAP-ENV="http://www.w3.org/2003/05/soap-envelope" '
        'xmlns:wsa="http://schemas.xmlsoap.org/ws/2004/08/addressing">'
        "<SOAP-ENV:Header><wsa:To>http://schemas.xmlsoap.org/ws/2004/08/addressing/role/"
        "anonymous</wsa:To></SOAP-ENV:Header><SOAP-ENV:Body>"
        f"{body}</SOAP-ENV:Body></SOAP-ENV:Envelope>"
    )


def response(content, status_code="200"):
    return {
        "reason": "OK",
        "url": "https://127.0.0.1:5986/wsman",
        "status_code": status_code,
        "content": content,
        "headers": {"Content-Type": "application/soap+xml;charset=UTF-8"},
        "responsetime": 0.1,
    }


def test_probes_omi_listener_ports(step):
    # OMI listens on 5985 (HTTP) and 5986 (HTTPS); 1270 is used when the agent
    # is managed by System Center Operations Manager.
    ports = step["url"]["nettacker_fuzzer"]["data"]["ports"]
    assert {1270, 5985, 5986} <= set(ports)


def test_matches_id_output_from_unauthenticated_execute_script(step):
    body = envelope(
        '<p:SCX_OperatingSystem_OUTPUT xmlns:p="http://schemas.dmtf.org/wbem/wscim/1/'
        'cim-schema/2/SCX_OperatingSystem">\n'
        "<p:ReturnValue>TRUE</p:ReturnValue>\n<p:ReturnCode>0</p:ReturnCode>\n"
        "<p:StdOut>uid=0(root) gid=0(root) groups=0(root)&#10;</p:StdOut>\n"
        "<p:StdErr></p:StdErr>\n</p:SCX_OperatingSystem_OUTPUT>"
    )
    assert response_conditions_matched(step, response(body))


@pytest.mark.parametrize(
    "body",
    [
        # Patched agent: the request without credentials is rejected.
        "",
        # Fault returned by an agent without the SCX provider.
        envelope(
            "<SOAP-ENV:Fault><SOAP-ENV:Code><SOAP-ENV:Value>SOAP-ENV:Sender"
            "</SOAP-ENV:Value></SOAP-ENV:Code><SOAP-ENV:Reason><SOAP-ENV:Text "
            'xml:lang="en-US">CIM_ERR_NOT_FOUND</SOAP-ENV:Text></SOAP-ENV:Reason>'
            "</SOAP-ENV:Fault>"
        ),
        # Script executed, but not as root.
        envelope("<p:StdOut>uid=1000(omi) gid=1000(omi) groups=1000(omi)</p:StdOut>"),
    ],
)
def test_ignores_responses_without_root_id_output(step, body):
    assert not response_conditions_matched(step, response(body))
