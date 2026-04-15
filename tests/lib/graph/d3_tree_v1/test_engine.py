import json
import re

import pytest

from nettacker.lib.graph.d3_tree_v1 import engine as d3_v1


def _extract_tree_data(result):
    match = re.search(r"treeData\s*=\s*(\{.*?\});", result, flags=re.S)
    assert match is not None
    return json.loads(match.group(1))


def test_escape_for_html_js():
    escaped = d3_v1.escape_for_html_js("<tag>&entity</tag>")
    assert escaped == "\\u003Ctag\\u003E\\u0026entity\\u003C/tag\\u003E"


@pytest.mark.parametrize(
    "raw, expected",
    [
        ("", ""),
        ("plain-text", "plain-text"),
        ('"quoted"', '"quoted"'),
        ("<a>&<b>", "\\u003Ca\\u003E\\u0026\\u003Cb\\u003E"),
        ("مرحبا<ok>", "مرحبا\\u003Cok\\u003E"),
    ],
)
def test_escape_for_html_js_parametrized(raw, expected):
    assert d3_v1.escape_for_html_js(raw) == expected


def test_d3_tree_v1_start_empty():
    result = d3_v1.start([])
    assert isinstance(result, str)
    assert result.strip()


def test_d3_tree_v1_start_with_multiple_events():
    events = [
        {"target": "127.0.0.1", "module_name": "port_scan", "port": 80, "event": "port_open"},
        {"target": "example.com", "module_name": "http_scan", "port": 443, "event": "http_ok"},
    ]
    result = d3_v1.start(events)
    payload = _extract_tree_data(result)

    assert isinstance(payload, dict)
    assert isinstance(payload.get("children"), list)

    names = {child["name"] for child in payload["children"]}
    assert "127.0.0.1" in names
    assert "example.com" in names


def test_d3_tree_v1_start_with_missing_optional_fields():
    result = d3_v1.start([{"target": "only-target"}])
    payload = _extract_tree_data(result)

    assert isinstance(payload, dict)
    assert any(child["name"] == "only-target" for child in payload["children"])


def test_d3_tree_v1_start_escapes_xss_payload():
    events = [{"target": "<script>alert(1)</script>", "module_name": "x", "port": 1, "event": "e"}]
    result = d3_v1.start(events)

    assert "<script>" not in result
    assert "\\u003Cscript\\u003E" in result


def test_d3_tree_v1_start_with_events_validates_event_fields():
    events = [{"target": "127.0.0.1", "module_name": "port_scan", "port": 80, "event": "port_open"}]
    result = d3_v1.start(events)
    payload = _extract_tree_data(result)

    entry = payload["children"][0]
    assert entry["name"] == "127.0.0.1"
    assert entry["children"][0]["name"] == "port_scan"
    description = entry["children"][0]["children"][0]["name"]
    assert "target: 127.0.0.1" in description
    assert "module_name: port_scan" in description
    assert "port: 80" in description
    assert "event: port_open" in description
