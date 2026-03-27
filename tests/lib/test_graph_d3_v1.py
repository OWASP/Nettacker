from nettacker.lib.graph.d3_tree_v1 import engine as d3_v1


def test_escape_for_html_js():
    escaped = d3_v1.escape_for_html_js("<tag>&entity</tag>")
    assert "\\u003C" in escaped
    assert "\\u003E" in escaped
    assert "\\u0026" in escaped


def test_d3_tree_v1_start_empty():
    result = d3_v1.start([])
    assert "Starting attack" in result
    assert isinstance(result, str)


def test_d3_tree_v1_start_with_events():
    events = [
        {
            "target": "127.0.0.1",
            "module_name": "port_scan",
            "port": 80,
            "event": "port_open",
        }
    ]
    result = d3_v1.start(events)
    assert "127.0.0.1" in result
    assert "port_scan" in result
    assert isinstance(result, str)
