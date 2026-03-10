import json
from unittest.mock import mock_open, patch

import pytest

from nettacker.lib.graph.d3_tree_v1.engine import escape_for_html_js, start


class TestEscapeForHtmlJs:
    def test_escapes_angle_brackets(self):
        assert escape_for_html_js("<script>") == "\\u003Cscript\\u003E"

    def test_escapes_ampersand(self):
        assert escape_for_html_js("a&b") == "a\\u0026b"

    def test_no_escaping_needed(self):
        assert escape_for_html_js("plain text") == "plain text"

    def test_empty_string(self):
        assert escape_for_html_js("") == ""


TEMPLATE = (
    "__data_will_locate_here__"
    "__title_to_replace__"
    "__description_to_replace__"
    "__html_title_to_replace__"
)


class TestStart:
    @patch("nettacker.lib.graph.d3_tree_v1.engine.messages", side_effect=lambda k: k)
    @patch(
        "nettacker.lib.graph.d3_tree_v1.engine.open",
        mock_open(read_data=TEMPLATE),
    )
    def test_returns_html_with_replacements(self, mock_messages):
        events = [{"target": "10.0.0.1", "module_name": "ssh_brute", "port": 22, "event": "ok"}]
        result = start(events)
        assert "10.0.0.1" in result
        assert "ssh_brute" in result
        assert "__data_will_locate_here__" not in result

    @patch("nettacker.lib.graph.d3_tree_v1.engine.messages", side_effect=lambda k: k)
    @patch(
        "nettacker.lib.graph.d3_tree_v1.engine.open",
        mock_open(read_data=TEMPLATE),
    )
    def test_empty_events(self, mock_messages):
        result = start([])
        d3_expected = {"name": "Starting attack", "children": []}
        assert escape_for_html_js(json.dumps(d3_expected)) in result

    @patch("nettacker.lib.graph.d3_tree_v1.engine.messages", side_effect=lambda k: k)
    def test_file_handle_closed(self, mock_messages):
        m = mock_open(read_data=TEMPLATE)
        with patch("nettacker.lib.graph.d3_tree_v1.engine.open", m):
            start([])
        handle = m()
        handle.__enter__.assert_called()
        handle.__exit__.assert_called()

    @patch("nettacker.lib.graph.d3_tree_v1.engine.messages", side_effect=lambda k: k)
    @patch(
        "nettacker.lib.graph.d3_tree_v1.engine.open",
        side_effect=FileNotFoundError("no template"),
    )
    def test_missing_template_raises(self, mock_open_fn, mock_messages):
        with pytest.raises(FileNotFoundError):
            start([])
