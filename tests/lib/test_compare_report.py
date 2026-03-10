import json
from unittest.mock import mock_open, patch

import pytest

from nettacker.lib.compare_report.engine import build_report

TEMPLATE = "<html>__data_will_locate_here__</html>"


class TestBuildReport:
    @patch(
        "nettacker.lib.compare_report.engine.open",
        mock_open(read_data=TEMPLATE),
    )
    def test_returns_html_with_data(self):
        result = build_report({"key": "value"})
        assert json.dumps({"key": "value"}) in result
        assert "__data_will_locate_here__" not in result

    @patch(
        "nettacker.lib.compare_report.engine.open",
        mock_open(read_data=TEMPLATE),
    )
    def test_empty_dict(self):
        result = build_report({})
        assert "<html>{}</html>" == result

    def test_file_handle_closed(self):
        m = mock_open(read_data=TEMPLATE)
        with patch("nettacker.lib.compare_report.engine.open", m):
            build_report({})
        handle = m()
        handle.__enter__.assert_called()
        handle.__exit__.assert_called()

    @patch(
        "nettacker.lib.compare_report.engine.open",
        side_effect=FileNotFoundError("no template"),
    )
    def test_missing_template_raises(self, mock_open_fn):
        with pytest.raises(FileNotFoundError):
            build_report({})

    @patch(
        "nettacker.lib.compare_report.engine.open",
        mock_open(read_data=""),
    )
    def test_empty_template_file(self):
        result = build_report({"a": 1})
        assert result == ""
