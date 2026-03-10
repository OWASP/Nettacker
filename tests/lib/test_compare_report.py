import json
from unittest.mock import mock_open, patch

import pytest

from nettacker.lib.compare_report.engine import build_report

TEMPLATE = "<html>__data_will_locate_here__</html>"


class TestBuildReport:
    """Tests for the build_report() comparison report generator."""

    @patch(
        "nettacker.lib.compare_report.engine.open",
        mock_open(read_data=TEMPLATE),
    )
    def test_returns_html_with_data(self):
        """Verify build_report embeds JSON data and removes the placeholder."""
        result = build_report({"key": "value"})
        assert json.dumps({"key": "value"}) in result
        assert "__data_will_locate_here__" not in result

    @patch(
        "nettacker.lib.compare_report.engine.open",
        mock_open(read_data=TEMPLATE),
    )
    def test_empty_dict(self):
        """Verify build_report handles an empty dict correctly."""
        result = build_report({})
        assert "<html>{}</html>" == result

    def test_file_handle_closed(self):
        """Verify the template file handle is properly closed after use."""
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
        """Verify build_report raises FileNotFoundError when the template is missing."""
        with pytest.raises(FileNotFoundError):
            build_report({})

    @patch(
        "nettacker.lib.compare_report.engine.open",
        mock_open(read_data=""),
    )
    def test_empty_template_file(self):
        """Verify build_report returns an empty string when the template is empty."""
        result = build_report({"a": 1})
        assert result == ""
