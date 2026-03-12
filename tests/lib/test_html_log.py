from unittest.mock import mock_open, patch

import pytest

from nettacker.lib.html_log.log_data import _read_file


class TestReadFile:
    """Tests for the _read_file helper used by html_log/log_data.py."""

    def test_reads_file_contents(self, tmp_path):
        """Verify _read_file returns the full contents of a text file."""
        p = tmp_path / "sample.txt"
        p.write_text("hello world")
        assert _read_file(p) == "hello world"

    def test_file_handle_closed_after_read(self, tmp_path):
        """Verify the file handle is properly closed after reading."""
        p = tmp_path / "sample.txt"
        m = mock_open(read_data="data")
        with patch("nettacker.lib.html_log.log_data.open", m):
            _read_file(p)
        handle = m()
        handle.__enter__.assert_called()
        handle.__exit__.assert_called()

    def test_empty_file(self, tmp_path):
        """Verify _read_file returns an empty string for an empty file."""
        p = tmp_path / "empty.txt"
        p.write_text("")
        assert _read_file(p) == ""

    def test_nonexistent_file_raises(self, tmp_path):
        """Verify _read_file raises FileNotFoundError for a missing file."""
        p = tmp_path / "no_such_file.txt"
        with pytest.raises(FileNotFoundError):
            _read_file(p)

    def test_multiline_content(self, tmp_path):
        """Verify _read_file preserves multiline content including newlines."""
        content = "line1\nline2\nline3\n"
        p = tmp_path / "multi.txt"
        p.write_text(content)
        assert _read_file(p) == content
