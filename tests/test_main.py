"""Tests for nettacker.main module."""

from io import StringIO
from unittest.mock import MagicMock, patch

from nettacker.environment import check_python_version


@patch("sys.exit")
@patch("sys.stdout", new_callable=StringIO)
def test_check_python_version_unsupported_old(mock_stdout, mock_exit):
    """Test that Python versions older than 3.10 are rejected."""
    with patch("sys.version_info", MagicMock(major=3, minor=9)):
        check_python_version()
        mock_exit.assert_called_once_with(1)
        output = mock_stdout.getvalue()
        assert "3.9" in output or "not supported" in output.lower()


@patch("sys.exit")
@patch("sys.stdout", new_callable=StringIO)
def test_check_python_version_unsupported_new(mock_stdout, mock_exit):
    """Test that Python versions newer than 3.12 are rejected."""
    with patch("sys.version_info", MagicMock(major=3, minor=13)):
        check_python_version()
        mock_exit.assert_called_once_with(1)
        output = mock_stdout.getvalue()
        assert "3.13" in output or "not supported" in output.lower()


@patch("sys.exit")
@patch("sys.stdout", new_callable=StringIO)
def test_check_python_version_unsupported_python2(mock_stdout, mock_exit):
    """Test that Python 2 is rejected."""
    with patch("sys.version_info", MagicMock(major=2, minor=7)):
        check_python_version()
        mock_exit.assert_called_once_with(1)
        output = mock_stdout.getvalue()
        assert "2.7" in output or "not supported" in output.lower()


@patch("sys.exit")
def test_check_python_version_supported_310(mock_exit):
    """Test that Python 3.10 is supported."""
    with patch("sys.version_info", MagicMock(major=3, minor=10)):
        check_python_version()
        mock_exit.assert_not_called()


@patch("sys.exit")
def test_check_python_version_supported_311(mock_exit):
    """Test that Python 3.11 is supported."""
    with patch("sys.version_info", MagicMock(major=3, minor=11)):
        check_python_version()
        mock_exit.assert_not_called()


@patch("sys.exit")
def test_check_python_version_supported_312(mock_exit):
    """Test that Python 3.12 is supported."""
    with patch("sys.version_info", MagicMock(major=3, minor=12)):
        check_python_version()
        mock_exit.assert_not_called()
