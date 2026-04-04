"""Tests for environment validation module."""

import sys
from io import StringIO
from unittest.mock import patch

from nettacker.core.die import die_failure
from nettacker.core.messages import messages as _


def test_supported_python_versions():
    """Test that supported Python versions are recognized as supported."""
    supported_versions = [
        (3, 10),
        (3, 11),
        (3, 12),
    ]

    from nettacker.environment import is_python_version_supported

    for major, minor in supported_versions:
        # Mock sys.version_info for the supported version
        with patch.object(sys, "version_info") as mock_version:
            mock_version.major = major
            mock_version.minor = minor

            # Should return True for supported versions
            assert is_python_version_supported() is True


def test_unsupported_python_versions():
    """Test that unsupported Python versions are recognized as unsupported."""
    unsupported_versions = [
        (3, 9),  # Too old
        (3, 13),  # Too new
        (2, 7),  # Python 2
        (4, 0),  # Future version
    ]

    from nettacker.environment import is_python_version_supported

    for major, minor in unsupported_versions:
        # Mock sys.version_info for the unsupported version
        with patch.object(sys, "version_info") as mock_version:
            mock_version.major = major
            mock_version.minor = minor

            # Should return False for unsupported versions
            assert is_python_version_supported() is False


def test_check_python_version_calls_die_failure_on_unsupported():
    """Test that check_python_version calls die_failure for unsupported versions."""
    from nettacker.environment import check_python_version

    # Mock sys.version_info to an unsupported version
    with patch.object(sys, "version_info") as mock_version:
        mock_version.major = 3
        mock_version.minor = 13

        # Mock die_failure at the import location (where it's used)
        with patch("nettacker.core.die.die_failure") as mock_die:
            check_python_version()

            # Verify die_failure was called
            mock_die.assert_called_once()

            # Verify the error message contains the version info
            call_args = mock_die.call_args[0][0]
            assert "3.13" in call_args


@patch("sys.stdout", new_callable=StringIO)
@patch("sys.exit")
def test_error_message_format(mock_exit, mock_stdout):
    """Test that the error message has the required solutions."""
    test_message = _("error_python_version").format("3.13")
    die_failure(test_message)

    error_output = mock_stdout.getvalue()

    # Verify the error contains the version info
    assert "3.13" in error_output

    # Verify it contains links to solutions
    assert "Docker" in error_output
    assert "pyenv" in error_output

    # Verify exit code is 1 (failure)
    mock_exit.assert_called_once_with(1)
