from io import StringIO
from unittest.mock import patch

from nettacker.core.die import die_success, die_failure
from nettacker.logger import TerminalCodes
from tests.common import TestCase


class TestDie(TestCase):
    @patch("sys.stdout", new_callable=StringIO)
    @patch("sys.exit")
    def test_die_success(self, mock_exit, mock_stdout):
        reset_code = TerminalCodes.RESET.value
        die_success()
        success_message = mock_stdout.getvalue()
        assert reset_code in success_message
        mock_exit.assert_called_once_with(0)

    @patch("sys.stdout", new_callable=StringIO)
    @patch("sys.exit")
    def test_die_failure(self, mock_exit, mock_stdout):
        test_message = "Test error message"
        die_failure(test_message)
        error_message = mock_stdout.getvalue()
        assert test_message in error_message
        mock_exit.assert_called_once_with(1)
