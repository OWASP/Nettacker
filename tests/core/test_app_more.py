from types import SimpleNamespace
from unittest.mock import MagicMock, patch
import os

from nettacker.core.app import Nettacker


def test_print_logo():
    with patch("nettacker.core.app.log") as mock_log:
        Nettacker.print_logo()
    mock_log.write_to_api_console.assert_called_once()
    mock_log.reset_color.assert_called_once()
