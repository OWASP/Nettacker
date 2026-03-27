from types import SimpleNamespace
from unittest.mock import MagicMock, patch
import os

from nettacker.core.app import Nettacker


def test_print_logo():
    with patch("nettacker.core.app.log"):
        Nettacker.print_logo()
