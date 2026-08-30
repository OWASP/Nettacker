import unittest
from pathlib import Path

from conftest import nettacker_dir, tests_dir


class TestCase(unittest.TestCase):
    nettacker_path = Path(nettacker_dir)
    tests_path = Path(tests_dir)
