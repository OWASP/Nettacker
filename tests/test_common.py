import unittest
from pathlib import Path

class TestCase(unittest.TestCase):
    def setUp(self):
        # Fix the paths
        self.project_root = Path(__file__).resolve().parent.parent  # Go up from 'tests'
        self.nettacker_path = self.project_root / "nettacker"  # Correct location
        self.tests_path = self.project_root / "tests"

        # Debugging information
        print(f"DEBUG: Expected nettacker_path: {self.nettacker_path}")
        print(f"DEBUG: Expected tests_path: {self.tests_path}")

    def test_paths_exist(self):
        # Check if paths exist
        self.assertTrue(self.nettacker_path.exists(), f"Nettacker directory does not exist: {self.nettacker_path}")
        self.assertTrue(self.tests_path.exists(), f"Tests directory does not exist: {self.tests_path}")

if __name__ == "__main__":
    unittest.main()
