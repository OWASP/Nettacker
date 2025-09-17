import sys
from pathlib import Path

project_root = Path(__file__).parent.parent
nettacker_dir = str(project_root / "nettacker")
tests_dir = str(project_root / "tests")

sys.path.insert(0, nettacker_dir)
sys.path.insert(1, tests_dir)
