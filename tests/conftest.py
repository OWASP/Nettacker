import sys
from pathlib import Path

project_root = Path(__file__).resolve().parent.parent
nettacker_dir = project_root / "src" / "nettacker"
tests_dir = project_root / "tests"

sys.path.insert(0, str(nettacker_dir))
sys.path.insert(1, str(tests_dir))
