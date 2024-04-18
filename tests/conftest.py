import sys
from os.path import abspath, dirname, join

project_root = dirname(dirname(__file__))
nettacker_dir = abspath(join(project_root, "src/nettacker"))
tests_dir = abspath(join(project_root, "tests"))

sys.path.insert(0, nettacker_dir)
sys.path.insert(1, tests_dir)
