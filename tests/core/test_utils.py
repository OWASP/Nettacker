from unittest.mock import patch

from nettacker.core.utils import common as utils
from tests.common import TestCase


class TestUtils(TestCase):
    def test_sort_dictionary(self):
        input_dict = {
            "a": 1,
            "c": 3,
            "d": 23,
            "b": 2,
        }
        expected_dict = {
            "a": 1,
            "b": 2,
            "c": 3,
            "d": 23,
        }
        input_dict_keys = tuple(input_dict.keys())
        expected_dict_keys = tuple(expected_dict.keys())
        self.assertNotEqual(input_dict_keys, expected_dict_keys)

        sorted_dict_keys = tuple(utils.sort_dictionary(input_dict).keys())
        self.assertEqual(sorted_dict_keys, expected_dict_keys)

    @patch("multiprocessing.cpu_count")
    def test_select_maximum_cpu_core(self, cpu_count_mock):
        cores_mapping = {
            1: {"low": 1, "normal": 1, "high": 1, "maximum": 1},
            2: {"low": 1, "normal": 1, "high": 1, "maximum": 1},
            4: {"low": 1, "normal": 1, "high": 2, "maximum": 3},
            6: {"low": 1, "normal": 1, "high": 3, "maximum": 5},
            8: {"low": 1, "normal": 2, "high": 4, "maximum": 7},
            10: {"low": 1, "normal": 2, "high": 5, "maximum": 9},
            12: {"low": 1, "normal": 3, "high": 6, "maximum": 11},
            16: {"low": 2, "normal": 4, "high": 8, "maximum": 15},
            32: {"low": 4, "normal": 8, "high": 16, "maximum": 31},
            48: {"low": 6, "normal": 12, "high": 24, "maximum": 47},
            64: {"low": 8, "normal": 16, "high": 32, "maximum": 63},
        }
        for num_cores, levels in cores_mapping.items():
            cpu_count_mock.return_value = num_cores
            for level in ("low", "normal", "high", "maximum"):
                self.assertEqual(
                    utils.select_maximum_cpu_core(level),
                    levels[level],
                    f"It should be {utils.select_maximum_cpu_core(level)} "
                    "of {num_cores} cores for '{level}' mode",
                )

            self.assertEqual(utils.select_maximum_cpu_core("invalid"), 1)
