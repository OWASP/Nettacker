from unittest.mock import patch

from nettacker.core.utils import common as common_utils
from tests.common import TestCase


class TestCommon(TestCase):
    def test_arrays_to_matrix(self):
        (
            self.assertEqual(
                sorted(
                    common_utils.arrays_to_matrix(
                        {"ports": [1, 2, 3, 4, 5]},
                    )
                ),
                [[1], [2], [3], [4], [5]],
            ),
        )

        self.assertEqual(
            sorted(
                common_utils.arrays_to_matrix(
                    {"x": [1, 2], "y": [3, 4], "z": [5, 6]},
                )
            ),
            [
                [1, 3, 5],
                [1, 3, 6],
                [1, 4, 5],
                [1, 4, 6],
                [2, 3, 5],
                [2, 3, 6],
                [2, 4, 5],
                [2, 4, 6],
            ],
        )

    def test_generate_target_groups_empty_list(self):
        targets = []
        set_hardware_usage = 3
        result = common_utils.generate_target_groups(targets, set_hardware_usage)
        assert result == []

    def test_generate_target_groups_set_hardware_less_than_targets_total(self):
        targets = [1, 2, 3, 4, 5]
        set_hardware_usage = 2
        result = common_utils.generate_target_groups(targets, set_hardware_usage)
        assert result == [[1, 2, 3], [4, 5]]

    def test_generate_target_groups_set_hardware_equal_to_targets_total(self):
        targets = [1, 2, 3, 4, 5]
        set_hardware_usage = 5
        result = common_utils.generate_target_groups(targets, set_hardware_usage)
        assert result == [[1], [2], [3], [4], [5]]

    def test_generate_target_groups_set_hardware_greater_than_targets_total(self):
        targets = [1, 2, 3]
        set_hardware_usage = 5
        result = common_utils.generate_target_groups(targets, set_hardware_usage)
        assert result == [[1], [2], [3]]

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

        sorted_dict_keys = tuple(common_utils.sort_dictionary(input_dict).keys())
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
                    common_utils.select_maximum_cpu_core(level),
                    levels[level],
                    f"It should be {common_utils.select_maximum_cpu_core(level)} "
                    "of {num_cores} cores for '{level}' mode",
                )

            self.assertEqual(common_utils.select_maximum_cpu_core("invalid"), 1)
