"""
This is the utility unit testing module
"""

import sys
import multiprocessing
import unittest
from core import utility

sys.path.insert(1, '../../')


class UtilityTesting(unittest.TestCase):
    """
    This is the class that tests the utility module functions.
    """

    def test_sort_dictionary(self):
        """Tests if the function sorts the input dictionary."""
        input_dict = {
            'a': 1,
            'c': 3,
            'd': 23,
            'b': 2,
        }
        sorted_dict = {
            'a': 1,
            'b': 2,
            'c': 3,
            'd': 23,
        }
        self.assertDictEqual(utility.sort_dictionary(input_dict), sorted_dict)

    def test_select_maximum_cpu_core(self):
        """Tests if it selects the proper amount of cpu's"""

        num_cores = int(multiprocessing.cpu_count()) - 1

        self.assertNotEqual(utility.select_maximum_cpu_core('maximum'), 3)
        self.assertEqual(utility.select_maximum_cpu_core('max'), 1)
        self.assertEqual(utility.select_maximum_cpu_core('maximum'), num_cores)
        self.assertGreaterEqual(utility.select_maximum_cpu_core('high'), 1)
        self.assertGreaterEqual(utility.select_maximum_cpu_core('normal'), 1)
        self.assertGreaterEqual(utility.select_maximum_cpu_core('low'), 1)
        self.assertEqual(utility.select_maximum_cpu_core('some rand value'), 1)


if __name__ == '__main__':
    unittest.main()
