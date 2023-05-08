"""
This is the utility unit testing module
"""

import sys
import unittest
from core import utility

sys.path.insert(1, '../../')


class UtilityTesting(unittest.TestCase):
    """
    This is the class that tests the utility module functions.
    """

    def test_sort_dictonary(self):
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
        self.assertDictEqual(utility.sort_dictonary(input_dict), sorted_dict)


if __name__ == '__main__':
    unittest.main()
