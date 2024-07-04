import ssl
from unittest.mock import patch

from core.utils import common as utils

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

    def test_is_weak_hash_algo(self):
        for algo in ("md2", "md4", "md5", "sha1"):
            self.assertTrue(utils.is_weak_hash_algo(algo))
        self.assertFalse(utils.is_weak_hash_algo("test_aglo"))

    def test_is_weak_ssl_version(self):
        for ver in {"TLSv1.2", "TLSv1.3"}:
            self.assertFalse(utils.is_weak_ssl_version(ver))
        self.assertTrue(utils.is_weak_ssl_version("test_version"))

    @patch("socket.socket")
    @patch("ssl.create_default_context")
    def test_is_weak_cipher_suite(self, mock_context, mock_socket):
        HOST = "example.com"
        PORT = 80
        TIMEOUT = 60

        socket_instance = mock_socket.return_value
        context_instance = mock_context.return_value

        self.assertTrue(utils.is_weak_cipher_suite(HOST, PORT, TIMEOUT))
        context_instance.wrap_socket.assert_called_with(socket_instance)
        socket_instance.settimeout.assert_called_with(TIMEOUT)
        socket_instance.connect.assert_called_with((HOST, PORT))

        context_instance.wrap_socket.side_effect = ssl.SSLError
        self.assertFalse(utils.is_weak_cipher_suite(HOST, PORT, TIMEOUT))
