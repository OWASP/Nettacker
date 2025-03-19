from collections import Counter

from tests.common import TestCase

wordlists = {
    "admin_file": ["lib/payloads/wordlists/admin_wordlist.txt", 533],
    "dir_file": ["lib/payloads/wordlists/dir_wordlist.txt", 1966],
    "pma_file": ["lib/payloads/wordlists/pma_wordlist.txt", 174],
    "wp_plugin_small_file": ["lib/payloads/wordlists/wp_plugin_small.txt", 291],
    "wp_theme_small_file": ["lib/payloads/wordlists/wp_theme_small.txt", 41],
    "wp_timethumb_file": ["lib/payloads/wordlists/wp_timethumbs.txt", 2424],
}


class TestWordlists(TestCase):
    def test_admin_wordlist(self):
        self.run_wordlist_test("admin_file")

    def test_dir_wordlist(self):
        self.run_wordlist_test("dir_file")

    def test_pma_wordlist(self):
        self.run_wordlist_test("pma_file")

    def test_wp_plugin_small_wordlist(self):
        self.run_wordlist_test("wp_plugin_small_file")

    def test_wp_theme_small_wordlist(self):
        self.run_wordlist_test("wp_theme_small_file")

    def test_wp_timethumb_wordlist(self):
        self.run_wordlist_test("wp_timethumb_file")

    def run_wordlist_test(self, key):
        wordlist_path = wordlists[key][0]
        wordlist_length = wordlists[key][1]

        with open(self.nettacker_path / wordlist_path) as wordlist_file:
            paths = [line.strip() for line in wordlist_file.readlines()]

        self.assertEqual(
            len(paths), wordlist_length, f"There are {wordlist_length} paths in {key}"
        )
        self.assertEqual(
            len(set(paths)),
            len(paths),
            f"The paths aren't unique in {key}: {Counter(paths).most_common(1)[0][0]}",
        )
