from collections import Counter
from pathlib import Path

import pytest

wordlists = {
    "admin_file": ("nettacker/lib/payloads/wordlists/admin_wordlist.txt", 533),
    "dir_file": ("nettacker/lib/payloads/wordlists/dir_wordlist.txt", 1966),
    "pma_file": ("nettacker/lib/payloads/wordlists/pma_wordlist.txt", 174),
    "wp_plugin_small_file": ("nettacker/lib/payloads/wordlists/wp_plugin_small.txt", 291),
    "wp_theme_small_file": ("nettacker/lib/payloads/wordlists/wp_theme_small.txt", 41),
    "wp_timethumb_file": ("nettacker/lib/payloads/wordlists/wp_timethumbs.txt", 2424),
}

nettacker_path = Path(__file__).parent.parent.parent.parent


@pytest.mark.parametrize("key", list(wordlists.keys()))
def test_wordlist(key):
    wordlist_path, expected_length = wordlists[key]
    full_path = nettacker_path / wordlist_path

    with open(full_path) as f:
        paths = [line.strip() for line in f.readlines()]

    assert len(paths) == expected_length, f"There are {expected_length} paths in {key}"
    assert len(set(paths)) == len(
        paths
    ), f"The paths aren't unique in {key}: {Counter(paths).most_common(1)[0][0]}"
