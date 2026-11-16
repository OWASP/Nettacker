import pytest

from nettacker.config import Config
from nettacker.core.fuzzer import read_from_file


@pytest.mark.parametrize(
    ("content", "expected"),
    [
        ("admin\nlogin\n", ["admin", "login"]),
        ("admin\nlogin", ["admin", "login"]),
        ("\nadmin\nlogin\n", ["", "admin", "login"]),
        ("admin\n\nlogin\n", ["admin", "", "login"]),
        ("admin\r\nlogin\r\n", ["admin", "login"]),
    ],
)
def test_read_from_file_ignores_only_the_trailing_newline(
    tmp_path, monkeypatch, content, expected
):
    monkeypatch.setattr(Config.path, "payloads_dir", tmp_path)
    (tmp_path / "words.txt").write_bytes(content.encode())

    assert read_from_file("words.txt") == expected


def test_admin_wordlist_has_no_empty_entry():
    words = read_from_file("wordlists/admin_wordlist.txt")

    assert "" not in words
    assert len(words) == 506


def test_password_list_keeps_single_empty_password():
    passwords = read_from_file("passwords/top_1000_common_passwords.txt")

    assert passwords[0] == ""
    assert passwords.count("") == 1
    assert len(passwords) == 1001
