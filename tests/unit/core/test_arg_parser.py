import sys

from nettacker.core.arg_parser import ArgParser


def test_user_and_password_lists_ignore_the_trailing_newline(tmp_path, monkeypatch):
    usernames = tmp_path / "users.txt"
    passwords = tmp_path / "passwords.txt"
    usernames.write_text("root\nadmin\n")
    passwords.write_text("\ntoor\n")
    argv = ["nettacker", "-i", "127.0.0.1", "-m", "ssh_brute"]
    argv += ["-U", str(usernames), "-P", str(passwords), "-o", str(tmp_path / "r.html")]
    monkeypatch.setattr(sys, "argv", argv)

    options = ArgParser().arguments

    assert sorted(options.usernames) == ["admin", "root"]
    # A blank line written on purpose is still an empty password.
    assert sorted(options.passwords) == ["", "toor"]
