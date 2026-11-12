import sys
from unittest.mock import patch

import pytest

from nettacker.core.arg_parser import ArgParser


class ApiStarted(Exception):
    pass


@pytest.fixture
def start_api():
    with patch("nettacker.api.engine.start_api_server", side_effect=ApiStarted) as mock:
        yield mock


def parse(*args):
    """Run ArgParser with --start-api and the given arguments."""
    with patch.object(sys, "argv", ["nettacker", "--start-api", *args]):
        try:
            ArgParser()
        except ApiStarted:
            pass


@pytest.mark.parametrize(
    "whitelist",
    [
        "192.0.2.10-192.0.2.1",
        "2001:db8::a-2001:db8::1",
        "192.0.2.1,192.0.2.10-192.0.2.1",
        "192.0.2.1,2001:db8::a-2001:db8::1",
        "192.0.2.1,not-an-ip",
        "",
        "192.0.2.1,,192.0.2.2",
        "192.0.2.1,",
        "10.1",
        "10.0.0.0/33",
    ],
)
def test_invalid_whitelist_never_starts_api(start_api, whitelist):
    with pytest.raises(SystemExit) as exit_info:
        parse("--api-client-whitelisted-ips", whitelist)

    assert exit_info.value.code == 1
    start_api.assert_not_called()


def test_invalid_whitelist_error_names_entry(start_api):
    with patch("nettacker.core.arg_parser.die_failure", side_effect=SystemExit(1)) as die:
        with pytest.raises(SystemExit):
            parse("--api-client-whitelisted-ips", "192.0.2.1,bad")

    assert "'bad'" in die.call_args.args[0]


def test_valid_whitelist_is_expanded(start_api):
    parse(
        "--api-client-whitelisted-ips",
        "192.0.2.1, 192.0.2.4-192.0.2.6,192.0.2.8/31,2001:db8::1,2001:db8::a-2001:db8::b",
    )

    start_api.assert_called_once()
    assert start_api.call_args.args[0].api_client_whitelisted_ips == [
        "192.0.2.1",
        "192.0.2.4",
        "192.0.2.5",
        "192.0.2.6",
        "192.0.2.8",
        "192.0.2.9",
        "2001:db8::1",
        "2001:db8::a",
        "2001:db8::b",
    ]


def test_omitted_whitelist_stays_unrestricted(start_api):
    parse()

    start_api.assert_called_once()
    assert start_api.call_args.args[0].api_client_whitelisted_ips == []


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
