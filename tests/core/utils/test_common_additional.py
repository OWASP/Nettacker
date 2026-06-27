import time
from threading import Thread

from nettacker.core.utils import common as common_utils


def test_remove_sensitive_header_keys_strips_auth():
    event = {"headers": {"Authorization": "secret", "X-Test": "ok"}}
    cleaned = common_utils.remove_sensitive_header_keys(event)
    assert "Authorization" not in cleaned["headers"]
    assert cleaned["headers"]["X-Test"] == "ok"


def test_reverse_and_regex_condition_reverse_true():
    assert common_utils.reverse_and_regex_condition([], True) is True


def test_merge_logs_to_list_nested():
    data = {"outer": {"log": "a"}, "items": {"log": "b"}}
    result = common_utils.merge_logs_to_list(data)
    assert set(result) == {"a", "b"}


def test_sanitize_path():
    assert common_utils.sanitize_path("../etc/passwd") == "etc_passwd"


def test_wait_for_threads_to_finish():
    thread = Thread(target=lambda: time.sleep(0.01))
    thread.start()
    assert common_utils.wait_for_threads_to_finish([thread]) is True


def test_generate_compare_filepath_format():
    scan_id = "scan123"
    generated = common_utils.generate_compare_filepath(scan_id)
    assert generated.endswith(f"{scan_id}.json")


def test_generate_random_token_length():
    token = common_utils.generate_random_token(5)
    assert len(token) == 5
