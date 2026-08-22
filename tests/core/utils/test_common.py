import threading
import time
from unittest.mock import MagicMock, patch

import pytest

from nettacker.core.utils import common as common_utils
from nettacker.core.utils.common import (
    UnsafeDependentExpression,
    find_dependent_expressions,
    parse_dependent_expression,
    replace_dependent_response,
    resolve_dependent_value,
)


def test_arrays_to_matrix():
    assert sorted(common_utils.arrays_to_matrix({"ports": [1, 2, 3, 4, 5]})) == [
        [1],
        [2],
        [3],
        [4],
        [5],
    ]

    assert sorted(common_utils.arrays_to_matrix({"x": [1, 2], "y": [3, 4], "z": [5, 6]})) == [
        [1, 3, 5],
        [1, 3, 6],
        [1, 4, 5],
        [1, 4, 6],
        [2, 3, 5],
        [2, 3, 6],
        [2, 4, 5],
        [2, 4, 6],
    ]


def test_generate_target_groups_empty_list():
    targets = []
    set_hardware_usage = 3
    result = common_utils.generate_target_groups(targets, set_hardware_usage)
    assert result == []


def test_generate_target_groups_set_hardware_less_than_targets_total():
    targets = [1, 2, 3, 4, 5]
    set_hardware_usage = 2
    result = common_utils.generate_target_groups(targets, set_hardware_usage)
    assert result == [[1, 2, 3], [4, 5]]


def test_generate_target_groups_set_hardware_equal_to_targets_total():
    targets = [1, 2, 3, 4, 5]
    set_hardware_usage = 5
    result = common_utils.generate_target_groups(targets, set_hardware_usage)
    assert result == [[1], [2], [3], [4], [5]]


def test_generate_target_groups_set_hardware_greater_than_targets_total():
    targets = [1, 2, 3]
    set_hardware_usage = 5
    result = common_utils.generate_target_groups(targets, set_hardware_usage)
    assert result == [[1], [2], [3]]


def test_sort_dictionary():
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
    assert input_dict_keys != expected_dict_keys
    sorted_dict_keys = tuple(common_utils.sort_dictionary(input_dict).keys())
    assert sorted_dict_keys == expected_dict_keys


@patch("multiprocessing.cpu_count")
def test_select_maximum_cpu_core(cpu_count_mock):
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
            assert common_utils.select_maximum_cpu_core(level) == levels[level]
        assert common_utils.select_maximum_cpu_core("invalid") == 1


def test_merge_logs_to_list_simple():
    result = {"log": "error occurred"}
    assert common_utils.merge_logs_to_list(result) == ["error occurred"]


def test_merge_logs_to_list_nested():
    result = {
        "log": "outer",
        "nested": {"log": "inner"},
    }
    logs = common_utils.merge_logs_to_list(result)
    assert sorted(logs) == ["inner", "outer"]


def test_merge_logs_to_list_no_log_key():
    result = {"status": "ok", "data": {"value": 42}}
    assert common_utils.merge_logs_to_list(result) == []


def test_merge_logs_to_list_deduplicates():
    result = {
        "log": "same",
        "nested": {"log": "same"},
    }
    assert common_utils.merge_logs_to_list(result) == ["same"]


def test_merge_logs_to_list_no_shared_state_between_calls():
    """Verify that consecutive calls without explicit log_list don't leak state."""
    result_a = {"log": "first"}
    result_b = {"log": "second"}
    logs_a = common_utils.merge_logs_to_list(result_a)
    logs_b = common_utils.merge_logs_to_list(result_b)
    assert logs_a == ["first"]
    assert logs_b == ["second"]


def test_wait_for_threads_to_finish_all_dead():
    """All threads already finished -- should return True immediately."""
    t = MagicMock(spec=threading.Thread)
    t.is_alive.return_value = False
    threads = [t]
    assert common_utils.wait_for_threads_to_finish(threads) is True
    assert threads == []


def test_wait_for_threads_to_finish_removes_all_dead_threads():
    """Verify every dead thread is removed, not just alternating ones (the original bug)."""
    dead = [MagicMock(spec=threading.Thread) for _ in range(5)]
    for t in dead:
        t.is_alive.return_value = False
    threads = list(dead)
    common_utils.wait_for_threads_to_finish(threads)
    assert threads == []


def test_wait_for_threads_to_finish_with_maximum():
    """Should break early when thread count drops below maximum."""

    def short_task():
        time.sleep(0.02)

    threads = [threading.Thread(target=short_task) for _ in range(3)]
    for t in threads:
        t.start()
    result = common_utils.wait_for_threads_to_finish(threads, maximum=3)
    assert result is True
    # Clean up
    for t in threads:
        t.join(timeout=1)


def test_wait_for_threads_to_finish_empties_list():
    """Threads that finish are removed in-place from the original list."""

    def quick():
        pass

    threads = [threading.Thread(target=quick) for _ in range(3)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()
    # All are dead now
    result = common_utils.wait_for_threads_to_finish(threads)
    assert result is True
    assert len(threads) == 0


def test_set_nested_value_single_key():
    d = {"a": 1}
    common_utils.set_nested_value(d, "a/", "X")
    assert d == {"a": "X"}


def test_set_nested_value_nested_path():
    d = {"a": {"b": {"c": 0}}}
    common_utils.set_nested_value(d, "a/b/c/", "Z")
    assert d == {"a": {"b": {"c": "Z"}}}


def test_set_nested_value_ignores_empty_segments():
    d = {"a": {"b": None}}
    # Trailing slash -> last segment is empty and filtered out.
    common_utils.set_nested_value(d, "a/b/", 42)
    assert d["a"]["b"] == 42


def test_generate_new_sub_steps_substitutes_values_without_exec():
    sub_steps = {"url": {"schema": None, "ports": None}}
    arrays = {"url/schema/": ["http"], "url/ports/": [80]}
    data_matrix = [["http", 80], ["https", 443]]

    result = common_utils.generate_new_sub_steps(sub_steps, data_matrix, arrays)

    assert result == [
        {"url": {"schema": "http", "ports": 80}},
        {"url": {"schema": "https", "ports": 443}},
    ]
    # Caller's sub_steps must not be mutated.
    assert sub_steps == {"url": {"schema": None, "ports": None}}


def test_apply_data_functions_skips_unknown_item():
    data = {"unrelated": {"read_from_file": "x.txt"}}
    assert common_utils.apply_data_functions(data) == data


def test_apply_data_functions_skips_unknown_function_name():
    data = {"passwords": {"not_allowed_fn": "payload"}}
    # Unknown function name is simply skipped, returning the original payload.
    assert common_utils.apply_data_functions(data) == data


def test_apply_data_functions_invokes_allowed_function():
    data = {"passwords": {"read_from_file": "pw.txt"}}
    with patch("nettacker.core.fuzzer.read_from_file", return_value=["a", "b"], create=True):
        result = common_utils.apply_data_functions(data)
    assert result == {"passwords": ["a", "b"]}


def _fuzzer_arrays(interceptors):
    return {
        "url": {
            "nettacker_fuzzer": {
                "input_format": "http://host/{path}",
                "prefix": "[",
                "suffix": "]",
                "interceptors": interceptors,
                "data": {"path": ["a", "b"]},
            }
        }
    }


def test_fuzzer_repeater_perform_no_interceptors():
    result = common_utils.fuzzer_repeater_perform(_fuzzer_arrays(""))
    assert result == {"url": ["[http://host/a]", "[http://host/b]"]}


def test_fuzzer_repeater_perform_allowed_interceptor_runs():
    arrays = {
        "url": {
            "nettacker_fuzzer": {
                "input_format": "NETTACKER_MD5_GENERATOR_START{seed}NETTACKER_MD5_GENERATOR_STOP",
                "prefix": "",
                "suffix": "",
                "interceptors": "generate_and_replace_md5",
                "data": {"seed": ["abc"]},
            }
        }
    }
    # This is basically: md5("abc")
    assert common_utils.fuzzer_repeater_perform(arrays) == {
        "url": ["900150983cd24fb0d6963f7d28e17f72"]
    }


def test_fuzzer_repeater_perform_disallowed_interceptor_raises():
    arrays = _fuzzer_arrays("os.system")
    with pytest.raises(ValueError, match="os.system"):
        common_utils.fuzzer_repeater_perform(arrays)


def test_fuzzer_repeater_perform_unknown_interceptor_alongside_allowed_raises():
    # Disallowed name listed first so we hit the allow-list check before any allowed
    # interceptor mutates the value.
    arrays = _fuzzer_arrays("__import__,generate_and_replace_md5")
    with pytest.raises(ValueError, match="__import__"):
        common_utils.fuzzer_repeater_perform(arrays)


def test_allowed_interceptors_registry_is_restricted():
    assert set(common_utils.ALLOWED_INTERCEPTORS) == {"generate_and_replace_md5"}


# ----------------------------
# Safe dependent-value resolution (replaces eval/exec, see issue #1651)
# ----------------------------

TEMP_EVENT = [
    {
        "status_code": ["200"],
        "content": ["<html>ns1.example.com</html>"],
        "headers": {"Set-Cookie": ["csrftoken=abc123", "sessionid=xyz789"]},
    }
]


@pytest.mark.parametrize(
    "expression, expected",
    [
        ("dependent_on_temp_event[0]['status_code'][0]", "200"),
        ("dependent_on_temp_event[0]['content'][0]", "<html>ns1.example.com</html>"),
        ("dependent_on_temp_event[0]['headers']['Set-Cookie'][1]", "sessionid=xyz789"),
    ],
)
def test_resolve_dependent_value_shipped_module_shapes(expression, expected):
    """Every dependent_on_temp_event expression used by shipped modules resolves."""
    assert resolve_dependent_value(expression, "dependent_on_temp_event", TEMP_EVENT) == expected


def test_parse_dependent_expression_returns_index_path():
    assert parse_dependent_expression(
        "dependent_on_temp_event[0]['headers']['Set-Cookie'][1]",
        "dependent_on_temp_event",
    ) == [0, "headers", "Set-Cookie", 1]
    assert parse_dependent_expression("response_dependent['service']", "response_dependent") == [
        "service"
    ]
    assert parse_dependent_expression('root[-1]["k"]', "root") == [-1, "k"]


def test_find_dependent_expressions_multiple_in_one_string():
    log = "response_dependent['status_code'] response_dependent['headers']['Location']"
    assert find_dependent_expressions(log, "response_dependent") == [
        "response_dependent['status_code']",
        "response_dependent['headers']['Location']",
    ]


@pytest.mark.parametrize(
    "expression",
    [
        # payload from issue #1651: import must never run
        "dependent_on_temp_event[0]['a'][__import__('platform').system()!='']",
        "dependent_on_temp_event[__import__('os').system('true')]",
        # attribute access after the chain
        "dependent_on_temp_event[0].keys",
        # non-literal subscripts
        "dependent_on_temp_event[name]",
        "dependent_on_temp_event[0 + 1]",
        "dependent_on_temp_event[True]",
        # call instead of subscript chain
        "__import__('os').getcwd()",
        # bare root without any index
        "dependent_on_temp_event",
        # wrong root name
        "response_dependent['service']",
    ],
)
def test_parse_dependent_expression_rejects_non_whitelisted_forms(expression):
    with pytest.raises(UnsafeDependentExpression):
        parse_dependent_expression(expression, "dependent_on_temp_event")


def test_replace_dependent_response_shipped_module_shapes():
    response = {
        "status_code": ["200"],
        "url": ["http://target/"],
        "service": ["http"],
        "content": ["Apache Tomcat"],
        "headers": {"Server": ["Apache"], "Last-Modified": ["Tue, 12 Mar 2024"]},
    }
    assert (
        replace_dependent_response("found: response_dependent['status_code']", response)
        == "found: 200"
    )
    assert (
        replace_dependent_response("u=response_dependent['url']", response) == "u=http://target/"
    )
    assert (
        replace_dependent_response(
            "srv: response_dependent['headers']['Server'] mod: "
            "response_dependent['headers']['Last-Modified']",
            response,
        )
        == "srv: Apache mod: Tue, 12 Mar 2024"
    )


def test_replace_dependent_response_multiple_expressions():
    response = {
        "status_code": ["301"],
        "headers": {"Location": ["http://target/login"]},
    }
    log = "moved response_dependent['status_code'] to response_dependent['headers']['Location']"
    assert replace_dependent_response(log, response) == "moved 301 to http://target/login"


def test_replace_dependent_response_unresolvable_uses_default():
    response = {"status_code": ["200"]}
    assert (
        replace_dependent_response("x response_dependent['missing_key']", response)
        == "x response dependent error"
    )
    assert replace_dependent_response("", {}) is None


def test_replace_dependent_response_never_evaluates_hostile_text():
    """Expressions outside the grammar stay literal; nothing gets executed."""
    response = {}
    hostile = "response_dependent['a' if __import__('platform').system() else 'b']"
    assert replace_dependent_response(hostile, response) == hostile


def test_replace_dependent_expression_string_subscript_is_data_only():
    """Quoted keys are plain dict lookups, never attribute/call resolution."""
    response = {"__class__": ["not-a-class"]}
    assert (
        replace_dependent_response("v=response_dependent['__class__']", response)
        == "v=not-a-class"
    )
