import importlib

import pytest

base = importlib.import_module("nettacker.core.lib.base")

# ----------------------------
# Helpers
# ----------------------------


class DummyEngine(base.BaseEngine):
    pass


@pytest.fixture
def engine():
    return DummyEngine()


TEMP_EVENT = [
    {
        "status_code": ["200"],
        "content": ["<html>csrf_token=abc</html>"],
        "headers": {"Set-Cookie": ["csrftoken=abc123", "sessionid=xyz789"]},
    }
]

# ----------------------------
# find_and_replace_dependent_values
# ----------------------------


def test_dict_branch_resolves_shipped_subdomain_shapes(engine):
    """Shapes taken from nettacker/modules/scan/subdomain.yaml."""
    sub_step = {
        "headers": {"Cookie": "dependent_on_temp_event[0]['headers']['Set-Cookie'][1]"},
        "data": {"csrfmiddlewaretoken": "dependent_on_temp_event[0]['content'][0]"},
    }
    result = engine.find_and_replace_dependent_values(sub_step, TEMP_EVENT)
    assert result["headers"]["Cookie"] == "sessionid=xyz789"
    assert result["data"]["csrfmiddlewaretoken"] == "<html>csrf_token=abc</html>"


def test_list_branch_and_nested_structures(engine):
    sub_step = [
        {"regex": "status dependent_on_temp_event[0]['status_code'][0]"},
        ["nested dependent_on_temp_event[0]['status_code'][0]"],
        5,
        b"bytes-untouched",
    ]
    result = engine.find_and_replace_dependent_values(sub_step, TEMP_EVENT)
    assert result[0]["regex"] == "status 200"
    assert result[1][0] == "nested 200"
    assert result[2] == 5
    assert result[3] == b"bytes-untouched"


def test_plain_text_expression_mid_string(engine):
    """Shape from nettacker/modules/scan/waf.yaml: expression inside prose/regex fields."""
    sub_step = {
        "log": "WAF detected, Got differenet response dependent_on_temp_event[0]['status_code'][0]",
        "response": {
            "conditions": {
                "status_code": {"regex": "dependent_on_temp_event[0]['status_code'][0]"}
            }
        },
    }
    result = engine.find_and_replace_dependent_values(sub_step, TEMP_EVENT)
    assert result["log"] == "WAF detected, Got differenet response 200"
    assert result["response"]["conditions"]["status_code"]["regex"] == "200"


def test_unresolvable_dependency_falls_back_to_error(engine):
    sub_step = {"url": "dependent_on_temp_event[0]['missing'][0]"}
    result = engine.find_and_replace_dependent_values(sub_step, TEMP_EVENT)
    assert result["url"] == "error"


def test_hostile_expressions_are_not_evaluated(engine):
    """Issue #1651 payload must not execute and must not corrupt the step."""
    payload = "dependent_on_temp_event[0]['a'][__import__('platform').system()!='']"
    sub_step = {"data": f"prefix {payload} suffix"}
    result = engine.find_and_replace_dependent_values(sub_step, TEMP_EVENT)
    # only the whitelisted prefix [0]['a'] resolves (to the error fallback);
    # the executable tail stays literal text.
    assert result["data"] == "prefix error[__import__('platform').system()!=''] suffix"


def test_no_globals_pollution(engine):
    """globals().update(locals()) used to leak frame locals into module globals."""
    engine.find_and_replace_dependent_values(
        {"k": "dependent_on_temp_event[0]['status_code'][0]"}, TEMP_EVENT
    )
    module_globals = vars(base)
    for leaked in ("key_name", "key_value", "generate_new_step", "sub_step", "temp_event"):
        assert leaked not in module_globals, f"{leaked} leaked into module globals"
