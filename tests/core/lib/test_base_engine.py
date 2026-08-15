from nettacker.core.lib.base import BaseEngine


class DummyBaseEngine(BaseEngine):
    pass


def test_find_and_replace_dependent_values_uses_key_lookup():
    engine = DummyBaseEngine()
    dependent_on_temp_event = [
        {
            "content": ["token"],
            "headers": {"Set-Cookie": ["session=a", "csrf=b"]},
        }
    ]
    sub_step = {
        "url": "https://example.test/dependent_on_temp_event[0]['content'][0]",
        "headers": {
            "Cookie": "dependent_on_temp_event[0]['headers']['Set-Cookie'][1]",
        },
    }

    result = engine.find_and_replace_dependent_values(sub_step, dependent_on_temp_event)

    assert result["url"] == "https://example.test/token"
    assert result["headers"]["Cookie"] == "csrf=b"


def test_find_and_replace_dependent_values_recurses_into_list_items():
    engine = DummyBaseEngine()
    dependent_on_temp_event = [{"status_code": ["200"]}]
    sub_step = [
        {"expected": "dependent_on_temp_event[0]['status_code'][0]"},
    ]

    result = engine.find_and_replace_dependent_values(sub_step, dependent_on_temp_event)

    assert result == [{"expected": "200"}]
