from unittest.mock import MagicMock, patch

from nettacker.core.lib.base import BaseEngine


def test_filter_large_content_truncates():
    engine = BaseEngine()
    content = "abcdefghij klm"
    result = engine.filter_large_content(content, filter_rate=10)
    assert result != content
    assert result.startswith("abcdefghij")
    assert "klm" not in result


@patch("nettacker.core.lib.base.submit_logs_to_db")
@patch("nettacker.core.lib.base.merge_logs_to_list", return_value=["logA"])
@patch("nettacker.core.lib.base.remove_sensitive_header_keys")
def test_process_conditions_success(mock_remove, mock_merge, mock_submit):
    engine = BaseEngine()
    event = {
        "headers": {"Authorization": "secret"},
        "response": {
            "conditions_results": {"log": "entry"},
            "conditions": {"dummy": {"reverse": False, "regex": ""}},
            "condition_type": "and",
        },
        "ports": 80,
    }
    options = {"retries": 1}
    mock_remove.return_value = event

    result = engine.process_conditions(
        event,
        "module",
        "target",
        "scan",
        options,
        {"resp": True},
        1,
        1,
        1,
        1,
        1,
    )
    assert result is True
    mock_submit.assert_called_once()
    mock_merge.assert_called_once()
    mock_remove.assert_called_once()


@patch("nettacker.core.lib.base.submit_temp_logs_to_db")
def test_process_conditions_save_temp(mock_submit_temp):
    engine = BaseEngine()
    event = {
        "response": {
            "conditions_results": [],
            "conditions": {},
            "condition_type": "and",
            "save_to_temp_events_only": "temp_evt",
        }
    }
    options = {"retries": 1}
    result = engine.process_conditions(
        event,
        "module",
        "target",
        "scan",
        options,
        {},
        1,
        1,
        1,
        1,
        1,
    )
    assert result is True
    mock_submit_temp.assert_called_once()
