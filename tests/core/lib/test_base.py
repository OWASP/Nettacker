import copy
from unittest.mock import MagicMock, patch

import pytest

from nettacker.core.lib.base import BaseEngine, BaseLibrary


class ConcreteLibrary(BaseLibrary):
    """Concrete implementation of BaseLibrary for testing."""

    def test_action(self, **kwargs):
        return {"result": "ok"}

    def failing_action(self, **kwargs):
        raise ConnectionError("connection refused")


class ConcreteEngine(BaseEngine):
    """Concrete implementation of BaseEngine for testing."""

    library = ConcreteLibrary


@pytest.fixture
def engine():
    return ConcreteEngine()


class TestBaseLibrary:
    def test_client_is_none_by_default(self):
        lib = ConcreteLibrary()
        assert lib.client is None

    def test_brute_force_is_noop(self):
        lib = ConcreteLibrary()
        result = lib.brute_force()
        assert result is None


class TestFilterLargeContent:
    def test_short_content_returned_as_is(self, engine):
        content = "short text"
        assert engine.filter_large_content(content) == content

    def test_content_at_exactly_filter_rate_returned_as_is(self, engine):
        content = "x" * 150
        assert engine.filter_large_content(content, filter_rate=150) == content

    def test_long_content_truncated_at_space_boundary(self, engine):
        # Content longer than filter_rate, with a space after the boundary
        content = "A" * 149 + " remaining text after space"
        result = engine.filter_large_content(content, filter_rate=150)
        assert result.startswith("A" * 149)
        assert "..." in result or "filtered" in result.lower()

    def test_long_content_no_space_returns_full(self, engine):
        # Content longer than filter_rate but no space character anywhere after boundary
        content = "A" * 200
        result = engine.filter_large_content(content, filter_rate=150)
        assert result == content

    def test_custom_filter_rate(self, engine):
        content = "Hello world this is a long content string"
        result = engine.filter_large_content(content, filter_rate=5)
        # "Hello" is 5 chars, then space at index 5 triggers truncation
        assert result.startswith("Hello")


class TestProcessConditions:
    @patch("nettacker.core.lib.base.submit_logs_to_db")
    @patch("nettacker.core.lib.base.submit_temp_logs_to_db")
    def test_successful_conditions_returns_true(self, mock_temp_db, mock_db, engine):
        event = {
            "response": {
                "conditions_results": {"content": ["matched"]},
                "conditions": {"content": {"regex": "test", "reverse": False}},
                "condition_type": "or",
            },
            "url": "http://target:80/path",
        }
        result = engine.process_conditions(
            event=event,
            module_name="test_module",
            target="target.com",
            scan_id="scan123",
            options={},
            response={"content": "matched"},
            process_number=1,
            module_thread_number=1,
            total_module_thread_number=1,
            request_number_counter=1,
            total_number_of_requests=1,
        )
        assert result is True
        mock_db.assert_called_once()

    @patch("nettacker.core.lib.base.submit_logs_to_db")
    @patch("nettacker.core.lib.base.submit_temp_logs_to_db")
    def test_empty_conditions_results_returns_false(self, mock_temp_db, mock_db, engine):
        event = {
            "response": {
                "conditions_results": {},
                "conditions": {"content": {"regex": "test", "reverse": False}},
                "condition_type": "or",
            },
        }
        result = engine.process_conditions(
            event=event,
            module_name="test_module",
            target="target.com",
            scan_id="scan123",
            options={},
            response={},
            process_number=1,
            module_thread_number=1,
            total_module_thread_number=1,
            request_number_counter=1,
            total_number_of_requests=1,
        )
        assert result is False
        mock_db.assert_not_called()

    @patch("nettacker.core.lib.base.submit_logs_to_db")
    @patch("nettacker.core.lib.base.submit_temp_logs_to_db")
    def test_save_to_temp_events_submits_temp_log(self, mock_temp_db, mock_db, engine):
        event = {
            "response": {
                "conditions_results": {"content": ["matched"]},
                "conditions": {"content": {"regex": "test", "reverse": False}},
                "condition_type": "or",
                "save_to_temp_events_only": "step1",
            },
            "ports": "80",
        }
        result = engine.process_conditions(
            event=event,
            module_name="test_module",
            target="target.com",
            scan_id="scan123",
            options={},
            response={"content": "matched"},
            process_number=1,
            module_thread_number=1,
            total_module_thread_number=1,
            request_number_counter=1,
            total_number_of_requests=1,
        )
        # save_to_temp_events_only means it should submit to temp DB
        mock_temp_db.assert_called_once()
        # Regular DB should NOT be called when save_to_temp_events_only is set
        mock_db.assert_not_called()
        # Return value should be True (save_to_temp_events_only IS in response)
        assert result is True

    @patch("nettacker.core.lib.base.submit_logs_to_db")
    @patch("nettacker.core.lib.base.submit_temp_logs_to_db")
    def test_port_extracted_from_url(self, mock_temp_db, mock_db, engine):
        event = {
            "response": {
                "conditions_results": {"content": ["matched"]},
                "conditions": {"content": {"regex": "test", "reverse": False}},
                "condition_type": "or",
            },
            "url": "https://target.com:8443/path",
        }
        engine.process_conditions(
            event=event,
            module_name="test_module",
            target="target.com",
            scan_id="scan123",
            options={},
            response={"content": "matched"},
            process_number=1,
            module_thread_number=1,
            total_module_thread_number=1,
            request_number_counter=1,
            total_number_of_requests=1,
        )
        call_args = mock_db.call_args[0][0]
        assert call_args["port"] == "8443"

    @patch("nettacker.core.lib.base.submit_logs_to_db")
    @patch("nettacker.core.lib.base.submit_temp_logs_to_db")
    def test_port_from_ports_field(self, mock_temp_db, mock_db, engine):
        event = {
            "response": {
                "conditions_results": {"content": ["matched"]},
                "conditions": {"content": {"regex": "test", "reverse": False}},
                "condition_type": "or",
            },
            "ports": "443",
        }
        engine.process_conditions(
            event=event,
            module_name="test_module",
            target="target.com",
            scan_id="scan123",
            options={},
            response={"content": "matched"},
            process_number=1,
            module_thread_number=1,
            total_module_thread_number=1,
            request_number_counter=1,
            total_number_of_requests=1,
        )
        call_args = mock_db.call_args[0][0]
        assert call_args["port"] == "443"

    @patch("nettacker.core.lib.base.submit_logs_to_db")
    @patch("nettacker.core.lib.base.submit_temp_logs_to_db")
    def test_log_field_cleaned_from_event(self, mock_temp_db, mock_db, engine):
        event = {
            "response": {
                "conditions_results": {"content": ["matched"], "log": "test log"},
                "conditions": {"content": {"regex": "test", "reverse": False}},
                "condition_type": "or",
                "log": "response_dependent log",
            },
            "url": "http://target:80/",
        }
        engine.process_conditions(
            event=event,
            module_name="test_module",
            target="target.com",
            scan_id="scan123",
            options={},
            response={"content": "matched"},
            process_number=1,
            module_thread_number=1,
            total_module_thread_number=1,
            request_number_counter=1,
            total_number_of_requests=1,
        )
        # After processing, log and conditions should be removed from event
        assert "log" not in event["response"]
        assert "conditions" not in event["response"]
        assert "condition_type" not in event["response"]


class TestBaseEngineRun:
    @patch("nettacker.core.lib.base.submit_logs_to_db")
    @patch("nettacker.core.lib.base.submit_temp_logs_to_db")
    def test_run_calls_library_method(self, mock_temp_db, mock_db, engine):
        sub_step = {
            "method": "test_action",
            "response": {
                "condition_type": "or",
                "conditions": {},
            },
            "host": "target.com",
        }
        options = {"retries": 1}
        engine.run(
            sub_step=sub_step,
            module_name="test_module",
            target="target.com",
            scan_id="scan123",
            options=options,
            process_number=1,
            module_thread_number=1,
            total_module_thread_number=1,
            request_number_counter=1,
            total_number_of_requests=1,
        )
        # After run, method and response should be restored to sub_step
        assert sub_step["method"] == "test_action"
        assert "response" in sub_step

    @patch("nettacker.core.lib.base.submit_logs_to_db")
    @patch("nettacker.core.lib.base.submit_temp_logs_to_db")
    def test_run_renames_ports_to_port(self, mock_temp_db, mock_db, engine):
        sub_step = {
            "method": "test_action",
            "response": {
                "condition_type": "or",
                "conditions": {},
            },
            "ports": "443",
        }
        options = {"retries": 1}

        original_library = ConcreteLibrary

        captured_kwargs = {}

        class CapturingLibrary(ConcreteLibrary):
            def test_action(self, **kwargs):
                captured_kwargs.update(kwargs)
                return {"result": "ok"}

        engine.library = CapturingLibrary
        try:
            engine.run(
                sub_step=sub_step,
                module_name="test_module",
                target="target.com",
                scan_id="scan123",
                options=options,
                process_number=1,
                module_thread_number=1,
                total_module_thread_number=1,
                request_number_counter=1,
                total_number_of_requests=1,
            )
            # ports should be converted to port with int value
            assert "port" in captured_kwargs
            assert captured_kwargs["port"] == 443
            assert "ports" not in captured_kwargs
        finally:
            engine.library = original_library

    @patch("nettacker.core.lib.base.submit_logs_to_db")
    @patch("nettacker.core.lib.base.submit_temp_logs_to_db")
    def test_run_retries_on_exception(self, mock_temp_db, mock_db, engine):
        call_count = 0

        class FailThenSucceedLibrary(ConcreteLibrary):
            def test_action(self, **kwargs):
                nonlocal call_count
                call_count += 1
                if call_count < 3:
                    raise ConnectionError("connection refused")
                return {"result": "ok"}

        engine.library = FailThenSucceedLibrary
        sub_step = {
            "method": "test_action",
            "response": {
                "condition_type": "or",
                "conditions": {},
            },
        }
        options = {"retries": 5}
        engine.run(
            sub_step=sub_step,
            module_name="test_module",
            target="target.com",
            scan_id="scan123",
            options=options,
            process_number=1,
            module_thread_number=1,
            total_module_thread_number=1,
            request_number_counter=1,
            total_number_of_requests=1,
        )
        assert call_count == 3  # Failed twice, succeeded on third

    @patch("nettacker.core.lib.base.submit_logs_to_db")
    @patch("nettacker.core.lib.base.submit_temp_logs_to_db")
    def test_run_all_retries_fail_returns_empty_response(self, mock_temp_db, mock_db, engine):
        class AlwaysFailLibrary(ConcreteLibrary):
            def test_action(self, **kwargs):
                raise ConnectionError("connection refused")

        engine.library = AlwaysFailLibrary
        sub_step = {
            "method": "test_action",
            "response": {
                "condition_type": "or",
                "conditions": {},
            },
        }
        options = {"retries": 3}
        engine.run(
            sub_step=sub_step,
            module_name="test_module",
            target="target.com",
            scan_id="scan123",
            options=options,
            process_number=1,
            module_thread_number=1,
            total_module_thread_number=1,
            request_number_counter=1,
            total_number_of_requests=1,
        )
        # conditions_results should be empty list (all retries failed)
        assert sub_step["response"]["conditions_results"] == []


class TestGetDependentResultsFromDatabase:
    @patch("nettacker.core.lib.base.find_temp_events")
    def test_returns_conditions_results(self, mock_find, engine):
        import json

        mock_event = {
            "response": {
                "conditions_results": {"content": ["matched_value"]}
            }
        }
        mock_find.return_value = json.dumps(mock_event)

        result = engine.get_dependent_results_from_database(
            "target.com", "test_module", "scan123", "step1"
        )
        assert result == [{"content": ["matched_value"]}]
        mock_find.assert_called_once_with("target.com", "test_module", "scan123", "step1")

    @patch("nettacker.core.lib.base.time.sleep")
    @patch("nettacker.core.lib.base.find_temp_events")
    def test_polls_until_event_available(self, mock_find, mock_sleep, engine):
        import json

        mock_event = {
            "response": {
                "conditions_results": {"content": ["value"]}
            }
        }
        # Return None twice, then the event
        mock_find.side_effect = [None, None, json.dumps(mock_event)]

        result = engine.get_dependent_results_from_database(
            "target.com", "test_module", "scan123", "step1"
        )
        assert result == [{"content": ["value"]}]
        assert mock_find.call_count == 3
        assert mock_sleep.call_count == 2  # Slept twice while waiting

    @patch("nettacker.core.lib.base.find_temp_events")
    def test_multiple_event_names(self, mock_find, engine):
        import json

        event1 = json.dumps({"response": {"conditions_results": {"a": [1]}}})
        event2 = json.dumps({"response": {"conditions_results": {"b": [2]}}})
        mock_find.side_effect = [event1, event2]

        result = engine.get_dependent_results_from_database(
            "target.com", "test_module", "scan123", "step1,step2"
        )
        assert len(result) == 2
        assert result[0] == {"a": [1]}
        assert result[1] == {"b": [2]}


class TestFindAndReplaceDependentValues:
    def test_dict_without_dependent_values_unchanged(self, engine):
        sub_step = {"url": "http://example.com", "timeout": 3}
        result = engine.find_and_replace_dependent_values(sub_step, [])
        assert result == {"url": "http://example.com", "timeout": 3}

    def test_nested_dict_without_dependent_values_unchanged(self, engine):
        sub_step = {"headers": {"User-Agent": "test", "Accept": "text/html"}}
        result = engine.find_and_replace_dependent_values(sub_step, [])
        assert result == {"headers": {"User-Agent": "test", "Accept": "text/html"}}

    def test_list_without_dependent_values_unchanged(self, engine):
        sub_step = ["http://example.com", 3, "test"]
        result = engine.find_and_replace_dependent_values(sub_step, [])
        assert result == ["http://example.com", 3, "test"]

    def test_non_string_values_preserved(self, engine):
        sub_step = {"timeout": 3, "port": 80, "ssl": True}
        result = engine.find_and_replace_dependent_values(sub_step, [])
        assert result["timeout"] == 3
        assert result["port"] == 80


class TestReplaceDependentValues:
    def test_delegates_to_find_and_replace(self, engine):
        sub_step = {"key": "value"}
        dep = [{"some": "data"}]
        engine.find_and_replace_dependent_values = MagicMock(return_value=sub_step)
        result = engine.replace_dependent_values(sub_step, dep)
        engine.find_and_replace_dependent_values.assert_called_once_with(sub_step, dep)
        assert result == sub_step
