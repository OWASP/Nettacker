from unittest.mock import AsyncMock, Mock, patch

import pytest

from nettacker.core.lib.http import (
    HttpEngine,
    perform_request_action,
    response_conditions_matched,
    send_request,
)


class MockResponse:
    """Mock HTTP response for testing."""

    def __init__(
        self, status=200, content=b"success", headers={}, reason="OK", url="http://test.com"
    ):
        self.status = status
        self.content = Mock()
        self.content.read = AsyncMock(return_value=content)
        self.headers = headers
        self.reason = reason
        self.url = url


class AsyncContextManagerMock:
    """Mock async context manager for HTTP actions."""

    def __init__(self, return_value=None, exception=None):
        self.return_value = return_value
        self.exception = exception

    def __call__(self, *args, **kwargs):
        return self

    async def __aenter__(self):
        if self.exception:
            raise self.exception
        return self.return_value

    async def __aexit__(self, exc_type, exc_val, exc_tb):
        pass


class TestPerformRequestAction:
    @pytest.mark.asyncio
    async def test_successful_request(self):
        """Test perform_request_action with a successful response."""
        mock_response = MockResponse()
        action = AsyncContextManagerMock(return_value=mock_response)
        result = await perform_request_action(action, {"url": "http://test.com"})
        assert result["status_code"] == "200"
        assert result["content"] == b"success"
        assert result["url"] == "http://test.com"

    @pytest.mark.asyncio
    async def test_request_timing(self):
        """Test perform_request_action includes response time."""
        mock_start_time = Mock(return_value=1.0)
        mock_end_time = Mock(return_value=1.1)
        with patch(
            "nettacker.core.lib.http.time.time", side_effect=[mock_start_time(), mock_end_time()]
        ):
            mock_response = MockResponse()
            action = AsyncContextManagerMock(return_value=mock_response)
            result = await perform_request_action(action, {"url": "http://test.com"})
            assert pytest.approx(result["responsetime"]) == 0.1

    @pytest.mark.asyncio
    async def test_request_error(self):
        """Test perform_request_action with a request error."""
        action = AsyncContextManagerMock(exception=Exception("Request failed"))
        with pytest.raises(Exception, match="Request failed"):
            await perform_request_action(action, {"url": "http://test.com"})


class TestSendRequest:
    @pytest.mark.asyncio
    async def test_method_execution(self):
        """Test send_request executes the specified method."""
        options = {"url": "http://test.com"}
        with patch("aiohttp.ClientSession") as mock_session:
            session_instance = mock_session.return_value
            session_instance.__aenter__ = AsyncMock(return_value=session_instance)
            session_instance.__aexit__ = AsyncMock()

            mock_response = MockResponse()
            mock_cm = AsyncContextManagerMock(return_value=mock_response)
            session_instance.get = mock_cm

            result = await send_request(options, "get")
            assert result["status_code"] == "200"
            assert result["content"] == b"success"

    @pytest.mark.asyncio
    async def test_session_cleanup(self):
        """Test that session is cleaned up in success and failure cases."""
        options = {"url": "http://test.com"}

        # Test successful case
        with patch("aiohttp.ClientSession") as mock_session:
            session_instance = mock_session.return_value
            session_instance.__aenter__ = AsyncMock(return_value=session_instance)
            session_instance.__aexit__ = AsyncMock()

            mock_response = MockResponse()
            mock_cm = AsyncContextManagerMock(return_value=mock_response)
            session_instance.get = mock_cm

            result = await send_request(options, "get")
            assert result["status_code"] == "200"
            assert session_instance.__aexit__.called

        # Test error case
        with patch("aiohttp.ClientSession") as mock_session:
            session_instance = mock_session.return_value
            session_instance.__aenter__ = AsyncMock(return_value=session_instance)
            session_instance.__aexit__ = AsyncMock()

            mock_cm = AsyncContextManagerMock(exception=Exception("Test error"))
            session_instance.get = mock_cm

            result = await send_request(options, "get")
            assert result is None
            assert session_instance.__aexit__.called


class TestResponseConditionsMatched:
    @pytest.mark.parametrize(
        "sub_step, response, expected",
        [
            # Test status_code with AND condition
            (
                {
                    "response": {
                        "condition_type": "and",
                        "conditions": {"status_code": {"regex": "200", "reverse": False}},
                    }
                },
                {"status_code": "200", "content": "test"},
                {"status_code": ["200"]},
            ),
            # Test content with AND condition
            (
                {
                    "response": {
                        "condition_type": "and",
                        "conditions": {"content": {"regex": "test", "reverse": False}},
                    }
                },
                {"status_code": "200", "content": "test content"},
                {"content": ["test"]},
            ),
            # Test content with reverse AND condition
            (
                {
                    "response": {
                        "condition_type": "and",
                        "conditions": {"content": {"regex": "test", "reverse": True}},
                    }
                },
                {"status_code": "200", "content": "other"},
                {"content": True},
            ),
            # Test headers with AND condition
            (
                {
                    "response": {
                        "condition_type": "and",
                        "conditions": {
                            "headers": {"Server": {"regex": "nginx", "reverse": False}}
                        },
                    }
                },
                {"status_code": "200", "headers": {"Server": "nginx"}},
                {"headers": {"Server": ["nginx"]}},
            ),
            # Test reason with AND condition
            (
                {
                    "response": {
                        "condition_type": "and",
                        "conditions": {"reason": {"regex": "OK", "reverse": False}},
                    }
                },
                {"status_code": "200", "reason": "OK"},
                {"reason": ["OK"]},
            ),
            # Test url with AND condition
            (
                {
                    "response": {
                        "condition_type": "and",
                        "conditions": {"url": {"regex": "test.com", "reverse": False}},
                    }
                },
                {"status_code": "200", "url": "http://test.com"},
                {"url": ["test.com"]},
            ),
            # Test null response
            (
                {
                    "response": {
                        "condition_type": "and",
                        "conditions": {"status_code": {"regex": "404", "reverse": False}},
                    }
                },
                None,
                {},
            ),
            # Test binary content with AND condition
            (
                {
                    "response": {
                        "condition_type": "and",
                        "conditions": {"content": {"regex": "test", "reverse": False}},
                    }
                },
                {"status_code": "200", "content": "test binary"},
                {"content": ["test"]},
            ),
            # Test headers with OR condition
            (
                {
                    "response": {
                        "condition_type": "or",
                        "conditions": {
                            "headers": {"X-Test": {"regex": "value", "reverse": False}}
                        },
                    }
                },
                {"status_code": "200", "headers": {"X-Test": "value"}},
                {"headers": {"X-Test": ["value"]}},
            ),
            # Test reason with reverse OR condition
            (
                {
                    "response": {
                        "condition_type": "or",
                        "conditions": {"reason": {"regex": "Not Found", "reverse": True}},
                    }
                },
                {"status_code": "200", "reason": "OK"},
                {"reason": True},
            ),
        ],
    )
    def test_conditions(self, sub_step, response, expected):
        """Test response_conditions_matched with various conditions."""
        result = response_conditions_matched(sub_step, response)
        assert result == expected

    @pytest.mark.parametrize(
        "operator, threshold, responsetime, expected",
        [
            ("==", 0.1, 0.1, {"responsetime": 0.1}),
            ("!=", 0.2, 0.1, {"responsetime": 0.1}),
            ("<", 0.2, 0.1, {"responsetime": 0.1}),
            (">", 0.05, 0.1, {"responsetime": 0.1}),
            ("<=", 0.1, 0.1, {"responsetime": 0.1}),
            (">=", 0.1, 0.1, {"responsetime": 0.1}),
        ],
    )
    def test_responsetime_operators(self, operator, threshold, responsetime, expected):
        """Test response_conditions_matched with responsetime operators."""
        sub_step = {
            "response": {
                "condition_type": "and",
                "conditions": {"responsetime": f"{operator} {threshold}"},
            }
        }
        response = {"responsetime": responsetime}
        result = response_conditions_matched(sub_step, response)
        assert result == expected


class TestHttpEngine:
    def test_run_method_with_retries(self):
        """Test HttpEngine.run with successful request and retries."""
        engine = HttpEngine()
        sub_step = {
            "method": "get",
            "response": {
                "condition_type": "or",
                "conditions": {"status_code": {"regex": "200", "reverse": False}},
            },
        }
        options = {"retries": 2, "user_agent": "ua1", "user_agents": ["ua1", "ua2"]}
        with patch(
            "nettacker.core.lib.http.send_request", new_callable=AsyncMock
        ) as mock_send, patch.object(HttpEngine, "process_conditions", return_value=True):
            mock_send.return_value = {
                "status_code": "200",
                "content": "test",
                "headers": {},
                "reason": "OK",
                "url": "http://test.com",
                "responsetime": 0.1,
            }
            result = engine.run(
                sub_step=sub_step,
                module_name="test",
                target="test.com",
                scan_id="123",
                options=options,
                process_number=1,
                module_thread_number=1,
                total_module_thread_number=1,
                request_number_counter=1,
                total_number_of_requests=1,
            )
            assert mock_send.called
            assert result is True

    def test_connection_error_retry(self):
        """Test HttpEngine.run retries on connection error."""
        engine = HttpEngine()
        sub_step = {
            "method": "get",
            "response": {
                "condition_type": "or",
                "conditions": {"status_code": {"regex": "200", "reverse": False}},
            },
        }
        options = {"retries": 2, "user_agent": "ua1", "user_agents": ["ua1"]}
        with patch(
            "nettacker.core.lib.http.send_request", new_callable=AsyncMock
        ) as mock_send, patch.object(HttpEngine, "process_conditions", return_value=True):
            mock_send.side_effect = [
                Exception("Connection error"),
                {
                    "status_code": "200",
                    "content": "test",
                    "headers": {},
                    "reason": "OK",
                    "url": "http://test.com",
                    "responsetime": 0.1,
                },
            ]
            result = engine.run(
                sub_step=sub_step,
                module_name="test",
                target="test.com",
                scan_id="123",
                options=options,
                process_number=1,
                module_thread_number=1,
                total_module_thread_number=1,
                request_number_counter=1,
                total_number_of_requests=1,
            )
            assert mock_send.call_count == 2
            assert result is True

    def test_iterative_response_matching(self):
        """Test HttpEngine.run with iterative response matching."""
        engine = HttpEngine()
        sub_step = {
            "method": "get",
            "response": {
                "condition_type": "or",
                "conditions": {
                    "iterative_response_match": {
                        "match1": {
                            "response": {
                                "condition_type": "and",
                                "conditions": {"content": {"regex": "pattern1", "reverse": False}},
                            }
                        }
                    },
                    "status_code": {"regex": "200", "reverse": False},
                },
            },
        }
        options = {"retries": 1, "user_agent": "ua1", "user_agents": ["ua1"]}
        with patch(
            "nettacker.core.lib.http.send_request", new_callable=AsyncMock
        ) as mock_send, patch.object(HttpEngine, "process_conditions") as mock_process:
            mock_send.return_value = {
                "status_code": "200",
                "content": "pattern1",
                "headers": {},
                "reason": "OK",
                "url": "http://test.com",
                "responsetime": 0.1,
            }

            def process_conditions_side_effect(*args, **kwargs):
                sub_step = args[0]
                sub_step["response"]["conditions_results"] = {"match1": {"content": ["pattern1"]}}
                return True

            mock_process.side_effect = process_conditions_side_effect
            result = engine.run(
                sub_step=sub_step,
                module_name="test",
                target="test.com",
                scan_id="123",
                options=options,
                process_number=1,
                module_thread_number=1,
                total_module_thread_number=1,
                request_number_counter=1,
                total_number_of_requests=1,
            )
            assert "match1" in sub_step["response"]["conditions_results"]
            assert sub_step["response"]["conditions_results"]["match1"]["content"] == ["pattern1"]
            assert result is True

    def test_invalid_method(self):
        """Test HttpEngine.run with an invalid HTTP method."""
        engine = HttpEngine()
        sub_step = {
            "method": "invalid",
            "response": {
                "condition_type": "or",
                "conditions": {"status_code": {"regex": "200", "reverse": False}},
            },
        }
        options = {"retries": 1, "user_agent": "ua1", "user_agents": ["ua1"]}
        with patch(
            "nettacker.core.lib.http.send_request", new_callable=AsyncMock
        ) as mock_send, patch.object(HttpEngine, "process_conditions", return_value=False):
            mock_send.return_value = []  # Invalid method results in empty response
            result = engine.run(
                sub_step=sub_step,
                module_name="test",
                target="test.com",
                scan_id="123",
                options=options,
                process_number=1,
                module_thread_number=1,
                total_module_thread_number=1,
                request_number_counter=1,
                total_number_of_requests=1,
            )
            assert mock_send.called
            assert result is False
