from unittest import IsolatedAsyncioTestCase
from unittest.mock import AsyncMock, Mock, patch

from nettacker.core.lib.http import (
    HttpEngine,
    perform_request_action,
    response_conditions_matched,
    send_request,
)


class MockResponse:
    """Mock HTTP response for testing."""

    def __init__(
        self,
        status=200,
        content=b"success",
        headers={},
        reason="OK",
        url="http://test.com",
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


class TestPerformRequestAction(IsolatedAsyncioTestCase):
    async def test_successful_request(self):
        """Test perform_request_action with a successful response."""
        mock_response = MockResponse()
        action = AsyncContextManagerMock(return_value=mock_response)
        result = await perform_request_action(action, {"url": "http://test.com"})
        self.assertEqual(result["status_code"], "200")
        self.assertEqual(result["content"], b"success")
        self.assertEqual(result["url"], "http://test.com")

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
            self.assertAlmostEqual(result["responsetime"], 0.1)

    async def test_request_error(self):
        """Test perform_request_action with a request error."""
        action = AsyncContextManagerMock(exception=Exception("Request failed"))
        with self.assertRaisesRegex(Exception, "Request failed"):
            await perform_request_action(action, {"url": "http://test.com"})


class TestSendRequest(IsolatedAsyncioTestCase):
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
            self.assertEqual(result["status_code"], "200")
            self.assertEqual(result["content"], b"success")

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
            self.assertEqual(result["status_code"], "200")
            self.assertTrue(session_instance.__aexit__.called)

        # Test error case
        with patch("aiohttp.ClientSession") as mock_session:
            session_instance = mock_session.return_value
            session_instance.__aenter__ = AsyncMock(return_value=session_instance)
            session_instance.__aexit__ = AsyncMock()

            mock_cm = AsyncContextManagerMock(exception=Exception("Test error"))
            session_instance.get = mock_cm

            result = await send_request(options, "get")
            self.assertIsNone(result)
            self.assertTrue(session_instance.__aexit__.called)


class TestResponseConditionsMatched(IsolatedAsyncioTestCase):
    def test_conditions_status_code_and(self):
        """Test status_code with AND condition."""
        sub_step = {
            "response": {
                "condition_type": "and",
                "conditions": {"status_code": {"regex": "200", "reverse": False}},
            }
        }
        response = {"status_code": "200", "content": "test"}
        result = response_conditions_matched(sub_step, response)
        self.assertEqual(result, {"status_code": ["200"]})

    def test_conditions_content_and(self):
        """Test content with AND condition."""
        sub_step = {
            "response": {
                "condition_type": "and",
                "conditions": {"content": {"regex": "test", "reverse": False}},
            }
        }
        response = {"status_code": "200", "content": "test content"}
        result = response_conditions_matched(sub_step, response)
        self.assertEqual(result, {"content": ["test"]})

    def test_conditions_content_reverse_and(self):
        """Test content with reverse AND condition."""
        sub_step = {
            "response": {
                "condition_type": "and",
                "conditions": {"content": {"regex": "test", "reverse": True}},
            }
        }
        response = {"status_code": "200", "content": "other"}
        result = response_conditions_matched(sub_step, response)
        self.assertEqual(result, {"content": True})

    def test_conditions_headers_and(self):
        """Test headers with AND condition."""
        sub_step = {
            "response": {
                "condition_type": "and",
                "conditions": {"headers": {"Server": {"regex": "nginx", "reverse": False}}},
            }
        }
        response = {"status_code": "200", "headers": {"Server": "nginx"}}
        result = response_conditions_matched(sub_step, response)
        self.assertEqual(result, {"headers": {"Server": ["nginx"]}})

    def test_conditions_reason_and(self):
        """Test reason with AND condition."""
        sub_step = {
            "response": {
                "condition_type": "and",
                "conditions": {"reason": {"regex": "OK", "reverse": False}},
            }
        }
        response = {"status_code": "200", "reason": "OK"}
        result = response_conditions_matched(sub_step, response)
        self.assertEqual(result, {"reason": ["OK"]})

    def test_conditions_url_and(self):
        """Test url with AND condition."""
        sub_step = {
            "response": {
                "condition_type": "and",
                "conditions": {"url": {"regex": "test.com", "reverse": False}},
            }
        }
        response = {"status_code": "200", "url": "http://test.com"}
        result = response_conditions_matched(sub_step, response)
        self.assertEqual(result, {"url": ["test.com"]})

    def test_conditions_null_response(self):
        """Test null response."""
        sub_step = {
            "response": {
                "condition_type": "and",
                "conditions": {"status_code": {"regex": "404", "reverse": False}},
            }
        }
        result = response_conditions_matched(sub_step, None)
        self.assertEqual(result, {})

    def test_conditions_binary_content_and(self):
        """Test binary content with AND condition."""
        sub_step = {
            "response": {
                "condition_type": "and",
                "conditions": {"content": {"regex": "test", "reverse": False}},
            }
        }
        response = {"status_code": "200", "content": "test binary"}
        result = response_conditions_matched(sub_step, response)
        self.assertEqual(result, {"content": ["test"]})

    def test_conditions_headers_or(self):
        """Test headers with OR condition."""
        sub_step = {
            "response": {
                "condition_type": "or",
                "conditions": {"headers": {"X-Test": {"regex": "value", "reverse": False}}},
            }
        }
        response = {"status_code": "200", "headers": {"X-Test": "value"}}
        result = response_conditions_matched(sub_step, response)
        self.assertEqual(result, {"headers": {"X-Test": ["value"]}})

    def test_conditions_reason_reverse_or(self):
        """Test reason with reverse OR condition."""
        sub_step = {
            "response": {
                "condition_type": "or",
                "conditions": {"reason": {"regex": "Not Found", "reverse": True}},
            }
        }
        response = {"status_code": "200", "reason": "OK"}
        result = response_conditions_matched(sub_step, response)
        self.assertEqual(result, {"reason": True})

    def test_responsetime_operators(self):
        """Test response_conditions_matched with responsetime operators."""
        test_cases = [
            ("==", 0.1, 0.1, {"responsetime": 0.1}),
            ("!=", 0.2, 0.1, {"responsetime": 0.1}),
            ("<", 0.2, 0.1, {"responsetime": 0.1}),
            (">", 0.05, 0.1, {"responsetime": 0.1}),
            ("<=", 0.1, 0.1, {"responsetime": 0.1}),
            (">=", 0.1, 0.1, {"responsetime": 0.1}),
        ]

        for operator, threshold, responsetime, expected in test_cases:
            with self.subTest(operator=operator):
                sub_step = {
                    "response": {
                        "condition_type": "and",
                        "conditions": {"responsetime": f"{operator} {threshold}"},
                    }
                }
                response = {"responsetime": responsetime}
                result = response_conditions_matched(sub_step, response)
                self.assertEqual(result, expected)


class TestHttpEngine(IsolatedAsyncioTestCase):
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
            self.assertTrue(mock_send.called)
            self.assertTrue(result)

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
            self.assertEqual(mock_send.call_count, 2)
            self.assertTrue(result)

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
            self.assertIn("match1", sub_step["response"]["conditions_results"])
            self.assertEqual(
                sub_step["response"]["conditions_results"]["match1"]["content"], ["pattern1"]
            )
            self.assertTrue(result)

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
            self.assertTrue(mock_send.called)
            self.assertFalse(result)
