import asyncio
import importlib
import time

import pytest

http = importlib.import_module("nettacker.core.lib.http")

# ----------------------------
# Helpers / Fakes
# ----------------------------


class FakeContent:
    def __init__(self, data: bytes):
        self._data = data

    async def read(self):
        return self._data


class FakeResponse:
    def __init__(
        self, *, reason="OK", url="http://example.com", status=200, headers=None, body=b"body"
    ):
        self.reason = reason
        self.url = url
        self.status = status
        self.headers = headers or {"X-Test": "yes"}
        self.content = FakeContent(body)


class FakeCtx:
    """
    Mimic aiohttp's _RequestContextManager: awaitable + async context manager.
    """

    def __init__(self, response: FakeResponse):
        self._response = response

    def __await__(self):
        async def _inner():
            return self._response

        return _inner().__await__()

    async def __aenter__(self):
        return self._response

    async def __aexit__(self, exc_type, exc, tb):
        return False


class FakeSession:
    """
    Mimic aiohttp.ClientSession with a single method (get/post/etc.) returning FakeCtx.
    """

    def __init__(self, method_response_map):
        self._method_response_map = method_response_map

    def __getattr__(self, name):
        if name in self._method_response_map:

            def _caller(**kwargs):
                return FakeCtx(self._method_response_map[name])

            return _caller
        raise AttributeError(name)

    async def __aenter__(self):
        return self

    async def __aexit__(self, exc_type, exc, tb):
        return False


class DummyEngine(http.HttpEngine):
    """
    Override BaseEngine interactions to isolate run().
    """

    def __init__(self):
        pass

    def get_dependent_results_from_database(self, *args, **kwargs):
        return {"token": "ABC123"}

    def replace_dependent_values(self, sub_step, temp_event):
        sub_step = dict(sub_step)
        sub_step["url"] = sub_step["url"].replace("{{token}}", temp_event["token"])
        return sub_step

    def process_conditions(
        self,
        sub_step,
        module_name,
        target,
        scan_id,
        options,
        response,
        process_number,
        module_thread_number,
        total_module_thread_number,
        request_number_counter,
        total_number_of_requests,
    ):
        # Make it observable
        return {
            "processed": True,
            "sub_step": sub_step,
            "response": response,
        }


# ----------------------------
# Tests for perform_request_action / send_request
# ----------------------------


def test_perform_request_action_happy_path(monkeypatch):
    # Freeze time to make responsetime predictable
    times = [1000.0, 1001.0]  # start, end
    monkeypatch.setattr(time, "time", lambda: times.pop(0))

    response = FakeResponse(
        reason="Created",
        url="http://example.com/hello",
        status=201,
        headers={"Content-Type": "text/plain"},
        body=b"hello",
    )

    async def run():
        return await http.perform_request_action(
            lambda **_: FakeCtx(response), {"url": "http://example.com/hello"}
        )

    result = asyncio.run(run())
    assert result["reason"] == "Created"
    assert result["url"] == "http://example.com/hello"
    assert result["status_code"] == "201"
    assert result["headers"]["Content-Type"] == "text/plain"
    assert result["content"] == b"hello"
    assert 0.99 <= result["responsetime"] <= 1.01  # ~1 second


@pytest.mark.asyncio
async def test_send_request_uses_session_and_method(monkeypatch):
    fake_resp = FakeResponse(status=202, body=b"accepted")
    fake_session = FakeSession({"get": fake_resp})

    class _FakeClientSession:
        def __init__(self, *a, **k):
            self._sess = fake_session

        async def __aenter__(self):
            return self._sess

        async def __aexit__(self, exc_type, exc, tb):
            return False

    monkeypatch.setattr(http.aiohttp, "ClientSession", _FakeClientSession)
    res = await http.send_request({"url": "http://example.com"}, "get")
    assert res["status_code"] == "202"
    assert res["content"] == b"accepted"


# ----------------------------
# Tests for response_conditions_matched
# ----------------------------


def test_response_conditions_matched_status_code_match():
    sub_step = {
        "timeout": 3.0,
        "headers": {"User-Agent": "Nettacker 0.4.0 QUIN"},
        "allow_redirects": False,
        "ssl": False,
        "url": "http://owasp.org:443",
        "method": "get",
        "response": {
            "condition_type": "and",
            "log": "response_dependent['status_code']",
            "conditions": {
                "status_code": {"regex": r"^200$", "reverse": False},
                "url": {"regex": r"owasp\.org", "reverse": False},
                "reason": {"regex": r"OK", "reverse": False},
            },
        },
    }
    response = {
        "status_code": "200",
        "url": "http://owasp.org:443",
        "reason": "OK",
        "headers": {},
        "responsetime": 0.1,
        "content": "body",
    }
    out = http.response_conditions_matched(sub_step, response)
    assert out != {}
    assert "log" in out  # log field should be present


def test_response_conditions_or_typical_response_match():
    sub_step = {
        "response": {
            "condition_type": "or",
            "log": "response_dependent['status_code']",
            "conditions": {
                "status_code": {"regex": r"\d\d\d", "reverse": False},
                "reason": {"regex": r"OK", "reverse": False},
            },
        }
    }
    response = {
        "reason": "Moved Permanently",
        "url": "http://owasp.org",
        "status_code": "301",
        "content": "<html><h1>301 Moved Permanently</h1></html>",
        "headers": {
            "Date": "Sat, 26 Jul 2025 09:28:43 GMT",
            "Content-Type": "text/html",
            "Content-Length": "167",
            "Server": "cloudflare",
        },
        "responsetime": 0.27,
    }

    out = http.response_conditions_matched(sub_step, response)
    assert out != {}
    assert "log" in out
    assert out["log"] == "301"


def test_response_conditions_or_typical_response_no_match():
    sub_step = {
        "response": {
            "condition_type": "or",
            "log": "response_dependent['status_code']",
            "conditions": {
                "status_code": {"regex": r"404", "reverse": False},
                "reason": {"regex": r"OK", "reverse": False},
            },
        }
    }
    response = {
        "reason": "Moved Permanently",
        "url": "http://owasp.org",
        "status_code": "301",  # Does not match 404
        "content": "<html><h1>301 Moved Permanently</h1></html>",
        "headers": {
            "Date": "Sat, 26 Jul 2025 09:28:43 GMT",
            "Content-Type": "text/html",
            "Content-Length": "167",
            "Server": "cloudflare",
        },
        "responsetime": 0.27,
    }

    out = http.response_conditions_matched(sub_step, response)
    assert out == {}, "Expected empty result since no condition matched"


def test_response_conditions_headers_case_insensitive():
    sub_step = {
        "timeout": 3.0,
        "headers": {"User-Agent": "Nettacker 0.4.0 QUIN"},
        "allow_redirects": False,
        "ssl": False,
        "url": "http://owasp.org:443",
        "method": "get",
        "response": {
            "condition_type": "and",
            "log": "response_dependent['status_code']",
            "conditions": {
                "headers": {
                    "Content-Type": {"regex": r"text/html", "reverse": False},
                }
            },
        },
    }
    response = {
        "status_code": "200",
        "url": "http://owasp.org:443",
        "reason": "OK",
        "headers": {
            "content-type": "text/html",  # Lowercase key to test case-insensitivity
        },
        "responsetime": 0.05,
        "content": "body",
    }
    out = http.response_conditions_matched(sub_step, response)
    assert out != {}
    assert out["headers"]["Content-Type"] == ["text/html"]


def test_response_conditions_responsetime(monkeypatch):
    sub_step = {
        "timeout": 3.0,
        "headers": {"User-Agent": "Nettacker 0.4.0 QUIN"},
        "allow_redirects": False,
        "ssl": False,
        "url": "http://owasp.org:443",
        "method": "get",
        "response": {
            "condition_type": "and",
            "log": "response_dependent['status_code']",
            "conditions": {"responsetime": ">= 0.5"},
        },
    }
    response = {
        "status_code": "200",
        "url": "http://owasp.org:443",
        "reason": "OK",
        "headers": {},
        "responsetime": 0.7,
        "content": "body",
    }
    assert http.response_conditions_matched(sub_step, response) != {}

    response["responsetime"] = 0.2
    assert http.response_conditions_matched(sub_step, response) == {}


# ----------------------------
# Tests for HttpEngine.run
# ----------------------------
def test_httpengine_run_happy_path_merges_headers_and_random_ua(monkeypatch):
    engine = DummyEngine()

    # Patch random.choice to deterministic value
    monkeypatch.setattr(http.random, "choice", lambda seq: seq[0])

    # Patch send_request to bypass network
    async def fake_send_request(options, method):
        return {
            "reason": "OK",
            "url": options["url"],
            "status_code": "200",
            "content": b"OK",
            "headers": {"Server": "nginx"},
            "responsetime": 0.1,
        }

    monkeypatch.setattr(http, "send_request", fake_send_request)

    sub_step = {
        "method": "get",
        "timeout": 3.0,
        "headers": {"User-Agent": "Nettacker 0.4.0 QUIN"},
        "allow_redirects": False,
        "ssl": False,
        "url": "http://owasp.org:80",
        "response": {
            "condition_type": "and",
            "log": "response_dependent['status_code']",
            "conditions": {"status_code": {"regex": r"200", "reverse": False}},
        },
    }
    options = {
        "http_header": ["X-Token: 12345", "X-Empty:"],
        "user_agent": "random_user_agent",
        "user_agents": ["ua1", "ua2"],
        "retries": 1,
    }

    result = engine.run(
        sub_step=sub_step,
        module_name="mod",
        target="t",
        scan_id="id",
        options=options,
        process_number=0,
        module_thread_number=0,
        total_module_thread_number=1,
        request_number_counter=1,
        total_number_of_requests=1,
    )

    assert result["processed"] is True
    # Confirm merged headers
    assert result["sub_step"]["headers"]["X-Token"] == "12345"
    assert result["sub_step"]["headers"]["X-Empty"] == ""
    assert result["sub_step"]["headers"]["User-Agent"] == "ua1"
    # Confirm content decoded
    assert result["response"]["content"] == "OK"


def test_httpengine_run_with_iterative_response_match(monkeypatch):
    engine = DummyEngine()

    async def fake_send_request(options, method):
        return {
            "reason": "OK",
            "url": options["url"],
            "status_code": "200",
            "content": b"pattern abc",
            "headers": {"Server": "nginx"},
            "responsetime": 0.1,
        }

    monkeypatch.setattr(http, "send_request", fake_send_request)

    sub_step = {
        "method": "get",
        "timeout": 3.0,
        "headers": {"User-Agent": "Nettacker 0.4.0 QUIN"},
        "allow_redirects": False,
        "ssl": False,
        "url": "http://owasp.org:80",
        "response": {
            "condition_type": "or",  # will still evaluate the iterative section
            "log": "response_dependent['status_code']",
            "conditions": {
                "status_code": {"regex": r"200", "reverse": False},
                "iterative_response_match": {
                    "match1": {
                        "response": {
                            "condition_type": "and",
                            "conditions": {"content": {"regex": r"abc", "reverse": False}},
                        }
                    }
                },
            },
        },
    }
    options = {"http_header": None, "user_agent": "", "user_agents": [], "retries": 1}

    result = engine.run(
        sub_step=sub_step,
        module_name="mod",
        target="t",
        scan_id="id",
        options=options,
        process_number=0,
        module_thread_number=0,
        total_module_thread_number=1,
        request_number_counter=1,
        total_number_of_requests=1,
    )

    # Ensure nested condition was evaluated and present
    assert "iterative_response_match" in result["sub_step"]["response"]["conditions"]
    assert "conditions_results" in result["sub_step"]["response"]
    assert "match1" in result["sub_step"]["response"]["conditions_results"]


def test_httpengine_run_with_dependent_on_temp_event(monkeypatch):
    class DepEngine(DummyEngine):
        def __init__(self):
            super().__init__()

    engine = DepEngine()

    async def fake_send_request(options, method):
        # url should have been replaced with ABC123
        assert options["url"] == "http://owasp.org/token/ABC123"
        return {
            "reason": "OK",
            "url": options["url"],
            "status_code": "200",
            "content": b"ok",
            "headers": {},
            "responsetime": 0.1,
        }

    monkeypatch.setattr(http, "send_request", fake_send_request)

    sub_step = {
        "method": "get",
        "timeout": 3.0,
        "headers": {"User-Agent": "Nettacker 0.4.0 QUIN"},
        "allow_redirects": False,
        "ssl": False,
        "url": "http://owasp.org/token/{{token}}",
        "response": {
            "dependent_on_temp_event": {"module": "m", "event": "e"},
            "condition_type": "and",
            "log": "response_dependent['status_code']",
            "conditions": {"status_code": {"regex": r"200", "reverse": False}},
        },
    }
    options = {"http_header": None, "user_agent": "", "user_agents": [], "retries": 1}

    result = engine.run(
        sub_step=sub_step,
        module_name="mod",
        target="t",
        scan_id="id",
        options=options,
        process_number=0,
        module_thread_number=0,
        total_module_thread_number=1,
        request_number_counter=1,
        total_number_of_requests=1,
    )

    assert result["processed"] is True
    assert "ABC123" in result["response"]["url"]
