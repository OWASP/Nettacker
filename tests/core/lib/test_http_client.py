import copy

from nettacker.core.lib import http_client

# ----------------------------
# Helpers / Fakes
# ----------------------------


class DummyHttpClientEngine(http_client.Http_clientEngine):
    """
    Override interactions to isolate run() and inspect the modified sub_step.
    """

    def __init__(self):
        pass

    def get_dependent_results_from_database(self, *args, **kwargs):
        return {}

    def replace_dependent_values(self, sub_step, temp_event):
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
        # Return the modified sub_step for inspection
        return {
            "processed": True,
            "sub_step": sub_step,
            "response": response,
        }


# ----------------------------
# Tests
# ----------------------------


def test_drop_empty_headers(monkeypatch):
    """Test that empty header values are dropped."""
    engine = DummyHttpClientEngine()

    # Mocks
    async def fake_send_request(sub_step, method):
        return {"content": b"OK", "status_code": "200"}

    monkeypatch.setattr(http_client, "send_request", fake_send_request)
    monkeypatch.setattr(http_client, "response_conditions_matched", lambda *a: {})

    sub_step = {
        "method": "get",
        "url": "http://example.com",
        "headers": {
            "User-Agent": "TestAgent",
            "X-API-Key": "",
            "Other-Header": None,
            "Valid-Header": "Value",
        },
        "response": {"conditions": {}},
    }
    options = {"http_header": None, "user_agent": "TestAgent", "retries": 1}

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

    headers = result["sub_step"]["headers"]
    assert "User-Agent" in headers
    assert "Valid-Header" in headers
    assert "X-API-Key" not in headers
    assert "Other-Header" not in headers


def test_drop_malformed_authorization(monkeypatch):
    """Test that malformed Authorization headers (e.g. 'Bearer ') are dropped."""
    engine = DummyHttpClientEngine()

    # Mocks
    async def fake_send_request(sub_step, method):
        return {"content": b"OK", "status_code": "200"}

    monkeypatch.setattr(http_client, "send_request", fake_send_request)
    monkeypatch.setattr(http_client, "response_conditions_matched", lambda *a: {})

    # Case 1: Authorization: "Bearer " (Trailing space)
    sub_step = {
        "method": "get",
        "url": "http://example.com",
        "headers": {"Authorization": "Bearer ", "User-Agent": "TestAgent"},
        "response": {"conditions": {}},
    }
    options = {"http_header": None, "user_agent": "TestAgent", "retries": 1}

    result = engine.run(
        sub_step=copy.deepcopy(sub_step),
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
    assert "Authorization" not in result["sub_step"]["headers"]

    # Case 2: Authorization: "Bearer" (No space)
    sub_step["headers"]["Authorization"] = "Bearer"
    result = engine.run(
        sub_step=copy.deepcopy(sub_step),
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
    assert "Authorization" not in result["sub_step"]["headers"]

    # Case 3: Proxy-Authorization: "Basic "
    sub_step["headers"] = {"Proxy-Authorization": "Basic ", "User-Agent": "TestAgent"}
    result = engine.run(
        sub_step=copy.deepcopy(sub_step),
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
    assert "Proxy-Authorization" not in result["sub_step"]["headers"]


def test_keep_valid_authorization(monkeypatch):
    """Test that valid Authorization headers are retained."""
    engine = DummyHttpClientEngine()

    # Mocks
    async def fake_send_request(sub_step, method):
        return {"content": b"OK", "status_code": "200"}

    monkeypatch.setattr(http_client, "send_request", fake_send_request)
    monkeypatch.setattr(http_client, "response_conditions_matched", lambda *a: {})

    # Case: Authorization: "Bearer 12345"
    sub_step = {
        "method": "get",
        "url": "http://example.com",
        "headers": {"Authorization": "Bearer 12345", "User-Agent": "TestAgent"},
        "response": {"conditions": {}},
    }
    options = {"http_header": None, "user_agent": "TestAgent", "retries": 1}

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
    assert "Authorization" in result["sub_step"]["headers"]
    assert result["sub_step"]["headers"]["Authorization"] == "Bearer 12345"


def test_drop_whitespace_headers(monkeypatch):
    """Test that headers containing only whitespace are dropped."""
    engine = DummyHttpClientEngine()

    # Mocks
    async def fake_send_request(sub_step, method):
        return {"content": b"OK", "status_code": "200"}

    monkeypatch.setattr(http_client, "send_request", fake_send_request)
    monkeypatch.setattr(http_client, "response_conditions_matched", lambda *a: {})

    sub_step = {
        "method": "get",
        "url": "http://example.com",
        "headers": {
            "User-Agent": "TestAgent",
            "X-API-Key": "   ",  # Whitespace only
            "Authorization": "  ",  # Whitespace only
            "Valid-Header": "Value",
        },
        "response": {"conditions": {}},
    }
    options = {"http_header": None, "user_agent": "TestAgent", "retries": 1}

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

    headers = result["sub_step"]["headers"]
    assert "User-Agent" in headers
    assert "Valid-Header" in headers
    assert "X-API-Key" not in headers
    assert "Authorization" not in headers
