import copy
import importlib
import json
import socketserver
import threading
from collections import deque
from contextlib import contextmanager

import pytest

base = importlib.import_module("nettacker.core.lib.base")
http = importlib.import_module("nettacker.core.lib.http")


class _LoopbackHTTPServer(socketserver.ThreadingTCPServer):
    allow_reuse_address = True
    daemon_threads = True


@contextmanager
def loopback_http_server(responses):
    class RequestHandler(socketserver.BaseRequestHandler):
        def handle(self):
            try:
                request = b""
                while b"\r\n\r\n" not in request:
                    chunk = self.request.recv(4096)
                    if not chunk:
                        break
                    request += chunk

                request_line = request.split(b"\r\n", 1)[0].decode("ascii")
                server.request_targets.append(request_line.split(" ")[1])

                with server.responses_lock:
                    response = server.responses.popleft()
                if response is None:
                    return

                status, reason, body, *content_length = response
                content_length = content_length[0] if content_length else len(body)
                self.request.sendall(
                    f"HTTP/1.1 {status} {reason}\r\n".encode()
                    + f"Content-Length: {content_length}\r\n".encode()
                    + b"Connection: close\r\n\r\n"
                    + body
                )
            except Exception as exception:
                server.errors.append(exception)

    server = _LoopbackHTTPServer(("127.0.0.1", 0), RequestHandler)
    server.responses = deque(responses)
    server.responses_lock = threading.Lock()
    server.request_targets = []
    server.errors = []
    server.url = f"http://127.0.0.1:{server.server_address[1]}"
    server_thread = threading.Thread(target=server.serve_forever, daemon=True)
    server_thread.start()

    try:
        yield server
    finally:
        server.shutdown()
        server.server_close()
        server_thread.join(timeout=5)

    if server.errors:
        raise server.errors[0]


def request_options(url, url_raw=None):
    options = {
        "url": url,
        "headers": {"User-Agent": "Nettacker test"},
        "allow_redirects": False,
        "ssl": False,
    }
    if url_raw is not None:
        options["url_raw"] = url_raw
    return options


def engine_step(url):
    return {
        "method": "get",
        "timeout": 3,
        "headers": {"User-Agent": "Nettacker test"},
        "allow_redirects": False,
        "ssl": False,
        "url_raw": True,
        "url": url,
        "response": {
            "condition_type": "and",
            "conditions": {
                "status_code": {"regex": "200", "reverse": False},
            },
        },
    }


def engine_options(retries=1):
    return {
        "http_header": None,
        "user_agent": "Nettacker test",
        "user_agents": ["Nettacker test"],
        "retries": retries,
    }


@pytest.mark.asyncio
async def test_send_request_url_raw_absent_preserves_default_behavior():
    with loopback_http_server([(200, "OK", b"safe")]) as server:
        options = request_options(f"{server.url}/encoded/%30/item")
        original_options = copy.deepcopy(options)

        response = await http.send_request(options, "get")

        assert response["status_code"] == "200"
        assert server.request_targets == ["/encoded/0/item"]
        assert options == original_options
        assert isinstance(options["url"], str)


@pytest.mark.asyncio
async def test_send_request_url_raw_false_preserves_default_behavior(monkeypatch):
    transport_options = []
    perform_request_action = http.perform_request_action

    async def capture_transport_options(action, options):
        transport_options.append(options.copy())
        return await perform_request_action(action, options)

    monkeypatch.setattr(http, "perform_request_action", capture_transport_options)

    with loopback_http_server([(200, "OK", b"safe")]) as server:
        options = request_options(f"{server.url}/encoded/%30/item", url_raw=False)
        original_options = copy.deepcopy(options)

        response = await http.send_request(options, "get")

        assert response["status_code"] == "200"
        assert server.request_targets == ["/encoded/0/item"]
        assert "url_raw" not in transport_options[0]
        assert options == original_options
        assert options["url_raw"] is False
        assert isinstance(options["url"], str)


@pytest.mark.asyncio
async def test_send_request_url_raw_true_preserves_encoded_path_and_input():
    with loopback_http_server([(200, "OK", b"safe")]) as server:
        options = request_options(f"{server.url}/encoded/%30/item", url_raw=True)
        original_options = copy.deepcopy(options)

        response = await http.send_request(options, "get")

        assert response["status_code"] == "200"
        assert server.request_targets == ["/encoded/%30/item"]
        assert options == original_options
        assert options["url"] == original_options["url"]
        assert options["url_raw"] is True
        assert isinstance(options["url"], str)


def test_httpengine_run_url_raw_retry_preserves_path_and_request_state(monkeypatch):
    request_snapshots = []
    send_request = http.send_request

    async def observe_request_state(options, method):
        original_options = copy.deepcopy(options)
        try:
            return await send_request(options, method)
        finally:
            request_snapshots.append((original_options, copy.deepcopy(options)))

    monkeypatch.setattr(http, "send_request", observe_request_state)
    monkeypatch.setattr(base, "submit_logs_to_db", lambda _log: True)
    monkeypatch.setattr(base.log, "success_event_info", lambda _message: None)
    monkeypatch.setattr(base.log, "verbose_info", lambda _message: None)

    responses = [(200, "OK", b"partial", 100), (200, "OK", b"safe")]
    with loopback_http_server(responses) as server:
        step = engine_step(f"{server.url}/encoded/%30/item")
        original_url = step["url"]

        result = http.HttpEngine().run(
            step,
            "test_module",
            "127.0.0.1",
            "scan-id",
            engine_options(retries=2),
            0,
            0,
            1,
            1,
            1,
        )

        assert result is True
        assert server.request_targets == ["/encoded/%30/item", "/encoded/%30/item"]
        assert len(request_snapshots) == 2
        assert all(before == after for before, after in request_snapshots)
        assert all(isinstance(after["url"], str) for _before, after in request_snapshots)
        assert step["url"] == original_url
        assert isinstance(step["url"], str)
        assert step["url_raw"] is True


def test_httpengine_run_url_raw_matching_response_is_serializable(monkeypatch):
    submitted_logs = []
    success_messages = []
    verbose_messages = []

    def submit_serializable_log(log):
        json.dumps(log["port"])
        json.dumps(log["event"])
        json.dumps(log["json_event"])
        submitted_logs.append(copy.deepcopy(log))
        return True

    monkeypatch.setattr(base, "submit_logs_to_db", submit_serializable_log)
    monkeypatch.setattr(base.log, "success_event_info", success_messages.append)
    monkeypatch.setattr(base.log, "verbose_info", verbose_messages.append)

    with loopback_http_server([(200, "OK", b"safe")]) as server:
        step = engine_step(f"{server.url}/encoded/%30/item")
        original_url = step["url"]

        result = http.HttpEngine().run(
            step,
            "test_module",
            "127.0.0.1",
            "scan-id",
            engine_options(),
            0,
            0,
            1,
            1,
            1,
        )

        assert result is True
        assert server.request_targets == ["/encoded/%30/item"]
        assert len(submitted_logs) == 1
        assert success_messages
        assert isinstance(step["url"], str)
        assert step["url"] == original_url
        assert step["url_raw"] is True
        assert isinstance(submitted_logs[0]["json_event"]["url"], str)
        assert json.loads(verbose_messages[-1])["url"] == original_url


def test_httpengine_run_url_raw_nonmatching_response_is_serializable(monkeypatch):
    submitted_logs = []
    verbose_messages = []

    monkeypatch.setattr(base, "submit_logs_to_db", submitted_logs.append)
    monkeypatch.setattr(base.log, "verbose_info", verbose_messages.append)

    with loopback_http_server([(404, "Not Found", b"safe")]) as server:
        step = engine_step(f"{server.url}/encoded/%30/item")
        original_url = step["url"]

        result = http.HttpEngine().run(
            step,
            "test_module",
            "127.0.0.1",
            "scan-id",
            engine_options(),
            0,
            0,
            1,
            1,
            1,
        )

        assert result is False
        assert server.request_targets == ["/encoded/%30/item"]
        assert submitted_logs == []
        assert isinstance(step["url"], str)
        assert step["url"] == original_url
        assert step["url_raw"] is True
        assert json.loads(verbose_messages[-1])["url"] == original_url
