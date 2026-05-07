import copy
import hashlib

from nettacker.core.lib.http import HttpEngine, response_conditions_matched


def _http_response(content="", headers=None, status_code="200"):
    content_bytes = content.encode()
    return {
        "reason": "OK",
        "url": "http://example.test/admin",
        "status_code": status_code,
        "content": content,
        "content_length": str(len(content_bytes)),
        "content_sha1": hashlib.sha1(content_bytes).hexdigest(),
        "headers": headers or {},
        "responsetime": 0.1,
    }


def _http_response_bytes(content="", headers=None, status_code="200"):
    response = _http_response(content, headers, status_code)
    response["content"] = content.encode()
    return response


def test_missing_header_can_match_absence_regex():
    sub_step = {
        "response": {
            "condition_type": "or",
            "conditions": {
                "headers": {
                    "Content-Security-Policy": {
                        "regex": "^$",
                        "reverse": False,
                    }
                }
            },
        }
    }

    result = response_conditions_matched(sub_step, _http_response(headers={}))

    assert result["headers"]["Content-Security-Policy"] == [""]


def test_baseline_response_suppresses_identical_catch_all_response():
    response = _http_response(content="same fallback body")
    response["baseline_response"] = _http_response(content="same fallback body")
    sub_step = {
        "response": {
            "condition_type": "and",
            "conditions": {
                "status_code": {
                    "regex": "200",
                    "reverse": False,
                },
                "baseline_response": {
                    "max_content_length_delta": 64,
                },
            },
        }
    }

    assert response_conditions_matched(sub_step, response) == {}


def test_baseline_response_matches_distinct_probe_response():
    response = _http_response(content="real admin page")
    response["baseline_response"] = _http_response(content="same fallback body")
    sub_step = {
        "response": {
            "condition_type": "and",
            "conditions": {
                "status_code": {
                    "regex": "200",
                    "reverse": False,
                },
                "baseline_response": {
                    "max_content_length_delta": 64,
                },
            },
        }
    }

    result = response_conditions_matched(sub_step, response)

    assert result["baseline_response"] == ["content_sha1"]


def test_baseline_followup_request_uses_aiohttp_options(monkeypatch):
    calls = []

    async def fake_send_request(request_options, method):
        calls.append((copy.deepcopy(request_options), method))
        return _http_response_bytes(content="real page" if len(calls) == 1 else "fallback")

    def fake_process_conditions(*_args, **_kwargs):
        return True

    monkeypatch.setattr("nettacker.core.lib.http.send_request", fake_send_request)
    monkeypatch.setattr(HttpEngine, "process_conditions", fake_process_conditions)

    sub_step = {
        "method": "get",
        "timeout": 3,
        "headers": {},
        "allow_redirects": False,
        "ssl": False,
        "url": "http://example.test/admin",
        "response": {
            "condition_type": "and",
            "conditions": {
                "status_code": {
                    "regex": "200",
                    "reverse": False,
                },
                "baseline_response": {
                    "max_content_length_delta": 64,
                },
            },
        },
    }

    assert HttpEngine().run(
        sub_step,
        "admin_scan",
        "example.test",
        "scan-id",
        {
            "http_header": None,
            "retries": 1,
            "user_agent": "Nettacker",
        },
        0,
        0,
        1,
        0,
        1,
    )

    assert calls[0][0]["url"] == "http://example.test/admin"
    assert calls[1][0]["url"].startswith("http://example.test/nettacker-")
    assert "method" not in calls[1][0]
    assert "response" not in calls[1][0]
