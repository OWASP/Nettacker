"""Check the GPUStack module's request and response conditions."""

from copy import deepcopy
from pathlib import Path

import pytest
import yaml

from nettacker.core.lib.http import response_conditions_matched

MODULE = Path("nettacker/modules/vuln/gpustack_cve_2026_102895.yaml")


def load_step():
    return yaml.safe_load(MODULE.read_text())["payloads"][0]["steps"][0]


def response(
    status="200",
    content='{"items":[{"username":"admin","is_admin":true}]}',
    content_type="application/json",
):
    return {"status_code": status, "content": content, "headers": {"content-type": content_type}}


def test_read_only_probe():
    step = load_step()
    assert step["method"] == "get"
    assert step["allow_redirects"] is False
    assert step["headers"]["X-GPUStack-Real-IP"] == "127.0.0.1"
    assert not {"Authorization", "Cookie"} & step["headers"].keys()
    assert not {"data", "json"} & step.keys()
    assert step["url"]["nettacker_fuzzer"]["data"]["paths"] == ["/v2/users"]


@pytest.mark.parametrize(
    "content_type", ["application/json", "application/json; charset=utf-8", "Application/JSON"]
)
@pytest.mark.parametrize(
    "content",
    [
        '{"items":[{"username":"admin","is_admin":true}]}',
        '{"items": [{"is_admin" : true, "username": "renamed"}]}',
        '{"items":[{"username":"user","is_admin":false},{"username":"admin","is_admin":true}]}',
        '{"items":[{"username":"admin","is_admin":true,"full_name":"A ] { user"}]}',
        '{"items":[{"username":"ad\\"min","is_admin":true}]}',
        '{"items":[{"id":1,"username":"admin","is_active":true,"is_admin":true,"role":null}]}',
    ],
)
def test_admin_response_matches(content_type, content):
    assert response_conditions_matched(
        load_step(), response(content=content, content_type=content_type)
    )


@pytest.mark.parametrize(
    "reply",
    [
        response(status="401"),
        response(status="403"),
        response(status="302"),
        response(status="500"),
        response(status="2000"),
        response(content='{"items":[]}'),
        response(content='{"items":[],"unrelated":{"username":"admin","is_admin":true}}'),
        response(content='{"items":[{"username":"admin","is_admin":true BROKEN}'),
        response(content='{"items":[{"username":"admin",,"is_admin":true}]}'),
        response(content='{"items":[{"username":"admin","is_admin":true,}]}'),
        response(content='{"items":[{"username":"admin" "is_admin":true}]}'),
        response(content='{"items":[{"username":"admin","is_admin":true,"is_admin":false}]}'),
        response(content='{"items":[{"username":"admin","username":"","is_admin":true}]}'),
        response(content='{"items":[{"username":"","is_admin":true}]}'),
        response(content='{"items":[{"note":"\\"username\\":\\"admin\\",\\"is_admin\\":true"}]}'),
        response(content='{"items":[{"username":"admin","profile":{},"is_admin":true}]}'),
        response(content='{"items":[{"username":"admin","is_admin":true}'),
        response(content='{"is_admin":true}'),
        response(content='{"items":[{"is_admin":true}]}'),
        response(content='{"items":[{"username":"admin"}],"is_admin":true}'),
        response(content='{"items":[{"username":"admin","is_admin":false},{"is_admin":true}]}'),
        response(content='{"items":[{"is_admin":false}]}'),
        response(content='{"is_admin":"true"}'),
        response(content='{"is_admin":trueish}'),
        response(content_type="text/html"),
        response(content_type="application/jsonp"),
        {"status_code": "200", "content": '{"is_admin":true}', "headers": {}},
    ],
)
def test_non_admin_or_error_response_does_not_match(reply):
    assert not response_conditions_matched(load_step(), deepcopy(reply))


@pytest.mark.asyncio
@pytest.mark.parametrize("status", [200, 401, 403])
async def test_probe_against_local_http_server(status):
    from aiohttp import web

    from nettacker.core.lib.http import send_request

    requests = []

    async def users(request):
        requests.append((request.method, request.headers.get("X-GPUStack-Real-IP")))
        if status == 200:
            return web.json_response({"items": [{"username": "admin", "is_admin": True}]})
        return web.json_response({"message": "unauthorized"}, status=status)

    app = web.Application()
    app.router.add_get("/v2/users", users)
    runner = web.AppRunner(app)
    await runner.setup()
    site = web.TCPSite(runner, "127.0.0.1", 0)
    await site.start()
    try:
        port = runner.addresses[0][1]
        step = load_step()
        options = {
            key: value for key, value in step.items() if key not in {"response", "url", "method"}
        }
        options["url"] = f"http://127.0.0.1:{port}/v2/users"
        options["headers"] = dict(options["headers"], **{"User-Agent": "Nettacker test"})
        reply = await send_request(options, step["method"])
        reply["content"] = reply["content"].decode()
        assert bool(response_conditions_matched(step, reply)) is (status == 200)
        assert requests == [("GET", "127.0.0.1")]
    finally:
        await runner.cleanup()
