import json
from types import SimpleNamespace
from unittest.mock import MagicMock, call, mock_open, patch

import pytest
from flask import Response
from werkzeug.exceptions import BadRequest, Forbidden, NotFound, Unauthorized

import nettacker.api.engine as engine


def make_options(**overrides):
    defaults = {
        "api_access_key": "secret-key",
        "api_access_log": "",
        "api_cert": None,
        "api_cert_key": None,
        "api_client_whitelisted_ips": [],
        "api_debug_mode": False,
        "api_hostname": "127.0.0.1",
        "api_port": 5000,
        "language": "en",
    }
    defaults.update(overrides)
    return SimpleNamespace(**defaults)


def make_report_session(report):
    session = MagicMock()
    session.query.return_value.filter.return_value.first.return_value = report
    return session


@pytest.mark.parametrize(
    ("handler", "error", "status_code", "message"),
    [
        (engine.error_400, BadRequest(description="bad request"), 400, "bad request"),
        (engine.error_401, Unauthorized(description="unauthorized"), 401, "unauthorized"),
        (engine.error_403, Forbidden(description="forbidden"), 403, "forbidden"),
        (engine.error_404, NotFound(), 404, engine._("not_found")),
    ],
)
def test_error_handlers_return_json(handler, error, status_code, message):
    with engine.app.app_context():
        response, actual_status = handler(error)

    assert actual_status == status_code
    assert response.get_json() == {"status": "error", "msg": message}


def test_set_security_headers_adds_defaults_without_overwriting_existing_value():
    response = Response("ok")
    response.headers["X-Frame-Options"] = "DENY"

    updated = engine.set_security_headers(response)

    assert updated.headers["Content-Security-Policy"] == "upgrade-insecure-requests"
    assert updated.headers["Referrer-Policy"] == "no-referrer-when-downgrade"
    assert updated.headers["X-Content-Type-Options"] == "nosniff"
    assert updated.headers["X-Frame-Options"] == "DENY"
    assert updated.headers["X-XSS-Protection"] == "1; mode=block"


def test_limit_remote_addr_enforces_whitelist(api_client):
    engine.app.config["OWASP_NETTACKER_CONFIG"]["api_client_whitelisted_ips"] = ["10.0.0.1"]

    allowed = api_client.get("/session/kill", environ_overrides={"REMOTE_ADDR": "10.0.0.1"})
    denied = api_client.get("/session/kill", environ_overrides={"REMOTE_ADDR": "10.0.0.2"})

    assert allowed.status_code == 200
    assert denied.status_code == 403
    assert denied.get_json() == {"status": "error", "msg": engine._("unauthorized_IP")}
    assert denied.headers["X-Frame-Options"] == "SAMEORIGIN"


def test_access_log_writes_request_details_when_enabled(api_client):
    engine.app.config["OWASP_NETTACKER_CONFIG"]["api_access_log"] = "/tmp/nettacker-api.log"

    with patch("builtins.open", mock_open()) as mocked_open, patch.object(
        engine, "now", return_value="2024-01-02 03:04:05"
    ):
        response = api_client.get(
            "/session/kill",
            headers={"User-Agent": "pytest-agent"},
            environ_overrides={"REMOTE_ADDR": "10.0.0.1"},
        )

    assert response.status_code == 200
    mocked_open.assert_called_once_with("/tmp/nettacker-api.log", "ab")

    handle = mocked_open()
    payload = handle.write.call_args.args[0].decode()

    assert "10.0.0.1 [2024-01-02 03:04:05]" in payload
    assert "pytest-agent" in payload
    assert "/session/kill?" in payload
    assert " 200 " in payload
    handle.close.assert_called_once_with()


@pytest.mark.parametrize(
    ("path", "expected_mimetype"),
    [
        ("assets/app.json", "application/json"),
        ("assets/app.unknown", "text/html"),
    ],
)
def test_get_statics_uses_expected_mimetype(api_client, path, expected_mimetype):
    with patch.object(engine, "get_file", return_value=b"file-data") as mock_get_file:
        response = api_client.get(f"/{path}")

    assert response.status_code == 200
    assert response.data == b"file-data"
    assert response.mimetype == expected_mimetype
    mock_get_file.assert_called_once_with(
        engine.os.path.join(engine.Config.path.web_static_dir, path)
    )


def test_index_renders_template_with_expected_context(api_client):
    with patch.object(engine, "graphs", return_value="GRAPHS"), patch.object(
        engine, "languages_to_country", return_value="LANGUAGES"
    ), patch.object(engine, "profiles", return_value="PROFILES"), patch.object(
        engine, "render_template", return_value="INDEX"
    ) as mock_render_template, patch.object(engine, "scan_methods", return_value="MODULES"):
        response = api_client.get("/")

    assert response.status_code == 200
    assert response.get_data(as_text=True) == "INDEX"
    mock_render_template.assert_called_once_with(
        "index.html",
        selected_modules="MODULES",
        profile="PROFILES",
        languages="LANGUAGES",
        graphs="GRAPHS",
        filename=engine.Config.settings.report_path_filename,
    )


@pytest.mark.parametrize(
    ("report_path_filename", "expected"),
    [
        ("report.html", "report.html"),
        ("report", "report"),
        ("report.exe", False),
        ("", False),
        ("../evil.txt", "evil.txt"),
    ],
)
def test_sanitize_report_path_filename_handles_expected_cases(
    tmp_path, report_path_filename, expected
):
    sanitized = engine.sanitize_report_path_filename(report_path_filename)

    if expected is False:
        assert sanitized is False
    else:
        assert sanitized == tmp_path / expected


def test_sanitize_report_path_filename_rejects_paths_outside_results_dir(tmp_path):
    with patch.object(type(tmp_path), "is_relative_to", return_value=False):
        assert engine.sanitize_report_path_filename("report.html") is False


@pytest.mark.parametrize("path", ["/session/check", "/results/get_list"])
def test_protected_routes_require_api_key(api_client, path):
    response = api_client.get(path)

    assert response.status_code == 401
    assert response.get_json() == {"status": "error", "msg": engine._("API_invalid")}
    assert response.headers["X-Frame-Options"] == "SAMEORIGIN"


def test_session_check_returns_ok_for_valid_api_key(api_client, api_key):
    response = api_client.get("/session/check", query_string={"key": api_key})

    assert response.status_code == 200
    assert response.get_json() == {"status": "ok", "msg": engine._("browser_session_valid")}
    assert response.headers["Content-Security-Policy"] == "upgrade-insecure-requests"


def test_session_set_sets_cookie_with_secure_flags(api_client, api_key):
    response = api_client.get("/session/set", query_string={"key": api_key})

    assert response.status_code == 200
    assert response.get_json() == {"status": "ok", "msg": engine._("browser_session_valid")}
    assert "key=test-key" in response.headers["Set-Cookie"]
    assert "HttpOnly" in response.headers["Set-Cookie"]
    assert "SameSite=Lax" in response.headers["Set-Cookie"]
    assert "Secure" in response.headers["Set-Cookie"]


def test_session_kill_expires_cookie(api_client):
    response = api_client.get("/session/kill")

    assert response.status_code == 200
    assert response.get_json() == {"status": "ok", "msg": engine._("browser_session_killed")}
    assert "key=" in response.headers["Set-Cookie"]
    assert "Expires=Thu, 01 Jan 1970" in response.headers["Set-Cookie"]


def test_new_scan_rejects_invalid_report_filename(api_client, api_key):
    with patch.object(engine, "Nettacker") as mock_nettacker, patch.object(
        engine, "Thread"
    ) as mock_thread:
        response = api_client.post(
            "/new/scan",
            query_string={"key": api_key},
            data={"report_path_filename": "scan.exe"},
        )

    assert response.status_code == 400
    assert response.get_json() == {"status": "error", "msg": "Invalid report filename"}
    mock_nettacker.assert_not_called()
    mock_thread.assert_not_called()


def test_new_scan_starts_thread_and_merges_defaults(api_client, api_key, tmp_path):
    created = {}

    def nettacker_factory(*, api_arguments):
        nettacker_app = MagicMock()
        nettacker_app.arguments = api_arguments
        nettacker_app.run = MagicMock()
        created["app"] = nettacker_app
        return nettacker_app

    with patch.object(
        engine, "Nettacker", side_effect=nettacker_factory
    ) as mock_nettacker, patch.object(engine, "Thread") as mock_thread:
        response = api_client.post(
            "/new/scan",
            query_string={"key": api_key},
            data={
                "http_header": "X-Test: 1\n\nAccept: application/json\n",
                "report_path_filename": "scan.json",
                "skip_service_discovery": "true",
                "targets": "example.com",
            },
        )

    arguments = created["app"].arguments

    assert response.status_code == 200
    assert response.get_json()["targets"] == "example.com"
    assert arguments.http_header == ["X-Test: 1", "Accept: application/json"]
    assert arguments.language == engine.nettacker_application_config["language"]
    assert arguments.report_path_filename == str(tmp_path / "scan.json")
    assert arguments.skip_service_discovery is True
    assert engine.app.config["OWASP_NETTACKER_CONFIG"]["options"] is arguments
    mock_nettacker.assert_called_once()
    mock_thread.assert_called_once_with(target=created["app"].run)
    mock_thread.return_value.start.assert_called_once_with()


def test_new_scan_without_http_header_keeps_skip_service_discovery_false(
    api_client, api_key, tmp_path
):
    created = {}

    def nettacker_factory(*, api_arguments):
        nettacker_app = MagicMock()
        nettacker_app.arguments = api_arguments
        nettacker_app.run = MagicMock()
        created["app"] = nettacker_app
        return nettacker_app

    with patch.object(engine, "Nettacker", side_effect=nettacker_factory), patch.object(
        engine, "Thread"
    ) as mock_thread:
        response = api_client.post(
            "/new/scan",
            query_string={"key": api_key},
            data={
                "report_path_filename": "scan.txt",
                "targets": "127.0.0.1",
            },
        )

    arguments = created["app"].arguments

    assert response.status_code == 200
    assert arguments.report_path_filename == str(tmp_path / "scan.txt")
    assert arguments.skip_service_discovery is False
    assert arguments.http_header is None
    mock_thread.return_value.start.assert_called_once_with()


def test_compare_scans_success_uses_generated_default_path(api_client, api_key):
    with patch.object(
        engine, "create_compare_report", return_value=True
    ) as mock_compare, patch.object(
        engine, "generate_compare_filepath", return_value="compare.html"
    ) as mock_generate:
        response = api_client.post(
            "/compare/scans",
            query_string={"key": api_key},
            data={"scan_id_first": "scan-1", "scan_id_second": "scan-2"},
        )

    assert response.status_code == 200
    assert response.get_json() == {"status": "success", "msg": "scan_comparison_completed"}
    mock_generate.assert_called_once_with("scan-1")
    mock_compare.assert_called_once_with(
        {"scan_compare_id": "scan-2", "compare_report_path_filename": "compare.html"},
        "scan-1",
    )


def test_compare_scans_returns_400_for_missing_scan_ids(api_client, api_key):
    response = api_client.post(
        "/compare/scans",
        query_string={"key": api_key},
        data={"scan_id_first": "scan-1"},
    )

    assert response.status_code == 400
    assert response.get_json() == {"status": "error", "msg": "Invalid Scan IDs"}


def test_compare_scans_returns_404_when_scan_ids_are_not_found(api_client, api_key):
    with patch.object(engine, "create_compare_report", return_value=False) as mock_compare:
        response = api_client.post(
            "/compare/scans",
            query_string={"key": api_key},
            data={
                "compare_report_path": "chosen.html",
                "scan_id_first": "scan-1",
                "scan_id_second": "scan-2",
            },
        )

    assert response.status_code == 404
    assert response.get_json() == {"status": "error", "msg": "Scan ID not found"}
    mock_compare.assert_called_once_with(
        {"scan_compare_id": "scan-2", "compare_report_path_filename": "chosen.html"},
        "scan-1",
    )


@pytest.mark.parametrize("error_type", [FileNotFoundError, PermissionError, IOError])
def test_compare_scans_returns_400_for_invalid_report_paths(api_client, api_key, error_type):
    with patch.object(engine, "create_compare_report", side_effect=error_type):
        response = api_client.post(
            "/compare/scans",
            query_string={"key": api_key},
            data={
                "compare_report_path": "broken.html",
                "scan_id_first": "scan-1",
                "scan_id_second": "scan-2",
            },
        )

    assert response.status_code == 400
    assert response.get_json() == {"status": "error", "msg": "Invalid file path"}


def test_get_results_uses_default_and_selected_page(api_client, api_key):
    with patch.object(
        engine, "select_reports", side_effect=lambda page: [{"page": page}]
    ) as mock_select:
        default_page = api_client.get("/results/get_list", query_string={"key": api_key})
        selected_page = api_client.get(
            "/results/get_list",
            query_string={"key": api_key, "page": 3},
        )

    assert default_page.status_code == 200
    assert default_page.get_json() == [{"page": 1}]
    assert selected_page.status_code == 200
    assert selected_page.get_json() == [{"page": 3}]
    assert mock_select.call_args_list == [call(1), call(3)]


def test_get_last_host_logs_uses_default_and_selected_page(api_client, api_key):
    with patch.object(
        engine, "last_host_logs", side_effect=lambda page: [{"page": page}]
    ) as mock_logs:
        default_page = api_client.get("/logs/get_list", query_string={"key": api_key})
        selected_page = api_client.get(
            "/logs/get_list",
            query_string={"key": api_key, "page": 2},
        )

    assert default_page.status_code == 200
    assert default_page.get_json() == [{"page": 1}]
    assert selected_page.status_code == 200
    assert selected_page.get_json() == [{"page": 2}]
    assert mock_logs.call_args_list == [call(1), call(2)]


def test_get_result_content_requires_scan_id(api_client, api_key):
    response = api_client.get("/results/get", query_string={"key": api_key})

    assert response.status_code == 400
    assert response.get_json() == {"status": "error", "msg": engine._("invalid_scan_id")}


def test_get_result_content_handles_database_errors(api_client, api_key):
    with patch.object(engine, "get_scan_result", side_effect=Exception("database failed")):
        response = api_client.get(
            "/results/get",
            query_string={"id": "scan-1", "key": api_key},
        )

    assert response.status_code == 500
    assert response.get_json() == {"status": "error", "msg": "database error!"}


def test_get_result_content_returns_attachment_with_expected_mimetype(api_client, api_key):
    with patch.object(
        engine, "get_scan_result", return_value=("/tmp/report.json", b'{"ok": true}')
    ):
        response = api_client.get(
            "/results/get",
            query_string={"id": "scan-1", "key": api_key},
        )

    assert response.status_code == 200
    assert response.data == b'{"ok": true}'
    assert response.mimetype == "application/json"
    assert response.headers["Content-Disposition"] == "attachment;filename=report.json"


def test_get_results_json_requires_scan_id(api_client, api_key):
    with patch.object(engine, "create_connection", return_value=MagicMock()) as mock_connection:
        response = api_client.get("/results/get_json", query_string={"key": api_key})

    assert response.status_code == 400
    assert response.get_json() == {"status": "error", "msg": engine._("invalid_scan_id")}
    mock_connection.assert_called_once_with()


def test_get_results_json_returns_attachment(api_client, api_key):
    report = SimpleNamespace(scan_unique_id="scan-1", report_path_filename=".report.html")
    session = make_report_session(report)
    data = [{"host": "example.com", "port": 443}]

    with patch.object(engine, "create_connection", return_value=session), patch.object(
        engine, "get_logs_by_scan_id", return_value=data
    ) as mock_logs:
        response = api_client.get(
            "/results/get_json",
            query_string={"id": "result-1", "key": api_key},
        )

    assert response.status_code == 200
    assert json.loads(response.get_data(as_text=True)) == data
    assert response.mimetype == "application/json"
    assert response.headers["Content-Disposition"] == "attachment;filename=report.json"
    mock_logs.assert_called_once_with("scan-1")
    session.query.assert_called_once_with(engine.Report)


def test_get_results_csv_requires_scan_id(api_client, api_key):
    with patch.object(engine, "create_connection", return_value=MagicMock()) as mock_connection:
        response = api_client.get("/results/get_csv", query_string={"key": api_key})

    assert response.status_code == 400
    assert response.get_json() == {"status": "error", "msg": engine._("invalid_scan_id")}
    mock_connection.assert_called_once_with()


def test_get_results_csv_returns_attachment(api_client, api_key):
    report = SimpleNamespace(scan_unique_id="scan-1", report_path_filename=".report.html")
    session = make_report_session(report)
    data = [{"host": "example.com", "result": "ok"}]
    writer = MagicMock()

    with patch.object(engine, "create_connection", return_value=session), patch.object(
        engine, "get_logs_by_scan_id", return_value=data
    ), patch("builtins.open", mock_open(read_data="host,result\nexample.com,ok\n")), patch.object(
        engine.csv, "DictWriter", return_value=writer
    ) as mock_writer:
        response = api_client.get(
            "/results/get_csv",
            query_string={"id": "result-1", "key": api_key},
        )

    assert response.status_code == 200
    assert response.get_data(as_text=True) == "host,result\nexample.com,ok\n"
    assert response.mimetype == "text/csv"
    assert response.headers["Content-Disposition"] == "attachment;filename=report.csv"
    assert list(mock_writer.call_args.kwargs["fieldnames"]) == ["host", "result"]
    assert mock_writer.call_args.kwargs["quoting"] == engine.csv.QUOTE_ALL
    writer.writeheader.assert_called_once_with()
    writer.writerow.assert_called_once_with({"host": "example.com", "result": "ok"})


def test_get_logs_html_returns_rendered_report(api_client, api_key):
    with patch.object(
        engine, "logs_to_report_html", return_value="<h1>report</h1>"
    ) as mock_report:
        response = api_client.get(
            "/logs/get_html",
            query_string={"key": api_key, "target": "example.com"},
        )

    assert response.status_code == 200
    assert response.get_data(as_text=True) == "<h1>report</h1>"
    mock_report.assert_called_once_with("example.com")


def test_get_logs_returns_deterministic_json_attachment(api_client, api_key):
    data = [{"host": "example.com", "status": "ok"}]

    with patch.object(engine, "logs_to_report_json", return_value=data) as mock_logs, patch.object(
        engine, "now", return_value="2024_01_02_03_04_05"
    ), patch.object(engine.random, "choice", side_effect=lambda _: "a"):
        response = api_client.get(
            "/logs/get_json",
            query_string={"key": api_key, "target": "example.com"},
        )

    assert response.status_code == 200
    assert json.loads(response.get_data(as_text=True)) == data
    assert response.mimetype == "application/json"
    assert (
        response.headers["Content-Disposition"]
        == "attachment;filename=report-2024_01_02_03_04_05aaaaaaaaaa.json"
    )
    mock_logs.assert_called_once_with("example.com")


def test_get_logs_csv_returns_deterministic_csv_attachment(api_client, api_key):
    data = [{"host": "example.com", "status": "ok"}]
    writer = MagicMock()

    with patch.object(engine, "logs_to_report_json", return_value=data) as mock_logs, patch.object(
        engine, "now", return_value="2024_01_02_03_04_05"
    ), patch.object(engine.random, "choice", side_effect=lambda _: "a"), patch(
        "builtins.open",
        mock_open(read_data="host,status\nexample.com,ok\n"),
    ), patch.object(engine.csv, "DictWriter", return_value=writer) as mock_writer:
        response = api_client.get(
            "/logs/get_csv",
            query_string={"key": api_key, "target": "example.com"},
        )

    assert response.status_code == 200
    assert response.get_data(as_text=True) == "host,status\nexample.com,ok\n"
    assert response.mimetype == "text/csv"
    assert (
        response.headers["Content-Disposition"]
        == "attachment;filename=report-2024_01_02_03_04_05aaaaaaaaaa.csv"
    )
    assert list(mock_writer.call_args.kwargs["fieldnames"]) == ["host", "status"]
    assert mock_writer.call_args.kwargs["quoting"] == engine.csv.QUOTE_ALL
    writer.writeheader.assert_called_once_with()
    writer.writerow.assert_called_once_with({"host": "example.com", "status": "ok"})
    mock_logs.assert_called_once_with("example.com")


def test_go_for_search_logs_normalizes_positive_page_numbers(api_client, api_key):
    with patch.object(engine, "search_logs", return_value=[{"query": "ssh"}]) as mock_search:
        response = api_client.get(
            "/logs/search",
            query_string={"key": api_key, "page": 2, "q": "ssh"},
        )

    assert response.status_code == 200
    assert response.get_json() == [{"query": "ssh"}]
    mock_search.assert_called_once_with(1, "ssh")


def test_go_for_search_logs_falls_back_for_invalid_page_and_missing_query(api_client, api_key):
    with patch.object(engine, "search_logs", return_value=[{"query": ""}]) as mock_search:
        response = api_client.get(
            "/logs/search",
            query_string={"key": api_key, "page": "bogus"},
        )

    assert response.status_code == 200
    assert response.get_json() == [{"query": ""}]
    mock_search.assert_called_once_with(0, "")


def test_go_for_search_logs_keeps_non_positive_pages(api_client, api_key):
    with patch.object(engine, "search_logs", return_value=[{"page": 0}]) as mock_search:
        response = api_client.get(
            "/logs/search",
            query_string={"key": api_key, "page": 0, "q": "ssh"},
        )

    assert response.status_code == 200
    assert response.get_json() == [{"page": 0}]
    mock_search.assert_called_once_with(0, "ssh")


def test_go_for_search_logs_falls_back_when_query_lookup_raises(api_key):
    original_get_value = engine.get_value

    def fake_get_value(flask_request, key):
        if key == "q":
            raise RuntimeError("boom")
        return original_get_value(flask_request, key)

    with engine.app.test_request_context("/logs/search?key=test-key&page=1"), patch.object(
        engine, "get_value", side_effect=fake_get_value
    ), patch.object(engine, "search_logs", return_value=[{"query": ""}]) as mock_search:
        response, status_code = engine.go_for_search_logs()

    assert status_code == 200
    assert response.get_json() == [{"query": ""}]
    mock_search.assert_called_once_with(0, "")


@pytest.mark.parametrize(
    ("options", "ssl_context"),
    [
        (make_options(), "adhoc"),
        (make_options(api_cert="cert.pem", api_cert_key="key.pem"), ("cert.pem", "key.pem")),
    ],
)
def test_start_api_subprocess_uses_expected_ssl_context(options, ssl_context):
    with patch.object(engine.app, "run") as mock_run:
        engine.start_api_subprocess(options)

    assert engine.app.config["OWASP_NETTACKER_CONFIG"]["api_access_key"] == options.api_access_key
    assert engine.app.config["OWASP_NETTACKER_CONFIG"]["options"] is options
    mock_run.assert_called_once_with(
        host=options.api_hostname,
        port=options.api_port,
        debug=options.api_debug_mode,
        use_reloader=False,
        ssl_context=ssl_context,
        threaded=True,
    )


def test_start_api_subprocess_reports_run_failures():
    options = make_options()

    with patch.object(engine.app, "run", side_effect=RuntimeError("boom")), patch.object(
        engine, "die_failure"
    ) as mock_die_failure:
        engine.start_api_subprocess(options)

    mock_die_failure.assert_called_once_with("boom")


def test_start_api_server_starts_process_and_logs_key():
    options = make_options(api_access_key="secret-key", api_port=8080)
    process = MagicMock()

    with patch.object(engine, "_", return_value="API {} {}"), patch.object(
        engine.log, "write_to_api_console"
    ) as mock_log, patch.object(
        engine.multiprocessing, "Process", return_value=process
    ) as mock_process, patch.object(engine.multiprocessing, "active_children", return_value=[]):
        engine.start_api_server(options)

    mock_log.assert_called_once_with("API 8080 secret-key")
    mock_process.assert_called_once_with(target=engine.start_api_subprocess, args=(options,))
    process.start.assert_called_once_with()


def test_start_api_server_terminates_children_on_keyboard_interrupt():
    options = make_options()
    process = MagicMock()
    child_one = MagicMock()
    child_two = MagicMock()

    with patch.object(engine, "_", return_value="API {} {}"), patch.object(
        engine.log, "write_to_api_console"
    ), patch.object(engine.multiprocessing, "Process", return_value=process), patch.object(
        engine.multiprocessing,
        "active_children",
        side_effect=[[child_one], [child_one, child_two]],
    ), patch.object(engine.time, "sleep", side_effect=KeyboardInterrupt):
        engine.start_api_server(options)

    process.start.assert_called_once_with()
    child_one.terminate.assert_called_once_with()
    child_two.terminate.assert_called_once_with()
