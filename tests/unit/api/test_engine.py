from unittest.mock import MagicMock, patch

import pytest

from nettacker.api.engine import app, strip_crlf

API_KEY = "test_key"


@pytest.fixture
def client():
    original_config = {key: app.config.get(key) for key in ("OWASP_NETTACKER_CONFIG", "TESTING")}
    app.config["OWASP_NETTACKER_CONFIG"] = {
        "api_access_key": API_KEY,
        "api_client_whitelisted_ips": [],
        "api_access_log": False,
    }
    app.config["TESTING"] = True
    try:
        with app.test_client() as client:
            yield client
    finally:
        for key, value in original_config.items():
            if value is None:
                app.config.pop(key, None)
            else:
                app.config[key] = value


@patch("nettacker.api.engine.get_logs_by_scan_id", return_value=[])
@patch("nettacker.api.engine.create_connection")
def test_get_results_csv_empty_data(mock_create_connection, mock_get_logs, client):
    client.set_cookie("key", API_KEY)
    """A scan with no logged events must return 404, not crash with IndexError."""
    scan_details = MagicMock(scan_unique_id="abc", report_path_filename=".report.html")
    session = MagicMock()
    session.query.return_value.filter.return_value.first.return_value = scan_details
    mock_create_connection.return_value = session

    response = client.get("/results/get_csv?id=1")

    assert response.status_code == 404
    assert response.json["status"] == "error"
    assert response.json["msg"] == "No scan data found"


@patch("nettacker.api.engine.logs_to_report_json", return_value=[])
def test_get_logs_csv_empty_data(mock_logs_to_report_json, client):
    """A target with no logged events must return 404, not crash with IndexError."""
    client.set_cookie("key", API_KEY)
    response = client.get("/logs/get_csv?target=example.com")

    assert response.status_code == 404
    assert response.json["status"] == "error"
    assert response.json["msg"] == "No scan data found"


def test_api_key_in_query_string_is_rejected(client):
    """The API key must not be accepted from the URL (it is written to access logs)."""
    response = client.get(f"/session/check?key={API_KEY}")

    assert response.status_code == 401
    assert response.json["status"] == "error"


def test_api_key_in_post_body_is_accepted(client):
    response = client.post("/session/set", data={"key": API_KEY})

    assert response.status_code == 200
    assert "key=" in response.headers.get("Set-Cookie", "")


def test_api_key_in_cookie_is_accepted(client):
    client.set_cookie("key", API_KEY)
    response = client.get("/session/check")

    assert response.status_code == 200


def test_strip_crlf_removes_line_breaks():
    assert strip_crlf("GET /x\r\nFAKE 127.0.0.1") == "GET /xFAKE 127.0.0.1"
    assert strip_crlf(None) == ""


def test_access_log_strips_crlf(client, tmp_path):
    log_file = tmp_path / "access.log"
    app.config["OWASP_NETTACKER_CONFIG"]["api_access_log"] = str(log_file)

    client.get("/session/check%0D%0Ainjected-line")

    lines = log_file.read_bytes().split(b"\r\n")
    assert lines[-1] == b""
    assert len(lines) == 2
    assert b"/session/checkinjected-line" in lines[0]
