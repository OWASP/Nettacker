from unittest.mock import MagicMock, patch

import pytest

from nettacker.api.engine import app

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
    """A scan with no logged events must return 404, not crash with IndexError."""
    scan_details = MagicMock(scan_unique_id="abc", report_path_filename=".report.html")
    session = MagicMock()
    session.query.return_value.filter.return_value.first.return_value = scan_details
    mock_create_connection.return_value = session

    response = client.get(f"/results/get_csv?id=1&key={API_KEY}")

    assert response.status_code == 404
    assert response.json["status"] == "error"
    assert response.json["msg"] == "No scan data found"


@patch("nettacker.api.engine.logs_to_report_json", return_value=[])
def test_get_logs_csv_empty_data(mock_logs_to_report_json, client):
    """A target with no logged events must return 404, not crash with IndexError."""
    response = client.get(f"/logs/get_csv?target=example.com&key={API_KEY}")

    assert response.status_code == 404
    assert response.json["status"] == "error"
    assert response.json["msg"] == "No scan data found"


@patch("nettacker.api.engine.create_connection")
def test_get_results_json_nonexistent_scan(mock_create_connection, client):
    """A nonexistent scan ID in /results/get_json must return 404."""
    session = MagicMock()
    session.query.return_value.filter.return_value.first.return_value = None
    mock_create_connection.return_value = session

    response = client.get(f"/results/get_json?id=9999&key={API_KEY}")

    assert response.status_code == 404
    assert response.json["status"] == "error"
    assert response.json["msg"] == "No scan data found"


@patch("nettacker.api.engine.create_connection")
def test_get_results_csv_nonexistent_scan(mock_create_connection, client):
    """A nonexistent scan ID in /results/get_csv must return 404."""
    session = MagicMock()
    session.query.return_value.filter.return_value.first.return_value = None
    mock_create_connection.return_value = session

    response = client.get(f"/results/get_csv?id=9999&key={API_KEY}")

    assert response.status_code == 404
    assert response.json["status"] == "error"
    assert response.json["msg"] == "No scan data found"


@patch("nettacker.api.engine.get_scan_result", return_value=None)
def test_get_result_content_not_found(mock_get_scan_result, client):
    """A nonexistent scan ID in /results/get must return 404."""
    response = client.get(f"/results/get?id=9999&key={API_KEY}")

    assert response.status_code == 404
    assert response.json["status"] == "error"
    assert response.json["msg"] == "No scan data found"


def test_get_last_host_logs_invalid_page(client):
    """Invalid page parameter in /logs/get_list must return 400 Bad Request."""
    response = client.get(f"/logs/get_list?page=invalid&key={API_KEY}")

    assert response.status_code == 400
    assert response.json["status"] == "error"
    assert response.json["msg"] == "Invalid page number"


def test_select_reports_invalid_page(client):
    """Invalid page parameter in /results/get_list must return 400 Bad Request."""
    response = client.get(f"/results/get_list?page=invalid&key={API_KEY}")

    assert response.status_code == 400
    assert response.json["status"] == "error"
    assert response.json["msg"] == "Invalid page number"
