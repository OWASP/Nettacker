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
@patch("nettacker.api.engine.get_logs_by_scan_id")
def test_get_results_json_filename_without_path_corruption(
    mock_get_logs, mock_create_connection, client
):
    """Report download filenames should be generated safely on Windows-style paths."""
    scan_details = MagicMock(
        scan_unique_id="abc", report_path_filename=r"C:\\tmp\\reports\\scan.2.0.html"
    )
    session = MagicMock()
    session.query.return_value.filter.return_value.first.return_value = scan_details
    mock_create_connection.return_value = session
    mock_get_logs.return_value = [{"field": "value"}]

    response = client.get(f"/results/get_json?id=1&key={API_KEY}")

    assert response.status_code == 200
    assert response.headers["Content-Disposition"] == "attachment;filename=scan.2.0.json"
    assert response.get_data(as_text=True) == '[{"field": "value"}]'


@patch("nettacker.api.engine.create_connection")
@patch("nettacker.api.engine.get_logs_by_scan_id")
def test_get_results_csv_generates_content_without_tempfile(
    mock_get_logs, mock_create_connection, client
):
    """CSV report downloads should be generated in-memory and avoid temp files."""
    scan_details = MagicMock(scan_unique_id="abc", report_path_filename="report.2026.html")
    session = MagicMock()
    session.query.return_value.filter.return_value.first.return_value = scan_details
    mock_create_connection.return_value = session
    mock_get_logs.return_value = [{"field": "value"}]

    with patch("nettacker.api.engine.open") as mock_open:
        response = client.get(f"/results/get_csv?id=1&key={API_KEY}")

        assert response.status_code == 200
        assert response.headers["Content-Disposition"] == "attachment;filename=report.2026.csv"
        assert '"field"' in response.get_data(as_text=True)
        assert mock_open.call_count == 0


@patch("nettacker.api.engine.create_connection")
def test_get_results_json_missing_scan_returns_invalid_scan_id(mock_create_connection, client):
    """Missing scan rows should return a clear invalid_scan_id response."""
    session = MagicMock()
    session.query.return_value.filter.return_value.first.return_value = None
    mock_create_connection.return_value = session

    response = client.get(f"/results/get_json?id=99&key={API_KEY}")

    assert response.status_code == 400
    assert response.json["status"] == "error"
    assert response.json["msg"] == "your scan id is not valid!"
