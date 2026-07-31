import os
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


@patch(
    "nettacker.api.engine.get_logs_by_scan_id",
    return_value=[{"target": "example.com", "date": "2026-01-01"}],
)
@patch("nettacker.api.engine.create_connection")
def test_get_results_csv_filename_and_no_disk_write(
    mock_create_connection, mock_get_logs, client, tmp_path
):
    """The download filename must keep every character of the report name, and
    the CSV must be built in memory rather than left behind on disk."""
    scan_details = MagicMock(
        scan_unique_id="abc", report_path_filename="/tmp/results/nettacker.html"
    )
    session = MagicMock()
    session.query.return_value.filter.return_value.first.return_value = scan_details
    mock_create_connection.return_value = session

    cwd = os.getcwd()
    os.chdir(tmp_path)
    try:
        response = client.get(f"/results/get_csv?id=1&key={API_KEY}")
        leftovers = list(tmp_path.iterdir())
    finally:
        os.chdir(cwd)

    assert response.status_code == 200
    assert response.headers["Content-Disposition"] == "attachment;filename=nettacker.csv"
    assert leftovers == []


@patch(
    "nettacker.api.engine.get_logs_by_scan_id",
    return_value=[{"target": "example.com"}],
)
@patch("nettacker.api.engine.create_connection")
def test_get_results_json_filename(mock_create_connection, mock_get_logs, client):
    """Same for the JSON endpoint: a dotted directory must not truncate the name."""
    scan_details = MagicMock(
        scan_unique_id="abc", report_path_filename="/home/user/.nettacker/results/scan.html"
    )
    session = MagicMock()
    session.query.return_value.filter.return_value.first.return_value = scan_details
    mock_create_connection.return_value = session

    response = client.get(f"/results/get_json?id=1&key={API_KEY}")

    assert response.status_code == 200
    assert response.headers["Content-Disposition"] == "attachment;filename=scan.json"
