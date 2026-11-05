from types import SimpleNamespace
from unittest.mock import MagicMock, patch

import pytest

from nettacker.api.engine import app, describe_targets

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


@patch("nettacker.api.engine.queue_scan")
@patch("nettacker.api.engine.Nettacker")
def test_new_scan_queues_scan_and_returns_its_id(mock_nettacker, mock_queue_scan, client):
    mock_nettacker.return_value.arguments = SimpleNamespace(targets=["example.com"])
    mock_queue_scan.return_value = "scan_1"

    response = client.post(
        f"/new/scan?key={API_KEY}",
        data={"targets": "example.com", "report_path_filename": "report.html"},
    )

    assert response.status_code == 200
    assert response.json == {"scan_id": "scan_1", "targets": ["example.com"]}
    mock_queue_scan.assert_called_once_with(mock_nettacker.return_value, "example.com")


@pytest.mark.parametrize(
    "scan_options, description",
    [
        ({"targets": "a.test"}, "a.test"),
        ({"targets": "a.test, b.test"}, "a.test, b.test"),
        ({"targets": "a.test,b.test,c.test,d.test"}, "a.test, b.test and 2 more"),
        ({"targets": None, "targets_list": "/tmp/0f3a_targets_list_hosts.txt"}, "hosts.txt"),
    ],
)
def test_describe_targets(scan_options, description):
    assert describe_targets(scan_options) == description


@patch("nettacker.api.engine.get_scans")
def test_scans_status_lists_the_scan_queue(mock_get_scans, client):
    scans = [{"scan_id": "abc", "status": "running"}]
    mock_get_scans.return_value = scans

    response = client.get(f"/scans/status?key={API_KEY}")

    assert response.status_code == 200
    assert response.json == scans


def test_scans_status_requires_api_key(client):
    response = client.get("/scans/status")

    assert response.status_code == 401
