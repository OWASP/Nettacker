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


@patch("nettacker.api.engine.get_scan_result", side_effect=Exception("db boom"))
def test_get_result_content_logs_and_returns_500_on_failure(mock_get_scan_result, client):
    """Regression test for issue #1711.

    get_scan_result() failures used to be swallowed by a bare `except Exception`
    without any log. The endpoint must still return 500, but the failure must
    now be recorded via logger.error instead of being silent.
    """
    with patch("nettacker.api.engine.log") as mock_logger:
        response = client.get(f"/results/get?id=1&key={API_KEY}")

    assert response.status_code == 500
    assert response.json["status"] == "error"
    mock_logger.error.assert_called_once()


@patch("nettacker.api.engine.search_logs", return_value=[])
@patch("nettacker.api.engine.get_value", side_effect=[ValueError("not an int"), "ssh"])
def test_search_logs_invalid_page_is_logged_and_defaults(
    mock_get_value, mock_search_logs, client
):
    """Regression test for issue #1711.

    A non-integer `page` used to be caught by a bare `except Exception` that
    silently defaulted to 0. It must still default to 0, but the bad value must
    now be logged via logger.error. The second get_value (query) still returns
    a normal value so only the page failure is logged.
    """
    with patch("nettacker.api.engine.log") as mock_logger:
        response = client.get(f"/logs/search?q=ssh&key={API_KEY}")

    assert response.status_code == 200
    mock_logger.error.assert_called_once()
