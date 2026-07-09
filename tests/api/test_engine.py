from unittest.mock import patch

from nettacker.api.engine import app

API_KEY = "test_key"


def _client():
    app.config["OWASP_NETTACKER_CONFIG"] = {
        "api_access_key": API_KEY,
        "api_client_whitelisted_ips": [],
        "api_access_log": "",
    }
    app.config["TESTING"] = True
    return app.test_client()


class TestGetResultContent:
    """Tests for the /results/get endpoint."""

    def test_html_inline_with_csp(self):
        client = _client()
        with patch("nettacker.api.engine.get_scan_result") as mock:
            mock.return_value = ("/results/report.html", b"<html></html>")
            resp = client.get(f"/results/get?key={API_KEY}&id=1")

        assert resp.status_code == 200
        assert "inline" in resp.headers["Content-Disposition"]
        assert "report.html" in resp.headers["Content-Disposition"]
        assert "Content-Security-Policy" in resp.headers
        csp = resp.headers["Content-Security-Policy"]
        assert "sandbox allow-scripts" in csp
        assert "frame-ancestors 'none'" in csp

    def test_htm_inline_with_csp(self):
        client = _client()
        with patch("nettacker.api.engine.get_scan_result") as mock:
            mock.return_value = ("/results/report.htm", b"<html></html>")
            resp = client.get(f"/results/get?key={API_KEY}&id=1")

        assert resp.status_code == 200
        assert "inline" in resp.headers["Content-Disposition"]
        assert "Content-Security-Policy" in resp.headers

    def test_non_html_attachment(self):
        client = _client()
        with patch("nettacker.api.engine.get_scan_result") as mock:
            mock.return_value = ("/results/report.txt", b"plain text")
            resp = client.get(f"/results/get?key={API_KEY}&id=1")

        assert resp.status_code == 200
        assert "attachment" in resp.headers["Content-Disposition"]
        assert "report.txt" in resp.headers["Content-Disposition"]
        assert "sandbox" not in resp.headers.get("Content-Security-Policy", "")

    def test_not_found_returns_404(self):
        client = _client()
        with patch("nettacker.api.engine.get_scan_result") as mock:
            mock.return_value = None
            resp = client.get(f"/results/get?key={API_KEY}&id=999")

        assert resp.status_code == 404

    def test_dict_result_returns_500(self):
        client = _client()
        with patch("nettacker.api.engine.get_scan_result") as mock:
            mock.return_value = {"status": "error", "msg": "db error"}
            resp = client.get(f"/results/get?key={API_KEY}&id=1")

        assert resp.status_code == 500

    def test_missing_id_returns_400(self):
        client = _client()
        resp = client.get(f"/results/get?key={API_KEY}")
        assert resp.status_code == 400

    def test_empty_safe_filename_fallback(self):
        client = _client()
        with (
            patch("nettacker.api.engine.get_scan_result") as mock_result,
            patch("nettacker.api.engine.secure_filename", return_value=""),
        ):
            mock_result.return_value = ("/results/report.html", b"<html></html>")
            resp = client.get(f"/results/get?key={API_KEY}&id=1")

        assert resp.status_code == 200
        assert "report.html" in resp.headers["Content-Disposition"]
