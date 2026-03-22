"""Tests for the /results/get endpoint in nettacker.api.engine.

Verifies that HTML reports are rendered inline while other file types
are served as attachment downloads (see GitHub issue #1316).

All heavy transitive imports are stubbed inside a session-scoped autouse
fixture using monkeypatch so that sys.modules is automatically restored
after the test session, preventing leakage into other test modules.
"""

import sys
import types
from unittest.mock import MagicMock, patch

import pytest


# ---------------------------------------------------------------------------
# Helper: build a minimal stub module and register it in sys.modules
# ---------------------------------------------------------------------------
def _make_stub(name: str) -> types.ModuleType:
    mod = types.ModuleType(name)
    sys.modules[name] = mod
    return mod


# Names that must be stubbed before nettacker.api.engine can be imported.
_STUB_NAMES = [
    "multiprocess",
    "texttable",
    "apsw",
    "netaddr",
    "impacket",
    "nettacker.logger",
    "nettacker.config",
    "nettacker.core.app",
    "nettacker.core.die",
    "nettacker.core.graph",
    "nettacker.core.messages",
    "nettacker.core.utils",
    "nettacker.core.utils.time",
    "nettacker.core.utils.common",
    "nettacker.api.helpers",
    "nettacker.database",
    "nettacker.database.db",
    "nettacker.database.models",
]


@pytest.fixture(scope="session", autouse=True)
def _stub_nettacker_modules():
    """Inject lightweight stub modules for all heavy nettacker dependencies.

    Uses monkeypatch-equivalent manual cleanup so that sys.modules entries
    added here are removed after the session, preventing cross-module leakage.
    """
    originals = {}

    for name in _STUB_NAMES:
        originals[name] = sys.modules.get(name)
        if name not in sys.modules:
            _make_stub(name)

    # Wire up just enough attributes for engine.py and api/core.py to import.
    sys.modules["nettacker.core.app"].Nettacker = MagicMock()
    sys.modules["nettacker.core.messages"].messages = lambda key: key
    sys.modules["nettacker.core.messages"].get_languages = MagicMock(return_value=[])
    sys.modules["nettacker.core.utils.common"].generate_compare_filepath = MagicMock()
    sys.modules["nettacker.core.utils.common"].now = MagicMock(return_value="2024_01_01")
    sys.modules["nettacker.core.utils.common"].generate_random_token = MagicMock(
        return_value="tok"
    )
    sys.modules["nettacker.core.graph"].create_compare_report = MagicMock()
    sys.modules["nettacker.core.graph"].create_report = MagicMock()
    sys.modules["nettacker.core.die"].die_failure = MagicMock()
    sys.modules["nettacker.database.db"].create_connection = MagicMock()
    sys.modules["nettacker.database.db"].get_logs_by_scan_id = MagicMock()
    sys.modules["nettacker.database.db"].get_scan_result = MagicMock()
    sys.modules["nettacker.database.db"].last_host_logs = MagicMock()
    sys.modules["nettacker.database.db"].logs_to_report_html = MagicMock()
    sys.modules["nettacker.database.db"].logs_to_report_json = MagicMock()
    sys.modules["nettacker.database.db"].search_logs = MagicMock()
    sys.modules["nettacker.database.db"].select_reports = MagicMock()
    sys.modules["nettacker.database.models"].Report = MagicMock()
    sys.modules["nettacker.logger"].get_logger = MagicMock(return_value=MagicMock())
    sys.modules["nettacker.api.helpers"].structure = MagicMock(return_value={})

    # Minimal Config mock used by engine.py at module scope.
    config_mock = MagicMock()
    config_mock.path.web_static_dir = MagicMock()
    config_mock.path.results_dir = MagicMock()
    config_mock.settings.as_dict.return_value = {}
    config_mock.settings.report_path_filename = "report.html"
    config_mock.api.as_dict.return_value = {"api_access_key": "test_key"}
    sys.modules["nettacker.config"].Config = config_mock

    # It is now safe to import the app.
    from nettacker.api.engine import app as _app  # noqa: PLC0415

    # Expose it on the fixture's module so tests can reference it.
    _stub_nettacker_modules.app = _app  # type: ignore[attr-defined]

    yield

    # Restore sys.modules to its original state.
    for name, original in originals.items():
        if original is None:
            sys.modules.pop(name, None)
        else:
            sys.modules[name] = original


# ---------------------------------------------------------------------------
# Flask test client fixture
# ---------------------------------------------------------------------------
@pytest.fixture
def client(_stub_nettacker_modules):
    """Flask test client with a minimal OWASP_NETTACKER_CONFIG."""
    app = _stub_nettacker_modules.app  # type: ignore[attr-defined]
    app.config["OWASP_NETTACKER_CONFIG"] = {
        "api_access_key": "test_key",
        "api_client_whitelisted_ips": [],
        "api_access_log": "",
    }
    app.config["TESTING"] = True
    with app.test_client() as c:
        yield c


# ---------------------------------------------------------------------------
# Tests for /results/get  (get_result_content)
# ---------------------------------------------------------------------------
@patch("nettacker.api.engine.api_key_is_valid")
@patch("nettacker.api.engine.get_scan_result")
def test_html_report_rendered_inline(mock_get_scan_result, mock_api_key, client):
    """HTML reports must render in the browser, not trigger a download."""
    mock_get_scan_result.return_value = ("report.html", b"<html><body>Report</body></html>")

    response = client.get("/results/get?id=1&key=test_key")

    assert response.status_code == 200
    assert response.content_type == "text/html; charset=utf-8"
    cd = response.headers["Content-Disposition"]
    assert "inline" in cd, f"Expected 'inline' in Content-Disposition, got: {cd}"
    assert "attachment" not in cd, "attachment must NOT appear for HTML reports"
    assert "report.html" in cd
    csp = response.headers.get("Content-Security-Policy", "")
    assert "script-src 'none'" in csp, f"Expected CSP to block scripts, got: {csp}"


@patch("nettacker.api.engine.api_key_is_valid")
@patch("nettacker.api.engine.get_scan_result")
def test_htm_report_rendered_inline(mock_get_scan_result, mock_api_key, client):
    """.htm files must render inline with the same security coverage as .html."""
    mock_get_scan_result.return_value = ("report.htm", b"<html><body>Report</body></html>")

    response = client.get("/results/get?id=1&key=test_key")

    assert response.status_code == 200
    assert response.content_type == "text/html; charset=utf-8"
    cd = response.headers["Content-Disposition"]
    assert "inline" in cd
    assert "attachment" not in cd
    # .htm must carry the same restrictive CSP as .html (security parity)
    csp = response.headers.get("Content-Security-Policy", "")
    assert "script-src 'none'" in csp, f"Expected CSP to block scripts for .htm, got: {csp}"


@patch("nettacker.api.engine.api_key_is_valid")
@patch("nettacker.api.engine.get_scan_result")
def test_json_report_downloaded_as_attachment(mock_get_scan_result, mock_api_key, client):
    """Non-HTML files (JSON) must still be served as downloads."""
    mock_get_scan_result.return_value = ("report.json", b'{"data": "test"}')

    response = client.get("/results/get?id=1&key=test_key")

    assert response.status_code == 200
    assert "application/json" in response.content_type
    cd = response.headers["Content-Disposition"]
    assert "attachment" in cd, f"Expected 'attachment' for JSON, got: {cd}"
    assert "report.json" in cd
    # The global set_security_headers hook adds a basic CSP to every response,
    # but the restrictive script-src 'none' must NOT appear for non-HTML files.
    csp = response.headers.get("Content-Security-Policy", "")
    assert "script-src 'none'" not in csp


@patch("nettacker.api.engine.api_key_is_valid")
@patch("nettacker.api.engine.get_scan_result")
def test_txt_report_downloaded_as_attachment(mock_get_scan_result, mock_api_key, client):
    """Non-HTML files (TXT) must still be served as downloads."""
    mock_get_scan_result.return_value = ("report.txt", b"plain text report")

    response = client.get("/results/get?id=1&key=test_key")

    assert response.status_code == 200
    assert "text/plain" in response.content_type
    cd = response.headers["Content-Disposition"]
    assert "attachment" in cd, f"Expected 'attachment' for TXT, got: {cd}"
    assert "report.txt" in cd
