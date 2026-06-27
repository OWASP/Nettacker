import json
from types import SimpleNamespace
from unittest.mock import MagicMock, patch

from nettacker.core import app as app_module
from nettacker.core.app import Nettacker


def test_expand_targets_handles_subdomains_and_port_scan(monkeypatch):
    scan_id = "scan-123"
    app = Nettacker.__new__(Nettacker)
    app.arguments = SimpleNamespace(
        targets=["http://example.com/path", "192.168.1.1-192.168.1.2", "example.org"],
        scan_ip_range=False,
        selected_modules=["mod1", "subdomain_scan", "port_scan"],
        scan_subdomains=True,
        ping_before_scan=False,
        skip_service_discovery=False,
        set_hardware_usage=1,
        scan_compare_id=None,
        socks_proxy=None,
        parallel_module_scan=2,
    )
    app.start_scan = MagicMock()

    def fake_find_events(target, module_name, _scan_id):
        if module_name == "subdomain_scan":
            return [
                json.dumps(
                    {"response": {"conditions_results": {"content": [f"sub.{target}"]}}}
                )
            ]
        if module_name in {"icmp_scan", "port_scan"}:
            return ["ok"]
        return []

    monkeypatch.setattr(app_module, "find_events", fake_find_events)

    expanded = set(app.expand_targets(scan_id))

    assert {"example.com", "example.org", "192.168.1.1", "192.168.1.2"}.issubset(expanded)
    assert "sub.example.com" in expanded
    assert app.arguments.url_base_path == "path/"
    assert app.start_scan.call_count == 2


def test_filter_target_by_event(monkeypatch):
    app = Nettacker.__new__(Nettacker)

    def fake_find_events(target, module_name, scan_id):
        return ["found"] if target == "keep" else []

    monkeypatch.setattr(app_module, "find_events", fake_find_events)

    result = app.filter_target_by_event(["keep", "drop"], "scan-1", "port_scan")
    assert result == ["keep"]


def test_run_returns_true_when_no_targets():
    app = Nettacker.__new__(Nettacker)
    app.arguments = SimpleNamespace(
        report_path_filename="report.txt",
        compare_report_path_filename="compare.txt",
        graph_name=None,
        scan_compare_id=None,
    )
    app.expand_targets = MagicMock(return_value=[])
    app.start_scan = MagicMock()

    result = app.run()

    assert result is True
    app.start_scan.assert_not_called()


def test_run_triggers_scan_and_report(monkeypatch):
    app = Nettacker.__new__(Nettacker)
    app.arguments = SimpleNamespace(
        report_path_filename="report.html",
        compare_report_path_filename="report.html",
        graph_name=None,
        scan_compare_id=None,
    )
    app.expand_targets = MagicMock(return_value=["example.com"])
    app.start_scan = MagicMock(return_value=0)

    with patch("nettacker.core.app.create_report") as mock_create_report, patch(
        "nettacker.core.app.create_compare_report"
    ) as mock_compare_report:
        exit_code = app.run()

    assert exit_code == 0
    app.start_scan.assert_called_once()
    mock_create_report.assert_called_once()
    mock_compare_report.assert_not_called()
