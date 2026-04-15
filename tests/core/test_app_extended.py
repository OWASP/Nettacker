import json
from types import SimpleNamespace
from unittest.mock import MagicMock, patch

from nettacker.core import app as app_module
from nettacker.core.app import Nettacker


def make_nettacker_with_options(**kwargs):
    app = Nettacker.__new__(Nettacker)
    defaults = {
        "targets": ["example.com"],
        "scan_ip_range": False,
        "selected_modules": ["mod"],
        "scan_subdomains": False,
        "ping_before_scan": False,
        "skip_service_discovery": False,
        "set_hardware_usage": 1,
        "scan_compare_id": None,
        "socks_proxy": None,
        "parallel_module_scan": 1,
        "report_path_filename": "report.txt",
        "compare_report_path_filename": "compare.txt",
        "graph_name": None,
    }
    defaults.update(kwargs)
    app.arguments = SimpleNamespace(**defaults)
    return app


@patch("nettacker.core.app.find_events", return_value=["ok"])
def test_expand_targets_single_targets(mock_find_events):
    app = make_nettacker_with_options(
        targets=["1.1.1.1"],
        skip_service_discovery=True,
        scan_subdomains=False,
        ping_before_scan=False,
    )

    result = app.expand_targets("scan-1")

    assert "1.1.1.1" in result
    assert "1.1.1.1" in app.arguments.targets


@patch("nettacker.core.app.find_events")
@patch("nettacker.core.app.generate_ip_range", return_value=["192.1.1.1", "192.1.1.2"])
def test_expand_targets_cidr(mock_gen_range, mock_find):
    app = make_nettacker_with_options(targets=["192.0.0.0/30"], scan_ip_range=False)
    app.start_scan = MagicMock()

    result = app.expand_targets("scan-1")

    assert "192.1.1.1" in result or "192.0.0.0" in result


@patch("nettacker.core.app.find_events")
def test_expand_targets_url_extracts_host_and_path(mock_find):
    mock_find.return_value = []
    app = make_nettacker_with_options(targets=["https://example.com:8080/api/v1"])

    app.expand_targets("scan-1")

    assert app.arguments.url_base_path == "api/v1/"


@patch("nettacker.core.app.multiprocess.Process")
@patch("nettacker.core.app.wait_for_threads_to_finish", return_value=True)
def test_start_scan_triggers_processes(mock_wait, mock_process):
    mock_proc = MagicMock()
    mock_process.return_value = mock_proc

    app = make_nettacker_with_options()

    result = app.start_scan("scan-1")

    assert result is True
    mock_process.assert_called()


@patch("nettacker.core.app.create_report")
@patch("nettacker.core.app.remove_old_logs")
def test_run_flow_with_targets(mock_remove_logs, mock_report):
    app = make_nettacker_with_options(targets=["1.1.1.1"])
    app.expand_targets = MagicMock(return_value=["1.1.1.1"])
    app.start_scan = MagicMock(return_value=0)

    result = app.run()

    assert result == 0
    app.expand_targets.assert_called_once()
    app.start_scan.assert_called_once()
    mock_report.assert_called_once()
