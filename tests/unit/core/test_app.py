import os
import socket
from types import SimpleNamespace
from unittest.mock import MagicMock

import multiprocess
import pytest

from nettacker.config import Config
from nettacker.core import app as app_module
from nettacker.core.app import Nettacker


def _make_nettacker():
    """Build a Nettacker instance without running __init__, to unit-test methods in isolation."""
    return Nettacker.__new__(Nettacker)


def test_check_dependencies_accepts_win32(monkeypatch):
    """win32 must not trigger die_failure() -- this is the Windows-compat fix under test."""
    monkeypatch.setattr(app_module.sys, "platform", "win32")
    mock_die_failure = MagicMock(side_effect=SystemExit)
    monkeypatch.setattr(app_module, "die_failure", mock_die_failure)
    monkeypatch.setattr(Config.path, "tmp_dir", MagicMock())
    monkeypatch.setattr(Config.path, "results_dir", MagicMock())
    monkeypatch.setattr(Config.db, "engine", "sqlite")
    monkeypatch.setattr(Config.path, "new_database_file", MagicMock(exists=lambda: True))

    _make_nettacker().check_dependencies()

    mock_die_failure.assert_not_called()


def test_check_dependencies_rejects_unsupported_platform(monkeypatch):
    """Sanity check: an unsupported platform still dies, proving the win32 test above
    is actually exercising the platform allow-list rather than passing vacuously."""
    monkeypatch.setattr(app_module.sys, "platform", "not-a-real-platform")
    mock_die_failure = MagicMock(side_effect=SystemExit)
    monkeypatch.setattr(app_module, "die_failure", mock_die_failure)

    with pytest.raises(SystemExit):
        _make_nettacker().check_dependencies()

    mock_die_failure.assert_called_once()


def test_scan_target_completes_without_os_ex_ok(monkeypatch):
    """Simulates the real Windows condition (os.EX_OK does not exist) end-to-end
    through scan_target(). Would fail with AttributeError if os.EX_OK were ever
    reintroduced there instead of the plain 0 literal."""
    monkeypatch.delattr(os, "EX_OK", raising=False)

    real_socket_cls = socket.socket
    real_getaddrinfo = socket.getaddrinfo
    monkeypatch.setattr(
        app_module, "set_socks_proxy", lambda proxy: (real_socket_cls, real_getaddrinfo)
    )
    fake_module = MagicMock()
    monkeypatch.setattr(app_module, "Module", MagicMock(return_value=fake_module))
    monkeypatch.setattr(app_module, "log", MagicMock())

    nettacker = _make_nettacker()
    nettacker.arguments = SimpleNamespace(socks_proxy=None)
    nettacker.modules_done = multiprocess.Value("i", 0)

    result = nettacker.scan_target(
        target="127.0.0.1",
        module_name="port_scan",
        scan_id="scan-id",
        process_number=0,
        thread_number=0,
        total_number_threads=1,
    )

    assert result == 0
    fake_module.load.assert_called_once()
    fake_module.generate_loops.assert_called_once()
    fake_module.sort_loops.assert_called_once()
    fake_module.start.assert_called_once()
    assert nettacker.modules_done.value == 1


@pytest.mark.parametrize(
    "scan_id, expected_scan_id",
    [("given_scan_id", "given_scan_id"), (None, "generated_scan_id")],
)
def test_run_uses_given_scan_id(monkeypatch, scan_id, expected_scan_id):
    nettacker = _make_nettacker()
    nettacker.arguments = SimpleNamespace()
    expand_targets = MagicMock(return_value=[])
    monkeypatch.setattr(nettacker, "expand_targets", expand_targets)
    monkeypatch.setattr(
        app_module.common_utils, "generate_random_token", lambda length: "generated_scan_id"
    )

    assert nettacker.run(scan_id) is True
    expand_targets.assert_called_once_with(expected_scan_id)


@pytest.fixture
def fake_modules(monkeypatch):
    """Replace modules with mocks, so scan_target() sends nothing over the network."""
    real_socket_cls = socket.socket
    real_getaddrinfo = socket.getaddrinfo
    monkeypatch.setattr(
        app_module, "set_socks_proxy", lambda proxy: (real_socket_cls, real_getaddrinfo)
    )
    monkeypatch.setattr(app_module, "Module", MagicMock())
    monkeypatch.setattr(app_module, "remove_old_logs", MagicMock())
    monkeypatch.setattr(app_module, "log", MagicMock())
    return app_module.Module


def test_crashed_module_still_counts(fake_modules):
    fake_modules.return_value.start.side_effect = RuntimeError("boom")
    nettacker = _make_nettacker()
    nettacker.arguments = SimpleNamespace(socks_proxy=None)
    nettacker.modules_done = multiprocess.Value("i", 0)

    with pytest.raises(RuntimeError):
        nettacker.scan_target("127.0.0.1", "port_scan", "scan-id", 0, 0, 1)

    assert nettacker.modules_done.value == 1


@pytest.mark.skipif(
    "fork" not in multiprocess.get_all_start_methods(), reason="needs fork to share the mocks"
)
def test_progress_is_counted_across_scan_processes(fake_modules, monkeypatch):
    # fork, so the child processes inherit the mocked modules
    context = multiprocess.get_context("fork")
    processes = []

    def start_process(*args, **kwargs):
        processes.append(context.Process(*args, **kwargs))
        return processes[-1]

    monkeypatch.setattr(app_module.multiprocess, "Process", start_process)
    nettacker = _make_nettacker()
    nettacker.arguments = SimpleNamespace(
        targets=[f"target{i}.test" for i in range(5)],
        selected_modules=["module_a", "module_b", "module_c"],
        set_hardware_usage=3,
        parallel_module_scan=2,
        scan_compare_id=None,
        socks_proxy=None,
    )
    nettacker.modules_done = context.Value("i", 0)

    nettacker.start_scan("scan-id")

    # 5 targets split over 3 processes, each running 3 modules per target in threads
    assert len(processes) == 3
    assert [process.exitcode for process in processes] == [0, 0, 0]
    assert nettacker.modules_done.value == 15


def test_expand_targets_counts_discovery_up_front(monkeypatch):
    nettacker = _make_nettacker()
    nettacker.arguments = SimpleNamespace(
        targets=["target1.test", "target2.test"],
        selected_modules=["module_a", "port_scan"],
        scan_ip_range=False,
        scan_subdomains=False,
        ping_before_scan=False,
        skip_service_discovery=False,
    )
    totals_at_discovery = []
    monkeypatch.setattr(
        nettacker,
        "start_scan",
        lambda scan_id: totals_at_discovery.append(nettacker.modules_total),
    )
    monkeypatch.setattr(nettacker, "filter_target_by_event", lambda targets, *args: targets)

    nettacker.expand_targets("scan-id")

    # port_scan runs once per target for discovery, then module_a
    assert totals_at_discovery == [4]


def test_run_recounts_progress_after_discovery(monkeypatch):
    nettacker = _make_nettacker()
    nettacker.arguments = SimpleNamespace(
        selected_modules=["module_a", "module_b"], scan_compare_id=None
    )
    progress_at_start = []

    # discovery finished 4 module runs and kept 3 targets
    def expand_targets(scan_id):
        nettacker.modules_done.value += 4
        return ["target1.test", "target2.test", "target3.test"]

    def start_scan(scan_id):
        progress_at_start.append((nettacker.modules_done.value, nettacker.modules_total))
        return True

    monkeypatch.setattr(nettacker, "expand_targets", expand_targets)
    monkeypatch.setattr(nettacker, "start_scan", start_scan)
    monkeypatch.setattr(app_module, "create_report", MagicMock())

    assert nettacker.run("scan-id") is True
    assert progress_at_start == [(4, 10)]
