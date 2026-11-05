import signal
import threading
import time
from types import SimpleNamespace
from unittest.mock import MagicMock, patch

import pytest

from nettacker.api import tasks


@pytest.fixture(autouse=True)
def clear_scans():
    yield
    tasks._scans.clear()
    tasks._apps.clear()


@pytest.fixture
def immediate_huey():
    """Run queued scans straight away in the calling thread, with in-memory storage."""
    tasks.huey.immediate = True
    yield
    tasks.huey.immediate = False


@pytest.fixture
def start_workers(tmp_path, monkeypatch):
    monkeypatch.setattr(tasks.huey.storage, "filename", str(tmp_path / "scan_queue.db"))
    consumers = []
    yield lambda workers: consumers.append(tasks.start_workers(workers))
    for consumer in consumers:
        consumer.stop(graceful=True)
    tasks.huey.storage.close()


def scan_status(scan_id):
    return {scan["scan_id"]: scan["status"] for scan in tasks.get_scans()}.get(scan_id)


def wait_for(condition, timeout=10):
    deadline = time.monotonic() + timeout
    while not condition():
        assert time.monotonic() < deadline, "timed out waiting for the scan queue"
        time.sleep(0.05)


def test_queue_scan_returns_a_queued_scan_id():
    with patch.object(tasks, "run_scan") as run_scan:
        scan_id = tasks.queue_scan(MagicMock(), "target.test")

    run_scan.assert_called_once_with(scan_id)
    assert tasks.get_scans() == [
        {"scan_id": scan_id, "status": "queued", "targets": "target.test"}
    ]


def test_finished_scan_is_done(immediate_huey):
    nettacker_app = MagicMock()

    scan_id = tasks.queue_scan(nettacker_app, "target.test")

    nettacker_app.run.assert_called_once_with(scan_id)
    assert scan_status(scan_id) == "done"
    assert tasks._apps == {}


@pytest.mark.parametrize("error", [RuntimeError("boom"), SystemExit(1)])
def test_crashed_scan_is_failed(immediate_huey, error):
    nettacker_app = MagicMock()
    nettacker_app.run.side_effect = error

    scan_id = tasks.queue_scan(nettacker_app, "target.test")

    assert scan_status(scan_id) == "failed"


@pytest.mark.parametrize("modules_total, progress", [(0, 0), (8, 25)])
def test_running_scan_shows_progress(immediate_huey, modules_total, progress):
    seen = []
    nettacker_app = MagicMock(modules_total=modules_total, modules_done=SimpleNamespace(value=2))
    nettacker_app.run.side_effect = lambda scan_id: seen.extend(tasks.get_scans())

    scan_id = tasks.queue_scan(nettacker_app, "target.test")

    assert seen[0]["status"] == "running"
    assert seen[0]["progress"] == progress
    assert tasks.get_scans() == [{"scan_id": scan_id, "status": "done", "targets": "target.test"}]


def test_oldest_finished_scans_are_dropped(immediate_huey, monkeypatch):
    monkeypatch.setattr(tasks, "MAX_FINISHED_SCANS", 2)

    scan_ids = [tasks.queue_scan(MagicMock(), "target.test") for _ in range(3)]

    assert [scan["scan_id"] for scan in tasks.get_scans()] == scan_ids[1:]


def test_scans_wait_for_a_free_worker(start_workers):
    release = threading.Event()
    ran_on = []

    def run(scan_id):
        ran_on.append(threading.current_thread().name)
        release.wait(timeout=10)

    start_workers(1)
    first = tasks.queue_scan(MagicMock(run=run, modules_total=0), "target.test")
    second = tasks.queue_scan(MagicMock(run=run, modules_total=0), "target.test")

    wait_for(lambda: scan_status(first) == "running")
    assert scan_status(second) == "queued"

    release.set()
    wait_for(lambda: scan_status(second) == "done")
    assert scan_status(first) == "done"
    assert ran_on == ["Worker-1", "Worker-1"]


def test_start_workers_keeps_signal_handlers(start_workers):
    handlers = {sig: signal.getsignal(sig) for sig in (signal.SIGINT, signal.SIGTERM)}

    start_workers(1)

    assert {sig: signal.getsignal(sig) for sig in handlers} == handlers


def test_scans_left_from_an_earlier_run_are_dropped(start_workers):
    tasks.huey.storage.initialize_schema()
    stale_app = MagicMock()
    tasks.queue_scan(stale_app, "target.test")

    start_workers(1)
    scan_id = tasks.queue_scan(MagicMock(modules_total=0), "target.test")

    wait_for(lambda: scan_status(scan_id) == "done")
    stale_app.run.assert_not_called()
