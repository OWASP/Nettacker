import signal
import threading

from huey import SqliteHuey

from nettacker import logger
from nettacker.config import Config
from nettacker.core.utils.common import generate_random_token

log = logger.get_logger()

# tables are created by start_workers(), so importing this module doesn't create the file
huey = SqliteHuey(
    "nettacker", filename=str(Config.path.scan_queue_file), results=False, create_tables=False
)

MAX_FINISHED_SCANS = 100

_lock = threading.Lock()
_apps = {}  # scan_id -> Nettacker instance, until its scan finishes
_scans = {}  # scan_id -> {"status": queued/running/done/failed, "targets": description}


def queue_scan(nettacker_app, targets):
    """Queue a Nettacker instance with parsed arguments and return its scan_id."""
    scan_id = generate_random_token(32)
    with _lock:
        _apps[scan_id] = nettacker_app
        _scans[scan_id] = {"status": "queued", "targets": targets}
    run_scan(scan_id)
    return scan_id


@huey.task()
def run_scan(scan_id):
    with _lock:
        nettacker_app = _apps[scan_id]
        _scans[scan_id]["status"] = "running"
    try:
        nettacker_app.run(scan_id)
        status = "done"
    # die_failure() raises SystemExit, which would otherwise end this worker thread
    except (Exception, SystemExit) as e:
        log.error(f"ScanID: {scan_id} failed: {e!r}")
        status = "failed"
    with _lock:
        del _apps[scan_id]
        _scans[scan_id]["status"] = status
        finished = [key for key, scan in _scans.items() if scan["status"] in ("done", "failed")]
        for key in finished[:-MAX_FINISHED_SCANS]:
            del _scans[key]


def get_scans():
    scans = []
    with _lock:
        for scan_id, scan in _scans.items():
            scan = {"scan_id": scan_id, **scan}
            if scan["status"] == "running":
                nettacker_app = _apps[scan_id]
                scan["progress"] = 0
                # modules_total stays 0 until the targets are expanded
                if nettacker_app.modules_total:
                    done = nettacker_app.modules_done.value
                    scan["progress"] = min(done * 100 // nettacker_app.modules_total, 100)
            scans.append(scan)
    return scans


def start_workers(workers):
    """Start the queue's worker threads in this process. Must run on the main thread.
    This returns the consumer"""
    huey.storage.initialize_schema()
    # queued scans only live in memory, so tasks left from an earlier run can't be run
    huey.flush()
    consumer = huey.create_consumer(
        workers=workers, worker_type="thread", max_delay=Config.scan_queue.poll_interval
    )
    signals = [signal.SIGINT, signal.SIGTERM]
    if hasattr(signal, "SIGHUP"):
        signals.append(signal.SIGHUP)
    handlers = {sig: signal.getsignal(sig) for sig in signals}
    consumer.start()
    for sig, handler in handlers.items():
        signal.signal(sig, handler)
    return consumer
