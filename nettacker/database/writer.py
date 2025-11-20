import json
import threading
import time
from multiprocessing import Queue
from pathlib import Path

from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

from nettacker import logger
from nettacker.config import Config
from nettacker.database.models import Report, HostsLog, TempEvents

log = logger.get_logger()


class DBWriter:
    def __init__(self, batch_size=100, interval=0.5):
        self.batch_size = int(batch_size)
        self.interval = float(interval)
        self._stop = threading.Event()
        self._thread = None
        # total processed across lifetime
        self._processed_count = 0

        self._use_litequeue = False
        self._lq = None
        self._lq_put = None
        self._lq_get = None

        try:
            import litequeue as _litequeue

            queue_file = Path(Config.path.data_dir) / "nettacker_db_queue.lq"
            queue_file.parent.mkdir(parents=True, exist_ok=True)
            # try common constructors
            if hasattr(_litequeue, "LiteQueue"):
                self._lq = _litequeue.LiteQueue(str(queue_file))
            elif hasattr(_litequeue, "Queue"):
                self._lq = _litequeue.Queue(str(queue_file))
            else:
                # fallback to a module-level factory
                try:
                    self._lq = _litequeue.open(str(queue_file))
                except Exception:
                    self._lq = None

            if self._lq is not None:
                # prefer destructive pop/get ordering
                if hasattr(self._lq, "put"):
                    self._lq_put = self._lq.put
                elif hasattr(self._lq, "push"):
                    self._lq_put = self._lq.push
                elif hasattr(self._lq, "add"):
                    self._lq_put = self._lq.add

                if hasattr(self._lq, "pop"):
                    self._lq_get = self._lq.pop
                elif hasattr(self._lq, "get"):
                    # note: some implementations require message_id; prefer pop above
                    self._lq_get = self._lq.get
                elif hasattr(self._lq, "take"):
                    self._lq_get = self._lq.take

                if self._lq_put and self._lq_get:
                    self._use_litequeue = True
        except Exception:
            self._use_litequeue = False

        if not self._use_litequeue:
            self.queue = Queue()

        db_url = Config.db.as_dict()
        engine_url = (
            "sqlite:///{name}".format(**db_url)
            if Config.db.engine.startswith("sqlite")
            else Config.db.engine
        )
        connect_args = {}
        if engine_url.startswith("sqlite"):
            connect_args["check_same_thread"] = False

        self.engine = create_engine(engine_url, connect_args=connect_args, pool_pre_ping=True)
        if engine_url.startswith("sqlite"):
            try:
                with self.engine.connect() as conn:
                    conn.execute("PRAGMA journal_mode=WAL")
            except Exception:
                pass

        self.Session = sessionmaker(bind=self.engine)

    def start(self):
        if self._thread and self._thread.is_alive():
            return
        self._stop.clear()
        self._thread = threading.Thread(target=self._run, name="nettacker-db-writer", daemon=True)
        self._thread.start()

    def stop(self):
        self._stop.set()
        if self._thread:
            self._thread.join(timeout=5)

    def enqueue(self, job):
        try:
            if self._use_litequeue:
                self._lq_put(json.dumps(job))
                return True
            self.queue.put(job)
            return True
        except Exception:
            log.warn("DBWriter: failed to enqueue job")
            return False

    def _acknowledge_message(self, message_id):
        """Acknowledge a successfully processed message."""
        if self._use_litequeue and message_id is not None:
            try:
                if hasattr(self._lq, "done"):
                    self._lq.done(message_id)
            except Exception:
                pass

    def _pop_one(self):
        if self._use_litequeue:
            try:
                # litequeue: use pop() to get and lock message, then mark done() AFTER processing
                msg = None
                if hasattr(self._lq, "pop"):
                    msg = self._lq.pop()
                elif hasattr(self._lq, "get"):
                    # fallback: try to get next via get
                    msg = self._lq.get()

                if msg is None:
                    return None

                if hasattr(msg, "data"):
                    payload = msg.data
                elif hasattr(msg, "message"):
                    payload = msg.message
                else:
                    payload = str(msg)

                if isinstance(payload, (bytes, bytearray)):
                    payload = payload.decode()

                # Return both the payload and message_id for deferred acknowledgment
                job_data = json.loads(payload)
                if hasattr(msg, "message_id"):
                    return {"data": job_data, "message_id": msg.message_id}
                else:
                    return {"data": job_data, "message_id": None}
            except Exception:
                return None
        else:
            try:
                job_data = self.queue.get_nowait()
                return {"data": job_data, "message_id": None}

            except Exception:
                return None

    def _run(self):
        pending = []
        while not self._stop.is_set():
            try:
                while len(pending) < self.batch_size:
                    job = self._pop_one()
                    if job is None:
                        break
                    pending.append(job)

                if pending:
                    # Process each job individually with immediate commit
                    for job in pending:
                        job_session = self.Session()  # Fresh session per job
                        try:
                            # Handle both litequeue format {"data": job, "message_id": id} and direct job
                            job_data = (
                                job["data"] if isinstance(job, dict) and "data" in job else job
                            )
                            self._apply_job(job_session, job_data)
                            job_session.commit()  # Immediate commit per job
                            self._processed_count += 1

                            # Only acknowledge after successful commit
                            if isinstance(job, dict) and "message_id" in job:
                                self._acknowledge_message(job["message_id"])

                        except Exception as e:
                            job_session.rollback()
                            log.error(f"Failed to process job: {e}")
                            # Job is not acknowledged, so it can be retried
                        finally:
                            job_session.close()

                    pending = []
                else:
                    time.sleep(self.interval)
            except Exception:
                time.sleep(0.1)

        # Final cleanup: process any remaining jobs individually
        try:
            while True:
                job = self._pop_one()
                if job is None:
                    break

                # Process final job individually with immediate commit
                cleanup_session = self.Session()
                try:
                    job_data = job["data"] if isinstance(job, dict) and "data" in job else job
                    self._apply_job(cleanup_session, job_data)
                    cleanup_session.commit()
                    self._processed_count += 1

                    # Only acknowledge after successful commit
                    if isinstance(job, dict) and "message_id" in job:
                        self._acknowledge_message(job["message_id"])

                except Exception as e:
                    cleanup_session.rollback()
                    log.error(f"Failed to process cleanup job: {e}")
                finally:
                    cleanup_session.close()
        except Exception:
            pass

    def drain_once(self, max_iterations=100000):
        """Consume all queued jobs and return when queue is empty.

        This method is intended for on-demand draining (not long-lived).
        """
        iterations = 0
        processed = 0

        try:
            while iterations < max_iterations:
                job = self._pop_one()
                if job is None:
                    break

                # Process each job individually with immediate commit for durability
                job_session = self.Session()  # Fresh session per job
                try:
                    # Handle both litequeue format {"data": job, "message_id": id} and direct job
                    job_data = job["data"] if isinstance(job, dict) and "data" in job else job
                    self._apply_job(job_session, job_data)
                    job_session.commit()  # Immediate commit per job
                    processed += 1
                    self._processed_count += 1

                    # Only acknowledge after successful commit
                    if isinstance(job, dict) and "message_id" in job:
                        self._acknowledge_message(job["message_id"])

                except Exception as e:
                    job_session.rollback()
                    log.error(f"Failed to process job during drain: {e}")
                    # Job is not acknowledged, so it can be retried
                finally:
                    job_session.close()

                iterations += 1
        except Exception as e:
            log.error(f"Error during drain operation: {e}")

        return processed

    def _apply_job(self, session, job):
        action = job.get("action")
        payload = job.get("payload", {})
        if action == "insert_report":
            session.add(
                Report(
                    date=payload.get("date"),
                    scan_unique_id=payload.get("scan_id"),
                    report_path_filename=payload.get("report_path_filename"),
                    options=json.dumps(payload.get("options", {})),
                )
            )
            return
        if action == "insert_hostslog":
            session.add(
                HostsLog(
                    target=payload.get("target"),
                    date=payload.get("date"),
                    module_name=payload.get("module_name"),
                    scan_unique_id=payload.get("scan_id"),
                    port=json.dumps(payload.get("port")),
                    event=json.dumps(payload.get("event")),
                    json_event=json.dumps(payload.get("json_event")),
                )
            )
            return
        if action == "insert_tempevent":
            session.add(
                TempEvents(
                    target=payload.get("target"),
                    date=payload.get("date"),
                    module_name=payload.get("module_name"),
                    scan_unique_id=payload.get("scan_id"),
                    event_name=payload.get("event_name"),
                    port=json.dumps(payload.get("port")),
                    event=json.dumps(payload.get("event")),
                    data=json.dumps(payload.get("data")),
                )
            )
            return
        log.warn(f"DBWriter: unsupported job action {action}")


# singleton writer
_writer = None


def get_writer():
    global _writer
    if _writer is None:
        _writer = DBWriter()
        try:
            _writer.start()
        except Exception:
            pass
    return _writer


def get_writer_configured(batch_size=None, interval=None):
    """Return singleton writer, applying optional configuration.

    If the writer already exists, provided parameters will update its settings.
    """
    w = get_writer()
    if batch_size is not None:
        try:
            w.batch_size = int(batch_size)
        except Exception:
            pass
    if interval is not None:
        try:
            w.interval = float(interval)
        except Exception:
            pass
    return w


def get_stats():
    w = get_writer()
    queue_size = None
    if getattr(w, "_use_litequeue", False) and getattr(w, "_lq", None) is not None:
        try:
            if hasattr(w._lq, "qsize"):
                queue_size = w._lq.qsize()
            elif hasattr(w._lq, "__len__"):
                queue_size = len(w._lq)
            elif hasattr(w._lq, "size"):
                queue_size = w._lq.size()
        except Exception:
            queue_size = None
    else:
        try:
            queue_size = w.queue.qsize()
        except Exception:
            queue_size = None
    return {"processed": getattr(w, "_processed_count", 0), "queue_size": queue_size}
