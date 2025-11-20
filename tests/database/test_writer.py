import os
import subprocess
from pathlib import Path


def start_worker_process(tmp_path):
    # run worker in separate process
    env = os.environ.copy()
    # ensure current project is first on PYTHONPATH
    env["PYTHONPATH"] = str(Path.cwd()) + os.pathsep + env.get("PYTHONPATH", "")
    # Pass config through environment
    data_dir = tmp_path / ".data"
    env["NETTACKER_DATA_DIR"] = str(data_dir)
    env["NETTACKER_DB_NAME"] = str(data_dir / "nettacker.db")

    proc = subprocess.Popen(
        [
            env.get("PYTHON_BIN", "python"),
            "-m",
            "nettacker.cli.db_worker",
            "--once",  # Process all items and exit
            "--max-items",
            "10",
            "--summary",  # Show processing stats
        ],
        env=env,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
    )
    print(f"Started worker process {proc.pid} with data_dir={data_dir}")
    return proc


def test_worker_writes(tmp_path):
    """Test that the database writer correctly processes queued jobs and writes to database."""
    # Create test database
    data_dir = tmp_path / ".data"
    data_dir.mkdir()
    db_path = str(data_dir / "nettacker.db")

    # Create database tables
    from sqlalchemy import create_engine, text

    from nettacker.database.models import Base

    engine = create_engine(f"sqlite:///{db_path}")
    Base.metadata.create_all(engine)
    engine.dispose()

    # Create a writer configured to use the test database
    from sqlalchemy.orm import sessionmaker

    from nettacker.database.writer import DBWriter

    writer = DBWriter()
    # Override the database connection to use our test database
    writer.engine = create_engine(
        f"sqlite:///{db_path}", connect_args={"check_same_thread": False}, pool_pre_ping=True
    )
    # Enable WAL mode for better concurrency
    with writer.engine.connect() as conn:
        conn.execute(text("PRAGMA journal_mode=WAL"))
        conn.commit()
    writer.Session = sessionmaker(bind=writer.engine)

    # Create test jobs for both report and hosts log
    jobs = [
        {
            "action": "insert_report",
            "payload": {
                "date": None,
                "scan_id": "test-scan",
                "report_path_filename": str(data_dir / "r.html"),
                "options": {"report_path_filename": str(data_dir / "r.html")},
            },
        },
        {
            "action": "insert_hostslog",
            "payload": {
                "date": None,
                "target": "127.0.0.1",
                "module_name": "m",
                "scan_id": "test-scan",
                "port": [],
                "event": {},
                "json_event": {},
            },
        },
    ]

    # Enqueue jobs to the writer
    for job in jobs:
        writer.enqueue(job)

    # Process all queued jobs
    processed_count = writer.drain_once(max_iterations=10)
    assert processed_count == 2

    # Verify the jobs were written to the database
    import sqlite3

    conn = sqlite3.connect(db_path)
    c = conn.cursor()

    c.execute("select count(*) from reports where scan_unique_id = ?", ("test-scan",))
    report_count = c.fetchone()[0]

    c.execute("select count(*) from scan_events where scan_unique_id = ?", ("test-scan",))
    hosts_count = c.fetchone()[0]

    conn.close()

    assert report_count == 1
    assert hosts_count == 1
