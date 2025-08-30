from datetime import datetime

import pytest
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

from nettacker.database.models import Base, Report, TempEvents, HostsLog


@pytest.fixture
def session():
    engine = create_engine("sqlite:///:memory:")
    Base.metadata.create_all(engine)
    Session = sessionmaker(bind=engine)
    sess = Session()
    yield sess
    sess.close()
    Base.metadata.drop_all(engine)


def test_report_model(session):
    test_date = datetime.now()
    test_report = Report(
        date=test_date,
        scan_unique_id="test123",
        report_path_filename="/path/to/report.txt",
        options='{"option1": "value1"}',
    )

    session.add(test_report)
    session.commit()

    retrieved_report = session.query(Report).first()
    assert retrieved_report is not None
    assert retrieved_report.scan_unique_id == "test123"
    assert retrieved_report.report_path_filename == "/path/to/report.txt"
    assert retrieved_report.options == '{"option1": "value1"}'

    repr_string = repr(retrieved_report)
    assert "test123" in repr_string
    assert "/path/to/report.txt" in repr_string


def test_temp_events_model(session):
    test_date = datetime.now()
    test_event = TempEvents(
        date=test_date,
        target="192.168.1.1",
        module_name="port_scan",
        scan_unique_id="test123",
        event_name="open_port",
        port="80",
        event="Port 80 is open",
        data='{"details": "HTTP server running"}',
    )

    session.add(test_event)
    session.commit()

    retrieved_event = session.query(TempEvents).first()
    assert retrieved_event is not None
    assert retrieved_event.target == "192.168.1.1"
    assert retrieved_event.module_name == "port_scan"
    assert retrieved_event.port == "80"

    repr_string = repr(retrieved_event)
    assert "192.168.1.1" in repr_string
    assert "port_scan" in repr_string


def test_hosts_log_model(session):
    test_date = datetime.now()
    test_log = HostsLog(
        date=test_date,
        target="192.168.1.1",
        module_name="vulnerability_scan",
        scan_unique_id="test123",
        port="443",
        event="Found vulnerability CVE-2021-12345",
        json_event='{"vulnerability": "CVE-2021-12345", "severity": "high"}',
    )

    session.add(test_log)
    session.commit()

    retrieved_log = session.query(HostsLog).first()
    assert retrieved_log is not None
    assert retrieved_log.target == "192.168.1.1"
    assert retrieved_log.module_name == "vulnerability_scan"
    assert retrieved_log.port == "443"
    assert retrieved_log.event == "Found vulnerability CVE-2021-12345"

    repr_string = repr(retrieved_log)
    assert "192.168.1.1" in repr_string
    assert "vulnerability_scan" in repr_string
