from datetime import datetime

from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

from nettacker.database.models import Base, Report, TempEvents, HostsLog
from tests.common import TestCase


class TestModels(TestCase):
    def setUp(self):
        # Creating an in-memory SQLite database for testing
        self.engine = create_engine("sqlite:///:memory:")
        Base.metadata.create_all(self.engine)
        Session = sessionmaker(bind=self.engine)
        self.session = Session()

    def tearDown(self):
        self.session.close()
        Base.metadata.drop_all(self.engine)

    def test_report_model(self):
        test_date = datetime.now()
        test_report = Report(
            date=test_date,
            scan_unique_id="test123",
            report_path_filename="/path/to/report.txt",
            options='{"option1": "value1"}',
        )

        self.session.add(test_report)
        self.session.commit()

        retrieved_report = self.session.query(Report).first()
        self.assertIsNotNone(retrieved_report)
        self.assertEqual(retrieved_report.scan_unique_id, "test123")
        self.assertEqual(retrieved_report.report_path_filename, "/path/to/report.txt")
        self.assertEqual(retrieved_report.options, '{"option1": "value1"}')

        repr_string = repr(retrieved_report)
        self.assertIn("test123", repr_string)
        self.assertIn("/path/to/report.txt", repr_string)

    def test_temp_events_model(self):
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

        self.session.add(test_event)
        self.session.commit()

        retrieved_event = self.session.query(TempEvents).first()
        self.assertIsNotNone(retrieved_event)
        self.assertEqual(retrieved_event.target, "192.168.1.1")
        self.assertEqual(retrieved_event.module_name, "port_scan")
        self.assertEqual(retrieved_event.port, "80")

        repr_string = repr(retrieved_event)
        self.assertIn("192.168.1.1", repr_string)
        self.assertIn("port_scan", repr_string)

    def test_hosts_log_model(self):
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

        self.session.add(test_log)
        self.session.commit()

        retrieved_log = self.session.query(HostsLog).first()
        self.assertIsNotNone(retrieved_log)
        self.assertEqual(retrieved_log.target, "192.168.1.1")
        self.assertEqual(retrieved_log.module_name, "vulnerability_scan")
        self.assertEqual(retrieved_log.port, "443")
        self.assertEqual(retrieved_log.event, "Found vulnerability CVE-2021-12345")

        repr_string = repr(retrieved_log)
        self.assertIn("192.168.1.1", repr_string)
        self.assertIn("vulnerability_scan", repr_string)
