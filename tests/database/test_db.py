import json
from datetime import datetime
from unittest.mock import MagicMock, Mock, call, mock_open, patch

import apsw

from nettacker.api.helpers import structure
from nettacker.database.db import (
    create_connection,
    db_inputs,
    find_events,
    find_temp_events,
    get_logs_by_scan_id,
    get_options_by_scan_id,
    get_scan_result,
    last_host_logs,
    logs_to_report_html,
    logs_to_report_json,
    remove_old_logs,
    search_logs,
    select_reports,
    send_submit_query,
    submit_logs_to_db,
    submit_report_to_db,
    submit_temp_logs_to_db,
)


class TestDatabase:
    def setup_method(self):
        self.sample_event = {
            "date": "2024-01-01 10:00:00",
            "scan_id": "test_scan_123",
            "options": {"report_path_filename": "/tmp/test_report.json", "target": "192.168.1.1"},
        }

        self.sample_log = {
            "target": "192.168.1.1",
            "date": datetime(2024, 1, 1, 10, 0, 0),
            "module_name": "port_scan",
            "scan_id": "test_scan_123",
            "port": {"port": 80, "protocol": "tcp"},
            "event": {"status": "open"},
            "json_event": {"service": "http"},
        }

        self.sample_log_temp = {
            "target": "192.168.1.1",
            "date": "2024-01-01",
            "module_name": "mod",
            "scan_id": "scan123",
            "event_name": "eventABC",
            "port": {"port": 443},
            "event": {"status": "open"},
            "data": {"info": "some data"},
        }

        # For search_logs
        self.page = 1
        self.query = "test"

        self.target = "192.168.1.1"
        self.module = "port_scan"
        self.scan_id = "scan_123"
        self.event_name = "event_abc"

    # -------------------------------------------------------
    #                   Tests for db_inputs
    # -------------------------------------------------------

    @patch("nettacker.database.db.Config")
    def test_db_inputs_postgres(self, mock_config):
        mock_config.db.as_dict.return_value = {
            "username": "user",
            "password": "pass",
            "host": "localhost",
            "port": "5432",
            "name": "testdb",
            "ssl_mode": "require",
        }

        result = db_inputs("postgres")
        expected = "postgresql+psycopg2://user:pass@localhost:5432/testdb?sslmode=require"
        assert result == expected

    @patch("nettacker.database.db.Config")
    def test_db_inputs_mysql(self, mock_config):
        mock_config.db.as_dict.return_value = {
            "username": "user",
            "password": "pass",
            "host": "localhost",
            "port": "3306",
            "name": "testdb",
            "ssl_mode": "disable",
            "journal_mode": "WAL",
            "synchronous_mode": "NORMAL",
        }

        result = db_inputs("mysql")
        expected = "mysql+pymysql://user:pass@localhost:3306/testdb"
        assert result == expected

    # -------------------------------------------------------
    #              tests for create_connection
    # -------------------------------------------------------

    @patch("nettacker.database.db.apsw.Connection")
    @patch("nettacker.database.db.Config")
    @patch("nettacker.database.db.config")
    def test_create_connection_sqlite(
        self, mock_config_instance, mock_config_class, mock_apsw_conn
    ):
        mock_config_class.db.engine = "sqlite:///test.db"
        mock_config_class.db.journal_mode = "WAL"
        mock_config_class.db.synchronous_mode = "NORMAL"
        mock_config_instance.db.as_dict.return_value = {"name": "/tmp/test.db"}
        mock_config_instance.settings.timeout = 30

        mock_connection = Mock()
        mock_cursor = Mock()
        mock_connection.cursor.return_value = mock_cursor
        mock_apsw_conn.return_value = mock_connection

        result = create_connection()

        mock_apsw_conn.assert_called_once_with("/tmp/test.db")
        mock_connection.setbusytimeout.assert_called_once_with(3000)
        mock_cursor.execute.assert_any_call("PRAGMA journal_mode=WAL")
        mock_cursor.execute.assert_any_call("PRAGMA synchronous=NORMAL")

        assert result == (mock_connection, mock_cursor)

    @patch("nettacker.database.db.create_engine")
    @patch("nettacker.database.db.sessionmaker")
    @patch("nettacker.database.db.Config")
    def test_create_connection_mysql(self, mock_config, mock_sessionmaker, mock_create_engine):
        mock_config.db.engine = "mysql"
        mock_session_class = Mock()
        mock_session = Mock()
        mock_session_class.return_value = mock_session
        mock_sessionmaker.return_value = mock_session_class

        with patch("nettacker.database.db.db_inputs", return_value="mysql://test"):
            result = create_connection()

        mock_create_engine.assert_called_once()
        mock_sessionmaker.assert_called_once()
        assert result == mock_session

    # -------------------------------------------------------
    #              tests for send_submit_query
    # -------------------------------------------------------

    def test_send_submit_query_sqlite_success(self):
        """Test send_submit_query with SQLite connection - success case"""
        mock_connection = Mock()
        mock_cursor = Mock()
        session = (mock_connection, mock_cursor)

        result = send_submit_query(session)

        mock_connection.execute.assert_called_once_with("COMMIT")
        mock_connection.close.assert_called_once()
        assert result

    def test_send_submit_query_sqlite_retry_then_success(self):
        """Test send_submit_query with SQLite connection - retry then success"""
        mock_connection = Mock()
        mock_cursor = Mock()
        session = (mock_connection, mock_cursor)

        # First call fails, second succeeds, third rollback
        mock_connection.execute.side_effect = [Exception("Lock error"), None, None]

        with patch("time.sleep"):
            result = send_submit_query(session)

        assert mock_connection.execute.call_count == 3
        mock_connection.execute.assert_any_call("ROLLBACK")
        mock_connection.execute.assert_any_call("COMMIT")
        assert result

    @patch("nettacker.database.db.messages", return_value="mocked fail message")
    @patch("nettacker.database.db.logger.warn")
    def test_send_submit_query_sqlite_failure(self, mock_warn, mock_messages):
        def sqlite_execute_side_effect(query):
            if query == "COMMIT":
                raise Exception("Simulated commit failure")
            elif query == "ROLLBACK":
                return None
            return None

        mock_connection = Mock()
        mock_cursor = Mock()
        mock_connection.execute.side_effect = sqlite_execute_side_effect

        session = (mock_connection, mock_cursor)

        result = send_submit_query(session)

        assert not result
        mock_warn.assert_called_with("mocked fail message")

    def test_send_submit_query_sqlalchemy_success(self):
        mock_session = Mock()

        result = send_submit_query(mock_session)

        mock_session.commit.assert_called_once()
        assert result

    @patch("nettacker.database.db.messages", return_value="mocked fail message")
    @patch("nettacker.database.db.logger.warn")
    def test_send_submit_query_sqlalchemy_failure(self, mock_warn, mock_messages):
        mock_session = Mock()
        mock_session.commit.side_effect = [Exception("fail")] * 100

        result = send_submit_query(mock_session)

        assert not result
        assert mock_session.commit.call_count >= 99
        mock_warn.assert_called_with("mocked fail message")

    # -------------------------------------------------------
    #             tests for submit_report_to_db
    # -------------------------------------------------------

    @patch("nettacker.database.db.create_connection")
    @patch("nettacker.database.db.send_submit_query")
    def test_submit_report_to_db_sqlite(self, mock_send_submit, mock_create_conn):
        """Test submit_report_to_db with SQLite"""
        mock_connection = Mock()
        mock_cursor = Mock()
        mock_create_conn.return_value = (mock_connection, mock_cursor)
        mock_send_submit.return_value = True

        result = submit_report_to_db(self.sample_event)

        mock_cursor.execute.assert_any_call("BEGIN")
        mock_cursor.execute.assert_any_call(
            """
                INSERT INTO reports (date, scan_unique_id, report_path_filename, options)
                VALUES (?, ?, ?, ?)
                """,
            (
                "2024-01-01 10:00:00",
                "test_scan_123",
                "/tmp/test_report.json",
                json.dumps(self.sample_event["options"]),
            ),
        )
        assert result

    @patch("nettacker.database.db.create_connection")
    @patch("nettacker.database.db.send_submit_query")
    @patch("nettacker.database.db.Report")
    def test_submit_report_to_db_sqlalchemy(self, mock_report, mock_send_submit, mock_create_conn):
        """Test submit_report_to_db with SQLAlchemy"""
        mock_session = Mock()
        mock_create_conn.return_value = mock_session
        mock_send_submit.return_value = True
        mock_report_instance = Mock()
        mock_report.return_value = mock_report_instance

        result = submit_report_to_db(self.sample_event)

        mock_session.add.assert_called_once_with(mock_report_instance)
        mock_send_submit.assert_called_once_with(mock_session)
        assert result

    # -------------------------------------------------------
    #             tests for remove_old_logs
    # -------------------------------------------------------

    @patch("nettacker.database.db.create_connection")
    @patch("nettacker.database.db.send_submit_query")
    def test_remove_old_logs_sqlite(self, mock_send_submit, mock_create_conn):
        """Test remove_old_logs with SQLite"""
        mock_connection = Mock()
        mock_cursor = Mock()
        mock_create_conn.return_value = (mock_connection, mock_cursor)
        mock_send_submit.return_value = True

        options = {
            "target": "192.168.1.1",
            "module_name": "port_scan",
            "scan_id": "current_scan",
            "scan_compare_id": "compare_scan",
        }

        result = remove_old_logs(options)

        mock_cursor.execute.assert_any_call("BEGIN")
        mock_cursor.execute.assert_any_call(
            """
                DELETE FROM scan_events
                    WHERE target = ?
                      AND module_name = ?
                      AND scan_unique_id != ?
                      AND scan_unique_id != ?
                """,
            ("192.168.1.1", "port_scan", "current_scan", "compare_scan"),
        )
        assert result

    @patch("nettacker.database.db.send_submit_query", return_value=True)
    @patch("nettacker.database.db.create_connection")
    def test_remove_old_logs_sqlalchemy(self, mock_create_conn, mock_send_submit):
        """Test SQLAlchemy path of remove_old_logs"""

        # Create a mock SQLAlchemy session
        mock_session = MagicMock()
        mock_query = mock_session.query.return_value
        mock_filter = mock_query.filter.return_value

        mock_create_conn.return_value = mock_session

        options = {
            "target": "192.168.1.1",
            "module_name": "port_scan",
            "scan_id": "scan_001",
            "scan_compare_id": "scan_002",
        }

        result = remove_old_logs(options)

        # Assert that delete was called
        mock_filter.delete.assert_called_once_with(synchronize_session=False)

        # Assert send_submit_query was called with the session
        mock_send_submit.assert_called_once_with(mock_session)

        # Assert final result
        assert result

    # -------------------------------------------------------
    #             tests for submit_logs_to_db
    # -------------------------------------------------------

    @patch("nettacker.database.db.create_connection")
    @patch("nettacker.database.db.send_submit_query")
    @patch("nettacker.database.db.Config")
    def test_submit_logs_to_db_sqlite_success(
        self, mock_config, mock_send_submit, mock_create_conn
    ):
        """Test submit_logs_to_db with SQLite - success case"""
        mock_connection = Mock()
        mock_cursor = Mock()
        mock_create_conn.return_value = (mock_connection, mock_cursor)
        mock_send_submit.return_value = True
        mock_connection.in_transaction = False
        mock_config.settings.max_retries = 3

        result = submit_logs_to_db(self.sample_log)

        mock_connection.execute.assert_called_with("BEGIN")
        mock_cursor.execute.assert_called_with(
            """
                            INSERT INTO scan_events (target, date, module_name, scan_unique_id, port, event, json_event)
                            VALUES (?, ?, ?, ?, ?, ?, ?)
                            """,
            (
                "192.168.1.1",
                str(self.sample_log["date"]),
                "port_scan",
                "test_scan_123",
                json.dumps({"port": 80, "protocol": "tcp"}),
                json.dumps({"status": "open"}),
                json.dumps({"service": "http"}),
            ),
        )
        assert result

    @patch("nettacker.database.db.messages", return_value="invalid log")
    @patch("nettacker.database.db.logger.warn")
    def test_log_not_dict(self, mock_warn, mock_messages):
        result = submit_logs_to_db("notadict")
        assert not result
        mock_warn.assert_called_once_with("invalid log")

    @patch("nettacker.database.db.send_submit_query", return_value=True)
    @patch("nettacker.database.db.create_connection")
    def test_sqlite_happy_path(self, mock_create_conn, mock_submit):
        mock_conn = Mock()
        mock_cursor = Mock()
        mock_conn.in_transaction = False
        mock_create_conn.return_value = (mock_conn, mock_cursor)

        log = {
            "target": "1.1.1.1",
            "date": "2024-01-01",
            "module_name": "mod",
            "scan_id": "abc",
            "port": {"p": 80},
            "event": {"e": "open"},
            "json_event": {"j": "data"},
        }

        result = submit_logs_to_db(log)
        assert result
        mock_conn.execute.assert_any_call("BEGIN")

    @patch("nettacker.database.db.Config.settings.retry_delay", 0)
    @patch("nettacker.database.db.Config.settings.max_retries", 1)
    @patch("nettacker.database.db.logger.warn")
    @patch("nettacker.database.db.create_connection")
    def test_apsw_busy_error(self, mock_create_conn, mock_warn):
        mock_conn = Mock()
        mock_cursor = Mock()
        mock_conn.in_transaction = True
        mock_cursor.execute.side_effect = apsw.BusyError("database is locked")
        mock_create_conn.return_value = (mock_conn, mock_cursor)

        log = {
            "target": "1.1.1.1",
            "date": "2024-01-01",
            "module_name": "mod",
            "scan_id": "abc",
            "port": {"p": 80},
            "event": {"e": "open"},
            "json_event": {"j": "data"},
        }

        submit_logs_to_db(log)
        mock_warn.assert_has_calls(
            [
                call("Retry 1/1, Database is locked. Retrying submission to database"),
                call("All retries exhausted. Skipping this log."),
            ]
        )

    @patch("nettacker.database.db.create_connection")
    def test_sqlite_operational_error(self, mock_create_conn):
        mock_conn = Mock()
        mock_cursor = Mock()
        mock_conn.in_transaction = True
        mock_cursor.execute.side_effect = apsw.BusyError("other error")
        mock_create_conn.return_value = (mock_conn, mock_cursor)

        log = {
            "target": "1.1.1.1",
            "date": "2024-01-01",
            "module_name": "mod",
            "scan_id": "abc",
            "port": {"p": 80},
            "event": {"e": "open"},
            "json_event": {"j": "data"},
        }

        result = submit_logs_to_db(log)
        assert not result

    @patch("nettacker.database.db.create_connection")
    def test_sqlite_generic_exception(self, mock_create_conn):
        mock_conn = Mock()
        mock_cursor = Mock()
        mock_conn.in_transaction = True
        mock_cursor.execute.side_effect = Exception("generic")
        mock_create_conn.return_value = (mock_conn, mock_cursor)
        mock_cursor.execute.side_effect = [Exception("generic"), None]

        log = {
            "target": "1.1.1.1",
            "date": "2024-01-01",
            "module_name": "mod",
            "scan_id": "abc",
            "port": {"p": 80},
            "event": {"e": "open"},
            "json_event": {"j": "data"},
        }
        result = submit_logs_to_db(log)
        assert not result

    @patch("nettacker.database.db.send_submit_query", return_value=True)
    @patch("nettacker.database.db.create_connection")
    def test_sqlalchemy_path(self, mock_create_conn, mock_submit):
        mock_session = Mock()
        mock_create_conn.return_value = mock_session

        log = {
            "target": "1.1.1.1",
            "date": "2024-01-01",
            "module_name": "mod",
            "scan_id": "abc",
            "port": {"p": 80},
            "event": {"e": "open"},
            "json_event": {"j": "data"},
        }
        result = submit_logs_to_db(log)
        assert result
        mock_session.add.assert_called()

    @patch("nettacker.database.db.send_submit_query", return_value=False)
    @patch("nettacker.database.db.create_connection")
    def test_sqlalchemy_submit_fail(self, mock_create_conn, mock_submit):
        mock_session = Mock()
        mock_create_conn.return_value = mock_session

        log = {
            "target": "1.1.1.1",
            "date": "2024-01-01",
            "module_name": "mod",
            "scan_id": "abc",
            "port": {"p": 80},
            "event": {"e": "open"},
            "json_event": {"j": "data"},
        }
        result = submit_logs_to_db(log)
        assert not result

    # -------------------------------------------------------
    #           tests for submit_temp_logs_to_db
    # -------------------------------------------------------

    @patch("nettacker.database.db.create_connection")
    @patch("nettacker.database.db.send_submit_query")
    @patch("nettacker.database.db.Config")
    def test_submit_temp_logs_to_db_sqlite_success(
        self, mock_config, mock_send_submit, mock_create_conn
    ):
        mock_connection = Mock()
        mock_cursor = Mock()
        mock_create_conn.return_value = (mock_connection, mock_cursor)
        mock_send_submit.return_value = True
        mock_connection.in_transaction = False
        mock_config.settings.max_retries = 3

        result = submit_temp_logs_to_db(self.sample_log_temp)

        mock_cursor.execute.assert_any_call("BEGIN")
        sql, params = mock_cursor.execute.call_args[0]
        assert "INSERT INTO temp_events" in sql.strip()
        assert params == (
            "192.168.1.1",
            "2024-01-01",
            "mod",
            "scan123",
            "eventABC",
            json.dumps({"port": 443}),
            json.dumps({"status": "open"}),
            json.dumps({"info": "some data"}),
        )

        assert result

    @patch("nettacker.database.db.messages", return_value="invalid log")
    @patch("nettacker.database.db.logger.warn")
    def test_temp_log_not_dict(self, mock_warn, mock_messages):
        result = submit_temp_logs_to_db("notadict")
        assert not result
        mock_warn.assert_called_once_with("invalid log")

    @patch("nettacker.database.db.Config.settings.retry_delay", 0)
    @patch("nettacker.database.db.Config.settings.max_retries", 1)
    @patch("nettacker.database.db.logger.warn")
    @patch("nettacker.database.db.create_connection")
    def test_temp_log_busy_error(self, mock_create_conn, mock_warn):
        mock_conn = Mock()
        mock_cursor = Mock()
        mock_conn.in_transaction = True
        mock_cursor.execute.side_effect = apsw.BusyError("database is locked")
        mock_create_conn.return_value = (mock_conn, mock_cursor)

        result = submit_temp_logs_to_db(self.sample_log_temp)
        mock_warn.assert_has_calls(
            [
                call("Retry 1/1, Database is locked. Retrying submission to database"),
                call("All retries exhausted. Skipping this log."),
            ]
        )
        assert result  # we're continuing operation hence it returns True

    @patch("nettacker.database.db.create_connection")
    def test_temp_log_operational_error(self, mock_create_conn):
        mock_conn = Mock()
        mock_cursor = Mock()
        mock_conn.in_transaction = True
        mock_cursor.execute.side_effect = apsw.BusyError("some other error")
        mock_create_conn.return_value = (mock_conn, mock_cursor)

        result = submit_temp_logs_to_db(self.sample_log_temp)
        assert not result

    @patch("nettacker.database.db.create_connection")
    def test_temp_log_generic_exception(self, mock_create_conn):
        mock_conn = Mock()
        mock_cursor = Mock()
        mock_conn.in_transaction = True
        mock_cursor.execute.side_effect = Exception("unexpected")
        mock_create_conn.return_value = (mock_conn, mock_cursor)

        result = submit_temp_logs_to_db(self.sample_log_temp)
        assert not result

    @patch("nettacker.database.db.TempEvents")
    @patch("nettacker.database.db.send_submit_query", return_value=True)
    @patch("nettacker.database.db.create_connection")
    def test_temp_log_sqlalchemy_path(self, mock_create_conn, mock_send, mock_temp):
        mock_session = Mock()
        mock_create_conn.return_value = mock_session

        result = submit_temp_logs_to_db(self.sample_log_temp)

        mock_session.add.assert_called()
        mock_send.assert_called_with(mock_session)
        assert result

    @patch("nettacker.database.db.create_connection")
    def test_submit_temp_logs_to_db_sqlite(self, mock_create_conn):
        """Test submit_temp_logs_to_db with SQLite"""
        mock_connection = Mock()
        mock_cursor = Mock()
        mock_create_conn.return_value = (mock_connection, mock_cursor)
        mock_connection.in_transaction = False

        with patch("nettacker.database.db.send_submit_query", return_value=True):
            with patch("nettacker.database.db.Config") as mock_config:
                mock_config.settings.max_retries = 3

                temp_log = {
                    "target": "192.168.1.1",
                    "date": datetime(2024, 1, 1),
                    "module_name": "test_module",
                    "scan_id": "scan_123",
                    "event_name": "test_event",
                    "port": {"port": 80},
                    "event": {"status": "test"},
                    "data": {"info": "test_data"},
                }

                result = submit_temp_logs_to_db(temp_log)

                mock_cursor.execute.assert_any_call("BEGIN")
                mock_cursor.execute.assert_any_call(
                    """
                            INSERT INTO temp_events (target, date, module_name, scan_unique_id, event_name, port, event, data)
                            VALUES (?, ?, ?, ?, ?, ?, ?, ?)
                            """,
                    (
                        "192.168.1.1",
                        str(temp_log["date"]),
                        "test_module",
                        "scan_123",
                        "test_event",
                        json.dumps({"port": 80}),
                        json.dumps({"status": "test"}),
                        json.dumps({"info": "test_data"}),
                    ),
                )
                assert result

    # -------------------------------------------------------
    #           tests for find_temp_events
    # -------------------------------------------------------

    @patch("nettacker.database.db.create_connection")
    def test_sqlite_successful_lookup(self, mock_create_conn):
        mock_conn = Mock()
        mock_cursor = Mock()
        mock_create_conn.return_value = (mock_conn, mock_cursor)

        mock_cursor.fetchone.return_value = ('{"status": "open"}',)

        result = find_temp_events(self.target, self.module, self.scan_id, self.event_name)
        assert result == '{"status": "open"}'
        mock_cursor.execute.assert_called_once()
        mock_cursor.close.assert_called_once()

    @patch("nettacker.database.db.create_connection")
    def test_sqlite_no_result(self, mock_create_conn):
        mock_conn = Mock()
        mock_cursor = Mock()
        mock_cursor.fetchone.return_value = None
        mock_create_conn.return_value = (mock_conn, mock_cursor)

        result = find_temp_events(self.target, self.module, self.scan_id, self.event_name)
        assert result == []

    @patch("nettacker.database.db.create_connection")
    def test_sqlite_exception_and_retry(self, mock_create_conn):
        mock_conn = Mock()
        mock_cursor = Mock()
        mock_cursor.execute.side_effect = Exception("fail")
        mock_create_conn.return_value = (mock_conn, mock_cursor)

        with patch("time.sleep"):  # Skip delay
            result = find_temp_events(self.target, self.module, self.scan_id, self.event_name)
        assert result == []

    @patch("nettacker.database.db.logger.warn")
    @patch("nettacker.database.db.messages", return_value="database fail")
    @patch("nettacker.database.db.create_connection")
    def test_sqlite_outer_exception(self, mock_create_conn, mock_messages, mock_warn):
        mock_conn = Mock()
        mock_cursor = Mock()
        mock_create_conn.return_value = (mock_conn, mock_cursor)
        mock_cursor.execute.side_effect = Exception("fail")
        mock_cursor.close.side_effect = Exception("cursor close fail")

        with patch("time.sleep"), patch("builtins.range", side_effect=Exception("loop fail")):
            result = find_temp_events(self.target, self.module, self.scan_id, self.event_name)
        assert result == []
        mock_warn.assert_called_once_with("database fail")

    @patch("nettacker.database.db.create_connection")
    def test_sqlalchemy_successful_lookup(self, mock_create_conn):
        mock_session = MagicMock()
        query_mock = MagicMock()
        filter_mock = MagicMock()

        fake_result = MagicMock()
        fake_result.event = {"foo": "bar"}

        mock_session.query.return_value = query_mock
        query_mock.filter.return_value = filter_mock
        filter_mock.first.return_value = fake_result

        mock_create_conn.return_value = mock_session

        result = find_temp_events(self.target, self.module, self.scan_id, self.event_name)
        assert result == {"foo": "bar"}

    @patch("nettacker.database.db.create_connection")
    def test_sqlalchemy_no_result(self, mock_create_conn):
        mock_session = MagicMock()
        mock_session.query().filter().first.return_value = None
        mock_create_conn.return_value = mock_session

        result = find_temp_events(self.target, self.module, self.scan_id, self.event_name)
        if result == []:
            result = None
        assert result is None

    @patch("nettacker.database.db.create_connection")
    def test_find_temp_events_sqlite(self, mock_create_conn):
        """Test find_temp_events with SQLite"""
        mock_connection = Mock()
        mock_cursor = Mock()
        mock_create_conn.return_value = (mock_connection, mock_cursor)

        mock_cursor.fetchone.return_value = ('{"test": "data"}',)

        result = find_temp_events("192.168.1.1", "port_scan", "scan_123", "event_1")

        called_query, called_params = mock_cursor.execute.call_args[0]

        expected_query = """
            SELECT event
            FROM temp_events
            WHERE target = ? AND module_name = ? AND scan_unique_id = ? AND event_name = ?
            LIMIT 1
        """

        # Normalize whitespace (collapse multiple spaces/newlines into one space)
        def normalize(sql: str) -> str:
            return " ".join(sql.split())

        assert normalize(called_query) == normalize(expected_query)
        assert called_params == ("192.168.1.1", "port_scan", "scan_123", "event_1")
        assert result == '{"test": "data"}'

    # -------------------------------------------------------
    #               tests for find_events
    # -------------------------------------------------------

    @patch("nettacker.database.db.create_connection")
    def test_find_events_sqlite(self, mock_create_conn):
        """Test find_events with SQLite"""
        mock_connection = Mock()
        mock_cursor = Mock()
        mock_create_conn.return_value = (mock_connection, mock_cursor)

        mock_cursor.fetchall.return_value = [('{"event1": "data1"}',), ('{"event2": "data2"}',)]

        result = find_events("192.168.1.1", "port_scan", "scan_123")

        mock_cursor.execute.assert_called_with(
            """
                SELECT json_event FROM scan_events
                WHERE target = ? AND module_name = ? and scan_unique_id = ?
                """,
            ("192.168.1.1", "port_scan", "scan_123"),
        )
        expected = ['{"event1": "data1"}', '{"event2": "data2"}']
        assert result == expected

    @patch("nettacker.database.db.logger.warn")
    @patch("nettacker.database.db.create_connection")
    def test_find_events_sqlite_exception(self, mock_create_conn, mock_warn):
        mock_connection = Mock()
        mock_cursor = Mock()
        mock_create_conn.return_value = (mock_connection, mock_cursor)

        mock_cursor.execute.side_effect = Exception("DB error")
        result = find_events("192.168.1.1", "http", "scan_123")

        assert result == []
        mock_warn.assert_called_once_with("Could not query the database")

    @patch("nettacker.database.db.create_connection")
    def test_find_events_sqlalchemy(self, mock_create_conn):
        mock_session = Mock()
        mock_create_conn.return_value = mock_session

        mock_row1 = Mock()
        mock_row2 = Mock()
        mock_row1.json_event = '{"event": "scan started"}'
        mock_row2.json_event = '{"event": "port open"}'
        mock_session.query.return_value.filter.return_value.all.return_value = [
            mock_row1,
            mock_row2,
        ]

        result = find_events("192.168.1.1", "http", "scan_123")
        assert result == ['{"event": "scan started"}', '{"event": "port open"}']

        mock_session.query.assert_called_once()
        mock_session.query.return_value.filter.return_value.all.assert_called_once()

    # -------------------------------------------------------
    #               tests for select_reports
    # -------------------------------------------------------

    @patch("nettacker.database.db.create_connection")
    def test_select_reports_sqlite(self, mock_create_conn):
        """Test select_reports with SQLite"""
        mock_connection = Mock()
        mock_cursor = Mock()
        mock_create_conn.return_value = (mock_connection, mock_cursor)

        mock_cursor.fetchall.return_value = [
            (1, "2024-01-01", "scan_123", "/tmp/report.json", '{"target": "192.168.1.1"}')
        ]

        result = select_reports(self.page)

        mock_cursor.execute.assert_called_with(
            """
                SELECT id, date, scan_unique_id, report_path_filename, options
                FROM reports
                ORDER BY id DESC
                LIMIT 10 OFFSET ?
                """,
            (0,),
        )

        expected = [
            {
                "id": 1,
                "date": "2024-01-01",
                "scan_id": "scan_123",
                "report_path_filename": "/tmp/report.json",
                "options": {"target": "192.168.1.1"},
            }
        ]
        assert result == expected

    @patch("nettacker.database.db.logger.warn")
    @patch("nettacker.database.db.create_connection")
    def test_select_reports_sqlite_exception(self, mock_create_conn, mock_warn):
        mock_connection = Mock()
        mock_cursor = Mock()
        mock_create_conn.return_value = (mock_connection, mock_cursor)
        mock_cursor.execute.side_effect = Exception("DB Error")

        result = select_reports(self.page)
        assert result == structure(status="error", msg="Database error!")
        mock_warn.assert_called_once_with("Could not retrieve the report")

    @patch("nettacker.database.db.create_connection")
    def test_select_reports_sqlalchemy(self, mock_create_conn):
        mock_session = Mock()
        mock_create_conn.return_value = mock_session

        mock_report = Mock()
        mock_report.id = 1
        mock_report.date = "2024-01-01"
        mock_report.scan_unique_id = "scan_123"
        mock_report.report_path_filename = "/tmp/report.json"
        mock_report.options = json.dumps({"target": "192.168.1.1"})

        mock_session.query.return_value.order_by.return_value.offset.return_value.limit.return_value = [
            mock_report
        ]
        result = select_reports(self.page)

        assert result == [
            {
                "id": 1,
                "date": "2024-01-01",
                "scan_id": "scan_123",
                "report_path_filename": "/tmp/report.json",
                "options": {"target": "192.168.1.1"},
            }
        ]

    @patch("nettacker.database.db.create_connection")
    def test_select_reports_sqlalchemy_exception(self, mock_create_conn):
        mock_session = Mock()
        mock_create_conn.return_value = mock_session
        mock_session.query.side_effect = Exception("DB Error")
        result = select_reports(self.page)
        assert result == structure(status="error", msg="Database error!")

    # -------------------------------------------------------
    #               tests for get_scan_result
    # -------------------------------------------------------

    @patch("nettacker.database.db.create_connection")
    @patch("builtins.open", new_callable=mock_open, read_data=b'{"result": "data"}')
    def test_get_scan_result_sqlite(self, mock_open, mock_create_conn):
        mock_connection = Mock()
        mock_cursor = Mock()
        mock_create_conn.return_value = (mock_connection, mock_cursor)

        mock_cursor.fetchone.return_value = ("/tmp/report.json",)

        result = get_scan_result(1)

        mock_cursor.execute.assert_called_with(
            "SELECT report_path_filename from reports WHERE id = ?",
            (1,),
        )

        filename, content = result
        assert filename == "/tmp/report.json"
        assert content == b'{"result": "data"}'

    @patch("nettacker.database.db.create_connection")
    @patch("builtins.open", new_callable=mock_open, read_data=b"mock file content")
    def test_get_scan_result_sqlalchemy(self, mock_open_builtin, mock_create_conn):
        mock_session = Mock()
        mock_create_conn.return_value = mock_session

        mock_report = Mock()
        mock_report.report_path_filename = "/tmp/mock_report.json"

        mock_session.query.return_value.filter_by.return_value.first.return_value = mock_report

        filename, content = get_scan_result(1)
        assert filename == "/tmp/mock_report.json"
        assert content == b"mock file content"

        mock_open_builtin.assert_called_once_with("/tmp/mock_report.json", "rb")

    # -------------------------------------------------------
    #               tests for last_host_logs
    # -------------------------------------------------------

    @patch("nettacker.database.db.create_connection")
    def test_last_host_logs_sqlite(self, mock_create_conn):
        """Test last_host_logs with SQLite"""
        mock_connection = Mock()
        mock_cursor = Mock()
        mock_create_conn.return_value = (mock_connection, mock_cursor)

        # Mock the sequence of database calls
        mock_cursor.fetchall.side_effect = [
            [(self.target,)],  # targets
            [("port_scan",)],  # module_names for target
            [("port_scan",), ("vuln_scan",)],  # events for target
        ]
        mock_cursor.fetchone.return_value = ("2024-01-01",)  # latest_date

        result = last_host_logs(1)

        # Verify the structure of the result
        assert len(result) == 1
        assert result[0]["target"] == "192.168.1.1"
        assert "info" in result[0]

    # -------------------------------------------------------
    #               tests for get_logs_by_scan_id
    # -------------------------------------------------------

    @patch("nettacker.database.db.create_connection")
    def test_get_logs_by_scan_id_sqlite(self, mock_create_conn):
        """Test get_logs_by_scan_id with SQLite"""
        mock_connection = Mock()
        mock_cursor = Mock()
        mock_create_conn.return_value = (mock_connection, mock_cursor)

        mock_cursor.fetchall.return_value = [
            (
                "scan_123",
                "192.168.1.1",
                "port_scan",
                "2024-01-01",
                '{"port": 80}',
                '{"status": "open"}',
                '{"service": "http"}',
            )
        ]

        result = get_logs_by_scan_id("scan_123")

        mock_cursor.execute.assert_called_with(
            "SELECT scan_unique_id, target, module_name, date, port, event, json_event from scan_events WHERE scan_unique_id = ?",
            ("scan_123",),
        )

        expected = [
            {
                "scan_id": "scan_123",
                "target": "192.168.1.1",
                "module_name": "port_scan",
                "date": "2024-01-01",
                "port": {"port": 80},
                "event": {"status": "open"},
                "json_event": {"service": "http"},
            }
        ]
        assert result == expected

    # -------------------------------------------------------
    #               tests for get_options_by_scan_id
    # -------------------------------------------------------

    @patch("nettacker.database.db.create_connection")
    def test_get_options_by_scan_id_sqlite(self, mock_create_conn):
        """Test get_options_by_scan_id with SQLite"""
        mock_connection = Mock()
        mock_cursor = Mock()
        mock_create_conn.return_value = (mock_connection, mock_cursor)

        mock_cursor.fetchall.return_value = [('{"target": "192.168.1.1"}',)]

        result = get_options_by_scan_id("scan_123")

        mock_cursor.execute.assert_called_with(
            "SELECT options from reports WHERE scan_unique_id = ?",
            ("scan_123",),
        )

        expected = [{"options": '{"target": "192.168.1.1"}'}]
        assert result == expected

    # -------------------------------------------------------
    #               tests for logs_to_report_json
    # -------------------------------------------------------

    @patch("nettacker.database.db.create_connection")
    def test_logs_to_report_json_sqlite(self, mock_create_conn):
        """Test logs_to_report_json with SQLite"""
        mock_connection = Mock()
        mock_cursor = Mock()
        mock_create_conn.return_value = (mock_connection, mock_cursor)

        mock_cursor.fetchall.return_value = [
            (
                "scan_123",
                "192.168.1.1",
                '{"port": 80}',
                '{"status": "open"}',
                '{"service": "http"}',
            )
        ]

        result = logs_to_report_json("192.168.1.1")

        mock_cursor.execute.assert_called_with(
            "SELECT scan_unique_id, target, port, event, json_event FROM scan_events WHERE target = ?",
            ("192.168.1.1",),
        )

        expected = [
            {
                "scan_id": "scan_123",
                "target": "192.168.1.1",
                "port": {"port": 80},
                "event": {"status": "open"},
                "json_event": {"service": "http"},
            }
        ]
        assert result == expected

    # -------------------------------------------------------
    #               tests for logs_to_report_html
    # -------------------------------------------------------

    @patch("nettacker.lib.html_log.log_data.table_title", "<html><head>{}</head><body>{}")
    @patch("nettacker.lib.html_log.log_data.css_1", "css_content")
    @patch("nettacker.lib.html_log.log_data.table_items", "<tr><td>...</td></tr>")
    @patch("nettacker.lib.html_log.log_data.table_end", "</table>")
    @patch("nettacker.core.graph.build_graph")
    @patch("nettacker.database.db.create_connection")
    @patch("nettacker.database.db.messages")
    def test_logs_to_report_html_sqlite(self, mock_messages, mock_create_conn, mock_build_graph):
        """Test logs_to_report_html with SQLite"""

        # Setup mock database connection and cursor
        mock_connection = Mock()
        mock_cursor = Mock()
        mock_create_conn.return_value = (mock_connection, mock_cursor)

        # Simulated query result from the logs table
        mock_cursor.fetchall.return_value = [
            (
                "2024-01-01",
                "192.168.1.1",
                "port_scan",
                "scan_123",
                '{"port": 80}',
                '{"status": "open"}',
                '{"service": "http"}',
            )
        ]

        # Simulated return values for graph and messages
        mock_build_graph.return_value = "graph_html"
        mock_messages.return_value = "Generated by Nettacker"

        # Call the function
        result = logs_to_report_html("192.168.1.1")

        # Assertions
        assert isinstance(result, str)
        assert "graph_html" in result
        assert "</table>" in result
        assert "Generated by Nettacker" in result

    @patch("nettacker.lib.html_log.log_data.table_title", "<html><head>{}</head><body>{}")
    @patch("nettacker.lib.html_log.log_data.css_1", "css_content")
    @patch(
        "nettacker.lib.html_log.log_data.table_items",
        "<tr><td>{0}</td><td>{1}</td><td>{2}</td><td>{3}</td><td>{4}</td><td>{5}</td><td>{6}</td></tr>",
    )
    @patch("nettacker.lib.html_log.log_data.table_end", "</table>")
    @patch("nettacker.core.graph.build_graph")
    @patch("nettacker.database.db.create_connection")
    @patch("nettacker.database.db.messages", return_value="Generated by Nettacker")
    def test_logs_to_report_html_sqlalchemy(
        self, mock_messages, mock_create_conn, mock_build_graph
    ):
        """Test logs_to_report_html with SQLAlchemy fallback"""

        # Simulate SQLAlchemy session
        mock_session = MagicMock()
        mock_create_conn.return_value = mock_session

        # Fake log row (SQLAlchemy object with attributes)
        fake_log = MagicMock()
        fake_log.date = "2024-01-01"
        fake_log.target = "192.168.1.1"
        fake_log.module_name = "port_scan"
        fake_log.scan_unique_id = "scan_123"
        fake_log.port = '{"port": 80}'
        fake_log.event = '{"status": "open"}'
        fake_log.json_event = '{"service": "http"}'

        # SQLAlchemy .query().filter().all() returns a list of logs
        mock_session.query().filter().all.return_value = [fake_log]

        # Graph output
        mock_build_graph.return_value = "graph_html"

        # Call the function
        result = logs_to_report_html("192.168.1.1")

        # Assertions
        assert isinstance(result, str)
        assert "graph_html" in result
        assert "</table>" in result
        assert "Generated by Nettacker" in result
        assert "192.168.1.1" in result
        assert "scan_123" in result

    # -------------------------------------------------------
    #               tests for search_logs
    # -------------------------------------------------------

    @patch("nettacker.database.db.create_connection")
    def test_search_logs_sqlite(self, mock_create_conn):
        """Test search_logs with SQLite"""
        mock_connection = Mock()
        mock_cursor = Mock()
        mock_create_conn.return_value = (mock_connection, mock_cursor)

        # Mock the sequence of calls for search
        mock_cursor.fetchall.side_effect = [
            [("192.168.1.1",)],  # targets matching query
            [
                (
                    "2024-01-01",
                    "port_scan",
                    '{"port": 80}',
                    '{"status": "open"}',
                    '{"service": "http"}',
                )
            ],  # results for target
        ]

        result = search_logs(1, "192.168")

        # Verify search query structure
        search_call = mock_cursor.execute.call_args_list[0]
        assert "%192.168%" in search_call[0][1]

        assert len(result) == 1
        assert result[0]["target"] == "192.168.1.1"

    @patch("nettacker.database.db.create_connection")
    @patch("nettacker.database.db.structure")
    def test_search_logs_no_results(self, mock_structure, mock_create_conn):
        """Test search_logs with no results"""
        mock_connection = Mock()
        mock_cursor = Mock()
        mock_create_conn.return_value = (mock_connection, mock_cursor)

        mock_cursor.fetchall.return_value = []
        mock_structure.return_value = {"status": "finished", "msg": "No more search results"}

        result = search_logs(1, "nonexistent")

        mock_structure.assert_called_with(status="finished", msg="No more search results")
        assert result == {"status": "finished", "msg": "No more search results"}

    @patch("nettacker.database.db.create_connection")
    def test_sqlite_path_exception(self, mock_create_conn):
        mock_conn = Mock()
        mock_cursor = Mock()
        mock_cursor.execute.side_effect = Exception("db error")
        mock_create_conn.return_value = (mock_conn, mock_cursor)

        result = search_logs(self.page, self.query)
        assert result["status"] == "error"
        assert "Database error" in result["msg"]

    @patch("nettacker.database.db.create_connection")
    def test_sqlalchemy_path_success(self, mock_create_conn):
        mock_session = MagicMock()
        mock_create_conn.return_value = mock_session

        host_mock = MagicMock()
        host_mock.target = "192.168.1.1"
        mock_session.query().filter().group_by().order_by().offset().limit().__iter__.return_value = [
            host_mock
        ]

        data_mock = MagicMock()
        data_mock.target = "192.168.1.1"
        data_mock.module_name = "mod"
        data_mock.date = "2024-01-01"
        data_mock.port = json.dumps({"port": 80})
        data_mock.event = json.dumps({"event": "open"})
        data_mock.json_event = json.dumps({"svc": "http"})
        mock_session.query().filter().group_by().order_by().all.return_value = [data_mock]

        result = search_logs(self.page, self.query)
        assert result[0]["target"] == "192.168.1.1"
        assert "mod" in result[0]["info"]["module_name"]

    @patch("nettacker.database.db.create_connection")
    def test_sqlalchemy_path_exception(self, mock_create_conn):
        mock_session = MagicMock()
        mock_create_conn.return_value = mock_session
        mock_session.query().filter().group_by().order_by().offset().limit.side_effect = Exception(
            "boom"
        )

        result = search_logs(self.page, self.query)
        assert result["status"] == "error"
        assert "Database error" in result["msg"]

    @patch("nettacker.database.db.create_connection")
    def test_sqlalchemy_path_no_results(self, mock_create_conn):
        mock_session = MagicMock()
        mock_create_conn.return_value = mock_session
        mock_session.query().filter().group_by().order_by().offset().limit().__iter__.return_value = []

        result = search_logs(self.page, self.query)
        assert result["status"] == "finished"
        assert result["msg"] == "No more search results"
