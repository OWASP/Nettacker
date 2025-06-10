from unittest.mock import patch, MagicMock

from sqlalchemy.exc import SQLAlchemyError

from nettacker.config import Config
from nettacker.database.models import Base
from nettacker.database.mysql import mysql_create_database, mysql_create_tables
from tests.common import TestCase


class TestMySQLFunctions(TestCase):
    """Test cases for mysql.py functions"""

    @patch("nettacker.database.mysql.create_engine")
    def test_mysql_create_database_success(self, mock_create_engine):
        """Test successful database creation"""
        # Set up mock config
        Config.db = MagicMock()
        Config.db.as_dict.return_value = {
            "username": "test_user",
            "password": "test_pass",
            "host": "localhost",
            "port": "3306",
            "name": "test_db",
        }
        Config.db.name = "test_db"

        # Set up mock connection and execution
        mock_conn = MagicMock()
        mock_engine = MagicMock()
        mock_create_engine.return_value = mock_engine
        mock_engine.connect.return_value.__enter__.return_value = mock_conn

        # Mock database query results - database doesn't exist yet
        mock_conn.execute.return_value = [("mysql",), ("information_schema",)]

        # Call the function
        mysql_create_database()

        # Assertions
        mock_create_engine.assert_called_once_with(
            "mysql+pymysql://test_user:test_pass@localhost:3306"
        )

        # Check that execute was called with any text object that has the expected SQL
        call_args_list = mock_conn.execute.call_args_list
        self.assertEqual(len(call_args_list), 2)  # Two calls to execute

        # Check that the first call is SHOW DATABASES
        first_call_arg = call_args_list[0][0][0]
        self.assertEqual(str(first_call_arg), "SHOW DATABASES;")

        # Check that the second call is CREATE DATABASE
        second_call_arg = call_args_list[1][0][0]
        self.assertEqual(str(second_call_arg), "CREATE DATABASE test_db ")

    @patch("nettacker.database.mysql.create_engine")
    def test_mysql_create_database_already_exists(self, mock_create_engine):
        """Test when database already exists"""
        # Set up mock config
        Config.db = MagicMock()
        Config.db.as_dict.return_value = {
            "username": "test_user",
            "password": "test_pass",
            "host": "localhost",
            "port": "3306",
            "name": "test_db",
        }
        Config.db.name = "test_db"

        # Set up mock connection and execution
        mock_conn = MagicMock()
        mock_engine = MagicMock()
        mock_create_engine.return_value = mock_engine
        mock_engine.connect.return_value.__enter__.return_value = mock_conn

        # Mock database query results - database already exists
        mock_conn.execute.return_value = [("mysql",), ("information_schema",), ("test_db",)]

        # Call the function
        mysql_create_database()

        # Assertions
        mock_create_engine.assert_called_once_with(
            "mysql+pymysql://test_user:test_pass@localhost:3306"
        )

        # Check that execute was called once with SHOW DATABASES
        self.assertEqual(mock_conn.execute.call_count, 1)
        call_arg = mock_conn.execute.call_args[0][0]
        self.assertEqual(str(call_arg), "SHOW DATABASES;")

    @patch("nettacker.database.mysql.create_engine")
    def test_mysql_create_database_exception(self, mock_create_engine):
        """Test exception handling in create database"""
        # Set up mock config
        Config.db = MagicMock()
        Config.db.as_dict.return_value = {
            "username": "test_user",
            "password": "test_pass",
            "host": "localhost",
            "port": "3306",
            "name": "test_db",
        }

        # Set up mock to raise exception
        mock_engine = MagicMock()
        mock_create_engine.return_value = mock_engine
        mock_engine.connect.side_effect = SQLAlchemyError("Connection error")

        # Call the function (should not raise exception)
        with patch("builtins.print") as mock_print:
            mysql_create_database()
            mock_print.assert_called_once()

    @patch("nettacker.database.mysql.create_engine")
    def test_mysql_create_tables(self, mock_create_engine):
        """Test table creation function"""
        # Set up mock config
        Config.db = MagicMock()
        Config.db.as_dict.return_value = {
            "username": "test_user",
            "password": "test_pass",
            "host": "localhost",
            "port": "3306",
            "name": "test_db",
        }

        # Set up mock engine
        mock_engine = MagicMock()
        mock_create_engine.return_value = mock_engine

        # Call the function
        with patch.object(Base.metadata, "create_all") as mock_create_all:
            mysql_create_tables()

            # Assertions
            mock_create_engine.assert_called_once_with(
                "mysql+pymysql://test_user:test_pass@localhost:3306/test_db"
            )
            mock_create_all.assert_called_once_with(mock_engine)
