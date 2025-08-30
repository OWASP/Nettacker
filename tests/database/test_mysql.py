from unittest.mock import patch, MagicMock

import pytest
from sqlalchemy.exc import SQLAlchemyError

from nettacker.config import Config
from nettacker.database.models import Base
from nettacker.database.mysql import mysql_create_database, mysql_create_tables


@pytest.fixture(autouse=True)
def setup_config():
    Config.db = MagicMock()
    Config.db.as_dict.return_value = {
        "username": "test_user",
        "password": "test_pass",
        "host": "localhost",
        "port": "3306",
        "name": "test_db",
    }
    Config.db.name = "test_db"


@patch("nettacker.database.mysql.create_engine")
def test_mysql_create_database_success(mock_create_engine):
    mock_conn = MagicMock()
    mock_engine = MagicMock()
    mock_create_engine.return_value = mock_engine
    mock_engine.connect.return_value.__enter__.return_value = mock_conn
    mock_conn.execute.return_value = [("mysql",), ("information_schema",)]

    mysql_create_database()

    mock_create_engine.assert_called_once_with(
        "mysql+pymysql://test_user:test_pass@localhost:3306"
    )

    call_args_list = mock_conn.execute.call_args_list
    assert len(call_args_list) == 2

    first_call_arg = call_args_list[0][0][0]
    assert str(first_call_arg) == "SHOW DATABASES;"

    second_call_arg = call_args_list[1][0][0]
    assert str(second_call_arg) == "CREATE DATABASE test_db "


@patch("nettacker.database.mysql.create_engine")
def test_mysql_create_database_already_exists(mock_create_engine):
    mock_conn = MagicMock()
    mock_engine = MagicMock()
    mock_create_engine.return_value = mock_engine
    mock_engine.connect.return_value.__enter__.return_value = mock_conn
    mock_conn.execute.return_value = [("mysql",), ("information_schema",), ("test_db",)]

    mysql_create_database()

    mock_create_engine.assert_called_once_with(
        "mysql+pymysql://test_user:test_pass@localhost:3306"
    )

    assert mock_conn.execute.call_count == 1
    call_arg = mock_conn.execute.call_args[0][0]
    assert str(call_arg) == "SHOW DATABASES;"


@patch("nettacker.database.mysql.create_engine")
def test_mysql_create_database_exception(mock_create_engine):
    mock_engine = MagicMock()
    mock_create_engine.return_value = mock_engine
    mock_engine.connect.side_effect = SQLAlchemyError("Connection error")

    with patch("builtins.print") as mock_print:
        mysql_create_database()
        mock_print.assert_called_once()


@patch("nettacker.database.mysql.create_engine")
def test_mysql_create_tables(mock_create_engine):
    mock_engine = MagicMock()
    mock_create_engine.return_value = mock_engine

    with patch.object(Base.metadata, "create_all") as mock_create_all:
        mysql_create_tables()

        mock_create_engine.assert_called_once_with(
            "mysql+pymysql://test_user:test_pass@localhost:3306/test_db"
        )
        mock_create_all.assert_called_once_with(mock_engine)
