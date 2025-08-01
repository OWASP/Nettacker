from unittest.mock import patch, MagicMock

import pytest
from sqlalchemy import create_engine, inspect

from nettacker.config import Config
from nettacker.database.models import Base
from nettacker.database.sqlite import sqlite_create_tables


@pytest.fixture
def mock_config():
    Config.db = MagicMock()
    yield Config.db


@patch("nettacker.database.sqlite.create_engine")
def test_sqlite_create_tables(mock_create_engine, mock_config):
    mock_config.as_dict.return_value = {"name": "/path/to/test.db"}

    mock_engine = MagicMock()
    mock_create_engine.return_value = mock_engine

    with patch.object(Base.metadata, "create_all") as mock_create_all:
        sqlite_create_tables()

        mock_create_engine.assert_called_once_with(
            "sqlite:////path/to/test.db", connect_args={"check_same_thread": False}
        )
        mock_create_all.assert_called_once_with(mock_engine)


def test_sqlite_create_tables_integration(mock_config):
    engine = create_engine("sqlite:///:memory:")
    mock_config.as_dict.return_value = {"name": ":memory:"}

    with patch("nettacker.database.sqlite.create_engine", return_value=engine):
        sqlite_create_tables()

        inspector = inspect(engine)
        tables = inspector.get_table_names()

        assert "reports" in tables, "Reports table was not created"
        assert "temp_events" in tables, "Temp events table was not created"
        assert "scan_events" in tables, "Scan events table was not created"
