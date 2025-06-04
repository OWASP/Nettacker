import unittest
from unittest.mock import patch, MagicMock
from sqlalchemy import create_engine, inspect

from nettacker.config import Config
from nettacker.database.models import Base
from nettacker.database.sqlite import sqlite_create_tables

from tests.common import TestCase

class TestSQLiteFunctions(TestCase):
    @patch('nettacker.database.sqlite.create_engine')
    def test_sqlite_create_tables(self, mock_create_engine):
        Config.db = MagicMock()
        Config.db.as_dict.return_value = {
            'name': '/path/to/test.db'
        }
        
        mock_engine = MagicMock()
        mock_create_engine.return_value = mock_engine
        
        with patch.object(Base.metadata, 'create_all') as mock_create_all:
            sqlite_create_tables()
            
            mock_create_engine.assert_called_once_with(
                "sqlite:////path/to/test.db",
                connect_args={"check_same_thread": False}
            )
            mock_create_all.assert_called_once_with(mock_engine)

    def test_sqlite_create_tables_integration(self):
        engine = create_engine("sqlite:///:memory:")
        
        Config.db = MagicMock()
        Config.db.as_dict.return_value = {
            'name': ':memory:'
        }
        
        with patch('nettacker.database.sqlite.create_engine', return_value=engine):
            sqlite_create_tables()
            
            inspector = inspect(engine)
            tables = inspector.get_table_names()
            
            self.assertIn('reports', tables, "Reports table was not created")
            self.assertIn('temp_events', tables, "Temp events table was not created")
            self.assertIn('scan_events', tables, "Scan events table was not created")