from unittest.mock import patch, MagicMock

from sqlalchemy.exc import OperationalError

from nettacker.config import Config
from nettacker.database.models import Base
from nettacker.database.postgresql import postgres_create_database
from tests.common import TestCase


class TestPostgresFunctions(TestCase):
    @patch("nettacker.database.postgresql.create_engine")
    def test_postgres_create_database_success(self, mock_create_engine):
        Config.db = MagicMock()
        Config.db.as_dict.return_value = {
            "username": "user",
            "password": "pass",
            "host": "localhost",
            "port": "5432",
            "name": "nettacker_db",
        }

        mock_engine = MagicMock()
        mock_create_engine.return_value = mock_engine

        with patch.object(Base.metadata, "create_all") as mock_create_all:
            postgres_create_database()

            mock_create_engine.assert_called_once_with(
                "postgresql+psycopg2://user:pass@localhost:5432/nettacker_db"
            )
            mock_create_all.assert_called_once_with(mock_engine)

    @patch("nettacker.database.postgresql.create_engine")
    def test_postgres_create_database_if_not_exists(self, mock_create_engine):
        Config.db = MagicMock()
        Config.db.as_dict.return_value = {
            "username": "user",
            "password": "pass",
            "host": "localhost",
            "port": "5432",
            "name": "nettacker_db",
        }
        Config.db.name = "nettacker_db"

        mock_engine_initial = MagicMock()
        mock_engine_fallback = MagicMock()
        mock_engine_final = MagicMock()

        mock_create_engine.side_effect = [
            mock_engine_initial,
            mock_engine_fallback,
            mock_engine_final,
        ]

        with patch.object(
            Base.metadata, "create_all", side_effect=[OperationalError("fail", None, None), None]
        ):
            mock_conn = MagicMock()
            mock_engine_fallback.connect.return_value = mock_conn
            mock_conn.execution_options.return_value = mock_conn

            postgres_create_database()

            assert mock_create_engine.call_count == 3
            args, _ = mock_conn.execute.call_args
            assert str(args[0]) == "CREATE DATABASE nettacker_db"
            mock_conn.close.assert_called_once()

    @patch("nettacker.database.postgresql.create_engine")
    def test_postgres_create_database_create_fail(self, mock_create_engine):
        Config.db = MagicMock()
        Config.db.as_dict.return_value = {
            "username": "user",
            "password": "pass",
            "host": "localhost",
            "port": "5432",
            "name": "nettacker_db",
        }

        mock_engine_initial = MagicMock()
        mock_engine_fallback = MagicMock()

        mock_create_engine.side_effect = [mock_engine_initial, mock_engine_fallback]

        mock_engine_fallback.connect.side_effect = OperationalError("fail again", None, None)

        with patch.object(
            Base.metadata, "create_all", side_effect=OperationalError("fail", None, None)
        ):
            with self.assertRaises(OperationalError):
                postgres_create_database()
