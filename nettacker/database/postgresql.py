from sqlalchemy import create_engine, text, inspect
from sqlalchemy.exc import OperationalError

from nettacker.config import Config
from nettacker.database.models import Base


def _ensure_temp_events_unique_constraint(engine):
    """Add the temp_events claim unique constraint if it does not already exist."""

    inspector = inspect(engine)

    if "temp_events" not in inspector.get_table_names():
        return

    existing = {
        constraint["name"]
        for constraint in inspector.get_unique_constraints("temp_events")
        if constraint.get("name")
    }

    if "uq_temp_events_claim" in existing:
        return

    with engine.begin() as conn:
        conn.execute(
            text(
                """
                ALTER TABLE temp_events
                ADD CONSTRAINT uq_temp_events_claim
                UNIQUE (
                    target,
                    module_name,
                    scan_unique_id,
                    event_name,
                    port
                )
                """
            )
        )


def postgres_create_database():
    """
    Create the PostgreSQL database (if needed), create tables,
    and upgrade existing databases with the temp_events unique
    constraint if required.
    """
    try:
        engine = create_engine(
            "postgresql+psycopg2://{username}:{password}@{host}:{port}/{name}".format(
                **Config.db.as_dict()
            )
        )

        Base.metadata.create_all(engine)
        _ensure_temp_events_unique_constraint(engine)

    except OperationalError:
        engine = create_engine(
            "postgresql+psycopg2://{username}:{password}@{host}:{port}/postgres".format(
                **Config.db.as_dict()
            )
        )

        conn = engine.connect()
        conn = conn.execution_options(isolation_level="AUTOCOMMIT")
        conn.execute(text(f"CREATE DATABASE {Config.db.name}"))
        conn.close()

        engine = create_engine(
            "postgresql+psycopg2://{username}:{password}@{host}:{port}/{name}".format(
                **Config.db.as_dict()
            )
        )

        Base.metadata.create_all(engine)
