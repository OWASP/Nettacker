from sqlalchemy import create_engine, inspect, text

from nettacker.config import Config
from nettacker.database.models import Base


def sqlite_create_tables():
    """
    Create the SQLite schema and migrate older temp_events tables if needed.
    """
    db_engine = create_engine(
        "sqlite:///{name}".format(**Config.db.as_dict()),
        connect_args={"check_same_thread": False},
    )

    _ensure_temp_events_unique_constraint(db_engine)
    Base.metadata.create_all(db_engine)


def _ensure_temp_events_unique_constraint(db_engine):
    """
    SQLite cannot ALTER TABLE to add a UNIQUE constraint.

    If an existing temp_events table predates the
    uq_temp_events_claim constraint, recreate it while preserving
    existing rows. Duplicate rows are discarded automatically via
    INSERT OR IGNORE.
    """

    inspector = inspect(db_engine)

    # Fresh database: create_all() will create the table.
    if "temp_events" not in inspector.get_table_names():
        return

    has_constraint = any(
        uc.get("name") == "uq_temp_events_claim"
        for uc in inspector.get_unique_constraints("temp_events")
    )

    if has_constraint:
        return

    with db_engine.begin() as conn:
        # Rename the old table.
        conn.execute(text("ALTER TABLE temp_events RENAME TO temp_events_old"))

    # Create the new table using the current SQLAlchemy model
    # (which now contains the UNIQUE constraint).
    Base.metadata.create_all(db_engine)

    with db_engine.begin() as conn:
        # Copy existing rows into the new table.
        # INSERT OR IGNORE drops duplicate claim rows automatically.
        conn.execute(
            text(
                """
                INSERT OR IGNORE INTO temp_events
                (
                    target,
                    date,
                    module_name,
                    scan_unique_id,
                    event_name,
                    port,
                    event,
                    data
                )
                SELECT
                    target,
                    date,
                    module_name,
                    scan_unique_id,
                    event_name,
                    port,
                    event,
                    data
                FROM temp_events_old
                """
            )
        )

        conn.execute(text("DROP TABLE temp_events_old"))
