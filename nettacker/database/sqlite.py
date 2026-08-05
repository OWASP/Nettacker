from sqlalchemy import create_engine, inspect, text

from nettacker.config import Config
from nettacker.database.models import Base


def sqlite_create_tables():
    db_engine = create_engine(
        "sqlite:///{name}".format(**Config.db.as_dict()),
        connect_args={"check_same_thread": False},
    )
    _ensure_temp_events_unique_constraint(db_engine)
    Base.metadata.create_all(db_engine)


def _ensure_temp_events_unique_constraint(db_engine):
    """
    `Base.metadata.create_all()` never alters an existing table, so a
    temp_events table created before uq_temp_events_claim existed would
    otherwise never pick it up. temp_events is transient, scan-scoped
    state (unlike reports/scan_events), so it's safe to drop and let
    create_all() rebuild it with the current schema if the constraint
    is missing.
    """

    inspector = inspect(db_engine)
    if "temp_events" not in inspector.get_table_names():
        return  # nothing to migrate, create_all() will build it fresh

    has_constraint = any(
        uc["name"] == "uq_temp_events_claim"
        for uc in inspector.get_unique_constraints("temp_events")
    )
    if not has_constraint:
        with db_engine.begin() as conn:
            conn.execute(text("DROP TABLE temp_events"))
