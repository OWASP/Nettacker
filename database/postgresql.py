from sqlalchemy import create_engine, text
from sqlalchemy.exc import OperationalError

from nettacker.config import Config
from nettacker.database.models import Base


def postgres_create_database():
    """
    when using postgres database, this is the function that is used to
    create the database for the first time when you the nettacker run module.
    """
    try:
        engine = create_engine(
            "postgresql+psycopg2://{username}:{password}@{host}:{port}/{name}".format(
                **Config.db.as_dict()
            )
        )
        Base.metadata.create_all(engine)
    except OperationalError:
        # if the database does not exist
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
