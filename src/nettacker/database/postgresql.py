from sqlalchemy import create_engine
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
            "postgres+psycopg2://{username}:{password}@{host}:{port}/{name}".format(
                **Config.db.as_dict()
            )
        )
        Base.metadata.create_all(engine)
    except OperationalError:
        # if the database does not exist
        engine = create_engine("postgres+psycopg2://postgres:postgres@localhost/postgres")
        conn = engine.connect()
        conn.execute("commit")
        conn.execute(f"CREATE DATABASE {Config.db.name}")
        conn.close()

        engine = create_engine(
            "postgres+psycopg2://{username}:{password}@{host}:{port}/{name}".format(
                **Config.db.as_dict()
            )
        )
        Base.metadata.create_all(engine)
