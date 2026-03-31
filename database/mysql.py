from sqlalchemy import create_engine, text

from nettacker.config import Config
from nettacker.database.models import Base


def mysql_create_database():
    """
    when using mysql database, this is the function that is used to create the
    database for the first time when you run the nettacker module.
    """
    engine = create_engine(
        "mysql+pymysql://{username}:{password}@{host}:{port}".format(**Config.db.as_dict())
    )

    # Earlier we were quering using the engine itself, but we first need to create a connection
    try:
        with engine.connect() as conn:
            existing_databases = conn.execute(text("SHOW DATABASES;"))
            existing_databases = [d[0] for d in existing_databases]

            if Config.db.name not in existing_databases:
                conn.execute(text("CREATE DATABASE {0} ".format(Config.db.name)))
    except Exception as e:
        print(e)


def mysql_create_tables():
    """
    when using mysql database, this is the function that is used to create the
    tables in the database for the first time when you run the nettacker module.

    Args:
        None

    Returns:
        True if success otherwise False
    """
    db_engine = create_engine(
        "mysql+pymysql://{username}:{password}@{host}:{port}/{name}".format(**Config.db.as_dict())
    )
    Base.metadata.create_all(db_engine)
