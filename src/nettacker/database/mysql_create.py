#!/usr/bin/env python3
# -*- coding: utf-8 -*-

from sqlalchemy import create_engine

from nettacker.config import nettacker_database_config
from nettacker.database.models import Base


USER = nettacker_database_config()["USERNAME"]
PASSWORD = nettacker_database_config()["PASSWORD"]
HOST = nettacker_database_config()["HOST"]
PORT = nettacker_database_config()["PORT"]
DATABASE = nettacker_database_config()["DATABASE"]


def mysql_create_database():
    """
    when using mysql database, this is the function that is used to create the database for the first time when you run
    the nettacker module.

    Args:
        None

    Returns:
        True if success otherwise False
    """
    try:
        engine = create_engine('mysql://{0}:{1}@{2}:{3}'.format(USER, PASSWORD, HOST, PORT))
        existing_databases = engine.execute("SHOW DATABASES;")
        existing_databases = [
            d[0] for d in existing_databases
        ]
        if DATABASE not in existing_databases:
            engine.execute("CREATE DATABASE {0} ".format(DATABASE))
        return True
    except Exception:
        return False


def mysql_create_tables():
    """
        when using mysql database, this is the function that is used to create the tables in the database for the first
        time when you run the nettacker module.

        Args:
            None

        Returns:
            True if success otherwise False
        """
    try:
        db_engine = create_engine('mysql://{0}:{1}@{2}:{3}/{4}'.format(USER, PASSWORD, HOST, PORT, DATABASE))
        Base.metadata.create_all(db_engine)
        return True
    except Exception:
        return False