#!/usr/bin/env python3
# -*- coding: utf-8 -*-

from sqlalchemy import create_engine
from config import nettacker_database_config
from database.models import Base
from sqlalchemy.exc import OperationalError

USER = nettacker_database_config()["USERNAME"]
PASSWORD = nettacker_database_config()["PASSWORD"]
HOST = nettacker_database_config()["HOST"]
PORT = nettacker_database_config()["PORT"]
DATABASE = nettacker_database_config()["DATABASE"]


def postgres_create_database():
    """
    when using postgres database, this is the function that is used to create the database for the first time when you
    the nettacker run module.

    Args:
        None

    Returns:
        True if success otherwise False
    """

    try:
        engine = create_engine(
            'postgres+psycopg2://{0}:{1}@{2}:{3}/{4}'.format(USER, PASSWORD, HOST, PORT, DATABASE)
        )
        Base.metadata.create_all(engine)
        return True
    except OperationalError:
        # if the database does not exist
        engine = create_engine(
            "postgres+psycopg2://postgres:postgres@localhost/postgres")
        conn = engine.connect()
        conn.execute("commit")
        conn.execute('CREATE DATABASE {0}'.format(DATABASE))
        conn.close()
        engine = create_engine(
            'postgres+psycopg2://{0}:{1}@{2}:{3}/{4}'.format(
                USER,
                PASSWORD,
                HOST,
                PORT,
                DATABASE
            )
        )
        Base.metadata.create_all(engine)
    except Exception:
        return False
