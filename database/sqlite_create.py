#!/usr/bin/env python
# -*- coding: utf-8 -*-

import time

from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

from database.models import Base
from core.config import _database_config
from core.alert import warn
from core.alert import messages


DATABASE = _database_config()["DATABASE"]

def create_tables():
    """
    when using sqlite database, this is the function that is used to create the database schema for the first time when
    you run the nettacker module.

    Args:
        None

    Returns:
        True if success otherwise False
    """
    try:
        db_engine = create_engine('sqlite:///{0}'.format(DATABASE))
        Base.metadata.create_all(db_engine)
        return True
    except:
        return False


def create_connection(language):
    """
        a function to create connections to db, it retries 100 times if connection returned an error

        Args:
            language: language

        Returns:
            connection if success otherwise False
    """
    try:
        for i in range(0, 100):
            try:
                db_engine = create_engine('sqlite:///{0}'.format(DATABASE))
                Session = sessionmaker(bind=db_engine)
                session = Session()
                return session
            except:
                time.sleep(0.01)
    except:
        warn(messages(language, "database_connect_fail"))
    return False
