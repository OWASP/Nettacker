#!/usr/bin/env python
# -*- coding: utf-8 -*-

from sqlalchemy import create_engine

from database.models import Base
from core.config import _database_config


DATABASE = _database_config()["DATABASE"]


def sqlite_create_tables():
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
    except Exception as _:
        return False

