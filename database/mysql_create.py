#!/usr/bin/env python
# -*- coding: utf-8 -*-

import time
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from database.config import HOST, USER, PASSWORD, PORT, DATABASE
from database.models import Base
from core.alert import warn
from core.alert import messages


def create_database():
    try:
        engine = create_engine('mysql://{0}:{1}@{2}:{3}'.format(USER, PASSWORD, HOST, PORT))
        existing_databases = engine.execute("SHOW DATABASES;")
        existing_databases = [d[0] for d in existing_databases]
        if DATABASE not in existing_databases:
            engine.execute("CREATE DATABASE {0} ".format(DATABASE))
        return True
    except:
        return False


def create_tables():
    try:
        db_engine = create_engine('mysql://{0}:{1}@{2}:{3}/{4}'.format(USER, PASSWORD, HOST, PORT, DATABASE))
        Base.metadata.create_all(db_engine)
        return True
    except:
        return False


def create_connection(language):
    try:
        for i in range(0, 100):
            try:
                db_engine = create_engine('mysql://{0}:{1}@{2}:{3}/{4}'.format(USER, PASSWORD, HOST, PORT, DATABASE))
                Session = sessionmaker(bind=db_engine)
                session = Session()
                return session
            except:
                time.sleep(0.01)
    except:
        warn(messages(language, "database_connect_fail"))
    return False
