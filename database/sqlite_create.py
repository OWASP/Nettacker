import time

from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

from database.config import DATABASE
from database.models import Base
from core.alert import warn
from core.alert import messages


def create_tables():
    try:
        db_engine = create_engine('sqlite:///{0}'.format(DATABASE))
        Base.metadata.create_all(db_engine)
        return True
    except:
        return False


def create_connection(language):
    try:
        for i in range(0, 100):
            try:
                db_engine = create_engine('sqlite:///sqlalchemy_example.db')
                Session = sessionmaker(bind=db_engine)
                session = Session()
                return session
            except:
                time.sleep(0.01)
    except:
        warn(messages(language, "database_connect_fail"))
    return False