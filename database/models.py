#!/usr/bin/env python3
# -*- coding: utf-8 -*-

from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy import (Column,
                        Integer,
                        Text,
                        DateTime)
from sqlalchemy.sql.sqltypes import VARCHAR

Base = declarative_base()


class Report(Base):
    """
    This class defines the table schema of the reports table. Any changes to the reports table need to be done here.
    """
    __tablename__ = 'reports'

    id = Column(Integer, primary_key=True, autoincrement=True)
    date = Column(DateTime)
    scan_unique_id = Column(Text)
    options = Column(Text)

    def __repr__(self):
        """
        returns a printable representation of the object of the class Report
        """
        return "<Report(id={0}, scan_unique_id={1}, date={2})>".format(self.id, self.scan_unique_id, self.date)


class HostsLog(Base):
    """
    This class defines the table schema of the hosts_log table. Any changes to the reports hosts_log need to be done here.
    """
    __tablename__ = 'scan_events'

    id = Column(Integer, primary_key=True, autoincrement=True)
    date = Column(DateTime)
    target = Column(Text)
    module_name = Column(Text)
    scan_unique_id = Column(Text)
    options = Column(Text)
    event = Column(Text)

    def __repr__(self):
        """
        returns a printable representation of the object of the class HostsLog
        """
        return '''
            <scan_events(id={0}, target={1}, date={2}, module_name={3}, scan_unqiue_id={4}, 
            options={5}, event={6})>
        '''.format(self.id, self.target, self.date, self.module_name, self.scan_unique_id,
                   self.options, self.event)
