#!/usr/bin/env python
# -*- coding: utf-8 -*-

from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy import Column, Integer, Text

Base = declarative_base()

class Update_Log(Base):
    """
    This Class defines the table schema for the update log table, Any changes related to updating log table need to be done here.
    """
    __tablename__ = 'update'
    id = Column(Integer, primary_key=True, autoincrement=True)
    last_update_time = Column(Text)
    def __repr__(self):
        """
        returns a printable representation of the object of the class Update Log
        """
        return "<Update_Log(id={0}, last_update_time={2})>".format(self.id, self.last_update_time)


class Report(Base):
    """
    This class defines the table schema of the reports table. Any changes to the reports table need to be done here.
    """
    __tablename__ = 'reports'

    id = Column(Integer, primary_key=True, autoincrement=True)
    date = Column(Text)
    scan_id = Column(Text)
    report_filename = Column(Text)
    events_num = Column(Integer)
    verbose = Column(Integer)
    api_flag = Column(Integer)
    report_type = Column(Text)
    graph_flag = Column(Text)
    category = Column(Text)
    profile = Column(Text)
    scan_method = Column(Text)
    language = Column(Text)
    scan_cmd = Column(Text)
    ports = Column(Text)

    def __repr__(self):
        """
        returns a printable representation of the object of the class Report
        """
        return "<Report(id={0}, scan_id={1}, date={2})>".format(self.id, self.scan_id, self.date)


class HostsLog(Base):
    """
    This class defines the table schema of the hosts_log table. Any changes to the reports hosts_log need to be done here.
    """
    __tablename__ = 'hosts_log'

    id = Column(Integer, primary_key=True, autoincrement=True)
    host = Column(Text)
    date = Column(Text)
    scan_id = Column(Text)
    scan_cmd = Column(Text)
    username = Column(Text)
    password = Column(Text)
    description = Column(Text)
    port = Column(Text)
    category = Column(Text)
    type = Column(Text)

    def __repr__(self):
        """
        returns a printable representation of the object of the class HostsLog
        """
        return "<HostsLog(id={0}, host={1}, date={2})>".format(self.id, self.host, self.date)
