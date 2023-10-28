#!/usr/bin/env python3
# -*- coding: utf-8 -*-

from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy import (Column,
                        Integer,
                        Text,
                        DateTime)

Base = declarative_base()


class Report(Base):
    """
    This class defines the table schema of the reports table. Any changes to the reports table need to be done here.
    """
    __tablename__ = 'reports'

    id = Column(Integer, primary_key=True, autoincrement=True)
    date = Column(DateTime)
    scan_unique_id = Column(Text)
    report_path_filename = Column(Text)
    options = Column(Text)

    def __repr__(self):
        """
        returns a printable representation of the object of the class Report
        """
        return "<Report(id={0}, scan_unique_id={1}, date={2}, report_path_filename={3})>".format(
            self.id,
            self.scan_unique_id,
            self.date,
            self.report_path_filename
        )


class TempEvents(Base):
    """
    This class defines the table schema of the reports table. Any changes to the reports table need to be done here.
    """
    __tablename__ = 'temp_events'

    id = Column(Integer, primary_key=True, autoincrement=True)
    date = Column(DateTime)
    target = Column(Text)
    module_name = Column(Text)
    scan_unique_id = Column(Text)
    event_name = Column(Text)
    port = Column(Text)
    event = Column(Text)
    data = Column(Text)

    def __repr__(self):
        """
        returns a printable representation of the object of the class Report
        """
        return '''
                    <scan_events(id={0}, target={1}, date={2}, module_name={3}, scan_unqiue_id={4}, 
                    port={5}, event={6}, data={7})>
                '''.format(
            self.id,
            self.target,
            self.date,
            self.module_name,
            self.scan_unique_id,
            self.port,
            self.event,
            self.data
        )


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
    port = Column(Text)
    event = Column(Text)
    json_event = Column(Text)

    def __repr__(self):
        """
        returns a printable representation of the object of the class HostsLog
        """
        return '''
            <scan_events(id={0}, target={1}, date={2}, module_name={3}, scan_unqiue_id={4}, 
            port={5}, event={6}, json_event={7})>
        '''.format(
            self.id,
            self.target,
            self.date,
            self.module_name,
            self.scan_unique_id,
            self.port,
            self.event,
            self.json_event
        )
