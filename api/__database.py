#!/usr/bin/env python
# -*- coding: utf-8 -*-

import sqlite3
import os
from core.config import _core_config
from core.config_builder import _core_default_config
from core.config_builder import _builder
from core.alert import warn
from core.alert import messages


def create_connection(language):
    try:
        return sqlite3.connect(os.path.join(os.path.dirname(os.path.dirname(__file__)),
                                            _builder(_core_config(), _core_default_config())["api_db_name"]))
    except:
        warn(messages(language, 168))
        return False


def submit_report_to_db(date, scan_id, report_filename, events_num, verbose, api_flag, report_type, graph_flag,
                        category, profile, scan_method, language, scan_cmd):
    conn = create_connection(language)
    if not conn:
        return False
    try:
        c = conn.cursor()
        c.execute("""
        INSERT INTO reports (
          date, scan_id, report_filename, events_num, verbose, 
          api_flag, report_type, graph_flag, category, profile, 
          scan_method, language, scan_cmd     
        )
        VALUES (
          '{0}', '{1}', '{2}', '{3}', '{4}',
          '{5}', '{6}', '{7}', '{8}', '{9}',
          '{10}', '{11}', '{12}'
        );
        """.format(date, scan_id, report_filename, events_num, verbose,
                   api_flag, report_type, graph_flag, category, profile,
                   scan_method, language, scan_cmd))
        conn.commit()
        conn.close()
    except:
        warn(messages(language, 168))
        print 2
        return False
    return True
