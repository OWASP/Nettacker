#!/usr/bin/env python
# -*- coding: utf-8 -*-

import sqlite3
import os
from core.config import _core_config
from core.config_builder import _core_default_config
from core.config_builder import _builder
from core.alert import warn
from core.alert import info
from core.alert import messages


def create_connection(language, api_flag):
    try:
        return sqlite3.connect(os.path.join(os.path.dirname(os.path.dirname(__file__)),
                                            _builder(_core_config(), _core_default_config())["api_db_name"]))
    except:
        if api_flag is 0:
            warn(messages(language, 168))
        return False


def submit_report_to_db(date, scan_id, report_filename, events_num, verbose, api_flag, report_type, graph_flag,
                        category, profile, scan_method, language, scan_cmd, ports):
    conn = create_connection(language, api_flag)
    if not conn:
        return False
    try:
        if api_flag is 0:
            info(messages(language, 169))
        c = conn.cursor()
        c.execute("""
        INSERT INTO reports (
          date, scan_id, report_filename, events_num, verbose, 
          api_flag, report_type, graph_flag, category, profile, 
          scan_method, language, scan_cmd, ports     
        )
        VALUES (
          '{0}', '{1}', '{2}', '{3}', '{4}',
          '{5}', '{6}', '{7}', '{8}', '{9}',
          '{10}', '{11}', '{12}', '{13}'
        );
        """.format(date, scan_id, report_filename, events_num, verbose,
                   api_flag, report_type, graph_flag, category, profile,
                   scan_method, language, scan_cmd, ports))
        conn.commit()
        conn.close()
    except:
        if api_flag is 0:
            warn(messages(language, 168))
        return False
    return True


def submit_logs_to_db(language, api_flag, log):
    conn = create_connection(language, api_flag)
    try:
        c = conn.cursor()
        c.execute("""
        INSERT INTO hosts_log (
          host, date, port, type, category,
          description, username, password, scan_id, scan_cmd    
        )
        VALUES (
          '{0}', '{1}', '{2}', '{3}', '{4}',
          '{5}', '{6}', '{7}', '{8}', '{9}'
        );
        """.format(log["HOST"], log["TIME"], log["PORT"], log["TYPE"], log["CATEGORY"],
                   log["DESCRIPTION"], log["USERNAME"], log["PASSWORD"], log["SCAN_ID"], log["SCAN_CMD"]))
        conn.commit()
        conn.close()
    except:
        if api_flag is 0:
            warn(messages(language, 168))
        return False
    return True
