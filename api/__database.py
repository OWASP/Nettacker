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
from api.api_core import __structure
from flask import jsonify


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


def __select_results(language, page, api_flag):
    conn = create_connection(language, api_flag)
    log = ""
    page = int(page * 10 if page > 0 else page * -10) - 10

    data_structure = {"id": "", "date": "", "scan_id": "", "report_filename": "",
                      "events_num": "", "verbose": "", "api_flag": "", "report_type": "",
                      "graph_flag": "", "category": "", "profile": "", "scan_method": "",
                      "language": "", "scan_cmd": "", "ports": ""}
    selected = []
    try:
        c = conn.cursor()
        for data in c.execute("""select * from reports where 1 order by id desc limit {0},10""".format(page)):
            tmp = dict(data_structure)
            tmp["id"] = data[0]
            tmp["date"] = data[1]
            tmp["scan_id"] = data[2]
            tmp["report_filename"] = data[3]
            tmp["events_num"] = data[4]
            tmp["verbose"] = data[5]
            tmp["api_flag"] = data[6]
            tmp["report_type"] = data[7]
            tmp["graph_flag"] = data[8]
            tmp["category"] = data[9]
            tmp["profile"] = data[10]
            tmp["scan_method"] = data[11]
            tmp["language"] = data[12]
            tmp["scan_cmd"] = data[13]
            tmp["ports"] = data[14]
            selected.append(tmp)
        conn.close()
    except:
        return __structure(status="error", msg="database error!")
    return selected


def __get_result(language, id, api_flag):
    conn = create_connection(language, api_flag)
    try:
        c = conn.cursor()
        c.execute("""select report_filename from reports where id={0}""".format(id))
        try:
            filename = c.fetchone()[0]
            return open(filename, 'rb').read(), 200
        except:
            return jsonify(__structure(status="error", msg="cannot find the file!")), 400
    except:
        return jsonify(__structure(status="error", msg="database error!")), 200
