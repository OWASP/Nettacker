#!/usr/bin/env python
# -*- coding: utf-8 -*-

import sqlite3
import os
import json
import time
from core.config import _core_config
from core.config_builder import _core_default_config
from core.config_builder import _builder
from core.alert import warn
from core.alert import info
from core.alert import messages
from api.api_core import __structure
from flask import jsonify
from core.compatible import version
from core._time import now
from core import compatible


def create_connection(language):
    try:
        # retries
        for i in range(0, 100):
            try:
                return sqlite3.connect(os.path.join(os.path.dirname(os.path.dirname(__file__)),
                                                    _builder(_core_config(), _core_default_config())["api_db_name"]))
            except:
                pass
                time.sleep(0.01)
    except:
        warn(messages(language, 168))
        return False


def send_submit_query(query, language):
    conn = create_connection(language)
    if not conn:
        return False
    try:
        for i in range(1, 100):
            try:
                c = conn.cursor()
                c.execute(query)
                conn.commit()
                conn.close()
                break
            except:
                pass
                time.sleep(0.01)
    except:
        warn(messages(language, 168))
        return False
    return True


def send_read_query(query, language):
    conn = create_connection(language)
    if not conn:
        return False
    try:
        for i in range(1, 100):
            try:
                c = conn.cursor()
                return c.execute(query)
            except:
                pass
                time.sleep(0.01)
    except:
        warn(messages(language, 168))
        return False
    return True


def submit_report_to_db(date, scan_id, report_filename, events_num, verbose, api_flag, report_type, graph_flag,
                        category, profile, scan_method, language, scan_cmd, ports):
    info(messages(language, 169))
    send_submit_query("""
    INSERT INTO reports (
      date, scan_id, report_filename, events_num, verbose, 
      api_flag, report_type, graph_flag, category, profile, 
      scan_method, language, scan_cmd, ports     
    )
    VALUES (
      "{0}", "{1}", "{2}", "{3}", "{4}",
      "{5}", "{6}", "{7}", "{8}", "{9}",
      "{10}", "{11}", "{12}", "{13}"
    );
    """.format(date, scan_id, report_filename, events_num, verbose,
               api_flag, report_type, graph_flag, category, profile,
               scan_method, language, scan_cmd, ports), language)
    return True


def remove_old_logs(host, type, scan_id, language):
    send_submit_query("""delete from hosts_log where host="{0}" and type="{1}" and scan_id!="{2}" """
                      .format(host, type, scan_id), language)
    return True


def submit_logs_to_db(language, log):
    if type(log) == str:
        log = json.loads(log)
    send_submit_query("""
                    INSERT INTO hosts_log (
                      host, date, port, type, category,
                      description, username, password, scan_id, scan_cmd    
                    )
                    VALUES (
                      "{0}", "{1}", "{2}", "{3}", "{4}",
                      "{5}", "{6}", "{7}", "{8}", "{9}"
                    );
                    """.format(log["HOST"], log["TIME"], log["PORT"], log["TYPE"], log["CATEGORY"],
                               log["DESCRIPTION"].encode('utf8') if version() is 2 else log["DESCRIPTION"],
                               log["USERNAME"], log["PASSWORD"], log["SCAN_ID"], log["SCAN_CMD"]),
                      language)
    return True


def __select_results(language, page):
    page = int(page * 10 if page > 0 else page * -10) - 10
    selected = []
    try:
        for data in send_read_query("""select * from reports where 1 order by id desc limit {0},10""".format(page),
                                    language):
            tmp = {  # fix later, junks
                "id": data[0],
                "date": data[1],
                "scan_id": data[2],
                "report_filename": data[3],
                "events_num": data[4],
                "verbose": data[5],
                "api_flag": data[6],
                "report_type": data[7],
                "graph_flag": data[8],
                "category": data[9],
                "profile": data[10],
                "scan_method": data[11],
                "language": data[12],
                "scan_cmd": data[13],
                "ports": data[14]
            }
            selected.append(tmp)
    except:
        return __structure(status="error", msg="database error!")
    return selected


def __get_result(language, id):
    try:
        try:
            filename = send_read_query("""select report_filename from reports where id=\"{0}\";""".format(id),
                                       language).fetchone()[0]
            return open(filename, 'rb').read(), 200
        except:
            return jsonify(__structure(status="error", msg="cannot find the file!")), 400
    except:
        return jsonify(__structure(status="error", msg="database error!")), 200


def __last_host_logs(language, page):
    page = int(page * 10 if page > 0 else page * -10) - 10
    data_structure = {
        "host": "",
        "info": {
            "open_ports": [],
            "scan_methods": [],
            "category": [],
            "descriptions": []
        }
    }
    selected = []
    try:
        for host in send_read_query(
                """select host from hosts_log where 1 group by host order by id desc limit {0},10""".format(page),
                language):
            for data in send_read_query(
                    """select host,port,type,category,description from hosts_log where host="{0}" group by type,port,username,""" \
                    """password,description order by id desc""".format(host[0]), language):
                n = 0
                capture = None
                for selected_data in selected:
                    if selected_data["host"] == host[0]:
                        capture = n
                    n += 1
                if capture is None:
                    tmp = {  # fix later, junks
                        "host": data[0],
                        "info": {
                            "open_ports": [],
                            "scan_methods": [],
                            "category": [],
                            "descriptions": []
                        }
                    }
                    selected.append(tmp)
                    n = 0
                    for selected_data in selected:
                        if selected_data["host"] == host[0]:
                            capture = n
                        n += 1
                if data[0] == selected[capture]["host"]:
                    if data[1] not in selected[capture]["info"]["open_ports"] and type(data[1]) is int:
                        selected[capture]["info"]["open_ports"].append(data[1])
                    if data[2] not in selected[capture]["info"]["scan_methods"]:
                        selected[capture]["info"]["scan_methods"].append(data[2])
                    if data[3] not in selected[capture]["info"]["category"]:
                        selected[capture]["info"]["category"].append(data[3])
                    if data[4] not in selected[capture]["info"]["descriptions"]:
                        selected[capture]["info"]["descriptions"].append(data[4])
    except:
        return __structure(status="error", msg="database error!")
    return selected


def __logs_by_scan_id(scan_id, language):
    try:
        logs = []
        for log in send_read_query(
                "select host,username,password,port,type,date,description from hosts_log where scan_id=\"{0}\"".format(
                    scan_id), language):
            data = {
                "SCAN_ID": scan_id,
                "HOST": log[0],
                "USERNAME": log[1],
                "PASSWORD": log[2],
                "PORT": log[3],
                "TYPE": log[4],
                "TIME": log[5],
                "DESCRIPTION": log[6]
            }
            logs.append(data)
        return logs
    except:
        return []


def __logs_to_report_json(host, language):
    try:
        logs = []
        for log in send_read_query(
                "select scan_id,username,password,port,type,date,description from hosts_log where host=\"{0}\"".format(
                    host), language):
            data = {
                "SCAN_ID": log[0],
                "HOST": host,
                "USERNAME": log[1],
                "PASSWORD": log[2],
                "PORT": log[3],
                "TYPE": log[4],
                "TIME": log[5],
                "DESCRIPTION": log[6]
            }
            logs.append(data)
        return logs
    except:
        return []


def __logs_to_report_html(host, language):
    try:
        logs = []
        for log in send_read_query(
                "select host,username,password,port,type,date,description from hosts_log where host=\"{0}\"".format(
                    host), language):
            data = {
                "SCAN_ID": host,
                "HOST": log[0],
                "USERNAME": log[1],
                "PASSWORD": log[2],
                "PORT": log[3],
                "TYPE": log[4],
                "TIME": log[5],
                "DESCRIPTION": log[6]
            }
            logs.append(data)
        from core.log import build_graph
        if compatible.version() is 2:
            import sys
            reload(sys)
            sys.setdefaultencoding('utf8')
        _graph = build_graph("d3_tree_v2_graph", "en", logs, 'HOST', 'USERNAME', 'PASSWORD', 'PORT', 'TYPE',
                             'DESCRIPTION')
        from lib.html_log import _log_data
        _table = _log_data.table_title.format(_graph, _log_data.css_1, 'HOST', 'USERNAME', 'PASSWORD', 'PORT', 'TYPE',
                                              'DESCRIPTION', 'TIME')
        for value in logs:
            _table += _log_data.table_items.format(value['HOST'], value['USERNAME'], value['PASSWORD'],
                                                   value['PORT'], value['TYPE'], value['DESCRIPTION'],
                                                   value['TIME'])
        _table += _log_data.table_end + '<p class="footer">' + messages("en", 93) \
            .format(compatible.__version__, compatible.__code_name__, now()) + '</p>'
        return _table
    except:
        return ""


def __search_logs(language, page, query):
    page = int(page * 10 if page > 0 else page * -10) - 10
    data_structure = {
        "host": "",
        "info": {
            "open_ports": [],
            "scan_methods": [],
            "category": [],
            "descriptions": []
        }
    }
    selected = []
    try:
        for host in send_read_query(
                """select host from hosts_log where host like \"%%{0}%%\" group by host order by id desc limit {1},10""".format(
                    query, page), language):
            for data in send_read_query(
                    """select host,port,type,category,description from hosts_log where host="{0}" group by type,port,username,""" \
                    """password,description order by id desc""".format(host[0]), language):
                n = 0
                capture = None
                for selected_data in selected:
                    if selected_data["host"] == host[0]:
                        capture = n
                    n += 1
                if capture is None:
                    tmp = {  # fix later, junks
                        "host": data[0],
                        "info": {
                            "open_ports": [],
                            "scan_methods": [],
                            "category": [],
                            "descriptions": []
                        }
                    }
                    selected.append(tmp)
                    n = 0
                    for selected_data in selected:
                        if selected_data["host"] == host[0]:
                            capture = n
                        n += 1
                if data[0] == selected[capture]["host"]:
                    if data[1] not in selected[capture]["info"]["open_ports"] and type(data[1]) is int:
                        selected[capture]["info"]["open_ports"].append(data[1])
                    if data[2] not in selected[capture]["info"]["scan_methods"]:
                        selected[capture]["info"]["scan_methods"].append(data[2])
                    if data[3] not in selected[capture]["info"]["category"]:
                        selected[capture]["info"]["category"].append(data[3])
                    if data[4] not in selected[capture]["info"]["descriptions"]:
                        selected[capture]["info"]["descriptions"].append(data[4])
    except:
        return __structure(status="error", msg="database error!")
    return selected
