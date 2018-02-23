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
    '''
    a function to create sqlite3 connections to db, it retries 100 times if connection returned an error
    :param language: language
    :return: sqlite3 connection if success otherwise False
    '''
    try:
        # retries
        for i in range(0, 100):
            try:
                return sqlite3.connect(os.path.join(os.path.dirname(os.path.dirname(__file__)),
                                                    _builder(_core_config(), _core_default_config())["api_db_name"]))
            except:
                time.sleep(0.01)
    except:
        warn(messages(language, 168))
    return False


def send_submit_query(query, language):
    '''
    a function to send submit based queries to db (such as insert and update or delete), it retries 100 times if
    connection returned an error.
    :param query: query to execute
    :param language: language
    :return: True if submitted success otherwise False
    '''
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
                return True
            except:
                time.sleep(0.01)
    except:
        warn(messages(language, 168))
        return False
    return False


def send_read_query(query, language):
    '''
    a function to send read based queries to db (such as select), it retries 100 times if connection returned an error.
    :param query: query to execute
    :param language: language
    :return: return executed query otherwise False
    '''
    conn = create_connection(language)
    if not conn:
        return False
    try:
        for i in range(1, 100):
            try:
                c = conn.cursor()
                return c.execute(query)
            except:
                time.sleep(0.01)
    except:
        warn(messages(language, 168))
        return False
    return False


def submit_report_to_db(date, scan_id, report_filename, events_num, verbose, api_flag, report_type, graph_flag,
                        category, profile, scan_method, language, scan_cmd, ports):
    '''
    this function created to submit the generated reports into db, the files are not stored in db, just the path!
    :param date: date and time
    :param scan_id: scan hash id
    :param report_filename: report full path and filename
    :param events_num: length of events in the report
    :param verbose: verbose level used to generated the report
    :param api_flag: 0 (False) if scan run from CLI and 1 (True) if scan run from API
    :param report_type: could be TEXT, JSON or HTML
    :param graph_flag: name of the graph used (if it's HTML type)
    :param category: category of the modules used in scan (vuln, scan, brute)
    :param profile: profiles used in scan
    :param scan_method: modules used in scan
    :param language: scan report language
    :param scan_cmd: scan command line if run in CLI otherwise messages(language, 158)
    :param ports: selected port otherwise None
    :return: return True if submitted otherwise False
    '''
    info(messages(language, 169))
    return send_submit_query("""
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


def remove_old_logs(host, type, scan_id, language):
    '''
    this function remove old events (and duplicated) from database based on host, module, scan_id
    :param host: host
    :param type: module name
    :param scan_id: scan id hash
    :param language: language
    :return: True if success otherwise False
    '''
    return send_submit_query("""delete from hosts_log where host="{0}" and type="{1}" and scan_id!="{2}" """
                             .format(host, type, scan_id), language)


def submit_logs_to_db(language, log):
    '''
    this function created to submit new events into database
    :param language: language
    :param log: log event in JSON type
    :return: True if success otherwise False
    '''
    if type(log) == str:
        log = json.loads(log)
    return send_submit_query("""
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


def __select_results(language, page):
    '''
    this function created to crawl into submitted results, it shows last 10 results submitted in the database.
    you may change the page (default 1) to go to next/previous page.
    :param language: language
    :param page: page number
    :return: list of events in array and JSON type, otherwise an error in JSON type.
    '''
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
    '''
    this function created to download results by the result ID.
    :param language: language
    :param id: result id
    :return: result file content (TEXT, HTML, JSON) if success otherwise and error in JSON type.
    '''
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
    '''
    this function created to select the last 10 events from the database. you can goto next page by changing page value.
    :param language: language
    :param page: page number
    :return: an array of events in JSON type if success otherwise an error in JSON type
    '''
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
    '''
    select all events by scan id hash
    :param scan_id: scan id hash
    :param language: language
    :return: an array with JSON events or an empty array
    '''
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
    '''
    select all reports of a host
    :param host: the host to search
    :param language: language
    :return: an array with JSON events or an empty array
    '''
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
    '''
    generate HTML report with d3_tree_v2_graph for a host
    :param host: the host
    :param language: language
    :return: HTML report
    '''
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
    '''
    search in events (host, date, port, module, category, description, username, password, scan_id, scan_cmd)
    :param language: language
    :param page: page number
    :param query: query to search
    :return: an array with JSON structure of founded events or an empty array
    '''
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
                """select host from hosts_log where host like \"%%{0}%%\" or date like \"%%{0}%%\" or
                port like \"%%{0}%%\" or type like \"%%{0}%%\" or category like \"%%{0}%%\" 
                or description like \"%%{0}%%\" or username like \"%%{0}%%\" or password 
                like \"%%{0}%%\" or scan_id like \"%%{0}%%\" or scan_cmd like \"%%{0}%%\"  
                group by host order by id desc limit {1},10""".format(query, page), language):
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
