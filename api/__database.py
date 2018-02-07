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


def submit_report_to_db(date, scan_id, report_filename, events_num, verbose, api_flag, report_type, graph_flag,
                        category, profile, scan_method, language, scan_cmd, ports):
    conn = create_connection(language)
    if not conn:
        return False
    try:
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
        warn(messages(language, 168))
        return False
    return True


def remove_old_logs(host, type, scan_id, language):
    conn = create_connection(language)
    try:
        c = conn.cursor()
        c.execute("""delete from hosts_log where host="{0}" and type="{1}" and scan_id!="{2}" """
                  .format(host, type, scan_id))
        conn.commit()
        conn.close()
    except:
        warn(messages(language, 168))
        return False
    return True


def submit_logs_to_db(language, log):
    conn = create_connection(language)
    if type(log) == str:
        log = json.loads(log)
    try:
        # retries
        for i in range(0, 100):
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
            except:
                pass
            time.sleep(0.01)
        conn.close()
    except:
        warn(messages(language, 168))
        return False
    return True


def __select_results(language, page):
    conn = create_connection(language)
    log = ""
    page = int(page * 10 if page > 0 else page * -10) - 10

    selected = []
    try:
        c = conn.cursor()
        for data in c.execute("""select * from reports where 1 order by id desc limit {0},10""".format(page)):
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
        conn.close()
    except:
        return __structure(status="error", msg="database error!")
    return selected


def __get_result(language, id):
    conn = create_connection(language)
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


def __last_host_logs(language, page):
    conn = create_connection(language)
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
        c = conn.cursor()
        for host in c.execute(
                """select host from hosts_log where 1 group by host order by id desc limit {0},10""".format(page)):
            d = conn.cursor()
            for data in d.execute(
                    """select host,port,type,category,description from hosts_log where host="{0}" group by type,port,username,""" \
                    """password,description order by id desc""".format(host[0])):
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
                    if data[1] not in selected[capture]["info"]["open_ports"]:
                        selected[capture]["info"]["open_ports"].append(data[1])
                    if data[2] not in selected[capture]["info"]["scan_methods"]:
                        selected[capture]["info"]["scan_methods"].append(data[2])
                    if data[3] not in selected[capture]["info"]["category"]:
                        selected[capture]["info"]["category"].append(data[3])
                    if data[4] not in selected[capture]["info"]["descriptions"]:
                        selected[capture]["info"]["descriptions"].append(data[4])

        conn.close()
    except:
        return __structure(status="error", msg="database error!")
    return selected


def __logs_to_report(scan_id, language):
    conn = create_connection(language)
    try:
        c = conn.cursor()
        logs = []
        for log in c.execute(
                "select host,username,password,port,type,date,description from hosts_log where scan_id=\"{0}\"".format(
                    scan_id)):
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
