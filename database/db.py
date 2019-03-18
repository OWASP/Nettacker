#!/usr/bin/env python
# -*- coding: utf-8 -*-

import json
import time
from flask import jsonify
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from database.models import HostsLog, Report, Update_Log
from core.alert import warn
from core.alert import info
from core.alert import messages
from core.compatible import version
from core._time import now
from core import compatible
from api.api_core import __structure
from core.config import _database_config

DB = _database_config()["DB"]
USER = _database_config()["USERNAME"]
PASSWORD = _database_config()["PASSWORD"]
HOST = _database_config()["HOST"]
PORT = _database_config()["PORT"]
DATABASE = _database_config()["DATABASE"]


def db_inputs(connection_type):
    """
        a function to determine the type of database the user wants to work with and
        selects the corresponding connection to the db

        Args:
            connection_type: type of db we are working with

        Returns:
            corresponding command to connect to the db
        """
    return {
        "mysql": 'mysql://{0}:{1}@{2}:{3}/{4}'.format(USER, PASSWORD, HOST, PORT, DATABASE),
        "sqlite": 'sqlite:///{0}'.format(DATABASE)
    }[connection_type]


def create_connection(language):
    """
    a function to create connections to db, it retries 100 times if connection returned an error

    Args:
        language: language

    Returns:
        connection if success otherwise False
    """
    try:
        for i in range(0, 100):
            try:
                db_engine = create_engine(db_inputs(DB))
                Session = sessionmaker(bind=db_engine)
                session = Session()
                return session
            except:
                time.sleep(0.01)
    except:
        warn(messages(language, "database_connect_fail"))
    return False


def send_submit_query(session, language):
    """
    a function to send submit based queries to db (such as insert and update or delete), it retries 100 times if
    connection returned an error.

    Args:
        session: session to commit
        language: language

    Returns:
        True if submitted success otherwise False
    """
    try:
        for _ in range(1, 100):
            try:
                session.commit()
                return True
            except Exception as _:
                time.sleep(0.01)
    except Exception as _:
        warn(messages(language, "database_connect_fail"))
        return False
    return False


def submit_report_to_db(date, scan_id, report_filename, events_num, verbose, api_flag, report_type, graph_flag,
                        category, profile, scan_method, language, scan_cmd, ports):
    """
    this function created to submit the generated reports into db, the files are not stored in db, just the path!

    Args:
        date: date and time
        scan_id: scan hash id
        report_filename: report full path and filename
        events_num: length of events in the report
        verbose: verbose level used to generated the report
        api_flag: 0 (False) if scan run from CLI and 1 (True) if scan run from API
        report_type: could be TEXT, JSON or HTML
        graph_flag: name of the graph used (if it's HTML type)
        category: category of the modules used in scan (vuln, scan, brute)
        profile: profiles used in scan
        scan_method: modules used in scan
        language: scan report language
        scan_cmd: scan command line if run in CLI otherwise messages(language,"through_API")
        ports: selected port otherwise None

    Returns:
        return True if submitted otherwise False
    """
    info(messages(language, "inserting_report_db"))
    session = create_connection(language)
    session.add(Report(
        date=date, scan_id=scan_id, report_filename=report_filename, events_num=events_num, verbose=verbose,
        api_flag=api_flag, report_type=report_type, graph_flag=graph_flag, category=category, profile=profile,
        scan_method=scan_method, language=language, scan_cmd=scan_cmd, ports=ports
    ))
    return send_submit_query(session, language)

def save_update_log(language):
    """
    This Function Saves date of previous time the Nettacker Update happened

    Args:
        Language
    Return:
        True or False if the data got saved in the db or not
    """
    session = create_connection(language)
    date_time = now()
    session.add(Update_Log(last_update_time=date_time))
    return send_submit_query(session, language)

def get_update_log(language):
    """
    This function Fetches last update time

    Args:
        Language
    Return:
        Return date in string format
    """
    session = create_connection(language)
    logs = session.query(Update_Log).all()
    return logs

def remove_old_logs(host, type, scan_id, language):
    """
    this function remove old events (and duplicated) from database based on host, module, scan_id

    Args:
        host: host
        type: module name
        scan_id: scan id hash
        language: language

    Returns:
        True if success otherwise False
    """
    session = create_connection(language)
    old_logs = session.query(HostsLog).filter(HostsLog.host == host, HostsLog.type == type, HostsLog.scan_id != scan_id)
    old_logs.delete(synchronize_session=False)
    return send_submit_query(session, language)


def submit_logs_to_db(language, log):
    """
    this function created to submit new events into database

    Args:
        language: language
        log: log event in JSON type

    Returns:
        True if success otherwise False
    """
    if isinstance(log, str):
        log = json.loads(log)

    if isinstance(log, dict):
        session = create_connection(language)
        session.add(HostsLog(
            host=log["HOST"], date=log["TIME"], port=log["PORT"], type=log["TYPE"], category=log["CATEGORY"],
            description=log["DESCRIPTION"].encode('utf8') if version() is 2 else log["DESCRIPTION"],
            username=log["USERNAME"], password=log["PASSWORD"], scan_id=log["SCAN_ID"], scan_cmd=log["SCAN_CMD"]
        ))
        return send_submit_query(session, language)
    else:
        warn(messages(language, "invalid_json_type_to_db").format(log))
        return False

def __select_results(language, page):
    """
    this function created to crawl into submitted results, it shows last 10 results submitted in the database.
    you may change the page (default 1) to go to next/previous page.

    Args:
        language: language
        page: page number

    Returns:
        list of events in array and JSON type, otherwise an error in JSON type.
    """
    page = int(page * 10 if page > 0 else page * -10) - 10
    selected = []
    session = create_connection(language)
    try:
        search_data = session.query(Report).order_by(Report.id.desc())[page:page + 11]
        for data in search_data:
            tmp = {  # fix later, junks
                "id": data.id,
                "date": data.date,
                "scan_id": data.scan_id,
                "report_filename": data.report_filename,
                "events_num": data.events_num,
                "verbose": data.verbose,
                "api_flag": data.api_flag,
                "report_type": data.report_type,
                "graph_flag": data.graph_flag,
                "category": data.category,
                "profile": data.profile,
                "scan_method": data.scan_method,
                "language": data.language,
                "scan_cmd": data.scan_cmd,
                "ports": data.ports
            }
            selected.append(tmp)
    except Exception as _:
        return __structure(status="error", msg="database error!")
    return selected


def __get_result(language, id):
    """
    this function created to download results by the result ID.

    Args:
        language: language
        id: result id

    Returns:
        result file content (TEXT, HTML, JSON) if success otherwise and error in JSON type.
    """
    session = create_connection(language)
    try:
        try:
            file_obj = session.query(Report).filter_by(id=id).first()
            filename = file_obj.report_filename
            return open(filename, 'rb').read(), 200
        except Exception as _:
            return jsonify(__structure(status="error", msg="cannot find the file!")), 400
    except Exception as _:
        return jsonify(__structure(status="error", msg="database error!")), 200


def __last_host_logs(language, page):
    """
    this function created to select the last 10 events from the database. you can goto next page by changing page value.

    Args:
        language: language
        page: page number

    Returns:
        an array of events in JSON type if success otherwise an error in JSON type
    """
    session = create_connection(language)
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
        for host in session.query(HostsLog).group_by(HostsLog.host).order_by(HostsLog.id.desc())[page:page+11]:
            for data in session.query(HostsLog).filter(HostsLog.host==host).group_by(HostsLog.type, HostsLog.port,
                                                    HostsLog.username, HostsLog.password, HostsLog.description).order_by(
                                                    HostsLog.id.desc()):
                n = 0
                capture = None
                for selected_data in selected:
                    if selected_data["host"] == host.host:
                        capture = n
                    n += 1
                if capture is None:
                    tmp = {  # fix later, junks
                        "host": data.host,
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
                        if selected_data["host"] == host.host:
                            capture = n
                        n += 1
                if data.host == selected[capture]["host"]:
                    if data.port not in selected[capture]["info"]["open_ports"] and isinstance(data.port, int):
                        selected[capture]["info"]["open_ports"].append(data.port)
                    if data.type not in selected[capture]["info"]["scan_methods"]:
                        selected[capture]["info"][
                            "scan_methods"].append(data.type)
                    if data.category not in selected[capture]["info"]["category"]:
                        selected[capture]["info"]["category"].append(data.category)
                    if data.description not in selected[capture]["info"]["descriptions"]:
                        selected[capture]["info"][
                            "descriptions"].append(data.description)
    except Exception as _:
        return __structure(status="error", msg="database error!")
    if len(selected) == 0:
        return __structure(status="finished", msg="No more search results")
    return selected


def __logs_by_scan_id(scan_id, language):
    """
    select all events by scan id hash

    Args:
        scan_id: scan id hash
        language: language

    Returns:
        an array with JSON events or an empty array
    """
    session = create_connection(language)
    # try:
    return_logs = []
    logs = session.query(HostsLog).filter(HostsLog.scan_id==scan_id).all()
    for log in logs:
        data = {
            "SCAN_ID": scan_id,
            "HOST": log.host,
            "USERNAME": log.username,
            "PASSWORD": log.password,
            "PORT": log.port,
            "TYPE": log.type,
            "TIME": log.date,
            "DESCRIPTION": log.description
        }
        return_logs.append(data)
    return return_logs
    # except:
    #     return []


def __logs_to_report_json(host, language):
    """
    select all reports of a host

    Args:
        host: the host to search
        language: language

    Returns:
        an array with JSON events or an empty array
    """
    try:
        session = create_connection(language)
        return_logs = []
        logs = session.query(HostsLog).filter(HostsLog.host == host)
        for log in logs:
            data = {
                "SCAN_ID": log.scan_id,
                "HOST": host,
                "USERNAME": log.username,
                "PASSWORD": log.password,
                "PORT": log.port,
                "TYPE": log.type,
                "TIME": log.date,
                "DESCRIPTION": log.description
            }
            return_logs.append(data)
        return return_logs
    except Exception as _:
        return []


def __logs_to_report_html(host, language):
    """
    generate HTML report with d3_tree_v2_graph for a host

    Args:
        host: the host
        language: language

    Returns:
        HTML report
    """
    session = create_connection(language)
    try:
        logs = []
        logs_data = session.query(HostsLog).filter(HostsLog.host == host).all()
        for log in logs_data:
            data = {
                "SCAN_ID": log.scan_id,
                "HOST": host,
                "USERNAME": log.username,
                "PASSWORD": log.password,
                "PORT": log.port,
                "TYPE": log.type,
                "TIME": log.date,
                "DESCRIPTION": log.description
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
                                                value['PORT'], value['TYPE'], value['DESCRIPTION'], value['TIME'])
        _table += _log_data.table_end + '<p class="footer">' + messages("en", "nettacker_report") \
            .format(compatible.__version__, compatible.__code_name__, now()) + '</p>'
        return _table
    except Exception as _:
        return ""


def __search_logs(language, page, query):
    """
    search in events (host, date, port, module, category, description, username, password, scan_id, scan_cmd)

    Args:
        language: language
        page: page number
        query: query to search

    Returns:
        an array with JSON structure of founded events or an empty array
    """
    session = create_connection(language)
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
        for host in session.query(HostsLog).filter(
                (HostsLog.host.like("%"+str(query)+"%"))
                | (HostsLog.date.like("%"+str(query)+"%"))
                | (HostsLog.port.like("%"+str(query)+"%"))
                | (HostsLog.type.like("%"+str(query)+"%"))
                | (HostsLog.category.like("%"+str(query)+"%"))
                | (HostsLog.description.like("%"+str(query)+"%"))
                | (HostsLog.username.like("%"+str(query)+"%"))
                | (HostsLog.password.like("%" + str(query) + "%"))
                | (HostsLog.scan_id.like("%" + str(query) + "%"))
                | (HostsLog.scan_cmd.like("%" + str(query) + "%"))
        ).group_by(HostsLog.host).order_by(HostsLog.id.desc())[page:page+11]:
            for data in session.query(HostsLog).filter(HostsLog.host==str(host.host)).group_by(HostsLog.type, HostsLog.port,
                                                    HostsLog.username, HostsLog.password, HostsLog.description).order_by(
                                                    HostsLog.id.desc()).all():
                n = 0
                capture = None
                for selected_data in selected:
                    if selected_data["host"] == host.host:
                        capture = n
                    n += 1
                if capture is None:
                    tmp = {  # fix later, junks
                        "host": data.host,
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
                        if selected_data["host"] == host.host:
                            capture = n
                        n += 1
                if data.host == selected[capture]["host"]:
                    if data.port not in selected[capture]["info"]["open_ports"] and isinstance(data.port, int):
                        selected[capture]["info"]["open_ports"].append(data.port)
                    if data.type not in selected[capture]["info"]["scan_methods"]:
                        selected[capture]["info"][
                            "scan_methods"].append(data.type)
                    if data.category not in selected[capture]["info"]["category"]:
                        selected[capture]["info"]["category"].append(data.category)
                    if data.description not in selected[capture]["info"]["descriptions"]:
                        selected[capture]["info"][
                            "descriptions"].append(data.description)
    except Exception as _:
        return __structure(status="error", msg="database error!")
    if len(selected) == 0:
        return __structure(status="finished", msg="No more search results")
    return selected
