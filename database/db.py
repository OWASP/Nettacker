#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import json
import time
from flask import jsonify
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from database.models import HostsLog, Report
from core.alert import warn
from core.alert import info
from core.alert import messages
from core.time import now
from core import compatible
from api.api_core import structure
from config import nettacker_database_config

DB = nettacker_database_config()["DB"]
USER = nettacker_database_config()["USERNAME"]
PASSWORD = nettacker_database_config()["PASSWORD"]
HOST = nettacker_database_config()["HOST"]
PORT = nettacker_database_config()["PORT"]
DATABASE = nettacker_database_config()["DATABASE"]


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
        "postgres": 'postgres+psycopg2://{0}:{1}@{2}:{3}/{4}'.format(USER, PASSWORD, HOST, PORT, DATABASE),
        "mysql": 'mysql://{0}:{1}@{2}:{3}/{4}'.format(USER, PASSWORD, HOST, PORT, DATABASE),
        "sqlite": 'sqlite:///{0}'.format(DATABASE)
    }[connection_type]


def create_connection():
    """
    a function to create connections to db, it retries 100 times if connection returned an error

    Returns:
        connection if success otherwise False
    """
    try:
        for i in range(0, 100):
            try:
                db_engine = create_engine(
                    db_inputs(DB),
                    connect_args={
                        'check_same_thread': False
                    }
                )
                Session = sessionmaker(bind=db_engine)
                session = Session()
                return session
            except Exception:
                time.sleep(0.01)
    except Exception:
        warn(messages("database_connect_fail"))
    return False


def send_submit_query(session):
    """
    a function to send submit based queries to db (such as insert and update or delete), it retries 100 times if
    connection returned an error.

    Args:
        session: session to commit

    Returns:
        True if submitted success otherwise False
    """
    try:
        for _ in range(1, 100):
            try:
                session.commit()
                return True
            except Exception:
                time.sleep(0.01)
    except Exception as _:
        warn(messages("database_connect_fail"))
        return False
    return False


def submit_report_to_db(log):
    """
    this function created to submit the generated reports into db, the files are not stored in db, just the path!

    Args:
        date: date and time
        scan_unique_id: scan hash id
        report_filename: report full path and filename
        events_num: length of events in the report
        verbose: verbose level used to generated the report
        start_api_server: 0 (False) if scan run from CLI and 1 (True) if scan run from API
        report_type: could be TEXT, JSON or HTML
        graph_name: name of the graph used (if it's HTML type)
        category: category of the modules used in scan (vuln, scan, brute)
        profile: profiles used in scan
        selected_modules: modules used in scan
        language: scan report language
        scan_cmd: scan command line if run in CLI otherwise messages("through_API")
        ports: selected port otherwise None

    Returns:
        return True if submitted otherwise False
    """
    info(messages("inserting_report_db"))
    session = create_connection()
    session.add(
        Report(
            date=log["date"],
            # module_name=log["module_name"],
            scan_unique_id=log["scan_unique_id"],
            options=json.dumps(log["options"]),
            # event=json.dumps(log["event"])
        )
    )
    return send_submit_query(session)


def remove_old_logs(options):
    """
    this function remove old events (and duplicated) from database based on target, module, scan_unique_id

    Args:
        options: identifiers

    Returns:
        True if success otherwise False
    """
    session = create_connection()
    session.query(HostsLog).filter(
        HostsLog.target == options["target"],
        HostsLog.module_name == options["module_name"],
        HostsLog.scan_unique_id != options["scan_unique_id"]
    ).delete(synchronize_session=False)
    return send_submit_query(session)


def submit_logs_to_db(log):
    """
    this function created to submit new events into database

    Args:
        log: log event in JSON type

    Returns:
        True if success otherwise False
    """
    if isinstance(log, dict):
        session = create_connection()
        session.add(
            HostsLog(
                target=log["target"],
                date=log["date"],
                module_name=log["module_name"],
                scan_unique_id=log["scan_unique_id"],
                options=json.dumps(log["options"]),
                event=json.dumps(log["event"])
            )
        )
        return send_submit_query(session)
    else:
        warn(messages("invalid_json_type_to_db").format(log))
        return False


def find_events(target, module_name, scan_unique_id):
    """
    select all events by scan_unique id, target, module_name

    Args:
        target: target
        module_name: module name
        scan_unique_id: unique scan identifier
        return_target_only: only return targets

    Returns:
        an array with JSON events or an empty array
    """
    session = create_connection()
    return session.query(HostsLog).filter(
        HostsLog.target == target,
        HostsLog.module_name == module_name,
        HostsLog.scan_unique_id == scan_unique_id
    ).all()


def __select_results(page):
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
    session = create_connection()
    try:
        search_data = session.query(Report).order_by(
            Report.id.desc())
        for data in search_data:
            tmp = {  # fix later, junks
                "id": data.id,
                "date": data.date,
                "scan_unique_id": data.scan_unique_id,
                "options": json.loads(data.options)
                
            }
            selected.append(tmp)
    except Exception as e:
        return structure(status="error", msg="database error!")
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
    session = create_connection()
    try:
        try:
            file_obj = session.query(Report).filter_by(id=id).first()
            filename = json.loads(file_obj.options)["output_file"]
            return open(filename, 'rb').read(), 200
        except Exception as _:
            return jsonify(structure(status="error", msg="cannot find the file!")), 400
    except Exception as _:
        return jsonify(structure(status="error", msg="database error!")), 200


def __last_host_logs(language, page):
    """
    this function created to select the last 10 events from the database. you can goto next page by changing page value.

    Args:
        language: language
        page: page number

    Returns:
        an array of events in JSON type if success otherwise an error in JSON type
    """
    session = create_connection()
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
        for host in session.query(HostsLog).group_by(HostsLog.host).order_by(HostsLog.id.desc())[page:page + 11]:
            for data in session.query(HostsLog).filter(HostsLog.host == host).group_by(
                    HostsLog.module_name, HostsLog.port, HostsLog.username, HostsLog.password,
                    HostsLog.description).order_by(HostsLog.id.desc()):
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
                        selected[capture]["info"]["open_ports"].append(
                            data.port)
                    if data.type not in selected[capture]["info"]["scan_methods"]:
                        selected[capture]["info"][
                            "scan_methods"].append(data.type)
                    if data.category not in selected[capture]["info"]["category"]:
                        selected[capture]["info"]["category"].append(
                            data.category)
                    if data.description not in selected[capture]["info"]["descriptions"]:
                        selected[capture]["info"][
                            "descriptions"].append(data.description)
    except Exception as _:
        return structure(status="error", msg="database error!")
    if len(selected) == 0:
        return structure(status="finished", msg="No more search results")
    return selected


def __logs_by_scan_id(scan_unique_id):
    """
    select all events by scan id hash

    Args:
        scan_unique_id: scan id hash
        language: language

    Returns:
        an array with JSON events or an empty array
    """
    session = create_connection()
    # try:
    return_logs = []
    logs = session.query(HostsLog).filter(HostsLog.scan_unique_id == scan_unique_id).all()
    
    for log in logs:
        data = {
            "scan_unique_id": scan_unique_id,
            "TARGET": log.target,
            #"DATE": log.date,
            "OPTIONS": json.loads(log.options),
            "EVENT": json.loads(log.event),
            # "HOST": host,
            # "USERNAME": log.username,
            # "PASSWORD": log.password,
            # "PORT": log.port,
            # "TYPE": log.type,
            # "TIME": log.date,
            # "DESCRIPTION": log.description
        }
        return_logs.append(data)
    return return_logs
    # except:
    #     return []


def __logs_to_report_json(target, language):
    """
    select all reports of a host

    Args:
        host: the host to search
        language: language

    Returns:
        an array with JSON events or an empty array
    """
    try:
        session = create_connection()
        return_logs = []
        logs = session.query(HostsLog).filter(HostsLog.target == target)
        for log in logs:
            data = {
                "scan_unique_id": log.scan_unique_id,
                "TARGET": log.target,
                #"DATE": log.date,
                "OPTIONS": json.loads(log.options),
                "EVENT": json.loads(log.event),
                # "HOST": host,
                # "USERNAME": log.username,
                # "PASSWORD": log.password,
                # "PORT": log.port,
                # "TYPE": log.type,
                # "TIME": log.date,
                # "DESCRIPTION": log.description
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
    session = create_connection()
    try:
        logs = []
        logs_data = session.query(HostsLog).filter(HostsLog.host == host).all()
        for log in logs_data:
            data = {
                "scan_unique_id": log.scan_unique_id,
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
    search in events (host, date, port, module, category, description, username, password, scan_unique_id, scan_cmd)

    Args:
        language: language
        page: page number
        query: query to search

    Returns:
        an array with JSON structure of founded events or an empty array
    """
    session = create_connection()
    page = int(page * 10 if page > 0 else page * -10) - 10
    data_structure = {
        "target": "",
        "info": {
            # "open_ports": [],
            # "scan_methods": [],
            "module_name": [],
            # "category": [],
            "options": [],
            "date": [],
            "event": [],
            # "descriptions": []
        }
    }
    selected = []
    try:
        for host in session.query(HostsLog).filter(
                (HostsLog.target.like("%" + str(query) + "%"))
                | (HostsLog.date.like("%" + str(query) + "%"))
                #| (HostsLog.port.like("%" + str(query) + "%"))
                | (HostsLog.module_name.like("%" + str(query) + "%"))
                | (HostsLog.options.like("%" + str(query) + "%"))
                | (HostsLog.event.like("%" + str(query) + "%"))
                #| (HostsLog.category.like("%" + str(query) + "%"))
                #| (HostsLog.description.like("%" + str(query) + "%"))
                #| (HostsLog.username.like("%" + str(query) + "%"))
                #| (HostsLog.password.like("%" + str(query) + "%"))
                | (HostsLog.scan_unique_id.like("%" + str(query) + "%"))
                #| (HostsLog.scan_cmd.like("%" + str(query) + "%"))
        ).group_by(HostsLog.target).order_by(HostsLog.id.desc())[page:page + 11]:
            for data in session.query(HostsLog).filter(HostsLog.target == str(host.target)).group_by(
                    HostsLog.module_name, HostsLog.options, HostsLog.scan_unique_id, HostsLog.event).order_by(
                HostsLog.id.desc()).all():
                n = 0
                capture = None
                for selected_data in selected:
                    if selected_data["target"] == host.target:
                        capture = n
                    n += 1
                if capture is None:
                    tmp = {  # fix later, junks
                        "target": data.target,
                        "info": {
                            # "open_ports": [],
                            # "scan_methods": [],
                            "module_name": [],
                            # "category": [],
                            "options": [],
                            "date": [],
                            "event": [],
                            # "descriptions": []
                        }
                    }
                    selected.append(tmp)
                    n = 0
                    for selected_data in selected:
                        if selected_data["target"] == host.target:
                            capture = n
                        n += 1
                if data.target == selected[capture]["target"]:
                    # if data.port not in selected[capture]["info"]["open_ports"] and isinstance(data.port, int):
                    #     selected[capture]["info"]["open_ports"].append(
                    #         data.port)
                    if data.module_name not in selected[capture]["info"]["module_name"]:
                        selected[capture]["info"][
                            "module_name"].append(data.module_name)
                    if data.date not in selected[capture]["info"]["date"]:
                        selected[capture]["info"][
                            "date"].append(data.date)
                    if data.options not in selected[capture]["info"]["options"]:
                        selected[capture]["info"][
                            "options"].append(json.loads(data.options))
                    if data.event not in selected[capture]["info"]["event"]:
                        selected[capture]["info"][
                            "event"].append(json.loads(data.event))
                    # if data.category not in selected[capture]["info"]["category"]:
                    #     selected[capture]["info"]["category"].append(
                    #         data.category)
                    # if data.description not in selected[capture]["info"]["descriptions"]:
                    #     selected[capture]["info"][
                    #         "descriptions"].append(data.description)
    except Exception as _:
        return structure(status="error", msg="database error!")
    if len(selected) == 0:
        return structure(status="finished", msg="No more search results")
    return selected
