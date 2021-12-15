#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import json
import time
from flask import jsonify
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from database.models import (HostsLog,
                             Report,
                             TempEvents)
from core.alert import warn
from core.alert import verbose_info
from core.alert import messages
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
        for _ in range(0, 100):
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
                time.sleep(0.1)
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
                time.sleep(0.1)
    except Exception as _:
        warn(messages("database_connect_fail"))
        return False
    return False


def submit_report_to_db(event):
    """
    this function created to submit the generated reports into db, the files are not stored in db, just the path!

    Args:
        event: event log

    Returns:
        return True if submitted otherwise False
    """
    verbose_info(messages("inserting_report_db"))
    session = create_connection()
    session.add(
        Report(
            date=event["date"],
            scan_unique_id=event["scan_unique_id"],
            report_path_filename=json.dumps(
                event["options"]["report_path_filename"]
            ),
            options=json.dumps(event["options"]),
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
                port=json.dumps(log["port"]),
                event=json.dumps(log["event"]),
                json_event=json.dumps(log["json_event"])
            )
        )
        return send_submit_query(session)
    else:
        warn(messages("invalid_json_type_to_db").format(log))
        return False


def submit_temp_logs_to_db(log):
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
            TempEvents(
                target=log["target"],
                date=log["date"],
                module_name=log["module_name"],
                scan_unique_id=log["scan_unique_id"],
                event_name=log["event_name"],
                port=json.dumps(log["port"]),
                event=json.dumps(log["event"]),
                data=json.dumps(log["data"])
            )
        )
        return send_submit_query(session)
    else:
        warn(messages("invalid_json_type_to_db").format(log))
        return False


def find_temp_events(target, module_name, scan_unique_id, event_name):
    """
        select all events by scan_unique id, target, module_name

        Args:
            target: target
            module_name: module name
            scan_unique_id: unique scan identifier
            event_name: event_name

        Returns:
            an array with JSON events or an empty array
        """
    session = create_connection()
    try:
        for _ in range(1, 100):
            try:
                return session.query(TempEvents).filter(
                    TempEvents.target == target,
                    TempEvents.module_name == module_name,
                    TempEvents.scan_unique_id == scan_unique_id,
                    TempEvents.event_name == event_name
                ).first()
            except Exception:
                time.sleep(0.1)
    except Exception as _:
        warn(messages("database_connect_fail"))
        return False
    return False



def find_events(target, module_name, scan_unique_id):
    """
    select all events by scan_unique id, target, module_name

    Args:
        target: target
        module_name: module name
        scan_unique_id: unique scan identifier

    Returns:
        an array with JSON events or an empty array
    """
    session = create_connection()
    return session.query(HostsLog).filter(
        HostsLog.target == target,
        HostsLog.module_name == module_name,
        HostsLog.scan_unique_id == scan_unique_id
    ).all()


def select_reports(page):
    """
    this function created to crawl into submitted results, it shows last 10 results submitted in the database.
    you may change the page (default 1) to go to next/previous page.

    Args:
        page: page number

    Returns:
        list of events in array and JSON type, otherwise an error in JSON type.
    """
    selected = []
    session = create_connection()
    try:
        search_data = session.query(Report).order_by(
            Report.id.desc()
        ).offset((page * 10) - 10).limit(10)
        for data in search_data:
            tmp = {
                "id": data.id,
                "date": data.date,
                "scan_unique_id": data.scan_unique_id,
                "report_path_filename": data.report_path_filename,
                "options": json.loads(data.options)
            }
            selected.append(tmp)
    except Exception:
        return structure(status="error", msg="database error!")
    return selected


def get_scan_result(id):
    """
    this function created to download results by the result ID.

    Args:
        id: scan id

    Returns:
        result file content (TEXT, HTML, JSON) if success otherwise and error in JSON type.
    """
    session = create_connection()
    try:
        try:
            filename = session.query(Report).filter_by(id=id).first().report_path_filename[1:-1]
            # for some reason filename saved like "filename" with double quotes in the beginning and end
            return filename, open(str(filename), 'rb').read()
        except Exception:
            return jsonify(structure(status="error", msg="cannot find the file!")), 404
    except Exception:
        return jsonify(structure(status="error", msg="database error!")), 500


def last_host_logs(page):
    """
    this function created to select the last 10 events from the database. you can goto next page by changing page value.

    Args:
        page: page number

    Returns:
        an array of events in JSON type if success otherwise an error in JSON type
    """
    session = create_connection()
    hosts = [
        {
            "target": host.target,
            "info": {
                "module_name": [
                    _.module_name for _ in session.query(HostsLog).filter(
                        HostsLog.target == host.target
                    ).group_by(HostsLog.module_name).all()
                ],
                "date": session.query(HostsLog).filter(
                    HostsLog.target == host.target
                ).order_by(
                    HostsLog.id.desc()
                ).first().date,
                # "options": [  # unnecessary data?
                #     _.options for _ in session.query(HostsLog).filter(
                #         HostsLog.target == host.target
                #     ).all()
                # ],
                "events": [
                    _.event for _ in session.query(HostsLog).filter(
                        HostsLog.target == host.target
                    ).all()
                ],
            }
        } for host in session.query(HostsLog).group_by(HostsLog.target).order_by(HostsLog.id.desc()).offset(
            (
                    page * 10
            ) - 10
        ).limit(10)
    ]
    if len(hosts) == 0:
        return structure(status="finished", msg="No more search results")
    return hosts


def get_logs_by_scan_unique_id(scan_unique_id):
    """
    select all events by scan id hash

    Args:
        scan_unique_id: scan id hash

    Returns:
        an array with JSON events or an empty array
    """
    session = create_connection()
    return [
        {
            "scan_unique_id": scan_unique_id,
            "target": log.target,
            "module_name": log.module_name,
            "date": str(log.date),
            "port": json.loads(log.port),
            "event": json.loads(log.event),
            "json_event": log.json_event,
        }
        for log in session.query(HostsLog).filter(
            HostsLog.scan_unique_id == scan_unique_id
        ).all()
    ]


def logs_to_report_json(target):
    """
    select all reports of a host

    Args:
        host: the host to search

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
                "target": log.target,
                "port": json.loads(log.port),
                "event": json.loads(log.event),
                "json_event": json.loads(log.json_event),
            }
            return_logs.append(data)
        return return_logs
    except Exception:
        return []


def logs_to_report_html(target):
    """
    generate HTML report with d3_tree_v2_graph for a host

    Args:
        target: the target

    Returns:
        HTML report
    """
    from core.graph import build_graph
    from lib.html_log import log_data
    session = create_connection()
    logs = [
        {
            "date": log.date,
            "target": log.target,
            "module_name": log.module_name,
            "scan_unique_id": log.scan_unique_id,
            "port": log.port,
            "event": log.event,
            "json_event": log.json_event
        } for log in session.query(HostsLog).filter(
            HostsLog.target == target
        ).all()
    ]
    html_graph = build_graph(
        "d3_tree_v2_graph",
        logs
    )

    html_content = log_data.table_title.format(
        html_graph,
        log_data.css_1,
        'date',
        'target',
        'module_name',
        'scan_unique_id',
        'port',
        'event',
        'json_event'
    )
    for event in logs:
        html_content += log_data.table_items.format(
            event['date'],
            event["target"],
            event['module_name'],
            event['scan_unique_id'],
            event['port'],
            event['event'],
            event['json_event']
        )
    html_content += log_data.table_end + '<p class="footer">' + messages("nettacker_report") + '</p>'
    return html_content


def search_logs(page, query):
    """
    search in events (host, date, port, module, category, description, username, password, scan_unique_id, scan_cmd)

    Args:
        page: page number
        query: query to search

    Returns:
        an array with JSON structure of founded events or an empty array
    """
    session = create_connection()
    selected = []
    try:
        for host in session.query(HostsLog).filter(
                (HostsLog.target.like("%" + str(query) + "%"))
                | (HostsLog.date.like("%" + str(query) + "%"))
                | (HostsLog.module_name.like("%" + str(query) + "%"))
                | (HostsLog.port.like("%" + str(query) + "%"))
                | (HostsLog.event.like("%" + str(query) + "%"))
                | (HostsLog.scan_unique_id.like("%" + str(query) + "%"))
        ).group_by(HostsLog.target).order_by(HostsLog.id.desc()).offset((page * 10) - 10).limit(10):
            for data in session.query(HostsLog).filter(HostsLog.target == str(host.target)).group_by(
                    HostsLog.module_name, HostsLog.port, HostsLog.scan_unique_id, HostsLog.event
            ).order_by(HostsLog.id.desc()).all():
                n = 0
                capture = None
                for selected_data in selected:
                    if selected_data["target"] == host.target:
                        capture = n
                    n += 1
                if capture is None:
                    tmp = {
                        "target": data.target,
                        "info": {
                            "module_name": [],
                            "port": [],
                            "date": [],
                            "event": [],
                            "json_event": []
                        }
                    }
                    selected.append(tmp)
                    n = 0
                    for selected_data in selected:
                        if selected_data["target"] == host.target:
                            capture = n
                        n += 1
                if data.target == selected[capture]["target"]:
                    if data.module_name not in selected[capture]["info"]["module_name"]:
                        selected[capture]["info"]["module_name"].append(data.module_name)
                    if data.date not in selected[capture]["info"]["date"]:
                        selected[capture]["info"]["date"].append(data.date)
                    if data.port not in selected[capture]["info"]["port"]:
                        selected[capture]["info"]["port"].append(
                            json.loads(data.port)
                        )
                    if data.event not in selected[capture]["info"]["event"]:
                        selected[capture]["info"]["event"].append(
                            json.loads(data.event)
                        )
                    if data.json_event not in selected[capture]["info"]["json_event"]:
                        selected[capture]["info"]["json_event"].append(
                            json.loads(data.json_event)
                        )
    except Exception:
        return structure(status="error", msg="database error!")
    if len(selected) == 0:
        return structure(status="finished", msg="No more search results")
    return selected
