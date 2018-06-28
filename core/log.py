#!/usr/bin/env python
# -*- coding: utf-8 -*-

import json
import sys
import texttable
import lockfile
from core.alert import messages
from core.alert import info
from core import compatible
from core._time import now
from core._die import __die_failure
from database.db import submit_report_to_db
from database.db import submit_logs_to_db
from database.db import remove_old_logs
from database.db import __logs_by_scan_id
from core.config_builder import default_paths
from core.config import _paths
from core.config_builder import _builder
from core.compatible import version
from core.alert import write


def build_graph(graph_flag, language, data, _HOST, _USERNAME, _PASSWORD, _PORT, _TYPE, _DESCRIPTION):
    """
    build a graph

    Args:
        graph_flag: graph name
        language: language
        data: events in JSON type
        _HOST: host key used in JSON
        _USERNAME: username key used in JSON
        _PASSWORD: password key used in JSON
        _PORT: port key used in JSON
        _TYPE: type key used in JSON
        _DESCRIPTION: description key used in JSON

    Returns:
        graph in HTML type
    """
    info(messages(language, "build_graph"))
    try:
        start = getattr(
            __import__('lib.graph.{0}.engine'.format(graph_flag.rsplit('_graph')[0]),
                       fromlist=['start']),
            'start')
    except:
        __die_failure(
            messages(language, "graph_module_unavailable").format(graph_flag))

    info(messages(language, "finish_build_graph"))
    return start(graph_flag, language, data, _HOST, _USERNAME, _PASSWORD, _PORT, _TYPE, _DESCRIPTION)


def __build_texttable(JSON_FROM_DB, _HOST, _USERNAME, _PASSWORD, _PORT, _TYPE, _DESCRIPTION, _TIME, language):
    """
    build a text table with generated event related to the scan

    :param JSON_FROM_DB: JSON events from database
    :param _HOST: host string
    :param _USERNAME: username string
    :param _PASSWORD: password string
    :param _PORT: port string
    :param _TYPE: type string
    :param _DESCRIPTION: description string
    :param _TIME: time string
    :param language: language
    :return:
        array [text table, event_number]
    """
    _table = texttable.Texttable()
    _table.add_rows(
        [[_HOST, _USERNAME, _PASSWORD, _PORT, _TYPE, _DESCRIPTION, _TIME]])
    events_num = 0
    for value in JSON_FROM_DB:
        _table.add_rows([[_HOST, _USERNAME, _PASSWORD, _PORT, _TYPE, _DESCRIPTION, _TIME],
                         [value['HOST'], value['USERNAME'], value['PASSWORD'], value['PORT'], value['TYPE'],
                          value['DESCRIPTION'], value['TIME']]])
        events_num += 1
    return [_table.draw().encode('utf8') + b'\n\n' + messages(language, "nettacker_version_details").format(
        compatible.__version__,
        compatible.__code_name__,
        now()).encode('utf8') + b"\n", events_num]


def sort_logs(log_in_file, language, graph_flag, scan_id, scan_cmd, verbose_level, api_flag, profile, scan_method,
              ports):
    """
    sort all events, create log file in HTML/TEXT/JSON and remove old logs

    Args:
        log_in_file: output filename
        language: language
        graph_flag: graph name
        scan_id: scan hash id
        scan_cmd: scan cmd
        verbose_level: verbose level number
        api_flag: API flag
        profile: profiles
        scan_method: module names
        ports: ports

    Returns:
        True if success otherwise None
    """
    _HOST = messages(language, "HOST")
    _USERNAME = messages(language, "USERNAME")
    _PASSWORD = messages(language, "PASSWORD")
    _PORT = messages(language, "PORT")
    _TYPE = messages(language, "TYPE")
    _DESCRIPTION = messages(language, "DESCRIPTION")
    _TIME = messages(language, "TIME")
    events_num = 0
    report_type = ""
    JSON_FROM_DB = __logs_by_scan_id(scan_id, language)
    JSON_Data = sorted(JSON_FROM_DB, key=sorted)
    if compatible.version() is 2:
        import sys
        reload(sys)
        sys.setdefaultencoding('utf8')
    if (len(log_in_file) >= 5 and log_in_file[-5:] == '.html') or (
            len(log_in_file) >= 4 and log_in_file[-4:] == '.htm'):
        report_type = "HTML"
        data = sorted(JSON_FROM_DB, key=lambda x: sorted(x.keys()))
        # if user want a graph
        _graph = ''
        if graph_flag is not None:
            _graph = build_graph(graph_flag, language, data, 'HOST', 'USERNAME', 'PASSWORD', 'PORT', 'TYPE',
                                 'DESCRIPTION')
        from lib.html_log import _log_data
        _css = _log_data.css_1
        _table = _log_data.table_title.format(_graph, _css, _HOST, _USERNAME, _PASSWORD, _PORT, _TYPE, _DESCRIPTION,
                                              _TIME)

        for value in data:
            _table += _log_data.table_items.format(value['HOST'], value['USERNAME'], value['PASSWORD'],
                                                   value['PORT'], value['TYPE'], value['DESCRIPTION'], value['TIME'])
            events_num += 1
        _table += _log_data.table_end + '<p class="footer">' + messages(language, "nettacker_version_details") \
            .format(compatible.__version__, compatible.__code_name__, now()) + '</p>'
        __log_into_file(log_in_file, 'w' if type(_table) ==
                                            str else 'wb', _table, language, final=True)
    elif len(log_in_file) >= 5 and log_in_file[-5:] == '.json':
        graph_flag = ""
        report_type = "JSON"
        data = json.dumps(JSON_Data)
        events_num = len(JSON_Data)
        __log_into_file(log_in_file, 'w', data, language, final=True)
    else:
        graph_flag = ""
        report_type = "TEXT"
        data, events_num = __build_texttable(JSON_FROM_DB, _HOST, _USERNAME, _PASSWORD, _PORT, _TYPE,
                                             _DESCRIPTION, _TIME, language)
        __log_into_file(log_in_file, 'wb', data, language, final=True)
    data = data if report_type == "TEXT" else __build_texttable(JSON_FROM_DB, _HOST, _USERNAME, _PASSWORD, _PORT, _TYPE,
                                                                _DESCRIPTION, _TIME, language)[0]
    info(messages(language, "updating_database"))
    category = []
    for sm in scan_method:
        if sm.rsplit("_")[-1] not in category:
            category.append(sm.rsplit("_")[-1])
    category = ",".join(list(set(category)))
    scan_method = ",".join(scan_method)
    if ports is None:
        ports = "default"
    submit_report_to_db(now(), scan_id, log_in_file, events_num, 0 if verbose_level is 0 else 1, api_flag, report_type,
                        graph_flag, category, profile, scan_method, language, scan_cmd, ports)
    info(messages(language, "removing_logs_db"))
    hosts = []
    for log in JSON_Data:
        if log["HOST"] not in hosts:
            hosts.append(log["HOST"])
    for host in hosts:
        for sm in scan_method.rsplit(','):
            remove_old_logs(host, sm, scan_id, language)
    # info(messages(language,"inserting_logs_db"))
    # for log in JSON_Data:
    #     submit_logs_to_db(language, log)
    if events_num:
        info(messages(language, "summary_report"))
        write(data)
    else:
        info(messages(language, "no_event_found"))
    info(messages(language, "file_saved").format(log_in_file))
    return True


def __log_into_file(filename, mode, data, language, final=False):
    """
    write a content into a file (support unicode) and submit logs in database. if final=False its writing log in
    the database.

    Args:
        filename: the filename
        mode: writing mode (a, ab, w, wb, etc.)
        data: content
        language: language
        final: True if it's final report otherwise False (default False)

    Returns:
        True if success otherwise None
    """
    log = ''
    if version() is 2:
        if isinstance(data, str):
            try:
                log = json.loads(data)
            except ValueError:
                log = ''

        if isinstance(log, dict):
            if final:
                with open(filename, mode) as save:
                    save.write(data + '\n')
            else:
                submit_logs_to_db(language, data)
        else:
            if not final:
                flock = lockfile.FileLock(filename)
                flock.acquire()
            with open(filename, mode) as save:
                save.write(data + '\n')
            if not final:
                flock.release()
    else:

        if isinstance(data, str):
            try:
                log = json.loads(data)
            except ValueError:
                log = ''

        if isinstance(log, dict):
            if final:
                with open(filename, mode, encoding='utf-8') as save:
                    save.write(data + '\n')
            else:
                submit_logs_to_db(language, data)
        else:
            if not final:
                flock = lockfile.FileLock(filename)
                flock.acquire()
            with open(filename, mode, encoding='utf-8') as save:
                save.write(data + '\n')
            if not final:
                flock.release()
    return True
