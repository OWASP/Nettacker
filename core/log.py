#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import json
import csv
import texttable
import lockfile
from core.alert import messages
from core.alert import info
from core.compatible import version_info
from core.time import now
from core.die import die_failure
from database.db import submit_report_to_db
from database.db import submit_logs_to_db
from database.db import remove_old_logs
import html
from database.db import __logs_by_scan_id
from core.alert import write


def build_graph(graph_name, language,
                data, _HOST, _USERNAME,
                _PASSWORD, _PORT, _TYPE,
                _DESCRIPTION):
    """
    build a graph

    Args:
        graph_name: graph name
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
    info(messages("build_graph"))
    try:
        start = getattr(
            __import__('lib.graph.{0}.engine'.format(
                graph_name.rsplit('_graph')[0]),
                fromlist=['start']),
            'start')
    except:
        die_failure(
            messages("graph_module_unavailable").format(graph_name))

    info(messages("finish_build_graph"))
    return start(graph_name, language,
                 data, _HOST, _USERNAME,
                 _PASSWORD, _PORT, _TYPE,
                 _DESCRIPTION)


def __build_texttable(JSON_FROM_DB, _HOST,
                      _USERNAME, _PASSWORD,
                      _PORT, _TYPE, _DESCRIPTION,
                      _TIME, language):
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
        _table.add_rows([[_HOST, _USERNAME, _PASSWORD,
                          _PORT, _TYPE, _DESCRIPTION, _TIME],
                         [value['HOST'], value['USERNAME'],
                          value['PASSWORD'], value['PORT'], value['TYPE'],
                          value['DESCRIPTION'], value['TIME']]])
        events_num += 1
    return [_table.draw().encode('utf8') + b'\n\n' + messages(
        "nettacker_version_details").format(
        version_info()[0],
        version_info()[1],
        now()).encode('utf8') + b"\n", events_num]


def sort_logs(logs):
    """
    sort all events, create log file in HTML/TEXT/JSON and remove old logs

    Args:
        events: events log

    Returns:
        True if success otherwise None
    """
    info(messages("removing_logs_db"))
    remove_old_logs(logs)
    info(messages("inserting_report_db"))
    submit_report_to_db(logs)
    info(messages("updating_database"))
    submit_logs_to_db(logs)

    info(
        json.dumps(logs["event"])
    )
    # info(messages( "file_saved").format(output_file))
    return True
