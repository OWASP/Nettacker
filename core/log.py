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
from database.db import get_logs_by_scan_unique_id
from core.alert import write


def build_graph(graph_name, language,
                data, date, target, module_name, scan_unique_id, options, event):
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
    except Exception as e:
        die_failure(
            messages("graph_module_unavailable").format(graph_name))

    # print(graph_name, language, data, date, target, module_name, scan_unique_id, options, event)
    info(messages("finish_build_graph"))
    return start(graph_name, language,
                 data, date, target, module_name, scan_unique_id, options, event)


def __build_texttable(JSON_FROM_DB, target,
                      module_name, scan_unique_id,
                      options, event, date):
    """
    value['date'], value["target"], value['module_name'], value['scan_unique_id'],
                                                    value['options'], value['event']
    build a text table with generated event related to the scan

    :param JSON_FROM_DB: JSON events from database
    :param target: host string
    :param module_name: username string
    :param scan_unique_id: password string
    :param options: port string
    :param event: type string
    :param date: description string
    :param _TIME: time string
    :param language: language
    :return:
        array [text table, event_number]
    """
    _table = texttable.Texttable()
    _table.add_rows(
        [[target, module_name, scan_unique_id, options, event, date]])
    events_num = 0
    for value in JSON_FROM_DB:
        _table.add_rows([[target, module_name, scan_unique_id,
                          options, event, date],
                         [value['target'], value['module_name'],
                          value['scan_unique_id'], value['options'], value['event'],
                          value['date']]])
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
    JSON_FROM_DB = get_logs_by_scan_unique_id(logs["scan_unique_id"])
    JSON_Data = sorted(JSON_FROM_DB, key=sorted)
    report_path_filename = logs["options"]["report_path_filename"]
    if (len(report_path_filename) >= 5 and report_path_filename[-5:] == '.html') or (
            len(report_path_filename) >= 4 and report_path_filename[-4:] == '.htm'):
        report_type = "HTML"
        data = sorted(JSON_FROM_DB, key=lambda x: sorted(x.keys()))
        # if user want a graph
        _graph = ''
        # for i in data:
        #     if(i["DESCRIPTION"]):
        #         i["DESCRIPTION"] = html.escape(i["DESCRIPTION"])
        #         break
        if logs["options"]["graph_name"] is not None:
            _graph = build_graph(logs["options"]["graph_name"], "en", data, logs["date"], logs["target"],
                                 logs["module_name"], logs["scan_unique_id"], logs["options"], logs["event"])
        from lib.html_log import log_data
        _css = log_data.css_1
        _table = log_data.table_title.format(
            _graph, log_data.css_1, 'date', 'target', 'module_name', 'scan_unique_id', 'options', 'event')
        for value in data:
            _table += log_data.table_items.format(value["date"], value["target"], value["module_name"], value["scan_unique_id"],
                                                  value["options"], value["event"])
            # events_num += 1
        _table += log_data.table_end + '<p class="footer">' + \
            messages("nettacker_version_details").format(version_info()[0], version_info()[1], now()) + '</p>'
        with open(report_path_filename, 'w', encoding='utf-8') as save:
            save.write(_table + '\n')
    elif len(report_path_filename) >= 5 and report_path_filename[-5:] == '.json':
        graph_name = ""
        report_type = "JSON"
        data = json.dumps(JSON_Data)
        # events_num = len(JSON_Data)
        with open(report_path_filename, 'w', encoding='utf-8') as save:
            save.write(str(data) + '\n')
    elif len(report_path_filename) >= 5 and report_path_filename[-4:] == '.csv':
        graph_name = ""
        report_type = "CSV"
        keys = JSON_Data[0].keys()
        data = json.dumps(JSON_Data)
        # events_num = len(JSON_Data)
        with open(report_path_filename, 'a') as csvfile:
            writer = csv.DictWriter(csvfile, fieldnames=keys)
            writer.writeheader()
            for i in JSON_Data:
                dicdata = {key: value for key, value in i.items()
                           if key in keys}
                writer.writerow(dicdata)

    else:
        graph_name = ""
        report_type = "TEXT"
        data, events_num = __build_texttable(
            JSON_FROM_DB, logs["target"], logs["module_name"], logs["scan_unique_id"], logs["options"], logs["event"], logs["date"])
        if len(report_path_filename) >= 4 and not report_path_filename[-3:] == '.txt':
            report_path_filename += ".txt"
        with open(report_path_filename, 'wb') as save:
            data = data if report_type == "TEXT" else __build_texttable(
                JSON_FROM_DB, logs["target"], logs["module_name"], logs["scan_unique_id"], logs["options"], logs["event"], logs["date"])[0]
            save.write(data)

    # info(messages("removing_logs_db"))
    # remove_old_logs(logs)
    # info(messages("inserting_report_db"))
    # submit_report_to_db(logs)
    # info(messages("updating_database"))
    # submit_logs_to_db(logs)

    info(
        json.dumps(logs["event"])
    )
    # info(messages( "file_saved").format(output_file))
    return True
