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
    info(messages( "build_graph"))
    try:
        start = getattr(
            __import__('lib.graph.{0}.engine'.format(
                graph_name.rsplit('_graph')[0]),
                       fromlist=['start']),
            'start')
    except:
        die_failure(
            messages( "graph_module_unavailable").format(graph_name))

    info(messages( "finish_build_graph"))
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
        output_file: output filename
        language: language
        graph_name: graph name
        scan_unique_id: scan hash id
        scan_cmd: scan cmd
        verbose_mode: verbose level number
        start_api_server: API flag
        profile: profiles
        selected_modules: module names
        ports: ports

    Returns:
        True if success otherwise None
    """
    # _HOST = messages( "HOST")
    # _USERNAME = messages( "USERNAME")
    # _PASSWORD = messages( "PASSWORD")
    # _PORT = messages( "PORT")
    # _TYPE = messages( "TYPE")
    # _DESCRIPTION = messages( "DESCRIPTION")
    # _TIME = messages( "TIME")
    # events_num = 0
    # report_type = ""
    # JSON_FROM_DB = __logs_by_scan_id(scan_unique_id, language)
    # JSON_Data = sorted(JSON_FROM_DB, key=sorted)

    # if (len(output_file) >= 5 and output_file[-5:] == '.html') or (
    #         len(output_file) >= 4 and output_file[-4:] == '.htm'):
    #     report_type = "HTML"
    #     data = sorted(JSON_FROM_DB, key=lambda x: sorted(x.keys()))
    #     # if user want a graph
    #     _graph = ''
    #     for i in data:
    #         if(i["DESCRIPTION"]):
    #             i["DESCRIPTION"] = html.escape(i["DESCRIPTION"])
    #             break
    #     if graph_name is not None:
    #         _graph = build_graph(graph_name,
    #                              language, data, 'HOST',
    #                              'USERNAME', 'PASSWORD',
    #                              'PORT', 'TYPE',
    #                              'DESCRIPTION')
    #     from lib.html_log import log_data
    #     _css = log_data.css_1
    #     _table = log_data.table_title.format(_graph, _css,
    #                                           _HOST, _USERNAME,
    #                                           _PASSWORD, _PORT,
    #                                           _TYPE, _DESCRIPTION,
    #                                           _TIME)

    #     for value in data:
    #         _table += log_data.table_items.format(value['HOST'],
    #                                                value['USERNAME'],
    #                                                value['PASSWORD'],
    #                                                value['PORT'],
    #                                                value['TYPE'],
    #                                                value['DESCRIPTION'],
    #                                                value['TIME'])
    #         events_num += 1
    #     _table += log_data.table_end + '<p class="footer">' + messages("nettacker_version_details") \
    #         .format(
    #             version_info()[0],
    #             version_info()[1],
    #             now()) + '</p>'
    #     __log_into_file(output_file,
    #                     'w' if type(_table) == str else 'wb',
    #                     _table, language, final=True)
    # elif len(output_file) >= 5 and output_file[-5:] == '.json':
    #     graph_name = ""
    #     report_type = "JSON"
    #     data = json.dumps(JSON_Data)
    #     events_num = len(JSON_Data)
    #     __log_into_file(output_file, 'w', data, language, final=True)

    # elif len(output_file) >= 5 and output_file[-4:] == '.csv':
    #     graph_name = ""
    #     report_type = "CSV"
    #     keys = JSON_Data[0].keys()
    #     data = json.dumps(JSON_Data)
    #     events_num = len(JSON_Data)
    #     with open(output_file, 'a') as csvfile:
    #         writer = csv.DictWriter(csvfile, fieldnames=keys)
    #         writer.writeheader()
    #         for i in JSON_Data:
    #             dicdata = {key: value for key, value in i.items()
    #                        if key in keys}
    #             writer.writerow(dicdata)

    # else:
    #     graph_name = ""
    #     report_type = "TEXT"
    #     data, events_num = __build_texttable(JSON_FROM_DB,
    #                                          _HOST, _USERNAME,
    #                                          _PASSWORD, _PORT,
    #                                          _TYPE,
    #                                          _DESCRIPTION,
    #                                          _TIME, language)
    #     __log_into_file(output_file, 'wb', data, language, final=True)
    # data = data if report_type == "TEXT" else __build_texttable(JSON_FROM_DB,
    #                                                             _HOST,
    #                                                             _USERNAME,
    #                                                             _PASSWORD,
    #                                                             _PORT,
    #                                                             _TYPE,
    #                                                             _DESCRIPTION,
    #                                                             _TIME,
    #                                                             language)[0]
    # info(messages( "updating_database"))
    # category = []
    # for sm in selected_modules:
    #     if sm.rsplit("_")[-1] not in category:
    #         category.append(sm.rsplit("_")[-1])
    # category = ",".join(list(set(category)))
    # selected_modules = ",".join(selected_modules)
    # if ports is None:
    #     ports = "default"
    info(messages( "removing_logs_db"))
    remove_old_logs(logs)
    info(messages( "inserting_report_db"))
    submit_report_to_db(logs)
    info(messages("updating_database"))
    submit_logs_to_db(logs)


    info(
            json.dumps(logs["event"])
    )
    # hosts = []
    # for log in JSON_Data:
    #     if log["HOST"] not in hosts:
    #         hosts.append(log["HOST"])
    # for host in hosts:
    #     for sm in selected_modules.rsplit(','):
    #         remove_old_logs(host, sm, scan_unique_id, language)
    # info(messages("inserting_logs_db"))
    # for log in JSON_Data:
    #     submit_logs_to_db(language, log)
    # if events_num:
    #     info(messages( "summary_report"))
    #     write(data)
    # else:
    #     info(messages( "no_event_found"))
    # info(messages( "file_saved").format(output_file))
    return True



