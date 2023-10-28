#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import json
import csv
import texttable
import html
from nettacker.core.alert import messages
from nettacker.core.alert import info, write
from nettacker.core.compatible import version_info
from nettacker.core.time import now
from nettacker.core.die import die_failure
from nettacker.database.db import get_logs_by_scan_unique_id
from nettacker.database.db import submit_report_to_db
from nettacker.core.utility import merge_logs_to_list


def build_graph(graph_name, events):
    """
    build a graph

    Args:
        graph_name: graph name
        events: list of events

    Returns:
        graph in HTML type
    """
    info(messages("build_graph"))
    try:
        start = getattr(
            __import__(
                'lib.graph.{0}.engine'.format(
                    graph_name.rsplit('_graph')[0]
                ),
                fromlist=['start']
            ),
            'start'
        )
    except Exception:
        die_failure(
            messages("graph_module_unavailable").format(graph_name)
        )

    info(messages("finish_build_graph"))
    return start(
        events
    )


def build_texttable(events):
    """
    value['date'], value["target"], value['module_name'], value['scan_unique_id'],
                                                    value['options'], value['event']
    build a text table with generated event related to the scan

    :param events: all events
    :return:
        array [text table, event_number]
    """
    _table = texttable.Texttable()
    table_headers = [
        'date',
        'target',
        'module_name',
        'port',
        'logs'

    ]
    _table.add_rows(
        [
            table_headers
        ]
    )
    for event in events:
        log = merge_logs_to_list(json.loads(event["json_event"]), [])
        _table.add_rows(
            [
                table_headers,
                [
                    event['date'],
                    event['target'],
                    event['module_name'],
                    event['port'],
                    "\n".join(log) if log else "Detected"

                ]
            ]
        )
    return _table.draw().encode('utf8') + b'\n\n' + messages("nettacker_version_details").format(
        version_info()[0],
        version_info()[1],
        now()
    ).encode('utf8') + b"\n"


def create_report(options, scan_unique_id):
    """
    sort all events, create log file in HTML/TEXT/JSON and remove old logs

    Args:
        options: parsing options
        scan_unique_id: scan unique id

    Returns:
        True if success otherwise None
    """
    all_scan_logs = get_logs_by_scan_unique_id(scan_unique_id)
    if not all_scan_logs:
        info(messages("no_events_for_report"))
        return True
    report_path_filename = options.report_path_filename
    if (
            len(report_path_filename) >= 5 and report_path_filename[-5:] == '.html'
    ) or (
            len(report_path_filename) >= 4 and report_path_filename[-4:] == '.htm'
    ):
        if options.graph_name:
            html_graph = build_graph(options.graph_name, all_scan_logs)
        else:
            html_graph = ''

        from nettacker.lib.html_log import log_data
        html_table_content = log_data.table_title.format(
            html_graph,
            log_data.css_1,
            'date',
            'target',
            'module_name',
            'port',
            'logs',
            'json_event'
        )
        index=1
        for event in all_scan_logs:
            log = merge_logs_to_list(json.loads(event["json_event"]), [])
            html_table_content += log_data.table_items.format(
                event["date"],
                event["target"],
                event["module_name"],
                event["port"],
                "<br>".join(log) if log else "Detected", #event["event"], #log
                index,
                html.escape(event["json_event"])
            )
            index+=1
        html_table_content += log_data.table_end + '<div id="json_length">' + str(index-1) + '</div>' + '<p class="footer">' + messages("nettacker_version_details").format(
            version_info()[0],
            version_info()[1],
            now()
        ) + '</p>' + log_data.json_parse_js
        with open(report_path_filename, 'w', encoding='utf-8') as save:
            save.write(html_table_content + '\n')
            save.close()
    elif len(report_path_filename) >= 5 and report_path_filename[-5:] == '.json':
        with open(report_path_filename, 'w', encoding='utf-8') as save:
            save.write(
                str(
                    json.dumps(all_scan_logs)
                ) + '\n'
            )
            save.close()
    elif len(report_path_filename) >= 5 and report_path_filename[-4:] == '.csv':
        keys = all_scan_logs[0].keys()
        with open(report_path_filename, 'a') as csvfile:
            writer = csv.DictWriter(csvfile, fieldnames=keys)
            writer.writeheader()
            for log in all_scan_logs:
                dict_data = {
                    key: value for key, value in log.items() if key in keys
                }
                writer.writerow(dict_data)
            csvfile.close()

    else:
        with open(report_path_filename, 'wb') as save:
            save.write(
                build_texttable(all_scan_logs)
            )
            save.close()
    write(build_texttable(all_scan_logs))
    submit_report_to_db(
        {
            "date": now(model=None),
            "scan_unique_id": scan_unique_id,
            "options": vars(options),
        }
    )

    info(messages("file_saved").format(report_path_filename))
    return True
