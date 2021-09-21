#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import json
import csv
import texttable
from core.alert import messages
from core.alert import info
from core.compatible import version_info
from core.time import now
from core.die import die_failure
from database.db import get_logs_by_scan_unique_id
from database.db import submit_report_to_db


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
        'scan_unique_id',
        'port',
        'event',
        'json_event'

    ]
    _table.add_rows(
        [
            table_headers
        ]
    )
    for event in events:
        _table.add_rows(
            [
                table_headers,
                [
                    event['date'],
                    event['target'],
                    event['module_name'],
                    event['scan_unique_id'],
                    event['port'],
                    event['event'],
                    event['json_event']

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

        from lib.html_log import log_data
        html_table_content = log_data.table_title.format(
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
        for event in all_scan_logs:
            html_table_content += log_data.table_items.format(
                event["date"],
                event["target"],
                event["module_name"],
                event["scan_unique_id"],
                event["port"],
                event["event"],
                event["json_event"]
            )
        html_table_content += log_data.table_end + '<p class="footer">' + messages("nettacker_version_details").format(
            version_info()[0],
            version_info()[1],
            now()
        ) + '</p>'
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

    submit_report_to_db(
        {
            "date": now(model=None),
            "scan_unique_id": scan_unique_id,
            "options": vars(options),
        }
    )

    info(messages("file_saved").format(report_path_filename))
    return True
