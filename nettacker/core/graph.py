import csv
import html
import importlib
import json
from datetime import datetime

import texttable

from nettacker import logger
from nettacker.config import version_info
from nettacker.core.die import die_failure
from nettacker.core.messages import messages as _
from nettacker.core.utils.common import merge_logs_to_list, now
from nettacker.database.db import get_logs_by_scan_id, submit_report_to_db

log = logger.get_logger()


def build_graph(graph_name, events):
    """
    build a graph

    Args:
        graph_name: graph name
        events: list of events

    Returns:
        graph in HTML type
    """
    log.info(_("build_graph"))
    try:
        start = getattr(
            importlib.import_module(
                f"nettacker.lib.graph.{graph_name.rsplit('_graph')[0]}.engine"
            ),
            "start",
        )
    except ModuleNotFoundError:
        die_failure(_("graph_module_unavailable").format(graph_name))

    log.info(_("finish_build_graph"))
    return start(events)


def build_text_table(events):
    """
    value['date'], value["target"], value['module_name'], value['scan_id'],
                                                    value['options'], value['event']
    build a text table with generated event related to the scan

    :param events: all events
    :return:
        array [text table, event_number]
    """
    _table = texttable.Texttable()
    table_headers = ["date", "target", "module_name", "port", "logs"]
    _table.add_rows([table_headers])
    for event in events:
        log = merge_logs_to_list(json.loads(event["json_event"]), [])
        _table.add_rows(
            [
                table_headers,
                [
                    event["date"],
                    event["target"],
                    event["module_name"],
                    str(event["port"]),
                    "\n".join(log) if log else "Detected",
                ],
            ]
        )
    return (
        _table.draw()
        + "\n\n"
        + _("nettacker_version_details").format(version_info()[0], version_info()[1], now())
        + "\n"
    )


def create_report(options, scan_id):
    """
    sort all events, create log file in HTML/TEXT/JSON and remove old logs

    Args:
        options: parsing options
        scan_id: scan unique id

    Returns:
        True if success otherwise None
    """
    all_scan_logs = get_logs_by_scan_id(scan_id)
    if not all_scan_logs:
        log.info(_("no_events_for_report"))
        return True
    report_path_filename = options.report_path_filename
    if (len(report_path_filename) >= 5 and report_path_filename[-5:] == ".html") or (
        len(report_path_filename) >= 4 and report_path_filename[-4:] == ".htm"
    ):
        if options.graph_name:
            html_graph = build_graph(options.graph_name, all_scan_logs)
        else:
            html_graph = ""

        from nettacker.lib.html_log import log_data

        html_table_content = log_data.table_title.format(
            html_graph,
            log_data.css_1,
            "date",
            "target",
            "module_name",
            "port",
            "logs",
            "json_event",
        )
        index = 1
        for event in all_scan_logs:
            log_list = merge_logs_to_list(json.loads(event["json_event"]), [])
            html_table_content += log_data.table_items.format(
                event["date"],
                event["target"],
                event["module_name"],
                event["port"],
                "<br>".join(log_list) if log_list else "Detected",  # event["event"], #log
                index,
                html.escape(event["json_event"]),
            )
            index += 1
        html_table_content += (
            log_data.table_end
            + '<div id="json_length">'
            + str(index - 1)
            + "</div>"
            + '<p class="footer">'
            + _("nettacker_version_details").format(version_info()[0], version_info()[1], now())
            + "</p>"
            + log_data.json_parse_js
        )
        with open(report_path_filename, "w", encoding="utf-8") as report_file:
            report_file.write(html_table_content + "\n")
            report_file.close()
    elif len(report_path_filename) >= 5 and report_path_filename[-5:] == ".json":
        with open(report_path_filename, "w", encoding="utf-8") as report_file:
            report_file.write(str(json.dumps(all_scan_logs)) + "\n")
            report_file.close()
    elif len(report_path_filename) >= 5 and report_path_filename[-4:] == ".csv":
        keys = all_scan_logs[0].keys()
        with open(report_path_filename, "a") as csvfile:
            writer = csv.DictWriter(csvfile, fieldnames=keys)
            writer.writeheader()
            for log_list in all_scan_logs:
                dict_data = {key: value for key, value in log_list.items() if key in keys}
                writer.writerow(dict_data)
            csvfile.close()

    else:
        with open(report_path_filename, "w", encoding="utf-8") as report_file:
            report_file.write(build_text_table(all_scan_logs))

    log.write(build_text_table(all_scan_logs))
    submit_report_to_db(
        {
            "date": datetime.now(),
            "scan_id": scan_id,
            "options": vars(options),
        }
    )

    log.info(_("file_saved").format(report_path_filename))
    return True
