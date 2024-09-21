import csv
import html
import importlib
import json
import os
from datetime import datetime

import texttable

from nettacker import logger
from nettacker.config import Config, version_info
from nettacker.core.die import die_failure
from nettacker.core.messages import messages as _
from nettacker.core.utils.common import (
    merge_logs_to_list,
    now,
    sanitize_path,
    generate_compare_filepath,
)
from nettacker.database.db import get_logs_by_scan_id, submit_report_to_db, get_options_by_scan_id

log = logger.get_logger()
nettacker_path_config = Config.path


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


def build_compare_report(compare_results):
    """
    build the compare report
    Args:
        compare_results: Final result of the comparision(dict)
    Returns:
        report in html format
    """
    log.info(_("build_compare_report"))
    try:
        build_report = getattr(
            importlib.import_module("nettacker.lib.compare_report.engine"),
            "build_report",
        )
    except ModuleNotFoundError:
        die_failure(_("graph_module_unavailable").format("compare_report"))

    log.info(_("finish_build_report"))
    return build_report(compare_results)


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


def create_compare_text_table(results):
    table = texttable.Texttable()
    table_headers = list(results.keys())
    table.add_rows([table_headers])
    table.add_rows(
        [
            table_headers,
            [results[col] for col in table_headers],
        ]
    )
    table.set_cols_width([len(i) for i in table_headers])
    return table.draw() + "\n\n"


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
            + " ScanID: {0}".format(scan_id)
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


def create_compare_report(options, scan_id):
    """
    if compare_id is given then create the report of comparision b/w scans
    Args:
        options: parsing options
        scan_id: scan unique id
    Returns:
        True if success otherwise None
    """
    comp_id = options["scan_compare_id"] if isinstance(options, dict) else options.scan_compare_id
    scan_log_curr = get_logs_by_scan_id(scan_id)
    scan_logs_comp = get_logs_by_scan_id(comp_id)

    if not scan_log_curr:
        log.info(_("no_events_for_report"))
        return None
    if not scan_logs_comp:
        log.info(_("no_scan_to_compare"))
        return None

    scan_opts_curr = get_options_by_scan_id(scan_id)
    scan_opts_comp = get_options_by_scan_id(comp_id)

    def get_targets_set(item):
        return tuple(json.loads(item["options"])["targets"])

    curr_target_set = set(get_targets_set(item) for item in scan_opts_curr)
    comp_target_set = set(get_targets_set(item) for item in scan_opts_comp)

    def get_modules_ports(item):
        return (item["target"], item["module_name"], item["port"])

    curr_modules_ports = set(get_modules_ports(item) for item in scan_log_curr)
    comp_modules_ports = set(get_modules_ports(item) for item in scan_logs_comp)

    compare_results = {
        "curr_scan_details": (scan_id, scan_log_curr[0]["date"]),
        "comp_scan_details": (comp_id, scan_logs_comp[0]["date"]),
        "curr_target_set": tuple(curr_target_set),
        "comp_target_set": tuple(comp_target_set),
        "curr_scan_result": tuple(curr_modules_ports),
        "comp_scan_result": tuple(comp_modules_ports),
        "new_targets_discovered": tuple(curr_modules_ports - comp_modules_ports),
        "old_targets_not_detected": tuple(comp_modules_ports - curr_modules_ports),
    }
    if isinstance(options, dict):
        compare_report_path_filename = options["compare_report_path_filename"]
    else:
        compare_report_path_filename = (
            options.compare_report_path_filename
            if len(options.compare_report_path_filename) != 0
            else generate_compare_filepath(scan_id)
        )

    base_path = str(nettacker_path_config.results_dir)
    compare_report_path_filename = sanitize_path(compare_report_path_filename)
    fullpath = os.path.normpath(os.path.join(base_path, compare_report_path_filename))

    if not fullpath.startswith(base_path):
        raise PermissionError

    if (len(fullpath) >= 5 and fullpath[-5:] == ".html") or (
        len(fullpath) >= 4 and fullpath[-4:] == ".htm"
    ):
        html_report = build_compare_report(compare_results)
        with open(fullpath, "w", encoding="utf-8") as compare_report:
            compare_report.write(html_report + "\n")
    elif len(fullpath) >= 5 and fullpath[-5:] == ".json":
        with open(fullpath, "w", encoding="utf-8") as compare_report:
            compare_report.write(str(json.dumps(compare_results)) + "\n")
    elif len(fullpath) >= 5 and fullpath[-4:] == ".csv":
        keys = compare_results.keys()
        with open(fullpath, "a") as csvfile:
            writer = csv.DictWriter(csvfile, fieldnames=keys)
            if csvfile.tell() == 0:
                writer.writeheader()
            writer.writerow(compare_results)
    else:
        with open(fullpath, "w", encoding="utf-8") as compare_report:
            compare_report.write(create_compare_text_table(compare_results))

    log.write(create_compare_text_table(compare_results))
    log.info(_("compare_report_saved").format(fullpath))
    return True
