#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import json
import os
from core.alert import messages


def start(events):
    """
    generate the d3_tree_v1_graph with events

    Args:
        events: all events

    Returns:
        a graph in HTML
    """

    # define  a normalised_json
    normalisedjson = {
        "name": "Started attack",
        "children": {}
    }
    # get data for normalised_json
    for each_scan in events:
        if each_scan['target'] not in normalisedjson['children']:
            normalisedjson['children'].update({each_scan['target']: {}})
            normalisedjson['children'][each_scan['target']].update(
                {each_scan['module_name']: []})

        if each_scan['module_name'] not in normalisedjson['children'][each_scan['target']]:
            normalisedjson['children'][each_scan['target']].update(
                {each_scan['module_name']: []})
        normalisedjson['children'][each_scan['target']][each_scan['module_name']].append(
            f"target: {each_scan['target']}, module_name: {each_scan['module_name']}, options: {each_scan['options']}, event: {each_scan['event']}")
    # define a d3_structure_json
    d3_structure = {"name": "Starting attack",
                    "children": []}
    # get data for normalised_json
    for target in list(normalisedjson['children'].keys()):
        for otype in list(normalisedjson['children'][target].keys()):
            for description in normalisedjson["children"][target][otype]:
                children_array = [{"name": otype, "children": [{"name": description}]}]
                d3_structure["children"].append({"name": target, "children": children_array})

    from config import nettacker_paths
    data = open(
        os.path.join(
            nettacker_paths()['web_static_files_path'],
            'report/d3_tree_v1.html'
        )
    ).read().replace('__data_will_locate_here__', json.dumps(d3_structure)) \
        .replace('__title_to_replace__', messages("pentest_graphs")) \
        .replace('__description_to_replace__', messages("graph_message")) \
        .replace('__html_title_to_replace__', messages("nettacker_report"))
    return data
