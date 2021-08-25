#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import os
import json
import string
import random
from core.alert import messages


def start(events):
    """
    generate the jit_circle_v1_graph with events

    Args:
        events: event

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
        if each_scan['HOST'] not in normalisedjson['children']:
            normalisedjson['children'].update({each_scan['HOST']: {}})
            normalisedjson['children'][each_scan['HOST']].update(
                {each_scan['TYPE']: []})

        if each_scan['TYPE'] not in normalisedjson['children'][each_scan['HOST']]:
            normalisedjson['children'][each_scan['HOST']].update(
                {each_scan['TYPE']: []})

        normalisedjson['children'][each_scan['HOST']][each_scan['TYPE']].append("HOST: \"%s\", PORT:\"%s\", DESCRIPTION:\"%s\", USERNAME:\"%s\", PASSWORD:\"%s\"" % (
            each_scan['HOST'], each_scan['PORT'], each_scan['DESCRIPTION'], each_scan['USERNAME'], each_scan['PASSWORD']))

    # define a dgraph_json
    dgraph = {
        "id": "0",
        "data": [],
        "relation": "",
        "name": "Start Attacking",
        "children": []
    }

    # get data for dgraph_json
    n = 1
    for host in normalisedjson['children']:

        dgraph['children'].append({"id": str(n), "name": host, "data": {"relation": "Start Attacking"}, "children": [{"id": ''.join(random.choice(
            string.ascii_letters + string.digits) for _ in range(20)), "name": otype, "data": {"band": [description.split(', ')[2].lstrip("DESCRIPTION: ").strip("\"") for description in normalisedjson['children'][host][otype]][0], "relation": [description.split(', ')[1:] for description in normalisedjson['children'][host][otype]]}, "children": [{"children": [], "data":{"band": description.split(', ')[2], "relation": description.split(', ')[1:]}, "id": ''.join(random.choice(
                string.ascii_letters + string.digits) for _ in range(20)), "name": description.split(', ')[1].lstrip("PORT: ").strip("\"")} for description in normalisedjson['children'][host][otype]]} for otype in normalisedjson['children'][host]]})
        n += 1

    from config import nettacker_paths

    data = open(
        os.path.join(
            nettacker_paths()['web_static_files_path'],
            'report/jit_circle_v1.html'
        )
    ).read().replace('__data_will_locate_here__', json.dumps(dgraph)) \
        .replace('__title_to_replace__', messages("pentest_graphs")) \
        .replace('__description_to_replace__', messages("graph_message")) \
        .replace('__html_title_to_replace__', messages("nettacker_report"))
    return data
