#!/usr/bin/env python
# -*- coding: utf-8 -*-

import json
import texttable
import string
import random
import datetime
from core.alert import messages
from core.alert import info
from core import compatible


def build_graph(language, data, _HOST, _USERNAME, _PASSWORD, _PORT, _TYPE, _DESCRIPTION):
    info(messages(language, 88))
    dgraph = {
        "id": "0",
        "name": "Start Attacking",
        "children": [],
        "data": [],
        "relation": ""
    }
    n = 1
    for data_graph in data:
        position = len(dgraph["children"])
        _to_modify = {
            "id": str(n),
            "name": data_graph[_HOST],
            "data": {},
            "children": [],
            "data": {
                "relation": "Start Attacking"
            }
        }
        add_flag = True
        _position = None
        m = 0
        for host in dgraph["children"]:
            if data_graph[_HOST] == host["name"]:
                add_flag = False
                _position = m
            m += 1
        if add_flag:
            dgraph["children"].append(_to_modify)
        _to_modify = {
            "children": [],
            "id": ''.join(random.choice(string.ascii_letters + string.digits) for _ in range(20)),
            "name": data_graph[_TYPE],
            "data": {
                "band": data_graph[_DESCRIPTION],
                "relation": [[_PORT + ': "' + str(data_graph[_PORT]) + '"',
                              _DESCRIPTION + ': "' + data_graph[_DESCRIPTION] + '"',
                              _USERNAME + ': "' + data_graph[_USERNAME] + '"',
                              _PASSWORD + ': "' + data_graph[_PASSWORD] + '"']]
            }
        }
        add_flag = True
        __position = 0
        try:
            for method in dgraph["children"]:
                if data_graph[_HOST] == method["name"]:
                    for imethod in method["children"]:
                        __position += 1
                        if data_graph[_TYPE] == imethod["name"]:
                            __position -= 1
                            add_flag = False
        except:
            pass
        if add_flag:
            if _position is not None:
                dgraph["children"][_position]["children"].append(_to_modify)
            else:
                dgraph["children"][position]["children"].append(_to_modify)
        else:
            if _position is not None:
                if dgraph["children"][_position]["children"][__position]["data"]["relation"] \
                        [0] != _PORT + ': "' + str(data_graph[_PORT]) + '"':
                    dgraph["children"][_position]["children"][__position]["data"]["relation"].append(
                        [_PORT + ': "' + str(data_graph[_PORT]) + '"',
                         _DESCRIPTION + ': "' + data_graph[_DESCRIPTION] + '"',
                         _USERNAME + ': "' + data_graph[_USERNAME] + '"',
                         _PASSWORD + ': "' + data_graph[_PASSWORD] + '"'])
            else:
                if dgraph["children"][position]["children"][__position]["data"]["relation"] \
                        [0] != _PORT + ': "' + str(data_graph[_PORT]) + '"':
                    dgraph["children"][position]["children"][__position]["data"]["relation"].append(
                        [_PORT + ': "' + str(data_graph[_PORT]) + '"',
                         _DESCRIPTION + ': "' + data_graph[_DESCRIPTION] + '"',
                         _USERNAME + ': "' + data_graph[_USERNAME] + '"',
                         _PASSWORD + ': "' + data_graph[_PASSWORD] + '"'])
        n += 1
    info(messages(language, 89))
    backup_dgraph = json.loads(json.dumps(dgraph))

    for b in range(0, len(backup_dgraph["children"])):
        for c in range(0, len(backup_dgraph["children"][b])):
            for d in range(0, len(backup_dgraph["children"][b]["children"])):
                for a in backup_dgraph["children"][b]["children"][d]["data"]["relation"]:
                    a = json.loads(json.dumps(a))
                    _to_modify = {
                        "children": [],
                        "id": ''.join(random.choice(string.ascii_letters + string.digits) for _ in range(20)),
                        "name": a[0].rsplit()[-1].replace('\"', ''),
                        "data": {
                            "band": a[1],
                            "relation": [a]
                        }
                    }
                    add_flag = True
                    for e in dgraph["children"][b]["children"][d]["children"]:
                        if _to_modify["name"] == e["name"]:
                            add_flag = False
                    if add_flag:
                        dgraph["children"][b]["children"][d]["children"].append(_to_modify)

    return open('lib/jit/sample.html').read() \
        .replace('__data_will_locate_here__', json.dumps(dgraph)) \
        .replace('__js_jit_lib_will_locate_here__', open('lib/jit/jit-yc.js').read()) \
        .replace('__title_to_replace__', messages(language, 90)) \
        .replace('__description_to_replace__', messages(language, 91)) \
        .replace('__html_title_to_replace__', messages(language, 92)) \
        .replace('__time_and_version_to_replace__', messages(language, 93)
                 .format(compatible.__version__,
                         compatible.__code_name__,
                         datetime.datetime.now()))


def sort_logs(log_in_file, language, graph_flag):
    _HOST = messages(language, 53)
    _USERNAME = messages(language, 54)
    _PASSWORD = messages(language, 55)
    _PORT = messages(language, 56)
    _TYPE = messages(language, 57)
    _DESCRIPTION = messages(language, 58)

    if (len(log_in_file) >= 5 and log_in_file[-5:] == '.html') or (
                    len(log_in_file) >= 4 and log_in_file[-4:] == '.htm'):
        o = open(log_in_file)
        data = ''
        for value in o:
            if value[0] == '{':
                data += value + ','
        data = sorted(json.loads('[' + data[:-1] + ']'))
        # if user want a graph
        _graph = ''
        if graph_flag is True:
            _graph = build_graph(language, data, _HOST, _USERNAME, _PASSWORD, _PORT, _TYPE, _DESCRIPTION)
        _table = '%s\n\n<center><br><br><br><table border="1">\n<tr><th>%s</th><th>%s</th><th>%s</th><th>%s' \
                 '</th><th>%s</th><th>%s</th></tr>\n' % (_graph,
                                                         _HOST,
                                                         _USERNAME,
                                                         _PASSWORD,
                                                         _PORT,
                                                         _TYPE,
                                                         _DESCRIPTION,
                                                         )
        for value in data:
            _table += '<th>%s</th><th>%s</th><th>%s</th><th>%s</th><th>%s</th><th>%s</th></tr>\n' % (
                value[_HOST], value[_USERNAME], value[_PASSWORD], value[_PORT], value[_TYPE],
                value[_DESCRIPTION])
        _table += '</table><br><br></center><br><br>' + messages(language, 93) \
            .format(compatible.__version__, compatible.__code_name__,
                    datetime.datetime.now())
        save = open(log_in_file, 'w')
        save.write(_table.encode('utf8'))
        save.close()
    else:
        o = open(log_in_file)
        data = ''
        for value in o:
            if value[0] == '{':
                data += value + ','
        data = sorted(json.loads('[' + data[:-1] + ']'))
        _table = texttable.Texttable()
        _table.add_rows([[_HOST, _USERNAME, _PASSWORD, _PORT, _TYPE, _DESCRIPTION]])
        for value in data:
            _table.add_rows([[_HOST, _USERNAME, _PASSWORD, _PORT, _TYPE, _DESCRIPTION],
                             [value[_HOST], value[_USERNAME], value[_PASSWORD], value[_PORT], value[_TYPE],
                              value[_DESCRIPTION]]])
        save = open(log_in_file, 'w')
        save.write(_table.draw().encode('utf8') + '\n\n' +
                   messages(language, 93).format(compatible.__version__, compatible.__code_name__,
                                                 datetime.datetime.now()).encode('utf8') + '\n\n')
        save.close()
    return 0
