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

    # dgraph until here is compatible with jit library
    # start making it to be compatible to d3 library
    d3_structure = {
        "name": "Started Attack",
        "children": [],
    }
    for d3_level1 in dgraph["children"]:
        for d3_level2 in d3_level1:
            _to_modify = {
                "name": d3_level1["name"],
                "children": []
            }
            add_flag = True
            for d3_name in d3_structure["children"]:
                if _to_modify["name"] == d3_name["name"]:
                    add_flag = False
            if add_flag:
                d3_structure["children"].append(_to_modify)
    for i in range(0, len(dgraph["children"])):
        for j in range(0, len(dgraph["children"][i]["children"])):
            ip = dgraph["children"][i]["name"]
            method = dgraph["children"][i]["children"][j]["name"]
            for k in range(0, len(d3_structure["children"])):
                if ip == d3_structure["children"][k]["name"]:
                    add_flag = True
                    for l in range(0, len(d3_structure["children"][k]["children"])):
                        if d3_structure["children"][k]["children"][l]["name"] == method:
                            add_flag = False
                    _to_modify = {
                        "name": method,
                        "children": []
                    }
                    if add_flag:
                        d3_structure["children"][k]["children"].append(_to_modify)

    for i in range(0, len(dgraph["children"])):
        for j in range(0, len(dgraph["children"][i]["children"])):
            for k in range(0, len(dgraph["children"])):
                ip = dgraph["children"][k]["name"]
                for d3_level3 in dgraph["children"][k]["children"]:
                    for l in range(0, len(dgraph["children"][k]["children"])):
                        method = dgraph["children"][k]["children"][l]["name"]
                        for m in range(0, len(dgraph["children"][k]["children"][l]["children"])):
                            port = dgraph["children"][k]["children"][l]["children"][m]["data"]["relation"][0][0]
                            description = dgraph["children"][k]["children"][l]["children"][m]["data"]["relation"][0][1]
                            user = dgraph["children"][k]["children"][l]["children"][m]["data"]["relation"][0][2]
                            passwd = dgraph["children"][k]["children"][l]["children"][m]["data"]["relation"][0][3]
                            desc = _HOST + ': ' + ip + ' ' + port + ' ' + description + ' ' + user + ' ' + passwd
                            _to_modify = {
                                "name": desc,
                            }
                            add_flag = True
                            for n in range(0, len(d3_structure["children"][k]["children"][l]["children"])):
                                if d3_structure["children"][k]["children"][l]["children"][n]["name"] == desc:
                                    add_flag = False
                            if add_flag:
                                d3_structure["children"][k]["children"][l]["children"].append(_to_modify)

    return open('lib/d3/sample.html', 'rb').read().decode('utf8') \
        .replace('__data_will_locate_here__', json.dumps(d3_structure)) \
        .replace('__title_to_replace__', messages(language, 90)) \
        .replace('__description_to_replace__', messages(language, 91)) \
        .replace('__html_title_to_replace__', messages(language, 92))


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
        _css = '''<style>

    table {
        background: #f5f5f5;
        border-collapse: separate;
        box-shadow: inset 0 1px 0 #fff;
        font-size: 12px;
        line-height: 24px;
        margin: 30px auto;
        text-align: left;
        width: 800px;
    }
    
    th {
        background: url(https://jackrugile.com/images/misc/noise-diagonal.png), linear-gradient(#777, #444);
        border-left: 1px solid #555;
        border-right: 1px solid #777;
        border-top: 1px solid #555;
        border-bottom: 1px solid #333;
        box-shadow: inset 0 1px 0 #999;
        color: #fff;
      font-weight: bold;
        padding: 10px 15px;
        position: relative;
        text-shadow: 0 1px 0 #000;
    }
    
    th:after {
        background: linear-gradient(rgba(255,255,255,0), rgba(255,255,255,.08));
        content: '';
        display: block;
        height: 25%;
        left: 0;
        margin: 1px 0 0 0;
        position: absolute;
        top: 25%;
        width: 100%;
    }
    
    th:first-child {
        border-left: 1px solid #777;
        box-shadow: inset 1px 1px 0 #999;
    }
    
    th:last-child {
        box-shadow: inset -1px 1px 0 #999;
    }
    
    td {
        border-right: 1px solid #fff;
        border-left: 1px solid #e8e8e8;
        border-top: 1px solid #fff;
        border-bottom: 1px solid #e8e8e8;
        padding: 10px 15px;
        position: relative;
        transition: all 300ms;
    }
    
    td:first-child {
        box-shadow: inset 1px 0 0 #fff;
    }
    
    td:last-child {
        border-right: 1px solid #e8e8e8;
        box-shadow: inset -1px 0 0 #fff;
    }
    
    
    tr:last-of-type td {
        box-shadow: inset 0 -1px 0 #fff;
    }
    
    tr:last-of-type td:first-child {
        box-shadow: inset 1px -1px 0 #fff;
    }
    
    tr:last-of-type td:last-child {
        box-shadow: inset -1px -1px 0 #fff;
    }
    
    tbody:hover td {
        color: transparent;
        text-shadow: 0 0 3px #aaa;
    }
    
    tbody:hover tr:hover td {
        color: #444;
        text-shadow: 0 1px 0 #fff;
    }
    </style>'''
        _table = '%s%s\n\n<center><br><br><br><table>\n<tr><th>%s</th><th>%s</th><th>%s</th><th>%s' \
                 '</th><th>%s</th><th>%s</th></tr>\n' % (_graph, _css, _HOST, _USERNAME,
                                                         _PASSWORD, _PORT, _TYPE, _DESCRIPTION,
                                                         )
        for value in data:
            _table += '<tr><td>%s</td><td>%s</td><td>%s</td><td>%s</td><td>%s</td><td>%s</td></tr>\n' % (
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
