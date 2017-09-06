#!/usr/bin/env python
# -*- coding: utf-8 -*-

import json
import texttable
import datetime
import sys
from core.alert import messages
from core.alert import info
from core.alert import error
from core import compatible


def build_graph(graph_flag, language, data, _HOST, _USERNAME, _PASSWORD, _PORT, _TYPE, _DESCRIPTION):
    info(messages(language, 88))
    try:
        start = getattr(
            __import__('lib.graph.%s.engine' % (graph_flag.rsplit('_graph')[0]),
                       fromlist=['start']),
            'start')
    except:
        error(messages(language, 98).format(graph_flag))
        from core.color import finish
        finish()
        sys.exit(1)

    info(messages(language, 89))
    return start(graph_flag, language, data, _HOST, _USERNAME, _PASSWORD, _PORT, _TYPE, _DESCRIPTION)


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
        if graph_flag is not None:
            _graph = build_graph(graph_flag, language, data, _HOST, _USERNAME, _PASSWORD, _PORT, _TYPE, _DESCRIPTION)
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
        save = open(log_in_file, 'wb')
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
        save = open(log_in_file, 'wb')
        save.write(_table.draw().encode('utf8') + '\n\n' +
                   messages(language, 93).format(compatible.__version__, compatible.__code_name__,
                                                 datetime.datetime.now()).encode('utf8') + '\n\n')
        save.close()
    return 0
