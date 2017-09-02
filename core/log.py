#!/usr/bin/env python
# -*- coding: utf-8 -*-

import json
import texttable
from core.alert import messages


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
        data = json.loads('[' + data[:-1] + ']')
        _table = '<table border="1">\n<tr><th>{0}</th><th>{1}</th><th>{2}</th><th>{3}' \
                 '</th><th>{4}</th><th>{5}</th></tr>\n'.format(
            _HOST, _USERNAME, _PASSWORD, _PORT, _TYPE, _DESCRIPTION)
        for value in data:
            _table += '<th>{0}</th><th>{1}</th><th>{2}</th><th>{3}</th><th>{4}</th><th>{5}</th></tr>\n'.format(
                value[_HOST], value[_USERNAME], value[_PASSWORD], value[_PORT], value[_TYPE],
                value[_DESCRIPTION])
        _table += '</table><br><br>'
        save_old = open(log_in_file)
        old = ''
        for value in save_old:
            if value[0] != '{':
                old += value
        save = open(log_in_file, 'w')
        save.write(old + _table + '\n\n')
        save.close()
    else:
        o = open(log_in_file)
        data = ''
        for value in o:
            if value[0] == '{':
                data += value + ','
        data = json.loads('[' + data[:-1] + ']')
        _table = texttable.Texttable()
        _table.add_rows([[_HOST, _USERNAME, _PASSWORD, _PORT, _TYPE, _DESCRIPTION]])
        for value in data:
            _table.add_rows([[_HOST, _USERNAME, _PASSWORD, _PORT, _TYPE, _DESCRIPTION],
                             [value[_HOST], value[_USERNAME], value[_PASSWORD], value[_PORT], value[_TYPE],
                              value[_DESCRIPTION]]])
        save_old = open(log_in_file)
        old = ''
        for value in save_old:
            if value[0] != '{':
                old += value
        save = open(log_in_file, 'w')
        save.write(old + _table.draw().encode('utf8') + '\n\n')
        save.close()
    return 0
