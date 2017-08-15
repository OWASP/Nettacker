#!/usr/bin/env python
# -*- coding: utf-8 -*-

import json
import texttable


def sort_logs(log_in_file):
    if (len(log_in_file)>= 5 and log_in_file[-5:] == '.html') or (len(log_in_file)>= 4 and log_in_file[-4:] == '.htm'):
        o = open(log_in_file)
        data = ''
        for value in o:
            if value[0] == '{':
                data += value + ','
        data = json.loads('[' + data[:-1] + ']')
        _table = '<table border="1">\n<tr><th>HOST</th><th>USERNAME</th><th>PASSWORD</th><th>PORT</th><th>TYPE</th><th>DESCRIPTION</th></tr>\n'
        for value in data:
            _table += '<th>%s</th><th>%s</th><th>%s</th><th>%s</th><th>%s</th><th>%s</th></tr>\n' % (
            value['HOST'], value['USERNAME'], value['PASSWORD'], str(value['PORT']), value['TYPE'],
            value['DESCRIPTION'])
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
        _table.add_rows([['HOST', 'USERNAME', 'PASSWORD', 'PORT', 'TYPE', 'DESCRIPTION']])
        for value in data:
            _table.add_rows([['HOST', 'USERNAME', 'PASSWORD', 'PORT', 'TYPE', 'DESCRIPTION'],
                             [value['HOST'], value['USERNAME'], value['PASSWORD'], value['PORT'], value['TYPE'],
                              value['DESCRIPTION']]])
        save_old = open(log_in_file)
        old = ''
        for value in save_old:
            if value[0] != '{':
                old += value
        save = open(log_in_file, 'w')
        save.write(old + _table.draw() + '\n\n')
        save.close()
    return 0