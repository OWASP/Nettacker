#!/usr/bin/env python
# -*- coding: utf-8 -*-

import json
import sys
import texttable
import lockfile
from core.alert import messages
from core.alert import info
from core.alert import error
from core import compatible
from core._time import now
from core._die import __die_failure
from api.__database import submit_report_to_db
from api.__database import submit_logs_to_db
from api.__database import remove_old_logs
from api.__database import __logs_to_report
from core.config_builder import default_paths
from core.config import _paths
from core.config_builder import _builder
from core.compatible import version

def build_graph(graph_flag, language, data, _HOST, _USERNAME, _PASSWORD, _PORT, _TYPE, _DESCRIPTION):
    info(messages(language, 88))
    try:
        start = getattr(
            __import__('lib.graph.{0}.engine'.format(graph_flag.rsplit('_graph')[0]),
                       fromlist=['start']),
            'start')
    except:
        __die_failure(messages(language, 98).format(graph_flag))

    info(messages(language, 89))
    return start(graph_flag, language, data, _HOST, _USERNAME, _PASSWORD, _PORT, _TYPE, _DESCRIPTION)


def _get_log_values(log_in_file):
    o = open(log_in_file)
    data = ''
    for value in o:
        if value[0] == '{':
            data += value + ','
    return data[:-1]


def sort_logs(log_in_file, language, graph_flag, scan_id, scan_cmd, verbose_level, api_flag, profile, scan_method,
              ports):
    _HOST = messages(language, 53)
    _USERNAME = messages(language, 54)
    _PASSWORD = messages(language, 55)
    _PORT = messages(language, 56)
    _TYPE = messages(language, 57)
    _DESCRIPTION = messages(language, 58)
    _TIME = messages(language, 115)
    events_num = 0
    report_type = ""
    JSON_FROM_DB = __logs_to_report(scan_id, language)
    JSON_Data = sorted(JSON_FROM_DB, key=sorted)
    if compatible.version() is 2:
        import sys
        reload(sys)
        sys.setdefaultencoding('utf8')
    if (len(log_in_file) >= 5 and log_in_file[-5:] == '.html') or (
            len(log_in_file) >= 4 and log_in_file[-4:] == '.htm'):
        report_type = "HTML"
        data = sorted(JSON_FROM_DB, key=lambda x: sorted(x.keys()))
        # if user want a graph
        _graph = ''
        if graph_flag is not None:
            _graph = build_graph(graph_flag, language, data, 'HOST', 'USERNAME', 'PASSWORD', 'PORT', 'TYPE',
                                 'DESCRIPTION')
        from lib.html_log import _log_data
        _css = _log_data.css_1
        _table = _log_data.table_title.format(_graph, _css, _HOST, _USERNAME, _PASSWORD, _PORT, _TYPE, _DESCRIPTION,
                                              _TIME)

        for value in data:
            _table += _log_data.table_items.format(value['HOST'], value['USERNAME'], value['PASSWORD'],
                                                   value['PORT'], value['TYPE'], value['DESCRIPTION'], value['TIME'])
            events_num += 1
        _table += _log_data.table_end + '<p class="footer">' + messages(language, 93) \
            .format(compatible.__version__, compatible.__code_name__, now()) + '</p>'
        __log_into_file(log_in_file, 'w' if type(_table) == str else 'wb', _table, language, final=True)
    elif len(log_in_file) >= 5 and log_in_file[-5:] == '.json':
        graph_flag = ""
        report_type = "JSON"
        data = json.dumps(JSON_Data)
        events_num = len(JSON_Data)
        __log_into_file(log_in_file, 'w', data, language, final=True)
    else:
        graph_flag = ""
        report_type = "TEXT"
        data = sorted(JSON_FROM_DB)
        _table = texttable.Texttable()
        _table.add_rows([[_HOST, _USERNAME, _PASSWORD, _PORT, _TYPE, _DESCRIPTION, _TIME]])
        for value in data:
            _table.add_rows([[_HOST, _USERNAME, _PASSWORD, _PORT, _TYPE, _DESCRIPTION, _TIME],
                             [value['HOST'], value['USERNAME'], value['PASSWORD'], value['PORT'], value['TYPE'],
                              value['DESCRIPTION'], value['TIME']]])
            events_num += 1
        data = _table.draw().encode('utf8') + '\n\n' + messages(language, 93).format(compatible.__version__,
                                                                                     compatible.__code_name__,
                                                                                     now()).encode('utf8')

        __log_into_file(log_in_file, 'wb', data, language, final=True)
    info(messages(language, 167))
    category = []
    for sm in scan_method:
        if sm.rsplit("_")[-1] not in category:
            category.append(sm.rsplit("_")[-1])
    category = ",".join(list(set(category)))
    scan_method = ",".join(scan_method)
    if ports is None:
        ports = "default"
    submit_report_to_db(now(), scan_id, log_in_file, events_num, 0 if verbose_level is 0 else 1, api_flag, report_type,
                        graph_flag, category, profile, scan_method, language, scan_cmd, ports)
    info(messages(language, 171))
    hosts = []
    for log in JSON_Data:
        if log["HOST"] not in hosts:
            hosts.append(log["HOST"])
    for host in hosts:
        for sm in scan_method.rsplit(','):
            remove_old_logs(host, sm, scan_id, language)
    # info(messages(language, 170))
    # for log in JSON_Data:
    #     submit_logs_to_db(language, log)
    return True


def __log_into_file(filename, mode, data, language, final=False):

    if version() is 2:
    
      if _builder(_paths(), default_paths())["tmp_path"] in filename:
          if not final:
              flock = lockfile.FileLock(filename)
              flock.acquire()
          with open(filename, mode) as save:
              save.write(data + '\n')
          if not final:
              flock.release()
      else:
          if final:
              with open(filename, mode) as save:
                  save.write(data + '\n')
          else:
              submit_logs_to_db(language, data)

    else:

      if _builder(_paths(), default_paths())["tmp_path"] in filename:
          if not final:
              flock = lockfile.FileLock(filename)
              flock.acquire()
          with open(filename, mode, encoding='utf-8') as save:
              save.write(data + '\n')
          if not final:
              flock.release()
      else:
          if final:
              with open(filename, mode, encoding='utf-8') as save:
                  save.write(data + '\n')
          else:
              submit_logs_to_db(language, data)

              
