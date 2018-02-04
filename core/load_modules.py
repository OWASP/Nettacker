#!/usr/bin/env python
# -*- coding: utf-8 -*-

import sys
import os
from glob import glob
from core.alert import messages
from core.alert import info
from core._die import __die_failure


def load_all_graphs():
    graph_names = []
    for lib in glob(
            'lib/graph/*/engine.py' if sys.platform == 'win32' or sys.platform == 'win64' else '{}/lib/graph/*/engine.py'.format(
                load_file_path())):
        lib = lib.rsplit('\\' if sys.platform == 'win32' or sys.platform == 'win64' else '/')[-2]
        if lib + '_graph' not in graph_names:
            graph_names.append(lib + '_graph')
    return graph_names


def load_all_modules():
    # Search for Modules
    module_names = []
    for lib in glob(
            'lib/*/*/engine.py' if sys.platform == 'win32' or sys.platform == 'win64' else '{}/lib/*/*/engine.py'.format(
                load_file_path())):

        libname = lib.rsplit('\\' if sys.platform == 'win32' or sys.platform == 'win64' else '/')[-2]
        category = lib.rsplit('\\' if sys.platform == 'win32' or sys.platform == 'win64' else '/')[-3]

        if category != 'graph' and libname + '_' + category not in module_names:
            module_names.append(libname + '_' + category)
    module_names.append('all')
    return module_names


def load_all_method_args(language, API=False):
    module_names = []
    modules_args = {}
    # get module names
    for lib in glob(
            'lib/*/*/engine.py' if sys.platform == 'win32' or sys.platform == 'win64' else '{}/lib/*/*/engine.py'.format(
                    load_file_path())):
        lib = lib.replace('/', '.').replace('\\', '.').rsplit('.py')[0]
        if lib.rsplit('.')[1] != 'graph' and lib not in module_names:
            module_names.append(lib)
    # get args
    res = ""
    for imodule in module_names:
        try:
            extra_requirements_dict = getattr(__import__(imodule, fromlist=['extra_requirements_dict']),
                                              'extra_requirements_dict')
        except:
            __die_failure(messages(language, 112).format(imodule))
        imodule_args = extra_requirements_dict()
        modules_args[imodule] = []
        for imodule_arg in imodule_args:
            if API:
                res += imodule_arg + "=" + ",".join(map(str, imodule_args[imodule_arg])) + "\n"
            modules_args[imodule].append(imodule_arg)
    if API:
        return res
    for imodule in modules_args:
        info(imodule.rsplit('.')[2] + '_' + imodule.rsplit('.')[1] + ' --> '
             + ", ".join(modules_args[imodule]))
    return module_names


def __check_external_modules():
    external_modules = ["argparse", "netaddr", "requests", "paramiko", "texttable", "socks", "win_inet_pton",
                        "flask", "sqlite3"]
    for module in external_modules:
        try:
            __import__(module)
        except:
            __die_failure("pip install -r requirements.txt ---> " + module + " not installed!")
    return True

def load_file_path():

    return os.path.dirname(os.path.dirname(os.path.realpath(__file__)))
