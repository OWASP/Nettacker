#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import os
import lib
import inspect
from glob import glob
from config import _core_config
from core.config_builder import _core_default_config
from core.config_builder import _builder
from core import module_protocols
from io import StringIO


class module:
    def __init__(self):
        self.module_path = None
        self.module_content = None
        self.module_inputs = {}
        self.libraries = dir(module_protocols)

    def load(self):
        import yaml
        self.module_content = yaml.load(
            StringIO(
                open(self.module_path, 'r').read().format(
                    **self.module_inputs
                )
            ),
            Loader=yaml.FullLoader
        )

    def generate_loops(self):
        from core.utility import expand_module_steps
        self.module_content['payloads'] = expand_module_steps(self.module_content['payloads'])

    def start(self):
        for payload in self.module_content['payloads']:
            if payload['library'] not in self.libraries:
                print('library [{library}] is not support!'.format(library=payload['library']))
                return None
            protocol = getattr(
                __import__(
                    'core.module_protocols.{library}'.format(library=payload['library']),
                    fromlist=['engine']
                ),
                'engine'
            )
            for step in payload['steps']:
                for sub_step in step:
                    # must be multi thread here!
                    protocol.run(sub_step, payload)


def load_all_graphs():
    """
    load all available graphs

    Returns:
        an array of graph names
    """
    graph_names = []
    for graph_library in glob(os.path.dirname(inspect.getfile(lib)) + '/graph/*/engine.py'):
        graph_names.append(graph_library.split('/')[-2] + '_graph')
    return graph_names


def load_all_modules():
    """
    load all available modules

    Returns:
        an array of all module names
    """
    # Search for Modules
    module_names = []
    for module_name in glob('/modules/*/*.yaml'):
        libname = module_name.split('/')[-1].split('.')[0]
        category = module_name.split('/')[-2]
        module_names.append(libname + '_' + category)
    module_names.append('all')
    return module_names


def load_file_path():
    """
    load home path

    Returns:
        value of home path
    """
    return _builder(_core_config(), _core_default_config())["home_path"]


def main():
    for directory in os.listdir('modules/scan/'):
        if 'dir_scan.yaml' in directory:
            validate_module = module()
            validate_module.module_path = "modules/scan/{}".format(directory)
            validate_module.module_inputs = {
                "BaseURL": 'https://evil.com',
                'TimeOut': 2
            }
            validate_module.load()
            validate_module.generate_loops()
            validate_module.start()
    return os.EX_OK
