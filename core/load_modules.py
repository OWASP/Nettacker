#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import os
from glob import glob
from core import module_protocols
from io import StringIO


class NettackerModules:
    def __init__(self):
        self.module_name = None
        self.module_content = None
        self.scan_unique_id = None
        self.target = None
        self.module_inputs = {}
        self.libraries = dir(module_protocols)

    def load(self):
        import yaml
        from config import nettacker_paths
        self.module_content = yaml.load(
            StringIO(
                open(
                    nettacker_paths()['modules_path'] +
                    '/' +
                    self.module_name.split('_')[-1].split('.yaml')[0] +
                    '/' +
                    '_'.join(self.module_name.split('_')[:-1]) +
                    '.yaml',
                    'r'
                ).read().format(
                    **self.module_inputs
                )
            ),
            Loader=yaml.FullLoader
        )

    def generate_loops(self):
        from core.utility import expand_module_steps
        self.module_content['payloads'] = expand_module_steps(self.module_content['payloads'])

    def start(self):
        from terminable_thread import Thread
        from core.utility import wait_for_threads_to_finish
        active_threads = []
        from core.alert import warn
        for payload in self.module_content['payloads']:
            if payload['library'] not in self.libraries:
                warn('library [{library}] is not support!'.format(library=payload['library']))
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
                    thread = Thread(
                        target=protocol.run,
                        args=(sub_step, payload,)
                    )
                    thread.name = f"{self.target} -> {self.module_name} -> {sub_step}"
                    thread.start()
                    active_threads.append(thread)
                    wait_for_threads_to_finish(
                        active_threads,
                        maximum=self.module_inputs['thread_per_host'],
                        terminable=True
                    )
        wait_for_threads_to_finish(
            active_threads,
            maximum=None,
            terminable=True
        )


def load_all_graphs():
    """
    load all available graphs

    Returns:
        an array of graph names
    """
    from config import nettacker_paths
    graph_names = []
    for graph_library in glob(os.path.join(nettacker_paths()['home_path'] + '/lib/graph/*/engine.py')):
        graph_names.append(graph_library.split('/')[-2] + '_graph')
    return graph_names


def load_all_languages():
    """
    load all available languages

    Returns:
        an array of languages
    """
    languages_list = []
    from config import nettacker_paths
    for language in glob(os.path.join(nettacker_paths()['home_path'] + '/lib/messages/*.yaml')):
        languages_list.append(language.split('/')[-1].split('.')[0])
    return languages_list


def load_all_modules():
    """
    load all available modules

    Returns:
        an array of all module names
    """
    # Search for Modules
    from config import nettacker_paths
    module_names = []
    for module_name in glob(os.path.join(nettacker_paths()['home_path'] + '/modules/*/*.yaml')):
        libname = module_name.split('/')[-1].split('.')[0]
        category = module_name.split('/')[-2]
        module_names.append(libname + '_' + category)
    module_names.append('all')
    return module_names


def perform_scan(options, target, module_name, scan_unique_id):
    from core.alert import (info,
                            messages)

    options.target = target
    validate_module = NettackerModules()
    validate_module.module_name = module_name
    validate_module.module_inputs = vars(options)
    validate_module.scan_unique_id = scan_unique_id
    validate_module.target = target
    validate_module.load()
    validate_module.generate_loops()
    info(f"starting scan {target} - {module_name}")
    validate_module.start()
    info(messages("finished_module").format(module_name, target))
    return os.EX_OK
