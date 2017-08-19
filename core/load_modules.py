#!/usr/bin/env python
# -*- coding: utf-8 -*-

from glob import glob


def load_all_modules():
    # Search for Modules
    module_names = []
    for lib in glob('lib\\brute/*/engine.py'):
        lib = lib.rsplit('\\')[-2]
        if lib + '_brute' not in module_names:
            module_names.append(lib + '_brute')
    for lib in glob('lib\\scan/*/engine.py'):
        lib = lib.rsplit('\\')[-2]
        if lib + '_scan' not in module_names:
            module_names.append(lib + '_scan')
    return module_names
