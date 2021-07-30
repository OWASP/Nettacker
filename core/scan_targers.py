#!/usr/bin/env python3
# -*- coding: utf-8 -*-

from core.targets import expand_targets
from core.utility import generate_random_token
from core.load_modules import perform_scan


def start_scan_processes(options):
    """
    preparing for attacks and managing multi-processing for host

    Args:
        options: all options

    Returns:
        True when it ends
    """
    scan_unique_id = generate_random_token(32)
    # find total number of targets + types + expand (subdomain, IPRanges, etc)
    options.targets = expand_targets(options)
    # todo: multi process here
    for target in options.targets:
        for module_name in options.selected_module:
            perform_scan(options, target, module_name, scan_unique_id)
    return True
