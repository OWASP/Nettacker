#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import numpy
import multiprocessing
from core.alert import (info,
                        messages)
from core.targets import expand_targets
from core.utility import generate_random_token
from core.load_modules import perform_scan
from terminable_thread import Thread
from core.utility import wait_for_threads_to_finish


def parallel_scan_process(options, targets, scan_unique_id):
    active_threads = []
    for target in targets:
        for module_name in options.selected_modules:
            from database.db import remove_old_logs
            remove_old_logs(
                {
                    "target": target,
                    "module_name": module_name,
                    "scan_unique_id": scan_unique_id,
                }
            )
            thread = Thread(
                target=perform_scan,
                args=(options, target, module_name, scan_unique_id,)
            )
            thread.name = f"{target} -> {module_name}"
            thread.start()
            info(messages("start_parallel_module_scan").format(module_name, target))
            active_threads.append(thread)
            if not wait_for_threads_to_finish(active_threads, options.parallel_module_scan, True):
                return False
    wait_for_threads_to_finish(active_threads, maximum=None, terminable=True)
    return True


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
    # optimize CPU usage
    options.targets = [
        targets.tolist() for targets in numpy.array_split(
            expand_targets(options, scan_unique_id),
            options.set_hardware_usage if options.set_hardware_usage >= len(options.targets) else len(options.targets)
        )
    ]
    active_processes = []
    info(messages("start_multi_process").format(len(options.targets)))
    for targets in options.targets:
        process = multiprocessing.Process(
            target=parallel_scan_process,
            args=(options, targets, scan_unique_id,)
        )
        process.start()
        active_processes.append(process)

    wait_for_threads_to_finish(active_processes)
    return True
