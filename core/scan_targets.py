#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import numpy
import multiprocessing
from core.alert import (info,
                        verbose_event_info,
                        messages)
from core.targets import expand_targets
from core.utility import generate_random_token
from core.load_modules import perform_scan
from terminable_thread import Thread
from core.utility import wait_for_threads_to_finish
from core.graph import create_report


def parallel_scan_process(options, targets, scan_unique_id, process_number):
    active_threads = []
    verbose_event_info(messages("single_process_started").format(process_number))
    total_number_of_modules = len(targets) * len(options.selected_modules)
    total_number_of_modules_counter = 1
    for target in targets:
        for module_name in options.selected_modules:
            thread = Thread(
                target=perform_scan,
                args=(
                    options,
                    target,
                    module_name,
                    scan_unique_id,
                    process_number,
                    total_number_of_modules_counter,
                    total_number_of_modules
                )
            )
            thread.name = f"{target} -> {module_name}"
            thread.start()
            verbose_event_info(
                messages("start_parallel_module_scan").format(
                    process_number,
                    module_name,
                    target,
                    total_number_of_modules_counter,
                    total_number_of_modules
                )
            )
            total_number_of_modules_counter += 1
            active_threads.append(thread)
            if not wait_for_threads_to_finish(active_threads, options.parallel_module_scan, True):
                return False
    wait_for_threads_to_finish(active_threads, maximum=None, terminable=True)
    return True


def multi_processor(options, scan_unique_id):
    if not options.targets:
        info(messages("no_live_service_found"))
        return True
    number_of_total_targets = len(options.targets)
    options.targets = [
        targets.tolist() for targets in numpy.array_split(
            options.targets,
            options.set_hardware_usage if options.set_hardware_usage <= len(options.targets)
            else number_of_total_targets
        )
    ]
    info(messages("removing_old_db_records"))
    from database.db import remove_old_logs
    for target_group in options.targets:
        for target in target_group:
            for module_name in options.selected_modules:
                remove_old_logs(
                    {
                        "target": target,
                        "module_name": module_name,
                        "scan_unique_id": scan_unique_id,
                    }
                )
    for _ in range(options.targets.count([])):
        options.targets.remove([])
    active_processes = []
    info(
        messages("start_multi_process").format(
            number_of_total_targets,
            len(options.targets)
        )
    )
    process_number = 0
    for targets in options.targets:
        process_number += 1
        process = multiprocessing.Process(
            target=parallel_scan_process,
            args=(options, targets, scan_unique_id, process_number,)
        )
        process.start()
        active_processes.append(process)
    return wait_for_threads_to_finish(active_processes, sub_process=True)


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
    info(messages("regrouping_targets"))
    options.targets = expand_targets(options, scan_unique_id)
    if options.targets:
        exit_code = multi_processor(options, scan_unique_id)
        create_report(options, scan_unique_id)
    else:
        info(messages("no_live_service_found"))
        exit_code = True
    return exit_code
