#!/usr/bin/env python3
# -*- coding: utf-8 -*-

from core.alert import info
from core.alert import messages
from core.log import sort_logs
from core.targets import expand_targets
from core.alert import write
from core.color import reset_color
from core.utility import generate_random_token


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

    info(messages("sorting_results"))
    sort_logs(
        output_file,
        language,
        graph_name,
        scan_id,
        scan_cmd,
        verbose_mode,
        0,
        None,
        selected_modules,
        backup_ports,
    )
    write("\n")
    info(messages("done"))
    write("\n\n")
    reset_color()
    return True
