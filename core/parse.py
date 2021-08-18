#!/usr/bin/env python3
# -*- coding: utf-8 -*-


from core.scan_targers import start_scan_processes
from core.alert import info
from core.alert import write
from core.alert import messages
from core.load_modules import load_all_modules
from core.args_loader import load_all_args
from core.args_loader import check_all_required


def load():
    """
    load all ARGS, Apply rules and go for attacks

    Returns:
        True if success otherwise None
    """
    write("\n\n")
    options = check_all_required(load_all_args())

    info(messages("scan_started"))
    info(messages("loaded_modules").format(len(load_all_modules())))
    exit_code = start_scan_processes(options)
    info(messages("done"))
    return exit_code
