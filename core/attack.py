#!/usr/bin/env python
# -*- coding: utf-8 -*-

import sys
from core.alert import info
from core.alert import error
from core.alert import messages


def start_attack(target, num, total, scan_method, users, passwds, timeout_sec, thread_number, ports, log_in_file,
                 time_sleep, language, verbose_level, socks_proxy, retries, ping_flag, methods_args, scan_id, scan_cmd):
    info(messages(language, 45).format(str(target), str(num), str(total)))
    # Calling Engines
    try:
        start = getattr(
            __import__('lib.{0}.{1}.engine'.format(scan_method.rsplit('_')[-1], '_'.join(scan_method.rsplit('_')[:-1])),
                       fromlist=['start']), 'start')
    except:
        error(messages(language, 46).format(scan_method))
        from core.color import finish
        finish()
        sys.exit(1)
    start(target, users, passwds, ports, timeout_sec, thread_number, num, total, log_in_file, time_sleep, language,
          verbose_level, socks_proxy, retries, ping_flag, methods_args, scan_id, scan_cmd)
    return 0
