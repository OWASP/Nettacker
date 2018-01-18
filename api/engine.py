#!/usr/bin/env python
# -*- coding: utf-8 -*-

import multiprocessing
import time
from flask import Flask
from core.alert import write
from core.alert import messages
from core._die import __die_success

app = Flask(__name__)


@app.route('/')
def index():
    return "Hello, World!"


def __process_it(api_host, api_port, api_debug_mode):
    app.run(host=api_host, port=api_port, debug=api_debug_mode)


def _start_api(api_host, api_port, api_debug_mode, api_access_key, api_client_white_list,
               api_client_white_list_ips, api_access_log, api_access_log_filename, language):
    # Starting the API
    write(messages(language, 156).format(api_access_key))
    p = multiprocessing.Process(target=__process_it, args=(api_host, api_port, api_debug_mode))
    p.start()
    # Sometimes it's take much time to terminate flask with CTRL+C
    # So It's better to use KeyboardInterrupt to terminate!
    while 1:
        try:
            exitflag = True
            if len(multiprocessing.active_children()) is not 0:
                exitflag = False
            time.sleep(0.3)
            if exitflag:
                break
        except KeyboardInterrupt:
            for process in multiprocessing.active_children():
                process.terminate()
            break

    __die_success()
