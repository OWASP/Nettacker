#!/usr/bin/env python
# -*- coding: utf-8 -*-

import multiprocessing
import time
import random
from flask import Flask
from flask import jsonify
from flask import request as flask_request
from core.alert import write_to_api_console
from core.alert import messages
from core._die import __die_success
from api.api_core import __structure
from api.api_core import __get_value
from core.config import _core_config
from core.config_builder import _core_default_config
from core.config_builder import _builder
from api.api_core import __remove_non_api_keys
from api.api_core import __rules
from api.__start_scan import __scan

app = Flask(__name__)


@app.before_request
def limit_remote_addr():
    language = app.config["OWASP_NETTACKER_CONFIG"]["language"]
    # IP Limitation
    if app.config["OWASP_NETTACKER_CONFIG"]["api_client_white_list"]:
        if flask_request.remote_addr not in app.config["OWASP_NETTACKER_CONFIG"]["api_client_white_list_ips"]:
            return jsonify(__structure(status="error", msg=messages(language, 161))), 403
    # API Key Ckeck
    if app.config["OWASP_NETTACKER_CONFIG"]["api_access_key"] != __get_value(flask_request, "key"):
        return jsonify(__structure(status="error", msg=messages(language, 160))), 401


@app.errorhandler(400)
def error_400(error):
    return jsonify(__structure(status="error", msg=error.description)), 400


@app.errorhandler(404)
def error_404(error):
    return jsonify(__structure(status="error",
                               msg=messages(app.config["OWASP_NETTACKER_CONFIG"]["language"], 162))), 400


@app.route('/', methods=["GET", "POST"])
def index():
    language = app.config["OWASP_NETTACKER_CONFIG"]["language"]
    return jsonify(__structure(status="ok", msg=messages(language, 159)))


@app.route('/new/scan', methods=["GET", "POST"])
def new_scan():
    _start_scan_config = {}
    language = app.config["OWASP_NETTACKER_CONFIG"]["language"]
    for key in _core_default_config():
        if __get_value(flask_request, key) is not None:
            _start_scan_config[key] = __get_value(flask_request, key)
    _start_scan_config = __rules(__remove_non_api_keys(_builder(_start_scan_config,
                                                                _builder(_core_config(), _core_default_config()))),
                                 _core_default_config(), language)
    scan_id = "".join(random.choice("0123456789abcdef") for x in range(32))
    scan_cmd = messages(language, 158)
    _start_scan_config["scan_id"] = scan_id
    p = multiprocessing.Process(target=__scan, args=[_start_scan_config, scan_id, scan_cmd])
    p.start()
    return jsonify(_start_scan_config)


def __process_it(api_host, api_port, api_debug_mode, api_access_key, api_client_white_list,
                 api_client_white_list_ips, api_access_log, api_access_log_filename, language):
    app.config["OWASP_NETTACKER_CONFIG"] = {
        "api_access_key": api_access_key,
        "api_client_white_list": api_client_white_list,
        "api_client_white_list_ips": api_client_white_list_ips,
        "api_access_log": api_access_log,
        "api_access_log_filename": api_access_log_filename,
        "language": language
    }
    app.run(host=api_host, port=api_port, debug=api_debug_mode)


def _start_api(api_host, api_port, api_debug_mode, api_access_key, api_client_white_list,
               api_client_white_list_ips, api_access_log, api_access_log_filename, language):
    # Starting the API
    write_to_api_console(messages(language, 156).format(api_access_key))
    p = multiprocessing.Process(target=__process_it,
                                args=(api_host, api_port, api_debug_mode, api_access_key, api_client_white_list,
                                      api_client_white_list_ips, api_access_log, api_access_log_filename, language))
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
