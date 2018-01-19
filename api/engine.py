#!/usr/bin/env python
# -*- coding: utf-8 -*-

import multiprocessing
import time
from flask import Flask
from flask import jsonify
from flask import request as flask_request
from flask import abort
from core.alert import write
from core.alert import messages
from core._die import __die_success
from api.routes import __structure

app = Flask(__name__)


@app.before_request
def limit_remote_addr():
    # IP Limitation
    if app.config["OWASP_NETTACKER_CONFIG"]["api_client_white_list"]:
        if flask_request.remote_addr not in app.config["OWASP_NETTACKER_CONFIG"]["api_client_white_list_ips"]:
            return jsonify(__structure(status="error",
                                       msg="your IP not authorized")), 403
    try:
        key = flask_request.args["key"]
    except:
        try:
            key = flask_request.form["key"]
        except:
            key = None
    if app.config["OWASP_NETTACKER_CONFIG"]["api_access_key"] != key:
        return jsonify(__structure(status="error",
                                   msg="invalid API key")), 401


@app.route('/', methods=["GET", "POST"])
def index():
    return jsonify(__structure(status="ok",
                               msg="please read documentations https://github.com/viraintel/OWASP-Nettacker/wiki"))


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
    write(messages(language, 156).format(api_access_key))
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
