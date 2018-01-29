#!/usr/bin/env python
# -*- coding: utf-8 -*-

import multiprocessing
import time
import random
import os
import string
from flask import Flask
from flask import jsonify
from flask import request as flask_request
from flask import render_template
from flask import abort
from flask import Response
from flask import make_response
from core.alert import write_to_api_console
from core.alert import messages
from core._die import __die_success
from api.api_core import __structure
from api.api_core import __get_value
from api.api_core import root_dir
from api.api_core import get_file
from api.api_core import __mime_types
from api.api_core import __scan_methods
from api.api_core import __profiles
from api.api_core import __graphs
from api.api_core import __languages
from core.load_modules import load_all_method_args
from core.config import _core_config
from core.config_builder import _core_default_config
from core.config_builder import _builder
from api.api_core import __remove_non_api_keys
from api.api_core import __rules
from api.api_core import __api_key_check
from api.__start_scan import __scan
from core._time import now

template_dir = os.path.join(os.path.join(os.path.dirname(os.path.dirname(__file__)), "web"), "static")
app = Flask(__name__, template_folder=template_dir)
app.config.from_object(__name__)


@app.errorhandler(400)
def error_400(error):
    return jsonify(__structure(status="error", msg=error.description)), 400


@app.errorhandler(401)
def error_401(error):
    return jsonify(__structure(status="error", msg=error.description)), 401


@app.errorhandler(403)
def error_403(error):
    return jsonify(__structure(status="error", msg=error.description)), 403


@app.errorhandler(404)
def error_404(error):
    return jsonify(__structure(status="error",
                               msg=messages(app.config["OWASP_NETTACKER_CONFIG"]["language"], 162))), 404


@app.before_request
def limit_remote_addr():
    language = app.config["OWASP_NETTACKER_CONFIG"]["language"]
    # IP Limitation
    if app.config["OWASP_NETTACKER_CONFIG"]["api_client_white_list"]:
        if flask_request.remote_addr not in app.config["OWASP_NETTACKER_CONFIG"]["api_client_white_list_ips"]:
            abort(403, messages(language, 161))


@app.after_request
def access_log(response):
    if app.config["OWASP_NETTACKER_CONFIG"]["api_access_log"]:
        r_log = open(app.config["OWASP_NETTACKER_CONFIG"]["api_access_log_filename"], "ab")
        # if you need to log POST data
        # r_log.write(
        #     "{0} [{1}] {2} \"{3} {4}\" {5} {6} {7}\r\n".format(flask_request.remote_addr, now(), flask_request.host,
        #                                                      flask_request.method, flask_request.full_path,
        #                                                      flask_request.user_agent, response.status_code,
        #                                                      json.dumps(flask_request.form)))
        r_log.write("{0} [{1}] {2} \"{3} {4}\" {5} {6}\r\n".format(flask_request.remote_addr, now(), flask_request.host,
                                                                   flask_request.method, flask_request.full_path,
                                                                   flask_request.user_agent, response.status_code))
        r_log.close()
    return response


@app.route("/", defaults={"path": ""})
@app.route("/<path:path>")
def get_statics(path):
    static_types = __mime_types()
    return Response(get_file(os.path.join(root_dir(), path)),
                    mimetype=static_types.get(os.path.splitext(path)[1], "text/html"))


@app.route("/", methods=["GET", "POST"])
def index():
    language = app.config["OWASP_NETTACKER_CONFIG"]["language"]
    filename = "results/results_{0}_{1}.html".format(now(model="%Y_%m_%d_%H_%M_%S"),
                                                     "".join(random.choice(string.ascii_lowercase) for x in
                                                             range(10)))
    return render_template("index.html", scan_methods=__scan_methods(), profiles=__profiles(),
                           graphs=__graphs(), languages=__languages(), filename=filename,
                           method_args_list=load_all_method_args(language, API=True))


@app.route("/new/scan", methods=["GET", "POST"])
def new_scan():
    _start_scan_config = {}
    language = app.config["OWASP_NETTACKER_CONFIG"]["language"]
    print flask_request.data
    __api_key_check(app, flask_request, language)
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


@app.route("/session/check", methods=["GET"])
def __session_check():
    language = app.config["OWASP_NETTACKER_CONFIG"]["language"]
    __api_key_check(app, flask_request, language)
    return jsonify(__structure(status="ok", msg=messages(language, 165))), 200


@app.route("/session/set", methods=["GET"])
def __session_set():
    language = app.config["OWASP_NETTACKER_CONFIG"]["language"]
    __api_key_check(app, flask_request, language)
    res = make_response(jsonify(__structure(status="ok", msg=messages(language, 165))))
    res.set_cookie("key", value=app.config["OWASP_NETTACKER_CONFIG"]["api_access_key"])
    return res


@app.route("/session/kill", methods=["GET"])
def __session_kill():
    language = app.config["OWASP_NETTACKER_CONFIG"]["language"]
    res = make_response(jsonify(__structure(status="ok", msg=messages(language, 166))))
    res.set_cookie("key", value="expired")
    return res


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
