# !/usr/bin/env python
# -*- coding: utf-8 -*-

import multiprocessing
import time
import random
import csv
import json
import string
from datetime import datetime
from database.db import create_connection, __logs_by_scan_id
from database.models import HostsLog, Report
import os
from flask import Flask
from flask import jsonify
from flask import request as flask_request
from flask import render_template
from flask import abort
from flask import escape
from flask import Response
from flask import make_response
from core.alert import write_to_api_console
from core.alert import messages
from core.die import die_success
from core.time import now
from api.api_core import structure
from api.api_core import get_value
from api.api_core import root_dir
from api.api_core import get_file
from api.api_core import mime_types
from api.api_core import scan_methods
# from api.api_core import profiles
from api.api_core import graphs
from api.api_core import languages
from api.api_core import remove_non_api_keys
from api.api_core import rules
from api.api_core import api_key_check
from api.start_scan import __scan
from database.db import __select_results
from database.db import __get_result
from database.db import __last_host_logs
from database.db import __logs_to_report_json
from database.db import __search_logs
from database.db import __logs_to_report_html

TEMPLATE_DIR = os.path.join(os.path.join(
    os.path.dirname(os.path.dirname(__file__)), "web"), "static")
app = Flask(__name__, template_folder=TEMPLATE_DIR)
app.config.from_object(__name__)


def __language(app=app):
    """
    find the language in config

    Args:
        app: flask app

    Returns:
        the language in string
    """
    return app.config["OWASP_NETTACKER_CONFIG"]["language"]


@app.errorhandler(400)
def error_400(error):
    """
    handle the 400 HTTP error

    Args:
        error: the flask error

    Returns:
        400 JSON error
    """
    return jsonify(structure(status="error", msg=error.description)), 400


@app.errorhandler(401)
def error_401(error):
    """
    handle the 401 HTTP error

    Args:
        error: the flask error

    Returns:
        401 JSON error
    """
    return jsonify(structure(status="error", msg=error.description)), 401


@app.errorhandler(403)
def error_403(error):
    """
    handle the 403 HTTP error

    Args:
        error: the flask error

    Returns:
        403 JSON error
    """
    return jsonify(structure(status="error", msg=error.description)), 403


@app.errorhandler(404)
def error_404(error):
    """
    handle the 404 HTTP error

    Args:
        error: the flask error

    Returns:
        404 JSON error
    """
    return jsonify(structure(status="error",
                             msg=messages(app.config[
                                              "OWASP_NETTACKER_CONFIG"]["language"],
                                          "not_found"))), 404


@app.before_request
def limit_remote_addr():
    """
    check if IP filtering applied and API address is in whitelist

    Returns:
        None if it's in whitelist otherwise abort(403)
    """
    # IP Limitation
    if app.config["OWASP_NETTACKER_CONFIG"]["api_client_whitelisted_ips"]:
        if flask_request.remote_addr not in app.config[
            "OWASP_NETTACKER_CONFIG"]["api_client_whitelisted_ips"]:
            abort(403, messages( "unauthorized_IP"))
    return


@app.after_request
def access_log(response):
    """
    if access log enabled, its writing the logs

    Args:
        response: the flask response

    Returns:
        the flask response
    """
    if app.config["OWASP_NETTACKER_CONFIG"]["api_access_log"]:
        r_log = open(app.config["OWASP_NETTACKER_CONFIG"][
                         "api_access_log"], "ab")
        # if you need to log POST data
        # r_log.write(
        #     "{0} [{1}] {2} \"{3} {4}\" {5} {6} {7}\r\n".format(
        #                                                      flask_request.remote_addr,
        #                                                      now(),
        #                                                      flask_request.host,
        #                                                      flask_request.method,
        #                                                      flask_request.full_path,
        #                                                      flask_request.user_agent,
        #                                                      response.status_code,
        #                                                      json.dumps(flask_request.form)))
        r_log.write("{0} [{1}] {2} \"{3} {4}\" {5} {6}\r\n".format(
            flask_request.remote_addr, now(),
            flask_request.host,
            flask_request.method, flask_request.full_path,
            flask_request.user_agent, response.status_code).encode())
        r_log.close()
    return response


@app.route("/", defaults={"path": ""})
@app.route("/<path:path>")
def get_statics(path):
    """
    getting static files and return content mime types

    Args:
        path: path and filename

    Returns:
        file content and content type if file found otherwise abort(404)
    """
    static_types = mime_types()
    return Response(get_file(os.path.join(root_dir(), path)),
                    mimetype=static_types.get(os.path.splitext(path)[1],
                                              "text/html"))


@app.route("/", methods=["GET", "POST"])
def index():  ## working fine
    """
    index page for WebUI

    Returns:
        rendered HTML page
    """
    from config import nettacker_user_application_config
    filename = nettacker_user_application_config()["report_path_filename"]

    return render_template("index.html", selected_modules=scan_methods(),
                           languages = languages(),
                           graphs=graphs(),
                           filename=filename)


@app.route("/new/scan", methods=["GET", "POST"])
def new_scan(): ## working fine but required improve
    """
    new scan through the API

    Returns:
        a JSON message with scan details if success otherwise a JSON error
    """
    _start_scan_config = {}
    api_key_check(app, flask_request, __language())
    targetValue = get_value(flask_request, "targets")
    # if (target_type(targetValue) == "UNKNOWN"):
    #     return jsonify({"error": "Please input correct target"}), 400
    options = app.config["OWASP_NETTACKER_CONFIG"]["options"]
    for key in vars(app.config["OWASP_NETTACKER_CONFIG"]["options"]):
        #print(key)
        if get_value(flask_request, key) is not None:
            print(escape(get_value(flask_request, key)))
            print(key)
            try:
                options.__dict__[key] = int(str(escape(get_value(flask_request, key))))
            except:
                options.__dict__[key] = str(escape(get_value(flask_request, key)))
    print(options)
    app.config["OWASP_NETTACKER_CONFIG"]["options"] = options
    #       _start_scan_config[key] = escape(get_value(flask_request, key))
    # _start_scan_config["backup_ports"] = get_value(flask_request, "ports")
    # _start_scan_config = rules(remove_non_api_keys(_builder(
    #     _start_scan_config, _builder(_core_config(), _core_default_config()))),
    #     _core_default_config(), __language())
    _p = multiprocessing.Process(target=__scan, args=(app.config["OWASP_NETTACKER_CONFIG"]["options"],))
    _p.start()
    return jsonify(vars(options)), 200


@app.route("/session/check", methods=["GET"])
def session_check():  ## working fine
    """
    check the session if it's valid

    Returns:
        a JSON message if it's valid otherwise abort(401)
    """
    api_key_check(app, flask_request, __language())
    return jsonify(structure(status="ok", msg=messages(
        "browser_session_valid"))), 200


@app.route("/session/set", methods=["GET"])
def session_set():  ## working fine ## todo: mtehod requires to be POST
    """
    set session on the browser

    Returns:
        200 HTTP response if session is valid and a set-cookie in the
        response if success otherwise abort(403)
    """
    api_key_check(app, flask_request, __language())
    res = make_response(
        jsonify(structure(status="ok", msg=messages(
            "browser_session_valid"))))
    res.set_cookie("key", value=app.config[
        "OWASP_NETTACKER_CONFIG"]["api_access_key"])
    return res


@app.route("/session/kill", methods=["GET"])
def session_kill(): ## working fine
    """
    unset session on the browser

    Returns:
        a 200 HTTP response with set-cookie to "expired"
        to unset the cookie on the browser
    """
    res = make_response(
        jsonify(structure(status="ok", msg=messages(
            "browser_session_killed"))))
    res.set_cookie("key", "", expires=0)
    return res


@app.route("/results/get_list", methods=["GET"])
def get_results():  ## WORKING FINE
    """
    get list of scan's results through the API

    Returns:
        an array of JSON scan's results if success otherwise abort(403)
    """
    api_key_check(app, flask_request, __language())
    try:
        page = int(get_value(flask_request, "page"))
    except Exception:
        page = 1
    return jsonify(__select_results(page)), 200


@app.route("/results/get", methods=["GET"])
def get_result_content():  ## todo: working now but improvement for filename
    """
    get a result HTML/TEXT/JSON content

    Returns:
        content of the scan result
    """
    api_key_check(app, flask_request, __language())
    try:
        _id = int(get_value(flask_request, "id"))
    except Exception:
        return jsonify(structure(status="error",
                                 msg="your scan id is not valid!")), 400
    return __get_result(__language(), _id)


@app.route("/results/get_json", methods=["GET"])
def get_results_json():  ##working fine
    """
    get host's logs through the API in JSON type

    Returns:
        an array with JSON events
    """
    session = create_connection()
    api_key_check(app, flask_request, __language())
    try:
        _id = int(get_value(flask_request, "id"))
        scan_id_temp = session.query(Report).filter(Report.id == _id).all()
    except Exception as _:
        _id = ""
        scan_id_temp = False
    if (scan_id_temp):
        result_id = session.query(Report).join(
            HostsLog, Report.scan_unique_id == HostsLog.scan_unique_id).filter(
            Report.scan_unique_id == scan_id_temp[0].scan_unique_id).all()
    else:
        result_id = []
    json_object = {}
    # print(result_id)
    if (result_id):
        scan_unique_id = result_id[0].scan_unique_id
        # print("amanguptss")
        data = __logs_by_scan_id(scan_unique_id)
        json_object = json.dumps(data)
    date_from_db = scan_id_temp[0].date
    #print(date_from_db, type(date_from_db))
    date_format = "aman"
    #date_format = datetime.strptime(str(date_from_db), "%Y-%m-%d %H:%M:%S").date()
    date_format = str(date_format).replace(
        "-", "_").replace(":", "_").replace(" ", "_")
    filename = "report-" + date_format + "".join(
        random.choice(string.ascii_lowercase) for x in range(10))
    #print(json_object)
    return Response(json_object,
                    mimetype='application/json',
                    headers={'Content-Disposition':
                                 'attachment;filename=' + filename + '.json'})


@app.route("/results/get_csv", methods=["GET"])
def get_results_csv():  #todo: need to fix time format
    """
    get host's logs through the API in JSON type

    Returns:
        an array with JSON events
    """
    session = create_connection()
    api_key_check(app, flask_request, __language())
    try:
        _id = int(get_value(flask_request, "id"))
        scan_id_temp = session.query(Report).filter(Report.id == _id).all()
    except Exception as _:
        _id = ""
    if (scan_id_temp):
        result_id = session.query(Report).join(
            HostsLog, Report.scan_unique_id == HostsLog.scan_unique_id).filter(
            Report.scan_unique_id == scan_id_temp[0].scan_unique_id).all()
    else:
        result_id = []
    date_from_db = scan_id_temp[0].date
    date_format = "aman"
    #date_format = datetime.strptime(date_from_db, "%Y-%m-%d %H:%M:%S")
    date_format = str(date_format).replace(
        "-", "_").replace(":", "_").replace(" ", "_")
    filename = "report-" + date_format + "".join(
        random.choice(string.ascii_lowercase) for x in range(10))
    _reader = ''
    if (result_id):
        scan_unique_id = result_id[0].scan_unique_id
        data = __logs_by_scan_id(scan_unique_id)
        keys = data[0].keys()
        with open(filename, "w") as report_path_filename:
            dict_writer = csv.DictWriter(
                report_path_filename, fieldnames=keys, quoting=csv.QUOTE_ALL)
            dict_writer.writeheader()
            for i in data:
                dictdata = {key: value for key, value in i.items()
                            if key in keys}
                dict_writer.writerow(dictdata)
        with open(filename, 'r') as report_path_filename:
            _reader = report_path_filename.read()
    return Response(_reader, mimetype='text/csv',
                    headers={'Content-Disposition':
                                 'attachment;filename=' + filename + '.csv'})


@app.route("/logs/get_list", methods=["GET"])
def get_last_host_logs():  ## working
    """
    get list of logs through the API

    Returns:
        an array of JSON logs if success otherwise abort(403)
    """
    api_key_check(app, flask_request, __language())
    try:
        page = int(get_value(flask_request, "page"))
    except Exception:
        page = 1
    return jsonify(__last_host_logs(__language(), page)), 200


@app.route("/logs/get_html", methods=["GET"])
def get_logs_html():  ## todo: html needs to be added to solve this error
    """
    get host's logs through the API in HTML type

    Returns:
        HTML report
    """
    api_key_check(app, flask_request, __language())
    try:
        host = get_value(flask_request, "host")
    except Exception:
        host = ""
    return make_response(__logs_to_report_html(host, __language()))


@app.route("/logs/get_json", methods=["GET"])
def get_logs():  ## working fine
    """
    get host's logs through the API in JSON type

    Returns:
        an array with JSON events
    """
    api_key_check(app, flask_request, __language())
    try:
        target = get_value(flask_request, "target")
    except Exception:
        target = ""
    data = __logs_to_report_json(target, __language())
    json_object = json.dumps(data)
    filename = "report-" + now(
        model="%Y_%m_%d_%H_%M_%S") + "".join(
        random.choice(string.ascii_lowercase) for x in range(10))
    return Response(json_object, mimetype='application/json',
                    headers={'Content-Disposition':
                                 'attachment;filename=' + filename + '.json'})


@app.route("/logs/get_csv", methods=["GET"])
def get_logs_csv(): ## working fine
    """
    get target's logs through the API in JSON type

    Returns:
        an array with JSON events
    """
    api_key_check(app, flask_request, __language())
    try:
        target = get_value(flask_request, "target")
    except Exception:
        target = ""
    data = __logs_to_report_json(target, __language())
    keys = data[0].keys()
    filename = "report-" + now(
        model="%Y_%m_%d_%H_%M_%S") + "".join(random.choice(
        string.ascii_lowercase) for x in range(10))
    with open(filename, "w") as report_path_filename:
        dict_writer = csv.DictWriter(
            report_path_filename, fieldnames=keys, quoting=csv.QUOTE_ALL)
        dict_writer.writeheader()
        for i in data:
            dictdata = {key: value for key, value in i.items()
                        if key in keys}
            dict_writer.writerow(dictdata)
    with open(filename, 'r') as report_path_filename:
        reader = report_path_filename.read()
    return Response(reader, mimetype='text/csv',
                    headers={'Content-Disposition':
                                 'attachment;filename=' + filename + '.csv'})


@app.route("/logs/search", methods=["GET"])
def go_for_search_logs(): ## working fine
    """
    search in all events

    Returns:
        an array with JSON events
    """
    api_key_check(app, flask_request, __language())
    try:
        page = int(get_value(flask_request, "page"))
    except Exception:
        page = 1
    try:
        query = get_value(flask_request, "q")
    except Exception:
        query = ""
    return jsonify(__search_logs(__language(), page, query)), 200


def start_api_subprocess(options):
    """
    a function to run flask in a subprocess to make kill signal in a better
    way!

    Args:
        options: all options
    """
    print(options)
    app.config["OWASP_NETTACKER_CONFIG"] = {
        "api_access_key": options.api_access_key,
        "api_client_whitelisted_ips": options.api_client_whitelisted_ips,
        "api_access_log": options.api_access_log,
        #"api_access_log_filename": options.api_access_log_filename,
        "api_cert": options.api_cert,
        "api_cert_key": options.api_cert_key,
        "language": options.language,
        "options": options
    }
    if options.api_cert and options.api_cert_key:
        app.run(
            host=options.api_hostname,
            port=options.api_port,
            debug=options.api_debug_mode,
            ssl_context=(
                options.api_cert,
                options.api_cert_key
            ),
            threaded=True
        )
    else:
        app.run(
            host=options.api_hostname,
            port=options.api_port,
            debug=options.api_debug_mode,
            threaded=True
        )


def start_api_server(options):
    """
    entry point to run the API through the flask

    Args:
        options: all options
    """
    # Starting the API
    write_to_api_console(messages("API_key").format(options.api_access_key))
    p = multiprocessing.Process(
        target=start_api_subprocess,
        args=(options,)
    )
    p.start()
    # Sometimes it's take much time to terminate flask with CTRL+C
    # So It's better to use KeyboardInterrupt to terminate!
    while len(multiprocessing.active_children()) != 0:
        try:
            time.sleep(0.3)
        except KeyboardInterrupt:
            for process in multiprocessing.active_children():
                process.terminate()
            break
    die_success()
