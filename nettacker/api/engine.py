import csv
import json
import multiprocessing
import os
import random
import string
import time
from threading import Thread
from types import SimpleNamespace

from flask import Flask, jsonify
from flask import request as flask_request
from flask import render_template, abort, Response, make_response

from nettacker import logger
from nettacker.api.core import (
    get_value,
    get_file,
    mime_types,
    scan_methods,
    profiles,
    graphs,
    languages_to_country,
    api_key_is_valid,
)
from nettacker.api.helpers import structure
from nettacker.config import Config
from nettacker.core.app import Nettacker
from nettacker.core.die import die_failure
from nettacker.core.graph import create_compare_report
from nettacker.core.messages import messages as _
from nettacker.core.utils.common import now, generate_compare_filepath
from nettacker.database.db import (
    create_connection,
    get_logs_by_scan_id,
    select_reports,
    get_scan_result,
    last_host_logs,
    logs_to_report_json,
    search_logs,
    logs_to_report_html,
)
from nettacker.database.models import Report

log = logger.get_logger()

app = Flask(__name__, template_folder=str(Config.path.web_static_dir))
app.config.from_object(__name__)

nettacker_application_config = Config.settings.as_dict()
nettacker_application_config.update(Config.api.as_dict())
del nettacker_application_config["api_access_key"]


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
    return jsonify(structure(status="error", msg=_("not_found"))), 404


@app.before_request
def limit_remote_addr():
    """
    check if IP filtering applied and API address is in whitelist

    Returns:
        None if it's in whitelist otherwise abort(403)
    """
    # IP Limitation
    if app.config["OWASP_NETTACKER_CONFIG"]["api_client_whitelisted_ips"]:
        if (
            flask_request.remote_addr
            not in app.config["OWASP_NETTACKER_CONFIG"]["api_client_whitelisted_ips"]
        ):
            abort(403, _("unauthorized_IP"))
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
        log_request = open(app.config["OWASP_NETTACKER_CONFIG"]["api_access_log"], "ab")
        log_request.write(
            '{0} [{1}] {2} "{3} {4}" {5} {6} {7}\r\n'.format(
                flask_request.remote_addr,
                now(),
                flask_request.host,
                flask_request.method,
                flask_request.full_path,
                flask_request.user_agent,
                response.status_code,
                json.dumps(flask_request.form),
            ).encode()
        )
        log_request.close()
    return response


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
    return Response(
        get_file(os.path.join(Config.path.web_static_dir, path)),
        mimetype=static_types.get(os.path.splitext(path)[1], "text/html"),
    )


@app.route("/", methods=["GET", "POST"])
def index():
    """
    index page for WebUI

    Returns:
        rendered HTML page
    """
    return render_template(
        "index.html",
        selected_modules=scan_methods(),
        profile=profiles(),
        languages=languages_to_country(),
        graphs=graphs(),
        filename=Config.settings.report_path_filename,
    )


@app.route("/new/scan", methods=["GET", "POST"])
def new_scan():
    """
    new scan through the API

    Returns:
        a JSON message with scan details if success otherwise a JSON error
    """
    api_key_is_valid(app, flask_request)
    form_values = dict(flask_request.form)
    for key in nettacker_application_config:
        if key not in form_values:
            form_values[key] = nettacker_application_config[key]

    nettacker_app = Nettacker(api_arguments=SimpleNamespace(**form_values))
    app.config["OWASP_NETTACKER_CONFIG"]["options"] = nettacker_app.arguments
    thread = Thread(target=nettacker_app.run)
    thread.start()

    return jsonify(vars(nettacker_app.arguments)), 200


@app.route("/compare/scans", methods=["POST"])
def compare_scans():
    """
    compare two scans through the API
    Returns:
        Success if the comparision is successfull and report is saved and error if not.
    """
    api_key_is_valid(app, flask_request)

    scan_id_first = get_value(flask_request, "scan_id_first")
    scan_id_second = get_value(flask_request, "scan_id_second")
    if not scan_id_first or not scan_id_second:
        return jsonify(structure(status="error", msg="Invalid Scan IDs")), 400

    compare_report_path_filename = get_value(flask_request, "compare_report_path")
    if not compare_report_path_filename:
        compare_report_path_filename = generate_compare_filepath(scan_id_first)

    compare_options = {
        "scan_compare_id": scan_id_second,
        "compare_report_path_filename": compare_report_path_filename,
    }

    try:
        result = create_compare_report(compare_options, scan_id_first)
        if result:
            return jsonify(
                structure(
                    status="success",
                    msg="scan_comparison_completed",
                )
            ), 200
        return jsonify(structure(status="error", msg="Scan ID not found")), 404
    except (FileNotFoundError, PermissionError, IOError):
        return jsonify(structure(status="error", msg="Invalid file path")), 400


@app.route("/session/check", methods=["GET"])
def session_check():
    """
    check the session if it's valid

    Returns:
        a JSON message if it's valid otherwise abort(401)
    """
    api_key_is_valid(app, flask_request)
    return jsonify(structure(status="ok", msg=_("browser_session_valid"))), 200


@app.route("/session/set", methods=["GET", "POST"])
def session_set():
    """
    set session on the browser

    Returns:
        200 HTTP response if session is valid and a set-cookie in the
        response if success otherwise abort(403)
    """
    api_key_is_valid(app, flask_request)
    res = make_response(jsonify(structure(status="ok", msg=_("browser_session_valid"))))
    res.set_cookie("key", value=app.config["OWASP_NETTACKER_CONFIG"]["api_access_key"])
    return res


@app.route("/session/kill", methods=["GET"])
def session_kill():
    """
    unset session on the browser

    Returns:
        a 200 HTTP response with set-cookie to "expired"
        to unset the cookie on the browser
    """
    res = make_response(jsonify(structure(status="ok", msg=_("browser_session_killed"))))
    res.set_cookie("key", "", expires=0)
    return res


@app.route("/results/get_list", methods=["GET"])
def get_results():
    """
    get list of scan's results through the API

    Returns:
        an array of JSON scan's results if success otherwise abort(403)
    """
    api_key_is_valid(app, flask_request)
    page = get_value(flask_request, "page")
    if not page:
        page = 1
    return jsonify(select_reports(int(page))), 200


@app.route("/results/get", methods=["GET"])
def get_result_content():
    """
    get a result HTML/TEXT/JSON content

    Returns:
        content of the scan result
    """
    api_key_is_valid(app, flask_request)
    scan_id = get_value(flask_request, "id")
    if not scan_id:
        return jsonify(structure(status="error", msg=_("invalid_scan_id"))), 400

    try:
        filename, file_content = get_scan_result(scan_id)
    except Exception:
        return jsonify(structure(status="error", msg="database error!")), 500

    return Response(
        file_content,
        mimetype=mime_types().get(os.path.splitext(filename)[1], "text/plain"),
        headers={"Content-Disposition": "attachment;filename=" + filename.split("/")[-1]},
    )


@app.route("/results/get_json", methods=["GET"])
def get_results_json():
    """
    get host's logs through the API in JSON type

    Returns:
        an array with JSON events
    """
    api_key_is_valid(app, flask_request)
    session = create_connection()
    result_id = get_value(flask_request, "id")
    if not result_id:
        return jsonify(structure(status="error", msg=_("invalid_scan_id"))), 400
    scan_details = session.query(Report).filter(Report.id == result_id).first()
    json_object = json.dumps(get_logs_by_scan_id(scan_details.scan_unique_id))
    filename = ".".join(scan_details.report_path_filename.split(".")[:-1])[1:] + ".json"
    return Response(
        json_object,
        mimetype="application/json",
        headers={"Content-Disposition": "attachment;filename=" + filename},
    )


@app.route("/results/get_csv", methods=["GET"])
def get_results_csv():  # todo: need to fix time format
    """
    get host's logs through the API in JSON type

    Returns:
        an array with JSON events
    """
    api_key_is_valid(app, flask_request)
    session = create_connection()
    result_id = get_value(flask_request, "id")
    if not result_id:
        return jsonify(structure(status="error", msg=_("invalid_scan_id"))), 400
    scan_details = session.query(Report).filter(Report.id == result_id).first()
    data = get_logs_by_scan_id(scan_details.scan_unique_id)
    keys = data[0].keys()
    filename = ".".join(scan_details.report_path_filename.split(".")[:-1])[1:] + ".csv"
    with open(filename, "w") as report_path_filename:
        dict_writer = csv.DictWriter(report_path_filename, fieldnames=keys, quoting=csv.QUOTE_ALL)
        dict_writer.writeheader()
        for event in data:
            dict_writer.writerow({key: value for key, value in event.items() if key in keys})
    with open(filename, "r") as report_path_filename:
        reader = report_path_filename.read()
    return Response(
        reader,
        mimetype="text/csv",
        headers={"Content-Disposition": "attachment;filename=" + filename},
    )


@app.route("/logs/get_list", methods=["GET"])
def get_last_host_logs():  # need to check
    """
    get list of logs through the API

    Returns:
        an array of JSON logs if success otherwise abort(403)
    """
    api_key_is_valid(app, flask_request)
    page = get_value(flask_request, "page")
    if not page:
        page = 1
    return jsonify(last_host_logs(int(page))), 200


@app.route("/logs/get_html", methods=["GET"])
def get_logs_html():  # todo: check until here - ali
    """
    get host's logs through the API in HTML type

    Returns:
        HTML report
    """
    api_key_is_valid(app, flask_request)
    target = get_value(flask_request, "target")
    return make_response(logs_to_report_html(target))


@app.route("/logs/get_json", methods=["GET"])
def get_logs():
    """
    get host's logs through the API in JSON type

    Returns:
        an array with JSON events
    """
    api_key_is_valid(app, flask_request)
    target = get_value(flask_request, "target")
    data = logs_to_report_json(target)
    json_object = json.dumps(data)
    filename = (
        "report-"
        + now(format="%Y_%m_%d_%H_%M_%S")
        + "".join(random.choice(string.ascii_lowercase) for _ in range(10))
    )
    return Response(
        json_object,
        mimetype="application/json",
        headers={"Content-Disposition": "attachment;filename=" + filename + ".json"},
    )


@app.route("/logs/get_csv", methods=["GET"])
def get_logs_csv():
    """
    get target's logs through the API in JSON type

    Returns:
        an array with JSON events
    """
    api_key_is_valid(app, flask_request)
    target = get_value(flask_request, "target")
    data = logs_to_report_json(target)
    keys = data[0].keys()
    filename = (
        "report-"
        + now(format="%Y_%m_%d_%H_%M_%S")
        + "".join(random.choice(string.ascii_lowercase) for _ in range(10))
    )
    with open(filename, "w") as report_path_filename:
        dict_writer = csv.DictWriter(report_path_filename, fieldnames=keys, quoting=csv.QUOTE_ALL)
        dict_writer.writeheader()
        for event in data:
            dict_writer.writerow({key: value for key, value in event.items() if key in keys})
    with open(filename, "r") as report_path_filename:
        reader = report_path_filename.read()
    return Response(
        reader,
        mimetype="text/csv",
        headers={"Content-Disposition": f"attachment;filename={filename}.csv"},
    )


@app.route("/logs/search", methods=["GET"])
def go_for_search_logs():
    """
    search in all events

    Returns:
        an array with JSON events
    """
    api_key_is_valid(app, flask_request)
    try:
        page = int(get_value(flask_request, "page"))
        if page > 0:
            page -= 1
    except Exception:
        page = 0
    try:
        query = get_value(flask_request, "q")
    except Exception:
        query = ""
    return jsonify(search_logs(page, query)), 200


def start_api_subprocess(options):
    """
    a function to run flask in a subprocess to make kill signal in a better
    way!

    Args:
        options: all options
    """
    app.config["OWASP_NETTACKER_CONFIG"] = {
        "api_access_key": options.api_access_key,
        "api_client_whitelisted_ips": options.api_client_whitelisted_ips,
        "api_access_log": options.api_access_log,
        "api_cert": options.api_cert,
        "api_cert_key": options.api_cert_key,
        "language": options.language,
        "options": options,
    }
    try:
        if options.api_cert and options.api_cert_key:
            app.run(
                host=options.api_hostname,
                port=options.api_port,
                debug=options.api_debug_mode,
                ssl_context=(options.api_cert, options.api_cert_key),
                threaded=True,
            )
        else:
            app.run(
                host=options.api_hostname,
                port=options.api_port,
                debug=options.api_debug_mode,
                ssl_context="adhoc",
                threaded=True,
            )
    except Exception as e:
        die_failure(str(e))


def start_api_server(options):
    """
    entry point to run the API through the flask

    Args:
        options: all options
    """
    # Starting the API
    log.write_to_api_console(_("API_key").format(options.api_port, options.api_access_key))
    p = multiprocessing.Process(target=start_api_subprocess, args=(options,))
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
