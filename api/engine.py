# !/usr/bin/env python
# -*- coding: utf-8 -*-

import multiprocessing
import time
import json
import os
import copy
from flask import Flask
from flask import jsonify
from flask import request as flask_request
from flask import render_template
from flask import abort
from flask import Response
from flasgger import Swagger
from flask import make_response
from core.alert import write_to_api_console
from core.alert import messages
from core.die import die_success, die_failure
from core.time import now
from api.api_core import structure
from api.api_core import get_file
from api.api_core import mime_types
from api.api_core import scan_methods
from api.api_core import profiles
from api.api_core import graphs
from api.api_core import languages_to_country
from api.api_core import api_key_is_valid
from config import nettacker_global_config
from core.args_loader import check_all_required
from core.scan_targers import start_scan_processes
from types import SimpleNamespace

app = Flask(
    __name__,
    template_folder=nettacker_global_config()['nettacker_paths']['web_static_files_path']
)
app.config.from_object(__name__)
nettacker_application_config = nettacker_global_config()['nettacker_user_application_config']
nettacker_application_config.update(nettacker_global_config()['nettacker_api_config'])
del nettacker_application_config['api_access_key']


@app.errorhandler(400)
def error_400(error):
    """
    handle the 400 HTTP error

    Args:
        error: the flask error

    Returns:
        400 JSON error
    """
    return jsonify(
        structure(
            status="error",
            msg=error.description
        )
    ), 400


@app.errorhandler(401)
def error_401(error):
    """
    handle the 401 HTTP error

    Args:
        error: the flask error

    Returns:
        401 JSON error
    """
    return jsonify(
        structure(
            status="error",
            msg=error.description
        )
    ), 401


@app.errorhandler(403)
def error_403(error):
    """
    handle the 403 HTTP error

    Args:
        error: the flask error

    Returns:
        403 JSON error
    """
    return jsonify(
        structure(
            status="error",
            msg=error.description
        )
    ), 403


@app.errorhandler(404)
def error_404(error):
    """
    handle the 404 HTTP error

    Args:
        error: the flask error

    Returns:
        404 JSON error
    """
    return jsonify(
        structure(
            status="error",
            msg=messages("not_found")
        )
    ), 404


@app.before_request
def limit_remote_addr():
    """
    check if IP filtering applied and API address is in whitelist

    Returns:
        None if it's in whitelist otherwise abort(403)
    """
    # IP Limitation
    if app.config["OWASP_NETTACKER_CONFIG"]["api_client_whitelisted_ips"]:
        if flask_request.remote_addr not in app.config["OWASP_NETTACKER_CONFIG"]["api_client_whitelisted_ips"]:
            abort(403, messages("unauthorized_IP"))
    if not (
            flask_request.path.startswith("/cookie") or
            flask_request.path == "/" or
            flask_request.path.startswith("/css/") or
            flask_request.path.startswith("/js/") or
            flask_request.path.startswith("/fonts/") or
            flask_request.path.startswith("/img/") or
            flask_request.path == "/favicon.ico"
    ):
        api_key_is_valid(app, flask_request)
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
        log_request = open(
            app.config["OWASP_NETTACKER_CONFIG"]["api_access_log"],
            "ab"
        )
        log_request.write(
            "{0} [{1}] {2} \"{3} {4}\" {5} {6} {7}\r\n".format(
                flask_request.remote_addr,
                now(),
                flask_request.host,
                flask_request.method,
                flask_request.full_path,
                flask_request.user_agent,
                response.status_code,
                json.dumps(flask_request.form)
            ).encode()
        )
        log_request.close()
    return response


@app.route("/<path:path>", methods=["GET"])
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
        get_file(
            os.path.join(
                nettacker_global_config()['nettacker_paths']['web_static_files_path'],
                path
            )
        ),
        mimetype=static_types.get(
            os.path.splitext(path)[1],
            "text/html"
        )
    )


@app.route("/", methods=["GET", "POST"])
def index():
    """
    index page for WebUI

    Returns:
        rendered HTML page
    """
    from config import nettacker_user_application_config
    filename = nettacker_user_application_config()["report_path_filename"]
    return render_template(
        "index.html",
        selected_modules=scan_methods(),
        profile=profiles(),
        languages=languages_to_country(),
        graphs=graphs(),
        filename=filename
    )


@app.route("/cookie/set", methods=["POST", "GET"])
def set_cookie():
    """
    Set cookie on browser or any library uses session.
    ---
    parameters:
        -   name: api_key
            in: formData
            type: string
            required: true
            default: ""
    definitions:
        api_key:
            type: string
    responses:
        200:
            description: The API key is valid
        401:
            description: The API key is invalid
    """
    res = make_response(
        jsonify(
            structure(
                status="ok",
                msg=messages("browser_session_valid")
            )
        )
    )
    res.set_cookie("api_key", value=api_key_is_valid(app, flask_request))
    return res


@app.route("/cookie/check", methods=["GET", "POST"])
def cookie_check():
    """
    Check cookie on browser or any library uses session.
    ---
    parameters:
        -   name: api_key
            in: formData
            type: string
            required: true
            default: ""
    definitions:
        api_key:
            type: string
    responses:
        200:
            description: The API key is valid
        401:
            description: The API key is invalid
    """
    api_key_is_valid(app, flask_request)
    return jsonify(
        structure(
            status="ok",
            msg=messages("browser_session_valid")
        )
    ), 200


@app.route("/cookie", methods=["DELETE"])
def cookie_delete():
    """
    Delete cookie on browser or any library uses session.
    ---
    responses:
        200:
            description: The API key is valid
        401:
            description: The API key is invalid
    """
    res = make_response(
        jsonify(
            structure(
                status="ok",
                msg=messages("browser_session_killed")
            )
        )
    )
    res.set_cookie("api_key", "")
    return res


@app.route("/scan/new", methods=["POST"])
def new_scan():
    """
    start a new scan
    ---
    parameters:
        -   name: language
            in: formData
            type: string
            required: false
            default: "en"
        -   name: graph_name
            in: formData
            type: string
            required: false
            default: "d3_tree_v2_graph"
        -   name: targets
            in: formData
            type: string
            required: true
            default: ""
        -   name: selected_modules
            in: formData
            type: string
            required: false
            default: ""
        -   name: excluded_modules
            in: formData
            type: string
            required: false
            default: ""
        -   name: profile
            in: formData
            type: string
            required: false
            default: ""
        -   name: usernames
            in: formData
            type: string
            required: false
            default: ""
        -   name: passwords
            in: formData
            type: string
            required: false
            default: ""
        -   name: ports
            in: formData
            type: string
            required: false
            default: ""
        -   name: timeout
            in: formData
            type: float
            required: false
            default: 3.0
        -   name: time_sleep_between_requests
            in: formData
            type: float
            required: false
            default: 0.0
        -   name: scan_ip_range
            in: formData
            type: boolean
            required: false
            default: false
        -   name: scan_subdomains
            in: formData
            type: boolean
            required: false
            default: false
        -   name: skip_service_discovery
            in: formData
            type: boolean
            required: false
            default: false
        -   name: thread_per_host
            in: formData
            type: integer
            required: false
            default: 100
        -   name: parallel_module_scan
            in: formData
            type: integer
            required: false
            default: 1
        -   name: socks_proxy
            in: formData
            type: string
            required: false
            default: ""
        -   name: retries
            in: formData
            type: integer
            required: false
            default: 1
        -   name: ping_before_scan
            in: formData
            type: boolean
            required: false
            default: false
        -   name: set_hardware_usage
            in: formData
            type: boolean
            required: false
            default: false
        -   name: hardware_usage
            in: formData
            type: string
            required: false
            default: "maximum"
        -   name: user_agent
            in: formData
            type: string
            required: false
            default: ""
        -   name: modules_extra_args
            in: formData
            type: string
            required: false
            default: ""
    definitions:
        language:
            type: string
        graph_name:
            type: string
        targets:
            type: string
        selected_modules:
            type: string
        excluded_modules:
            type: string
        profile:
            type: string
        usernames:
            type: string
        passwords:
            type: string
        ports:
            type: string
        timeout:
            type: float
        time_sleep_between_requests:
            type: float
        scan_ip_range:
            type: boolean
        scan_subdomains:
            type: boolean
        skip_service_discovery:
            type: boolean
        thread_per_host:
            type: integer
        parallel_module_scan:
            type: integer
        socks_proxy:
            type: string
        retries:
            type: integer
        ping_before_scan:
            type: boolean
        set_hardware_usage:
            type: boolean
        hardware_usage:
            type: string
        user_agent:
            type: string
        modules_extra_args:
            type: string
    responses:
        201:
            description: Scan started
        400:
            description: Missing arguments
        401:
            description: The API key is invalid

    """
    api_key_is_valid(app, flask_request)
    form_values = dict(flask_request.form)
    for key in nettacker_application_config:
        if key not in form_values:
            form_values[key] = nettacker_application_config[key]
    options = check_all_required(
        None,
        api_forms=SimpleNamespace(**copy.deepcopy(form_values))
    )
    if type(options) == list:
        return jsonify(
            structure(
                status="error",
                msg=", ".join(options)
            )
        ), 400
    app.config["OWASP_NETTACKER_CONFIG"]["options"] = options
    new_process = multiprocessing.Process(target=start_scan_processes, args=(options,))
    new_process.start()
    return jsonify(
        vars(
            options
        )
    ), 201


# todo: develop below api endpoints
# start new scan
# list of scans
# get scan
# stop scan
# delete scan (stop if it's running)
# restart scan
# download scan report json
# download scan report csv
# download scan report html
# get assets
# delete assets
# generate assets report json
# generate assets report csv
# generate assets report html
# delete assets
# get events
# generate events report json
# generate events report csv
# generate events report html
# delete events

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
        "options": options
    }
    app.config["SWAGGER"] = {
        "title": "OWASP Nettacker API"
    }
    Swagger(app)

    try:
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
                ssl_context='adhoc',
                threaded=True
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
    write_to_api_console(
        messages("API_key").format(
            options.api_port,
            options.api_access_key
        )
    )
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
