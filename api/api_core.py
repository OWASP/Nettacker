#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import os
from core.load_modules import load_all_modules, load_all_profiles
from core.load_modules import load_all_graphs
from core.alert import messages
from flask import abort


def structure(status="", msg=""):
    """
    basic JSON message structure

    Args:
        status: status (ok, failed)
        msg: the message content

    Returns:
        a JSON message
    """
    return {
        "status": status,
        "msg": msg
    }


def get_value(flask_request, _key):
    """
    get a value from GET, POST or CCOKIES

    Args:
        flask_request: the flask request
        _key: the value name to find

    Returns:
        the value content if found otherwise None
    """
    try:
        key = flask_request.args[_key]
    except:
        try:
            key = flask_request.form[_key]
        except:
            try:
                key = flask_request.cookies[_key]
            except:
                key = None
    if key is not None:
        # fix it later
        key = key.replace("\\\"", "\"").replace("\\\'", "\'")
    return key


def remove_non_api_keys(config):
    """
    a function to remove non-api keys while loading ARGV

    Args:
        config: all keys in JSON

    Returns:
        removed non-api keys in all keys in JSON
    """
    non_api_keys = [
        "start_api_server", "api_host", "api_port", "api_debug_mode", "api_access_key", "api_client_white_list",
        "api_client_white_list_ips", "api_access_log", "api_access_log", "api_access_log_filename", 
        "api_cert", "api_cert_key", "show_version", "check_update", "show_help_menu", "targets_list", 
        "usernames_list", "passwds_list", "excluded_modules"
    ]
    new_config = {}
    for key in config:
        if key not in non_api_keys:
            new_config[key] = config[key]
    return new_config


def is_login(app, flask_request):
    """
    check if session is valid

    Args:
        app: flask app
        flask_request: flask request

    Returns:
        True if session is valid otherwise False
    """
    if app.config["OWASP_NETTACKER_CONFIG"]["api_access_key"] == get_value(flask_request, "key"):
        return True
    return False


def mime_types():
    """
    contains all mime types for HTTP request

    Returns:
        all mime types in json
    """
    return {
        ".aac": "audio/aac",
        ".abw": "application/x-abiword",
        ".arc": "application/octet-stream",
        ".avi": "video/x-msvideo",
        ".azw": "application/vnd.amazon.ebook",
        ".bin": "application/octet-stream",
        ".bz": "application/x-bzip",
        ".bz2": "application/x-bzip2",
        ".csh": "application/x-csh",
        ".css": "text/css",
        ".csv": "text/csv",
        ".doc": "application/msword",
        ".docx": "application/vnd.openxmlformats-officedocument.wordprocessingml.document",
        ".eot": "application/vnd.ms-fontobject",
        ".epub": "application/epub+zip",
        ".gif": "image/gif",
        ".htm": ".htm",
        ".html": "text/html",
        ".ico": "image/x-icon",
        ".ics": "text/calendar",
        ".jar": "application/java-archive",
        ".jpeg": ".jpeg",
        ".jpg": "image/jpeg",
        ".js": "application/javascript",
        ".json": "application/json",
        ".mid": ".mid",
        ".midi": "audio/midi",
        ".mpeg": "video/mpeg",
        ".mpkg": "application/vnd.apple.installer+xml",
        ".odp": "application/vnd.oasis.opendocument.presentation",
        ".ods": "application/vnd.oasis.opendocument.spreadsheet",
        ".odt": "application/vnd.oasis.opendocument.text",
        ".oga": "audio/ogg",
        ".ogv": "video/ogg",
        ".ogx": "application/ogg",
        ".otf": "font/otf",
        ".png": "image/png",
        ".pdf": "application/pdf",
        ".ppt": "application/vnd.ms-powerpoint",
        ".pptx": "application/vnd.openxmlformats-officedocument.presentationml.presentation",
        ".rar": "application/x-rar-compressed",
        ".rtf": "application/rtf",
        ".sh": "application/x-sh",
        ".svg": "image/svg+xml",
        ".swf": "application/x-shockwave-flash",
        ".tar": "application/x-tar",
        ".tif": ".tif",
        ".tiff": "image/tiff",
        ".ts": "application/typescript",
        ".ttf": "font/ttf",
        ".vsd": "application/vnd.visio",
        ".wav": "audio/x-wav",
        ".weba": "audio/webm",
        ".webm": "video/webm",
        ".webp": "image/webp",
        ".woff": "font/woff",
        ".woff2": "font/woff2",
        ".xhtml": "application/xhtml+xml",
        ".xls": "application/vnd.ms-excel",
        ".xlsx": "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet",
        ".xml": "application/xml",
        ".xul": "application/vnd.mozilla.xul+xml",
        ".zip": "application/zip",
        ".3gp": "video/3gpp",
        "audio/3gpp": "video",
        ".3g2": "video/3gpp2",
        "audio/3gpp2": "video",
        ".7z": "application/x-7z-compressed"
    }


def root_dir():
    """
    find the root directory for web static files

    Returns:
        root path for static files
    """
    return os.path.join(os.path.join(os.path.dirname(os.path.dirname(__file__)), "web"), "static")


def get_file(filename):
    """
    open the requested file in HTTP requests

    Args:
        filename: path and the filename

    Returns:
        content of the file or abort(404)
    """
    try:
        src = os.path.join(root_dir(), filename)
        return open(src, 'rb').read()
    except IOError as exc:
        abort(404)


def api_key_check(app, flask_request, language):
    """
    check the validity of API key

    Args:
        app: the flask app
        flask_request: the flask request
        language: language

    Returns:
        200 HTTP code if it's valid otherwise 401 error

    """
    if app.config["OWASP_NETTACKER_CONFIG"]["api_access_key"] != get_value(flask_request, "key"):
        abort(401, messages( "API_invalid"))
    return


def languages():
    """
    define list of languages with country flag for API

    Returns:
        HTML code for each language with its country flag
    """
    from core.load_modules import load_all_languages
    languages = load_all_languages()
    res = ""
    flags = {
        "el": "gr",
        "fr": "fr",
        "en": "us",
        "nl": "nl",
        "ps": "ps",
        "tr": "tr",
        "de": "de",
        "ko": "kr",
        "it": "it",
        "ja": "jp",
        "fa": "ir",
        "hy": "am",
        "ar": "sa",
        "zh-cn": "cn",
        "vi": "vi",
        "ru": "ru",
        "hi": "in",
        "ur": "pk",
        "id": "id",
        "es": "es",
        "iw": "il"
    }
    for lang in languages:
        res += """<option {2} id="{0}" data-content='<span class="flag-icon flag-icon-{1}" value="{0}"></span> {0}'></option>""" \
            .format(lang, flags[lang], "selected" if lang == "en" else "")
    return res


def graphs():
    """
    all available graphs for API

    Returns:
        HTML content or available graphs
    """
    res = """<label><input id="" type="radio" name="graph_name" value="" class="radio"><a
                            class="label label-default">None</a></label>&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;"""
    for graph in load_all_graphs():
        res += """<label><input id="{0}" type="radio" name="graph_name" value="{0}" class="radio"><a
                            class="label label-default">{0}</a></label>&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;""".format(graph)
    return res


def profiles():
    """
    all available profiles for API

    Returns:
        HTML content or available profiles
    """
    #profiles = load_all_profiles()
    for synonym in synonyms:
        del (profiles[synonym])
    res = ""
    for profile in profiles:
        label = "success" if (profile == "scan") else "warning" if (profile == "brute") else "danger" if (profile ==
                                                                                                          "vulnerability") else "default"
        res += """<label><input id="{0}" type="checkbox" class="checkbox checkbox-{0}"><a class="label 
            label-{1}">{0}</a></label>&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;""".format(profile, label)
    return res


def scan_methods():
    """
    all available modules for API

    Returns:
        HTML content or available modules
    """
    methods = load_all_modules()
    methods.pop("all")
    res = ""
    for sm in methods.keys():
        label = "success" if sm.endswith("_scan") else "warning" if sm.endswith("_brute") else "danger" if sm.endswith(
            "_vuln") else "default"
        profile = "scan" if sm.endswith("_scan") else "brute" if sm.endswith("_brute") else "vuln" if sm.endswith(
            "_vuln") else "default"
        res += """<label><input id="{0}" type="checkbox" class="checkbox checkbox-{2}-module">
        <a class="label label-{1}">{0}</a></label>&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;""".format(sm, label, profile)
    return res


def rules(config, defaults, language):
    """
    Load ARGS from API requests and apply the rules

    Args:
        config: all user config
        defaults: default config
        language: language

    Returns:
        config with applied rules
    """
    # Check Ranges
    config["scan_ip_range"] = True if config[
                                         "scan_ip_range"] is not False else False
    # Check Subdomains
    config["scan_subdomains"] = True if config[
                                             "scan_subdomains"] is not False else False
    # Check Graph
    config["graph_name"] = config["graph_name"] if config[
                                                       "graph_name"] in load_all_graphs() else None
    # Check Language
    config["language"] = config["language"] if config[
                                                   "language"] in [lang for lang in messages(-1, 0)] else "en"
    # Check Targets
    if config["targets"] is not None:
        config["targets"] = list(set(config["targets"].rsplit(",")))
    else:
        abort(400, messages( "error_target"))
    # Check Log File
    try:
        f = open(config["report_path_filename"], "a")
        f.close()
    except:
        abort(400, messages( "file_write_error").format(
            config["report_path_filename"]))

    # Check Passwords
    config["passwords"] = config["passwords"].rsplit(
        ',') if config["passwords"] is not None else None
    # Check Ping Before Scan
    config["ping_before_scan"] = True if config["ping_before_scan"] is not False else False
    # Check Ports
    ports = config["ports"]
    if type(ports) is not list and ports is not None:
        tmp_ports = []
        for port in ports.rsplit(','):
            try:
                if '-' not in port:
                    if int(port) not in tmp_ports:
                        tmp_ports.append(int(port))
                else:
                    t_ports = range(
                        int(port.rsplit('-')[0]), int(port.rsplit('-')[1]) + 1)
                    for p in t_ports:
                        if p not in tmp_ports:
                            tmp_ports.append(p)
            except:
                abort(400, messages( "ports_int"))
        if len(tmp_ports) == 0:
            ports = None
        else:
            ports = tmp_ports[:]
    config["ports"] = ports
    # Check Profiles
    if config["profile"] is not None:
        _all_profiles = _builder(_profiles(), default_profiles())
        synonyms = _synonym_profile().keys()
        for synonym in synonyms:
            del (_all_profiles[synonym])
        if config["selected_modules"] is None:
            config["selected_modules"] = ""
        else:
            config["selected_modules"] += ","
        if "all" in config["profile"].rsplit(","):
            config["profile"] = ",".join(_all_profiles)
        tmp_sm = config["selected_modules"]
        for pr in config["profile"].rsplit(","):
            try:
                for sm in _all_profiles[pr]:
                    if sm not in tmp_sm.rsplit(","):
                        tmp_sm += sm + ","
            except:
                abort(400, messages( "profile_404").format(pr))
        if tmp_sm[-1] == ",":
            tmp_sm = tmp_sm[0:-1]
        config["selected_modules"] = ",".join(list(set(tmp_sm.rsplit(","))))
    # Check retries
    try:
        config["retries"] = int(config["retries"])
    except:
        config["retries"] = defaults["retries"]
    # Check Scanning Method
    if config["selected_modules"] is not None and "all" in config["selected_modules"].rsplit(","):
        config["selected_modules"] = load_all_modules()
        config["selected_modules"].remove("all")
    elif config["selected_modules"] is not None and len(config["selected_modules"].rsplit(",")) == 1 and "*_" not in config[
        "selected_modules"]:
        if config["selected_modules"] in load_all_modules():
            config["selected_modules"] = config["selected_modules"].rsplit()
        else:
            abort(400, messages( "scan_module_not_found").format(
                config["selected_modules"]))
    else:
        if config["selected_modules"] is not None:
            if config["selected_modules"] not in load_all_modules():
                if "*_" in config["selected_modules"] or "," in config["selected_modules"]:
                    config["selected_modules"] = config["selected_modules"].rsplit(",")
                    scan_method_tmp = config["selected_modules"][:]
                    for sm in scan_method_tmp:
                        scan_method_error = True
                        if sm.startswith("*_"):
                            config["selected_modules"].remove(sm)
                            found_flag = False
                            for mn in load_all_modules():
                                if mn.endswith("_" + sm.rsplit("*_")[1]):
                                    config["selected_modules"].append(mn)
                                    scan_method_error = False
                                    found_flag = True
                            if found_flag is False:
                                abort(400, messages(
                                    "module_pattern_404").format(sm))
                        elif sm == "all":
                            config["selected_modules"] = load_all_modules()
                            scan_method_error = False
                            config["selected_modules"].remove("all")
                            break
                        elif sm in load_all_modules():
                            scan_method_error = False
                        elif sm not in load_all_modules():
                            abort(400, messages(
                                "scan_module_not_found").format(sm))
                else:
                    scan_method_error = True
            if scan_method_error:
                abort(400, messages( "scan_module_not_found").format(
                    config["selected_modules"]))
        else:
            abort(400, messages( "scan_method_select"))
        config["selected_modules"] = list(set(config["selected_modules"]))

    # Check Socks Proxy
    socks_proxy = config["socks_proxy"]
    if socks_proxy is not None:
        e = False
        if socks_proxy.startswith("socks://"):
            socks_flag = 5
            socks_proxy = socks_proxy.replace("socks://", "")
        elif socks_proxy.startswith("socks5://"):
            socks_flag = 5
            socks_proxy = socks_proxy.replace("socks5://", "")
        elif socks_proxy.startswith("socks4://"):
            socks_flag = 4
            socks_proxy = socks_proxy.replace("socks4://", "")
        else:
            socks_flag = 5
        if "://" in socks_proxy:
            socks_proxy = socks_proxy.rsplit("://")[1].rsplit("/")[0]
        try:
            if len(socks_proxy.rsplit(":")) < 2 or len(socks_proxy.rsplit(":")) > 3:
                e = True
            elif len(socks_proxy.rsplit(":")) == 2 and socks_proxy.rsplit(":")[1] == "":
                e = True
            elif len(socks_proxy.rsplit(":")) == 3 and socks_proxy.rsplit(":")[2] == "":
                e = True
        except:
            e = True
        if e:
            abort(400, messages( "valid_socks_address"))
        if socks_flag == 4:
            socks_proxy = "socks4://" + socks_proxy
        if socks_flag == 5:
            socks_proxy = "socks5://" + socks_proxy
    config["socks_proxy"] = socks_proxy
    # Check thread numbers
    try:
        config["thread_per_host"] = int(config["thread_per_host"])
    except:
        config["thread_per_host"] = defaults["thread_per_host"]
    # Check thread number for hosts
    try:
        config["parallel_host_scan"] = int(config["parallel_host_scan"])
    except:
        config["parallel_host_scan"] = defaults["parallel_host_scan"]
    # Check time sleep
    try:
        config["time_sleep_between_requests"] = float(config["time_sleep_between_requests"])
    except:
        config["time_sleep_between_requests"] = defaults["time_sleep_between_requests"]
    # Check timeout sec
    try:
        config["timeout_sec"] = int(config["timeout_sec"])
    except:
        config["parallel_host_scan"] = defaults["parallel_host_scan"]
    # Check usernames
    config["usernames"] = config["usernames"].rsplit(
        ',') if config["usernames"] is not None else None
    return config
