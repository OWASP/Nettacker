#!/usr/bin/env python
# -*- coding: utf-8 -*-

import os
from core.load_modules import load_all_modules
from core.load_modules import load_all_graphs
from core.alert import messages
from core.config_builder import default_profiles
from core.config import _profiles, _synonym_profile
from core.config_builder import _builder
from flask import abort


def __structure(status="", msg=""):
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


def __get_value(flask_request, _key):
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


def __remove_non_api_keys(config):
    """
    a function to remove non-api keys while loading ARGV

    Args:
        config: all keys in JSON

    Returns:
        removed non-api keys in all keys in JSON
    """
    non_api_keys = ["start_api", "api_host", "api_port", "api_debug_mode", "api_access_key", "api_client_white_list",
                    "api_client_white_list_ips", "api_access_log", "api_access_log", "api_access_log_filename",
                    "show_version", "check_update", "help_menu_flag", "targets_list", "users_list", "passwds_list",
                    "method_args_list", "startup_check_for_update", "wizard_mode", "exclude_method"]
    new_config = {}
    for key in config:
        if key not in non_api_keys:
            new_config[key] = config[key]
    return new_config


def __is_login(app, flask_request):
    """
    check if session is valid

    Args:
        app: flask app
        flask_request: flask request

    Returns:
        True if session is valid otherwise False
    """
    if app.config["OWASP_NETTACKER_CONFIG"]["api_access_key"] == __get_value(flask_request, "key"):
        return True
    return False


def __mime_types():
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


def __api_key_check(app, flask_request, language):
    """
    check the validity of API key

    Args:
        app: the flask app
        flask_request: the flask request
        language: language

    Returns:
        200 HTTP code if it's valid otherwise 401 error

    """
    if app.config["OWASP_NETTACKER_CONFIG"]["api_access_key"] != __get_value(flask_request, "key"):
        abort(401, messages(language, "API_invalid"))
    return


def __languages():
    """
    define list of languages with country flag for API

    Returns:
        HTML code for each language with its country flag
    """
    languages = [lang for lang in messages(-1, 0)]
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


def __graphs():
    """
    all available graphs for API

    Returns:
        HTML content or available graphs
    """
    res = """<label><input id="" type="radio" name="graph_flag" value="" class="radio"><a
                            class="label label-default">None</a></label>&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;"""
    for graph in load_all_graphs():
        res += """<label><input id="{0}" type="radio" name="graph_flag" value="{0}" class="radio"><a
                            class="label label-default">{0}</a></label>&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;""".format(graph)
    return res


def __profiles():
    """
    all available profiles for API

    Returns:
        HTML content or available profiles
    """
    profiles = _builder(_profiles(), default_profiles())
    synonyms = _synonym_profile().keys()
    for synonym in synonyms:
        del (profiles[synonym])
    res = ""
    for profile in profiles:
        label = "success" if (profile == "scan") else "warning" if (profile == "brute") else "danger" if (profile ==
                                                                                                          "vulnerability") else "default"
        res += """<label><input id="{0}" type="checkbox" class="checkbox checkbox-{0}"><a class="label 
            label-{1}">{0}</a></label>&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;""".format(profile, label)
    return res


def __scan_methods():
    """
    all available modules for API

    Returns:
        HTML content or available modules
    """
    methods = load_all_modules()
    methods.remove("all")
    res = ""
    for sm in methods:
        label = "success" if sm.endswith("_scan") else "warning" if sm.endswith("_brute") else "danger" if sm.endswith(
            "_vuln") else "default"
        profile = "scan" if sm.endswith("_scan") else "brute" if sm.endswith("_brute") else "vuln" if sm.endswith(
            "_vuln") else "default"
        res += """<label><input id="{0}" type="checkbox" class="checkbox checkbox-{2}-module">
        <a class="label label-{1}">{0}</a></label>&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;""".format(sm, label, profile)
    return res


def __rules(config, defaults, language):
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
    config["check_ranges"] = True if config[
                                         "check_ranges"] is not False else False
    # Check Subdomains
    config["check_subdomains"] = True if config[
                                             "check_subdomains"] is not False else False
    # Check Graph
    config["graph_flag"] = config["graph_flag"] if config[
                                                       "graph_flag"] in load_all_graphs() else None
    # Check Language
    config["language"] = config["language"] if config[
                                                   "language"] in [lang for lang in messages(-1, 0)] else "en"
    # Check Targets
    if config["targets"] is not None:
        config["targets"] = list(set(config["targets"].rsplit(",")))
    else:
        abort(400, messages(language, "error_target"))
    # Check Log File
    try:
        f = open(config["log_in_file"], "a")
        f.close()
    except:
        abort(400, messages(language, "file_write_error").format(
            config["log_in_file"]))
    # Check Method ARGS
    methods_args = config["methods_args"]
    if methods_args is not None:
        new_methods_args = {}
        methods_args = methods_args.rsplit("&")
        for imethod_args in methods_args:
            if len(imethod_args.rsplit("=")) is 2:
                new_methods_args[imethod_args.rsplit("=")[0]] = imethod_args.rsplit("=")[
                    1].rsplit(",")
            else:
                new_methods_args[imethod_args] = ["True"]
        methods_args = new_methods_args
    config["methods_args"] = methods_args

    # Check Passwords
    config["passwds"] = config["passwds"].rsplit(
        ',') if config["passwds"] is not None else None
    # Check Ping Before Scan
    config["ping_flag"] = True if config["ping_flag"] is not False else False
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
                abort(400, messages(language, "ports_int"))
        if len(tmp_ports) is 0:
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
        if config["scan_method"] is None:
            config["scan_method"] = ""
        else:
            config["scan_method"] += ","
        if "all" in config["profile"].rsplit(","):
            config["profile"] = ",".join(_all_profiles)
        tmp_sm = config["scan_method"]
        for pr in config["profile"].rsplit(","):
            try:
                for sm in _all_profiles[pr]:
                    if sm not in tmp_sm.rsplit(","):
                        tmp_sm += sm + ","
            except:
                abort(400, messages(language, "profile_404").format(pr))
        if tmp_sm[-1] == ",":
            tmp_sm = tmp_sm[0:-1]
        config["scan_method"] = ",".join(list(set(tmp_sm.rsplit(","))))
    # Check retries
    try:
        config["retries"] = int(config["retries"])
    except:
        config["retries"] = defaults["retries"]
    # Check Scanning Method
    if config["scan_method"] is not None and "all" in config["scan_method"].rsplit(","):
        config["scan_method"] = load_all_modules()
        config["scan_method"].remove("all")
    elif config["scan_method"] is not None and len(config["scan_method"].rsplit(",")) is 1 and "*_" not in config[
        "scan_method"]:
        if config["scan_method"] in load_all_modules():
            config["scan_method"] = config["scan_method"].rsplit()
        else:
            abort(400, messages(language, "scan_module_not_found").format(
                config["scan_method"]))
    else:
        if config["scan_method"] is not None:
            if config["scan_method"] not in load_all_modules():
                if "*_" in config["scan_method"] or "," in config["scan_method"]:
                    config["scan_method"] = config["scan_method"].rsplit(",")
                    scan_method_tmp = config["scan_method"][:]
                    for sm in scan_method_tmp:
                        scan_method_error = True
                        if sm.startswith("*_"):
                            config["scan_method"].remove(sm)
                            found_flag = False
                            for mn in load_all_modules():
                                if mn.endswith("_" + sm.rsplit("*_")[1]):
                                    config["scan_method"].append(mn)
                                    scan_method_error = False
                                    found_flag = True
                            if found_flag is False:
                                abort(400, messages(
                                    language, "module_pattern_404").format(sm))
                        elif sm == "all":
                            config["scan_method"] = load_all_modules()
                            scan_method_error = False
                            config["scan_method"].remove("all")
                            break
                        elif sm in load_all_modules():
                            scan_method_error = False
                        elif sm not in load_all_modules():
                            abort(400, messages(
                                language, "scan_module_not_found").format(sm))
                else:
                    scan_method_error = True
            if scan_method_error:
                abort(400, messages(language, "scan_module_not_found").format(
                    config["scan_method"]))
        else:
            abort(400, messages(language, "scan_method_select"))
        config["scan_method"] = list(set(config["scan_method"]))

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
            elif len(socks_proxy.rsplit(":")) is 2 and socks_proxy.rsplit(":")[1] == "":
                e = True
            elif len(socks_proxy.rsplit(":")) is 3 and socks_proxy.rsplit(":")[2] == "":
                e = True
        except:
            e = True
        if e:
            abort(400, messages(language, "valid_socks_address"))
        if socks_flag is 4:
            socks_proxy = "socks4://" + socks_proxy
        if socks_flag is 5:
            socks_proxy = "socks5://" + socks_proxy
    config["socks_proxy"] = socks_proxy
    # Check thread numbers
    try:
        config["thread_number"] = int(config["thread_number"])
    except:
        config["thread_number"] = defaults["thread_number"]
    # Check thread number for hosts
    try:
        config["thread_number_host"] = int(config["thread_number_host"])
    except:
        config["thread_number_host"] = defaults["thread_number_host"]
    # Check time sleep
    try:
        config["time_sleep"] = float(config["time_sleep"])
    except:
        config["time_sleep"] = defaults["time_sleep"]
    # Check timeout sec
    try:
        config["timeout_sec"] = int(config["timeout_sec"])
    except:
        config["thread_number_host"] = defaults["thread_number_host"]
    # Check users
    config["users"] = config["users"].rsplit(
        ',') if config["users"] is not None else None
    return config
