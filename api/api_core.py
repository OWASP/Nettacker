#!/usr/bin/env python
# -*- coding: utf-8 -*-

import os
from core.load_modules import load_all_modules
from core.load_modules import load_all_graphs
from core.alert import messages
from core.config_builder import default_profiles
from core.config import _profiles
from core.config_builder import _builder
from flask import abort


def __structure(status="", msg=""):
    return {
        "status": status,
        "msg": msg
    }


def __get_value(flask_request, _key):
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
    return key


def __remove_non_api_keys(config):
    non_api_keys = ["start_api", "api_host", "api_port", "api_debug_mode", "api_access_key", "api_client_white_list",
                    "api_client_white_list_ips", "api_access_log", "api_access_log", "api_access_log_filename",
                    "show_version", "check_update", "help_menu_flag", "targets_list", "users_list", "passwds_list",
                    "method_args_list", "startup_check_for_update", "wizard_mode", "exclude_method"]
    new_config = {}
    for key in config:
        if key not in non_api_keys:
            new_config[key] = config[key]
    return new_config


def __mime_types():
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
    return os.path.join(os.path.join(os.path.dirname(os.path.dirname(__file__)), "web"), "static")


def get_file(filename):
    try:
        src = os.path.join(root_dir(), filename)
        return open(src, 'rb').read()
    except IOError as exc:
        abort(404)


def __api_key_check(app, flask_request, language):
    if app.config["OWASP_NETTACKER_CONFIG"]["api_access_key"] != __get_value(flask_request, "key"):
        abort(401, messages(language, 160))


def __method_args_list(language):
    return load_all_method_args(language, API=True)


def __languages():
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
        "es": "es"
    }
    for lang in languages:
        res += """<option {2} data-content='<span class="flag-icon flag-icon-{1}"></span> {0}'></option>""" \
            .format(lang, flags[lang], "selected" if lang == "en" else "")
    return res


def __graphs():
    res = ""
    for graph in load_all_graphs():
        res += """<label><input id="{0}" type="radio" class="radio"><a
                            class="label label-default">{0}</a></label>&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;""".format(graph)
    return res


def __profiles():
    profiles = _builder(_profiles(), default_profiles())
    res = ""
    for profile in profiles:
        res += """<label><input id="{0}" type="checkbox" class="checkbox"><a class="label 
        label-primary">{0}</a></label>&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;""".format(profile)
    return res


def __scan_methods():
    methods = load_all_modules()
    methods.remove("all")
    res = ""
    for sm in methods:
        label = "success" if sm.endswith("_scan") else "warning" if sm.endswith("_brute") else "danger" if sm.endswith(
            "_vuln") else "default"
        res += """<label><input type="checkbox" class="checkbox">
        <a class="label label-{1}">{0}</a></label>&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;""".format(sm, label)
    return res


def __rules(config, defaults, language):
    # Check Ranges
    config["check_ranges"] = True if config["check_ranges"] is not False else False
    # Check Subdomains
    config["check_subdomains"] = True if config["check_subdomains"] is not False else False
    # Check Graph
    config["graph_flag"] = config["graph_flag"] if config["graph_flag"] in load_all_graphs() else None
    # Check Language
    config["language"] = config["language"] if config["language"] in [lang for lang in messages(-1, 0)] else "en"
    # Check Targets
    if config["targets"] is not None:
        config["targets"] = list(set(config["targets"].rsplit(",")))
    else:
        abort(400, messages(language, 26))
    # Check Log File
    try:
        f = open(config["log_in_file"], "a")
        f.close()
    except:
        abort(400, messages(language, 40).format(config["log_in_file"]))
    # Check Method ARGS
    methods_args = config["methods_args"]
    if methods_args is not None:
        new_methods_args = {}
        methods_args = methods_args.rsplit("&")
        for imethod_args in methods_args:
            if len(imethod_args.rsplit("=")) is 2:
                new_methods_args[imethod_args.rsplit("=")[0]] = imethod_args.rsplit("=")[1].rsplit(",")
            else:
                new_methods_args[imethod_args.rsplit("=")[0]] = ""
        methods_args = new_methods_args
    config["methods_args"] = methods_args

    # Check Passwords
    config["passwds"] = config["passwds"].rsplit(',') if config["passwds"] is not None else None
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
                    t_ports = range(int(port.rsplit('-')[0]), int(port.rsplit('-')[1]) + 1)
                    for p in t_ports:
                        if p not in tmp_ports:
                            tmp_ports.append(p)
            except:
                abort(400, messages(language, 157))
        if len(tmp_ports) is 0:
            ports = None
        else:
            ports = tmp_ports[:]
    config["ports"] = ports
    # Check Profiles
    config["profile"] = config["profile"].rsplit(',') if config["profile"] is not None else None
    if config["profile"] is not None:
        if config["scan_method"] is None:
            config["scan_method"] = ""
        else:
            config["scan_method"] += ","
        if config["profile"][0] == "all":
            config["profile"] = ",".join(_builder(_profiles(), default_profiles()))
        tmp_sm = config["scan_method"]
        for pr in config["profile"]:
            try:
                for sm in _builder(_profiles(), default_profiles())[pr]:
                    if sm not in tmp_sm.rsplit(","):
                        tmp_sm += sm + ","
            except:
                abort(400, messages(language, 137).format(pr))
        if tmp_sm[-1] == ",":
            tmp_sm = tmp_sm[0:-1]
        config["scan_method"] = ",".join(list(set(tmp_sm.rsplit(","))))
    # Check retries
    try:
        config["retries"] = int(config["retries"])
    except:
        config["retries"] = defaults["retries"]
    # Check Scanning Method
    config["scan_method"] = config["scan_method"].rsplit(',') if config["scan_method"] is not None else None
    if config["scan_method"] is None:
        abort(400, messages(language, 41))
    else:
        if "all" in config["scan_method"]:
            config["scan_method"] = load_all_modules()
            config["scan_method"].remove("all")
        else:
            methods = config["scan_method"][:]
            for sm in methods:
                if sm not in load_all_modules():
                    abort(400, messages(language, 30).format(sm))
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
            abort(400, messages(language, 63))
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
    config["users"] = config["users"].rsplit(',') if config["users"] is not None else None
    return config
