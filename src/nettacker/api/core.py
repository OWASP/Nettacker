import os

from flask import abort

from nettacker.config import Config
from nettacker.core.app import Nettacker
from nettacker.core.messages import messages as _
from nettacker.core.messages import get_languages


def get_value(flask_request, key):
    """
    get a value from GET, POST or COOKIES

    Args:
        flask_request: the flask request
        key: the value name to find

    Returns:
        the value content if found otherwise None
    """
    return (
        dict(flask_request.args).get(key)
        or dict(flask_request.form).get(key)
        or dict(flask_request.cookies).get(key)
        or ""
    )


def mime_types():
    """
    contains all mime types for HTTP request

    Returns:
        all mime types in json
    """
    return {
        ".3g2": "video/3gpp2",
        ".3gp": "video/3gpp",
        ".7z": "application/x-7z-compressed",
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
        ".pdf": "application/pdf",
        ".png": "image/png",
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
        ".txt": "text/plain",
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
        "audio/3gpp": "video",
        "audio/3gpp2": "video",
    }


def get_file(filename):
    """
    open the requested file in HTTP requests

    Args:
        filename: path and the filename

    Returns:
        content of the file or abort(404)
    """
    if not os.path.normpath(filename).startswith(str(Config.path.web_static_dir)):
        abort(404)
    try:
        return open(filename, "rb").read()
    except ValueError:
        abort(404)
    except IOError:
        abort(404)


def api_key_is_valid(app, flask_request):
    """
    check the validity of API key

    Args:
        app: the flask app
        flask_request: the flask request

    Returns:
        200 HTTP code if it's valid otherwise 401 error

    """
    if app.config["OWASP_NETTACKER_CONFIG"]["api_access_key"] != get_value(flask_request, "key"):
        abort(401, _("API_invalid"))
    return


def languages_to_country():
    """
    define list of languages with country flag for API

    Returns:
        HTML code for each language with its country flag
    """
    languages = get_languages()
    res = ""
    flags = {
        "ar": "sa",
        "bn": "in",
        "de": "de",
        "el": "gr",
        "en": "us",
        "es": "es",
        "fa": "ir",
        "fr": "fr",
        "hi": "in",
        "hy": "am",
        "id": "id",
        "it": "it",
        "iw": "il",
        "ja": "jp",
        "ko": "kr",
        "nl": "nl",
        "ps": "ps",
        "pt-br": "br",
        "ru": "ru",
        "tr": "tr",
        "ur": "pk",
        "vi": "vi",
        "zh-cn": "cn",
    }
    for language in languages:
        res += """<option {2} id="{0}" data-content='<span class="flag-icon flag-icon-{1}"
        value="{0}"></span> {0}'></option>""".format(
            language, flags[language], "selected" if language == "en" else ""
        )
    return res


def graphs():
    """
    all available graphs for API

    Returns:
        HTML content or available graphs
    """
    res = """
        <label><input id="" type="radio" name="graph_name" value="" class="radio">
        <a class="label label-default">None</a></label>&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;"""
    for graph in Nettacker.load_graphs():
        res += """
            <label><input id="{0}" type="radio" name="graph_name" value="{0}" class="radio">
            <a class="label label-default">{0}</a></label>&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;""".format(
            graph
        )
    return res


def profiles():
    """
    all available profiles for API

    Returns:
        HTML content or available profiles
    """
    res = ""
    for profile in sorted(Nettacker.load_profiles().keys()):
        label = (
            "success"
            if (profile == "scan")
            else "warning"
            if (profile == "brute")
            else "danger"
            if (profile == "vulnerability")
            else "default"
        )
        res += """
            <label><input id="{0}" type="checkbox" class="checkbox checkbox-{0}">
            <a class="label label-{1}">{0}</a></label>&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;""".format(
            profile, label
        )
    return res


def scan_methods():
    """
    all available modules for API

    Returns:
        HTML content or available modules
    """
    methods = Nettacker.load_modules()
    methods.pop("all")
    res = ""
    for sm in methods.keys():
        label = (
            "success"
            if sm.endswith("_scan")
            else "warning"
            if sm.endswith("_brute")
            else "danger"
            if sm.endswith("_vuln")
            else "default"
        )
        profile = (
            "scan"
            if sm.endswith("_scan")
            else "brute"
            if sm.endswith("_brute")
            else "vuln"
            if sm.endswith("_vuln")
            else "default"
        )
        res += """<label><input id="{0}" type="checkbox" class="checkbox checkbox-{2}-module">
        <a class="label label-{1}">{0}</a></label>&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;""".format(
            sm, label, profile
        )
    return res
