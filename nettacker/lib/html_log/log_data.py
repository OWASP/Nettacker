from nettacker.config import Config

_TEMPLATE_FILES = {
    "css_1": "report/html_table.css",
    "json_parse_js": "report/json_parse.js",
    "table_end": "report/table_end.html",
    "table_items": "report/table_items.html",
    "table_title": "report/table_title.html",
}


def __getattr__(name):
    """Read report templates on first access instead of at import time.

    Reading at import made import order significant: any code that changed
    Config.path.web_static_dir before this module was first imported caused
    the import itself to fail.
    """
    try:
        relative_path = _TEMPLATE_FILES[name]
    except KeyError:
        raise AttributeError(f"module {__name__!r} has no attribute {name!r}") from None

    value = (Config.path.web_static_dir / relative_path).read_text()
    globals()[name] = value
    return value


def __dir__():
    return sorted([*globals(), *_TEMPLATE_FILES])
