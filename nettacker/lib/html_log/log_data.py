from nettacker.config import Config


def _read_static_file(filename):
    """Read a static file from the web static directory."""
    with open(Config.path.web_static_dir / filename) as f:
        return f.read()


css_1 = _read_static_file("report/html_table.css")
json_parse_js = _read_static_file("report/json_parse.js")
table_end = _read_static_file("report/table_end.html")
table_items = _read_static_file("report/table_items.html")
table_title = _read_static_file("report/table_title.html")
