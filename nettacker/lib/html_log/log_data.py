from nettacker.config import Config


def _read_file(path):
    with open(path) as f:
        return f.read()


css_1 = _read_file(Config.path.web_static_dir / "report/html_table.css")
json_parse_js = _read_file(Config.path.web_static_dir / "report/json_parse.js")
table_end = _read_file(Config.path.web_static_dir / "report/table_end.html")
table_items = _read_file(Config.path.web_static_dir / "report/table_items.html")
table_title = _read_file(Config.path.web_static_dir / "report/table_title.html")
