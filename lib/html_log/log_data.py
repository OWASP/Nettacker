from nettacker.config import Config

with open(Config.path.web_static_dir / "report/html_table.css") as f:
    css_1 = f.read()

with open(Config.path.web_static_dir / "report/json_parse.js") as f:
    json_parse_js = f.read()

with open(Config.path.web_static_dir / "report/table_end.html") as f:
    table_end = f.read()

with open(Config.path.web_static_dir / "report/table_items.html") as f:
    table_items = f.read()

with open(Config.path.web_static_dir / "report/table_title.html") as f:
    table_title = f.read()