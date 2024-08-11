from nettacker.config import Config

css_1 = open(Config.path.web_static_dir / "report/html_table.css").read()
json_parse_js = open(Config.path.web_static_dir / "report/json_parse.js").read()
table_end = open(Config.path.web_static_dir / "report/table_end.html").read()
table_items = open(Config.path.web_static_dir / "report/table_items.html").read()
table_title = open(Config.path.web_static_dir / "report/table_title.html").read()
