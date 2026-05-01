from pathlib import Path

from nettacker.config import Config

css_1 = (Config.path.web_static_dir / "report/html_table.css").read_text()
json_parse_js = (Config.path.web_static_dir / "report/json_parse.js").read_text()
table_end = (Config.path.web_static_dir / "report/table_end.html").read_text()
table_items = (Config.path.web_static_dir / "report/table_items.html").read_text()
table_title = (Config.path.web_static_dir / "report/table_title.html").read_text()
