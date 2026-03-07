from pathlib import Path

from nettacker.config import Config


def read_static_text(path: Path) -> str:
    return path.read_text(encoding="utf-8")


css_1 = read_static_text(Config.path.web_static_dir / "report/html_table.css")
json_parse_js = read_static_text(Config.path.web_static_dir / "report/json_parse.js")
table_end = read_static_text(Config.path.web_static_dir / "report/table_end.html")
table_items = read_static_text(Config.path.web_static_dir / "report/table_items.html")
table_title = read_static_text(Config.path.web_static_dir / "report/table_title.html")
