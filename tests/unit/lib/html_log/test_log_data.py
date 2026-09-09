import importlib
import sys
from pathlib import Path

import pytest

from nettacker.config import Config

MODULE = "nettacker.lib.html_log.log_data"


def _reimport(monkeypatch, static_dir):
    monkeypatch.setattr(Config.path, "web_static_dir", static_dir)
    monkeypatch.delitem(sys.modules, MODULE, raising=False)
    return importlib.import_module(MODULE)


def test_import_does_not_read_files(monkeypatch):
    """Importing must not touch the filesystem.

    Reading templates at import time made import order significant: any
    earlier code that changed web_static_dir broke this import (#1721).
    """
    _reimport(monkeypatch, Path("/nonexistent/nettacker-1721"))


def test_templates_are_read_from_current_static_dir(monkeypatch, tmp_path):
    report_dir = tmp_path / "report"
    report_dir.mkdir()
    (report_dir / "html_table.css").write_text("/*css*/")
    (report_dir / "json_parse.js").write_text("/*js*/")
    (report_dir / "table_end.html").write_text("</table>")
    (report_dir / "table_items.html").write_text("<tr></tr>")
    (report_dir / "table_title.html").write_text("<table>")

    log_data = _reimport(monkeypatch, tmp_path)

    assert log_data.css_1 == "/*css*/"
    assert log_data.json_parse_js == "/*js*/"
    assert log_data.table_end == "</table>"
    assert log_data.table_items == "<tr></tr>"
    assert log_data.table_title == "<table>"


def test_unknown_attribute_raises_attribute_error(monkeypatch, tmp_path):
    log_data = _reimport(monkeypatch, tmp_path)

    with pytest.raises(AttributeError):
        _ = log_data.not_a_template
