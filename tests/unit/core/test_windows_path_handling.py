from pathlib import PureWindowsPath
from unittest.mock import MagicMock

from nettacker.config import Config
from nettacker.core import arg_parser, messages
from nettacker.core.arg_parser import ArgParser


def test_load_graphs_extracts_name_from_windows_style_path(monkeypatch):
    """graph_library.parent.name must correctly parse a backslash-separated path,
    not just avoid crashing -- the old str(...).split("/") code raised IndexError here."""
    windows_path = PureWindowsPath(r"C:\nettacker\nettacker\lib\graph\d3_tree_v1\engine.py")
    fake_graph_dir = MagicMock()
    fake_graph_dir.glob.return_value = [windows_path]
    monkeypatch.setattr(Config.path, "graph_dir", fake_graph_dir)

    assert ArgParser.load_graphs() == ["d3_tree_v1_graph"]


def test_load_languages_extracts_stem_from_windows_style_path(monkeypatch):
    """language.stem must correctly extract "en" from a backslash-separated path."""
    windows_path = PureWindowsPath(r"C:\nettacker\nettacker\locale\en.yaml")
    fake_locale_dir = MagicMock()
    fake_locale_dir.glob.return_value = [windows_path]
    monkeypatch.setattr(Config.path, "locale_dir", fake_locale_dir)

    assert ArgParser.load_languages() == ["en"]


def test_load_modules_extracts_library_and_category_from_windows_style_path(monkeypatch):
    """module_name.stem / .parent.name must correctly split a backslash-separated path
    into library ("port") and category ("scan") -- the old code raised IndexError
    on category since str(path).split("/") never finds a separator."""
    windows_path = PureWindowsPath(r"C:\nettacker\nettacker\modules\scan\port.yaml")
    fake_modules_dir = MagicMock()
    fake_modules_dir.glob.return_value = [windows_path]
    monkeypatch.setattr(Config.path, "modules_dir", fake_modules_dir)
    monkeypatch.setattr(
        arg_parser.TemplateLoader,
        "open",
        lambda self: "info:\n  severity: 1\n  description: test\npayload:\n",
    )

    result = ArgParser.load_modules(full_details=True)

    assert result["port_scan"] == {"severity": 1, "description": "test"}


def test_get_languages_extracts_stem_from_windows_style_path(monkeypatch):
    """The duplicate implementation in messages.py (caught by self-review, separate
    from arg_parser.py's load_languages) must also correctly parse backslash paths."""
    windows_path = PureWindowsPath(r"C:\nettacker\nettacker\locale\en.yaml")
    fake_locale_dir = MagicMock()
    fake_locale_dir.glob.return_value = [windows_path]
    monkeypatch.setattr(Config.path, "locale_dir", fake_locale_dir)

    assert messages.get_languages() == ["en"]
