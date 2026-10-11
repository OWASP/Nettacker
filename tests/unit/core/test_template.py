import copy
import locale

from nettacker.config import Config
from nettacker.core.template import TemplateLoader


def test_open_reads_non_ascii_content_under_non_utf8_default_encoding(monkeypatch, tmp_path):
    """Proves the explicit encoding="utf-8" in TemplateLoader.open() is load-bearing.

    The module file on disk is genuinely UTF-8 encoded and contains non-ASCII
    content. The environment's default text encoding is mocked to cp1252 (what
    Windows uses by default, and the actual cause of the original bug) via
    locale.getpreferredencoding -- the same fallback Python's open() consults
    when no encoding is given. If encoding="utf-8" were removed from open(),
    this test would fail: either open() raises UnicodeDecodeError trying to
    decode the UTF-8 bytes as cp1252, or the content silently mismatches.
    """
    non_ascii_content = "info:\n  description: café — テスト\npayload:\n"
    action_dir = tmp_path / "scan"
    action_dir.mkdir()
    (action_dir / "unicodemod.yaml").write_text(non_ascii_content, encoding="utf-8")

    monkeypatch.setattr(Config.path, "modules_dir", tmp_path)
    monkeypatch.setattr(locale, "getpreferredencoding", lambda do_setlocale=True: "cp1252")

    result = TemplateLoader("unicodemod_scan").open()

    assert result == non_ascii_content


def test_parse_substitutes_nested_values_from_inputs():
    """Values from module_inputs replace matching keys at any nesting depth."""
    content = {"info": {"author": "original", "name": "keep_me"}, "payload": "x"}

    result = TemplateLoader.parse(copy.deepcopy(content), {"author": "new_author"})

    assert result["info"]["author"] == "new_author"
    assert result["info"]["name"] == "keep_me"


def test_parse_keeps_yaml_value_when_falsy_input():
    """Empty or None inputs must not wipe out values from the YAML template."""
    content = {"description": "original"}

    result = TemplateLoader.parse(content, {"description": ""})

    assert result["description"] == "original"


def test_parse_overrides_timeout_only_when_it_differs_from_default():
    """Timeout is special: only non-default values are substituted."""
    content = {"timeout": 3.0}
    default = Config.settings.timeout

    custom = TemplateLoader.parse(copy.deepcopy(content), {"timeout": default + 10})
    same_as_default = TemplateLoader.parse(copy.deepcopy(content), {"timeout": default})

    assert custom["timeout"] == default + 10
    assert same_as_default["timeout"] == 3.0


def test_parse_recurses_into_lists():
    """List entries containing dicts are parsed recursively."""
    content = [{"target": "yaml_target", "nested": {"port": "yaml_port"}}]

    result = TemplateLoader.parse(content, {"target": "user_target"})

    assert result[0]["target"] == "user_target"
    assert result[0]["nested"]["port"] == "yaml_port"


def test_format_substitutes_placeholders_in_template_file(monkeypatch, tmp_path):
    """format() reads the module YAML and applies str.format(**inputs)."""
    action_dir = tmp_path / "scan"
    action_dir.mkdir()
    (action_dir / "templmod.yaml").write_text(
        "info:\n  description: scan {target_host}\n", encoding="utf-8"
    )
    monkeypatch.setattr(Config.path, "modules_dir", tmp_path)

    loader = TemplateLoader("templmod_scan", inputs={"target_host": "127.0.0.1"})

    assert "scan 127.0.0.1" in loader.format()


def test_load_parses_yaml_and_applies_inputs(monkeypatch, tmp_path):
    """load() chains format() -> yaml.safe_load -> parse()."""
    action_dir = tmp_path / "scan"
    action_dir.mkdir()
    (action_dir / "loadmod.yaml").write_text(
        "info:\n  author: original\n  target: {target_host}\npayload: []\n",
        encoding="utf-8",
    )
    monkeypatch.setattr(Config.path, "modules_dir", tmp_path)

    result = TemplateLoader("loadmod_scan", inputs={"target_host": "10.0.0.1"}).load()

    assert result["info"]["target"] == "10.0.0.1"
    assert result["info"]["author"] == "original"
    assert result["payload"] == []