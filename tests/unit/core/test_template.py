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
