import string

import pytest
import yaml

from nettacker.config import Config

LOCALE_FILES = sorted(Config.path.locale_dir.glob("*.yaml"))


def load_locale(path):
    return yaml.safe_load(path.read_text(encoding="utf-8"))


@pytest.mark.parametrize("locale_file", LOCALE_FILES, ids=lambda path: path.stem)
def test_api_key_message_shows_access_key(locale_file):
    """API_key is formatted as (api_port, api_access_key) in nettacker/api/engine.py."""
    message = load_locale(locale_file).get("API_key")
    if message is None:
        pytest.skip("API_key not translated, falls back to English")

    rendered = message.format(5000, "test-access-key-1234")

    assert "test-access-key-1234" in rendered


@pytest.mark.parametrize("locale_file", LOCALE_FILES, ids=lambda path: path.stem)
def test_messages_are_valid_format_strings(locale_file):
    """Messages are rendered with str.format(), so a typo like "{1}}" or a translated
    placeholder name like "{code}" crashes Nettacker when that language is selected."""
    formatter = string.Formatter()
    used_keys = load_locale(Config.path.locale_dir / "en.yaml").keys()
    for key, message in load_locale(locale_file).items():
        if key not in used_keys:
            continue  # obsolete key, never rendered
        try:
            fields = [field for _, field, _, _ in formatter.parse(str(message)) if field]
        except ValueError as error:
            pytest.fail(f"{key}: {error}")
        named = [field for field in fields if not field.isdigit()]
        assert not named, f"{key}: unexpected placeholder(s) {named}"
