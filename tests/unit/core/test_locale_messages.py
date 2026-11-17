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
