from pathlib import PurePosixPath, PureWindowsPath
from unittest.mock import patch

from nettacker.core.messages import get_languages


@patch("nettacker.core.messages.Config")
def test_get_languages_returns_bare_sorted_codes(mock_config):
    # Mix Windows and POSIX paths to confirm the separator is not hardcoded.
    paths = [
        PureWindowsPath(r"C:\nettacker\locale\fa.yaml"),
        PureWindowsPath(r"C:\nettacker\locale\en.yaml"),
        PurePosixPath("/opt/nettacker/locale/fr.yaml"),
    ]
    mock_config.path.locale_dir.glob.return_value = paths

    result = get_languages()

    # Bare language codes, sorted and de-duplicated, with no path or extension.
    assert result == ["en", "fa", "fr"]
    for code in result:
        assert "/" not in code
        assert "\\" not in code
        assert "." not in code


@patch("nettacker.core.messages.Config")
def test_get_languages_deduplicates(mock_config):
    mock_config.path.locale_dir.glob.return_value = [
        PurePosixPath("/locale/en.yaml"),
        PurePosixPath("/locale/en.yaml"),
        PurePosixPath("/locale/de.yaml"),
    ]

    assert get_languages() == ["de", "en"]
