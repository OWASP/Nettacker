import os
from unittest.mock import mock_open, patch, MagicMock

import pytest
from flask import Flask
from werkzeug.exceptions import NotFound, Unauthorized

from nettacker.api.core import (
    get_value,
    mime_types,
    get_file,
    api_key_is_valid,
    languages_to_country,
    graphs,
    profiles,
    scan_methods,
)
from nettacker.config import Config
from nettacker.core.app import Nettacker

TEST_API_KEY = "test_key"
TEST_FILE_CONTENT = b"test content"
TEST_FILE_NAME = "test.txt"


@pytest.fixture
def app():
    """Fixture providing configured Flask app for testing."""
    test_app = Flask(__name__)
    test_app.config["OWASP_NETTACKER_CONFIG"] = {"api_access_key": TEST_API_KEY}
    return test_app


@pytest.fixture
def mock_request():
    """Fixture providing mock Flask request with empty parameters."""
    mock = MagicMock()
    mock.args = {}
    mock.form = {}
    mock.cookies = {}
    return mock


def test_get_value_retrieves_from_args_when_present(mock_request):
    """Test that get_value retrieves value from args when present."""
    expected_value = "args_value"
    mock_request.args = {"test_key": expected_value}

    result = get_value(mock_request, "test_key")

    assert result == expected_value


def test_get_value_retrieves_from_form_when_args_empty(mock_request):
    """Test that get_value retrieves value from form when args is empty."""
    expected_value = "form_value"
    mock_request.form = {"test_key": expected_value}

    result = get_value(mock_request, "test_key")

    assert result == expected_value


def test_get_value_retrieves_from_cookies_when_others_empty(mock_request):
    """Test that get_value retrieves value from cookies when args and form are empty."""
    expected_value = "cookie_value"
    mock_request.cookies = {"test_key": expected_value}

    result = get_value(mock_request, "test_key")

    assert result == expected_value


def test_get_value_returns_empty_when_key_not_found(mock_request):
    """Test that get_value returns empty string when key is not found."""
    result = get_value(mock_request, "nonexistent_key")

    assert result == ""


def test_get_value_respects_source_precedence(mock_request):
    """Test that get_value respects precedence: args > form > cookies."""
    mock_request.args = {"test_key": "args_value"}
    mock_request.form = {"test_key": "form_value"}
    mock_request.cookies = {"test_key": "cookie_value"}

    result = get_value(mock_request, "test_key")

    assert result == "args_value"


def test_mime_types_returns_correct_mappings():
    """Test that mime_types returns correct content type mappings."""
    mime_dict = mime_types()

    assert isinstance(mime_dict, dict)

    assert mime_dict[".pdf"] == "application/pdf"
    assert mime_dict[".jpg"] == "image/jpeg"
    assert mime_dict[".html"] == "text/html"

    assert len(mime_dict) > 50


def test_get_file_returns_content_for_valid_path():
    """Test that get_file returns file content for valid path."""
    Config.path.web_static_dir = "/test/path"
    test_file_path = os.path.join(str(Config.path.web_static_dir), TEST_FILE_NAME)

    with patch("builtins.open", mock_open(read_data=TEST_FILE_CONTENT)) as mock_file:
        content = get_file(test_file_path)

        mock_file.assert_called_once_with(test_file_path, "rb")
        assert content == TEST_FILE_CONTENT


def test_get_file_raises_404_for_invalid_path():
    """Test that get_file raises 404 for paths outside web static directory."""
    Config.path.web_static_dir = "/test/path"

    with pytest.raises(NotFound):
        get_file("/invalid/path/test.txt")


def test_get_file_raises_404_for_io_error():
    """Test that get_file raises 404 when IOError occurs."""
    Config.path.web_static_dir = "/test/path"
    test_file_path = os.path.join(str(Config.path.web_static_dir), TEST_FILE_NAME)

    with patch("builtins.open", mock_open()) as mock_file:
        mock_file.side_effect = IOError()

        with pytest.raises(NotFound):
            get_file(test_file_path)


def test_get_file_raises_404_for_value_error():
    """Test that get_file raises 404 when ValueError occurs."""
    Config.path.web_static_dir = "/test/path"
    test_file_path = os.path.join(str(Config.path.web_static_dir), TEST_FILE_NAME)

    with patch("builtins.open", mock_open()) as mock_file:
        mock_file.side_effect = ValueError()

        with pytest.raises(NotFound):
            get_file(test_file_path)


def test_api_key_valid_accepts_correct_key(app, mock_request):
    """Test that api_key_is_valid accepts correct API key."""
    mock_request.args = {"key": TEST_API_KEY}

    result = api_key_is_valid(app, mock_request)

    assert result is None


def test_api_key_valid_raises_401_for_invalid_key(app, mock_request):
    """Test that api_key_is_valid raises 401 for incorrect API key."""
    mock_request.args = {"key": "wrong_key"}

    with pytest.raises(Unauthorized):
        api_key_is_valid(app, mock_request)


@patch("nettacker.api.core.get_languages")
def test_languages_to_country_generates_correct_html(mock_get_languages):
    """Test that languages_to_country generates correct HTML with flags."""
    test_languages = ["en", "es", "fr"]
    mock_get_languages.return_value = test_languages

    result = languages_to_country()

    assert isinstance(result, str)

    expected_flags = {"en": "us", "es": "es", "fr": "fr"}
    for lang, flag in expected_flags.items():
        assert f"flag-icon-{flag}" in result
        assert f'value="{lang}"' in result

    assert "selected" in result and 'value="en"' in result


@patch.object(Nettacker, "load_graphs")
def test_graphs_generates_correct_html(mock_load_graphs):
    """Test that graphs generates correct HTML with all graph options."""
    test_graphs = ["d3_tree", "d3_force"]
    mock_load_graphs.return_value = test_graphs

    result = graphs()

    assert isinstance(result, str)

    assert 'value=""' in result
    assert "None" in result

    for graph in test_graphs:
        assert f'value="{graph}"' in result
        assert 'class="radio"' in result


@patch.object(Nettacker, "load_profiles")
def test_profiles_generates_correct_html(mock_load_profiles):
    """Test that profiles generates correct HTML with appropriate styling."""
    test_profiles = {"scan": {}, "brute": {}, "vulnerability": {}}
    mock_load_profiles.return_value = test_profiles

    result = profiles()

    assert isinstance(result, str)

    style_map = {"scan": "success", "brute": "warning", "vulnerability": "danger"}

    for profile, style in style_map.items():
        assert f'class="checkbox checkbox-{profile}"' in result
        assert f'label label-{style}"' in result
        assert profile in result


@patch.object(Nettacker, "load_modules")
def test_scan_methods_generates_correct_html(mock_load_modules):
    """Test that scan_methods generates correct HTML with appropriate styling."""
    test_modules = {"all": {}, "port_scan": {}, "ssh_brute": {}, "wp_vuln": {}}
    mock_load_modules.return_value = test_modules

    result = scan_methods()

    assert isinstance(result, str)

    assert "all" not in result

    assert "port_scan" in result
    assert "label-success" in result
    assert "ssh_brute" in result
    assert "label-warning" in result
    assert "wp_vuln" in result
    assert "label-danger" in result
