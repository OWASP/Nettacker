from pathlib import Path
from unittest.mock import patch, MagicMock, mock_open

import pytest
from flask import Flask, Request
from werkzeug.exceptions import NotFound

from nettacker.api.core import (
    api_key_is_valid,
    get_file,
    get_value,
    graphs,
    languages_to_country,
    mime_types,
    profiles,
    scan_methods,
)
from nettacker.config import Config


@pytest.fixture
def app():
    app = Flask(__name__)
    app.config["OWASP_NETTACKER_CONFIG"] = {"api_access_key": "test_key"}
    return app


@pytest.fixture
def request_():
    req = MagicMock(spec=Request)
    req.args = {"key": "test_key"}
    req.form = {}
    req.cookies = {}
    return req


def test_get_value(request_):
    assert get_value(request_, "key") == "test_key"
    assert get_value(request_, "nonexistent") == ""


def test_mime_types():
    mtypes = mime_types()
    assert ".html" in mtypes
    assert mtypes[".html"] == "text/html"


@patch("builtins.open", new_callable=mock_open, read_data="test_data")
def test_get_file_valid(mock_open):
    Config.path.web_static_dir = Path.cwd()
    filename = Config.path.web_static_dir / "test.txt"
    assert get_file(filename) == "test_data"


@patch("builtins.open", side_effect=IOError)
def test_get_file_ioerror(mock_open):
    Config.path.web_static_dir = Path.cwd()
    filename = Config.path.web_static_dir / "test.txt"
    with pytest.raises(NotFound):
        get_file(filename)


@patch("builtins.open", side_effect=ValueError)
def test_get_file_valueerror(mock_open):
    Config.path.web_static_dir = Path.cwd()
    filename = Config.path.web_static_dir / "test.txt"
    with pytest.raises(NotFound):
        get_file(filename)


def test_get_file_outside_web_static_dir():
    Config.path.web_static_dir = Path("/safe/dir").resolve()
    filename = Path("/unauthorized/access.txt").resolve()
    with pytest.raises(NotFound):
        get_file(filename)


def test_api_key_is_valid(app, request_):
    with app.test_request_context():
        api_key_is_valid(app, request_)  # Should not raise


def test_api_key_invalid(app, request_):
    request_.args = {"key": "wrong_key"}
    with pytest.raises(Exception):
        api_key_is_valid(app, request_)


@patch("nettacker.core.app.Nettacker.load_graphs", return_value=["graph1", "graph2"])
def test_graphs(mock_graphs):
    result = graphs()
    assert '<input id="graph1"' in result
    assert '<a class="label label-default">graph2</a>' in result
    assert 'value="graph1"' in result
    assert 'name="graph_name"' in result


@patch("nettacker.core.app.Nettacker.load_graphs", return_value=[])
def test_graphs_empty(mock_graphs):
    result = graphs()
    assert "None</a>" in result


@patch(
    "nettacker.core.app.Nettacker.load_profiles",
    return_value={"scan": {}, "brute": {}, "custom": {}},
)
def test_profiles(mock_profiles):
    result = profiles()
    assert "checkbox-scan" in result
    assert 'label-success">scan</a>' in result
    assert 'label-warning">brute</a>' in result
    assert 'label-default">custom</a>' in result


@patch(
    "nettacker.core.app.Nettacker.load_modules",
    return_value={"ssh_brute": {}, "http_vuln": {}, "tcp_scan": {}, "all": {}},
)
def test_scan_methods(mock_methods):
    result = scan_methods()
    assert "checkbox-scan-module" in result
    assert 'label-success">tcp_scan</a>' in result
    assert "checkbox-brute-module" in result
    assert 'label-warning">ssh_brute</a>' in result
    assert "checkbox-vuln-module" in result
    assert 'label-danger">http_vuln</a>' in result
    assert "all" not in result


@patch("nettacker.core.messages.get_languages", return_value=["en", "fr", "es", "de"])
def test_languages_to_country(mock_langs):
    result = languages_to_country()
    assert "flag-icon-us" in result
    assert "flag-icon-fr" in result
    assert '<option selected id="en"' in result
    assert "flag-icon-es" in result
