from pathlib import Path
from unittest.mock import MagicMock, mock_open, patch

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


def test_get_file_valid(tmp_path, monkeypatch):
    static = tmp_path / "static"
    static.mkdir()
    f = static / "test.txt"
    f.write_bytes(b"test_data")
    monkeypatch.setattr(Config.path, "web_static_dir", static)
    assert get_file(str(f)) == b"test_data"


def test_get_file_traversal_rejected(tmp_path, monkeypatch):
    static = tmp_path / "static"
    static.mkdir()
    outside = tmp_path / "secret.txt"
    outside.write_text("secret")
    monkeypatch.setattr(Config.path, "web_static_dir", static)
    with pytest.raises(NotFound):
        get_file(str(static / ".." / "secret.txt"))


def test_get_file_sibling_prefix_rejected(tmp_path, monkeypatch):
    static = tmp_path / "static"
    static.mkdir()
    sibling = tmp_path / "static_evil.txt"
    sibling.write_text("evil")
    monkeypatch.setattr(Config.path, "web_static_dir", static)
    with pytest.raises(NotFound):
        get_file(str(static / ".." / "static_evil.txt"))


def test_get_file_nonexistent_rejected(tmp_path, monkeypatch):
    static = tmp_path / "static"
    static.mkdir()
    monkeypatch.setattr(Config.path, "web_static_dir", static)
    with pytest.raises(NotFound):
        get_file(str(static / "missing.txt"))


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
