import os
from unittest.mock import patch, MagicMock, mock_open

from flask import Flask, Request
from werkzeug.exceptions import NotFound

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
from tests.common import TestCase


class TestCore(TestCase):
    def setUp(self):
        self.app = Flask(__name__)
        self.app.config["OWASP_NETTACKER_CONFIG"] = {"api_access_key": "test_key"}
        self.request = MagicMock(spec=Request)
        self.request.args = {"key": "test_key"}
        self.request.form = {}
        self.request.cookies = {}

    def test_get_value(self):
        self.assertEqual(get_value(self.request, "key"), "test_key")
        self.assertEqual(get_value(self.request, "nonexistent"), "")

    def test_mime_types(self):
        mtypes = mime_types()
        self.assertIn(".html", mtypes)
        self.assertEqual(mtypes[".html"], "text/html")

    @patch("builtins.open", new_callable=mock_open, read_data="test_data")
    def test_get_file_valid(self, mock_open):
        Config.path.web_static_dir = os.getcwd()
        filename = os.path.join(Config.path.web_static_dir, "test.txt")
        self.assertEqual(get_file(filename), "test_data")

    @patch("builtins.open", side_effect=IOError)
    def test_get_file_ioerror(self, mock_open):
        Config.path.web_static_dir = os.getcwd()
        filename = os.path.join(Config.path.web_static_dir, "test.txt")
        with self.assertRaises(NotFound):
            get_file(filename)

    @patch("builtins.open", side_effect=ValueError)
    def test_get_file_valueerror(self, mock_open):
        Config.path.web_static_dir = os.getcwd()
        filename = os.path.join(Config.path.web_static_dir, "test.txt")
        with self.assertRaises(NotFound):
            get_file(filename)

    def test_get_file_outside_web_static_dir(self):
        Config.path.web_static_dir = os.path.abspath("/safe/dir")
        filename = os.path.abspath("/unauthorized/access.txt")
        with self.assertRaises(NotFound):
            get_file(filename)

    def test_api_key_is_valid(self):
        with self.app.test_request_context():
            api_key_is_valid(self.app, self.request)

    def test_api_key_invalid(self):
        self.request.args = {"key": "wrong_key"}
        with self.assertRaises(Exception):
            api_key_is_valid(self.app, self.request)

    @patch("nettacker.core.app.Nettacker.load_graphs", return_value=["graph1", "graph2"])
    def test_graphs(self, mock_graphs):
        result = graphs()
        self.assertIn('<input id="graph1"', result)
        self.assertIn('<a class="label label-default">graph2</a>', result)
        self.assertIn('value="graph1"', result)
        self.assertIn('name="graph_name"', result)

    @patch("nettacker.core.app.Nettacker.load_graphs", return_value=[])
    def test_graphs_empty(self, mock_graphs):
        result = graphs()
        self.assertIn("None</a>", result)

    @patch(
        "nettacker.core.app.Nettacker.load_profiles",
        return_value={"scan": {}, "brute": {}, "custom": {}},
    )
    def test_profiles(self, mock_profiles):
        result = profiles()
        self.assertIn("checkbox-scan", result)
        self.assertIn('label-success">scan</a>', result)
        self.assertIn('label-warning">brute</a>', result)
        self.assertIn('label-default">custom</a>', result)

    @patch(
        "nettacker.core.app.Nettacker.load_modules",
        return_value={"ssh_brute": {}, "http_vuln": {}, "tcp_scan": {}, "all": {}},
    )
    def test_scan_methods(self, mock_methods):
        result = scan_methods()
        self.assertIn("checkbox-scan-module", result)
        self.assertIn('label-success">tcp_scan</a>', result)

        self.assertIn("checkbox-brute-module", result)
        self.assertIn('label-warning">ssh_brute</a>', result)

        self.assertIn("checkbox-vuln-module", result)
        self.assertIn('label-danger">http_vuln</a>', result)

        self.assertNotIn("all", result)

    @patch("nettacker.core.messages.get_languages", return_value=["en", "fr", "es", "de"])
    def test_languages_to_country(self, mock_langs):
        result = languages_to_country()
        self.assertIn("flag-icon-us", result)
        self.assertIn("flag-icon-fr", result)
        self.assertIn('<option selected id="en"', result)
        self.assertIn("flag-icon-es", result)
        self.assertIn("flag-icon-de", result)
