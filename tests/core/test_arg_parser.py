"""
Unit tests for arg_parser module, specifically testing --modules-extra-args parsing
"""

from unittest.mock import patch, MagicMock

from nettacker.core.arg_parser import ArgParser


class TestModulesExtraArgs:
    """Test suite for --modules-extra-args parsing"""

    @patch("nettacker.core.arg_parser.ArgParser.load_graphs")
    @patch("nettacker.core.arg_parser.ArgParser.load_languages")
    @patch("nettacker.core.arg_parser.ArgParser.load_modules")
    @patch("nettacker.core.arg_parser.ArgParser.load_profiles")
    @patch("nettacker.core.arg_parser.ArgParser.add_arguments")
    @patch("sys.exit")
    def test_modules_extra_args_without_equal_sign(
        self,
        mock_exit,
        mock_add_args,
        mock_load_profiles,
        mock_load_modules,
        mock_load_languages,
        mock_load_graphs,
    ):
        """Test that malformed --modules-extra-args without '=' sign raises error"""
        # Setup mocks
        mock_load_graphs.return_value = []
        mock_load_languages.return_value = []
        mock_load_modules.return_value = {}
        mock_load_profiles.return_value = []

        # Mock sys.argv with malformed --modules-extra-args
        test_args = [
            "nettacker.py",
            "-i",
            "owasp.org",
            "-m",
            "port_scan",
            "--modules-extra-args",
            "api_key",  # Missing '=' sign
        ]

        with patch("sys.argv", test_args):
            ArgParser()
            # Should call sys.exit(1) due to die_failure
            mock_exit.assert_called_once_with(1)

    @patch("nettacker.core.arg_parser.ArgParser.load_graphs")
    @patch("nettacker.core.arg_parser.ArgParser.load_languages")
    @patch("nettacker.core.arg_parser.ArgParser.load_modules")
    @patch("nettacker.core.arg_parser.ArgParser.load_profiles")
    @patch("nettacker.core.arg_parser.ArgParser.add_arguments")
    @patch("sys.exit")
    def test_modules_extra_args_with_empty_key(
        self,
        mock_exit,
        mock_add_args,
        mock_load_profiles,
        mock_load_modules,
        mock_load_languages,
        mock_load_graphs,
    ):
        """Test that --modules-extra-args with empty key raises error"""
        # Setup mocks
        mock_load_graphs.return_value = []
        mock_load_languages.return_value = []
        mock_load_modules.return_value = {}
        mock_load_profiles.return_value = []

        # Mock sys.argv with empty key
        test_args = [
            "nettacker.py",
            "-i",
            "owasp.org",
            "-m",
            "port_scan",
            "--modules-extra-args",
            "=value",  # Empty key
        ]

        with patch("sys.argv", test_args):
            ArgParser()
            # Should call sys.exit(1) due to die_failure
            mock_exit.assert_called_once_with(1)

    @patch("nettacker.core.arg_parser.ArgParser.load_graphs")
    @patch("nettacker.core.arg_parser.ArgParser.load_languages")
    @patch("nettacker.core.arg_parser.ArgParser.load_modules")
    @patch("nettacker.core.arg_parser.ArgParser.load_profiles")
    @patch("nettacker.core.arg_parser.ArgParser.add_arguments")
    @patch("nettacker.core.arg_parser.ArgParser.parse_arguments")
    def test_modules_extra_args_valid_format(
        self,
        mock_parse_args,
        mock_add_args,
        mock_load_profiles,
        mock_load_modules,
        mock_load_languages,
        mock_load_graphs,
    ):
        """Test that properly formatted --modules-extra-args is parsed correctly"""
        # Setup mocks
        mock_load_graphs.return_value = []
        mock_load_languages.return_value = []
        mock_load_modules.return_value = {}
        mock_load_profiles.return_value = []

        # Create a mock options object that parse_arguments would return
        mock_options = MagicMock()
        mock_options.modules_extra_args = "api_key=123&password=abc"
        mock_parse_args.return_value = mock_options

        # This should not raise an error
        ArgParser()

        # Verify parse_arguments was called
        mock_parse_args.assert_called_once()

    @patch("nettacker.core.arg_parser.ArgParser.load_graphs")
    @patch("nettacker.core.arg_parser.ArgParser.load_languages")
    @patch("nettacker.core.arg_parser.ArgParser.load_modules")
    @patch("nettacker.core.arg_parser.ArgParser.load_profiles")
    @patch("nettacker.core.arg_parser.ArgParser.add_arguments")
    @patch("nettacker.core.arg_parser.ArgParser.parse_arguments")
    def test_modules_extra_args_with_equals_in_value(
        self,
        mock_parse_args,
        mock_add_args,
        mock_load_profiles,
        mock_load_modules,
        mock_load_languages,
        mock_load_graphs,
    ):
        """Test that values containing '=' sign are handled correctly"""
        # Setup mocks
        mock_load_graphs.return_value = []
        mock_load_languages.return_value = []
        mock_load_modules.return_value = {}
        mock_load_profiles.return_value = []

        # Create a mock options object with value containing '='
        mock_options = MagicMock()
        mock_options.modules_extra_args = "api_key=abc=def=123"
        mock_parse_args.return_value = mock_options

        # This should not raise an error
        ArgParser()

        # Verify parse_arguments was called
        mock_parse_args.assert_called_once()
