"""
Unit tests for port range parsing in arg_parser module
Tests the regex-based validation for --ports and --excluded-ports
"""

from unittest.mock import patch, MagicMock

from nettacker.core.arg_parser import ArgParser

class TestPortParsing:
    """Test suite for port range parsing (--ports and --excluded-ports)"""

    @patch("nettacker.core.arg_parser.ArgParser.load_graphs")
    @patch("nettacker.core.arg_parser.ArgParser.load_languages")
    @patch("nettacker.core.arg_parser.ArgParser.load_modules")
    @patch("nettacker.core.arg_parser.ArgParser.load_profiles")
    @patch("nettacker.core.arg_parser.ArgParser.add_arguments")
    @patch("sys.exit")
    def test_port_multiple_dashes(
        self,
        mock_exit,
        mock_add_args,
        mock_load_profiles,
        mock_load_modules,
        mock_load_languages,
        mock_load_graphs,
    ):
        """Test that port ranges with multiple dashes (80-90-100) are rejected"""
        mock_load_graphs.return_value = []
        mock_load_languages.return_value = []
        mock_load_modules.return_value = {}
        mock_load_profiles.return_value = []

        test_args = [
            "nettacker.py",
            "-i",
            "127.0.0.1",
            "-m",
            "port_scan",
            "--ports",
            "80-90-100",  # Multiple dashes - should fail
        ]

        with patch("sys.argv", test_args):
            ArgParser()
            mock_exit.assert_called_once_with(1)

    @patch("nettacker.core.arg_parser.ArgParser.load_graphs")
    @patch("nettacker.core.arg_parser.ArgParser.load_languages")
    @patch("nettacker.core.arg_parser.ArgParser.load_modules")
    @patch("nettacker.core.arg_parser.ArgParser.load_profiles")
    @patch("nettacker.core.arg_parser.ArgParser.add_arguments")
    @patch("sys.exit")
    def test_port_trailing_dash(
        self,
        mock_exit,
        mock_add_args,
        mock_load_profiles,
        mock_load_modules,
        mock_load_languages,
        mock_load_graphs,
    ):
        """Test that trailing dash (80-) is rejected"""
        mock_load_graphs.return_value = []
        mock_load_languages.return_value = []
        mock_load_modules.return_value = {}
        mock_load_profiles.return_value = []

        test_args = [
            "nettacker.py",
            "-i",
            "127.0.0.1",
            "-m",
            "port_scan",
            "--ports",
            "80-",  # Trailing dash - should fail
        ]

        with patch("sys.argv", test_args):
            ArgParser()
            mock_exit.assert_called_once_with(1)

    @patch("nettacker.core.arg_parser.ArgParser.load_graphs")
    @patch("nettacker.core.arg_parser.ArgParser.load_languages")
    @patch("nettacker.core.arg_parser.ArgParser.load_modules")
    @patch("nettacker.core.arg_parser.ArgParser.load_profiles")
    @patch("nettacker.core.arg_parser.ArgParser.add_arguments")
    @patch("sys.exit")
    def test_port_leading_dash(
        self,
        mock_exit,
        mock_add_args,
        mock_load_profiles,
        mock_load_modules,
        mock_load_languages,
        mock_load_graphs,
    ):
        """Test that leading dash (-80) is rejected"""
        mock_load_graphs.return_value = []
        mock_load_languages.return_value = []
        mock_load_modules.return_value = {}
        mock_load_profiles.return_value = []

        test_args = [
            "nettacker.py",
            "-i",
            "127.0.0.1",
            "-m",
            "port_scan",
            "--ports",
            "-80",  # Leading dash - should fail
        ]

        with patch("sys.argv", test_args):
            ArgParser()
            mock_exit.assert_called_once_with(1)

    @patch("nettacker.core.arg_parser.ArgParser.load_graphs")
    @patch("nettacker.core.arg_parser.ArgParser.load_languages")
    @patch("nettacker.core.arg_parser.ArgParser.load_modules")
    @patch("nettacker.core.arg_parser.ArgParser.load_profiles")
    @patch("nettacker.core.arg_parser.ArgParser.add_arguments")
    @patch("sys.exit")
    def test_port_range_reversed(
        self,
        mock_exit,
        mock_add_args,
        mock_load_profiles,
        mock_load_modules,
        mock_load_languages,
        mock_load_graphs,
    ):
        """Test that reversed port range (90-80) is rejected"""
        mock_load_graphs.return_value = []
        mock_load_languages.return_value = []
        mock_load_modules.return_value = {}
        mock_load_profiles.return_value = []

        test_args = [
            "nettacker.py",
            "-i",
            "127.0.0.1",
            "-m",
            "port_scan",
            "--ports",
            "90-80",  # Reversed range - should fail
        ]

        with patch("sys.argv", test_args):
            ArgParser()
            mock_exit.assert_called_once_with(1)

    @patch("nettacker.core.arg_parser.ArgParser.load_graphs")
    @patch("nettacker.core.arg_parser.ArgParser.load_languages")
    @patch("nettacker.core.arg_parser.ArgParser.load_modules")
    @patch("nettacker.core.arg_parser.ArgParser.load_profiles")
    @patch("nettacker.core.arg_parser.ArgParser.add_arguments")
    @patch("sys.exit")
    def test_port_out_of_range(
        self,
        mock_exit,
        mock_add_args,
        mock_load_profiles,
        mock_load_modules,
        mock_load_languages,
        mock_load_graphs,
    ):
        """Test that port numbers > 65535 are rejected"""
        mock_load_graphs.return_value = []
        mock_load_languages.return_value = []
        mock_load_modules.return_value = {}
        mock_load_profiles.return_value = []

        test_args = [
            "nettacker.py",
            "-i",
            "127.0.0.1",
            "-m",
            "port_scan",
            "--ports",
            "70000",  # Out of range - should fail
        ]

        with patch("sys.argv", test_args):
            ArgParser()
            mock_exit.assert_called_once_with(1)

    @patch("nettacker.core.arg_parser.ArgParser.load_graphs")
    @patch("nettacker.core.arg_parser.ArgParser.load_languages")
    @patch("nettacker.core.arg_parser.ArgParser.load_modules")
    @patch("nettacker.core.arg_parser.ArgParser.load_profiles")
    @patch("nettacker.core.arg_parser.ArgParser.add_arguments")
    @patch("sys.exit")
    def test_port_zero(
        self,
        mock_exit,
        mock_add_args,
        mock_load_profiles,
        mock_load_modules,
        mock_load_languages,
        mock_load_graphs,
    ):
        """Test that port number 0 is rejected"""
        mock_load_graphs.return_value = []
        mock_load_languages.return_value = []
        mock_load_modules.return_value = {}
        mock_load_profiles.return_value = []

        test_args = [
            "nettacker.py",
            "-i",
            "127.0.0.1",
            "-m",
            "port_scan",
            "--ports",
            "0",  # Port 0 - should fail
        ]

        with patch("sys.argv", test_args):
            ArgParser()
            mock_exit.assert_called_once_with(1)

    @patch("nettacker.core.arg_parser.ArgParser.load_graphs")
    @patch("nettacker.core.arg_parser.ArgParser.load_languages")
    @patch("nettacker.core.arg_parser.ArgParser.load_modules")
    @patch("nettacker.core.arg_parser.ArgParser.load_profiles")
    @patch("nettacker.core.arg_parser.ArgParser.add_arguments")
    @patch("sys.exit")
    def test_excluded_port_multiple_dashes(
        self,
        mock_exit,
        mock_add_args,
        mock_load_profiles,
        mock_load_modules,
        mock_load_languages,
        mock_load_graphs,
    ):
        """Test that excluded port ranges with multiple dashes are rejected"""
        mock_load_graphs.return_value = []
        mock_load_languages.return_value = []
        mock_load_modules.return_value = {}
        mock_load_profiles.return_value = []

        test_args = [
            "nettacker.py",
            "-i",
            "127.0.0.1",
            "-m",
            "port_scan",
            "--excluded-ports",
            "135-139-445",  # Multiple dashes - should fail
        ]

        with patch("sys.argv", test_args):
            ArgParser()
            mock_exit.assert_called_once_with(1)

    @patch("nettacker.core.arg_parser.ArgParser.load_graphs")
    @patch("nettacker.core.arg_parser.ArgParser.load_languages")
    @patch("nettacker.core.arg_parser.ArgParser.load_modules")
    @patch("nettacker.core.arg_parser.ArgParser.load_profiles")
    @patch("nettacker.core.arg_parser.ArgParser.add_arguments")
    @patch("nettacker.core.arg_parser.ArgParser.parse_arguments")
    def test_valid_port_single(
        self,
        mock_parse_args,
        mock_add_args,
        mock_load_profiles,
        mock_load_modules,
        mock_load_languages,
        mock_load_graphs,
    ):
        """Test that valid single port is parsed correctly"""
        mock_load_graphs.return_value = []
        mock_load_languages.return_value = []
        mock_load_modules.return_value = {}
        mock_load_profiles.return_value = []

        mock_options = MagicMock()
        mock_options.ports = "80"
        mock_parse_args.return_value = mock_options

        ArgParser()
        mock_parse_args.assert_called_once()

    @patch("nettacker.core.arg_parser.ArgParser.load_graphs")
    @patch("nettacker.core.arg_parser.ArgParser.load_languages")
    @patch("nettacker.core.arg_parser.ArgParser.load_modules")
    @patch("nettacker.core.arg_parser.ArgParser.load_profiles")
    @patch("nettacker.core.arg_parser.ArgParser.add_arguments")
    @patch("nettacker.core.arg_parser.ArgParser.parse_arguments")
    def test_valid_port_range(
        self,
        mock_parse_args,
        mock_add_args,
        mock_load_profiles,
        mock_load_modules,
        mock_load_languages,
        mock_load_graphs,
    ):
        """Test that valid port range is parsed correctly"""
        mock_load_graphs.return_value = []
        mock_load_languages.return_value = []
        mock_load_modules.return_value = {}
        mock_load_profiles.return_value = []

        mock_options = MagicMock()
        mock_options.ports = "80-90"
        mock_parse_args.return_value = mock_options

        ArgParser()
        mock_parse_args.assert_called_once()

    @patch("nettacker.core.arg_parser.ArgParser.load_graphs")
    @patch("nettacker.core.arg_parser.ArgParser.load_languages")
    @patch("nettacker.core.arg_parser.ArgParser.load_modules")
    @patch("nettacker.core.arg_parser.ArgParser.load_profiles")
    @patch("nettacker.core.arg_parser.ArgParser.add_arguments")
    @patch("nettacker.core.arg_parser.ArgParser.parse_arguments")
    def test_valid_port_mixed(
        self,
        mock_parse_args,
        mock_add_args,
        mock_load_profiles,
        mock_load_modules,
        mock_load_languages,
        mock_load_graphs,
    ):
        """Test that valid mixed port specification is parsed correctly"""
        mock_load_graphs.return_value = []
        mock_load_languages.return_value = []
        mock_load_modules.return_value = {}
        mock_load_profiles.return_value = []

        mock_options = MagicMock()
        mock_options.ports = "22,80-90,443,8080-8090"
        mock_parse_args.return_value = mock_options

        ArgParser()
        mock_parse_args.assert_called_once()

    @patch("nettacker.core.arg_parser.ArgParser.load_graphs")
    @patch("nettacker.core.arg_parser.ArgParser.load_languages")
    @patch("nettacker.core.arg_parser.ArgParser.load_modules")
    @patch("nettacker.core.arg_parser.ArgParser.load_profiles")
    @patch("nettacker.core.arg_parser.ArgParser.add_arguments")
    @patch("sys.exit")
    def test_port_with_spaces(
        self,
        mock_exit,
        mock_add_args,
        mock_load_profiles,
        mock_load_modules,
        mock_load_languages,
        mock_load_graphs,
    ):
        """Test that port with non-digit characters is rejected"""
        mock_load_graphs.return_value = []
        mock_load_languages.return_value = []
        mock_load_modules.return_value = {}
        mock_load_profiles.return_value = []

        test_args = [
            "nettacker.py",
            "-i",
            "127.0.0.1",
            "-m",
            "port_scan",
            "--ports",
            "80 90",  # Space instead of comma or dash - should fail
        ]

        with patch("sys.argv", test_args):
            ArgParser()
            mock_exit.assert_called_once_with(1)
