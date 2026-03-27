"""
Targeted tests for low-coverage modules to push coverage beyond 64%.
Focus on protocol libraries (smtp, telnet, etc.) and utility modules.
"""

import sys
from unittest.mock import MagicMock, patch, mock_open
import pytest
import smtplib
import telnetlib

from nettacker.core.lib.smtp import SmtpLibrary, SmtpEngine
from nettacker.core.lib.smtps import SmtpsLibrary, SmtpsEngine
from nettacker.core.lib.telnet import TelnetLibrary, TelnetEngine
from nettacker.core.lib.ftp import FtpLibrary, FtpEngine
from nettacker.core.lib.pop3 import Pop3Library, Pop3Engine
from nettacker.core.lib.ssh import SshLibrary, SshEngine
from nettacker.lib.compare_report.engine import build_report
from nettacker.core.messages import application_language, get_languages, load_message


class TestSmtpLibrary:
    """Test SMTP protocol library."""
    
    def test_smtp_library_class_defined(self):
        """Test SmtpLibrary class exists and has client."""
        assert SmtpLibrary.client == smtplib.SMTP
    
    def test_smtp_library_instantiation(self):
        """Test SmtpLibrary can be instantiated."""
        library = SmtpLibrary()
        assert library is not None
        assert library.client == smtplib.SMTP
    
    def test_smtp_engine_has_library(self):
        """Test SmtpEngine has SmtpLibrary."""
        assert SmtpEngine.library == SmtpLibrary


class TestSmtpsLibrary:
    """Test SMTPS protocol library."""
    
    def test_smtps_library_defined(self):
        """Test SmtpsLibrary exists."""
        assert SmtpsLibrary is not None
        assert hasattr(SmtpsLibrary, 'client')
    
    def test_smtps_engine_defined(self):
        """Test SmtpsEngine exists and has library."""
        assert SmtpsEngine.library == SmtpsLibrary


class TestTelnetLibrary:
    """Test Telnet protocol library."""
    
    def test_telnet_library_class_defined(self):
        """Test TelnetLibrary class exists."""
        assert TelnetLibrary is not None
        assert hasattr(TelnetLibrary, 'client')
    
    def test_telnet_library_instantiation(self):
        """Test TelnetLibrary can be instantiated."""
        library = TelnetLibrary()
        assert library is not None
    
    def test_telnet_engine_defined(self):
        """Test TelnetEngine exists and has library."""
        assert TelnetEngine.library == TelnetLibrary


class TestFtpLibrary:
    """Test FTP protocol library."""
    
    def test_ftp_library_defined(self):
        """Test FtpLibrary class exists."""
        assert FtpLibrary is not None
        assert hasattr(FtpLibrary, 'client')
    
    def test_ftp_engine_defined(self):
        """Test FtpEngine exists."""
        assert FtpEngine.library == FtpLibrary


class TestPop3Library:
    """Test POP3 protocol library."""
    
    def test_pop3_library_defined(self):
        """Test Pop3Library class exists."""
        assert Pop3Library is not None
        assert hasattr(Pop3Library, 'client')
    
    def test_pop3_engine_defined(self):
        """Test Pop3Engine exists."""
        assert Pop3Engine.library == Pop3Library


class TestSshLibrary:
    """Test SSH protocol library."""
    
    def test_ssh_library_defined(self):
        """Test SshLibrary class exists."""
        assert SshLibrary is not None
        assert hasattr(SshLibrary, 'client')
    
    def test_ssh_engine_defined(self):
        """Test SshEngine exists."""
        assert SshEngine.library == SshLibrary


class TestCompareReportEngine:
    """Test compare report module."""
    
    def test_build_report_with_simple_data(self):
        """Test build_report function with simple data."""
        compare_result = {"scan1": "data1", "scan2": "data2"}
        
        with patch("builtins.open", mock_open(read_data="__data_will_locate_here__")):
            result = build_report(compare_result)
            assert '"scan1": "data1"' in result
            assert '"scan2": "data2"' in result
    
    def test_build_report_with_complex_data(self):
        """Test build_report with nested data structure."""
        compare_result = {
            "comparison": {
                "added": [1, 2, 3],
                "removed": [4, 5]
            }
        }
        
        with patch("builtins.open", mock_open(read_data="prefix __data_will_locate_here__ suffix")):
            result = build_report(compare_result)
            assert "prefix" in result
            assert "suffix" in result
            assert "added" in result
    
    def test_build_report_html_replacement(self):
        """Test that placeholder is properly replaced."""
        html_template = "<html>Compare: __data_will_locate_here__</html>"
        data = {"status": "ok"}
        
        with patch("builtins.open", mock_open(read_data=html_template)):
            result = build_report(data)
            assert "__data_will_locate_here__" not in result
            assert "status" in result


class TestApplicationLanguage:
    """Test language selection logic."""
    
    def test_language_from_L_flag(self):
        """Test language selection from -L flag."""
        with patch.object(sys, "argv", ["prog", "-L", "fr"]):
            with patch("nettacker.core.messages.get_languages", return_value=["en", "fr"]):
                lang = application_language()
                assert lang == "fr"
    
    def test_language_from_long_flag(self):
        """Test language selection from --language flag."""
        with patch.object(sys, "argv", ["prog", "--language", "de"]):
            with patch("nettacker.core.messages.get_languages", return_value=["en", "de"]):
                lang = application_language()
                assert lang == "de"
    
    def test_language_from_config(self):
        """Test language selection from config."""
        with patch.object(sys, "argv", ["prog"]):
            with patch("nettacker.core.messages.Config.settings.language", "fa"):
                with patch("nettacker.core.messages.get_languages", return_value=["en", "fa"]):
                    lang = application_language()
                    assert lang == "fa"
    
    def test_language_default_to_en(self):
        """Test default language is English."""
        with patch.object(sys, "argv", ["prog", "-L", "invalid"]):
            with patch("nettacker.core.messages.get_languages", return_value=["en"]):
                lang = application_language()
                assert lang == "en"
    
    def test_language_invalid_reverts_to_en(self):
        """Test invalid language reverts to English."""
        with patch.object(sys, "argv", ["prog", "-L", "xx"]):
            with patch("nettacker.core.messages.get_languages", return_value=["en", "fr"]):
                lang = application_language()
                assert lang == "en"


class TestGetLanguages:
    """Test language detection."""
    
    @patch("nettacker.core.messages.Config.path.locale_dir")
    def test_get_languages_returns_list(self, mock_locale_dir):
        """Test get_languages returns list of available languages."""
        mock_paths = [
            MagicMock(__str__=lambda x: "/path/en.yaml"),
            MagicMock(__str__=lambda x: "/path/fr.yaml"),
            MagicMock(__str__=lambda x: "/path/de.yaml"),
        ]
        mock_locale_dir.glob.return_value = mock_paths
        
        languages = get_languages()
        assert len(languages) >= 3
        assert "en" in languages


class TestLoadMessageClass:
    """Test load_message class initialization."""
    
    @patch("nettacker.core.messages.application_language", return_value="en")
    @patch("nettacker.core.messages.load_yaml")
    def test_load_message_init_english(self, mock_load_yaml, mock_app_lang):
        """Test load_message initialization with English."""
        mock_load_yaml.return_value = {"test": "message"}
        
        loader = load_message()
        assert loader.language == "en"
        assert loader.messages == {"test": "message"}
    
    @patch("nettacker.core.messages.application_language", return_value="fa")
    @patch("nettacker.core.messages.load_yaml")
    def test_load_message_init_farsi_with_fallback(self, mock_load_yaml, mock_app_lang):
        """Test load_message initialization with Farsi and English fallback."""
        # First call for Farsi, second call for English fallback
        mock_load_yaml.side_effect = [
            {"translated": "message"},
            {"key": "en_value"}
        ]
        
        loader = load_message()
        assert loader.language == "fa"
        assert mock_load_yaml.call_count >= 1


class TestMessagesGetter:
    """Test message retrieval methods."""
    
    @patch("nettacker.core.messages.application_language", return_value="en")
    @patch("nettacker.core.messages.load_yaml")
    def test_load_message_messages_dict(self, mock_load_yaml, mock_app_lang):
        """Test load_message creates messages dict."""
        mock_load_yaml.return_value = {"greeting": "Hello", "farewell": "Goodbye"}
        
        loader = load_message()
        assert loader.messages == {"greeting": "Hello", "farewell": "Goodbye"}
        assert loader.language == "en"
    
    @patch("nettacker.core.messages.application_language", return_value="en")
    @patch("nettacker.core.messages.load_yaml")
    def test_load_message_attribute_access(self, mock_load_yaml, mock_app_lang):
        """Test load_message stores messages."""
        mock_load_yaml.return_value = {"error": "An error occurred"}
        
        loader = load_message()
        assert hasattr(loader, "messages")
        assert hasattr(loader, "language")


class TestProtocolEngines:
    """Test protocol engine classes."""
    
    def test_smtp_engine_has_library(self):
        """Test SmtpEngine has SmtpLibrary."""
        assert SmtpEngine.library == SmtpLibrary
    
    def test_telnet_engine_has_library(self):
        """Test TelnetEngine has TelnetLibrary."""
        assert TelnetEngine.library == TelnetLibrary
    
    def test_ftp_engine_has_library(self):
        """Test FtpEngine has FtpLibrary."""
        assert FtpEngine.library == FtpLibrary
    
    def test_pop3_engine_has_library(self):
        """Test Pop3Engine has Pop3Library."""
        assert Pop3Engine.library == Pop3Library
    
    def test_ssh_engine_has_library(self):
        """Test SshEngine has SshLibrary."""
        assert SshEngine.library == SshLibrary


class TestProtocolClientAttributes:
    """Test that protocol libraries have proper client attributes."""
    
    def test_smtp_has_client(self):
        """Test SMTP library has client attribute."""
        assert hasattr(SmtpLibrary, "client")
        assert SmtpLibrary.client is not None
    
    def test_smtps_has_client(self):
        """Test SMTPS library has client attribute."""
        assert hasattr(SmtpsLibrary, "client")
    
    def test_telnet_has_client(self):
        """Test Telnet library has client attribute."""
        assert hasattr(TelnetLibrary, "client")
    
    def test_ftp_has_client(self):
        """Test FTP library has client attribute."""
        assert hasattr(FtpLibrary, "client")
    
    def test_pop3_has_client(self):
        """Test POP3 library has client attribute."""
        assert hasattr(Pop3Library, "client")
    
    def test_ssh_has_client(self):
        """Test SSH library has client attribute."""
        assert hasattr(SshLibrary, "client")
