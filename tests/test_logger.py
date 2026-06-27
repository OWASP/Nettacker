"""
Comprehensive tests for nettacker logger module.
Tests all branches including verbose modes and API mode detection.
"""

import sys
from unittest.mock import MagicMock, patch
import pytest

from nettacker.logger import TerminalCodes, Logger, get_logger


class TestTerminalCodes:
    """Test TerminalCodes enum."""
    
    def test_terminal_codes_enum_values(self):
        """Test that terminal codes have correct ANSI escape values."""
        assert TerminalCodes.RESET.value == "\033[0m"
        assert TerminalCodes.RED.value == "\033[1;31m"
        assert TerminalCodes.GREEN.value == "\033[1;32m"
        assert TerminalCodes.YELLOW.value == "\033[1;33m"
        assert TerminalCodes.BLUE.value == "\033[1;34m"
        assert TerminalCodes.PURPLE.value == "\033[1;35m"
        assert TerminalCodes.CYAN.value == "\033[1;36m"
        assert TerminalCodes.WHITE.value == "\033[1;37m"
        assert TerminalCodes.GREY.value == "\033[1;30m"
        
    def test_terminal_codes_all_defined(self):
        """Test that all color codes are defined."""
        colors = [code.value for code in TerminalCodes]
        assert len(colors) > 0
        assert all(isinstance(color, str) for color in colors)


class TestLoggerBasic:
    """Test basic Logger functionality."""
    
    def test_logger_log_static_method(self):
        """Test Logger.log static method."""
        with patch("builtins.print") as mock_print:
            Logger.log("test message")
            mock_print.assert_called_once_with("test message", end="", flush=True)
    
    def test_logger_log_multiple_calls(self):
        """Test Logger.log with multiple calls."""
        with patch("builtins.print") as mock_print:
            Logger.log("line 1")
            Logger.log("line 2")
            assert mock_print.call_count == 2


class TestLoggerRunFromApi:
    """Test run_from_api detection (cached property)."""
    
    def test_run_from_api_detected(self):
        """Test detection of --start-api flag."""
        with patch.object(sys, "argv", ["nettacker.py", "--start-api"]):
            # Create new logger instance to get fresh cached_property
            logger = Logger()
            assert logger.run_from_api is True
    
    def test_run_from_api_not_detected(self):
        """Test run_from_api when flag is not present."""
        with patch.object(sys, "argv", ["nettacker.py", "--other-flag"]):
            logger = Logger()
            assert logger.run_from_api is False
    
    def test_run_from_api_cached(self):
        """Test that run_from_api property is cached."""
        with patch.object(sys, "argv", ["nettacker.py", "--start-api"]):
            logger = Logger()
            first_call = logger.run_from_api
            second_call = logger.run_from_api
            assert first_call is second_call


class TestLoggerVerboseMode:
    """Test verbose mode detection."""
    
    def test_verbose_mode_enabled_with_verbose(self):
        """Test verbose mode with --verbose flag."""
        with patch.object(sys, "argv", ["nettacker.py", "--verbose"]):
            logger = Logger()
            assert logger.verbose_mode_is_enabled is True
    
    def test_verbose_mode_enabled_with_v_flag(self):
        """Test verbose mode with -v flag."""
        with patch.object(sys, "argv", ["nettacker.py", "-v"]):
            logger = Logger()
            assert logger.verbose_mode_is_enabled is True
    
    def test_verbose_mode_disabled(self):
        """Test verbose mode when disabled."""
        with patch.object(sys, "argv", ["nettacker.py"]):
            logger = Logger()
            assert logger.verbose_mode_is_enabled is False


class TestLoggerEventVerboseMode:
    """Test event verbose mode detection."""
    
    def test_event_verbose_mode_enabled(self):
        """Test event verbose mode with --verbose-event flag."""
        with patch.object(sys, "argv", ["nettacker.py", "--verbose-event"]):
            logger = Logger()
            assert logger.event_verbose_mode_is_enabled is True
    
    def test_event_verbose_mode_disabled(self):
        """Test event verbose mode when disabled."""
        with patch.object(sys, "argv", ["nettacker.py"]):
            logger = Logger()
            assert logger.event_verbose_mode_is_enabled is False


class TestLoggerInfoMethod:
    """Test Logger.info logging method."""
    
    def test_info_not_from_api(self):
        """Test info logs when not running from API."""
        with patch.object(sys, "argv", ["nettacker.py"]):
            logger = Logger()
            with patch.object(logger, "log") as mock_log:
                logger.info("test info message")
                mock_log.assert_called_once()
                call_args = mock_log.call_args[0][0]
                assert "test info message" in call_args
                assert TerminalCodes.GREEN.value in call_args
    
    def test_info_from_api_silent(self):
        """Test info is silent when running from API."""
        with patch.object(sys, "argv", ["nettacker.py", "--start-api"]):
            logger = Logger()
            with patch.object(logger, "log") as mock_log:
                logger.info("test info message")
                mock_log.assert_not_called()


class TestLoggerVerboseEventInfo:
    """Test Logger.verbose_event_info method."""
    
    def test_verbose_event_info_with_event_verbose(self):
        """Test verbose_event_info logs with --verbose-event flag."""
        with patch.object(sys, "argv", ["nettacker.py", "--verbose-event"]):
            logger = Logger()
            with patch.object(logger, "log") as mock_log:
                logger.verbose_event_info("event test")
                mock_log.assert_called_once()
    
    def test_verbose_event_info_with_verbose(self):
        """Test verbose_event_info logs with --verbose flag."""
        with patch.object(sys, "argv", ["nettacker.py", "--verbose"]):
            logger = Logger()
            with patch.object(logger, "log") as mock_log:
                logger.verbose_event_info("event test")
                mock_log.assert_called_once()
    
    def test_verbose_event_info_disabled(self):
        """Test verbose_event_info silent when neither flag set."""
        with patch.object(sys, "argv", ["nettacker.py"]):
            logger = Logger()
            with patch.object(logger, "log") as mock_log:
                logger.verbose_event_info("event test")
                mock_log.assert_not_called()
    
    def test_verbose_event_info_from_api_silent(self):
        """Test verbose_event_info silent from API."""
        with patch.object(sys, "argv", ["nettacker.py", "--start-api", "--verbose-event"]):
            logger = Logger()
            with patch.object(logger, "log") as mock_log:
                logger.verbose_event_info("event test")
                mock_log.assert_not_called()


class TestLoggerWriteMethod:
    """Test Logger.write method."""
    
    def test_write_not_from_api(self):
        """Test write outputs when not from API."""
        with patch.object(sys, "argv", ["nettacker.py"]):
            logger = Logger()
            with patch.object(logger, "log") as mock_log:
                logger.write("write test")
                mock_log.assert_called_once_with("write test")
    
    def test_write_from_api_silent(self):
        """Test write silent when from API."""
        with patch.object(sys, "argv", ["nettacker.py", "--start-api"]):
            logger = Logger()
            with patch.object(logger, "log") as mock_log:
                logger.write("write test")
                mock_log.assert_not_called()


class TestLoggerSuccessEventInfo:
    """Test Logger.success_event_info method."""
    
    def test_success_event_info_not_from_api(self):
        """Test success_event_info logs when not from API."""
        with patch.object(sys, "argv", ["nettacker.py"]):
            logger = Logger()
            with patch.object(logger, "log") as mock_log:
                logger.success_event_info("success message")
                mock_log.assert_called_once()
                call_args = mock_log.call_args[0][0]
                assert "success message" in call_args
                assert TerminalCodes.CYAN.value in call_args
    
    def test_success_event_info_from_api_silent(self):
        """Test success_event_info silent from API."""
        with patch.object(sys, "argv", ["nettacker.py", "--start-api"]):
            logger = Logger()
            with patch.object(logger, "log") as mock_log:
                logger.success_event_info("success message")
                mock_log.assert_not_called()


class TestLoggerVerboseInfo:
    """Test Logger.verbose_info method."""
    
    def test_verbose_info_enabled(self):
        """Test verbose_info logs with verbose mode."""
        with patch.object(sys, "argv", ["nettacker.py", "--verbose"]):
            logger = Logger()
            with patch.object(logger, "log") as mock_log:
                logger.verbose_info("verbose message")
                mock_log.assert_called_once()
                call_args = mock_log.call_args[0][0]
                assert "verbose message" in call_args
                assert TerminalCodes.PURPLE.value in call_args
    
    def test_verbose_info_disabled(self):
        """Test verbose_info silent without verbose mode."""
        with patch.object(sys, "argv", ["nettacker.py"]):
            logger = Logger()
            with patch.object(logger, "log") as mock_log:
                logger.verbose_info("verbose message")
                mock_log.assert_not_called()


class TestLoggerWarnMethod:
    """Test Logger.warn method."""
    
    def test_warn_not_from_api(self):
        """Test warn logs when not from API."""
        with patch.object(sys, "argv", ["nettacker.py"]):
            logger = Logger()
            with patch.object(logger, "log") as mock_log:
                logger.warn("warning message")
                mock_log.assert_called_once()
                call_args = mock_log.call_args[0][0]
                assert "warning message" in call_args
    
    def test_warn_from_api_silent(self):
        """Test warn silent from API."""
        with patch.object(sys, "argv", ["nettacker.py", "--start-api"]):
            logger = Logger()
            with patch.object(logger, "log") as mock_log:
                logger.warn("warning message")
                mock_log.assert_not_called()


class TestLoggerErrorMethod:
    """Test Logger.error method."""
    
    def test_error_always_logs(self):
        """Test error logs unconditionally (unlike other methods)."""
        with patch.object(sys, "argv", ["nettacker.py"]):
            logger = Logger()
            with patch.object(logger, "log") as mock_log:
                logger.error("error message")
                mock_log.assert_called_once()
                call_args = mock_log.call_args[0][0]
                assert "error message" in call_args
                assert TerminalCodes.RED.value in call_args
    
    def test_error_logs_even_from_api(self):
        """Test error logs even when running from API."""
        with patch.object(sys, "argv", ["nettacker.py", "--start-api"]):
            logger = Logger()
            with patch.object(logger, "log") as mock_log:
                logger.error("error message")
                # Error actually logs even from API (no run_from_api check)
                mock_log.assert_called_once()


class TestGetLogger:
    """Test get_logger factory function."""
    
    def test_get_logger_returns_logger_instance(self):
        """Test get_logger returns a Logger instance."""
        logger = get_logger()
        assert isinstance(logger, Logger)
    
    def test_get_logger_creates_new_instances(self):
        """Test get_logger creates new instances each time."""
        logger1 = get_logger()
        logger2 = get_logger()
        # get_logger creates new instances, not singleton
        assert logger1 is not logger2


class TestLoggerIntegration:
    """Integration tests for Logger with different configurations."""
    
    def test_logger_all_flags_enabled(self):
        """Test logger with all flags enabled."""
        with patch.object(sys, "argv", [
            "nettacker.py", 
            "--start-api", 
            "--verbose", 
            "--verbose-event"
        ]):
            logger = Logger()
            assert logger.run_from_api is True
            assert logger.verbose_mode_is_enabled is True
            assert logger.event_verbose_mode_is_enabled is True
    
    def test_logger_all_flags_disabled(self):
        """Test logger with all flags disabled."""
        with patch.object(sys, "argv", ["nettacker.py"]):
            logger = Logger()
            assert logger.run_from_api is False
            assert logger.verbose_mode_is_enabled is False
            assert logger.event_verbose_mode_is_enabled is False
    
    def test_logger_output_formatting(self):
        """Test that logger properly formats output with color codes."""
        with patch.object(sys, "argv", ["nettacker.py"]):
            logger = Logger()
            with patch("builtins.print") as mock_print:
                logger.info("test")
                # Check that info() uses the log method
                assert mock_print.called
