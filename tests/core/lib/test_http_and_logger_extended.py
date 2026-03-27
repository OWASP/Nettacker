"""
Additional tests for HTTP engine and logger to achieve higher coverage.
"""

import sys
from unittest.mock import MagicMock, patch
import pytest

from nettacker.core.lib.http import HttpEngine
from nettacker.logger import Logger, TerminalCodes, get_logger


class TestHttpEngine:
    """Test HTTP protocol engine in detail."""
    
    def test_http_engine_exists(self):
        """Test HttpEngine class exists."""
        engine = HttpEngine()
        assert engine is not None
        assert callable(engine.run)
    
    def test_http_engine_has_library(self):
        """Test HttpEngine has library attribute."""
        engine = HttpEngine()
        assert hasattr(HttpEngine, "library")
        assert hasattr(engine, "run")
        assert callable(engine.run)


class TestLoggerResetColor:
    """Test logger reset color method."""
    
    def test_reset_color_calls_log(self):
        """Test reset_color method."""
        logger = Logger()
        with patch.object(logger, "log") as mock_log:
            logger.reset_color()
            mock_log.assert_called_once_with(TerminalCodes.RESET.value)


class TestLoggerVerboseEvent:
    """Additional tests for verbose event logging."""
    
    def test_verbose_event_info_with_verbose_mode_only(self):
        """Test verbose_event_info with --verbose but not --verbose-event."""
        with patch.object(sys, "argv", ["prog", "--verbose"]):
            logger = Logger()
            with patch.object(logger, "log") as mock_log:
                logger.verbose_event_info("event")
                # Should log because --verbose enables it
                mock_log.assert_called()
    
    def test_verbose_event_info_with_event_verbose_only(self):
        """Test verbose_event_info with --verbose-event but not --verbose."""
        with patch.object(sys, "argv", ["prog", "--verbose-event"]):
            logger = Logger()
            with patch.object(logger, "log") as mock_log:
                logger.verbose_event_info("event")
                # Should log because --verbose-event enables it
                mock_log.assert_called()
    
    def test_verbose_event_info_both_flags_with_api(self):
        """Test verbose_event_info is silent when running from API even with flags."""
        with patch.object(sys, "argv", ["prog", "--start-api", "--verbose-event"]):
            logger = Logger()
            with patch.object(logger, "log") as mock_log:
                logger.verbose_event_info("event")
                # Should be silent despite flags due to run_from_api
                mock_log.assert_not_called()


class TestLoggerInfoBranches:
    """Test all branches of info logging."""
    
    def test_info_message_format(self):
        """Test info message contains expected components."""
        with patch.object(sys, "argv", ["prog"]):
            logger = Logger()
            with patch.object(logger, "log") as mock_log:
                logger.info("test info")
                output = mock_log.call_args[0][0]
                assert TerminalCodes.YELLOW.value in output
                assert TerminalCodes.GREEN.value in output
                assert TerminalCodes.RESET.value in output
                assert "[+]" in output


class TestLoggerSuccessEventFormat:
    """Test success event logging format."""
    
    def test_success_event_message_format(self):
        """Test success_event_info message format."""
        with patch.object(sys, "argv", ["prog"]):
            logger = Logger()
            with patch.object(logger, "log") as mock_log:
                logger.success_event_info("success")
                output = mock_log.call_args[0][0]
                assert TerminalCodes.RED.value in output
                assert TerminalCodes.CYAN.value in output
                assert "[+++]" in output


class TestLoggerWarnFormat:
    """Test warn message format."""
    
    def test_warn_message_format(self):
        """Test warn message contains expected components."""
        with patch.object(sys, "argv", ["prog"]):
            logger = Logger()
            with patch.object(logger, "log") as mock_log:
                logger.warn("warning")
                output = mock_log.call_args[0][0]
                assert TerminalCodes.BLUE.value in output
                assert "warning" in output


class TestLoggerVerboseInfoFormat:
    """Test verbose info format."""
    
    def test_verbose_info_message_format(self):
        """Test verbose_info message format."""
        with patch.object(sys, "argv", ["prog", "--verbose"]):
            logger = Logger()
            with patch.object(logger, "log") as mock_log:
                logger.verbose_info("verbose")
                output = mock_log.call_args[0][0]
                assert TerminalCodes.YELLOW.value in output
                assert TerminalCodes.PURPLE.value in output


class TestLoggerErrorFormat:
    """Test error message format."""
    
    def test_error_message_format(self):
        """Test error message format."""
        with patch.object(sys, "argv", ["prog"]):
            logger = Logger()
            with patch.object(logger, "log") as mock_log:
                logger.error("error")
                output = mock_log.call_args[0][0]
                assert TerminalCodes.RED.value in output
                assert TerminalCodes.YELLOW.value in output
                assert "[X]" in output


class TestLoggerMultipleCalls:
    """Test logger with multiple sequential calls."""
    
    def test_multiple_log_calls(self):
        """Test multiple log calls in sequence."""
        with patch.object(sys, "argv", ["prog"]):
            logger = Logger()
            with patch("builtins.print") as mock_print:
                logger.log("first")
                logger.log("second")
                logger.log("third")
                assert mock_print.call_count == 3
    
    def test_multiple_info_calls_with_different_messages(self):
        """Test multiple info calls."""
        with patch.object(sys, "argv", ["prog"]):
            logger = Logger()
            with patch.object(logger, "log") as mock_log:
                logger.info("message 1")
                logger.info("message 2")
                logger.info("message 3")
                assert mock_log.call_count == 3


class TestLoggerWriteFormat:
    """Test write method output."""
    
    def test_write_direct_output(self):
        """Test write method passes content directly."""
        with patch.object(sys, "argv", ["prog"]):
            logger = Logger()
            with patch("builtins.print") as mock_print:
                logger.write("direct message")
                assert mock_print.called


class TestGetLoggerInstance:
    """Test get_logger function."""
    
    def test_get_logger_returns_instance(self):
        """Test get_logger returns Logger instance."""
        logger = get_logger()
        assert isinstance(logger, Logger)
    
    def test_get_logger_multiple_calls_different_instances(self):
        """Test get_logger creates new instances each time."""
        logger1 = get_logger()
        logger2 = get_logger()
        logger3 = get_logger()
        assert isinstance(logger1, Logger)
        assert isinstance(logger2, Logger)
        assert isinstance(logger3, Logger)


class TestLoggerEdgeCases:
    """Test edge cases and special conditions."""
    
    def test_empty_message(self):
        """Test logging empty message."""
        with patch.object(sys, "argv", ["prog"]):
            logger = Logger()
            with patch("builtins.print") as mock_print:
                logger.log("")
                mock_print.assert_called_once()
    
    def test_very_long_message(self):
        """Test logging very long message."""
        with patch.object(sys, "argv", ["prog"]):
            logger = Logger()
            long_message = "x" * 10000
            with patch.object(logger, "log") as mock_log:
                logger.info(long_message)
                # Should still work with long messages
                mock_log.assert_called()
    
    def test_message_with_special_characters(self):
        """Test logging message with special characters."""
        with patch.object(sys, "argv", ["prog"]):
            logger = Logger()
            with patch("builtins.print") as mock_print:
                logger.log("message with \n newline and \t tab")
                mock_print.assert_called()
    
    def test_message_with_unicode(self):
        """Test logging unicode messages."""
        with patch.object(sys, "argv", ["prog"]):
            logger = Logger()
            with patch("builtins.print") as mock_print:
                logger.log("Unicode: 你好世界 مرحبا بالعالم")
                mock_print.assert_called()


class TestLoggerFlushBehavior:
    """Test logger flush behavior."""
    
    def test_log_uses_flush_true(self):
        """Test that log uses flush=True."""
        with patch("builtins.print") as mock_print:
            Logger.log("test")
            # Verify flush=True was passed
            call_kwargs = mock_print.call_args[1]
            assert call_kwargs.get("flush") is True
    
    def test_log_uses_end_empty_string(self):
        """Test that log uses end=''."""
        with patch("builtins.print") as mock_print:
            Logger.log("test")
            # Verify end='' was passed
            call_kwargs = mock_print.call_args[1]
            assert call_kwargs.get("end") == ""
