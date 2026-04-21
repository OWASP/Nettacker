"""Tests for socks_proxy module - specifically for issue #1214 fix."""
import socket
from unittest.mock import patch, MagicMock

import pytest


class TestSetSocksProxyWithoutProxy:
    """Test set_socks_proxy when no proxy is provided."""

    def test_returns_default_socket_when_none(self):
        """Test that None proxy returns default socket objects."""
        from nettacker.core.socks_proxy import set_socks_proxy
        
        sock, getaddr = set_socks_proxy(None)
        assert sock == socket.socket
        assert getaddr == socket.getaddrinfo

    def test_returns_default_socket_when_empty_string(self):
        """Test that empty string proxy returns default socket objects."""
        from nettacker.core.socks_proxy import set_socks_proxy
        
        sock, getaddr = set_socks_proxy("")
        assert sock == socket.socket
        assert getaddr == socket.getaddrinfo


class TestSetSocksProxyMalformedInput:
    """Test set_socks_proxy with malformed input - Issue #1214."""

    @patch("nettacker.core.die.die_failure")
    def test_malformed_at_without_colon_calls_die_failure(self, mock_die):
        """Test that 'user@hostname' (no colon) calls die_failure."""
        # Mock die_failure to prevent actual exit
        mock_die.side_effect = SystemExit(1)
        
        from nettacker.core.socks_proxy import set_socks_proxy
        
        with pytest.raises(SystemExit):
            set_socks_proxy("user@hostname:8080")
        
        mock_die.assert_called_once()
        # Verify error message mentions expected format
        call_args = str(mock_die.call_args)
        assert "username:password@host:port" in call_args

    @patch("nettacker.core.die.die_failure")
    def test_socks5_malformed_at_without_colon(self, mock_die):
        """Test that 'socks5://admin@server:8080' calls die_failure."""
        mock_die.side_effect = SystemExit(1)
        
        from nettacker.core.socks_proxy import set_socks_proxy
        
        with pytest.raises(SystemExit):
            set_socks_proxy("socks5://admin@server:8080")
        
        mock_die.assert_called_once()

    @patch("nettacker.core.die.die_failure")
    def test_socks4_malformed_at_without_colon(self, mock_die):
        """Test that 'socks4://user@host:1080' calls die_failure."""
        mock_die.side_effect = SystemExit(1)
        
        from nettacker.core.socks_proxy import set_socks_proxy
        
        with pytest.raises(SystemExit):
            set_socks_proxy("socks4://user@host:1080")
        
        mock_die.assert_called_once()


class TestSetSocksProxyValidInput:
    """Test set_socks_proxy with valid formatted input."""

    @patch("socks.set_default_proxy")
    @patch("socks.socksocket")
    def test_valid_socks5_with_credentials(self, mock_socksocket, mock_set_proxy):
        """Test valid socks5://user:pass@host:port format."""
        from nettacker.core.socks_proxy import set_socks_proxy
        
        result = set_socks_proxy("socks5://myuser:mypass@proxy.example.com:1080")
        
        assert mock_set_proxy.called
        # Verify credentials were parsed correctly
        call_args = mock_set_proxy.call_args
        assert call_args[1]["username"] == "myuser"
        assert call_args[1]["password"] == "mypass"

    @patch("socks.set_default_proxy")
    @patch("socks.socksocket")
    def test_password_with_colon(self, mock_socksocket, mock_set_proxy):
        """Test that passwords containing colons are handled correctly."""
        from nettacker.core.socks_proxy import set_socks_proxy
        
        # Password "pass:word" contains a colon
        result = set_socks_proxy("socks5://myuser:pass:word@proxy.example.com:1080")
        
        assert mock_set_proxy.called
        call_args = mock_set_proxy.call_args
        assert call_args[1]["username"] == "myuser"
        assert call_args[1]["password"] == "pass:word"  # Full password preserved

    @patch("socks.set_default_proxy")
    @patch("socks.socksocket")
    def test_password_with_at_symbol(self, mock_socksocket, mock_set_proxy):
        """Test that passwords containing @ are handled correctly."""
        from nettacker.core.socks_proxy import set_socks_proxy
        
        # Password "p@ssword" contains an @ symbol
        result = set_socks_proxy("socks5://myuser:p@ssword@proxy.example.com:1080")
        
        assert mock_set_proxy.called
        call_args = mock_set_proxy.call_args
        assert call_args[1]["username"] == "myuser"
        assert call_args[1]["password"] == "p@ssword"  # Full password with @ preserved

