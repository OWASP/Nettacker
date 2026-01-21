"""
Unit tests for socks_proxy module, specifically testing set_socks_proxy() validation
"""

from unittest.mock import patch, MagicMock
import pytest

from nettacker.core.socks_proxy import set_socks_proxy


class TestSetSocksProxy:
    """Test suite for set_socks_proxy function"""

    def test_valid_socks5_proxy_with_auth(self):
        """Test valid SOCKS5 proxy with authentication"""
        # Mock the socks module before it gets imported
        mock_socks = MagicMock()
        mock_socks.SOCKS5 = 2
        mock_socks.SOCKS4 = 1
        mock_socks.socksocket = MagicMock()
        
        with patch.dict('sys.modules', {'socks': mock_socks}):
            set_socks_proxy("socks5://user:pass@proxy.example.com:1080")
            
            mock_socks.set_default_proxy.assert_called_once_with(
                2,  # SOCKS5
                "proxy.example.com",
                1080,
                username="user",
                password="pass"
            )

    def test_valid_socks4_proxy_with_auth(self):
        """Test valid SOCKS4 proxy with authentication"""
        mock_socks = MagicMock()
        mock_socks.SOCKS4 = 1
        mock_socks.SOCKS5 = 2
        mock_socks.socksocket = MagicMock()
        
        with patch.dict('sys.modules', {'socks': mock_socks}):
            set_socks_proxy("user:pass@proxy.example.com:1080")
            
            mock_socks.set_default_proxy.assert_called_once_with(
                1,  # SOCKS4
                "proxy.example.com",
                1080,
                username="user",
                password="pass"
            )

    def test_valid_proxy_without_auth(self):
        """Test valid proxy without authentication"""
        mock_socks = MagicMock()
        mock_socks.SOCKS5 = 2
        mock_socks.SOCKS4 = 1
        mock_socks.socksocket = MagicMock()
        
        with patch.dict('sys.modules', {'socks': mock_socks}):
            set_socks_proxy("socks5://proxy.example.com:1080")
            
            mock_socks.set_default_proxy.assert_called_once_with(
                2,  # SOCKS5
                "proxy.example.com",
                1080
            )

    @patch("sys.exit")
    def test_malformed_proxy_missing_colon_in_credentials(self, mock_exit):
        """Test that malformed proxy with @ but no : raises error (Bug #1214)"""
        # Make sys.exit actually raise SystemExit so code stops executing
        mock_exit.side_effect = SystemExit(1)
        
        mock_socks = MagicMock()
        mock_socks.SOCKS4 = 1
        mock_socks.SOCKS5 = 2
        
        with patch.dict('sys.modules', {'socks': mock_socks}):
            with pytest.raises(SystemExit) as exc_info:
                set_socks_proxy("user@proxy.example.com:1080")
            
            # Verify exit code
            assert exc_info.value.code == 1

    @patch("sys.exit")
    def test_malformed_proxy_missing_colon_with_scheme(self, mock_exit):
        """Test malformed proxy with scheme but missing credentials separator"""
        mock_exit.side_effect = SystemExit(1)
        
        mock_socks = MagicMock()
        mock_socks.SOCKS4 = 1
        mock_socks.SOCKS5 = 2
        
        with patch.dict('sys.modules', {'socks': mock_socks}):
            with pytest.raises(SystemExit) as exc_info:
                set_socks_proxy("socks5://admin@server:1080")
            
            assert exc_info.value.code == 1

    @patch("sys.exit")
    def test_malformed_proxy_username_only(self, mock_exit):
        """Test malformed proxy with only username, no password or host"""
        mock_exit.side_effect = SystemExit(1)
        
        mock_socks = MagicMock()
        mock_socks.SOCKS4 = 1
        mock_socks.SOCKS5 = 2
        
        with patch.dict('sys.modules', {'socks': mock_socks}):
            with pytest.raises(SystemExit) as exc_info:
                set_socks_proxy("user@hostname")
            
            assert exc_info.value.code == 1

    def test_none_proxy_returns_socket(self):
        """Test that None proxy returns standard socket"""
        import socket
        result = set_socks_proxy(None)
        
        assert result == (socket.socket, socket.getaddrinfo)

    def test_empty_string_returns_socket(self):
        """Test that empty string returns standard socket"""
        import socket
        result = set_socks_proxy("")
        
        assert result == (socket.socket, socket.getaddrinfo)

    def test_proxy_with_special_chars_in_password(self):
        """Test proxy with special characters in password"""
        mock_socks = MagicMock()
        mock_socks.SOCKS5 = 2
        mock_socks.SOCKS4 = 1
        mock_socks.socksocket = MagicMock()
        
        with patch.dict('sys.modules', {'socks': mock_socks}):
            set_socks_proxy("socks5://user:p@ss:w0rd!@proxy.example.com:1080")
            
            # The password should be everything between first : and @
            mock_socks.set_default_proxy.assert_called_once_with(
                2,
                "proxy.example.com",
                1080,
                username="user",
                password="p@ss:w0rd!"
            )

    def test_proxy_with_numeric_credentials(self):
        """Test proxy with numeric credentials"""
        mock_socks = MagicMock()
        mock_socks.SOCKS4 = 1
        mock_socks.SOCKS5 = 2
        mock_socks.socksocket = MagicMock()
        
        with patch.dict('sys.modules', {'socks': mock_socks}):
            set_socks_proxy("123:456@proxy.example.com:1080")
            
            mock_socks.set_default_proxy.assert_called_once_with(
                1,
                "proxy.example.com",
                1080,
                username="123",
                password="456"
            )

    def test_proxy_without_scheme_defaults_to_socks4(self):
        """Test that proxy without scheme defaults to SOCKS4"""
        mock_socks = MagicMock()
        mock_socks.SOCKS4 = 1
        mock_socks.SOCKS5 = 2
        mock_socks.socksocket = MagicMock()
        
        with patch.dict('sys.modules', {'socks': mock_socks}):
            set_socks_proxy("user:pass@proxy.example.com:1080")
            
            # Should use SOCKS4 (not SOCKS5) when no scheme specified
            assert mock_socks.set_default_proxy.call_args[0][0] == 1

    def test_proxy_with_socks5_scheme(self):
        """Test that socks5:// scheme uses SOCKS5"""
        mock_socks = MagicMock()
        mock_socks.SOCKS4 = 1
        mock_socks.SOCKS5 = 2
        mock_socks.socksocket = MagicMock()
        
        with patch.dict('sys.modules', {'socks': mock_socks}):
            set_socks_proxy("socks5://user:pass@proxy.example.com:1080")
            
            # Should use SOCKS5
            assert mock_socks.set_default_proxy.call_args[0][0] == 2
    def test_proxy_with_invalid_port_non_numeric(self):
        """Test that non-numeric port raises error"""
        from nettacker.core.die import die_failure
        
        mock_socks = MagicMock()
        mock_socks.SOCKS4 = 1
        mock_socks.SOCKS5 = 2
        
        with patch.dict('sys.modules', {'socks': mock_socks}):
            with patch('nettacker.core.socks_proxy.die_failure', side_effect=die_failure) as mock_die:
                with pytest.raises(SystemExit):
                    set_socks_proxy("proxy.example.com:abc")
                
                # Should call die_failure with invalid port error
                assert mock_die.called
                error_msg = str(mock_die.call_args[0][0])
                assert "Invalid SOCKS proxy port" in error_msg
                assert "abc" in error_msg

    def test_proxy_with_invalid_port_out_of_range_low(self):
        """Test that port < 1 raises error"""
        from nettacker.core.die import die_failure
        
        mock_socks = MagicMock()
        mock_socks.SOCKS4 = 1
        mock_socks.SOCKS5 = 2
        
        with patch.dict('sys.modules', {'socks': mock_socks}):
            with patch('nettacker.core.socks_proxy.die_failure', side_effect=die_failure) as mock_die:
                with pytest.raises(SystemExit):
                    set_socks_proxy("proxy.example.com:0")
                
                # Should call die_failure with invalid port error
                assert mock_die.called
                error_msg = str(mock_die.call_args[0][0])
                assert "Invalid SOCKS proxy port" in error_msg

    def test_proxy_with_invalid_port_out_of_range_high(self):
        """Test that port > 65535 raises error"""
        from nettacker.core.die import die_failure
        
        mock_socks = MagicMock()
        mock_socks.SOCKS4 = 1
        mock_socks.SOCKS5 = 2
        
        with patch.dict('sys.modules', {'socks': mock_socks}):
            with patch('nettacker.core.socks_proxy.die_failure', side_effect=die_failure) as mock_die:
                with pytest.raises(SystemExit):
                    set_socks_proxy("proxy.example.com:65536")
                
                # Should call die_failure with invalid port error
                assert mock_die.called
                error_msg = str(mock_die.call_args[0][0])
                assert "Invalid SOCKS proxy port" in error_msg

    def test_authenticated_proxy_with_invalid_port_non_numeric(self):
        """Test that non-numeric port in authenticated proxy raises error"""
        from nettacker.core.die import die_failure
        
        mock_socks = MagicMock()
        mock_socks.SOCKS4 = 1
        mock_socks.SOCKS5 = 2
        
        with patch.dict('sys.modules', {'socks': mock_socks}):
            with patch('nettacker.core.socks_proxy.die_failure', side_effect=die_failure) as mock_die:
                with pytest.raises(SystemExit):
                    set_socks_proxy("user:pass@proxy.example.com:xyz")
                
                # Should call die_failure with invalid port error
                assert mock_die.called
                error_msg = str(mock_die.call_args[0][0])
                assert "Invalid SOCKS proxy port" in error_msg
                assert "xyz" in error_msg

    def test_authenticated_proxy_with_invalid_port_out_of_range(self):
        """Test that out-of-range port in authenticated proxy raises error"""
        from nettacker.core.die import die_failure
        
        mock_socks = MagicMock()
        mock_socks.SOCKS4 = 1
        mock_socks.SOCKS5 = 2
        
        with patch.dict('sys.modules', {'socks': mock_socks}):
            with patch('nettacker.core.socks_proxy.die_failure', side_effect=die_failure) as mock_die:
                with pytest.raises(SystemExit):
                    set_socks_proxy("user:pass@proxy.example.com:99999")
                
                # Should call die_failure with invalid port error
                assert mock_die.called
                error_msg = str(mock_die.call_args[0][0])
                assert "Invalid SOCKS proxy port" in error_msg