import socket
import sys
from unittest.mock import MagicMock, patch

from nettacker.core.socks_proxy import getaddrinfo, set_socks_proxy


class TestGetaddrinfo:
    def test_returns_correct_tuple_format(self):
        result = getaddrinfo("127.0.0.1", 8080)
        assert result == [(socket.AF_INET, socket.SOCK_STREAM, 6, "", ("127.0.0.1", 8080))]

    def test_with_hostname(self):
        result = getaddrinfo("example.com", 443)
        assert result == [(socket.AF_INET, socket.SOCK_STREAM, 6, "", ("example.com", 443))]

    def test_returns_single_element_list(self):
        result = getaddrinfo("10.0.0.1", 1080)
        assert len(result) == 1

    def test_extra_args_ignored(self):
        result = getaddrinfo("host", 80, "extra1", "extra2")
        assert result == [(socket.AF_INET, socket.SOCK_STREAM, 6, "", ("host", 80))]


class TestSetSocksProxyNone:
    def test_returns_stdlib_socket_when_no_proxy(self):
        sock, addr_info = set_socks_proxy(None)
        assert sock is socket.socket
        assert addr_info is socket.getaddrinfo

    def test_returns_stdlib_socket_when_empty_string(self):
        sock, addr_info = set_socks_proxy("")
        assert sock is socket.socket
        assert addr_info is socket.getaddrinfo


class TestSetSocksProxySocks5:
    def test_socks5_no_auth(self):
        mock_socks = MagicMock()
        mock_socks.SOCKS5 = 2
        mock_socks.SOCKS4 = 1

        with patch.dict(sys.modules, {"socks": mock_socks}):
            sock, addr_info = set_socks_proxy("socks5://127.0.0.1:1080")

        mock_socks.set_default_proxy.assert_called_once_with(
            2,  # SOCKS5
            "127.0.0.1",
            1080,
        )
        assert sock is mock_socks.socksocket
        assert addr_info is getaddrinfo

    def test_socks5_with_auth(self):
        mock_socks = MagicMock()
        mock_socks.SOCKS5 = 2
        mock_socks.SOCKS4 = 1

        with patch.dict(sys.modules, {"socks": mock_socks}):
            sock, addr_info = set_socks_proxy("socks5://myuser:mypass@proxy.example.com:9050")

        mock_socks.set_default_proxy.assert_called_once_with(
            2,  # SOCKS5
            "proxy.example.com",
            9050,
            username="myuser",
            password="mypass",
        )
        assert sock is mock_socks.socksocket


class TestSetSocksProxySocks4:
    def test_socks4_no_auth(self):
        mock_socks = MagicMock()
        mock_socks.SOCKS5 = 2
        mock_socks.SOCKS4 = 1

        with patch.dict(sys.modules, {"socks": mock_socks}):
            set_socks_proxy("socks4://10.0.0.1:1080")

        mock_socks.set_default_proxy.assert_called_once_with(
            1,  # SOCKS4
            "10.0.0.1",
            1080,
        )

    def test_no_scheme_defaults_to_socks4(self):
        mock_socks = MagicMock()
        mock_socks.SOCKS5 = 2
        mock_socks.SOCKS4 = 1

        with patch.dict(sys.modules, {"socks": mock_socks}):
            set_socks_proxy("192.168.1.1:1080")

        mock_socks.set_default_proxy.assert_called_once_with(
            1,  # SOCKS4
            "192.168.1.1",
            1080,
        )
