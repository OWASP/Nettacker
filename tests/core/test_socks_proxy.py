import socket
from unittest.mock import patch

import socks

from nettacker.core.socks_proxy import getaddrinfo, set_socks_proxy


class TestGetAddrInfo:
    def test_returns_correct_format(self):
        result = getaddrinfo("example.com", 80)
        assert result == [(socket.AF_INET, socket.SOCK_STREAM, 6, "", ("example.com", 80))]

    def test_returns_list_with_one_element(self):
        result = getaddrinfo("192.168.1.1", 443)
        assert len(result) == 1

    def test_preserves_host_and_port(self):
        result = getaddrinfo("target.com", 8080)
        assert result[0][4] == ("target.com", 8080)


class TestSetSocksProxy:
    def test_no_proxy_returns_default_socket(self):
        socket_func, addr_func = set_socks_proxy(None)
        assert socket_func == socket.socket
        assert addr_func == socket.getaddrinfo

    @patch("socks.set_default_proxy")
    @patch("socks.socksocket")
    def test_socks5_without_auth(self, mock_socksocket, mock_set_proxy):
        socket_func, addr_func = set_socks_proxy("socks5://myhost:1080")

        mock_set_proxy.assert_called_once_with(
            socks.SOCKS5,
            "myhost",
            1080,
        )

    @patch("socks.set_default_proxy")
    @patch("socks.socksocket")
    def test_socks4_without_auth(self, mock_socksocket, mock_set_proxy):
        socket_func, addr_func = set_socks_proxy("socks4://myhost:1080")

        mock_set_proxy.assert_called_once_with(
            socks.SOCKS4,
            "myhost",
            1080,
        )

    @patch("socks.set_default_proxy")
    @patch("socks.socksocket")
    def test_socks5_with_auth(self, mock_socksocket, mock_set_proxy):
        socket_func, addr_func = set_socks_proxy("socks5://user:pass@myhost:1080")

        mock_set_proxy.assert_called_once_with(
            socks.SOCKS5,
            "myhost",
            1080,
            username="user",
            password="pass",
        )
