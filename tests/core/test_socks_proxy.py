import socket
from unittest.mock import MagicMock, patch

from nettacker.core.socks_proxy import getaddrinfo, set_socks_proxy


def test_getaddrinfo_returns_correct_format():
    result = getaddrinfo("127.0.0.1", 8080)
    assert len(result) == 1
    family, socktype, proto, canonname, sockaddr = result[0]
    assert family == socket.AF_INET
    assert socktype == socket.SOCK_STREAM
    assert proto == 6
    assert canonname == ""
    assert sockaddr == ("127.0.0.1", 8080)


def test_getaddrinfo_with_domain():
    result = getaddrinfo("example.com", 443)
    assert result[0][4] == ("example.com", 443)


def test_set_socks_proxy_none_returns_default_socket():
    sock, resolver = set_socks_proxy(None)
    assert sock is socket.socket
    assert resolver is socket.getaddrinfo


def test_set_socks_proxy_empty_string_returns_default_socket():
    sock, resolver = set_socks_proxy("")
    assert sock is socket.socket
    assert resolver is socket.getaddrinfo


@patch("nettacker.core.socks_proxy.socks", create=True)
def test_set_socks_proxy_socks5(mock_socks):
    mock_socks.SOCKS5 = 2
    mock_socks.SOCKS4 = 1
    mock_socks.socksocket = MagicMock()

    with patch.dict("sys.modules", {"socks": mock_socks}):
        sock, resolver = set_socks_proxy("socks5://127.0.0.1:1080")

    mock_socks.set_default_proxy.assert_called_once_with(
        2, "127.0.0.1", 1080
    )
    assert sock is mock_socks.socksocket
    assert resolver is getaddrinfo


@patch("nettacker.core.socks_proxy.socks", create=True)
def test_set_socks_proxy_socks4(mock_socks):
    mock_socks.SOCKS5 = 2
    mock_socks.SOCKS4 = 1
    mock_socks.socksocket = MagicMock()

    with patch.dict("sys.modules", {"socks": mock_socks}):
        sock, resolver = set_socks_proxy("socks4://192.168.1.1:9050")

    mock_socks.set_default_proxy.assert_called_once_with(
        1, "192.168.1.1", 9050
    )


@patch("nettacker.core.socks_proxy.socks", create=True)
def test_set_socks_proxy_with_auth(mock_socks):
    mock_socks.SOCKS5 = 2
    mock_socks.SOCKS4 = 1
    mock_socks.socksocket = MagicMock()

    with patch.dict("sys.modules", {"socks": mock_socks}):
        sock, resolver = set_socks_proxy("socks5://user:pass@proxy.example.com:1080")

    mock_socks.set_default_proxy.assert_called_once_with(
        2, "proxy.example.com", 1080,
        username="user", password="pass"
    )
