from unittest.mock import patch, MagicMock

from nettacker.core.socks_proxy import set_socks_proxy


def test_set_socks_proxy_none():
    result = set_socks_proxy(None)
    assert isinstance(result, tuple)
    assert len(result) == 2


@patch("socks.socksocket")
@patch("socket.getaddrinfo")
def test_set_socks_proxy_with_proxy(mock_getaddrinfo, mock_socksocket):
    # Test with a valid SOCKS proxy setup
    result = set_socks_proxy("socks5://localhost:1080")
    assert isinstance(result, tuple)
    assert len(result) == 2
