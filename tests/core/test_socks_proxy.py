from unittest.mock import patch, MagicMock

from nettacker.core import socks_proxy as socks_proxy_module

from nettacker.core.socks_proxy import set_socks_proxy


def test_set_socks_proxy_none():
    result = set_socks_proxy(None)
    assert isinstance(result, tuple)
    assert len(result) == 2


@patch("socks.set_default_proxy")
@patch("socks.socksocket")
def test_set_socks_proxy_with_proxy(mock_socksocket, mock_set_default_proxy):
    # Test with a valid SOCKS proxy setup
    socket_factory, resolver = set_socks_proxy("socks5://localhost:1080")
    assert isinstance((socket_factory, resolver), tuple)
    assert socket_factory is mock_socksocket
    assert resolver is socks_proxy_module.getaddrinfo
    mock_set_default_proxy.assert_called_once()
