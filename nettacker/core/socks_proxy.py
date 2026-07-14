import re
import socket

from nettacker.core.die import die_failure
from nettacker.core.messages import messages as _


def getaddrinfo(*args):
    """
    same getaddrinfo() used in socket except its resolve addresses with socks proxy

    Args:
        args: *args

    Returns:
        getaddrinfo
    """
    return [(socket.AF_INET, socket.SOCK_STREAM, 6, "", (args[0], args[1]))]


def set_socks_proxy(socks_proxy):
    if socks_proxy:
        import socks

        socks_version = socks.SOCKS5 if socks_proxy.startswith("socks5://") else socks.SOCKS4
        socks_proxy = socks_proxy.split("://")[1] if "://" in socks_proxy else socks_proxy
        
        if "@" in socks_proxy:
            if not re.match(r'^[^:@]+:.+@.+:\d+$', socks_proxy):  # One-line regex validation
                die_failure(_("error_socks_proxy_invalid_format"))
            credentials, host_port = socks_proxy.rsplit("@", 1)
            socks_username, socks_password = credentials.split(":", 1)
            socks_host, socks_port = host_port.rsplit(":", 1)
            port = int(socks_port)
            if not (1 <= port <= 65535):
                die_failure(_("error_socks_proxy_invalid_port").format(socks_port))
            socks.set_default_proxy(
                socks_version, socks_host, port,
                username=socks_username, password=socks_password,
            )
        else:
            if not re.match(r'^.+:\d+$', socks_proxy):  # One-line regex validation
                die_failure(_("error_socks_proxy_invalid_format"))
            socks_host, socks_port = socks_proxy.rsplit(":", 1)
            port = int(socks_port)
            if not (1 <= port <= 65535):
                die_failure(_("error_socks_proxy_invalid_port").format(socks_port))
            socks.set_default_proxy(socks_version, socks_host, port)
        
        return socks.socksocket, getaddrinfo
    else:
        return socket.socket, socket.getaddrinfo
