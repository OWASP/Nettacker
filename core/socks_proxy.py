import socket


def getaddrinfo(*args):
    """
    same getaddrinfo() used in socket except its resolve addresses with socks proxy

    Args:
        args: *args

    Returns:
        getaddrinfo
    """
    return [(socket.AF_INET, socket.SOCK_STREAM, 6, '', (args[0], args[1]))]


def set_socks_proxy(socks_proxy):
    if socks_proxy:
        import socks
        socks_version = socks.SOCKS5 if socks_proxy.startswith('socks5://') else socks.SOCKS4
        socks_proxy = socks_proxy.split('://')[1] if '://' in socks_proxy else socks_proxy
        if '@' in socks_proxy:
            socks_username = socks_proxy.split(':')[0]
            socks_password = socks_proxy.split(':')[1].split('@')[0]
            socks.set_default_proxy(
                socks_version,
                str(socks_proxy.rsplit('@')[1].rsplit(':')[0]),  # hostname
                int(socks_proxy.rsplit(':')[-1]),  # port
                username=socks_username,
                password=socks_password
            )
        else:
            socks.set_default_proxy(
                socks_version,
                str(socks_proxy.rsplit(':')[0]),  # hostname
                int(socks_proxy.rsplit(':')[1])  # port
            )
        return socks.socksocket, getaddrinfo
    else:
        return socket.socket, socket.getaddrinfo
