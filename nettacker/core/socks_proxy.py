import socket


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
    """
    Configure SOCKS proxy settings for the application.
    
    Args:
        socks_proxy: Proxy string in format 'socks5://username:password@host:port'
                    or 'socks5://host:port' for unauthenticated proxy
    
    Returns:
        tuple: (socket_class, getaddrinfo_function) if proxy configured,
               (socket.socket, socket.getaddrinfo) otherwise
    """
    if socks_proxy:
        import socks

        socks_version = socks.SOCKS5 if socks_proxy.startswith("socks5://") else socks.SOCKS4
        socks_proxy = socks_proxy.split("://")[1] if "://" in socks_proxy else socks_proxy

        if "@" in socks_proxy:
            # Parse credentials from format: username:password@host:port
            # Use rsplit to handle '@' characters in passwords correctly
            auth_part, host_part = socks_proxy.rsplit("@", 1)

            # Split credentials safely
            auth_parts = auth_part.split(":", 1)
            socks_username = auth_parts[0]
            socks_password = auth_parts[1] if len(auth_parts) > 1 else ""

            # Split host and port safely with error handling
            host_parts = host_part.rsplit(":", 1)
            hostname = host_parts[0]
            if len(host_parts) > 1:
                try:
                    port = int(host_parts[1])
                except ValueError:
                    port = 1080  # Default SOCKS port
            else:
                port = 1080

            socks.set_default_proxy(
                socks_version,
                str(hostname),
                port,
                username=socks_username,
                password=socks_password,
            )
        else:
            # Parse host:port without credentials
            host_parts = socks_proxy.rsplit(":", 1)
            hostname = host_parts[0]
            if len(host_parts) > 1:
                try:
                    port = int(host_parts[1])
                except ValueError:
                    port = 1080  # Default SOCKS port
            else:
                port = 1080

            socks.set_default_proxy(
                socks_version,
                str(hostname),
                port,
            )
        return socks.socksocket, getaddrinfo
    else:
        return socket.socket, socket.getaddrinfo
