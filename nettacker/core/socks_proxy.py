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
            # Validate format: username:password@host:port
            # Split credentials from host:port using rightmost @
            parts = socks_proxy.rsplit("@", 1)
            credentials_part = parts[0]
            host_port_part = parts[1]

            # Validate credentials contain a colon separator
            if ":" not in credentials_part:
                die_failure(_("error_socks_proxy_missing_colon"))

            # Parse credentials using split with maxsplit=1 to handle passwords with colons
            credentials_split = credentials_part.split(":", 1)
            socks_username = credentials_split[0]
            socks_password = credentials_split[1]

            # Parse host and port from the host:port part
            host_port_split = host_port_part.rsplit(":", 1)
            if len(host_port_split) != 2:
                die_failure(_("error_socks_proxy_missing_port"))

            # Validate port is numeric
            try:
                port = int(host_port_split[1])
                if port < 1 or port > 65535:
                    die_failure(_("error_socks_proxy_invalid_port").format(host_port_split[1]))
            except ValueError:
                die_failure(_("error_socks_proxy_invalid_port").format(host_port_split[1]))

            socks.set_default_proxy(
                socks_version,
                str(host_port_split[0]),  # hostname
                port,
                username=socks_username,
                password=socks_password,
            )
        else:
            # Validate host:port format
            host_port_split = socks_proxy.rsplit(":", 1)
            if len(host_port_split) != 2:
                die_failure(_("error_socks_proxy_missing_port"))
            
            port_str = host_port_split[1]
            try:
                port = int(port_str)
                if port < 1 or port > 65535:
                    die_failure(_("error_socks_proxy_invalid_port").format(port_str))
            except ValueError:
                die_failure(_("error_socks_proxy_invalid_port").format(port_str))

            socks.set_default_proxy(
                socks_version,
                str(host_port_split[0]),  # hostname
                port,
            )
        return socks.socksocket, getaddrinfo
    else:
        return socket.socket, socket.getaddrinfo
