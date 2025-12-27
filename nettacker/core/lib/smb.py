from nettacker.core.lib.base import BaseEngine, BaseLibrary

# impacket is optional - SMB features will be disabled if not available
try:
    from impacket.smbconnection import SMBConnection

    IMPACKET_AVAILABLE = True
except ImportError:
    IMPACKET_AVAILABLE = False
    SMBConnection = None


def create_connection(host, port):
    if not IMPACKET_AVAILABLE:
        raise ImportError("impacket is required for SMB connections. Please install it with: pip install impacket")
    return SMBConnection(host, remoteHost=host, sess_port=port)


class SmbLibrary(BaseLibrary):
    def brute_force(self, *args, **kwargs):
        if not IMPACKET_AVAILABLE:
            raise ImportError("impacket is required for SMB brute force. Please install it with: pip install impacket")
        
        host = kwargs["host"]
        port = kwargs["port"]
        username = kwargs["username"]

        response = {
            "host": host,
            "port": port,
            "username": username,
        }

        domain = "."
        if "domain" in kwargs:
            domain = kwargs["domain"]
            response.update({"domain": domain})

        password = ""
        if "password" in kwargs:
            password = kwargs["password"]
            response.update({"password": password})

        lm = ""
        if "lm" in kwargs:
            lm = kwargs["lm"]
            response.update({"lm": lm})

        nt = ""
        if "nt" in kwargs:
            nt = kwargs["nt"]
            response.update({"nt": nt})

        connection = create_connection(host, port)
        connection.login(username, password, domain, lm, nt)

        return response


class SmbEngine(BaseEngine):
    library = SmbLibrary
