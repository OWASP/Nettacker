from impacket.smbconnection import SMBConnection

from nettacker.core.lib.base import BaseEngine, BaseLibrary


def create_connection(host, port):
    return SMBConnection(host, remoteHost=host, sess_port=port)


class SmbLibrary(BaseLibrary):
    def brute_force(self, *args, **kwargs):
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
