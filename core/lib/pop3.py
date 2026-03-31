import poplib

from nettacker.core.lib.base import BaseEngine, BaseLibrary


class Pop3Library(BaseLibrary):
    client = poplib.POP3

    def brute_force(self, host, port, username, password, timeout):
        connection = self.client(host, port=port, timeout=timeout)
        connection.user(username)
        connection.pass_(password)
        connection.quit()

        return {
            "host": host,
            "port": port,
            "username": username,
            "password": password,
        }


class Pop3Engine(BaseEngine):
    library = Pop3Library
