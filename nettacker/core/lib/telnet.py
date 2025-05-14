import telnetlib

from nettacker.core.lib.base import BaseEngine, BaseLibrary


class TelnetLibrary(BaseLibrary):
    client = telnetlib.Telnet

    def brute_force(self, host, port, username, password, timeout):
        connection = self.client(host, port, timeout)
        connection.read_until(b"login: ")
        connection.write(username.encode("utf-8") + b"\n")
        connection.read_until(b"Password: ")
        connection.write(password.encode("utf-8") + b"\n")
        connection.close()

        return {
            "host": host,
            "port": port,
            "username": username,
            "password": password,
        }


class TelnetEngine(BaseEngine):
    library = TelnetLibrary
