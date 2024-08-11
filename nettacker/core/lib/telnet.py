import telnetlib

from nettacker.core.lib.base import BaseEngine, BaseLibrary


class TelnetLibrary(BaseLibrary):
    client = telnetlib.Telnet

    def brute_force(host, port, username, password, timeout):
        connection = telnetlib.Telnet(host, port, timeout)
        connection.read_until(b"login: ")
        connection.write(username + "\n")
        connection.read_until(b"Password: ")
        connection.write(password + "\n")
        connection.close()

        return {
            "host": host,
            "port": port,
            "username": username,
            "password": password,
        }


class TelnetEngine(BaseEngine):
    library = TelnetLibrary
