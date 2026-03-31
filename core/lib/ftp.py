import ftplib

from nettacker.core.lib.base import BaseEngine, BaseLibrary


class FtpLibrary(BaseLibrary):
    client = ftplib.FTP

    def brute_force(self, host, port, username, password, timeout):
        connection = self.client(timeout=timeout)
        connection.connect(host, port)
        connection.login(username, password)
        connection.close()

        return {
            "host": host,
            "port": port,
            "username": username,
            "password": password,
        }


class FtpEngine(BaseEngine):
    library = FtpLibrary
