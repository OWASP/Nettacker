import smtplib

from nettacker.core.lib.base import BaseEngine, BaseLibrary


class SmtpLibrary(BaseLibrary):
    client = smtplib.SMTP

    def brute_force(self, host, port, username, password, timeout):
        connection = self.client(host, port, timeout=timeout)
        connection.login(username, password)
        connection.close()

        return {
            "host": host,
            "port": port,
            "username": username,
            "password": password,
        }


class SmtpEngine(BaseEngine):
    library = SmtpLibrary
