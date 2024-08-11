import logging

from paramiko import SSHClient, AutoAddPolicy
from paramiko.auth_strategy import NoneAuth, Password

from nettacker.core.lib.base import BaseEngine, BaseLibrary

logging.getLogger("paramiko.transport").disabled = True


class SshLibrary(BaseLibrary):
    def brute_force(self, *args, **kwargs):
        host = kwargs["host"]
        port = kwargs["port"]
        username = kwargs["username"]
        password = kwargs["password"]

        connection = SSHClient()
        connection.set_missing_host_key_policy(AutoAddPolicy())
        connection.connect(
            **{
                "hostname": host,
                "port": port,
                "auth_strategy": Password(username=username, password_getter=lambda: password)
                if password
                else NoneAuth(username=username),
            }
        )

        return {
            "host": host,
            "port": port,
            "username": username,
            "password": password,
        }


class SshEngine(BaseEngine):
    library = SshLibrary
