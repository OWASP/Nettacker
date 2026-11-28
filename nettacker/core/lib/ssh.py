import logging

from paramiko import AutoAddPolicy, SSHClient
from paramiko.auth_strategy import AuthStrategy, NoneAuth, Password

from nettacker.core.lib.base import BaseEngine, BaseLibrary

logging.getLogger("paramiko.transport").disabled = True


class RepeatedPasswordAuthStrategy(AuthStrategy):
    """Try one password repeatedly within the same SSH connection."""

    def __init__(self, username, password, attempts):
        super().__init__(ssh_config=None)
        self.username = username
        self.password = password
        self.attempts = attempts

    def get_sources(self):
        for _attempt in range(self.attempts):
            yield Password(
                username=self.username,
                password_getter=lambda: self.password,
            )


class SshLibrary(BaseLibrary):
    client = SSHClient

    def brute_force(self, *args, **kwargs):
        host = kwargs["host"]
        port = kwargs["port"]
        username = kwargs["username"]
        password = kwargs["password"]
        timeout = kwargs.get("timeout")
        authentication_attempts = kwargs.get("authentication_attempts", 1)

        if authentication_attempts < 1:
            raise ValueError("authentication_attempts must be at least 1")

        if not password:
            auth_strategy = NoneAuth(username=username)
        elif authentication_attempts == 1:
            auth_strategy = Password(username=username, password_getter=lambda: password)
        else:
            auth_strategy = RepeatedPasswordAuthStrategy(
                username=username,
                password=password,
                attempts=authentication_attempts,
            )

        connection_options = {
            "hostname": host,
            "port": port,
            "auth_strategy": auth_strategy,
        }
        if timeout is not None:
            connection_options.update(
                {
                    "timeout": timeout,
                    "banner_timeout": timeout,
                    "auth_timeout": timeout,
                }
            )

        connection = self.client()
        connection.set_missing_host_key_policy(AutoAddPolicy())
        try:
            connection.connect(**connection_options)

            return {
                "host": host,
                "port": port,
                "username": username,
                "password": password,
            }
        finally:
            connection.close()


class SshEngine(BaseEngine):
    library = SshLibrary
