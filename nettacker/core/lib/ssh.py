import logging
import socket
from paramiko import SSHClient, AutoAddPolicy, AuthenticationException, SSHException
from paramiko.auth_strategy import NoneAuth, Password
from nettacker.core.lib.base import BaseEngine, BaseLibrary

logging.getLogger("paramiko.transport").disabled = True

class SshLibrary(BaseLibrary):
    client = SSHClient

    def brute_force(self, *args, **kwargs):
        host = kwargs["host"]
        port = kwargs["port"]
        username = kwargs["username"]
        password = kwargs.get("password")
        timeout = kwargs.get("timeout", 3)

        connection = self.client()
        connection.set_missing_host_key_policy(AutoAddPolicy())

        try:
            connection.connect(
                hostname=host,
                port=port,
                auth_strategy=Password(username=username, password_getter=lambda: password) if password else NoneAuth(username=username),
                timeout=timeout,
                look_for_keys=False,
                allow_agent=False,
                banner_timeout=timeout,
            )
            transport = connection.get_transport()
            if not transport or not transport.is_active():
                return {}
            return {
                "host": host,
                "port": port,
                "username": username,
                "password": password if password else "",
            }

        except AuthenticationException:
            return {}
        except SSHException:
            return {}
        except (socket.timeout, socket.error, ConnectionRefusedError, OSError):
            return {}
        except Exception:
            return {}
        finally:
            try:
                connection.close()
            except Exception:
                pass

class SshEngine(BaseEngine):
    library = SshLibrary
