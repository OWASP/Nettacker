import re
import telnetlib

from nettacker.core.lib.base import BaseEngine, BaseLibrary


class TelnetLoginError(Exception):
    """Raised when a telnet login attempt was not confirmed as successful."""


class TelnetLibrary(BaseLibrary):
    client = telnetlib.Telnet

    login_prompt = b"login: "
    password_prompt = b"Password: "

    # Specific phrases that mean the server rejected the login. A bare "failed" is deliberately
    # not listed: a successful login can print a banner like "Last failed login: ...". The
    # prompts reappearing at the end of the reply also mean the login was rejected.
    failure_markers = (
        rb"login incorrect",
        rb"login failed",
        rb"login invalid",
        rb"invalid login",
        rb"authentication (?:failed|failure)",
        rb"access denied",
        rb"permission denied",
        rb"(?:incorrect|invalid|wrong|bad) password",
        rb"(?<!Last )login: \Z",
        rb"Password: \Z",
    )

    # Positive evidence of a successful login: a "Last login" line or a conservative shell
    # prompt on the last line (one word without "<" or ">" that ends in one of > $ # %).
    success_markers = (
        rb"Last login",
        rb"(?:\A|[\r\n])[^\s<>$#%]{0,64}(?:>| ?[$#%]) ?\Z",
    )

    def brute_force(self, host, port, username, password, timeout):
        connection = self.client(host, port, timeout)
        try:
            self.read_prompt(connection, self.login_prompt, timeout)
            connection.write(username.encode("utf-8") + b"\n")
            self.read_prompt(connection, self.password_prompt, timeout)
            connection.write(password.encode("utf-8") + b"\n")
            self.confirm_login(connection, timeout)
        finally:
            connection.close()

        return {
            "host": host,
            "port": port,
            "username": username,
            "password": password,
        }

    def read_prompt(self, connection, prompt, timeout):
        """Wait up to timeout seconds for the prompt and raise if it did not arrive."""
        if not connection.read_until(prompt, timeout).endswith(prompt):
            raise TelnetLoginError(f"prompt {prompt!r} not received")

    def confirm_login(self, connection, timeout):
        """Read the server's reply to the password and raise unless it confirms the login."""
        failure = re.compile(b"|".join(self.failure_markers), re.IGNORECASE)
        success = re.compile(b"|".join(self.success_markers))
        # The failure patterns come first, so they win when both match the same reply.
        index, _, reply = connection.expect([failure, success], timeout)
        if index != 1:
            raise TelnetLoginError(f"login not confirmed, reply: {reply[-80:]!r}")


class TelnetEngine(BaseEngine):
    library = TelnetLibrary
