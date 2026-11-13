import re
import selectors
import telnetlib
import time

from nettacker.core.lib.base import BaseEngine, BaseLibrary


class TelnetLoginError(Exception):
    """Raised when a telnet login attempt was not confirmed as successful."""


class TelnetLibrary(BaseLibrary):
    client = telnetlib.Telnet

    login_prompt = b"login: "
    password_prompt = b"Password: "

    # Specific phrases that mean the server rejected the login. A bare "failed" is deliberately
    # not listed: a successful login can print a banner like "Last failed login: ...". They
    # reject the login as soon as they have arrived.
    failure_markers = (
        rb"login incorrect",
        rb"login failed",
        rb"login invalid",
        rb"invalid login",
        rb"authentication (?:failed|failure)",
        rb"access denied",
        rb"permission denied",
        rb"(?:incorrect|invalid|wrong|bad) password",
    )

    # The prompts reappearing at the end of the reply also mean the login was rejected. A banner
    # that comes in pieces can end in "login: " too ("Last failed login: "), so they are only
    # believed once the reply stayed quiet for settle_time seconds or the deadline is reached.
    prompt_markers = (
        rb"(?<!Last )login: \Z",
        rb"Password: \Z",
    )

    # Positive evidence of a successful login: a "Last login" line or a conservative shell
    # prompt on the last line (one word without "<" or ">" that ends in one of > $ # %).
    success_markers = (
        rb"Last login",
        rb"(?:\A|[\r\n])[^\s<>$#%]{0,64}(?:>| ?[$#%]) ?\Z",
    )

    # A success marker or a trailing prompt is only believed once nothing more arrived for
    # settle_time seconds (or the deadline is reached or the server closed the connection), so a
    # reply that comes in pieces is judged as a whole. What arrives after a longer pause than this
    # is not taken into account: a failure after a prompt-like piece is still taken for a success,
    # and the rest of a banner after a piece that ends in "login: " for a failure.
    settle_time = 0.5
    # A prompt read or a reply that grows beyond this many bytes is abandoned as not confirmed.
    max_reply_size = 16 * 1024

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

    def read_chunk(self, connection, wait):
        """Return the data that arrived within wait seconds, or None if nothing did.

        Raises EOFError when the server has closed the connection. Telnet.expect() only checks
        its deadline when nothing is readable, so a server that keeps sending can hold it past
        the timeout, and it searches the whole buffer again after every 50 bytes it reads.
        Reading one chunk at a time lets the callers own the deadline. fill_rawq() (one recv())
        and process_rawq() (telnet option negotiation) are not documented, but read_until() and
        expect() are built on the same two calls and they keep the option handling of telnetlib.
        read_some() was rejected because it loops until it has data, so a stream of nothing but
        option bytes keeps it busy past any deadline. Calling read_until() in short slices was
        rejected because every attempt would then pay for the polling interval.
        """
        pending = connection.read_very_lazy()
        if pending:
            return pending
        # not select.select(), which fails for file descriptors above 1023 on POSIX
        with selectors.DefaultSelector() as selector:
            selector.register(connection.get_socket(), selectors.EVENT_READ)
            if not selector.select(wait):
                return None
        connection.fill_rawq()
        connection.process_rawq()
        return connection.read_very_lazy()  # b"" when there was only option negotiation

    def read_prompt(self, connection, prompt, timeout):
        """Wait up to timeout seconds for the prompt and raise if it did not arrive."""
        deadline = time.monotonic() + timeout
        received = b""
        while prompt not in received:
            wait = deadline - time.monotonic()
            if wait <= 0 or len(received) > self.max_reply_size:
                raise TelnetLoginError(f"prompt {prompt!r} not received")
            received += self.read_chunk(connection, wait) or b""

    def confirm_login(self, connection, timeout):
        """Read the server's reply to the password and raise unless it confirms the login."""
        failure = re.compile(b"|".join(self.failure_markers), re.IGNORECASE)
        prompt = re.compile(b"|".join(self.prompt_markers), re.IGNORECASE)
        success = re.compile(b"|".join(self.success_markers))
        deadline = time.monotonic() + timeout
        reply = b""
        while True:
            wait = deadline - time.monotonic()
            if success.search(reply) or prompt.search(reply):
                wait = min(wait, self.settle_time)  # then the reply must stay quiet this long
            if wait <= 0:
                break
            try:
                chunk = self.read_chunk(connection, wait)
            except EOFError:
                break
            if chunk is None:
                break  # nothing arrived during the whole wait: deadline or quiet period over
            reply += chunk
            if len(reply) > self.max_reply_size:
                raise TelnetLoginError(f"reply larger than {self.max_reply_size} bytes")
            # everything received so far is checked again after every chunk
            if failure.search(reply):
                raise TelnetLoginError(f"login rejected, reply: {reply[-80:]!r}")
        # every failure marker is checked before any success marker (the phrases were also checked
        # after every chunk; only the prompts can still be new here)
        if failure.search(reply) or prompt.search(reply):
            raise TelnetLoginError(f"login rejected, reply: {reply[-80:]!r}")
        if not success.search(reply):
            raise TelnetLoginError(f"login not confirmed, reply: {reply[-80:]!r}")


class TelnetEngine(BaseEngine):
    library = TelnetLibrary
