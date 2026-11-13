import socket
import threading
import time
from contextlib import contextmanager

from nettacker.core.lib.telnet import TelnetEngine, TelnetLibrary, TelnetLoginError
from tests.unit.common import TestCase

USERNAME = "admin"
PASSWORD = "s3cret"
# Cases where the reply arrives immediately use a generous timeout so that a slow test runner
# cannot make them flaky; cases that are meant to time out use a short one to stay fast.
LONG_TIMEOUT = 5
SHORT_TIMEOUT = 0.5


def read_line(connection):
    data = b""
    while not data.endswith(b"\n"):
        chunk = connection.recv(1)
        if not chunk:
            break
        data += chunk
    return data.strip()


def wait_for_client_to_close(connection):
    while connection.recv(1):
        pass


def scripted(
    reply, login_prompt=b"mock login: ", password_prompt=b"Password: ", close_after_reply=False
):
    """Return a handler that plays a telnet login and answers the password with `reply`."""

    def handler(connection, received):
        connection.sendall(login_prompt)
        received.append(read_line(connection))
        connection.sendall(password_prompt)
        received.append(read_line(connection))
        if reply:
            connection.sendall(reply)
        if not close_after_reply:
            wait_for_client_to_close(connection)

    return handler


def accepts_only(username, password):
    """Return a handler that accepts one credential pair, like a real login would."""

    def handler(connection, received):
        connection.sendall(b"mock login: ")
        user = read_line(connection)
        connection.sendall(b"Password: ")
        passwd = read_line(connection)
        received.extend([user, passwd])
        if (user, passwd) == (username.encode(), password.encode()):
            connection.sendall(b"\r\nLast login: Tue Nov 10 10:00:00 2026\r\nadmin@mock:~$ ")
        else:
            connection.sendall(b"\r\nLogin incorrect\r\nmock login: ")
        wait_for_client_to_close(connection)

    return handler


@contextmanager
def telnet_server(handler):
    """Serve one connection on 127.0.0.1 and yield (port, list of lines the client sent)."""
    server = socket.socket()
    server.bind(("127.0.0.1", 0))
    server.listen(1)
    server.settimeout(10)
    received = []

    def serve():
        try:
            connection, _ = server.accept()
        except OSError:
            return
        with connection:
            connection.settimeout(10)
            try:
                handler(connection, received)
            except OSError:
                pass

    thread = threading.Thread(target=serve, daemon=True)
    thread.start()
    try:
        yield server.getsockname()[1], received
    finally:
        server.close()
        thread.join(timeout=10)


class TestTelnetBruteForce(TestCase):
    def attempt(self, handler, password=PASSWORD, timeout=SHORT_TIMEOUT):
        """Run one login attempt against a local server; return (result, received lines)."""
        with telnet_server(handler) as (port, received):
            result = TelnetLibrary().brute_force(
                host="127.0.0.1",
                port=port,
                username=USERNAME,
                password=password,
                timeout=timeout,
            )
            return result, received, port

    def assert_rejected(self, handler, errors=(TelnetLoginError,), timeout=SHORT_TIMEOUT):
        started = time.monotonic()
        with self.assertRaises(errors):
            self.attempt(handler, timeout=timeout)
        # a rejection must never wait longer than the bounded reads allow
        self.assertLess(time.monotonic() - started, 3 * timeout + 5)

    def test_correct_password_accepted(self):
        reply = b"\r\nLast login: Tue Nov 10 10:00:00 2026 from 10.0.0.1\r\nadmin@mock:~$ "

        result, received, port = self.attempt(scripted(reply), timeout=LONG_TIMEOUT)

        self.assertEqual(
            result,
            {"host": "127.0.0.1", "port": port, "username": USERNAME, "password": PASSWORD},
        )
        self.assertEqual(received, [USERNAME.encode(), PASSWORD.encode()])

    def test_only_the_right_pair_is_accepted_by_a_server_that_checks_credentials(self):
        result, _, _ = self.attempt(
            accepts_only(USERNAME, PASSWORD), password=PASSWORD, timeout=LONG_TIMEOUT
        )
        self.assertEqual(result["password"], PASSWORD)

        with self.assertRaises(TelnetLoginError):
            self.attempt(accepts_only(USERNAME, PASSWORD), password="wrong", timeout=LONG_TIMEOUT)

    def test_wrong_password_rejected(self):
        self.assert_rejected(
            scripted(b"\r\nLogin incorrect\r\nmock login: "), timeout=LONG_TIMEOUT
        )

    def test_each_failure_phrase_rejected(self):
        for phrase in (
            b"Login incorrect",
            b"LOGIN FAILED",
            b"% Login invalid",
            b"% Authentication failed",
            b"Access denied",
            b"Permission denied, please try again.",
            b"Invalid password",
        ):
            with self.subTest(phrase=phrase):
                self.assert_rejected(scripted(b"\r\n" + phrase + b"\r\n"), timeout=LONG_TIMEOUT)

    def test_login_prompt_reappearing_rejected_without_a_known_message(self):
        self.assert_rejected(
            scripted(b"\r\nAnmeldung fehlgeschlagen\r\nmock login: "), timeout=LONG_TIMEOUT
        )

    def test_password_prompt_reappearing_rejected(self):
        self.assert_rejected(scripted(b"\r\n% Bad secrets\r\nPassword: "), timeout=LONG_TIMEOUT)

    def test_failure_marker_wins_over_other_text_and_a_prompt(self):
        reply = b"\r\nWelcome to mock\r\nLogin incorrect\r\nLast login: never\r\nadmin@mock:~$ "
        self.assert_rejected(scripted(reply), timeout=LONG_TIMEOUT)

    def test_last_failed_login_banner_still_counts_as_success(self):
        reply = (
            b"\r\nLast failed login: Tue Nov 10 09:59:00 2026 from 10.0.0.9 on ttyS0\r\n"
            b"There were 3 failed login attempts since the last successful login.\r\n"
            b"admin@mock:~$ "
        )

        result, _, _ = self.attempt(scripted(reply), timeout=LONG_TIMEOUT)

        self.assertEqual(result["username"], USERNAME)

    def test_common_shell_prompts_accepted(self):
        for prompt in (b"admin@mock:~$ ", b"~ # ", b"# ", b"$ ", b"Router>", b"C:\\Users\\a>"):
            with self.subTest(prompt=prompt):
                result, _, _ = self.attempt(scripted(b"\r\n" + prompt), timeout=LONG_TIMEOUT)
                self.assertEqual(result["password"], PASSWORD)

    def test_banner_containing_a_greater_than_sign_is_not_a_prompt(self):
        for banner in (
            b"\r\nWelcome to <MockOS> console, see <docs> for help >\r\n",
            b"\r\nWelcome >",
            b"\r\nPress <Enter>",
        ):
            with self.subTest(banner=banner):
                self.assert_rejected(scripted(banner))

    def test_silent_server_rejected_within_the_timeout(self):
        self.assert_rejected(scripted(b""))

    def test_server_closing_after_the_password_rejected(self):
        self.assert_rejected(
            scripted(b"", close_after_reply=True), errors=(TelnetLoginError, EOFError)
        )
        self.assert_rejected(
            scripted(b"\r\nLogin incorrect\r\n", close_after_reply=True),
            errors=(TelnetLoginError, EOFError),
        )

    def test_no_login_prompt_then_close_rejected(self):
        self.assert_rejected(lambda connection, received: None, errors=(EOFError,))

    def test_no_login_prompt_and_connection_held_open_rejected_within_the_timeout(self):
        def handler(connection, received):
            connection.sendall(b"Welcome to mock\r\n")
            wait_for_client_to_close(connection)

        self.assert_rejected(handler)

    def test_missing_password_prompt_rejected_within_the_timeout(self):
        def handler(connection, received):
            connection.sendall(b"mock login: ")
            received.append(read_line(connection))
            wait_for_client_to_close(connection)

        self.assert_rejected(handler)

    def test_different_login_prompt_text_is_not_matched(self):
        # The prompt strings are unchanged ("login: " and "Password: "), so a server that asks
        # for "Username: " is never logged in to; it is now given up on after the timeout.
        def handler(connection, received):
            connection.sendall(b"Username: ")
            wait_for_client_to_close(connection)

        self.assert_rejected(handler)

    def test_connection_refused(self):
        server = socket.socket()
        server.bind(("127.0.0.1", 0))
        port = server.getsockname()[1]
        server.close()

        # Windows reports a refused connection only after about 2 seconds, so the timeout
        # must be longer than that or the connect would time out first.
        with self.assertRaises(ConnectionRefusedError):
            TelnetLibrary().brute_force(
                host="127.0.0.1",
                port=port,
                username=USERNAME,
                password=PASSWORD,
                timeout=LONG_TIMEOUT,
            )

    def test_engine_uses_telnet_library(self):
        self.assertIs(TelnetEngine.library, TelnetLibrary)
