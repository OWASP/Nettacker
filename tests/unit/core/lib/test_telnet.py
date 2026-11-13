import os
import socket
import threading
import time
from contextlib import contextmanager

try:
    import resource
except ImportError:  # not available on Windows
    resource = None

from nettacker.core.lib.telnet import TelnetEngine, TelnetLibrary, TelnetLoginError
from tests.unit.common import TestCase

USERNAME = "admin"
PASSWORD = "s3cret"
# Cases where the reply arrives immediately use a generous timeout so that a slow test runner
# cannot make them flaky; cases that are meant to time out use a short one to stay fast.
LONG_TIMEOUT = 5
SHORT_TIMEOUT = 0.5
# Most tests use a short settle_time to stay fast; the tests that say so use the production
# default instead. FRAGMENT_GAP must stay well below the settle_time of the test.
FAST_SETTLE = 0.2
FRAGMENT_GAP = 0.02
# No login attempt may run longer than this in a test: a hang is reported as a failure.
HARD_LIMIT = 10
# Wordings of a login banner whose first piece ends in "login: ", where a login prompt ends too.
BANNERS = (
    b"Last failed login: ",
    b"Last unsuccessful login: ",
    b"Last successful login: ",
    b"Last login: ",
)
AFTER_BANNER = b"Tue Nov 10 10:00:00 2026 from 10.0.0.1 on ttyS0\r\nadmin@mock:~$ "


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
    reply,
    login_prompt=b"mock login: ",
    password_prompt=b"Password: ",
    close_after_reply=False,
    gap=0,
):
    """Return a handler that plays a telnet login and answers the password with `reply`.

    `reply` is sent in one write, or as separate writes `gap` seconds apart if it is a list.
    """
    pieces = reply if isinstance(reply, list) else [reply]

    def handler(connection, received):
        connection.sendall(login_prompt)
        received.append(read_line(connection))
        connection.sendall(password_prompt)
        received.append(read_line(connection))
        for number, piece in enumerate(pieces):
            if number:
                time.sleep(gap)
            if piece:
                connection.sendall(piece)
        if not close_after_reply:
            wait_for_client_to_close(connection)

    return handler


def discard_input(connection):
    try:
        while connection.recv(4096):
            pass
    except OSError:
        pass


def flooding(block, delay=0, stage="reply"):
    """Return a handler that sends `block` over and over once `stage` of the login is reached.

    The stage is "login", "password" or "reply". It stops with an OSError when the client or the
    test closes the connection, and in any case after 30 seconds.
    """

    def handler(connection, received):
        if stage != "login":
            connection.sendall(b"mock login: ")
            received.append(read_line(connection))
        if stage == "reply":
            connection.sendall(b"Password: ")
            received.append(read_line(connection))
        # the answers of the client to option negotiation must not fill the buffers
        threading.Thread(target=discard_input, args=(connection,), daemon=True).start()
        end = time.monotonic() + 3 * HARD_LIMIT
        while time.monotonic() < end:
            connection.sendall(block)
            if delay:
                time.sleep(delay)

    return handler


def ending_at_byte_50(text, rest):
    """Return one reply in which `text` ends at byte 50, where the first telnetlib read ends."""
    filler = b"Authorized use only".ljust(50 - len(text) - 4)
    reply = b"\r\n" + filler + b"\r\n" + text + rest
    assert reply.index(text) + len(text) == 50
    return reply


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
    accepted = []

    def serve():
        try:
            connection, _ = server.accept()
        except OSError:
            return
        accepted.append(connection)
        # without this a small write can be held back until the previous one is acknowledged
        connection.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
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
        # closing the connection also ends a client that is stuck reading from it
        for connection in accepted:
            try:
                connection.shutdown(socket.SHUT_RDWR)
            except OSError:
                pass
        server.close()
        thread.join(timeout=10)


class TestTelnetBruteForce(TestCase):
    def attempt(
        self, handler, password=PASSWORD, timeout=SHORT_TIMEOUT, settle_time=FAST_SETTLE, **limits
    ):
        """Run one login attempt against a local server; return (result, received lines, port).

        settle_time=None keeps the production default. The attempt runs in a thread, and the
        test fails (instead of hanging) if it is still running after HARD_LIMIT seconds.
        """
        library = TelnetLibrary()
        for name, value in dict(limits, settle_time=settle_time).items():
            if value is not None:
                setattr(library, name, value)
        outcome = {}
        with telnet_server(handler) as (port, received):

            def run():
                try:
                    outcome["result"] = library.brute_force(
                        host="127.0.0.1",
                        port=port,
                        username=USERNAME,
                        password=password,
                        timeout=timeout,
                    )
                except Exception as error:  # noqa: BLE001 - handed to the thread of the test
                    outcome["error"] = error

            worker = threading.Thread(target=run, daemon=True)
            worker.start()
            worker.join(HARD_LIMIT)
            stuck = worker.is_alive()
        if stuck:
            self.fail(f"brute_force was still running after {HARD_LIMIT} seconds")
        if "error" in outcome:
            raise outcome["error"]
        return outcome["result"], received, port

    def assert_rejected(
        self, handler, errors=(TelnetLoginError,), timeout=SHORT_TIMEOUT, **options
    ):
        started = time.monotonic()
        with self.assertRaises(errors):
            self.attempt(handler, timeout=timeout, **options)
        # a rejection must never wait longer than the bounded reads allow
        self.assertLess(time.monotonic() - started, 3 * timeout + 5)

    def rejection_time(self, handler, **options):
        """Return the seconds a rejected attempt needed."""
        started = time.monotonic()
        self.assert_rejected(handler, **options)
        return time.monotonic() - started

    def test_correct_password_accepted(self):
        reply = b"\r\nLast login: Tue Nov 10 10:00:00 2026 from 10.0.0.1\r\nadmin@mock:~$ "

        # settle_time=None: the production quiet period is used here on purpose
        result, received, port = self.attempt(
            scripted(reply), timeout=LONG_TIMEOUT, settle_time=None
        )

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

    def test_failure_in_pieces_is_not_accepted_on_a_prompt_like_first_piece(self):
        # Breaks if the reply is judged on its first piece: b"\r\n%" already looks like a prompt.
        # Runs with the production settle_time, so the real quiet period is exercised.
        self.assert_rejected(
            scripted([b"\r\n%", b" Bad secrets\r\nPassword: "], gap=0.05),
            timeout=LONG_TIMEOUT,
            settle_time=None,
        )

    def test_cisco_style_percent_piece_is_not_accepted_as_a_prompt(self):
        self.assert_rejected(
            scripted([b"\r\n% ", b"Login invalid\r\n\r\nUsername: "], gap=FRAGMENT_GAP),
            timeout=LONG_TIMEOUT,
        )

    def test_prompt_like_end_of_the_first_50_bytes_of_one_write_is_not_accepted(self):
        # telnetlib reads 50 bytes at a time; here the 50th byte is a "$" although the server
        # sent the whole failure message in a single write.
        reply = b"\r\n" + b"x" * 47 + b"$" + b" invalid password\r\n"
        self.assert_rejected(scripted(reply), timeout=LONG_TIMEOUT)

    def test_failure_marker_split_across_pieces_is_rejected(self):
        for pieces in (
            [b"\r\nLogin inc", b"orrect\r\nmock login: "],
            [b"\r\nBad secrets\r\nPass", b"word: "],
        ):
            with self.subTest(pieces=pieces):
                self.assert_rejected(scripted(pieces, gap=FRAGMENT_GAP), timeout=LONG_TIMEOUT)

    def test_success_split_across_pieces_is_accepted(self):
        for pieces in (
            [b"\r\nLast log", b"in: Tue Nov 10 10:00:00 2026\r\nadmin@mock:~$ "],
            [b"\r\nWelcome to mock\r\n", b"admin@mock:~$ "],
        ):
            with self.subTest(pieces=pieces):
                result, _, _ = self.attempt(
                    scripted(pieces, gap=FRAGMENT_GAP), timeout=LONG_TIMEOUT
                )
                self.assertEqual(result["password"], PASSWORD)

    def test_quiet_period_at_production_settle_time(self):
        pieces = [b"\r\n%", b" Bad secrets\r\nPassword: "]
        # the rest of the failure arrives well inside the quiet period: rejected
        self.assert_rejected(scripted(pieces, gap=0.1), timeout=LONG_TIMEOUT, settle_time=None)
        # Known limit, pinned here on purpose: when the rest arrives after the quiet period
        # (more than 0.5 s later) the login has already been accepted.
        result, _, _ = self.attempt(
            scripted(pieces, gap=1.5), timeout=LONG_TIMEOUT, settle_time=None
        )
        self.assertEqual(result["password"], PASSWORD)

    def test_banner_in_pieces_is_accepted_when_the_first_piece_ends_in_login(self):
        # "Last login: " is also protected by a lookbehind; the other wordings are only accepted
        # because a trailing prompt is judged once the reply has been quiet for settle_time.
        for banner in BANNERS:
            with self.subTest(banner=banner):
                result, _, _ = self.attempt(
                    scripted([b"\r\n" + banner, AFTER_BANNER], gap=FRAGMENT_GAP),
                    timeout=LONG_TIMEOUT,
                )
                self.assertEqual(result["password"], PASSWORD)

    def test_banner_ending_at_byte_50_of_one_write_is_accepted(self):
        # telnetlib reads 50 bytes at a time, so its first read of this one write ends in "login: "
        for banner in BANNERS:
            with self.subTest(banner=banner):
                result, _, _ = self.attempt(
                    scripted(ending_at_byte_50(banner, AFTER_BANNER)), timeout=LONG_TIMEOUT
                )
                self.assertEqual(result["password"], PASSWORD)

    def test_password_text_in_a_successful_reply_is_accepted_when_split_after_it(self):
        text = b"Notice - your Password: "
        rest = b"expires in 5 days\r\nadmin@mock:~$ "
        for name, handler in (
            ("two writes", scripted([b"\r\n" + text, rest], gap=FRAGMENT_GAP)),
            ("byte 50 of one write", scripted(ending_at_byte_50(text, rest))),
        ):
            with self.subTest(case=name):
                result, _, _ = self.attempt(handler, timeout=LONG_TIMEOUT)
                self.assertEqual(result["password"], PASSWORD)

    def test_prompt_without_a_known_phrase_is_rejected_after_the_quiet_period(self):
        # judged once the reply stayed quiet for settle_time: not at once, and long before the
        # timeout of 5 seconds
        for reply in (b"\r\nmock login: ", b"\r\nPassword: "):
            with self.subTest(reply=reply):
                elapsed = self.rejection_time(scripted(reply), timeout=LONG_TIMEOUT)
                self.assertGreaterEqual(elapsed, FAST_SETTLE * 0.75)
                self.assertLess(elapsed, FAST_SETTLE + 1)

    def test_explicit_phrase_is_rejected_without_waiting_for_the_quiet_period(self):
        # settle_time is longer than the limit below, so waiting for it would fail the test
        elapsed = self.rejection_time(
            scripted(b"\r\nLogin incorrect\r\nmock login: "), timeout=LONG_TIMEOUT, settle_time=3
        )
        self.assertLess(elapsed, 1.5)

    def test_trailing_prompt_wins_over_a_success_marker(self):
        self.assert_rejected(
            scripted(b"\r\nLast login: never\r\nmock login: "), timeout=LONG_TIMEOUT
        )

    def test_server_closing_after_a_trailing_prompt_is_rejected(self):
        # the close ends the quiet period; the prompt is judged on what arrived, not raised as EOF
        self.assert_rejected(
            scripted(b"\r\nLast login: never\r\nmock login: ", close_after_reply=True),
            timeout=LONG_TIMEOUT,
        )

    def test_banner_continuing_after_the_quiet_period_is_rejected(self):
        # Known limit, pinned on purpose: the rest of the banner arrives after the quiet period,
        # so the first piece, which ends in "login: ", has already been judged as a login prompt.
        self.assert_rejected(
            scripted([b"\r\nLast failed login: ", AFTER_BANNER], gap=3 * FAST_SETTLE),
            timeout=LONG_TIMEOUT,
        )

    def test_deadline_during_the_quiet_period_after_a_trailing_prompt_is_a_rejection(self):
        # The prompt arrives after 0.3 s and the timeout of 0.8 s ends in the middle of the 3 s
        # quiet period: the attempt is rejected at the timeout, not after settle_time.
        elapsed = self.rejection_time(
            scripted([b"", b"\r\nmock login: "], gap=0.3), timeout=0.8, settle_time=3
        )
        self.assertGreaterEqual(elapsed, 0.7)
        self.assertLess(elapsed, 0.8 + 1)

    def test_flood_during_the_reply_is_rejected_within_the_timeout(self):
        self.assert_rejected(flooding(b"x" * 1024), timeout=1)

    def test_option_negotiation_flood_during_the_reply_is_rejected_within_the_timeout(self):
        self.assert_rejected(flooding(b"\xff\xfd\x01" * 300), timeout=1)

    def test_drip_slower_than_1_ms_per_byte_is_rejected_within_the_timeout(self):
        self.assert_rejected(flooding(b"x", delay=0.005), timeout=1)

    def test_flood_while_waiting_for_a_prompt_is_rejected_within_the_timeout(self):
        for stage in ("login", "password"):
            with self.subTest(stage=stage):
                self.assert_rejected(flooding(b"x" * 1024, stage=stage), timeout=1)

    def test_finite_reply_larger_than_the_limit_is_cut_off_before_the_timeout(self):
        # 64 KiB is four times the default limit. It must be cut off by its size, long before
        # the 8 second timeout (telnetlib alone needs about 15 seconds to get through it).
        started = time.monotonic()
        self.assert_rejected(scripted(b"y" * 64 * 1024), timeout=8)
        self.assertLess(time.monotonic() - started, 8)

    def test_connection_with_a_file_descriptor_above_1023(self):
        # select.select() cannot watch such a descriptor on POSIX, and a scan with many threads
        # in one process gets there easily.
        if resource is None:
            self.skipTest("the resource module is not available")
        soft, hard = resource.getrlimit(resource.RLIMIT_NOFILE)
        if hard != resource.RLIM_INFINITY and hard < 1300:
            self.skipTest("cannot open enough files")
        resource.setrlimit(resource.RLIMIT_NOFILE, (max(soft, 1300), hard))
        spare = []
        try:
            while not spare or spare[-1] < 1100:
                spare.append(os.open(os.devnull, os.O_RDONLY))
            reply = b"\r\nLast login: Tue Nov 10 10:00:00 2026\r\nadmin@mock:~$ "
            result, _, _ = self.attempt(scripted(reply), timeout=LONG_TIMEOUT)
            self.assertEqual(result["password"], PASSWORD)
        finally:
            for descriptor in spare:
                os.close(descriptor)
            resource.setrlimit(resource.RLIMIT_NOFILE, (soft, hard))

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
