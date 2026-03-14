import sys
from unittest.mock import MagicMock, patch

import pytest

HAS_TELNETLIB = sys.version_info < (3, 13)


HOST = "192.168.1.10"
PORT_SSH = 22
PORT_FTP = 21
PORT_SMTP = 25
PORT_SMTPS = 465
PORT_POP3 = 110
PORT_POP3S = 995
PORT_TELNET = 23
USERNAME = "admin"
PASSWORD = "secret"  # noqa: S105
TIMEOUT = 5


class TestSshLibrary:
    def _make_library(self):
        from nettacker.core.lib.ssh import SshLibrary

        return SshLibrary()

    @patch("nettacker.core.lib.ssh.SSHClient")
    def test_brute_force_with_password(self, mock_ssh_cls):
        mock_conn = MagicMock()
        mock_ssh_cls.return_value = mock_conn

        lib = self._make_library()
        lib.client = mock_ssh_cls

        result = lib.brute_force(host=HOST, port=PORT_SSH, username=USERNAME, password=PASSWORD)

        mock_conn.set_missing_host_key_policy.assert_called_once()
        connect_kwargs = mock_conn.connect.call_args[1]
        assert connect_kwargs["hostname"] == HOST
        assert connect_kwargs["port"] == PORT_SSH
        # With a password, auth_strategy should be Password
        auth_strategy = connect_kwargs["auth_strategy"]
        from paramiko.auth_strategy import Password

        assert isinstance(auth_strategy, Password)

        assert result == {
            "host": HOST,
            "port": PORT_SSH,
            "username": USERNAME,
            "password": PASSWORD,
        }

    @patch("nettacker.core.lib.ssh.SSHClient")
    def test_brute_force_without_password(self, mock_ssh_cls):
        mock_conn = MagicMock()
        mock_ssh_cls.return_value = mock_conn

        lib = self._make_library()
        lib.client = mock_ssh_cls

        result = lib.brute_force(host=HOST, port=PORT_SSH, username=USERNAME, password="")  # noqa: S106

        connect_kwargs = mock_conn.connect.call_args[1]
        from paramiko.auth_strategy import NoneAuth

        assert isinstance(connect_kwargs["auth_strategy"], NoneAuth)

        assert result["password"] == ""

    @patch("nettacker.core.lib.ssh.SSHClient")
    def test_brute_force_connection_error(self, mock_ssh_cls):
        mock_conn = MagicMock()
        mock_conn.connect.side_effect = ConnectionRefusedError("refused")
        mock_ssh_cls.return_value = mock_conn

        lib = self._make_library()
        lib.client = mock_ssh_cls

        with pytest.raises(ConnectionRefusedError):
            lib.brute_force(host=HOST, port=PORT_SSH, username=USERNAME, password=PASSWORD)

    @patch("nettacker.core.lib.ssh.SSHClient")
    def test_brute_force_auth_failure(self, mock_ssh_cls):
        from paramiko.ssh_exception import AuthenticationException

        mock_conn = MagicMock()
        mock_conn.connect.side_effect = AuthenticationException("bad creds")
        mock_ssh_cls.return_value = mock_conn

        lib = self._make_library()
        lib.client = mock_ssh_cls

        with pytest.raises(AuthenticationException):
            lib.brute_force(host=HOST, port=PORT_SSH, username=USERNAME, password="wrong")  # noqa: S106


class TestSshEngine:
    def test_engine_uses_ssh_library(self):
        from nettacker.core.lib.ssh import SshEngine, SshLibrary

        assert SshEngine.library is SshLibrary


class TestFtpLibrary:
    def _make_library(self):
        from nettacker.core.lib.ftp import FtpLibrary

        return FtpLibrary()

    def test_brute_force_success(self):
        mock_ftp = MagicMock()
        lib = self._make_library()
        lib.client = MagicMock(return_value=mock_ftp)

        result = lib.brute_force(
            host=HOST,
            port=PORT_FTP,
            username=USERNAME,
            password=PASSWORD,
            timeout=TIMEOUT,
        )

        lib.client.assert_called_once_with(timeout=TIMEOUT)
        mock_ftp.connect.assert_called_once_with(HOST, PORT_FTP)
        mock_ftp.login.assert_called_once_with(USERNAME, PASSWORD)
        mock_ftp.close.assert_called_once()

        assert result == {
            "host": HOST,
            "port": PORT_FTP,
            "username": USERNAME,
            "password": PASSWORD,
        }

    def test_brute_force_login_failure(self):
        import ftplib

        mock_ftp = MagicMock()
        mock_ftp.login.side_effect = ftplib.error_perm("530 Login incorrect")
        lib = self._make_library()
        lib.client = MagicMock(return_value=mock_ftp)

        with pytest.raises(ftplib.error_perm):
            lib.brute_force(
                host=HOST,
                port=PORT_FTP,
                username=USERNAME,
                password="wrong",  # noqa: S106
                timeout=TIMEOUT,
            )

        mock_ftp.close.assert_not_called()

    def test_brute_force_connection_timeout(self):
        lib = self._make_library()
        lib.client = MagicMock(side_effect=TimeoutError("timed out"))

        with pytest.raises(TimeoutError):
            lib.brute_force(
                host=HOST,
                port=PORT_FTP,
                username=USERNAME,
                password=PASSWORD,
                timeout=TIMEOUT,
            )


class TestFtpEngine:
    def test_engine_uses_ftp_library(self):
        from nettacker.core.lib.ftp import FtpEngine, FtpLibrary

        assert FtpEngine.library is FtpLibrary


class TestFtpsLibrary:
    def test_client_is_ftp_tls(self):
        import ftplib

        from nettacker.core.lib.ftps import FtpsLibrary

        assert FtpsLibrary.client is ftplib.FTP_TLS

    def test_inherits_brute_force_from_ftp(self):
        from nettacker.core.lib.ftp import FtpLibrary
        from nettacker.core.lib.ftps import FtpsLibrary

        assert FtpsLibrary.brute_force is FtpLibrary.brute_force

    def test_brute_force_success(self):
        from nettacker.core.lib.ftps import FtpsLibrary

        mock_ftp_tls = MagicMock()
        lib = FtpsLibrary()
        lib.client = MagicMock(return_value=mock_ftp_tls)

        result = lib.brute_force(
            host=HOST,
            port=PORT_FTP,
            username=USERNAME,
            password=PASSWORD,
            timeout=TIMEOUT,
        )

        mock_ftp_tls.connect.assert_called_once_with(HOST, PORT_FTP)
        mock_ftp_tls.login.assert_called_once_with(USERNAME, PASSWORD)
        assert result["username"] == USERNAME


class TestFtpsEngine:
    def test_engine_uses_ftps_library(self):
        from nettacker.core.lib.ftps import FtpsEngine, FtpsLibrary

        assert FtpsEngine.library is FtpsLibrary


class TestSmtpLibrary:
    def _make_library(self):
        from nettacker.core.lib.smtp import SmtpLibrary

        return SmtpLibrary()

    def test_brute_force_success(self):
        mock_smtp = MagicMock()
        lib = self._make_library()
        lib.client = MagicMock(return_value=mock_smtp)

        result = lib.brute_force(
            host=HOST,
            port=PORT_SMTP,
            username=USERNAME,
            password=PASSWORD,
            timeout=TIMEOUT,
        )

        lib.client.assert_called_once_with(HOST, PORT_SMTP, timeout=TIMEOUT)
        mock_smtp.login.assert_called_once_with(USERNAME, PASSWORD)
        mock_smtp.close.assert_called_once()

        assert result == {
            "host": HOST,
            "port": PORT_SMTP,
            "username": USERNAME,
            "password": PASSWORD,
        }

    def test_brute_force_auth_failure(self):
        import smtplib

        mock_smtp = MagicMock()
        mock_smtp.login.side_effect = smtplib.SMTPAuthenticationError(
            535, b"Authentication failed"
        )
        lib = self._make_library()
        lib.client = MagicMock(return_value=mock_smtp)

        with pytest.raises(smtplib.SMTPAuthenticationError):
            lib.brute_force(
                host=HOST,
                port=PORT_SMTP,
                username=USERNAME,
                password="wrong",  # noqa: S106
                timeout=TIMEOUT,
            )

    def test_brute_force_connection_refused(self):
        lib = self._make_library()
        lib.client = MagicMock(side_effect=ConnectionRefusedError("refused"))

        with pytest.raises(ConnectionRefusedError):
            lib.brute_force(
                host=HOST,
                port=PORT_SMTP,
                username=USERNAME,
                password=PASSWORD,
                timeout=TIMEOUT,
            )


class TestSmtpEngine:
    def test_engine_uses_smtp_library(self):
        from nettacker.core.lib.smtp import SmtpEngine, SmtpLibrary

        assert SmtpEngine.library is SmtpLibrary


class TestSmtpsLibrary:
    def _make_library(self):
        from nettacker.core.lib.smtps import SmtpsLibrary

        return SmtpsLibrary()

    def test_brute_force_calls_starttls(self):
        mock_smtp = MagicMock()
        lib = self._make_library()
        lib.client = MagicMock(return_value=mock_smtp)

        result = lib.brute_force(
            host=HOST,
            port=PORT_SMTPS,
            username=USERNAME,
            password=PASSWORD,
            timeout=TIMEOUT,
        )

        lib.client.assert_called_once_with(HOST, PORT_SMTPS, timeout=TIMEOUT)
        mock_smtp.starttls.assert_called_once()
        mock_smtp.login.assert_called_once_with(USERNAME, PASSWORD)
        mock_smtp.close.assert_called_once()

        assert result == {
            "host": HOST,
            "port": PORT_SMTPS,
            "username": USERNAME,
            "password": PASSWORD,
        }

    def test_starttls_called_before_login(self):
        call_order = []
        mock_smtp = MagicMock()
        mock_smtp.starttls.side_effect = lambda: call_order.append("starttls")
        mock_smtp.login.side_effect = lambda u, p: call_order.append("login")

        lib = self._make_library()
        lib.client = MagicMock(return_value=mock_smtp)

        lib.brute_force(
            host=HOST,
            port=PORT_SMTPS,
            username=USERNAME,
            password=PASSWORD,
            timeout=TIMEOUT,
        )

        assert call_order == ["starttls", "login"]

    def test_starttls_failure_propagates(self):
        mock_smtp = MagicMock()
        mock_smtp.starttls.side_effect = RuntimeError("TLS handshake failed")

        lib = self._make_library()
        lib.client = MagicMock(return_value=mock_smtp)

        with pytest.raises(RuntimeError, match="TLS handshake failed"):
            lib.brute_force(
                host=HOST,
                port=PORT_SMTPS,
                username=USERNAME,
                password=PASSWORD,
                timeout=TIMEOUT,
            )

        mock_smtp.login.assert_not_called()


class TestSmtpsEngine:
    def test_engine_uses_smtps_library(self):
        from nettacker.core.lib.smtps import SmtpsEngine, SmtpsLibrary

        assert SmtpsEngine.library is SmtpsLibrary


class TestPop3Library:
    def _make_library(self):
        from nettacker.core.lib.pop3 import Pop3Library

        return Pop3Library()

    def test_brute_force_success(self):
        mock_pop3 = MagicMock()
        lib = self._make_library()
        lib.client = MagicMock(return_value=mock_pop3)

        result = lib.brute_force(
            host=HOST,
            port=PORT_POP3,
            username=USERNAME,
            password=PASSWORD,
            timeout=TIMEOUT,
        )

        lib.client.assert_called_once_with(HOST, port=PORT_POP3, timeout=TIMEOUT)
        mock_pop3.user.assert_called_once_with(USERNAME)
        mock_pop3.pass_.assert_called_once_with(PASSWORD)
        mock_pop3.quit.assert_called_once()

        assert result == {
            "host": HOST,
            "port": PORT_POP3,
            "username": USERNAME,
            "password": PASSWORD,
        }

    def test_brute_force_auth_failure(self):
        import poplib

        mock_pop3 = MagicMock()
        mock_pop3.pass_.side_effect = poplib.error_proto("-ERR authentication failed")
        lib = self._make_library()
        lib.client = MagicMock(return_value=mock_pop3)

        with pytest.raises(poplib.error_proto):
            lib.brute_force(
                host=HOST,
                port=PORT_POP3,
                username=USERNAME,
                password="wrong",  # noqa: S106
                timeout=TIMEOUT,
            )

    def test_user_called_before_pass(self):
        call_order = []
        mock_pop3 = MagicMock()
        mock_pop3.user.side_effect = lambda u: call_order.append("user")
        mock_pop3.pass_.side_effect = lambda p: call_order.append("pass_")

        lib = self._make_library()
        lib.client = MagicMock(return_value=mock_pop3)

        lib.brute_force(
            host=HOST,
            port=PORT_POP3,
            username=USERNAME,
            password=PASSWORD,
            timeout=TIMEOUT,
        )

        assert call_order == ["user", "pass_"]


class TestPop3Engine:
    def test_engine_uses_pop3_library(self):
        from nettacker.core.lib.pop3 import Pop3Engine, Pop3Library

        assert Pop3Engine.library is Pop3Library


class TestPop3sLibrary:
    def test_client_is_pop3_ssl(self):
        import poplib

        from nettacker.core.lib.pop3s import Pop3sLibrary

        assert Pop3sLibrary.client is poplib.POP3_SSL

    def test_inherits_brute_force_from_pop3(self):
        from nettacker.core.lib.pop3 import Pop3Library
        from nettacker.core.lib.pop3s import Pop3sLibrary

        assert Pop3sLibrary.brute_force is Pop3Library.brute_force

    def test_brute_force_success(self):
        from nettacker.core.lib.pop3s import Pop3sLibrary

        mock_pop3s = MagicMock()
        lib = Pop3sLibrary()
        lib.client = MagicMock(return_value=mock_pop3s)

        result = lib.brute_force(
            host=HOST,
            port=PORT_POP3S,
            username=USERNAME,
            password=PASSWORD,
            timeout=TIMEOUT,
        )

        mock_pop3s.user.assert_called_once_with(USERNAME)
        mock_pop3s.pass_.assert_called_once_with(PASSWORD)
        assert result["port"] == PORT_POP3S


class TestPop3sEngine:
    def test_engine_uses_pop3s_library(self):
        from nettacker.core.lib.pop3s import Pop3sEngine, Pop3sLibrary

        assert Pop3sEngine.library is Pop3sLibrary


@pytest.mark.skipif(not HAS_TELNETLIB, reason="telnetlib removed in Python 3.13")
class TestTelnetLibrary:
    def _make_library(self):
        from nettacker.core.lib.telnet import TelnetLibrary

        return TelnetLibrary()

    def test_brute_force_success(self):
        mock_telnet = MagicMock()
        lib = self._make_library()
        lib.client = MagicMock(return_value=mock_telnet)

        result = lib.brute_force(
            host=HOST,
            port=PORT_TELNET,
            username=USERNAME,
            password=PASSWORD,
            timeout=TIMEOUT,
        )

        lib.client.assert_called_once_with(HOST, PORT_TELNET, TIMEOUT)
        mock_telnet.read_until.assert_any_call(b"login: ")
        mock_telnet.read_until.assert_any_call(b"Password: ")
        mock_telnet.write.assert_any_call(USERNAME.encode("utf-8") + b"\n")
        mock_telnet.write.assert_any_call(PASSWORD.encode("utf-8") + b"\n")
        mock_telnet.close.assert_called_once()

        assert result == {
            "host": HOST,
            "port": PORT_TELNET,
            "username": USERNAME,
            "password": PASSWORD,
        }

    def test_login_sequence_order(self):
        call_order = []
        mock_telnet = MagicMock()
        mock_telnet.read_until.side_effect = lambda prompt: call_order.append(("read", prompt))
        mock_telnet.write.side_effect = lambda data: call_order.append(("write", data))

        lib = self._make_library()
        lib.client = MagicMock(return_value=mock_telnet)

        lib.brute_force(
            host=HOST,
            port=PORT_TELNET,
            username=USERNAME,
            password=PASSWORD,
            timeout=TIMEOUT,
        )

        assert call_order == [
            ("read", b"login: "),
            ("write", USERNAME.encode("utf-8") + b"\n"),
            ("read", b"Password: "),
            ("write", PASSWORD.encode("utf-8") + b"\n"),
        ]

    def test_brute_force_connection_refused(self):
        lib = self._make_library()
        lib.client = MagicMock(side_effect=ConnectionRefusedError("refused"))

        with pytest.raises(ConnectionRefusedError):
            lib.brute_force(
                host=HOST,
                port=PORT_TELNET,
                username=USERNAME,
                password=PASSWORD,
                timeout=TIMEOUT,
            )

    def test_brute_force_read_timeout(self):
        mock_telnet = MagicMock()
        mock_telnet.read_until.side_effect = EOFError("connection closed")

        lib = self._make_library()
        lib.client = MagicMock(return_value=mock_telnet)

        with pytest.raises(EOFError):
            lib.brute_force(
                host=HOST,
                port=PORT_TELNET,
                username=USERNAME,
                password=PASSWORD,
                timeout=TIMEOUT,
            )


@pytest.mark.skipif(not HAS_TELNETLIB, reason="telnetlib removed in Python 3.13")
class TestTelnetEngine:
    def test_engine_uses_telnet_library(self):
        from nettacker.core.lib.telnet import TelnetEngine, TelnetLibrary

        assert TelnetEngine.library is TelnetLibrary
