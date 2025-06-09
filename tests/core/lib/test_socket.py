from unittest.mock import patch

import pytest

from nettacker.core.lib.socket import create_tcp_socket, SocketEngine


class Responses:
    tcp_connect_only = socket_icmp = {}

    tcp_connect_send_and_receive = {
        "response": 'HTTP/1.1 400 Bad Request\r\nServer: Apache/2.4.62 (Debian)\r\nContent-Length: 302\r\nConnection: close\r\nContent-Type: text/html; charset=iso-8859-1\r\n\r\n<!DOCTYPE HTML PUBLIC "-//IETF//DTD HTML 2.0//EN">\n<html><head>\n<title>400 Bad Request</title>\n</head><body>\n<h1>Bad Request</h1>\n<p>Your browser sent a request that this server could not understand.<br />\n</p>\n<hr>\n<address>Apache/2.4.62 (Debian)</address>\n</body></html>\n',
        "service": "http",
        "peer_name": (
            "127.0.0.1",
            80,
        ),
        "ssl_flag": True,
    }

    ssl_version_scan = {
        "ssl_version": "TLSv1",
        "weak_version": True,
        "weak_cipher_suite": True,
        "ssl_flag": True,
    }

    none = None


class Substeps:
    tcp_connect_send_and_receive = {
        "method": "tcp_connect_send_and_receive",
        "response": {
            "condition_type": "or",
            "log": "response_dependent['service']",
            "conditions": {
                "service": {
                    "open_port": {"regex": "", "reverse": False},
                    "ftp": {
                        "regex": "220-You are user number|530 USER and PASS required|Invalid command: try being more creative|220 \\S+ FTP (Service|service|Server|server)|220 FTP Server ready|Directory status|Service closing control connection|Requested file action|Connection closed; transfer aborted|Directory not empty",
                        "reverse": False,
                    },
                    "ftps": {
                        "regex": "220-You are user number|530 USER and PASS required|Invalid command: try being more creative|220 \\S+ FTP (Service|service|Server|server)|220 FTP Server ready|Directory status|Service closing control connection|Requested file action|Connection closed; transfer aborted|Directory not empty",
                        "reverse": False,
                    },
                    "http": {
                        "regex": "HTTPStatus.BAD_REQUEST|HTTP\\/[\\d.]+\\s+[\\d]+|Server: |Content-Length: \\d+|Content-Type: |Access-Control-Request-Headers: |Forwarded: |Proxy-Authorization: |User-Agent: |X-Forwarded-Host: |Content-MD5: |Access-Control-Request-Method: |Accept-Language: ",
                        "reverse": False,
                    },
                    "imap": {
                        "regex": "Internet Mail Server|IMAP4 service|BYE Hi This is the IMAP SSL Redirect|LITERAL\\+ SASL\\-IR LOGIN\\-REFERRALS ID ENABLE IDLE AUTH\\=PLAIN AUTH\\=LOGIN AUTH\\=DIGEST\\-MD5 AUTH\\=CRAM-MD5|CAPABILITY completed|OK IMAPrev1|LITERAL\\+ SASL\\-IR LOGIN\\-REFERRALS ID ENABLE IDLE NAMESPACE AUTH\\=PLAIN AUTH\\=LOGIN|BAD Error in IMAP command received by server|IMAP4rev1 SASL-IR|OK \\[CAPABILITY IMAP4rev1",
                        "reverse": False,
                    },
                    "mariadb": {
                        "regex": "is not allowed to connect to this MariaDB server",
                        "reverse": False,
                    },
                    "mysql": {
                        "regex": "is not allowed to connect to this MySQL server",
                        "reverse": False,
                    },
                    "nntp": {
                        "regex": "NetWare\\-News\\-Server|NetWare nntpd|nntp|Leafnode nntpd|InterNetNews NNRP server INN",
                        "reverse": False,
                    },
                    "pop3": {
                        "regex": "POP3|POP3 gateway ready|POP3 Server|Welcome to mpopd|OK Hello there",
                        "reverse": False,
                    },
                    "pop3s": {
                        "regex": "POP3|POP3 gateway ready|POP3 Server|Welcome to mpopd|OK Hello there",
                        "reverse": False,
                    },
                    "portmap": {
                        "regex": "Program\tVersion\tProtocol\tPort|portmapper|nfs\t2|nlockmgr\t1",
                        "reverse": False,
                    },
                    "postgressql": {
                        "regex": "FATAL 1\\:  invalid length of startup packet|received invalid response to SSL negotiation\\:|unsupported frontend protocol|fe\\_sendauth\\: no password supplied|no pg\\_hba\\.conf entry for host",
                        "reverse": False,
                    },
                    "pptp": {
                        "regex": "Hostname: pptp server|Vendor: Fortinet pptp",
                        "reverse": False,
                    },
                    "smtp": {
                        "regex": "Fidelix Fx2020|ESMTP|Server ready|SMTP synchronization error|220-Greetings|ESMTP Arnet Email Security|SMTP 2.0",
                        "reverse": False,
                    },
                    "smtps": {
                        "regex": "Fidelix Fx2020|ESMTP|Server ready|SMTP synchronization error|220-Greetings|ESMTP Arnet Email Security|SMTP 2.0",
                        "reverse": False,
                    },
                    "rsync": {"regex": "@RSYNCD\\:", "reverse": False},
                    "ssh": {
                        "regex": "openssh|\\-OpenSSH\\_|\\r\\nProtocol mism|\\_sshlib|\\x00\\x1aversion info line too long|SSH Windows NT Server|WinNT sshd|sshd| SSH Secure Shell|WinSSHD",
                        "reverse": False,
                    },
                    "telnet": {
                        "regex": "Check Point FireWall-1 authenticated Telnet server running on|Raptor Firewall Secure Gateway|No more connections are allowed to telnet server|Closing Telnet connection due to host problems|NetportExpress|WARNING WARNING WARNING WARNING WARNING WARNING WARNING WARNING WARNING|Login authentication|recommended to use Stelnet|is not a secure protocol|Welcome to Microsoft Telnet Servic|no decompiling or reverse-engineering shall be allowed",
                        "reverse": False,
                    },
                },
            },
        },
    }

    tcp_connect_only = {
        "method": "tcp_connect_only",
        "response": {
            "condition_type": "or",
            "conditions": {"time_response": {"regex": "", "reverse": False}},
        },
    }

    socket_icmp = {
        "method": "socket_icmp",
        "response": {
            "condition_type": "or",
            "conditions": {"time_response": {"regex": "", "reverse": False}},
        },
    }


@pytest.fixture
def socket_engine():
    return SocketEngine()


@pytest.fixture
def substeps():
    return Substeps()


@pytest.fixture
def responses():
    return Responses()


class TestSocketMethod:
    @patch("socket.socket")
    @patch("ssl.wrap_socket")
    def test_create_tcp_socket(self, mock_wrap, mock_socket):
        HOST = "example.com"
        PORT = 80
        TIMEOUT = 60

        create_tcp_socket(HOST, PORT, TIMEOUT)
        socket_instance = mock_socket.return_value
        socket_instance.settimeout.assert_called_with(TIMEOUT)
        socket_instance.connect.assert_called_with((HOST, PORT))
        mock_wrap.assert_called_with(socket_instance)

    def test_response_conditions_matched_socket_icmp(self, socket_engine, substeps, responses):
        result = socket_engine.response_conditions_matched(
            substeps.socket_icmp, responses.socket_icmp
        )
        assert result == responses.socket_icmp

    def test_response_conditions_matched_tcp_connect_send_and_receive(
        self, socket_engine, substeps, responses
    ):
        result = socket_engine.response_conditions_matched(
            substeps.tcp_connect_send_and_receive, responses.tcp_connect_send_and_receive
        )

        expected = {
            "http": ["Content-Type: ", "Content-Length: 302", "HTTP/1.1 400", "Server: "],
            "log": [
                "{'running_service': 'http', 'matched_regex': ['Server: ', 'HTTP/1.1 400', 'Content-Length: 302', 'Content-Type: '], 'default_service': 'http', 'ssl_flag': True}"
            ],
            "service": [
                "{'running_service': 'http', 'matched_regex': ['Server: ', 'HTTP/1.1 400', 'Content-Length: 302', 'Content-Type: '], 'default_service': 'http', 'ssl_flag': True}"
            ],
        }

        assert sorted(result) == sorted(expected)

    def test_response_conditions_matched_tcp_connect_only(
        self, socket_engine, substeps, responses
    ):
        result = socket_engine.response_conditions_matched(
            substeps.tcp_connect_only, responses.tcp_connect_only
        )
        assert result == responses.tcp_connect_only

    def test_response_conditions_matched_with_none_response(
        self, socket_engine, substeps, responses
    ):
        result = socket_engine.response_conditions_matched(
            substeps.tcp_connect_send_and_receive, responses.none
        )
        assert result == []
