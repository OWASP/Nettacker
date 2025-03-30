from unittest.mock import patch
from nettacker.core.lib.socket import create_tcp_socket, SocketEngine
from tests.common import TestCase
import re


class Responses:
    tcp_connect_only = socket_icmp = {"response": "default"}

    tcp_connect_send_and_receive = {
        "response": 'HTTP/1.1 400 Bad Request\r\n'
                    'Server: Apache/2.4.62 (Debian)\r\n'
                    'Content-Length: 302\r\n'
                    'Connection: close\r\n'
                    'Content-Type: text/html; charset=iso-8859-1\r\n\r\n'
                    '<!DOCTYPE HTML PUBLIC "-//IETF//DTD HTML 2.0//EN">\n<html><head>\n'
                    '<title>400 Bad Request</title>\n</head><body>\n<h1>Bad Request</h1>\n'
                    '<p>Your browser sent a request that this server could not understand.<br />\n</p>\n<hr>\n'
                    '<address>Apache/2.4.62 (Debian)</address>\n</body></html>\n',
        "peer_name": ("127.0.0.1", 80),
        "ssl_flag": True,
    }

    none = None


class Substeps:
    tcp_connect_send_and_receive = {
        "method": "tcp_connect_send_and_receive",
        "response": {
            "condition_type": "or",
            "conditions": {
                "ftp": {"regex": "220 FTP Server ready", "reverse": False},
                "http": {
                    "regex": "HTTP/1.1 \\d+|Content-Length: \\d+|Server: [^\\r\\n]+|Content-Type: [^\\r\\n]+",
                    "reverse": False,
                },
                "ssh": {"regex": "OpenSSH", "reverse": False},
                "smtp": {"regex": "ESMTP", "reverse": False},
                "rsync": {"regex": "@RSYNCD:", "reverse": False},
                "telnet": {"regex": "Telnet", "reverse": False},
                "imap": {"regex": "IMAP4rev1", "reverse": False},
                "mariadb": {"regex": "MariaDB", "reverse": False},
                "mysql": {"regex": "MySQL", "reverse": False},
                "pop3": {"regex": r"\+OK POP3", "reverse": False},
                "ldap": {"regex": "LDAP", "reverse": False},
            },
        },
    }

    tcp_connect_only = {
        "method": "tcp_connect_only",
        "response": {
            "condition_type": "or",
            "conditions": {"time_response": {"regex": ".*", "reverse": False}},
        },
    }

    socket_icmp = {
        "method": "socket_icmp",
        "response": {
            "condition_type": "or",
            "conditions": {"time_response": {"regex": ".*", "reverse": False}},
        },
    }


class TestSocketMethod(TestCase):
    @patch("socket.socket")
    @patch("ssl.wrap_socket")
    def test_create_tcp_socket(self, mock_wrap, mock_socket):
        """
        Test the creation of a TCP socket with mocked socket and SSL wrap.
        """
        HOST = "example.com"
        PORT = 80
        TIMEOUT = 60

        create_tcp_socket(HOST, PORT, TIMEOUT)
        socket_instance = mock_socket.return_value
        socket_instance.settimeout.assert_called_with(TIMEOUT)
        socket_instance.connect.assert_called_with((HOST, PORT))
        mock_wrap.assert_called_with(socket_instance)

    def test_response_conditions_matched(self):
        """
        Test the response conditions matching logic for different scan methods.
        """
        engine = SocketEngine()
        Substep = Substeps()
        Response = Responses()

        # Test socket_icmp method
        self.assertEqual(
            engine.response_conditions_matched(
                Substep.socket_icmp, Response.socket_icmp
            ),
            Response.socket_icmp,
        )

        # Test tcp_connect_send_and_receive method with various protocols
        protocols = {
            "http": [
                "HTTP/1.1 400",
                "Content-Length: 302",
                "Content-Type: text/html; charset=iso-8859-1",
                "Server: Apache/2.4.62 (Debian)",
            ],
            "ftp": ["220 FTP Server ready"],
            "ssh": ["OpenSSH"],
            "telnet": ["Telnet"],
            "smtp": ["ESMTP"],
            "imap": ["IMAP4rev1"],
            "mariadb": ["MariaDB"],
            "mysql": ["MySQL"],
            "pop3": ["+OK POP3"],
            "ldap": ["LDAP"],
        }

        for protocol, expected_matches in protocols.items():
            response_result = engine.response_conditions_matched(
                Substep.tcp_connect_send_and_receive,
                {"response": "\r\n".join(expected_matches)},
            )

            self.assertIn(protocol, response_result, f"Missing protocol {protocol} in response")
            self.assertTrue(
                set(expected_matches).issubset(response_result.get(protocol, [])),
                f"Expected matches not found in response for {protocol}"
            )

        # Test tcp_connect_only
        self.assertEqual(
            engine.response_conditions_matched(
                Substep.tcp_connect_only, Response.tcp_connect_only
            ),
            Response.tcp_connect_only,
        )

        # Test response conditions when the response is None
        self.assertEqual(
            engine.response_conditions_matched(
                Substep.tcp_connect_send_and_receive, Response.none
            ),
            [],
        )