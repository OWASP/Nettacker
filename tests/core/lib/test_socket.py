from unittest.mock import patch
from nettacker.core.lib.socket import create_tcp_socket, SocketEngine
from tests.common import TestCase

# Mock responses for various scan methods
class Responses:
    tcp_connect_only = socket_icmp = {}

    tcp_connect_send_and_receive = {
        "response": (
            'HTTP/1.1 400 Bad Request\r\n'
            'Server: Apache/2.4.62 (Debian)\r\n'
            'Content-Length: 302\r\n'
            'Connection: close\r\n'
            'Content-Type: text/html; charset=iso-8859-1\r\n\r\n'
            '<!DOCTYPE HTML PUBLIC "-//IETF//DTD HTML 2.0//EN">\n<html><head>\n'
            '<title>400 Bad Request</title>\n</head><body>\n<h1>Bad Request</h1>\n'
            '<p>Your browser sent a request that this server could not understand.<br />\n'
            '</p>\n<hr>\n'
            '<address>Apache/2.4.62 (Debian)</address>\n</body></html>\n'
        ),
        "peer_name": ("127.0.0.1", 80),
        "ssl_flag": True,
    }

    ssl_version_scan = {
        "ssl_version": "TLSv1",
        "weak_version": True,
        "weak_cipher_suite": True,
        "ssl_flag": True,
    }

    none = None

# Mock substeps for different scan methods
class Substeps:
    tcp_connect_send_and_receive = {
        "method": "tcp_connect_send_and_receive",
        "response": {
            "condition_type": "or",
            "conditions": {
                "open_port": {"regex": "", "reverse": False},
                "ftp": {"regex": "220 FTP Server ready|Connection closed; transfer aborted", "reverse": False},
                "http": {"regex": "HTTPStatus.BAD_REQUEST|Content-Length: \\d+", "reverse": False},
                # Add more protocols as needed
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

# Test cases for socket methods
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
            engine.response_conditions_matched(Substep.socket_icmp, Response.socket_icmp),
            Response.socket_icmp,
        )

        # Test tcp_connect_send_and_receive method
        self.assertEqual(
            sorted(
                engine.response_conditions_matched(
                    Substep.tcp_connect_send_and_receive,
                    Response.tcp_connect_send_and_receive,
                )
            ),
            sorted({"http": ["Content-Type: ", "Content-Length: 302", "HTTP/1.1 400", "Server: "]}),
        )

        # Test tcp_connect_only method
        self.assertEqual(
            engine.response_conditions_matched(Substep.tcp_connect_only, Response.tcp_connect_only),
            Response.tcp_connect_only,
        )

        # Test failed connection with None response
        self.assertEqual(
            engine.response_conditions_matched(Substep.tcp_connect_send_and_receive, Response.none),
            [],
        )