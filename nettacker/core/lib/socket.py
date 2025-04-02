#!/usr/bin/env python

import copy
import logging
import os
import re
import select
import socket
import ssl
import struct
import time
import sys

from nettacker.core.lib.base import BaseEngine, BaseLibrary
from nettacker.core.utils.common import reverse_and_regex_condition

log = logging.getLogger(__name__)


def create_tcp_socket(host, port, timeout):
    try:
        socket_connection = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        socket_connection.settimeout(timeout)
        socket_connection.connect((host, port))
        ssl_flag = False
    except ConnectionRefusedError:
        return None

    try:
        if sys.version_info >= (3, 13):
            # Python 3.13+ requires SSLContext
            context = ssl.create_default_context()
            socket_connection = context.wrap_socket(socket_connection)
        else:
            # Older versions use direct wrap_socket
            socket_connection = ssl.wrap_socket(socket_connection)
        ssl_flag = True
    except Exception:
        # If SSL wrapping fails, try plain socket again
        try:
            socket_connection = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            socket_connection.settimeout(timeout)
            socket_connection.connect((host, port))
            ssl_flag = False
        except Exception:
            return None

    return socket_connection, ssl_flag


class SocketLibrary(BaseLibrary):
    def tcp_connect_only(self, host, port, timeout):
        tcp_socket = create_tcp_socket(host, port, timeout)
        if tcp_socket is None:
            return None

        socket_connection, ssl_flag = tcp_socket
        peer_name = socket_connection.getpeername()
        socket_connection.close()
        return {
            "peer_name": peer_name,
            "service": socket.getservbyport(int(port)),
            "ssl_flag": ssl_flag,
        }

    def tcp_connect_send_and_receive(self, host, port, timeout):
        tcp_socket = create_tcp_socket(host, port, timeout)
        if tcp_socket is None:
            return None

        socket_connection, ssl_flag = tcp_socket
        peer_name = socket_connection.getpeername()
        try:
            socket_connection.send(b"ABC\x00\r\n\r\n\r\n" * 10)
            response = socket_connection.recv(1024 * 1024 * 10)
            socket_connection.close()
        except Exception:
            try:
                socket_connection.close()
                response = b""
            except Exception:
                response = b""
        return {
            "peer_name": peer_name,
            "service": socket.getservbyport(port),
            "response": response.decode(errors="ignore"),
            "ssl_flag": ssl_flag,
        }

    def socket_icmp(self, host, timeout):
        icmp_socket = socket.getprotobyname("icmp")
        socket_connection = socket.socket(socket.AF_INET, socket.SOCK_RAW, icmp_socket)
        random_integer = os.getpid() & 0xFFFF
        icmp_echo_request = 8
        dummy_checksum = 0
        header = struct.pack(
            "bbHHh", icmp_echo_request, 0, dummy_checksum, random_integer, 1
        )
        data = (
            struct.pack("d", time.time())
            + struct.pack("d", time.time())
            + str((76 - struct.calcsize("d")) * "Q").encode()
        )
        source_string = header + data
        
        calculate_data = 0
        max_size = (len(source_string) / 2) * 2
        counter = 0
        while counter < max_size:
            calculate_data += source_string[counter + 1] * 256 + source_string[counter]
            calculate_data = calculate_data & 0xFFFFFFFF
            counter += 2

        if max_size < len(source_string):
            calculate_data += source_string[len(source_string) - 1]
            calculate_data = calculate_data & 0xFFFFFFFF

        calculate_data = (calculate_data >> 16) + (calculate_data & 0xFFFF)
        calculate_data = calculate_data + (calculate_data >> 16)
        calculated_data = ~calculate_data & 0xFFFF

        dummy_checksum = calculated_data >> 8 | (calculated_data << 8 & 0xFF00)

        header = struct.pack(
            "bbHHh",
            icmp_echo_request,
            0,
            socket.htons(dummy_checksum),
            random_integer,
            1,
        )
        socket_connection.sendto(header + data, (socket.gethostbyname(host), 1))

        while True:
            started_select = time.time()
            what_ready = select.select([socket_connection], [], [], timeout)
            how_long_in_select = time.time() - started_select
            if not what_ready[0]:
                break
            time_received = time.time()
            received_packet, address = socket_connection.recvfrom(1024)
            icmp_header = received_packet[20:28]
            (
                packet_type,
                packet_code,
                packet_checksum,
                packet_id,
                packet_sequence,
            ) = struct.unpack("bbHHh", icmp_header)
            if packet_id == random_integer:
                packet_bytes = struct.calcsize("d")
                time_sent = struct.unpack("d", received_packet[28 : 28 + packet_bytes])[0]
                delay = time_received - time_sent
                break

            timeout = timeout - how_long_in_select
            if timeout <= 0:
                break
        socket_connection.close()
        return {"host": host, "response_time": delay, "ssl_flag": False}


class SocketEngine(BaseEngine):
    library = SocketLibrary

    def response_conditions_matched(self, sub_step, response):
        conditions = sub_step["response"]["conditions"]
        condition_type = sub_step["response"]["condition_type"]
        condition_results = {}
        if sub_step["method"] == "tcp_connect_only":
            return response
        if sub_step["method"] == "tcp_connect_send_and_receive":
            if response:
                for condition in conditions:
                    regex = re.findall(
                        re.compile(conditions[condition]["regex"]),
                        (
                            response["response"]
                            if condition != "open_port"
                            else str(response["peer_name"][1])
                        ),
                    )
                    reverse = conditions[condition]["reverse"]
                    condition_results[condition] = reverse_and_regex_condition(
                        regex, reverse
                    )
                for condition in copy.deepcopy(condition_results):
                    if not condition_results[condition]:
                        del condition_results[condition]
                if "open_port" in condition_results and len(condition_results) > 1:
                    del condition_results["open_port"]
                    del conditions["open_port"]
                if condition_type == "and":
                    return (
                        condition_results
                        if len(condition_results) == len(conditions)
                        else []
                    )
                if condition_type == "or":
                    return condition_results if condition_results else []
                return []
        if sub_step["method"] == "socket_icmp":
            return response
        return []

    def apply_extra_data(self, sub_step, response):
        sub_step["response"]["ssl_flag"] = (
            response["ssl_flag"] if isinstance(response, dict) else False
        )
        sub_step["response"]["conditions_results"] = self.response_conditions_matched(
            sub_step, response
        )