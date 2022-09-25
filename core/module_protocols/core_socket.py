#!/usr/bin/env python
# -*- coding: utf-8 -*-

import socket
import copy
import re
import os
import select
import struct
import time
import ssl
from core.utility import reverse_and_regex_condition
from core.utility import process_conditions
from core.utility import get_dependent_results_from_database
from core.utility import replace_dependent_values


def response_conditions_matched(sub_step, response):
    conditions = sub_step['response']['conditions']
    condition_type = sub_step['response']['condition_type']
    condition_results = {}
    if sub_step['method'] == 'tcp_connect_only':
        return response
    if sub_step['method'] == 'tcp_connect_send_and_receive':
        if response:
            received_content = response['response']
            for condition in conditions:
                regex = re.findall(re.compile(conditions[condition]['regex']), received_content)
                reverse = conditions[condition]['reverse']
                condition_results[condition] = reverse_and_regex_condition(regex, reverse)
            for condition in copy.deepcopy(condition_results):
                if not condition_results[condition]:
                    del condition_results[condition]
            if 'open_port' in condition_results and len(condition_results) > 1:
                del condition_results['open_port']
                del conditions['open_port']
            if condition_type == 'and':
                return condition_results if len(condition_results) == len(conditions) else []
            if condition_type == 'or':
                return condition_results if condition_results else []
            return []
    if sub_step['method'] == 'socket_icmp':
        return response
    return []


def create_tcp_socket(host, ports, timeout):
    socket_connection = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    socket_connection.settimeout(timeout)
    socket_connection.connect((host, int(ports)))
    ssl_flag = False
    try:
        socket_connection = ssl.wrap_socket(socket_connection)
        ssl_flag = True
    except Exception:
        socket_connection = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        socket_connection.settimeout(timeout)
        socket_connection.connect((host, int(ports)))
    return socket_connection, ssl_flag


class NettackerSocket:
    def tcp_connect_only(host, ports, timeout):
        socket_connection, ssl_flag = create_tcp_socket(host, ports, timeout)
        peer_name = socket_connection.getpeername()
        socket_connection.close()
        return {
            "peer_name": peer_name,
            "service": socket.getservbyport(int(ports)),
            "ssl_flag": ssl_flag
        }

    def tcp_connect_send_and_receive(host, ports, timeout):
        socket_connection, ssl_flag = create_tcp_socket(host, ports, timeout)
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
            "service": socket.getservbyport(int(ports)),
            "response": response.decode(errors='ignore'),
            "ssl_flag": ssl_flag
        }

    def socket_icmp(host, timeout):
        """
            A pure python ping implementation using raw socket.
            Note that ICMP messages can only be sent from processes running as root.
            Derived from ping.c distributed in Linux's netkit. That code is
            copyright (c) 1989 by The Regents of the University of California.
            That code is in turn derived from code written by Mike Muuss of the
            US Army Ballistic Research Laboratory in December, 1983 and
            placed in the public domain. They have my thanks.
            Bugs are naturally mine. I'd be glad to hear about them. There are
            certainly word - size dependenceies here.
            Copyright (c) Matthew Dixon Cowles, <http://www.visi.com/~mdc/>.
            Distributable under the terms of the GNU General Public License
            version 2. Provided with no warranties of any sort.
            Original Version from Matthew Dixon Cowles:
              -> ftp://ftp.visi.com/users/mdc/ping.py
            Rewrite by Jens Diemer:
              -> http://www.python-forum.de/post-69122.html#69122
            Rewrite by George Notaras:
              -> http://www.g-loaded.eu/2009/10/30/python-ping/
            Fork by Pierre Bourdon:
              -> http://bitbucket.org/delroth/python-ping/
            Revision history
            ~~~~~~~~~~~~~~~~
            November 22, 1997
            -----------------
            Initial hack. Doesn't do much, but rather than try to guess
            what features I (or others) will want in the future, I've only
            put in what I need now.
            December 16, 1997
            -----------------
            For some reason, the checksum bytes are in the wrong order when
            this is run under Solaris 2.X for SPARC but it works right under
            Linux x86. Since I don't know just what's wrong, I'll swap the
            bytes always and then do an htons().
            December 4, 2000
            ----------------
            Changed the struct.pack() calls to pack the checksum and ID as
            unsigned. My thanks to Jerome Poincheval for the fix.
            May 30, 2007
            ------------
            little rewrite by Jens Diemer:
             -  change socket asterisk import to a normal import
             -  replace time.time() with time.clock()
             -  delete "return None" (or change to "return" only)
             -  in checksum() rename "str" to "source_string"
            November 8, 2009
            ----------------
            Improved compatibility with GNU/Linux systems.
            Fixes by:
             * George Notaras -- http://www.g-loaded.eu
            Reported by:
             * Chris Hallman -- http://cdhallman.blogspot.com
            Changes in this release:
             - Re-use time.time() instead of time.clock(). The 2007 implementation
               worked only under Microsoft Windows. Failed on GNU/Linux.
               time.clock() behaves differently under the two OSes[1].
            [1] http://docs.python.org/library/time.html#time.clock
            September 25, 2010
            ------------------
            Little modifications by Georgi Kolev:
             -  Added quiet_ping function.
             -  returns percent lost packages, max round trip time, avrg round trip
                time
             -  Added packet size to verbose_ping & quiet_ping functions.
             -  Bump up version to 0.2
            ------------------
            5 Aug 2021 - Modified by Ali Razmjoo Qalaei (Reformat the code and more human readable)
        """
        icmp_socket = socket.getprotobyname("icmp")
        socket_connection = socket.socket(
            socket.AF_INET,
            socket.SOCK_RAW,
            icmp_socket
        )
        random_integer = os.getpid() & 0xFFFF
        icmp_echo_request = 8
        # Make a dummy header with a 0 checksum.
        dummy_checksum = 0
        header = struct.pack("bbHHh", icmp_echo_request, 0, dummy_checksum, random_integer, 1)
        data = struct.pack("d", time.time()) + struct.pack("d", time.time()) + str(
            (76 - struct.calcsize("d")) * "Q"
        ).encode()  # packet size = 76 (removed 8 bytes size of header)
        source_string = header + data
        # Calculate the checksum on the data and the dummy header.
        calculate_data = 0
        max_size = (len(source_string) / 2) * 2
        counter = 0
        while counter < max_size:
            calculate_data += source_string[counter + 1] * 256 + source_string[counter]
            calculate_data = calculate_data & 0xffffffff  # Necessary?
            counter += 2

        if max_size < len(source_string):
            calculate_data += source_string[len(source_string) - 1]
            calculate_data = calculate_data & 0xffffffff  # Necessary?

        calculate_data = (calculate_data >> 16) + (calculate_data & 0xffff)
        calculate_data = calculate_data + (calculate_data >> 16)
        calculated_data = ~calculate_data & 0xffff

        # Swap bytes. Bugger me if I know why.
        dummy_checksum = calculated_data >> 8 | (calculated_data << 8 & 0xff00)

        header = struct.pack(
            "bbHHh", icmp_echo_request, 0, socket.htons(dummy_checksum), random_integer, 1
        )
        socket_connection.sendto(header + data, (socket.gethostbyname(host), 1))  # Don't know about the 1

        while True:
            started_select = time.time()
            what_ready = select.select([socket_connection], [], [], timeout)
            how_long_in_select = (time.time() - started_select)
            if not what_ready[0]:  # Timeout
                break
            time_received = time.time()
            received_packet, address = socket_connection.recvfrom(1024)
            icmp_header = received_packet[20:28]
            packet_type, packet_code, packet_checksum, packet_id, packet_sequence = struct.unpack(
                "bbHHh", icmp_header
            )
            if packet_id == random_integer:
                packet_bytes = struct.calcsize("d")
                time_sent = struct.unpack("d", received_packet[28:28 + packet_bytes])[0]
                delay = time_received - time_sent
                break

            timeout = timeout - how_long_in_select
            if timeout <= 0:
                break
        socket_connection.close()
        return {
            "host": host,
            "response_time": delay,
            "ssl_flag": False
        }


class Engine:
    def run(
            sub_step,
            module_name,
            target,
            scan_unique_id,
            options,
            process_number,
            module_thread_number,
            total_module_thread_number,
            request_number_counter,
            total_number_of_requests
    ):
        backup_method = copy.deepcopy(sub_step['method'])
        backup_response = copy.deepcopy(sub_step['response'])
        del sub_step['method']
        del sub_step['response']
        if 'dependent_on_temp_event' in backup_response:
            temp_event = get_dependent_results_from_database(
                target,
                module_name,
                scan_unique_id,
                backup_response['dependent_on_temp_event']
            )
            sub_step = replace_dependent_values(
                sub_step,
                temp_event
            )
        action = getattr(NettackerSocket, backup_method, None)
        for _ in range(options['retries']):
            try:
                response = action(**sub_step)
                break
            except Exception:
                response = []
        sub_step['method'] = backup_method
        sub_step['response'] = backup_response
        sub_step['response']['ssl_flag'] = response['ssl_flag'] if type(response) == dict else False
        sub_step['response']['conditions_results'] = response_conditions_matched(sub_step, response)
        return process_conditions(
            sub_step,
            module_name,
            target,
            scan_unique_id,
            options,
            response,
            process_number,
            module_thread_number,
            total_module_thread_number,
            request_number_counter,
            total_number_of_requests
        )
