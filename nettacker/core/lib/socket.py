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
import random

from nettacker.core.lib.probe_sender import raw_to_bytes
from nettacker.core.lib.probes_loader import build_probes_from_yaml
from nettacker.core.lib.Probe_Engine import ProbeEngine
from nettacker.core.lib.base import BaseEngine, BaseLibrary
<<<<<<< HEAD
from nettacker.core.utils.common import reverse_and_regex_condition, replace_dependent_response
from nettacker.core.ip import checksum,resolve_hostname,build_ip_header,get_src_ip,ICMP_PROTO,TCP_PROTO

=======
from nettacker.core.utils.common import replace_dependent_response, reverse_and_regex_condition
>>>>>>> master

log = logging.getLogger(__name__)

def tcp_connect_send_and_receive(host, port, timeout):
        tcp_socket = create_tcp_socket(host, port, timeout)
        if tcp_socket is None:
            return {
                "status":"closed"
            }
        
        socket_connection, ssl_flag = tcp_socket
        peer_name = socket_connection.getpeername()
        try:
            socket_connection.send(b"ABC\x00\r\n\r\n\r\n" * 10)
            response = socket_connection.recv(1024 * 1024 * 10)
            socket_connection.close()
        # except ConnectionRefusedError:
        #     return None
        except Exception:
            try:
                socket_connection.close()
                response = b""
            except Exception:
                response = b""
        try:
            service = socket.getservbyport(port)
        except OSError:
            service = "unknown"

        if response == b"":
            
            return {
                "peer_name": peer_name,
                "response": response.decode(errors="ignore"),
                "service": service,
                "ssl_flag": ssl_flag,
                "status":"filtered"
            }
            
        return {
            "peer_name": peer_name,
            "response": response.decode(errors="ignore"),
            "service": service,
            "ssl_flag": ssl_flag,
            "status":"open"
        }

def udp_scan(dst_ip, dst_port, timeout=3):
    dst_ip = resolve_hostname(dst_ip)

    if dst_ip is None:
        return {
            "status":"closed"
        }
        
    # 1. Setup the ICMP listener FIRST
    try:
        # You need sudo/admin for this
        icmp_socket = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_ICMP)
        icmp_socket.setblocking(False) 
    except PermissionError:
        return {
            "status":"Permission error"
        }

    # 2. Setup the UDP sender
    udp_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    
    # 3. Send the packet (using a small payload is often better than empty)
    udp_socket.sendto(b"PING", (dst_ip, dst_port))
    
    start_time = time.time()
    result = "open|filtered" # Default assumption

    # 4. Listen for the ICMP error
    while time.time() - start_time < timeout:
        # Use select to wait for data on the ICMP socket
        ready = select.select([icmp_socket], [], [], 1)
        
        if ready[0]:
            response, addr = icmp_socket.recvfrom(1024)
            
            # The ICMP packet starts after the IP header (usually 20 bytes)
            # ICMP Type is at byte 20, Code is at byte 21
            icmp_type = response[20]
            icmp_code = response[21]

            # Type 3, Code 3 = Destination Port Unreachable
            if icmp_type == 3:
                if icmp_code == 3:
                    result = "closed"
                    break
                elif icmp_code in [1, 2, 9, 10, 13]:
                    result = "filtered"
                    break

    icmp_socket.close()
    udp_socket.close()
    return{
        "status":result
    }

def create_tcp_socket(host, port, timeout):
    try:
        socket_connection = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        socket_connection.settimeout(timeout)
        socket_connection.connect((host, port))
        ssl_flag = False
    except ConnectionRefusedError:
        pass

    
    try:
        socket_connection = ssl.wrap_socket(socket_connection)
        ssl_flag = True
    except Exception:
        socket_connection = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        socket_connection.settimeout(timeout)
        socket_connection.connect((host, port))
    # finally:
    #     socket_connection.shutdown()

    return socket_connection, ssl_flag

    
class SocketLibrary(BaseLibrary):
    def tcp_connect_only(self, host, port, timeout):
        tcp_socket = create_tcp_socket(host, port, timeout)
        if tcp_socket is None:
            return None

        socket_connection, ssl_flag = tcp_socket
        peer_name = socket_connection.getpeername()
        socket_connection.close()

        try:
            service = socket.getservbyport(port)
        except OSError:
            service = "unknown"

        return {
            "peer_name": peer_name,
            "service": service,
            "ssl_flag": ssl_flag,
        }

    def tcp_and_udp_scan(self, host, port:int, timeout):
        probes_by_name = build_probes_from_yaml()
        tcp_status = tcp_connect_send_and_receive(host , port , timeout)
        tcp_result = None
        udp_result = None
        if tcp_status["status"] != "closed":
            engine = ProbeEngine(
                    port= port,
                    protocol="tcp",
                    host= host,
                    probes_by_name=probes_by_name,
            )
            tcp_result = engine.probe_sequentially()
            if tcp_result != None:
                return tcp_result
        udp_status = udp_scan( host , port , timeout)
        if udp_status["status"] != "closed":
            engine = ProbeEngine(
                    port= port,
                    protocol="udp",
                    host= host,
                    probes_by_name=probes_by_name,
            )
            udp_result = engine.probe_sequentially()
            if udp_result != None:
                return udp_result
            
        
        if tcp_status["status"] == "closed" and udp_status["status"]=="closed":
            return None
        
        print(f"returning the initial result only!")
        return {
            "service":tcp_status["service"],
            "ssl_flag":tcp_status["ssl_flag"],
            "log":["Open|Filtered"]
        }

    
    def socket_icmp(self, host, timeout):
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
        socket_connection = socket.socket(socket.AF_INET, socket.SOCK_RAW, icmp_socket)
        random_integer = os.getpid() & 0xFFFF
        icmp_echo_request = 8
        # Make a dummy header with a 0 checksum.
        dummy_checksum = 0
        header = struct.pack("bbHHh", icmp_echo_request, 0, dummy_checksum, random_integer, 1)
        data = (
            struct.pack("d", time.time())
            + struct.pack("d", time.time())
            + str((76 - struct.calcsize("d")) * "Q").encode()
        )  # packet size = 76 (removed 8 bytes size of header)
        source_string = header + data
        # Calculate the checksum on the data and the dummy header.
        calculate_data = 0
        max_size = (len(source_string) / 2) * 2
        counter = 0
        while counter < max_size:
            calculate_data += source_string[counter + 1] * 256 + source_string[counter]
            calculate_data = calculate_data & 0xFFFFFFFF  # Necessary?
            counter += 2

        if max_size < len(source_string):
            calculate_data += source_string[len(source_string) - 1]
            calculate_data = calculate_data & 0xFFFFFFFF  # Necessary?

        calculate_data = (calculate_data >> 16) + (calculate_data & 0xFFFF)
        calculate_data = calculate_data + (calculate_data >> 16)
        calculated_data = ~calculate_data & 0xFFFF

        # Swap bytes. Bugger me if I know why.
        dummy_checksum = calculated_data >> 8 | (calculated_data << 8 & 0xFF00)

        header = struct.pack(
            "bbHHh",
            icmp_echo_request,
            0,
            socket.htons(dummy_checksum),
            random_integer,
            1,
        )
        socket_connection.sendto(
            header + data, (socket.gethostbyname(host), 1)
        )  # Don't know about the 1

        while True:
            started_select = time.time()
            what_ready = select.select([socket_connection], [], [], timeout)
            how_long_in_select = time.time() - started_select
            if not what_ready[0]:  # Timeout
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
            if packet_id == random_integer and packet_type==0:
                packet_bytes = struct.calcsize("d")
                time_sent = struct.unpack("d", received_packet[28 : 28 + packet_bytes])[0]
                delay = time_received - time_sent
                break

            timeout = timeout - how_long_in_select
            if timeout <= 0:
                break
        socket_connection.close()
        return {"host": host, "response_time": delay, "ssl_flag": False }


    
class SocketEngine(BaseEngine):
    library = SocketLibrary

    def response_conditions_matched(self, sub_step, response):
        if sub_step["method"] == "tcp_connect_only":
            if not response:
                return []
            logs = []
            for k, v in response.items():
                logs.append(f"{k}: {v}")
            return logs

        if sub_step["method"] == "tcp_and_udp_scan":
            log_response = {
                    "running_service": response["service"],
                    "matched_regex": "",
                    "default_service": response["service"],
                    "ssl_flag": response["ssl_flag"],
                }
            logs = []
            condition_results = {}
            logs.append(f"running_service: {response["service"]}")
            logs.append(f"ssl_flag: {response['ssl_flag']}")
            
            if isinstance(response.get("log"), list):
                logs.extend(response["log"])

            condition_results["service"] = [str(log_response)]
            condition_results["log"] = str(logs)
            return condition_results if condition_results else []

        if sub_step["method"] == "socket_icmp":
            if not response:
                return []
            logs = []
            for k, v in response.items():
                logs.append(f"{k}: {v}")
            return logs

        return []

    def apply_extra_data(self, sub_step, response):
        if isinstance(response, list):
            if response:
                response = response[0]
        if response:
            sub_step["response"]["ssl_flag"] = (
                response["ssl_flag"] if isinstance(response, dict) else False
            )
            sub_step["response"]["conditions_results"] = self.response_conditions_matched(
                sub_step, response
            )
