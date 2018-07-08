#!/usr/bin/env python
# -*- coding: utf-8 -*-
# Author: Pradeep Jairamani , github.com/pradeepjairamani
# Service Scanner (Product and Version Detection)

import threading
import socket
import socks
import ssl
import time
import re

from lib.socks_resolver.engine import getaddrinfo

result_dict = {}
external_run_values = []

ports_services_and_condition = {
    "http": ["HTTP", ["OK", "CREATED", "No Content", "Moved Permanently", "Found", "Not Modified", "Permanent Redirect"
                      "Bad Request", "Unauthorized", "Payment Required", "Forbidden", "Not Found", "Method Not Allowed",
                      "Not Acceptable", "Request Timeout", "Unsupported Media Type", "Too Many Requests",
                      "Internal Server Error", "Bad Gateway", "Service Unavailable", "Gateway Timeout",
                      "444 No Response"],
             ],
    "ftp": ["FTP", ["214", "220", "530", "230", "502", "500"]],
    "ssh": ["SSH"],
    "telnet": ["Telnet"],
    "smtp": ["SMTP", ["220", "554", "250"]],
    "imap": ["IMAP"],
    "mariadb": ["MariaDB"],
    "mysql": ["MySQL"],
    "PostgreSQL": ["PostgreSQL"],
    "ILC 150 GSM/GPRS|pcworx": ["ILC 150 GSM/GPRS"],
    "RTSP": ["RTSP"],
    "pptp": [["Firmware:", "Hostname:", "Vendor:", "pptp"]],
    "rsync": [["rsync", "RSYNC"]],
    "portmap": ["Portmap"],
}

ports_services_or_condition = {
    "http": ["400 Bad Request", "401 Unauthorized", "302 Found", "Server: cloudflare", "Server: nginx",
             "Content-Length:", "Content-Type:", "text/html", "application/json", "multipart/form-data",
             "Access-Control-Request-Headers", "Forwarded: for=", "Proxy-Authorization:", "User-Agent:",
             "X-Forwarded-Host", "Content-MD5", ["HTTP", "Authorization"], "Access-Control-Request-Method",
             "Accept-Language", "HTTP", "404 Not Found", "HTML", "Apache"],
    "ftp": [["Pure-FTPd", "----------\r\n"], "\r\n220-You are user number", ["orks FTP server", "VxWorks VxWorks"],
            "530 USER and PASS required", "Server ready.\r\n5", "Invalid command: try being more creative",
            "220 Hotspot FTP server (MikroTik 6.27) ready", "220 SHARP MX-M264N Ver 01.05.00.0n.16.U FTP server.",
            "220 Microsoft FTP Service", "220 FTP Server ready.", "220 Microsoft FTP Service",
            "220 Welcome to virtual FTP service.", "220 DreamHost FTP Server",
            "220 FRITZ!BoxFonWLAN7360SL(UI) FTP server ready.", "Directory status",
            "Service closing control connection", "Requested file action", "Connection closed; transfer aborted",
            "Requested file action not taken", "Directory not empty"],
    "ssh": ["openssh", "-OpenSSH_", "\r\nProtocol mism", "_sshlib GlobalSCAPE\r\n",
            "\x00\x1aversion info line too long","SSH Windows NT Server", "WinNT sshd", "Secure sshd",
            "sshd", "SSH Secure Shell", "WinSSHD"],
    "telnet": ["Welcome to Microsoft Telnet Service", "no decompiling or reverse-engineering shall be allowed",
               "is not a secure protocol", "recommended to use Stelnet", "Login authentication",
               "*WARNING WARNING WARNING WARNING WARNING WARNING WARNING WARNING WARNING*", "NetportExpress",
               "Closing Telnet connection due to host problems", "No more connections are allowed to telnet server",
               "Raptor Firewall Secure Gateway", "Check Point FireWall-1 authenticated Telnet server running on"],
    "smtp": ["Server ready", "SMTP synchronization error", "220-Greetings", "ESMTP Arnet Email Security", "SMTP 2.0",
             "Fidelix Fx2020", "ESMTP"],
    "imap": ["BAD Error in IMAP command received by server", "IMAP4rev1 SASL-IR", "OK [CAPABILITY IMAP4rev1",
             "OK IMAPrev1", "LITERAL+ SASL-IR LOGIN-REFERRALS ID ENABLE IDLE NAMESPACE AUTH=PLAIN AUTH=LOGIN]",
             "CAPABILITY completed"
             "LITERAL+ SASL-IR LOGIN-REFERRALS ID ENABLE IDLE AUTH=PLAIN AUTH=LOGIN AUTH=DIGEST-MD5 AUTH=CRAM-MD5]",
             "Internet Mail Server", "IMAP4 service", "BYE Hi This is the IMAP SSL Redirect"],
    "mariadb": ["is not allowed to connect to this MariaDB server"],
    "mysql": ["is not allowed to connect to this MySQL server"],
    "PostgreSQL": ["fe_sendauth: no password supplied", "no pg_hba.conf entry for host",
                   "received invalid response to SSL negotiation:", "unsupported frontend protocol",
                   "FATAL 1:  invalid length of startup packet",],
    "ILC 150 GSM/GPRS|pcworx": ["PLC Type: ILC 150 GSM/GPRS", "Model Number: 2916545", "Firmware Version: 3.93",
                                "Firmware Version: 3.71", "Firmware Version: 3.70", "Firmware Date:", "Firmware Time:"],
    "RTSP": ["RTSP/1.0 401 Unauthorized", "RTSP/1.0 200 OK", "WWW-Authenticate:", 'Basic realm="device"',
             "Server: Dahua Rtsp Server", "Server: Rtsp Server/2.0", "RTSP/1.0 404 Not Found"],
    "pptp": ["Firmware: 1", "Hostname: pptp server", "Vendor: BRN", "Vendor: Fortinet pptp", "Vendor: AMIT"],
    "rsync": ["@RSYNCD: 30.0", "@RSYNCD: EXIT"],
    "Portmap": ["Program", "Program	Version	Protocol	Port", "portmapper", "status	1", "nfs	2",
                "nlockmgr	1"],
    "antivir": ["Symantec AntiVirus Scan Engine", "antivirus", "NOD32 AntiVirus", "NOD32SS"],
    "nntp": ["NetWare-News-Server", "NetWare nntpd", "nntp", "Leafnode nntpd", "InterNetNews NNRP server INN"],
    "pop3": ["POP3", "POP3 gateway ready", "POP3 Server", "Welcome to mpopd", "OK Hello there"],
}

ports_services_regex = {
    "http": ["HTTP\/[\d.]+\s+[\d]+", ],  # checks for any pattern of type HTTP/1.0 200 OK, etc.
    "ftp": ["FTP\/[\d.]+\s+[\d]+"],  # similar to above in HTTP
    "ssh": ["SSH-([\d.]+)-OpenSSH_([\w._-]+)[ -]{1,2}Debian[ -_](.*ubuntu.*)", ],
    "mysql": [".\0\0\0\xff..Host .* is not allowed to connect to this MySQL server$", ],
    "mariadb": ["[\d.]+[\d][\d]-MariaDB", ],
}


def recv_all(s, limit=4196):
    """
    receive all data from a socket
    Args:
        s: python socket
        limit: limit size to get response
    Returns:
        response or b""
    """
    response = ""
    while len(response) < limit:
        try:
            r = s.recv(1)
            if r != b"":
                response += r.decode()
            else:
                break
        except Exception as _:
            break
    return response


def discover_by_port(host, port, timeout, send_data, socks_proxy, external_run=False):
    """
    request a port to scan and check for existing signatures to discover the service
    Args:
        host: host to scan
        port: port to scan
        timeout: timeout second
        send_data: data to send to port
        socks_proxy: socks proxy
        external_run: if you run this from other module or not calling it from discovery function, you must set
        external_run as True
    Returns:
        discovered services and ports in JSON dict
    """

    ssl_flag = False
    if socks_proxy is not None:
        socks_version = socks.SOCKS5 if socks_proxy.startswith(
            'socks5://') else socks.SOCKS4
        socks_proxy = socks_proxy.rsplit('://')[1]
        if '@' in socks_proxy:
            socks_username = socks_proxy.rsplit(':')[0]
            socks_password = socks_proxy.rsplit(':')[1].rsplit('@')[0]
            socks.set_default_proxy(socks_version, str(socks_proxy.rsplit('@')[1].rsplit(':')[0]),
                                    int(socks_proxy.rsplit(':')[-1]), username=socks_username,
                                    password=socks_password)
            socket.socket = socks.socksocket
            socket.getaddrinfo = getaddrinfo
        else:
            socks.set_default_proxy(socks_version, str(
                socks_proxy.rsplit(':')[0]), int(socks_proxy.rsplit(':')[1]))
            socket.socket = socks.socksocket
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(timeout)
        sock.connect((host, port))
    except Exception as _:
        return None
    try:
        sock = ssl.wrap_socket(sock)
        ssl_flag = True
    except Exception as _:
        # No SSL Support for Service
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(timeout)
            sock.connect((host, port))
        except Exception:
            return None
    data1 = recv_all(sock)
    try:
        sock.send(send_data)
    except Exception as _:
        pass
    final_data = recv_all(sock) + data1  # print( "PORT : " + str(port) +final_data)
    for service in ports_services_and_condition:
        FLAG = True
        c = 0
        for signature in ports_services_and_condition[service]:
            if isinstance(signature, list):
                OFLAG = True
                for s in ports_services_and_condition[service][c]:
                    if s in final_data:
                        OFLAG = False
                if OFLAG:
                    FLAG = False
            else:
                if signature not in final_data:
                    FLAG = False
        if FLAG:
            if ssl_flag:
                result_dict[port] = service + "/ssl"
            else:
                result_dict[port] = service
        c += 1
    for service in ports_services_or_condition:
        FLAG = False
        c = 0
        for signature in ports_services_or_condition[service]:
            if isinstance(signature, list):
                OFLAG = True
                for s in ports_services_or_condition[service][c]:
                    if s not in final_data:
                        OFLAG = False
                if OFLAG:
                    FLAG = True
            else:
                if signature in final_data:
                    FLAG = True
        if FLAG:
            if ssl_flag:
                result_dict[port] = service + "/ssl"
            else:
                result_dict[port] = service
        c += 1
    for service in ports_services_regex:
        for signature in ports_services_regex[service]:
            try:
                pattern = re.compile(signature)
                if pattern.match(final_data):
                    if ssl_flag:
                        result_dict[port] = service + "/ssl"
                    else:
                        result_dict[port] = service
            except Exception as _:
                pass
    try:
        result_dict[port]
    except Exception as _:
        result_dict[port] = "UNKNOWN"
    if external_run and port not in external_run_values:
        external_run_values.append(port)
    return result_dict[port]


def discovery(target, ports=None, timeout=3, thread_number=1000, send_data=None, time_sleep=0, socks_proxy=None):
    """
    Discover the service run on the port, it can detect real service names when users change default port number
    Args:
        target: target to scan
        ports: ports in array, or if None it will test 1000 common ports
        timeout: timeout seconds
        thread_number: thread numbers
        send_data: data to send by socket, if None it will send b"ABC\x00\r\n" * 10 by default
        time_sleep: time to sleep between requests
        socks_proxy: socks proxy
    Returns:
        discovered services and ports in JSON dict
    """

    threads = []
    if not send_data:
        send_data = b"ABC\x00\r\n" * 10
    if not ports:
        from lib.scan.port.engine import extra_requirements_dict as port_scanner_default_ports
        ports = port_scanner_default_ports()["port_scan_ports"]
    for port in ports:
        t = threading.Thread(target=discover_by_port,
                             args=(target, int(port), int(timeout), send_data, socks_proxy))
        threads.append(t)
        t.start()
        time.sleep(time_sleep)
        while 1:
            try:
                if threading.activeCount() <= thread_number:
                    break
                time.sleep(0.01)
            except KeyboardInterrupt:
                break
    kill_switch = 0
    while 1:
        time.sleep(0.01)
        kill_switch += 1
        try:
            if threading.activeCount() is 1 or int(kill_switch) is int(timeout * 5 * 10):
                break
        except KeyboardInterrupt:
            break
    return result_dict
