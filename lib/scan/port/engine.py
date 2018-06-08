#!/usr/bin/env python
# -*- coding: utf-8 -*-

import socket
import socks
import time
import json
import threading
import string
import random
import os
import logging
from core.alert import *
from core.targets import target_type
from core.targets import target_to_host
from core.load_modules import load_file_path
from lib.socks_resolver.engine import getaddrinfo
from core._time import now
from core.log import __log_into_file
from core.compatible import is_windows
from lib.payload.scanner.service.engine import discover_by_port

logging.getLogger("scapy.runtime").setLevel(logging.CRITICAL)


def extra_requirements_dict():
    return {  # 1000 common ports used by nmap scanner
        "port_scan_stealth": ["False"],
        "udp_scan" : ["False"],
        "port_scan_ports": [1, 3, 4, 6, 7, 9, 13, 17, 19, 20, 21, 22, 23, 24, 25, 26, 30, 32, 33, 37, 42,
                            43, 49, 53, 67, 68, 69, 70, 79, 80, 81, 82, 83, 84, 85, 88, 89, 90, 99, 100, 106, 109, 110,
                            111, 113, 119, 125, 135, 139, 143, 144, 146, 161, 162, 163, 179, 199, 211, 212, 222,
                            254, 255, 256, 259, 264, 280, 301, 306, 311, 340, 366, 389, 406, 407, 416, 417,
                            425, 427, 443, 444, 445, 458, 464, 465, 481, 497, 500, 512, 513, 514, 515, 524,
                            541, 543, 544, 545, 548, 554, 555, 563, 587, 593, 616, 617, 625, 631, 636, 646,
                            648, 666, 667, 668, 683, 687, 691, 700, 705, 711, 714, 720, 722, 726, 749, 765,
                            777, 783, 787, 800, 801, 808, 843, 873, 880, 888, 898, 900, 901, 902, 903, 911,
                            912, 981, 987, 990, 992, 993, 995, 999, 1000, 1001, 1002, 1007, 1009, 1010,
                            1011, 1021, 1022, 1023, 1024, 1025, 1026, 1027, 1028, 1029, 1030, 1031, 1032,
                            1033, 1034, 1035, 1036, 1037, 1038, 1039, 1040, 1041, 1042, 1043, 1044, 1045,
                            1046, 1047, 1048, 1049, 1050, 1051, 1052, 1053, 1054, 1055, 1056, 1057, 1058,
                            1059, 1060, 1061, 1062, 1063, 1064, 1065, 1066, 1067, 1068, 1069, 1070, 1071,
                            1072, 1073, 1074, 1075, 1076, 1077, 1078, 1079, 1080, 1081, 1082, 1083, 1084,
                            1085, 1086, 1087, 1088, 1089, 1090, 1091, 1092, 1093, 1094, 1095, 1096, 1097,
                            1098, 1099, 1100, 1102, 1104, 1105, 1106, 1107, 1108, 1110, 1111, 1112, 1113,
                            1114, 1117, 1119, 1121, 1122, 1123, 1124, 1126, 1130, 1131, 1132, 1137, 1138,
                            1141, 1145, 1147, 1148, 1149, 1151, 1152, 1154, 1163, 1164, 1165, 1166, 1169,
                            1174, 1175, 1183, 1185, 1186, 1187, 1192, 1198, 1199, 1201, 1213, 1216, 1217,
                            1218, 1233, 1234, 1236, 1244, 1247, 1248, 1259, 1271, 1272, 1277, 1287, 1296,
                            1300, 1301, 1309, 1310, 1311, 1322, 1328, 1334, 1352, 1417, 1433, 1434, 1443,
                            1455, 1461, 1494, 1500, 1501, 1503, 1521, 1524, 1533, 1556, 1580, 1583, 1594,
                            1600, 1641, 1658, 1666, 1687, 1688, 1700, 1717, 1718, 1719, 1720, 1721, 1723,
                            1755, 1761, 1782, 1783, 1801, 1805, 1812, 1839, 1840, 1862, 1863, 1864, 1875,
                            1900, 1914, 1935, 1947, 1971, 1972, 1974, 1984, 1998, 1999, 2000, 2001, 2002,
                            2003, 2004, 2005, 2006, 2007, 2008, 2009, 2010, 2013, 2020, 2021, 2022, 2030,
                            2033, 2034, 2035, 2038, 2040, 2041, 2042, 2043, 2045, 2046, 2047, 2048, 2049,
                            2065, 2068, 2099, 2100, 2103, 2105, 2106, 2107, 2111, 2119, 2121, 2126, 2135,
                            2144, 2160, 2161, 2170, 2179, 2190, 2191, 2196, 2200, 2222, 2251, 2260, 2288,
                            2301, 2323, 2366, 2381, 2382, 2383, 2393, 2394, 2399, 2401, 2492, 2500, 2522,
                            2525, 2557, 2601, 2602, 2604, 2605, 2607, 2608, 2638, 2701, 2702, 2710, 2717,
                            2718, 2725, 2800, 2809, 2811, 2869, 2875, 2909, 2910, 2920, 2967, 2968, 2998,
                            3000, 3001, 3003, 3005, 3006, 3007, 3011, 3013, 3017, 3030, 3031, 3052, 3071,
                            3077, 3128, 3168, 3211, 3221, 3260, 3261, 3268, 3269, 3283, 3300, 3301, 3306,
                            3322, 3323, 3324, 3325, 3333, 3351, 3367, 3369, 3370, 3371, 3372, 3389, 3390,
                            3404, 3476, 3493, 3517, 3527, 3546, 3551, 3580, 3659, 3689, 3690, 3703, 3737,
                            3766, 3784, 3800, 3801, 3809, 3814, 3826, 3827, 3828, 3851, 3869, 3871, 3878,
                            3880, 3889, 3905, 3914, 3918, 3920, 3945, 3971, 3986, 3995, 3998, 4000, 4001,
                            4002, 4003, 4004, 4005, 4006, 4045, 4111, 4125, 4126, 4129, 4224, 4242, 4279,
                            4321, 4343, 4443, 4444, 4445, 4446, 4449, 4550, 4567, 4662, 4848, 4899, 4900,
                            4998, 5000, 5001, 5002, 5003, 5004, 5009, 5030, 5033, 5050, 5051, 5054, 5060,
                            5061, 5080, 5087, 5100, 5101, 5102, 5120, 5190, 5200, 5214, 5221, 5222, 5225,
                            5226, 5269, 5280, 5298, 5357, 5405, 5414, 5431, 5432, 5440, 5500, 5510, 5544,
                            5550, 5555, 5560, 5566, 5631, 5633, 5666, 5678, 5679, 5718, 5730, 5800, 5801,
                            5802, 5810, 5811, 5815, 5822, 5825, 5850, 5859, 5862, 5877, 5900, 5901, 5902,
                            5903, 5904, 5906, 5907, 5910, 5911, 5915, 5922, 5925, 5950, 5952, 5959, 5960,
                            5961, 5962, 5963, 5987, 5988, 5989, 5998, 5999, 6000, 6001, 6002, 6003, 6004,
                            6005, 6006, 6007, 6009, 6025, 6059, 6100, 6101, 6106, 6112, 6123, 6129, 6156,
                            6346, 6389, 6502, 6510, 6543, 6547, 6565, 6566, 6567, 6580, 6646, 6666, 6667,
                            6668, 6669, 6689, 6692, 6699, 6779, 6788, 6789, 6792, 6839, 6881, 6901, 6969,
                            7000, 7001, 7002, 7004, 7007, 7019, 7025, 7070, 7100, 7103, 7106, 7200, 7201,
                            7402, 7435, 7443, 7496, 7512, 7625, 7627, 7676, 7741, 7777, 7778, 7800, 7911,
                            7920, 7921, 7937, 7938, 7999, 8000, 8001, 8002, 8007, 8008, 8009, 8010, 8011,
                            8021, 8022, 8031, 8042, 8045, 8080, 8081, 8082, 8083, 8084, 8085, 8086, 8087,
                            8088, 8089, 8090, 8093, 8099, 8100, 8180, 8181, 8192, 8193, 8194, 8200, 8222,
                            8254, 8290, 8291, 8292, 8300, 8333, 8383, 8400, 8402, 8443, 8500, 8600, 8649,
                            8651, 8652, 8654, 8701, 8800, 8873, 8888, 8899, 8994, 9000, 9001, 9002, 9003,
                            9009, 9010, 9011, 9040, 9050, 9071, 9080, 9081, 9090, 9091, 9099, 9100, 9101,
                            9102, 9103, 9110, 9111, 9200, 9207, 9220, 9290, 9415, 9418, 9485, 9500, 9502,
                            9503, 9535, 9575, 9593, 9594, 9595, 9618, 9666, 9876, 9877, 9878, 9898, 9900,
                            9917, 9929, 9943, 9944, 9968, 9998, 9999, 10000, 10001, 10002, 10003, 10004,
                            10009, 10010, 10012, 10024, 10025, 10082, 10180, 10215, 10243, 10566, 10616,
                            10617, 10621, 10626, 10628, 10629, 10778, 11110, 11111, 11967, 12000, 12174,
                            12265, 12345, 13456, 13722, 13782, 13783, 14000, 14238, 14441, 14442, 15000,
                            15002, 15003, 15004, 15660, 15742, 16000, 16001, 16012, 16016, 16018, 16080,
                            16113, 16992, 16993, 17877, 17988, 18040, 18101, 18988, 19101, 19283, 19315,
                            19350, 19780, 19801, 19842, 20000, 20005, 20031, 20221, 20222, 20828, 21571,
                            22939, 23502, 24444, 24800, 25734, 25735, 26214, 27000, 27352, 27353, 27355,
                            27356, 27715, 28201, 30000, 30718, 30951, 31038, 31337, 32768, 32769, 32770,
                            32771, 32772, 32773, 32774, 32775, 32776, 32777, 32778, 32779, 32780, 32781,
                            32782, 32783, 32784, 32785, 33354, 33899, 34571, 34572, 34573, 35500, 38292,
                            40193, 40911, 41511, 42510, 44176, 44442, 44443, 44501, 45100, 48080, 49152,
                            49153, 49154, 49155, 49156, 49157, 49158, 49159, 49160, 49161, 49163, 49165,
                            49167, 49175, 49176, 49400, 49999, 50000, 50001, 50002, 50003, 50006, 50300,
                            50389, 50500, 50636, 50800, 51103, 51493, 52673, 52822, 52848, 52869, 54045,
                            54328, 55055, 55056, 55555, 55600, 56737, 56738, 57294, 57797, 58080, 60020,
                            60443, 61532, 61900, 62078, 63331, 64623, 64680, 65000, 65129, 65389]
    }


if "--method-args" in sys.argv and "port_scan_stealth" in " ".join(sys.argv).lower():
    from scapy.all import *

    if is_windows():  # fix later
        from scapy.base_classes import Gen, SetGen
        import scapy.plist as plist
        from scapy.utils import PcapReader
        from scapy.data import MTU, ETH_P_ARP
        import re
        import sys
        import itertools
    WINDOWS = True
    conf.verb = 0
    conf.nofilter = 1

def check_closed(ip):
    for i in range(1, 10):
        s = sr1(IP(dst=ip) / TCP(dport=i), timeout=2, verbose=0)
        if s != 'SA' and s is not None:
            return i
    return 0


def filter_port(ip, port):
    closed_port = check_closed(ip)
    s = sr1(IP(dst=str(ip)) / TCP(dport=port, flags='S'), timeout=2, verbose=0)
    try:
        if s != 'SA':
            try:
                if s[0][1].seq == 0:
                    pass
            except:
                s = sr1(IP(dst=ip) / TCP(dport=closed_port, flags='S'), timeout=2, verbose=0)
                if s == None:
                    return None
                else:
                    return True
    except:
        pass


def stealth(host, port, timeout_sec, log_in_file, language, time_sleep, thread_tmp_filename, socks_proxy, scan_id,
            scan_cmd, stealth_flag):
    try:
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
        src_port = RandShort()

        stealth_scan_resp = sr1(
            IP(dst=host) / TCP(sport=src_port, dport=port, flags="S"), timeout=int(timeout_sec))
        if (str(type(stealth_scan_resp)) == "<type 'NoneType'>"):
            # "Filtered"
            pass
        elif (stealth_scan_resp.haslayer(TCP)):
            if (stealth_scan_resp.getlayer(TCP).flags == 0x12):
                # send_rst = sr(IP(dst=host) / TCP(sport=src_port, dport=port, flags="R"), timeout=timeout_sec)
                try:
                    service_name = "/" + discover_by_port(host, port, timeout_sec, b"ABC\x00\r\n" * 10, socks_proxy,
                                                          external_run=True)
                except Exception as _:
                    service_name = None
                if not service_name or service_name == "/UNKNOWN":
                    try:
                        service_name = "/" + socket.getservbyport(port)
                    except Exception:
                        service_name = ""
                data = json.dumps(
                    {'HOST': host, 'USERNAME': '', 'PASSWORD': '', 'PORT': port, 'TYPE': 'port_scan',
                     'DESCRIPTION': messages(language, "port/type").format(str(port) + service_name, "STEALTH"),
                     'TIME': now(),
                     'CATEGORY': "scan", 'SCAN_ID': scan_id,
                     'SCAN_CMD': scan_cmd}) + '\n'
                __log_into_file(log_in_file, 'a', data, language)
                __log_into_file(thread_tmp_filename, 'w', '0', language)
            elif (stealth_scan_resp.getlayer(TCP).flags == 0x14):
                # "Closed"
                pass
        elif (stealth_scan_resp.haslayer(ICMP)):
            if (int(stealth_scan_resp.getlayer(ICMP).type) == 3
                    and int(stealth_scan_resp.getlayer(ICMP).code) in [1, 2, 3, 9, 10, 13]):
                pass
        else:
            # "CHECK"
            pass
        return True
    except:
        return False

def __udp(host, port, timeout_sec, log_in_file, language, time_sleep, thread_tmp_filename, socks_proxy, scan_id,
            scan_cmd, stealth_flag):
    try:
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
                socket.getaddrinfo = getaddrinfo
        data = "\n\n\n\n\n\n\n\n\n\n\n\n\n\n"
        if target_type(host) == "SINGLE_IPv6":
            s = socket.socket(socket.AF_INET6, socket.SOCK_DGRAM, 0)
        else:
            s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        if timeout_sec is not None:
            s.settimeout(timeout_sec)
        if target_type(host) == "SINGLE_IPv6":
            s.sendto((host, port, 0, 0))
        else:
            s.sendto(data,(host,port))
        try:
            s.recvfrom(4096)
        except:
            return False
        try:
            service_name = "/" + socket.getservbyport(port)
        except Exception:
            service_name = ""
        info(messages(language, "port_found").format(host, str(port) + service_name, "UDP"), log_in_file,
             "a", {'HOST': host, 'USERNAME': '', 'PASSWORD': '', 'PORT': port, 'TYPE': 'port_scan',
                   'DESCRIPTION': messages(language, "port/type").format(str(port) + service_name, "UDP"),
                   'TIME': now(), 'CATEGORY': "scan", 'SCAN_ID': scan_id, 'SCAN_CMD': scan_cmd}, language,
             thread_tmp_filename)
        s.close()
        return True
    except socket.timeout:
        try:
            service_name = "/" + discover_by_port(host, port, timeout_sec, b"ABC\x00\r\n" * 10, socks_proxy,
                                                  external_run=True)
        except Exception as _:
            service_name = None
        if not service_name or service_name == "/UNKNOWN":
            try:
                service_name = "/" + socket.getservbyport(port)
            except Exception:
                service_name = ""
        try:
            if filter_port(host, port):
                info(messages(language, "port_found").format(host, str(port) + service_name, "TCP_CONNECT"))
                data = json.dumps({'HOST': host, 'USERNAME': '', 'PASSWORD': '', 'PORT': port, 'TYPE': 'port_scan',
                                   'DESCRIPTION': messages(language, "port/type").format(str(port) + service_name,
                                                                                         "TCP_CONNECT"),
                                   'TIME': now(), 'CATEGORY': "scan", 'SCAN_ID': scan_id, 'SCAN_CMD': scan_cmd}) + '\n'
                __log_into_file(log_in_file, 'a', data, language)
                __log_into_file(thread_tmp_filename, 'w', '0', language)
        except:
            pass
    except:
        return False


def connect(host, port, timeout_sec, log_in_file, language, time_sleep, thread_tmp_filename, socks_proxy, scan_id,
            scan_cmd, stealth_flag):
    try:
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
                socket.getaddrinfo = getaddrinfo
        if target_type(host) == "SINGLE_IPv6":
            s = socket.socket(socket.AF_INET6, socket.SOCK_STREAM, 0)
        else:
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        if timeout_sec is not None:
            s.settimeout(timeout_sec)
        if target_type(host) == "SINGLE_IPv6":
            s.connect((host, port, 0, 0))
        else:
            s.connect((host, port))
        try:
            service_name = "/" + discover_by_port(host, port, timeout_sec, b"ABC\x00\r\n" * 10, socks_proxy,
                                                  external_run=True)
        except Exception as _:
            service_name = None
        if not service_name or service_name == "/UNKNOWN":
            try:
                service_name = "/" + socket.getservbyport(port)
            except Exception:
                service_name = ""
        info(messages(language, "port_found").format(host, str(port) + service_name, "TCP_CONNECT"), log_in_file,
             "a", {'HOST': host, 'USERNAME': '', 'PASSWORD': '', 'PORT': port, 'TYPE': 'port_scan',
                   'DESCRIPTION': messages(language, "port/type").format(str(port) + service_name, "TCP_CONNECT"),
                   'TIME': now(), 'CATEGORY': "scan", 'SCAN_ID': scan_id, 'SCAN_CMD': scan_cmd}, language,
             thread_tmp_filename)
        s.close()
        return True
    except socket.timeout:
        try:
            service_name = "/" + discover_by_port(host, port, timeout_sec, b"ABC\x00\r\n" * 10, socks_proxy,
                                                  external_run=True)
        except Exception as _:
            service_name = None
        if not service_name or service_name == "/UNKNOWN":
            try:
                service_name = "/" + socket.getservbyport(port)
            except Exception:
                service_name = ""
        try:
            if filter_port(host, port):
                info(messages(language, "port_found").format(host, str(port) + service_name, "TCP_CONNECT"))
                data = json.dumps({'HOST': host, 'USERNAME': '', 'PASSWORD': '', 'PORT': port, 'TYPE': 'port_scan',
                                   'DESCRIPTION': messages(language, "port/type").format(str(port) + service_name,
                                                                                         "TCP_CONNECT"),
                                   'TIME': now(), 'CATEGORY': "scan", 'SCAN_ID': scan_id, 'SCAN_CMD': scan_cmd}) + '\n'
                __log_into_file(log_in_file, 'a', data, language)
                __log_into_file(thread_tmp_filename, 'w', '0', language)
        except:
            pass
    except:
        return False


def start(target, users, passwds, ports, timeout_sec, thread_number, num, total, log_in_file, time_sleep, language,
          verbose_level, socks_proxy, retries, methods_args, scan_id, scan_cmd):  # Main function
    if target_type(target) != 'SINGLE_IPv4' or target_type(target) != 'DOMAIN' or target_type(
            target) != 'HTTP' or target_type(target) != 'SINGLE_IPv6':
        # requirements check
        new_extra_requirements = extra_requirements_dict()
        if methods_args is not None:
            for extra_requirement in extra_requirements_dict():
                if extra_requirement in methods_args:
                    new_extra_requirements[
                        extra_requirement] = methods_args[extra_requirement]
        extra_requirements = new_extra_requirements
        if ports is None:
            ports = extra_requirements["port_scan_ports"]
        try:
            if extra_requirements["port_scan_stealth"][0].lower() == "true":
                stealth_flag = True
                udp_flag = False
            elif extra_requirements["udp_scan"][0].lower() == "true":
                stealth_flag = False
                udp_flag = True
            else:
                stealth_flag = False
                udp_flag = False
        except Exception:
            udp_flag = False
            stealth_flag = False

        if target_type(target) == 'HTTP':
            target = target_to_host(target)
        threads = []
        total_req = len(ports)
        thread_tmp_filename = '{}/tmp/thread_tmp_'.format(load_file_path()) + ''.join(
            random.choice(string.ascii_letters + string.digits) for _ in range(20))
        __log_into_file(thread_tmp_filename, 'w', '1', language)
        trying = 0
        keyboard_interrupt_flag = False
        for port in ports:
            t = threading.Thread(target = stealth if stealth_flag else (__udp if udp_flag else connect),
                                 args=(target, int(port), timeout_sec, log_in_file, language, time_sleep,
                                       thread_tmp_filename, socks_proxy, scan_id, scan_cmd, stealth_flag))
            threads.append(t)
            t.start()
            time.sleep(time_sleep)
            trying += 1
            if verbose_level > 3:
                info(
                    messages(language, "trying_message").format(trying, total_req, num, total, target, port,
                                                                'port_scan'))
            while 1:
                try:
                    if threading.activeCount() >= thread_number:
                        time.sleep(0.01)
                    else:
                        break
                except KeyboardInterrupt:
                    keyboard_interrupt_flag = True
                    break
            if keyboard_interrupt_flag:
                break

        # wait for threads
        kill_switch = 0
        kill_time = int(
            timeout_sec / 0.1) * (5 + timeout_sec) * 10 if int(timeout_sec / 0.1) is not 0 else 2
        while 1:
            time.sleep(0.1)
            kill_switch += 1
            try:
                if threading.activeCount() is 1 or kill_switch is kill_time:
                    break
            except KeyboardInterrupt:
                break
        thread_write = int(open(thread_tmp_filename).read().rsplit()[0])
        if thread_write is 1 and verbose_level is not 0:
            data = json.dumps(
                {'HOST': target, 'USERNAME': '', 'PASSWORD': '', 'PORT': '', 'TYPE': 'port_scan',
                 'DESCRIPTION': messages(language, "no_open_ports"), 'TIME': now(), 'CATEGORY': "scan",
                 'SCAN_ID': scan_id, 'SCAN_CMD': scan_cmd}) + "\n"
            __log_into_file(log_in_file, 'a', data, language)
        os.remove(thread_tmp_filename)

    else:
        warn(messages(language, "input_target_error").format('port_scan', target))
