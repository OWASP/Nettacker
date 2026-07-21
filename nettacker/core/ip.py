import json
import random
import socket
import struct

import netaddr
import requests

ICMP_PROTO = socket.getprotobyname("icmp")
TCP_PROTO = socket.getprotobyname("tcp")


def generate_ip_range(ip_range):
    """
    IP range to CIDR and IPNetwork type

    Args:
        ip_range: IP range

    Returns:
        an array with CIDRs
    """
    if "/" in ip_range:
        return [ip.format() for ip in [cidr for cidr in netaddr.IPNetwork(ip_range)]]
    else:
        ips = []
        for generator_ip_range in [
            cidr.iter_hosts() for cidr in netaddr.iprange_to_cidrs(*ip_range.rsplit("-"))
        ]:
            for ip in generator_ip_range:
                ips.append(ip.format())
        return ips


def get_ip_range(ip):
    """
    get IPv4 range from RIPE online database

    Args:
        ip: IP address

    Returns:
        IP Range
    """
    try:
        return generate_ip_range(
            json.loads(
                requests.get(
                    f"https://rest.db.ripe.net/search.json?query-string={ip}&flags=no-filtering"
                ).content
            )["objects"]["object"][0]["primary-key"]["attribute"][0]["value"].replace(" ", "")
        )
    except Exception:
        return [ip]


def is_single_ipv4(ip):
    """
    to check a value if its IPv4 address

    Args:
        ip: the value to check if its IPv4

    Returns:
         True if it's IPv4 otherwise False
    """
    return netaddr.valid_ipv4(str(ip))


def is_ipv4_range(ip_range):
    try:
        return (
            "/" in ip_range
            and "." in ip_range
            and "-" not in ip_range
            and bool(netaddr.IPNetwork(ip_range))
        )
    except Exception:
        return False


def is_ipv4_cidr(ip_range):
    try:
        return (
            "/" not in ip_range
            and "." in ip_range
            and "-" in ip_range
            and bool(netaddr.iprange_to_cidrs(*ip_range.split("-")))
        )
    except Exception:
        return False


def is_single_ipv6(ip):
    """
    to check a value if its IPv6 address

    Args:
        ip: the value to check if its IPv6

    Returns:
         True if it's IPv6 otherwise False
    """
    return netaddr.valid_ipv6(ip)


def is_ipv6_range(ip_range):
    try:
        return (
            "/" not in ip_range
            and ":" in ip_range
            and "-" in ip_range
            and bool(netaddr.iprange_to_cidrs(*ip_range.split("-")))
        )
    except Exception:
        return False


def is_ipv6_cidr(ip_range):
    try:
        return (
            "/" in ip_range
            and ":" in ip_range
            and "-" not in ip_range
            and bool(netaddr.IPNetwork(ip_range))
        )
    except Exception:
        return False


def checksum(data):
    s = 0
    for i in range(0, len(data), 2):
        word = data[i] << 8 | (data[i + 1] if i + 1 < len(data) else 0)
        s += word
    s = (s >> 16) + (s & 0xFFFF)
    s += s >> 16
    return ~s & 0xFFFF


def build_ip_header(src, dst):
    return struct.pack(
        "!BBHHHBBH4s4s",
        69,  # Version + IHL
        0,
        40,
        random.randint(0, 65535),
        0,
        64,
        TCP_PROTO,
        0,
        socket.inet_aton(src),
        socket.inet_aton(dst),
    )


def get_src_ip(dst_ip):
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        # No packets are sent
        s.connect((dst_ip, 80))
        src_ip = s.getsockname()[0]
    finally:
        s.close()
    return src_ip


def resolve_hostname(hostname):
    try:
        return socket.gethostbyname(hostname)
    except socket.gaierror:
        return None
