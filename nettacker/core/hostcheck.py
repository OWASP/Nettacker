# nettacker/core/hostcheck.py
from __future__ import annotations
import re
import socket
import time
import concurrent.futures
from nettacker import logger
from nettacker.core.ip import (
    get_ip_range,
    generate_ip_range,
    is_single_ipv4,
    is_ipv4_range,
    is_ipv4_cidr,
    is_single_ipv6,
    is_ipv6_range,
    is_ipv6_cidr,
)
log = logger.get_logger()

_LABEL = re.compile(r"^(?!-)[A-Za-z0-9-]{1,63}(?<!-)$")

def is_ip_literal(name: str) -> bool:
    """Return True if name is a valid IPv4 or IPv6 address literal."""
    try:
        socket.inet_pton(socket.AF_INET, name)
        return True
    except OSError:
        pass
    try:
        socket.inet_pton(socket.AF_INET6, name)
        return True
    except OSError:
        return False

def valid_hostname(
    host: str, 
    allow_single_label: bool = True
) -> bool:
    """
    Validate hostname syntax per RFC 1123.
    Args:
        host: Hostname to validate.
        allow_single_label: If True, accept single-label names (e.g., "localhost").
    
    Returns:
        True if the hostname is syntactically valid.
    """
    if host.endswith("."):
        host = host[:-1]
    if len(host) > 253:
        return False
    parts = host.split(".")
    if len(parts) < 2 and not allow_single_label:
        return False
    return all(_LABEL.match(p) for p in parts)


def _gai_once(name: str, use_ai_addrconfig: bool, port):
    flags = getattr(socket, "AI_ADDRCONFIG", 0) if use_ai_addrconfig else 0
    return socket.getaddrinfo(
        name, port, socket.AF_UNSPEC, socket.SOCK_STREAM, 0, flags
    )

def _clean_host(s: str) -> str:
    # remove surrounding quotes and whitespace, lone commas, repeated dots
    s = s.strip().strip('"').strip("'")
    s = s.strip()  # again, after quote strip
    # drop trailing commas that often sneak in from CSV-like inputs
    if s.endswith(","):
        s = s[:-1].rstrip()
    # collapse accidental spaces inside
    return s

def resolve_quick(
        host: str,
        timeout_sec: float = 2.0,
        allow_single_label: bool = True
) -> tuple[bool, str | None]:
    """
    Perform fast DNS resolution with timeout.
    Args:
        host: Hostname or IP literal to resolve.
        timeout_sec: Maximum time to wait for resolution.
        allow_single_label: If True, allow single-label hostnames (e.g., "intranet").
    
    Returns:
        (True, host_name) on success, (False, None) on failure/timeout.
    """
    host = _clean_host(host)
    if is_single_ipv4(host) or is_single_ipv6(host):
        if is_ip_literal(host):
            return True, host
        return False, None
    
    if host.endswith("."):
        host = host[:-1]
        
    if not valid_hostname(host):
        return False, None
    
    if "." not in host and not allow_single_label:
        return False, None

    def _call(use_ai_addrconfig: bool):
        return _gai_once(host, use_ai_addrconfig, None)

    for use_ai in (True, False):
        try:
            # Run getaddrinfo in a thread so we can enforce timeout
            with concurrent.futures.ThreadPoolExecutor(max_workers=1) as ex:
                fut = ex.submit(_call, use_ai)
                fut.result(timeout=timeout_sec)  # raises on timeout or error
            return True, host.lower()
        except concurrent.futures.TimeoutError:
            continue
        except (OSError, socket.gaierror):
            # DNS resolution failed for this candidate, try next
            continue
    return False, None
            
       
