# nettacker/core/hostcheck.py
from __future__ import annotations
import re
import socket
import time
import concurrent.futures
import os
import sys


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
    allow_single_label: bool = False
) -> bool:
    """
    Validate hostname syntax per RFC 1123.
    Args:
        host: Hostname to validate.
        allow_single_label: If True, accept single-label names (e.g., "localhost").
    
    Returns:
        True if the hostname is syntactically valid.
    """
    if len(host) > 253:
        return False
    if host.endswith("."):
        host = host[:-1]
    parts = host.split(".")
    if len(parts) < 2 and not allow_single_label:
        # log.warn("Its a name like google")
        print("itegb")
        return False
    return all(_LABEL.match(p) for p in parts)

def _system_search_suffixes() -> list[str]:
    # Only used when host has no dots; mirrors OS resolver search behavior (UNIX).
    sufs: list[str] = []
    try:
        with open("/etc/resolv.conf") as f:
            for line in f:
                line = line.strip()
                if not line or line.startswith("#"): continue
                if line.startswith("search") or line.startswith("domain"):
                    sufs += [x for x in line.split()[1:] if x]
    except Exception:
        pass
    seen = set(); out: list[str] = []
    for s in sufs:
        if s not in seen:
            seen.add(s); out.append(s)
    return out

# --- safer, more robust pieces to replace in hostcheck.py ---

def _gai_once(name: str, use_ai_addrconfig: bool, port):
    flags = getattr(socket, "AI_ADDRCONFIG", 0) if use_ai_addrconfig else 0
    return socket.getaddrinfo(
        name, port, socket.AF_UNSPEC, socket.SOCK_STREAM, 0, flags
    )

def resolve_quick(
        host: str,
        timeout_sec: float = 2.0,
        try_search_suffixes: bool = True,
        allow_single_label: bool = True
) -> tuple[bool, str | None]:
    """
    Perform fast DNS resolution with timeout and suffix search.
    
    Args:
        host: Hostname or IP literal to resolve.
        timeout_sec: Maximum time to wait for resolution.
        try_search_suffixes: If True, append /etc/resolv.conf search suffixes for single-label hosts.
        allow_single_label: If True, allow single-label hostnames (e.g., "intranet").
    
    Returns:
        (True, canonical_hostname) on success, (False, None) on failure/timeout.
    """
    candidates: list[str] = []
    if "." in host:
        # try both plain and absolute forms; whichever resolves first wins
        if host.endswith("."):
            candidates.extend([host, host[:-1]])
        else:
            candidates.extend([host, host + "."])
    else:
        # single label (e.g., "intranet")
        if not allow_single_label:
            return False, None
        if try_search_suffixes:
            for s in _system_search_suffixes():
                candidates.extend([f"{host}.{s}", f"{host}.{s}."])
        if not host.endswith("."):
            candidates.append(host + ".")  # bare absolute
        candidates.append(host) 

    seen, uniq = set(), []
    for c in candidates:
        if c not in seen:
            seen.add(c); uniq.append(c)
    candidates = uniq
    if not candidates:
        return False, None

    for pass_ix, (use_ai_addrconfig, port) in enumerate(((True, None), (False, None))):
        deadline = time.monotonic() + timeout_sec
        maxw = min(len(candidates), 4)
        ex = concurrent.futures.ThreadPoolExecutor(max_workers=maxw)
        try:
            fut2cand = {ex.submit(_gai_once, c, use_ai_addrconfig, port): c for c in candidates}
            pending = set(fut2cand)
            while pending:
                remaining = deadline - time.monotonic()
                if remaining <= 0:
                    break
                done, pending = concurrent.futures.wait(
                    pending, timeout=remaining,
                    return_when=concurrent.futures.FIRST_COMPLETED
                )
                for fut in done:
                    try:
                        res = fut.result() 
                        if not res:
                            continue
                        chosen = fut2cand[fut]
                        for p in pending:
                           p.cancel()
                        # ensure we don't wait on the executor shutdown
                        try:
                            ex.shutdown(wait=False, cancel_futures=True)
                        except TypeError:  # Py<3.9
                            ex.shutdown(wait=False)
                        canon = chosen[:-1] if chosen.endswith(".") else chosen
                        return True, canon.lower()
                    except Exception:
                        continue
            # cancel any survivors in this pass
            for f in fut2cand: 
                f.cancel()
        finally:
            # best-effort non-blocking shutdown
            try:
                ex.shutdown(wait=False, cancel_futures=True)
            except TypeError:
                ex.shutdown(wait=False)
    return False, None
