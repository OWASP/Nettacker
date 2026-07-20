import socket
import time
import ssl
from nettacker.core.ip import is_single_ipv4, is_single_ipv6


def raw_to_bytes(payload: str) -> bytes:
    """Converts a raw string with escape characters into literal bytes."""
    if not payload:
        return b""
    return payload.encode("latin1").decode("unicode_escape").encode("latin1")


def tcp_probe(host: str, port: int, payload: str = "", timeout_ms=5000, tcpwrappedms=3000):
    timeout = timeout_ms / 1000.0
    tcp_wrapped = tcpwrappedms / 1000.0
    
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.settimeout(timeout)
    
    tcp_wrap = False
    peer_name = None
    chunks = []
    
    if not isinstance(payload, bytes):
        try:
            payload = raw_to_bytes(payload)
        except Exception as e:
            print(f"Failed to convert payload: {e}")
            payload = b""

    try:
        s.connect((host, port))
        peer_name = s.getpeername()
        
        if payload:
            s.sendall(payload)
            
        try:
            s.shutdown(socket.SHUT_WR)
        except OSError:
            pass  # Peer might have closed the socket already
        
        start = time.time()
        while True:
            remaining_time = timeout - (time.time() - start)
            if remaining_time <= 0:
                break
            s.settimeout(remaining_time)
            try:
                data = s.recv(4096)
                if not data:
                    break
                chunks.append(data)
            except socket.timeout:
                break  # Break loop to return what we captured so far
                
        elapsed = time.time() - start
        if elapsed <= tcp_wrapped and not chunks:
            tcp_wrap = True
            
    except (socket.timeout, OSError):
        pass
    finally:
        try:
            s.close()
        except Exception:
            pass

    raw = b"".join(chunks)
    return {
        "tcp_wrapped": tcp_wrap,
        "ssl_flag": False,
        "peer_name": peer_name or "",
        "raw_bytes": raw,
    }


def tcp_probe_ssl(
    host: str,
    port: int,
    payload: str = "",
    timeout_ms=5000,
    tcpwrappedms=3000,
    server_hostname=None
):
    if not isinstance(payload, bytes):
        payload = raw_to_bytes(payload)
        
    # SNI configuration fallback
    if not server_hostname:
        if not is_single_ipv4(host) and not is_single_ipv6(host):
            server_hostname = host

    timeout = timeout_ms / 1000.0
    tcp_wrapped = tcpwrappedms / 1000.0

    raw_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    raw_sock.settimeout(timeout)

    context = ssl.create_default_context()
    context.check_hostname = False
    context.verify_mode = ssl.CERT_NONE
    
    chunks = []
    tcp_wrap = False
    peer_name = None
    cipher = None
    ssl_sock = None

    try:
        start = time.time()
        raw_sock.connect((host, port))

        ssl_sock = context.wrap_socket(
            raw_sock,
            server_hostname=server_hostname,
            do_handshake_on_connect=True
        )

        peer_name = ssl_sock.getpeername()
        cipher = ssl_sock.cipher()

        if payload:
            ssl_sock.sendall(payload)

        while True:
            remaining = timeout - (time.time() - start)
            if remaining <= 0:
                break

            ssl_sock.settimeout(remaining)
            try:
                data = ssl_sock.recv(4096)
                if not data:
                    break
                chunks.append(data)
            except socket.timeout:
                break
            except ssl.SSLWantReadError:
                continue

        elapsed = time.time() - start
        tcp_wrap = elapsed <= tcp_wrapped and not chunks
        
    except (OSError, ssl.SSLError):
        pass
    finally:
        # Closing the wrapper socket safely teardowns the nested raw socket
        if ssl_sock:
            try:
                ssl_sock.close()
            except Exception:
                pass
        else:
            try:
                raw_sock.close()
            except Exception:
                pass

    raw = b"".join(chunks)
    return {
        "tcp_wrapped": tcp_wrap,
        "ssl_flag": True,
        "peer_name": peer_name or "",
        "raw_bytes": raw,
        "cipher": cipher
    }

        
def udp_probe(host: str, port: int, payload: str = "", timeout_ms=5000, max_tries=1):
    timeout = timeout_ms / 1000.0
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.settimeout(timeout)
    addr = (host, port)
    
    if not isinstance(payload, bytes):
        payload = raw_to_bytes(payload)
        
    raw = b""
    try:
        for _ in range(max_tries):
            try:
                s.sendto(payload, addr)
                data, peer = s.recvfrom(4096)
                raw += data
                break 
            except socket.timeout:
                continue
    except Exception:
        pass
    finally:
        try:
            s.close()
        except Exception:
            pass

    return {
        "peer_name": addr,
        "raw_bytes": raw,
        "response": raw.decode(errors="ignore"),
    }