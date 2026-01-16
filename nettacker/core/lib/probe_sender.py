import socket
import time
import ssl
from nettacker.core.ip import is_single_ipv4,is_single_ipv6


def raw_to_bytes(payload: str) -> bytes:
    return payload.encode("latin1").decode("unicode_escape").encode("latin1")

def tcp_probe(host:str , port:int ,  payload:str="" ,timeout_ms=5000 , tcpwrappedms=3000):
    timeout = timeout_ms/1000.0
    tcp_wrapped = tcpwrappedms/1000.0
    s=socket.socket(socket.AF_INET , socket.SOCK_STREAM)
    s.settimeout(timeout)
    tcp_wrap=False
    peer_name=None
    raw=""
    if not isinstance(payload, bytes):
        try:
            payload = raw_to_bytes(payload)
        except Exception as e:
            print(f"failed to convert with {e}")
    
    try:
        s.connect((host,port))
        peer_name = s.getpeername()
        
        if payload:
            s.sendall(payload)
        try:
            s.shutdown(socket.SHUT_WR)
        except OSError:
            pass # Some sockets might already be closed by the peer
        
        chunks=[]
        start = time.time()
        while True:
            remaining_time = timeout-(time.time()-start)
            if remaining_time<=0:
                break
            s.settimeout(remaining_time)
            try:
                data = s.recv(4096)
                if not data:
                    break
                chunks.append(data)
            except socket.timeout:
                raw = b"".join(chunks)
                try:
                    s.close()
                except:
                    pass
                return{
                    "tcp_wrapped" : tcp_wrap,
                    "ssl_flag":False,
                    "peer_name": "",
                    "raw_bytes": raw,
                }
        tcp_wrap=False
        if(time.time()-start<=tcp_wrapped and chunks==[]):
            tcp_wrap = True
       
        raw = b"".join(chunks)
        try:
            s.close()
        except:
            pass
        return {
            "tcp_wrapped" : tcp_wrap,
            "ssl_flag":False,
            "peer_name": peer_name,
            "raw_bytes": raw,
        }
    except socket.timeout :
        try:
            s.close()
        except:
            pass
        return{
            "tcp_wrapped" : tcp_wrap,
            "ssl_flag":False,
            "peer_name": peer_name,
            "raw_bytes": raw,
        }
    finally:
        try:
            s.close()
        except Exception as e:
            print(f"final excep is {e}")
            pass
        

def tcp_probe_ssl(
    host,
    port,
    payload: str = "",
    timeout_ms=5000,
    tcpwrappedms=3000,
    server_hostname=None
):
    if not isinstance(payload, bytes):
        payload = raw_to_bytes(payload)
        
    hostname = None
    if not is_single_ipv4(host) and not is_single_ipv6(host):
        hostname = host
        
    server_hostname = hostname
    timeout = timeout_ms / 1000.0
    tcp_wrapped = tcpwrappedms / 1000.0

    raw_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    raw_sock.settimeout(timeout)

    context = ssl.create_default_context()
    context.check_hostname = False
    context.verify_mode = ssl.CERT_NONE
    
    try:
        start = time.time()
        raw_sock.connect((host, port))

        ssl_sock = context.wrap_socket(
            raw_sock,
            server_hostname=server_hostname or host,
            do_handshake_on_connect=True
        )

        if payload:
            ssl_sock.sendall(payload)

        chunks = []
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
        cipher = ssl_sock.cipher()
        peer_name = ssl_sock.getpeername()
        try:
            ssl_sock.shutdown(socket.SHUT_RDWR)
            ssl_sock.close()
        except Exception:
            pass
        
        try:
            raw_sock.close()
        except Exception:
            pass
        raw = b"".join(chunks)

        try:
            raw_sock.close()
        except Exception:
            pass
        return None
    except (OSError, ssl.SSLError):
        try:
            raw_sock.close()
        except Exception:
            pass
        if raw :
            return None
        else:
            return None
        
    finally:
            try:
                raw_sock.close()
            except Exception:
                pass

        
def udp_probe(host, port , payload:bytes="" , timeout_ms = 5000 , max_tries=1):
    timeout = timeout_ms/1000.0
    s=socket.socket(socket.AF_INET , socket.SOCK_DGRAM)
    s.settimeout(timeout)
    addr = (host,port)
    if not isinstance(payload, bytes):
        payload = raw_to_bytes(payload)
        
    try:
        raw=b""
        for _ in range(max_tries):
            s.sendto(payload, addr)
            try:
                data, peer = s.recvfrom(4096)
                raw += data
                break 
            except socket.timeout:
                continue

        return {
            "peer_name": addr,
            "raw_bytes": raw,
            "response": raw.decode(errors="ignore"),
        }
    except Exception:
        return None
    finally:
        try:
            s.close()
        except Exception:
            pass

        
