import socket
import ssl
def recv_all(s):
    response = ""
    while len(response) < 4196:
        try:
            r = s.recv(1)
            if r != "":
                response += r
            else:
                break
        except Exception as _:
            break
    return response

sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
sock.settimeout(3)
sock.connect(("google.com", 443))
try:
    sock = ssl.wrap_socket(sock)
except:
    print 1
sock.send("GET / HTTP/1.1\r\n")
print(recv_all(sock))
