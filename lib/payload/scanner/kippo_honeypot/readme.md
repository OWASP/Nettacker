Kippo SSH Honeypot detection usage

from lib.payload.scanner.kippo_honeypot.engine import kippo_detect
result = kippo_detect(host, port, timeout, socks_proxy)

or 

result = kippo_detect(host, port, timeout)

or 

result = kippo_detect(host,port)

#Example

from lib.payload.scanner.kippo_honeypot.engine import kippo_detect
result = kippo_detect("192.168.2.1", 22)

