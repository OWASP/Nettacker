Service Scanner
====================================

It's able to detect the services on un-default ports by using existing signatures.

```python
In [1]: from lib.payload.scanner.service.engine import discovery

In [2]: discovery("127.0.0.1")
Out[2]:
{80: 'http',
 443: 'http/ssl',
 445: 'UNKNOWN',
 902: 'UNKNOWN',
 912: 'UNKNOWN',
 2179: 'UNKNOWN',
 3306: 'mariadb',
 6000: 'UNKNOWN'}
```

feel free to modify inputs (threads, timeout and etc) as your network requires!

```python
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
```

if you need to use it with single port from different function than `discoery`, here is a great example for it!

```python
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
```