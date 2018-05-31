OWASP Nettacker Payloads
=====================================

OWASP Nettacker payloads are located in here

Password List Generator
====================================

if you want to output the generated list in a file:

from lib.payload.password_list_generator import generate
password_list = generate("word_filename.txt")

if you don't want to output the generated list in a file:

from lib.payload.password_list_generator import generate
password_list = generate(None)

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