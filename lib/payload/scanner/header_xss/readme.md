# Author: Pradeep Jairamani , github.com/pradeepjairamani

Header Based XSS Injection (Fuzzer)

from lib.payload.scanner.header_xss.engine import header_xss
result = header_xss(host)

#Example

from lib.payload.scanner.header_xss.engine import header_xss
result = header_xss("https://zdresearch.com")

