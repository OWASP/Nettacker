# Author: Pradeep Jairamani , github.com/pradeepjairamani

Header Based Blind SQL Injection (Fuzzer)

from lib.payload.scanner.header_blind_sqli.engine import header_bsqli
result = header_bsqli(host)

#Example

from lib.payload.scanner.header_blind_sqli.engine import header_bsqli
result = header_bsqli("https://zdresearch.com")

