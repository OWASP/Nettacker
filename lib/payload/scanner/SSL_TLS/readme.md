SSL Scanner (Protocol and Cipher Enumeration tool)

from lib.payload.scanner.SSL_TLS.engine import processTarget
result_dict = processTarget("host")

or

result_dict = processTarget("host:port")

# For now only available for HTTPS ports
# dport (Default Port can be changed in processTarget function

#Example

from lib.payload.scanner.SSL_TLS.engine import processTarget
result_dict = processTarget("zdresearch.com")

or

result_dict = processTarget("zdresearch.com:443")

