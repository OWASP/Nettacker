SSL Scanner (Protocol and Cipher Enumeration tool)

# For Python2

from lib.payload.scanner.SSL_TLS.engine import processTarget
result_dict = processTarget("host")

or

result_dict = processTarget("host:port")

# For Python3

from lib.payload.scanner.SSL_TLS.engine3 import processTarget
result_dict = processTarget("host")

or

result_dict = processTarget("host", port=443)

# For now only available for HTTPS ports
# dport (Default Port can be changed in processTarget function

#Example Python2

from lib.payload.scanner.SSL_TLS.engine import processTarget
result_dict = processTarget("google.com")

or

result_dict = processTarget("google.com:443")

#Example Python3

from lib.payload.scanner.SSL_TLS.engine3 import processTarget
result_dict = processTarget("google.com")

or

result_dict = processTarget("google.com", port=443)

