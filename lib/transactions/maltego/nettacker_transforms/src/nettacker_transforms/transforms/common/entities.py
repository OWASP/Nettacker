from canari.maltego.message import *

__author__ = 'Shaddy Garg'
__copyright__ = 'Copyright 2018, nettacker_transforms Project'
__credits__ = []

__license__ = 'GPLv3'
__version__ = '0.1'
__maintainer__ = 'Shaddy Garg'
__email__ = 'shaddygarg1@gmail.com'
__status__ = 'Development'


class NettackerScan(Entity):
    _category_ = 'Nettacker'
    _namespace_ = 'OWASPNettacker'

    retries = IntegerEntityField('retries', display_name='Retries')
    verbose = IntegerEntityField('verbose', display_name='Verbose Level')
    timeout_sec = IntegerEntityField('timeout_sec', display_name='Timeout Seconds')
    host = StringEntityField('host', display_name='Host', is_value=True)
    socks_proxy = StringEntityField('socks_proxy', display_name='Socks Proxy')
    ports = StringEntityField('ports', display_name='Ports')
    thread_no = IntegerEntityField('thread_no', display_name='Thread Number')


class NettackerBrute(NettackerScan):
    _category_ = 'Nettacker'
    _namespace_ = 'OWASP-Nettacker'

    usernames = StringEntityField('usernames', display_name='Usernames')
    passwords = StringEntityField('passwords', display_name='Passwords')