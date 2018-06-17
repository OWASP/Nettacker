import random

from canari.maltego.transform import Transform
from canari.maltego.entities import URL
from canari.framework import EnableDebugWindow
from common.entities import NettackerScan

from lib.vuln.ProFTPd_exec_arbitary.engine import start

from database.db import __logs_by_scan_id as find_log

__author__ = 'Shaddy Garg'
__copyright__ = 'Copyright 2018, nettacker_transforms Project'
__credits__ = []

__license__ = 'GPLv3'
__version__ = '0.1'
__maintainer__ = 'Shaddy Garg'
__email__ = 'shaddygarg1@gmail.com'
__status__ = 'Development'


@EnableDebugWindow
class ProFTPdExecArbitraryVulnScan(Transform):
    """TODO: Your transform description."""

    # The transform input entity type.
    input_type = NettackerScan

    def do_transform(self, request, response, config):
        # TODO: write your code here.
        scan_request = request.entity
        scan_id = "".join(random.choice("0123456789abcdef") for x in range(32))
        scan_request.ports = scan_request.ports.split(', ') if scan_request.ports is not None else None
        start(scan_request.host, [], [], scan_request.ports, scan_request.timeout_sec, scan_request.thread_no,
              1, 1, 'abcd', 0, "en", scan_request.verbose, scan_request.socks_proxy, scan_request.retries, [], scan_id,
              "Through Maltego")
        results = find_log(scan_id, "en")
        for result in results:
            url = result["HOST"] + ":" + result["PORT"]
            response += URL(url=url, title=result["DESCRIPTION"],
                            short_title="ProFTPd exec arbitaryl Found!",
                            link_label='ProFTPd_exec_arbitary_vuln')
        return response

    def on_terminate(self):
        """This method gets called when transform execution is prematurely terminated. It is only applicable for local
        transforms. It can be excluded if you don't need it."""
        pass
