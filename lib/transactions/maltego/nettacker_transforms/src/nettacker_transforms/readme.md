OWASP Nettacker Transforms
=======================
This folder mainly contains all the entities and transforms
* `resources/` - This contains all the resources for the transforms such as entities. The entities file can be located 
in `resorces/maltego/entities.mtz`. You need to import these entities file into the maltego software.
* `transforms/` - This folder contains all the codes for every transform available.
* `__init__.py` - This is the module instantiation file for this folder

### Adding a new module
This is the structure for a basic transform:
```
import random

from canari.maltego.transform import Transform
from canari.maltego.entities import {TYPE OF OUTPUT}
from canari.framework import EnableDebugWindow
from common.entities import {NettackerScan or NettackerBrute or something else}

from lib.scan.{name of the module}.engine import start

from database.db import __logs_by_scan_id as find_log

__author__ = '{YOUR NAME}' 
__copyright__ = 'Copyright 2018, nettacker_transforms Project'
__credits__ = []

__license__ = 'GPLv3'
__version__ = '0.1'
__maintainer__ = '{YOUR NAME}'
__email__ =  '{YOUR EMAIL}'
__status__ = 'Development'


@EnableDebugWindow
class {NameOfTransform}(Transform):
    """TODO: Your transform description."""

    # The transform input entity type.
    input_type = {NettackerScan or NettackerBrute or something else}

    def do_transform(self, request, response, config):
        # Do whatever you want to do here. Here is an example for pma_scan
        scan_request = request.entity
        scan_id = "".join(random.choice("0123456789abcdef") for x in range(32))
        ports = scan_request.ports.split(', ')
        start(scan_request.host, [], [], ports, scan_request.timeout_sec, scan_request.thread_no,
              1, 1, 'abcd', 0, "en", scan_request.verbose, scan_request.socks_proxy, scan_request.retries, [], scan_id,
              "Through Maltego")
        results = find_log(scan_id, "en")
        for result in results:
            url = result["DESCRIPTION"].split()[0]
            response += URL(url=url, title=result["DESCRIPTION"], short_title=result["DESCRIPTION"],
                            link_label='pma_scan')
        return response

    def on_terminate(self):
        """This method gets called when transform execution is prematurely terminated. It is only applicable for local
        transforms. It can be excluded if you don't need it."""
        pass
```
After this you need to run `canari create-profile nettacker_transforms -w {YOUR OWASP-Nettacker directory}/lib/transactions/maltego/nettacker_transforms/src `. 
Import it into your maltego and you are ready to go.
