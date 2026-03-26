import io

import requests

from nettacker import logger
from nettacker.core.messages import messages as _

log = logger.get_logger()


class DefectDojoClient:
    def __init__(self, url: str, api_key: str, product_name: str, engagement_name: str):
        """
        Initialize the DefectDojo client.

        Args:
            url: The base URL to the DefectDojo instance (e.g., 'http://localhost:8080')
            api_key: The API token for authentication
            product_name: The name of the Product in DefectDojo
            engagement_name: The name of the Engagement in DefectDojo
        """
        self.url = url.rstrip("/")
        self.api_key = api_key
        self.product_name = product_name
        self.engagement_name = engagement_name

        self.headers = {
            "Authorization": f"Token {self.api_key}",
        }

    def push_findings(self, dd_json_content: str) -> bool:
        """
        Pushes a DefectDojo JSON report content to the /api/v2/import-scan/ endpoint.

        Args:
            dd_json_content: string representation of the `.dd.json` report content

        Returns:
            True if successful, False otherwise
        """
        endpoint = f"{self.url}/api/v2/import-scan/"

        # We need to simulate a file upload with multipart/form-data
        # Create an in-memory file for the requests library to upload
        file_obj = io.StringIO(dd_json_content)

        files = {"file": ("nettacker_report.json", file_obj, "application/json")}

        data = {
            "scan_type": "Generic Findings Import",
            "product_name": self.product_name,
            "engagement_name": self.engagement_name,
            "auto_create_context": "True",
            "active": "True",
            "verified": "True",
        }

        try:
            log.info(_("pushing_defectdojo_findings").format(self.url, self.product_name))
            response = requests.post(
                endpoint, headers=self.headers, files=files, data=data, verify=False
            )

            if response.status_code in [200, 201]:
                log.info(_("defectdojo_push_success"))
                return True
            else:
                log.warn(_("defectdojo_push_failed").format(response.status_code, response.text))
                return False

        except requests.exceptions.RequestException as e:
            log.warn(_("defectdojo_connection_failed").format(str(e)))
            return False
