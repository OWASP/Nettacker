import json
import unittest
from unittest.mock import patch, MagicMock

from nettacker.lib.export.defectdojo import DefectDojoClient


class TestDefectDojoClient(unittest.TestCase):
    def setUp(self):
        self.url = "http://dojo.test"
        self.api_key = "test_token_123"
        self.product_name = "Nettacker Test Product"
        self.engagement_name = "Automated Scan"
        self.client = DefectDojoClient(
            url=self.url,
            api_key=self.api_key,
            product_name=self.product_name,
            engagement_name=self.engagement_name
        )
        self.sample_json = json.dumps({"findings": []})

    def test_init(self):
        """Test client initialization and headers"""
        self.assertEqual(self.client.url, "http://dojo.test")
        self.assertEqual(self.client.api_key, "test_token_123")
        self.assertEqual(self.client.headers["Authorization"], "Token test_token_123")

    @patch('nettacker.lib.export.defectdojo.requests.post')
    def test_push_findings_success(self, mock_post):
        """Test successful finding push (201 Created or 200 OK)"""
        # Mock successful response
        mock_response = MagicMock()
        mock_response.status_code = 201
        mock_post.return_value = mock_response

        result = self.client.push_findings(self.sample_json)

        self.assertTrue(result)
        mock_post.assert_called_once()
        
        # Verify call arguments
        call_args, call_kwargs = mock_post.call_args
        self.assertEqual(call_args[0], "http://dojo.test/api/v2/import-scan/")
        self.assertEqual(call_kwargs['headers']['Authorization'], "Token test_token_123")
        self.assertEqual(call_kwargs['data']['product_name'], self.product_name)
        self.assertEqual(call_kwargs['data']['engagement_name'], self.engagement_name)

    @patch('nettacker.lib.export.defectdojo.requests.post')
    def test_push_findings_failure(self, mock_post):
        """Test API rejecting the push (400 Bad Request)"""
        mock_response = MagicMock()
        mock_response.status_code = 400
        mock_response.text = '{"error": "Invalid format"}'
        mock_post.return_value = mock_response

        result = self.client.push_findings(self.sample_json)

        self.assertFalse(result)
        mock_post.assert_called_once()

    @patch('nettacker.lib.export.defectdojo.requests.post')
    def test_push_findings_connection_error(self, mock_post):
        """Test connection/network errors"""
        import requests
        mock_post.side_effect = requests.exceptions.ConnectionError("Connection refused")

        result = self.client.push_findings(self.sample_json)

        self.assertFalse(result)
        mock_post.assert_called_once()
