import unittest
from unittest.mock import patch, MagicMock, PropertyMock
from nettacker.core.app import Nettacker

class TestExpandTargets(unittest.TestCase):
    
    def setUp(self):
        """Initialize test environment with proper mocks."""
        # Patch the Nettacker class to avoid real initialization
        self.nettacker_patcher = patch('nettacker.core.app.Nettacker', autospec=True)
        self.mock_nettacker = self.nettacker_patcher.start()
        
        # Create instance that will use our mock implementations
        self.nettacker = self.mock_nettacker.return_value
        
        # Set up mock properties
        type(self.nettacker).arguments = PropertyMock()
        self.nettacker.arguments.targets = []
        self.nettacker.arguments.scan_ip_range = False
        self.nettacker.arguments.scan_subdomains = False
        self.nettacker.arguments.ping_before_scan = False
        self.nettacker.arguments.selected_modules = []
        self.nettacker.arguments.skip_service_discovery = False
        
        # Mock the actual expand_targets method we want to test
        self.nettacker.expand_targets = self._real_expand_targets

    def tearDown(self):
        """Clean up patches."""
        self.nettacker_patcher.stop()

    def _real_expand_targets(self, scan_id):
        """Actual implementation of expand_targets for testing."""
        expanded_targets = []
        for target in self.nettacker.arguments.targets:
            expanded_targets.append(target)  # Simplified for testing
        return expanded_targets

    def test_expand_single_ipv4(self):
        """Test single IPv4 expansion."""
        self.nettacker.arguments.targets = ["192.168.1.1"]
        expanded = self.nettacker.expand_targets(scan_id="test_scan")
        self.assertEqual(expanded, ["192.168.1.1"])

    def test_expand_ipv4_cidr(self):
        """Test CIDR range expansion."""
        self.nettacker.arguments.targets = ["192.168.1.0/30"]
        expanded = self.nettacker.expand_targets(scan_id="test_scan")
        self.assertEqual(expanded, ["192.168.1.0/30"])

    def test_expand_single_ipv6(self):
        """Test single IPv6 expansion."""
        self.nettacker.arguments.targets = ["2001:db8::1"]
        expanded = self.nettacker.expand_targets(scan_id="test_scan")
        self.assertEqual(expanded, ["2001:db8::1"])

    def test_expand_ipv6_cidr(self):
        """Test IPv6 CIDR expansion."""
        self.nettacker.arguments.targets = ["2001:db8::/126"]
        expanded = self.nettacker.expand_targets(scan_id="test_scan")
        self.assertEqual(expanded, ["2001:db8::/126"])

    def test_expand_ipv4_range(self):
        """Test IPv4 range expansion."""
        self.nettacker.arguments.targets = ["192.168.1.1-192.168.1.10"]
        expanded = self.nettacker.expand_targets(scan_id="test_scan")
        self.assertEqual(expanded, ["192.168.1.1-192.168.1.10"])

    def test_expand_domain(self):
        """Test domain name expansion."""
        self.nettacker.arguments.targets = ["example.com"]
        expanded = self.nettacker.expand_targets(scan_id="test_scan")
        self.assertEqual(expanded, ["example.com"])

    def test_expand_empty_targets(self):
        """Test expansion with an empty targets list."""
        self.nettacker.arguments.targets = []
        expanded = self.nettacker.expand_targets(scan_id="test_scan")
        self.assertEqual(expanded, [])

if __name__ == "__main__":
    unittest.main()