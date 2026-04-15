
import pytest
from unittest.mock import patch
from nettacker.api.core import profiles, scan_methods

@patch("nettacker.core.app.Nettacker.load_profiles")
def test_profiles_deduplication(mock_load_profiles):
    # Setup: a profile that appears in both scan and brute categories
    # Profiles are categorized by the suffix of the modules they contain.
    # 'mixed_profile' has 'a_scan' and 'b_brute', so it should appear in both categories.
    mock_load_profiles.return_value = {
        "mixed_profile": ["mod1_scan", "mod2_brute"],
        "only_scan": ["mod3_scan"]
    }
    
    result = profiles()
    
    # Check if 'mixed_profile' appears in the scan category
    assert 'id="mixed_profile"' in result
    # Check if 'mixed_profile' is listed with its modules
    assert 'data-modules="mod1_scan,mod2_brute"' in result
    
    # The HTML structure should have panels for scan, brute, and vuln
    assert 'id="collapse_scan"' in result
    assert 'id="collapse_brute"' in result
    assert 'id="collapse_vuln"' in result

@patch("nettacker.core.app.Nettacker.load_modules")
def test_scan_methods_categorization(mock_load_modules):
    mock_load_modules.return_value = {
        "ssh_brute": {},
        "ftp_scan": {},
        "heartbleed_vuln": {},
        "custom_vulnerability": {}
    }
    
    result = scan_methods()
    
    # Check if modules are in their respective categories
    assert 'id="ssh_brute"' in result
    assert 'checkbox-sm-brute-module' in result
    
    assert 'id="ftp_scan"' in result
    assert 'checkbox-sm-scan-module' in result
    
    assert 'id="heartbleed_vuln"' in result
    assert 'checkbox-sm-vuln-module' in result
    
    # 'custom_vulnerability' should be mapped to 'vuln' category
    assert 'id="custom_vulnerability"' in result
    assert 'checkbox-sm-vuln-module' in result

@patch("nettacker.core.app.Nettacker.load_profiles")
def test_profiles_removes_all_and_dots(mock_load_profiles):
    mock_load_profiles.return_value = {
        "all": ["mod1_scan"],
        "...": ["mod2_scan"],
        "valid": ["mod3_scan"]
    }
    
    result = profiles()
    assert 'id="all"' not in result
    assert 'id="..."' not in result
    assert 'id="valid"' in result
