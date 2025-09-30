#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
Test CVE DSL matching integration
"""

import sys
import os
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..'))

import yaml
from core.module_protocols.core_http import response_conditions_matched

def test_cve_dsl_integration():
    """Test CVE DSL integration"""
    print("Testing CVE DSL Integration")
    print("=" * 30)
    
    # Create a test module structure for CVE matching
    test_step = {
        'response': {
            'condition_type': 'and',
            'conditions': {
                'cve_version_match': {
                    'patterns': [
                        'Apache[/\\s]([0-9]+\\.[0-9]+\\.[0-9]+)',
                        'Server:\\s*Apache[/\\s]([0-9]+\\.[0-9]+\\.[0-9]+)'
                    ],
                    'affected_versions': [
                        '>=2.4.0',
                        '<2.4.58',
                        '2.4.49',
                        '2.4.50'
                    ],
                    'reverse': False
                }
            }
        }
    }
    
    test_cases = [
        ('Server: Apache/2.4.49', True, "Exact vulnerable version"),
        ('Server: Apache/2.4.25', True, "Version in vulnerable range"),
        ('Server: Apache/2.4.60', False, "Version above vulnerable range"),
        ('Server: Apache/2.3.9', False, "Version below vulnerable range"),
    ]
    
    for server_header, expected_vulnerable, description in test_cases:
        print(f"\nTesting: {description}")
        print(f"Server header: {server_header}")
        
        mock_response = {
            'status_code': '200',
            'content': server_header,
            'headers': {'server': server_header},
            'reason': 'OK'
        }
        
        try:
            result = response_conditions_matched(test_step, mock_response)
            is_vulnerable = bool(result.get('cve_version_match', []))
            
            status = "✓" if is_vulnerable == expected_vulnerable else "✗"
            print(f"  {status} Expected vulnerable: {expected_vulnerable}, Got: {is_vulnerable}")
            
            if is_vulnerable:
                print(f"  📍 Detected version: {result['cve_version_match']}")
                
        except Exception as e:
            print(f"  ✗ Error: {e}")

if __name__ == "__main__":
    test_cve_dsl_integration()
