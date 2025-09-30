#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
Test DSL matching integration with module loading
"""

import sys
import os
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..'))

import yaml
from core.module_protocols.core_http import response_conditions_matched

def test_dsl_integration():
    """Test DSL integration with module loading"""
    print("Testing DSL Integration with Module Loading")
    print("=" * 50)
    
    # Load a DSL module
    module_path = "modules/vuln/nginx_version_dsl_check.yaml"
    try:
        with open(module_path, 'r') as f:
            module_data = yaml.safe_load(f)
    except FileNotFoundError:
        print(f"Module file {module_path} not found")
        return False
    
    print(f"✓ Successfully loaded module: {module_data['info']['name']}")
    
    # Extract the response conditions from the module
    step = module_data['payloads'][0]['steps'][0]
    
    # Mock response data that would match the DSL conditions
    mock_response = {
        'status_code': '200',
        'content': 'Server: nginx/1.18.5',
        'headers': {'server': 'nginx/1.18.5'},
        'reason': 'OK'
    }
    
    print("\nTesting response conditions...")
    print(f"Mock response server header: {mock_response['headers']['server']}")
    
    # Test the response conditions
    try:
        result = response_conditions_matched(step, mock_response)
        print(f"✓ Response conditions matched: {result}")
        
        if 'version_dsl' in result and result['version_dsl']:
            print(f"✓ DSL version matching successful: {result['version_dsl']}")
            return True
        else:
            print("✗ DSL version matching failed")
            return False
    except Exception as e:
        print(f"✗ Error during response matching: {e}")
        return False

if __name__ == "__main__":
    success = test_dsl_integration()
    if success:
        print("\n🎉 DSL matching integration test passed!")
    else:
        print("\n❌ DSL matching integration test failed!")
