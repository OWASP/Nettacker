#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
Test complex DSL expressions
"""

import sys
import os
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..'))

from core.dsl_matcher import DSLMatcher

def test_complex_dsl():
    """Test complex DSL expressions that might be used in real modules"""
    print("Testing Complex DSL Expressions")
    print("=" * 35)
    
    matcher = DSLMatcher()
    
    # Real-world test cases
    test_cases = [
        {
            'description': 'Apache 2.4.x CVE-2021-44790 (Path Traversal)',
            'expression': '>=2.4.7,<=2.4.51',
            'test_versions': [
                ('2.4.49', True),
                ('2.4.51', True),
                ('2.4.52', False),
                ('2.4.6', False),
                ('2.2.34', False)
            ]
        },
        {
            'description': 'WordPress versions with known vulnerabilities',
            'expression': '<6.1.1,5.9.*,5.8.*',
            'test_versions': [
                ('6.1.0', True),
                ('6.1.1', False),
                ('5.9.5', True),
                ('5.8.3', True),
                ('5.7.8', True),
                ('6.2.0', False)
            ]
        },
        {
            'description': 'Nginx versions affected by multiple CVEs (corrected)',
            'expression': '~1.18.0,~1.19.0,1.20.0,1.20.1',
            'test_versions': [
                ('1.18.0', True),
                ('1.18.9', True),
                ('1.19.0', True),
                ('1.19.10', True),
                ('1.20.0', True),
                ('1.20.1', True),
                ('1.20.2', False),
                ('1.17.9', False)
            ]
        },
        {
            'description': 'Semantic versioning with exclusions',
            'expression': '>=2.0.0,<3.0.0,!=2.1.0,!=2.2.0',
            'test_versions': [
                ('2.0.0', True),
                ('2.0.5', True),
                ('2.1.0', False),  # Excluded
                ('2.2.0', False),  # Excluded
                ('2.3.0', True),
                ('3.0.0', False),
                ('1.9.9', False)
            ]
        }
    ]
    
    for test_case in test_cases:
        print(f"\n{test_case['description']}")
        print(f"Expression: {test_case['expression']}")
        print("-" * 40)
        
        for version, expected in test_case['test_versions']:
            result = matcher.parse_dsl_expression(test_case['expression'], version)
            status = "✓" if result == expected else "✗"
            print(f"  {status} {version:>8} -> {result:>5} (expected: {expected})")

if __name__ == "__main__":
    test_complex_dsl()
