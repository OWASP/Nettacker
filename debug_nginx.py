#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
Debug the nginx case specifically
"""

import sys
import os
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..'))

from core.dsl_matcher import DSLMatcher

def debug_nginx_case():
    """Debug the nginx mixed condition case"""
    matcher = DSLMatcher()
    
    expression = "~1.18.0,~1.19.0,>=1.20.0,<1.20.2"
    test_versions = ["1.20.2", "1.17.9"]
    
    print("Debug Nginx Mixed Conditions")
    print("=" * 30)
    print(f"Expression: {expression}")
    print()
    
    for version in test_versions:
        print(f"Testing version: {version}")
        
        # Test individual conditions
        conditions = [cond.strip() for cond in expression.split(',')]
        for cond in conditions:
            result = matcher.parse_dsl_expression(cond, version)
            print(f"  {version} {cond} -> {result}")
        
        # Test overall
        overall = matcher.parse_dsl_expression(expression, version)
        print(f"  Overall: {overall}")
        print()

if __name__ == "__main__":
    debug_nginx_case()
