#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
Debug script for multiple conditions
"""

import sys
import os
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..'))

from core.dsl_matcher import DSLMatcher

def debug_multiple_conditions():
    """Debug multiple conditions"""
    matcher = DSLMatcher()
    
    test_cases = [
        ("1.8.5", ">=1.0.0,<2.0.0"),
        ("1.8.0", ">=1.0.0,<2.0.0,!=1.5.0"),
    ]
    
    print("Debug Multiple Conditions")
    print("=" * 30)
    
    for version, expression in test_cases:
        print(f"\nTesting: {version} against {expression}")
        
        # Test individual conditions
        conditions = [cond.strip() for cond in expression.split(',')]
        for cond in conditions:
            result = matcher.parse_dsl_expression(cond, version)
            print(f"  {version} {cond} -> {result}")
        
        # Test overall
        overall = matcher.parse_dsl_expression(expression, version)
        print(f"  Overall: {overall}")

if __name__ == "__main__":
    debug_multiple_conditions()
