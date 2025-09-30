#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
Debug script for DSL matching to understand the CVE version issue
"""

import sys
import os
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..'))

from core.dsl_matcher import DSLMatcher

def debug_cve_matching():
    """Debug CVE version matching to understand the logic"""
    matcher = DSLMatcher()
    
    # Test cases for CVE version matching
    affected_versions = [
        ">=2.4.0",
        "<2.4.58", 
        "2.4.49",
        "2.4.50"
    ]
    
    test_versions = ["2.4.60", "2.3.9", "3.0.0", "2.4.25"]
    
    print("Debug CVE Version Matching")
    print("=" * 40)
    print(f"Affected versions: {affected_versions}")
    print()
    
    for version in test_versions:
        print(f"Testing version: {version}")
        for expr in affected_versions:
            result = matcher.parse_dsl_expression(expr, version)
            print(f"  {version} {expr} -> {result}")
        
        overall = matcher.match_cve_version_range(version, affected_versions)
        print(f"  Overall result: {overall}")
        print()

if __name__ == "__main__":
    debug_cve_matching()
