#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
Test script for DSL matching functionality
This script tests the DSL matcher with various version scenarios
"""

import sys
import os
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..'))

from core.dsl_matcher import DSLMatcher


def test_basic_comparisons():
    """Test basic version comparison operators"""
    matcher = DSLMatcher()
    
    test_cases = [
        # (target_version, dsl_expression, expected_result)
        ("2.4.49", ">=2.4.0", True),
        ("2.3.9", ">=2.4.0", False),
        ("2.4.58", "<2.4.59", True),
        ("2.4.59", "<2.4.59", False),
        ("2.4.49", "==2.4.49", True),
        ("2.4.48", "==2.4.49", False),
        ("2.4.48", "!=2.4.49", True),
        ("2.4.49", "!=2.4.49", False),
        ("1.2.3", ">1.2.2", True),
        ("1.2.1", ">1.2.2", False),
        ("1.2.3", "<=1.2.3", True),
        ("1.2.4", "<=1.2.3", False),
    ]
    
    print("Testing basic comparisons...")
    for target_version, dsl_expression, expected in test_cases:
        result = matcher.parse_dsl_expression(dsl_expression, target_version)
        status = "✓" if result == expected else "✗"
        print(f"  {status} {target_version} {dsl_expression} -> {result} (expected: {expected})")
    
    return True


def test_range_expressions():
    """Test range-based expressions"""
    matcher = DSLMatcher()
    
    test_cases = [
        ("2.4.25", "2.4.0 to 2.4.50", True),
        ("2.4.60", "2.4.0 to 2.4.50", False),
        ("1.5.0", "1.0-2.0", True),
        ("2.1.0", "1.0-2.0", False),
        ("1.8.5", ">=1.0.0,<2.0.0", True),
        ("2.0.0", ">=1.0.0,<2.0.0", False),
    ]
    
    print("\nTesting range expressions...")
    for target_version, dsl_expression, expected in test_cases:
        result = matcher.parse_dsl_expression(dsl_expression, target_version)
        status = "✓" if result == expected else "✗"
        print(f"  {status} {target_version} {dsl_expression} -> {result} (expected: {expected})")
    
    return True


def test_semantic_versioning():
    """Test semantic versioning patterns"""
    matcher = DSLMatcher()
    
    test_cases = [
        ("1.2.4", "~1.2.3", True),   # Patch level
        ("1.3.0", "~1.2.3", False),  # Minor change
        ("1.5.0", "^1.2.3", True),   # Compatible
        ("2.0.0", "^1.2.3", False),  # Major change
        ("1.2.9", "~1.2.0", True),   # Patch level
        ("1.3.0", "~1.2.0", False),  # Minor change
    ]
    
    print("\nTesting semantic versioning...")
    for target_version, dsl_expression, expected in test_cases:
        result = matcher.parse_dsl_expression(dsl_expression, target_version)
        status = "✓" if result == expected else "✗"
        print(f"  {status} {target_version} {dsl_expression} -> {result} (expected: {expected})")
    
    return True


def test_wildcard_patterns():
    """Test wildcard patterns"""
    matcher = DSLMatcher()
    
    test_cases = [
        ("1.2.5", "1.2.*", True),
        ("1.3.5", "1.2.*", False),
        ("1.5.3", "1.?.3", True),
        ("1.5.4", "1.?.3", False),
        ("2.4.49", "2.*.*", True),
        ("1.4.49", "2.*.*", False),
    ]
    
    print("\nTesting wildcard patterns...")
    for target_version, dsl_expression, expected in test_cases:
        result = matcher.parse_dsl_expression(dsl_expression, target_version)
        status = "✓" if result == expected else "✗"
        print(f"  {status} {target_version} {dsl_expression} -> {result} (expected: {expected})")
    
    return True


def test_multiple_conditions():
    """Test multiple conditions in one expression"""
    matcher = DSLMatcher()
    
    test_cases = [
        ("2.4.49", "2.4.49,2.4.50,2.4.51", True),
        ("2.4.52", "2.4.49,2.4.50,2.4.51", False),
        ("1.8.0", ">=1.0.0,<2.0.0,!=1.5.0", True),
        ("1.5.0", ">=1.0.0,<2.0.0,!=1.5.0", False),  # Excluded by !=
    ]
    
    print("\nTesting multiple conditions...")
    for target_version, dsl_expression, expected in test_cases:
        result = matcher.parse_dsl_expression(dsl_expression, target_version)
        status = "✓" if result == expected else "✗"
        print(f"  {status} {target_version} {dsl_expression} -> {result} (expected: {expected})")
    
    return True


def test_version_extraction():
    """Test version extraction from response content"""
    matcher = DSLMatcher()
    
    test_cases = [
        ("Server: Apache/2.4.49", ["Apache[/\\s]([0-9]+\\.[0-9]+\\.[0-9]+)"], "2.4.49"),
        ("Server: nginx/1.18.0", ["nginx[/\\s]([0-9]+\\.[0-9]+\\.[0-9]+)"], "1.18.0"),
        ("WordPress 5.8.3", ["WordPress ([0-9]+\\.[0-9]+\\.[0-9]+)"], "5.8.3"),
        ("version: 1.2.3", ["version[:]?\\s*([0-9]+\\.[0-9]+\\.[0-9]+)"], "1.2.3"),
        ("No version here", ["version[:]?\\s*([0-9]+\\.[0-9]+\\.[0-9]+)"], None),
    ]
    
    print("\nTesting version extraction...")
    for content, patterns, expected in test_cases:
        result = matcher.extract_version_from_response(content, patterns)
        status = "✓" if result == expected else "✗"
        print(f"  {status} Extract from '{content}' -> '{result}' (expected: '{expected}')")
    
    return True


def test_cve_version_matching():
    """Test CVE-specific version matching"""
    matcher = DSLMatcher()
    
    # Test cases for CVE version matching
    affected_versions = [
        ">=2.4.0",
        "<2.4.58",
        "2.4.49",
        "2.4.50"
    ]
    
    test_cases = [
        ("2.4.49", True),   # Exact match
        ("2.4.50", True),   # Exact match
        ("2.4.25", True),   # In range
        ("2.4.60", False),  # Above range
        ("2.3.9", False),   # Below range
        ("3.0.0", False),   # Above range
    ]
    
    print("\nTesting CVE version matching...")
    for target_version, expected in test_cases:
        result = matcher.match_cve_version_range(target_version, affected_versions)
        status = "✓" if result == expected else "✗"
        print(f"  {status} {target_version} vs {affected_versions} -> {result} (expected: {expected})")
    
    return True


def test_edge_cases():
    """Test edge cases and error handling"""
    matcher = DSLMatcher()
    
    test_cases = [
        # Invalid inputs should return False
        ("", ">=1.0.0", False),
        ("1.0.0", "", False),
        (None, ">=1.0.0", False),
        ("1.0.0", None, False),
        
        # Malformed versions should be handled gracefully
        ("v1.2.3", ">=1.0.0", True),  # Should strip 'v' prefix
        ("1.2.3-beta", ">=1.0.0", True),  # Should extract main version
        ("Version 1.2.3 (Build 123)", ">=1.0.0", True),  # Should extract version
        
        # Malformed expressions should return False
        ("1.2.3", "invalid", False),
        ("1.2.3", ">=invalid", False),
    ]
    
    print("\nTesting edge cases...")
    for target_version, dsl_expression, expected in test_cases:
        result = matcher.parse_dsl_expression(dsl_expression, target_version)
        status = "✓" if result == expected else "✗"
        print(f"  {status} '{target_version}' {dsl_expression} -> {result} (expected: {expected})")
    
    return True


def main():
    """Run all tests"""
    print("DSL Matcher Test Suite")
    print("=" * 50)
    
    tests = [
        test_basic_comparisons,
        test_range_expressions,
        test_semantic_versioning,
        test_wildcard_patterns,
        test_multiple_conditions,
        test_version_extraction,
        test_cve_version_matching,
        test_edge_cases,
    ]
    
    for test_func in tests:
        try:
            test_func()
        except Exception as e:
            print(f"Test {test_func.__name__} failed with error: {e}")
    
    print("\n" + "=" * 50)
    print("DSL Matcher test suite completed!")
    print("\nTo use DSL matching in your CVE modules:")
    print("1. Add version_dsl or cve_version_match conditions")
    print("2. Specify regex patterns to extract versions")
    print("3. Define DSL expressions for version matching")
    print("\nSee docs/DSL_MATCHING.md for detailed documentation.")


if __name__ == "__main__":
    main()
