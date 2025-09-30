#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
Debug script for DSL evaluation flow
"""

import sys
import os
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..'))

from core.dsl_matcher import DSLMatcher

def debug_dsl_flow():
    """Debug DSL evaluation flow"""
    matcher = DSLMatcher()
    
    print("Debug DSL Flow")
    print("=" * 20)
    
    # Test the flow for the failing case
    dsl_expression = ">=1.0.0,<2.0.0"
    target_version = "1.8.5"
    
    print(f"Expression: {dsl_expression}")
    print(f"Target: {target_version}")
    print()
    
    # Check what path it takes in _evaluate_dsl
    if dsl_expression.startswith('>='):
        print("Takes >= path")
    elif dsl_expression.startswith('<='):
        print("Takes <= path")
    elif dsl_expression.startswith('>'):
        print("Takes > path")
    elif dsl_expression.startswith('<'):
        print("Takes < path")
    elif dsl_expression.startswith('=='):
        print("Takes == path")
    elif dsl_expression.startswith('!='):
        print("Takes != path")
    elif dsl_expression.startswith('~'):
        print("Takes ~ path")
    elif dsl_expression.startswith('^'):
        print("Takes ^ path")
    elif 'to' in dsl_expression or '-' in dsl_expression:
        print("Takes range path")
    elif ',' in dsl_expression:
        print("Takes multiple conditions path")
    elif '*' in dsl_expression or '?' in dsl_expression:
        print("Takes wildcard path")
    else:
        print("Takes default exact match path")

if __name__ == "__main__":
    debug_dsl_flow()
