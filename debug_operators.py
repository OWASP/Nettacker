#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
Debug script for operator detection
"""

import sys
import os
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..'))

from core.dsl_matcher import DSLMatcher

def debug_operator_detection():
    """Debug operator detection in multiple conditions"""
    matcher = DSLMatcher()
    
    expression = ">=1.0.0,<2.0.0,!=1.5.0"
    conditions = [cond.strip() for cond in expression.split(',')]
    
    print("Debug Operator Detection")
    print("=" * 30)
    print(f"Expression: {expression}")
    print(f"Conditions: {conditions}")
    
    has_operators = any(
        cond.startswith(('>=', '<=', '>', '<', '==', '!=', '~', '^')) 
        for cond in conditions
    )
    
    print(f"Has operators: {has_operators}")
    
    for cond in conditions:
        starts_with_op = cond.startswith(('>=', '<=', '>', '<', '==', '!=', '~', '^'))
        print(f"  '{cond}' starts with operator: {starts_with_op}")

if __name__ == "__main__":
    debug_operator_detection()
