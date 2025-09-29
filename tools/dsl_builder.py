#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
DSL Expression Builder Utility
Helper tool for creating and testing DSL expressions for CVE modules
"""

import sys
import os
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..'))

from core.dsl_matcher import DSLMatcher
import argparse


def test_expression(target_version, dsl_expression):
    """Test a DSL expression against a target version"""
    matcher = DSLMatcher()
    result = matcher.parse_dsl_expression(dsl_expression, target_version)
    return result


def validate_patterns(content, patterns):
    """Validate version extraction patterns"""
    matcher = DSLMatcher()
    extracted = matcher.extract_version_from_response(content, patterns)
    return extracted


def interactive_mode():
    """Interactive mode for testing DSL expressions"""
    matcher = DSLMatcher()
    print("DSL Expression Interactive Tester")
    print("=" * 40)
    print("Commands:")
    print("  test <version> <expression>  - Test DSL expression")
    print("  extract <content> <pattern>  - Test version extraction")
    print("  examples                     - Show example expressions")
    print("  quit                         - Exit")
    print()
    
    while True:
        try:
            command = input("dsl> ").strip()
            if not command:
                continue
                
            if command.lower() in ['quit', 'exit', 'q']:
                break
                
            elif command.lower() == 'examples':
                show_examples()
                
            elif command.startswith('test '):
                parts = command[5:].split(' ', 1)
                if len(parts) == 2:
                    version, expression = parts
                    result = matcher.parse_dsl_expression(expression, version)
                    print(f"Result: {version} {expression} -> {result}")
                else:
                    print("Usage: test <version> <expression>")
                    
            elif command.startswith('extract '):
                parts = command[8:].split(' ', 1)
                if len(parts) == 2:
                    content, pattern = parts
                    result = matcher.extract_version_from_response(content, [pattern])
                    print(f"Extracted version: '{result}' from '{content}'")
                else:
                    print("Usage: extract <content> <pattern>")
                    
            else:
                print("Unknown command. Type 'examples' for help or 'quit' to exit.")
                
        except KeyboardInterrupt:
            break
        except Exception as e:
            print(f"Error: {e}")
    
    print("Goodbye!")


def show_examples():
    """Show example DSL expressions"""
    examples = {
        "Basic Comparisons": [
            ">=2.4.0",
            "<2.4.58",
            "==2.4.49",
            "!=1.0.0",
            ">1.2.3",
            "<=3.0.0"
        ],
        "Range Expressions": [
            "2.4.0 to 2.4.58",
            "1.0-2.0",
            ">=1.0.0,<2.0.0"
        ],
        "Semantic Versioning": [
            "~1.2.3",  # Patch level
            "^1.2.3",  # Compatible changes
        ],
        "Wildcard Patterns": [
            "1.2.*",
            "1.?.3",
            "2.*.*"
        ],
        "Multiple Conditions": [
            "2.4.49,2.4.50,2.4.51",
            ">=1.0.0,<2.0.0,!=1.5.0"
        ]
    }
    
    patterns = {
        "Common Version Patterns": [
            r"Apache[/\s]([0-9]+\.[0-9]+\.[0-9]+)",
            r"nginx[/\s]([0-9]+\.[0-9]+\.[0-9]+)",
            r"WordPress ([0-9]+\.[0-9]+\.[0-9]+)",
            r"version[:\s]*([0-9]+\.[0-9]+\.[0-9]+)",
            r"Server:\s*([^\s]+)\s*([0-9]+\.[0-9]+\.[0-9]+)"
        ]
    }
    
    print("\nDSL Expression Examples:")
    print("-" * 30)
    for category, expressions in examples.items():
        print(f"\n{category}:")
        for expr in expressions:
            print(f"  {expr}")
    
    print("\nVersion Extraction Patterns:")
    print("-" * 30)
    for category, pattern_list in patterns.items():
        print(f"\n{category}:")
        for pattern in pattern_list:
            print(f"  {pattern}")


def bulk_test_mode(test_file):
    """Run bulk tests from a file"""
    matcher = DSLMatcher()
    
    try:
        with open(test_file, 'r') as f:
            lines = f.readlines()
        
        print(f"Running bulk tests from {test_file}")
        print("=" * 50)
        
        for i, line in enumerate(lines, 1):
            line = line.strip()
            if not line or line.startswith('#'):
                continue
                
            try:
                parts = line.split('\t')
                if len(parts) >= 3:
                    version, expression, expected = parts[:3]
                    expected = expected.lower() == 'true'
                    
                    result = matcher.parse_dsl_expression(expression, version)
                    status = "✓" if result == expected else "✗"
                    print(f"Line {i:3d}: {status} {version} {expression} -> {result}")
                    
            except Exception as e:
                print(f"Line {i:3d}: Error - {e}")
                
    except FileNotFoundError:
        print(f"Test file '{test_file}' not found")
    except Exception as e:
        print(f"Error reading test file: {e}")


def create_sample_test_file():
    """Create a sample test file"""
    content = """# DSL Matcher Test File
# Format: version	expression	expected_result
# Lines starting with # are ignored

# Basic comparisons
2.4.49	>=2.4.0	true
2.3.9	>=2.4.0	false
2.4.58	<2.4.59	true
2.4.59	<2.4.59	false

# Range expressions
2.4.25	2.4.0 to 2.4.50	true
2.4.60	2.4.0 to 2.4.50	false

# Semantic versioning
1.2.4	~1.2.3	true
1.3.0	~1.2.3	false
1.5.0	^1.2.3	true
2.0.0	^1.2.3	false

# Wildcard patterns
1.2.5	1.2.*	true
1.3.5	1.2.*	false

# Multiple conditions
2.4.49	2.4.49,2.4.50	true
2.4.52	2.4.49,2.4.50	false
"""
    
    with open('dsl_test_samples.txt', 'w') as f:
        f.write(content)
    
    print("Sample test file 'dsl_test_samples.txt' created!")


def main():
    """Main function"""
    parser = argparse.ArgumentParser(description='DSL Expression Builder Utility')
    parser.add_argument('--test', nargs=2, metavar=('VERSION', 'EXPRESSION'),
                      help='Test a DSL expression against a version')
    parser.add_argument('--extract', nargs=2, metavar=('CONTENT', 'PATTERN'),
                      help='Test version extraction pattern')
    parser.add_argument('--interactive', '-i', action='store_true',
                      help='Start interactive mode')
    parser.add_argument('--bulk-test', metavar='FILE',
                      help='Run bulk tests from file')
    parser.add_argument('--create-samples', action='store_true',
                      help='Create sample test file')
    parser.add_argument('--examples', action='store_true',
                      help='Show examples and exit')
    
    args = parser.parse_args()
    
    if args.test:
        version, expression = args.test
        result = test_expression(version, expression)
        print(f"Result: {version} {expression} -> {result}")
        
    elif args.extract:
        content, pattern = args.extract
        result = validate_patterns(content, [pattern])
        print(f"Extracted version: '{result}' from '{content}'")
        
    elif args.bulk_test:
        bulk_test_mode(args.bulk_test)
        
    elif args.create_samples:
        create_sample_test_file()
        
    elif args.examples:
        show_examples()
        
    else:
        # Default to interactive mode
        interactive_mode()


if __name__ == "__main__":
    main()
