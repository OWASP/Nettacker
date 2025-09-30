#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
DSL (Domain Specific Language) matching engine for Nettacker
Provides version matching capabilities for CVE modules and vulnerability assessment
"""

import re
from packaging import version
from packaging.specifiers import SpecifierSet
from packaging.version import Version, InvalidVersion
import semver
import logging


class DSLMatcher:
    """
    DSL (Domain Specific Language) matcher for version comparison and pattern matching
    Supports various version matching operations useful for CVE module development
    """

    def __init__(self):
        self.logger = logging.getLogger(__name__)

    def parse_dsl_expression(self, dsl_expression, target_version):
        """
        Parse and evaluate DSL expression against target version
        
        Args:
            dsl_expression (str): DSL expression to evaluate
            target_version (str): Version string to compare against
            
        Returns:
            bool: True if expression matches, False otherwise
        """
        try:
            if not dsl_expression or not target_version:
                return False
                
            # Clean version string
            cleaned_version = self._clean_version(target_version)
            if not cleaned_version:
                return False
                
            # Parse DSL expression
            return self._evaluate_dsl(dsl_expression, cleaned_version)
            
        except Exception as e:
            self.logger.debug(f"DSL evaluation error: {e}")
            return False

    def _clean_version(self, version_str):
        """
        Clean and normalize version string
        
        Args:
            version_str (str): Raw version string
            
        Returns:
            str: Cleaned version string or None if invalid
        """
        if not version_str:
            return None
            
        # Remove common prefixes/suffixes
        cleaned = str(version_str).strip()
        cleaned = re.sub(r'^[vV]', '', cleaned)  # Remove v/V prefix
        
        # Extract version pattern - try more comprehensive patterns
        patterns = [
            r'(\d+(?:\.\d+){1,})',  # Standard version pattern
            r'[Vv]ersion\s+(\d+(?:\.\d+)*)',  # "Version 1.2.3"
            r'(\d+(?:\.\d+)*)\s*\([^)]*\)',  # "1.2.3 (Build 123)"
            r'(\d+(?:\.\d+)*)',  # Simple pattern as fallback
        ]
        
        for pattern in patterns:
            version_match = re.search(pattern, cleaned)
            if version_match:
                return version_match.group(1)
            
        return None

    def _evaluate_dsl(self, dsl_expression, target_version):
        """
        Evaluate DSL expression against target version
        
        Args:
            dsl_expression (str): DSL expression
            target_version (str): Cleaned version string
            
        Returns:
            bool: True if expression matches
        """
        try:
            # Handle different DSL expression formats
            # Check for multiple conditions first (comma-separated)
            if ',' in dsl_expression:
                return self._evaluate_multiple(dsl_expression, target_version)
            elif dsl_expression.startswith('>='):
                return self._compare_version(target_version, dsl_expression[2:].strip(), '>=')
            elif dsl_expression.startswith('<='):
                return self._compare_version(target_version, dsl_expression[2:].strip(), '<=')
            elif dsl_expression.startswith('>'):
                return self._compare_version(target_version, dsl_expression[1:].strip(), '>')
            elif dsl_expression.startswith('<'):
                return self._compare_version(target_version, dsl_expression[1:].strip(), '<')
            elif dsl_expression.startswith('=='):
                return self._compare_version(target_version, dsl_expression[2:].strip(), '==')
            elif dsl_expression.startswith('!='):
                return self._compare_version(target_version, dsl_expression[2:].strip(), '!=')
            elif dsl_expression.startswith('~'):
                return self._compare_version(target_version, dsl_expression[1:].strip(), '~')
            elif dsl_expression.startswith('^'):
                return self._compare_version(target_version, dsl_expression[1:].strip(), '^')
            elif 'to' in dsl_expression or '-' in dsl_expression:
                return self._evaluate_range(dsl_expression, target_version)
            elif '*' in dsl_expression or '?' in dsl_expression:
                return self._evaluate_wildcard(dsl_expression, target_version)
            else:
                # Default to exact match
                return self._compare_version(target_version, dsl_expression.strip(), '==')
                
        except Exception as e:
            self.logger.debug(f"DSL evaluation error: {e}")
            return False

    def _compare_version(self, version1, version2, operator):
        """
        Compare two versions using specified operator
        
        Args:
            version1 (str): First version
            version2 (str): Second version  
            operator (str): Comparison operator
            
        Returns:
            bool: Comparison result
        """
        try:
            # Try packaging library first (more robust)
            v1 = Version(version1)
            v2 = Version(version2)
            
            if operator == '>=':
                return v1 >= v2
            elif operator == '<=':
                return v1 <= v2
            elif operator == '>':
                return v1 > v2
            elif operator == '<':
                return v1 < v2
            elif operator == '==':
                return v1 == v2
            elif operator == '!=':
                return v1 != v2
            elif operator == '~':
                return self._tilde_compare(version1, version2)
            elif operator == '^':
                return self._caret_compare(version1, version2)
                
        except InvalidVersion:
            # Fallback to semver if packaging fails
            try:
                if operator == '>=':
                    return semver.compare(version1, version2) >= 0
                elif operator == '<=':
                    return semver.compare(version1, version2) <= 0
                elif operator == '>':
                    return semver.compare(version1, version2) > 0
                elif operator == '<':
                    return semver.compare(version1, version2) < 0
                elif operator == '==':
                    return semver.compare(version1, version2) == 0
                elif operator == '!=':
                    return semver.compare(version1, version2) != 0
                elif operator == '~':
                    return self._tilde_compare(version1, version2)
                elif operator == '^':
                    return self._caret_compare(version1, version2)
            except Exception:
                # Final fallback to string comparison
                return self._string_version_compare(version1, version2, operator)
                
        return False

    def _tilde_compare(self, version1, version2):
        """
        Tilde comparison (~) - allows patch-level changes
        ~1.2.3 := >=1.2.3 <1.3.0
        """
        try:
            v1_parts = [int(x) for x in version1.split('.')]
            v2_parts = [int(x) for x in version2.split('.')]
            
            # Pad to same length
            max_len = max(len(v1_parts), len(v2_parts))
            v1_parts.extend([0] * (max_len - len(v1_parts)))
            v2_parts.extend([0] * (max_len - len(v2_parts)))
            
            # Check if v1 >= v2
            if not self._compare_version_parts(v1_parts, v2_parts, '>='):
                return False
            
            # Check if v1 < next minor version
            if len(v2_parts) >= 2:
                next_minor = v2_parts.copy()
                next_minor[1] += 1
                for i in range(2, len(next_minor)):
                    next_minor[i] = 0
                    
                return self._compare_version_parts(v1_parts, next_minor, '<')
                        
            return True
            
        except Exception:
            return False

    def _caret_compare(self, version1, version2):
        """
        Caret comparison (^) - allows backward compatible changes
        ^1.2.3 := >=1.2.3 <2.0.0
        """
        try:
            v1_parts = [int(x) for x in version1.split('.')]
            v2_parts = [int(x) for x in version2.split('.')]
            
            # Pad to same length
            max_len = max(len(v1_parts), len(v2_parts))
            v1_parts.extend([0] * (max_len - len(v1_parts)))
            v2_parts.extend([0] * (max_len - len(v2_parts)))
            
            # Check if v1 >= v2
            if not self._compare_version_parts(v1_parts, v2_parts, '>='):
                return False
            
            # Check if v1 < next major version
            if len(v2_parts) >= 1:
                next_major = v2_parts.copy()
                next_major[0] += 1
                for i in range(1, len(next_major)):
                    next_major[i] = 0
                    
                return self._compare_version_parts(v1_parts, next_major, '<')
                        
            return True
            
        except Exception:
            return False

    def _evaluate_range(self, dsl_expression, target_version):
        """
        Evaluate range expressions (e.g., "1.0 to 2.0", "1.0-2.0")
        """
        try:
            if 'to' in dsl_expression:
                parts = dsl_expression.split('to')
            else:
                parts = dsl_expression.split('-')
                
            if len(parts) != 2:
                return False
                
            start_version = parts[0].strip()
            end_version = parts[1].strip()
            
            return (self._compare_version(target_version, start_version, '>=') and
                    self._compare_version(target_version, end_version, '<='))
                    
        except Exception:
            return False

    def _evaluate_multiple(self, dsl_expression, target_version):
        """
        Evaluate multiple conditions separated by commas
        
        Logic rules:
        1. If all conditions are strict range operators (>=, <, <=, >, !=), use AND logic
        2. If conditions include semantic operators (~, ^) or wildcards/versions, use OR logic
        3. Mixed cases default to OR logic for vulnerability detection
        """
        try:
            conditions = [cond.strip() for cond in dsl_expression.split(',')]
            
            # Categorize conditions
            strict_operators = []
            other_conditions = []
            
            for cond in conditions:
                if any(cond.startswith(op) for op in ['>=', '<=', '>', '<', '!=']):
                    strict_operators.append(cond)
                else:
                    other_conditions.append(cond)
            
            # If we have non-strict operators (semantic, wildcards, exact versions), use OR logic
            if other_conditions:
                return any(self._evaluate_dsl(cond, target_version) for cond in conditions)
            
            # If all are strict range operators, use AND logic
            if strict_operators:
                return all(self._evaluate_dsl(cond, target_version) for cond in conditions)
                
            # Fallback to OR logic
            return any(self._evaluate_dsl(cond, target_version) for cond in conditions)
                
        except Exception:
            return False

    def _evaluate_wildcard(self, dsl_expression, target_version):
        """
        Evaluate wildcard patterns (* and ?)
        """
        try:
            # Convert wildcard to regex
            pattern = dsl_expression.replace('.', r'\.')
            pattern = pattern.replace('*', '.*')
            pattern = pattern.replace('?', '.')
            pattern = f'^{pattern}$'
            
            return bool(re.match(pattern, target_version))
        except Exception:
            return False

    def _string_version_compare(self, version1, version2, operator):
        """
        Fallback string-based version comparison
        """
        try:
            v1_parts = [int(x) for x in version1.split('.')]
            v2_parts = [int(x) for x in version2.split('.')]
            
            # Pad to same length
            max_len = max(len(v1_parts), len(v2_parts))
            v1_parts.extend([0] * (max_len - len(v1_parts)))
            v2_parts.extend([0] * (max_len - len(v2_parts)))
            
            for i in range(max_len):
                if v1_parts[i] > v2_parts[i]:
                    result = 1
                    break
                elif v1_parts[i] < v2_parts[i]:
                    result = -1
                    break
            else:
                result = 0
                
            if operator == '>=':
                return result >= 0
            elif operator == '<=':
                return result <= 0
            elif operator == '>':
                return result > 0
            elif operator == '<':
                return result < 0
            elif operator == '==':
                return result == 0
            elif operator == '!=':
                return result != 0
                
        except Exception:
            return False

    def match_cve_version_range(self, target_version, affected_versions):
        """
        Match version against CVE affected version ranges
        
        For CVE matching, the logic is:
        - Range operators (>=, <, <=, >, !=) are combined with AND logic
        - Exact versions (==, simple versions) are combined with OR logic
        - A version is affected if it matches the range AND/OR any exact version
        
        Args:
            target_version (str): Version to check
            affected_versions (list): List of affected version expressions
            
        Returns:
            bool: True if version is in affected range
        """
        if not affected_versions:
            return False
            
        # Clean the target version
        cleaned_version = self._clean_version(target_version)
        if not cleaned_version:
            return False
        
        # Separate range conditions from exact versions
        range_conditions = []
        exact_versions = []
        
        for expr in affected_versions:
            expr = expr.strip()
            if any(expr.startswith(op) for op in ['>=', '<=', '>', '<', '!=']):
                range_conditions.append(expr)
            else:
                exact_versions.append(expr)
        
        # Check exact versions first (OR logic)
        for version_expr in exact_versions:
            if self.parse_dsl_expression(version_expr, cleaned_version):
                return True
        
        # Check range conditions (AND logic)
        if range_conditions:
            for condition in range_conditions:
                if not self.parse_dsl_expression(condition, cleaned_version):
                    return False
            return True  # All range conditions matched
        
        return False

    def extract_version_from_response(self, content, patterns):
        """
        Extract version information from response content
        
        Args:
            content (str): Response content to parse
            patterns (list): List of regex patterns to try
            
        Returns:
            str: Extracted version or None
        """
        if not content or not patterns:
            return None
            
        for pattern in patterns:
            try:
                match = re.search(pattern, content, re.IGNORECASE)
                if match:
                    if match.groups():
                        return match.group(1)
                    return match.group(0)
            except Exception:
                continue
                
        return None

    def _compare_version_parts(self, v1_parts, v2_parts, operator):
        """
        Compare two version part arrays using specified operator
        
        Args:
            v1_parts (list): First version parts
            v2_parts (list): Second version parts
            operator (str): Comparison operator
            
        Returns:
            bool: Comparison result
        """
        try:
            max_len = max(len(v1_parts), len(v2_parts))
            v1_parts_padded = v1_parts + [0] * (max_len - len(v1_parts))
            v2_parts_padded = v2_parts + [0] * (max_len - len(v2_parts))
            
            for i in range(max_len):
                if v1_parts_padded[i] > v2_parts_padded[i]:
                    result = 1
                    break
                elif v1_parts_padded[i] < v2_parts_padded[i]:
                    result = -1
                    break
            else:
                result = 0
                
            if operator == '>=':
                return result >= 0
            elif operator == '<=':
                return result <= 0
            elif operator == '>':
                return result > 0
            elif operator == '<':
                return result < 0
            elif operator == '==':
                return result == 0
            elif operator == '!=':
                return result != 0
                
        except Exception:
            return False
            
        return False
