# OWASP Nettacker Issue #933 - OS-Agnostic Path Implementation Plan

## Overview
Fix hardcoded forward slashes and implement OS-agnostic path handling across the Nettacker codebase to ensure Windows/Unix compatibility.

## Key Issues Identified

### 1. hardcoded "/" usage in path operations
- **common.py line 168**: `key_name.split("/")[:-1]` - path component extraction
- **common.py line 200**: `root += key + "/"` - path construction
- **arg_parser.py lines 54,68,86,87**: `str(path).split("/")[-2]` - path component extraction  
- **messages.py lines 36,44,50**: String formatting with "/" for paths
- **api/engine.py line 395**: `filename.split("/")[-1]` - basename extraction

### 2. Path construction using string concatenation
- Multiple locations use string concatenation instead of pathlib operations
- Need to replace with Path.joinpath() or "/" operator on Path objects

## Implementation Strategy

### Phase 1: Create path_utils.py module
- Central location for all OS-agnostic path operations
- Helper functions for common path operations
- Use pathlib.Path for all operations

### Phase 2: Fix identified hardcoded "/" usage
- Replace string split operations with pathlib methods
- Update path construction to use pathlib
- Ensure all path operations are OS-agnostic

### Phase 3: Comprehensive testing
- Test on Windows and Unix systems
- Verify backward compatibility
- Add unit tests for new path utilities

## Files to Modify

1. **nettacker/core/utils/path_utils.py** (new file)
2. **nettacker/core/utils/common.py** 
3. **nettacker/core/arg_parser.py**
4. **nettacker/core/messages.py** 
5. **nettacker/api/engine.py**
6. **tests/core/utils/test_path_utils.py** (new file)

## Expected Outcome
- Full Windows/Unix path compatibility
- Clean, maintainable path handling code
- Zero breaking changes to existing functionality
- Comprehensive test coverage