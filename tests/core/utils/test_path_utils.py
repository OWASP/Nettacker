"""
Tests for OS-agnostic path utilities

This test suite validates that all path operations work correctly
across different operating systems and handle edge cases properly.
"""

import os
import sys
import tempfile
import unittest
from pathlib import Path, PurePath
from unittest.mock import patch

# Add the project root to the path so we can import nettacker modules
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '../../..'))

from nettacker.core.utils.path_utils import (
    safe_path_split,
    get_path_component,
    get_parent_components,
    safe_join_path,
    get_filename_without_path,
    get_filename_stem,
    get_file_extension,
    normalize_path,
    build_message_path,
    create_repeater_key_name,
    safe_path_exists,
    safe_mkdir,
    get_path_relative_to
)


class TestPathUtils(unittest.TestCase):
    """Test cases for path utility functions"""

    def setUp(self):
        """Set up test environment"""
        self.temp_dir = tempfile.mkdtemp()
        self.unix_path = "/path/to/file.txt"
        self.windows_path = "C:\\path\\to\\file.txt"
        self.relative_path = "path/to/file.txt"

    def tearDown(self):
        """Clean up test environment"""
        import shutil
        if os.path.exists(self.temp_dir):
            shutil.rmtree(self.temp_dir)

    def test_safe_path_split_unix_style(self):
        """Test path splitting with Unix-style paths"""
        result = safe_path_split("/path/to/file.txt")
        expected = ["/", "path", "to", "file.txt"]
        self.assertEqual(result, expected)

    def test_safe_path_split_relative(self):
        """Test path splitting with relative paths"""
        result = safe_path_split("path/to/file.txt")
        expected = ["path", "to", "file.txt"]
        self.assertEqual(result, expected)

    def test_safe_path_split_path_object(self):
        """Test path splitting with Path objects"""
        path_obj = Path("path/to/file.txt")
        result = safe_path_split(path_obj)
        expected = ["path", "to", "file.txt"]
        self.assertEqual(result, expected)

    def test_get_path_component_positive_index(self):
        """Test getting path component with positive index"""
        result = get_path_component("/path/to/file.txt", 1)
        self.assertEqual(result, "path")

    def test_get_path_component_negative_index(self):
        """Test getting path component with negative index"""
        result = get_path_component("/path/to/file.txt", -1)
        self.assertEqual(result, "file.txt")
        
        result = get_path_component("/path/to/file.txt", -2)
        self.assertEqual(result, "to")

    def test_get_path_component_out_of_range(self):
        """Test getting path component with out-of-range index"""
        with self.assertRaises(IndexError):
            get_path_component("/path/to/file.txt", 10)

    def test_get_parent_components_default(self):
        """Test getting parent components with default level"""
        result = get_parent_components("/path/to/file.txt")
        expected = ["to"]
        self.assertEqual(result, expected)

    def test_get_parent_components_multiple_levels(self):
        """Test getting parent components with multiple levels"""
        result = get_parent_components("/path/to/file.txt", 2)
        expected = ["path", "to"]
        self.assertEqual(result, expected)

    def test_get_parent_components_excessive_levels(self):
        """Test getting parent components with more levels than available"""
        result = get_parent_components("/path/to/file.txt", 10)
        expected = ["/", "path", "to"]
        self.assertEqual(result, expected)

    def test_safe_join_path_multiple_components(self):
        """Test joining multiple path components"""
        result = safe_join_path("path", "to", "file.txt")
        expected = str(Path("path") / "to" / "file.txt")
        self.assertEqual(result, expected)

    def test_safe_join_path_empty_components(self):
        """Test joining path with empty components"""
        result = safe_join_path("path", "", "file.txt")
        expected = str(Path("path") / "file.txt")
        self.assertEqual(result, expected)

    def test_safe_join_path_no_components(self):
        """Test joining path with no components"""
        result = safe_join_path()
        self.assertEqual(result, "")

    def test_get_filename_without_path_unix(self):
        """Test extracting filename from Unix path"""
        result = get_filename_without_path("/path/to/file.txt")
        self.assertEqual(result, "file.txt")

    def test_get_filename_without_path_path_object(self):
        """Test extracting filename from Path object"""
        path_obj = Path("/path/to/file.txt")
        result = get_filename_without_path(path_obj)
        self.assertEqual(result, "file.txt")

    def test_get_filename_stem(self):
        """Test extracting filename stem (without extension)"""
        result = get_filename_stem("/path/to/file.txt")
        self.assertEqual(result, "file")

    def test_get_filename_stem_no_extension(self):
        """Test extracting filename stem from file without extension"""
        result = get_filename_stem("/path/to/filename")
        self.assertEqual(result, "filename")

    def test_get_file_extension(self):
        """Test extracting file extension"""
        result = get_file_extension("/path/to/file.txt")
        self.assertEqual(result, ".txt")

    def test_get_file_extension_no_extension(self):
        """Test extracting extension from file without extension"""
        result = get_file_extension("/path/to/filename")
        self.assertEqual(result, "")

    def test_normalize_path_string(self):
        """Test normalizing path string"""
        result = normalize_path("path/to/file.txt")
        expected = str(Path("path/to/file.txt"))
        self.assertEqual(result, expected)

    def test_normalize_path_object(self):
        """Test normalizing Path object"""
        path_obj = Path("path/to/file.txt")
        result = normalize_path(path_obj)
        expected = str(path_obj)
        self.assertEqual(result, expected)

    def test_build_message_path(self):
        """Test building message file path"""
        result = build_message_path("/app/locale", "en")
        expected = str(Path("/app/locale") / "en.yaml")
        self.assertEqual(result, expected)

    def test_build_message_path_with_path_object(self):
        """Test building message file path with Path object"""
        base_path = Path("/app/locale")
        result = build_message_path(base_path, "fr")
        expected = str(base_path / "fr.yaml")
        self.assertEqual(result, expected)

    def test_create_repeater_key_name(self):
        """Test creating repeater key name from path"""
        result = create_repeater_key_name("key1/key2/key3")
        expected = "['key1']['key2']"
        self.assertEqual(result, expected)

    def test_create_repeater_key_name_single_key(self):
        """Test creating repeater key name with single key"""
        result = create_repeater_key_name("key1")
        expected = ""
        self.assertEqual(result, expected)

    def test_create_repeater_key_name_path_object(self):
        """Test creating repeater key name with Path object"""
        path_obj = Path("key1/key2/key3")
        result = create_repeater_key_name(path_obj)
        expected = "['key1']['key2']"
        self.assertEqual(result, expected)

    def test_safe_path_exists_existing_path(self):
        """Test checking existence of existing path"""
        # Create a temporary file
        temp_file = os.path.join(self.temp_dir, "test_file.txt")
        with open(temp_file, 'w') as f:
            f.write("test")
        
        result = safe_path_exists(temp_file)
        self.assertTrue(result)

    def test_safe_path_exists_non_existing_path(self):
        """Test checking existence of non-existing path"""
        non_existing = os.path.join(self.temp_dir, "non_existing.txt")
        result = safe_path_exists(non_existing)
        self.assertFalse(result)

    def test_safe_mkdir_new_directory(self):
        """Test creating new directory"""
        new_dir = os.path.join(self.temp_dir, "new_directory")
        safe_mkdir(new_dir)
        self.assertTrue(os.path.exists(new_dir))
        self.assertTrue(os.path.isdir(new_dir))

    def test_safe_mkdir_existing_directory(self):
        """Test creating existing directory with exist_ok=True"""
        # Should not raise error
        safe_mkdir(self.temp_dir)
        self.assertTrue(os.path.exists(self.temp_dir))

    def test_safe_mkdir_with_parents(self):
        """Test creating directory with parent directories"""
        deep_dir = os.path.join(self.temp_dir, "level1", "level2", "level3")
        safe_mkdir(deep_dir, parents=True)
        self.assertTrue(os.path.exists(deep_dir))
        self.assertTrue(os.path.isdir(deep_dir))

    def test_get_path_relative_to(self):
        """Test getting relative path"""
        base_path = "/home/user"
        full_path = "/home/user/documents/file.txt"
        result = get_path_relative_to(full_path, base_path)
        expected = str(Path("documents/file.txt"))
        self.assertEqual(result, expected)

    def test_get_path_relative_to_path_objects(self):
        """Test getting relative path with Path objects"""
        base_path = Path("/home/user")
        full_path = Path("/home/user/documents/file.txt")
        result = get_path_relative_to(full_path, base_path)
        expected = str(Path("documents/file.txt"))
        self.assertEqual(result, expected)

    def test_cross_platform_compatibility(self):
        """Test that functions work on different path formats"""
        # Test with both Unix and Windows style paths when applicable
        unix_result = get_filename_without_path("/path/to/file.txt")
        
        # This should work the same regardless of the current OS
        self.assertEqual(unix_result, "file.txt")
        
        # Test path component extraction
        unix_component = get_path_component("/path/to/file.txt", -2)
        self.assertEqual(unix_component, "to")

    def test_edge_cases(self):
        """Test edge cases and error conditions"""
        # Empty path
        result = safe_path_split("")
        self.assertEqual(result, [])
        
        # Root path
        result = safe_path_split("/")
        self.assertEqual(result, ["/"])
        
        # Single component
        result = safe_path_split("file.txt")
        self.assertEqual(result, ["file.txt"])

    def test_windows_compatibility(self):
        """Test Windows-specific path handling"""
        # Test with PurePath to handle Windows paths on any system
        from pathlib import PureWindowsPath
        
        # Create a Windows-style path using PureWindowsPath
        windows_path = PureWindowsPath("C:\\Users\\user\\file.txt")
        filename = get_filename_without_path(windows_path)
        self.assertEqual(filename, "file.txt")
        
        stem = get_filename_stem(windows_path)
        self.assertEqual(stem, "file")


class TestPathUtilsIntegration(unittest.TestCase):
    """Integration tests with the actual functions being replaced"""

    def test_re_address_repeaters_key_name_compatibility(self):
        """Test that the new function produces same output as old logic"""
        # This tests the specific function that was replaced in common.py
        test_cases = [
            "key1/key2/key3",
            "a/b/c/d",
            "single",
            "path/to/deeply/nested/key"
        ]
        
        for key_name in test_cases:
            # New implementation
            new_result = create_repeater_key_name(key_name)
            
            # Original logic (for comparison)
            original_result = "".join(["['" + _key + "']" for _key in key_name.split("/")[:-1]])
            
            self.assertEqual(new_result, original_result)

    def test_message_path_building(self):
        """Test message path building functionality"""
        base_path = "/app/locale"
        language = "en"
        
        result = build_message_path(base_path, language)
        expected = "/app/locale/en.yaml"
        
        # Normalize for comparison (handles OS differences)
        result_normalized = str(Path(result))
        expected_normalized = str(Path(expected))
        
        self.assertEqual(result_normalized, expected_normalized)


if __name__ == '__main__':
    # Run the tests
    unittest.main(verbosity=2)