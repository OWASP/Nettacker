"""
Comprehensive test suite for cross-platform path handling
Tests compatibility across Windows, Linux, and macOS environments
"""

import asyncio
import os
import platform
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch, MagicMock

import pytest

from nettacker.core.utils.cross_platform import (
    CrossPlatformPathHandler,
    AsyncNetworkOptimizer,
    get_cross_platform_config_dir,
    get_cross_platform_data_dir
)


class TestCrossPlatformPathHandler(unittest.TestCase):
    """Test cases for CrossPlatformPathHandler"""
    
    def setUp(self):
        self.handler = CrossPlatformPathHandler()
        self.test_dir = Path(tempfile.mkdtemp())
    
    def tearDown(self):
        import shutil
        if self.test_dir.exists():
            shutil.rmtree(self.test_dir)
    
    def test_safe_path_join_basic(self):
        """Test basic path joining functionality"""
        result = self.handler.safe_path_join("home", "user", "documents")
        expected = Path("home") / "user" / "documents"
        self.assertEqual(result, expected)
    
    def test_safe_path_join_with_pathlib(self):
        """Test path joining with mixed string and Path objects"""
        result = self.handler.safe_path_join(Path("home"), "user", Path("documents"))
        expected = Path("home") / "user" / "documents"
        self.assertEqual(result, expected)
    
    def test_safe_path_join_empty(self):
        """Test path joining with empty components"""
        result = self.handler.safe_path_join()
        self.assertEqual(result, Path())
    
    def test_ensure_directory_exists_new(self):
        """Test creating new directory"""
        new_dir = self.test_dir / "new_directory"
        self.assertFalse(new_dir.exists())
        
        result = self.handler.ensure_directory_exists(new_dir)
        self.assertTrue(result)
        self.assertTrue(new_dir.exists())
        self.assertTrue(new_dir.is_dir())
    
    def test_ensure_directory_exists_nested(self):
        """Test creating nested directories"""
        nested_dir = self.test_dir / "level1" / "level2" / "level3"
        self.assertFalse(nested_dir.exists())
        
        result = self.handler.ensure_directory_exists(nested_dir)
        self.assertTrue(result)
        self.assertTrue(nested_dir.exists())
        self.assertTrue(nested_dir.is_dir())
    
    def test_ensure_directory_exists_existing(self):
        """Test handling existing directory"""
        result = self.handler.ensure_directory_exists(self.test_dir)
        self.assertTrue(result)
        self.assertTrue(self.test_dir.exists())
    
    def test_get_platform_temp_dir_windows(self):
        """Test Windows temp directory detection"""
        with patch('platform.system', return_value='Windows'):
            with patch.dict(os.environ, {'TEMP': 'C:\\Windows\\Temp'}):
                result = self.handler.get_platform_temp_dir()
                self.assertEqual(result, Path('C:\\Windows\\Temp'))
    
    def test_get_platform_temp_dir_unix(self):
        """Test Unix-like temp directory detection"""
        with patch('platform.system', return_value='Linux'):
            result = self.handler.get_platform_temp_dir()
            self.assertEqual(result, Path('/tmp'))
    
    def test_normalize_path_separators_unix(self):
        """Test path separator normalization on Unix-like systems"""
        with patch('platform.system', return_value='Linux'):
            mixed_path = "home\\user\\documents/file.txt"
            result = self.handler.normalize_path_separators(mixed_path)
            self.assertEqual(result, "home/user/documents/file.txt")
    
    def test_normalize_path_separators_windows(self):
        """Test path separator normalization on Windows"""
        with patch('platform.system', return_value='Windows'):
            mixed_path = "home/user/documents\\file.txt"
            result = self.handler.normalize_path_separators(mixed_path)
            # On Windows, pathlib should handle this appropriately
            self.assertIn("home", result)
            self.assertIn("user", result)
            self.assertIn("documents", result)
            self.assertIn("file.txt", result)
    
    def test_generate_safe_filename_invalid_chars(self):
        """Test filename sanitization with invalid characters"""
        dangerous_filename = "file<name>with:invalid|chars?.txt"
        result = self.handler.generate_safe_filename(dangerous_filename)
        
        # Should not contain any invalid characters
        invalid_chars = '<>:"|?*'
        for char in invalid_chars:
            self.assertNotIn(char, result)
        
        # Should contain replacement characters
        self.assertIn("_", result)
    
    def test_generate_safe_filename_windows_reserved(self):
        """Test handling of Windows reserved names"""
        with patch('platform.system', return_value='Windows'):
            reserved_names = ['CON', 'PRN', 'AUX', 'NUL', 'COM1', 'LPT1']
            
            for name in reserved_names:
                result = self.handler.generate_safe_filename(name)
                self.assertNotEqual(result.upper(), name)
                self.assertTrue(result.startswith("_"))
    
    def test_generate_safe_filename_custom_replacement(self):
        """Test filename sanitization with custom replacement character"""
        dangerous_filename = "file<name>with:invalid|chars?.txt"
        result = self.handler.generate_safe_filename(dangerous_filename, replacement_char="-")
        
        # Should contain custom replacement character
        self.assertIn("-", result)
        self.assertNotIn("_", result)


class TestAsyncNetworkOptimizer(unittest.TestCase):
    """Test cases for AsyncNetworkOptimizer"""
    
    def setUp(self):
        self.optimizer = AsyncNetworkOptimizer(max_concurrent_requests=5)
    
    @pytest.mark.asyncio
    async def test_execute_with_semaphore(self):
        """Test semaphore-controlled execution"""
        async def mock_coro():
            await asyncio.sleep(0.1)
            return "test_result"
        
        result = await self.optimizer.execute_with_semaphore(mock_coro())
        self.assertEqual(result, "test_result")
    
    @pytest.mark.asyncio
    async def test_batch_execute_small_batch(self):
        """Test batch execution with small batch"""
        async def mock_coro(value):
            await asyncio.sleep(0.01)
            return value * 2
        
        coroutines = [mock_coro(i) for i in range(3)]
        results = await self.optimizer.batch_execute(coroutines)
        
        self.assertEqual(len(results), 3)
        self.assertEqual(results, [0, 2, 4])
    
    @pytest.mark.asyncio
    async def test_batch_execute_large_batch(self):
        """Test batch execution with large batch"""
        async def mock_coro(value):
            await asyncio.sleep(0.01)
            return value
        
        coroutines = [mock_coro(i) for i in range(20)]
        results = await self.optimizer.batch_execute(coroutines, batch_size=5)
        
        self.assertEqual(len(results), 20)
        self.assertEqual(results, list(range(20)))
    
    @pytest.mark.asyncio
    async def test_batch_execute_with_exceptions(self):
        """Test batch execution handling exceptions"""
        async def mock_coro(value):
            if value == 5:
                raise ValueError("Test exception")
            return value
        
        coroutines = [mock_coro(i) for i in range(10)]
        results = await self.optimizer.batch_execute(coroutines)
        
        self.assertEqual(len(results), 10)
        # Check that exception is included in results
        self.assertTrue(any(isinstance(r, ValueError) for r in results))
    
    @pytest.mark.asyncio
    async def test_async_sleep_with_jitter(self):
        """Test async sleep with jitter"""
        import time
        
        start_time = time.time()
        await self.optimizer.async_sleep_with_jitter(0.1, jitter_factor=0.5)
        end_time = time.time()
        
        elapsed = end_time - start_time
        # Should be roughly 0.1 seconds +/- jitter
        self.assertGreaterEqual(elapsed, 0.05)
        self.assertLessEqual(elapsed, 0.15)


class TestCrossPlatformConfigDirectories(unittest.TestCase):
    """Test cases for cross-platform configuration directories"""
    
    def test_get_cross_platform_config_dir_windows(self):
        """Test Windows config directory"""
        with patch('platform.system', return_value='Windows'):
            with patch.dict(os.environ, {'APPDATA': 'C:\\Users\\Test\\AppData\\Roaming'}):
                result = get_cross_platform_config_dir("testapp")
                expected = Path('C:\\Users\\Test\\AppData\\Roaming') / "testapp"
                self.assertEqual(result, expected)
    
    def test_get_cross_platform_config_dir_macos(self):
        """Test macOS config directory"""
        with patch('platform.system', return_value='Darwin'):
            with patch('pathlib.Path.home', return_value=Path('/Users/test')):
                result = get_cross_platform_config_dir("testapp")
                expected = Path('/Users/test/Library/Application Support/testapp')
                self.assertEqual(result, expected)
    
    def test_get_cross_platform_config_dir_linux(self):
        """Test Linux config directory"""
        with patch('platform.system', return_value='Linux'):
            with patch.dict(os.environ, {'XDG_CONFIG_HOME': '/home/test/.config'}):
                result = get_cross_platform_config_dir("testapp")
                expected = Path('/home/test/.config/testapp')
                self.assertEqual(result, expected)
    
    def test_get_cross_platform_config_dir_linux_default(self):
        """Test Linux config directory with default XDG path"""
        with patch('platform.system', return_value='Linux'):
            with patch.dict(os.environ, {}, clear=True):
                with patch('pathlib.Path.expanduser') as mock_expanduser:
                    mock_expanduser.return_value = Path('/home/test/.config')
                    result = get_cross_platform_config_dir("testapp")
                    expected = Path('/home/test/.config/testapp')
                    self.assertEqual(result, expected)
    
    def test_get_cross_platform_data_dir_windows(self):
        """Test Windows data directory"""
        with patch('platform.system', return_value='Windows'):
            with patch.dict(os.environ, {'LOCALAPPDATA': 'C:\\Users\\Test\\AppData\\Local'}):
                result = get_cross_platform_data_dir("testapp")
                expected = Path('C:\\Users\\Test\\AppData\\Local') / "testapp"
                self.assertEqual(result, expected)
    
    def test_get_cross_platform_data_dir_macos(self):
        """Test macOS data directory"""
        with patch('platform.system', return_value='Darwin'):
            with patch('pathlib.Path.home', return_value=Path('/Users/test')):
                result = get_cross_platform_data_dir("testapp")
                expected = Path('/Users/test/Library/Application Support/testapp')
                self.assertEqual(result, expected)
    
    def test_get_cross_platform_data_dir_linux(self):
        """Test Linux data directory"""
        with patch('platform.system', return_value='Linux'):
            with patch.dict(os.environ, {'XDG_DATA_HOME': '/home/test/.local/share'}):
                result = get_cross_platform_data_dir("testapp")
                expected = Path('/home/test/.local/share/testapp')
                self.assertEqual(result, expected)


class TestCrossPlatformIntegration(unittest.TestCase):
    """Integration tests for cross-platform functionality"""
    
    def test_path_operations_consistency(self):
        """Test that path operations work consistently across platforms"""
        handler = CrossPlatformPathHandler()
        
        # Test path joining and directory creation
        test_path = handler.safe_path_join("test", "nested", "directory")
        
        with tempfile.TemporaryDirectory() as tmpdir:
            full_path = Path(tmpdir) / test_path
            
            success = handler.ensure_directory_exists(full_path)
            self.assertTrue(success)
            self.assertTrue(full_path.exists())
            self.assertTrue(full_path.is_dir())
    
    def test_filename_sanitization_comprehensive(self):
        """Test comprehensive filename sanitization"""
        handler = CrossPlatformPathHandler()
        
        test_cases = [
            "normal_filename.txt",
            "file with spaces.txt",
            "file<with>invalid:chars|.txt",
            "CON.txt" if platform.system() == "Windows" else "valid_name.txt",
            "file/with/path/separators.txt",
            "file\\with\\windows\\separators.txt"
        ]
        
        for test_case in test_cases:
            result = handler.generate_safe_filename(test_case)
            
            # Result should not contain any dangerous characters
            dangerous_chars = '<>:"|?*\0'
            for char in dangerous_chars:
                self.assertNotIn(char, result)
            
            # Result should not be empty
            self.assertGreater(len(result), 0)
    
    def test_config_directories_exist_or_creatable(self):
        """Test that config directories can be determined and created"""
        config_dir = get_cross_platform_config_dir("nettacker_test")
        data_dir = get_cross_platform_data_dir("nettacker_test")
        
        # Should be Path objects
        self.assertIsInstance(config_dir, Path)
        self.assertIsInstance(data_dir, Path)
        
        # Should be absolute paths
        self.assertTrue(config_dir.is_absolute())
        self.assertTrue(data_dir.is_absolute())
        
        # Should contain the app name
        self.assertIn("nettacker_test", str(config_dir))
        self.assertIn("nettacker_test", str(data_dir))


if __name__ == '__main__':
    # Run async tests
    import sys
    if sys.version_info >= (3, 7):
        # For Python 3.7+, use pytest for async tests
        pytest.main([__file__])
    else:
        # For older Python versions, run only sync tests
        unittest.main()