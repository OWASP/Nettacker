"""
Cross-platform utility functions for OWASP Nettacker
Provides enhanced path handling and async utilities for improved cross-platform compatibility
"""

import asyncio
import os
import platform
from pathlib import Path
from typing import Union, List, Optional


class CrossPlatformPathHandler:
    """
    Enhanced cross-platform path handling utility
    Provides methods to ensure consistent path operations across Windows, Linux, and macOS
    """
    
    @staticmethod
    def safe_path_join(*components: Union[str, Path]) -> Path:
        """
        Safely join path components using pathlib for cross-platform compatibility
        
        Args:
            *components: Path components to join
            
        Returns:
            Path: Cross-platform compatible path object
        """
        if not components:
            return Path()
        
        base_path = Path(components[0])
        for component in components[1:]:
            base_path = base_path / component
        return base_path
    
    @staticmethod
    def ensure_directory_exists(path: Union[str, Path]) -> bool:
        """
        Ensure directory exists, create if necessary with proper permissions
        
        Args:
            path: Directory path to create
            
        Returns:
            bool: True if directory exists or was created successfully
        """
        try:
            path_obj = Path(path)
            path_obj.mkdir(parents=True, exist_ok=True)
            return True
        except Exception as e:
            print(f"Failed to create directory {path}: {e}")
            return False
    
    @staticmethod
    def get_platform_temp_dir() -> Path:
        """
        Get platform-specific temporary directory
        
        Returns:
            Path: Platform-appropriate temporary directory
        """
        if platform.system() == "Windows":
            temp_dir = Path(os.environ.get('TEMP', 'C:\\temp'))
        else:
            temp_dir = Path('/tmp')
        
        return temp_dir
    
    @staticmethod
    def normalize_path_separators(path: str) -> str:
        """
        Normalize path separators for current platform
        
        Args:
            path: Path string with mixed separators
            
        Returns:
            str: Path with normalized separators
        """
        if platform.system() == "Windows":
            # On Windows, pathlib handles this naturally
            return str(Path(path))
        else:
            # On Unix-like systems, manually convert backslashes to forward slashes
            # because pathlib treats backslashes as valid filename characters
            normalized_path = path.replace('\\', '/')
            return str(Path(normalized_path))
    
    @staticmethod
    def generate_safe_filename(filename: str, replacement_char: str = "_") -> str:
        """
        Generate safe filename by replacing invalid characters
        
        Args:
            filename: Original filename
            replacement_char: Character to replace invalid chars with
            
        Returns:
            str: Safe filename for current platform
        """
        # Start with common invalid characters
        invalid_chars = '<>:"|?*\0/'
        
        # On Windows, these are additional restrictions, on Unix we're more permissive
        if platform.system() == "Windows":
            # Windows has the most restrictions
            invalid_chars = '<>:"|?*\0/\\'
        else:
            # Unix-like systems: be conservative and sanitize common problematic chars
            # but allow more flexibility
            invalid_chars = '<>:"|?*\0'
        
        safe_name = filename
        
        for char in invalid_chars:
            safe_name = safe_name.replace(char, replacement_char)
        
        # Handle reserved names on Windows
        if platform.system() == "Windows":
            reserved_names = {'CON', 'PRN', 'AUX', 'NUL', 'COM1', 'COM2', 'COM3', 'COM4', 
                            'COM5', 'COM6', 'COM7', 'COM8', 'COM9', 'LPT1', 'LPT2', 'LPT3', 
                            'LPT4', 'LPT5', 'LPT6', 'LPT7', 'LPT8', 'LPT9'}
            name_only = safe_name.split('.')[0].upper()
            if name_only in reserved_names:
                safe_name = f"{replacement_char}{safe_name}"
        
        return safe_name


class AsyncNetworkOptimizer:
    """
    Async optimization utilities for network operations
    Provides async alternatives to threading-based network operations
    """
    
    def __init__(self, max_concurrent_requests: int = 100):
        self.max_concurrent_requests = max_concurrent_requests
        self.semaphore = asyncio.Semaphore(max_concurrent_requests)
    
    async def execute_with_semaphore(self, coro):
        """
        Execute coroutine with semaphore to limit concurrent operations
        
        Args:
            coro: Coroutine to execute
            
        Returns:
            Result of coroutine execution
        """
        async with self.semaphore:
            return await coro
    
    async def batch_execute(self, coroutines: List, batch_size: Optional[int] = None) -> List:
        """
        Execute coroutines in batches for optimal resource utilization
        
        Args:
            coroutines: List of coroutines to execute
            batch_size: Size of each batch (defaults to max_concurrent_requests)
            
        Returns:
            List: Results from all coroutines
        """
        if batch_size is None:
            batch_size = self.max_concurrent_requests
        
        results = []
        for i in range(0, len(coroutines), batch_size):
            batch = coroutines[i:i + batch_size]
            batch_results = await asyncio.gather(*batch, return_exceptions=True)
            results.extend(batch_results)
        
        return results
    
    @staticmethod
    async def async_sleep_with_jitter(base_delay: float, jitter_factor: float = 0.1):
        """
        Async sleep with jitter to prevent thundering herd
        
        Args:
            base_delay: Base delay in seconds
            jitter_factor: Factor for random jitter (0.0 to 1.0)
        """
        import random
        jitter = random.uniform(-jitter_factor, jitter_factor) * base_delay
        await asyncio.sleep(base_delay + jitter)


def get_cross_platform_config_dir(app_name: str = "nettacker") -> Path:
    """
    Get platform-appropriate configuration directory
    
    Args:
        app_name: Application name for config directory
        
    Returns:
        Path: Platform-appropriate config directory
    """
    system = platform.system()
    
    if system == "Windows":
        config_dir = Path(os.environ.get('APPDATA', '~')).expanduser() / app_name
    elif system == "Darwin":  # macOS
        config_dir = Path.home() / "Library" / "Application Support" / app_name
    else:  # Linux and other Unix-like systems
        config_dir = Path(os.environ.get('XDG_CONFIG_HOME', '~/.config')).expanduser() / app_name
    
    return config_dir


def get_cross_platform_data_dir(app_name: str = "nettacker") -> Path:
    """
    Get platform-appropriate data directory
    
    Args:
        app_name: Application name for data directory
        
    Returns:
        Path: Platform-appropriate data directory
    """
    system = platform.system()
    
    if system == "Windows":
        data_dir = Path(os.environ.get('LOCALAPPDATA', '~')).expanduser() / app_name
    elif system == "Darwin":  # macOS
        data_dir = Path.home() / "Library" / "Application Support" / app_name
    else:  # Linux and other Unix-like systems
        data_dir = Path(os.environ.get('XDG_DATA_HOME', '~/.local/share')).expanduser() / app_name
    
    return data_dir