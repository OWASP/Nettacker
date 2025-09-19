"""
OS-agnostic path utilities for OWASP Nettacker

This module provides cross-platform path handling functions to ensure
compatibility across Windows, macOS, and Linux systems. All functions
use pathlib.Path for proper OS-specific path operations.

Addresses Issue #933: Refactor the code to make sure os path related logic is OS agnostic
"""

import os
from pathlib import Path, PurePath
from typing import List, Union, Optional


def safe_path_split(path: Union[str, Path]) -> List[str]:
    """
    Split a path into its component parts in an OS-agnostic way.
    
    Args:
        path: Path to split (string or Path object)
        
    Returns:
        List of path components
        
    Example:
        safe_path_split("/path/to/file") -> ["path", "to", "file"]
        safe_path_split("path\\to\\file") -> ["path", "to", "file"]  # Windows
    """
    if isinstance(path, str):
        path = Path(path)
    return list(path.parts)


def get_path_component(path: Union[str, Path], index: int) -> str:
    """
    Get a specific component of a path by index in an OS-agnostic way.
    
    Args:
        path: Path to extract from (string or Path object)
        index: Index of component to extract (supports negative indexing)
        
    Returns:
        Path component at the specified index
        
    Raises:
        IndexError: If index is out of range
        
    Example:
        get_path_component("/path/to/file.txt", -1) -> "file.txt"
        get_path_component("/path/to/file.txt", -2) -> "to"
    """
    if isinstance(path, str):
        path = Path(path)
    return path.parts[index]


def get_parent_components(path: Union[str, Path], levels: int = 1) -> List[str]:
    """
    Get parent directory components of a path.
    
    Args:
        path: Path to extract from (string or Path object)  
        levels: Number of parent levels to include (default: 1)
        
    Returns:
        List of parent directory components
        
    Example:
        get_parent_components("/path/to/file.txt") -> ["to"]
        get_parent_components("/path/to/file.txt", 2) -> ["path", "to"]
    """
    if isinstance(path, str):
        path = Path(path)
    
    parts = list(path.parts)
    if len(parts) <= levels:
        return parts[:-1] if parts else []
    
    return parts[-(levels + 1):-1]


def safe_join_path(*components) -> str:
    """
    Join path components in an OS-agnostic way.
    
    Args:
        *components: Path components to join
        
    Returns:
        Joined path as string
        
    Example:
        safe_join_path("path", "to", "file") -> "path/to/file" (Unix)
        safe_join_path("path", "to", "file") -> "path\\to\\file" (Windows)
    """
    if not components:
        return ""
    
    # Convert all components to strings and filter out empty ones
    clean_components = [str(c) for c in components if c]
    
    if not clean_components:
        return ""
    
    # Create path from components
    path = Path(clean_components[0])
    for component in clean_components[1:]:
        path = path / component
        
    return str(path)


def get_filename_without_path(path: Union[str, Path]) -> str:
    """
    Extract filename from a path in an OS-agnostic way.
    
    Args:
        path: Full path (string or Path object)
        
    Returns:
        Filename without directory path
        
    Example:
        get_filename_without_path("/path/to/file.txt") -> "file.txt"
        get_filename_without_path("C:\\path\\to\\file.txt") -> "file.txt"
    """
    if isinstance(path, str):
        path = Path(path)
    return path.name


def get_filename_stem(path: Union[str, Path]) -> str:
    """
    Extract filename without extension in an OS-agnostic way.
    
    Args:
        path: Full path (string or Path object)
        
    Returns:
        Filename without extension
        
    Example:
        get_filename_stem("/path/to/file.txt") -> "file"
        get_filename_stem("C:\\path\\to\\file.txt") -> "file"
    """
    if isinstance(path, str):
        path = Path(path)
    return path.stem


def get_file_extension(path: Union[str, Path]) -> str:
    """
    Extract file extension in an OS-agnostic way.
    
    Args:
        path: Full path (string or Path object)
        
    Returns:
        File extension including the dot
        
    Example:
        get_file_extension("/path/to/file.txt") -> ".txt"
        get_file_extension("C:\\path\\to\\file.txt") -> ".txt"
    """
    if isinstance(path, str):
        path = Path(path)
    return path.suffix


def normalize_path(path: Union[str, Path]) -> str:
    """
    Normalize a path to use the OS-appropriate separators.
    
    Args:
        path: Path to normalize (string or Path object)
        
    Returns:
        Normalized path as string
        
    Example:
        normalize_path("path/to/file") -> "path\\to\\file" (Windows)
        normalize_path("path\\to\\file") -> "path/to/file" (Unix)
    """
    if isinstance(path, str):
        path = Path(path)
    return str(path)


def build_message_path(messages_path: Union[str, Path], language: str) -> str:
    """
    Build a path for message files in an OS-agnostic way.
    
    Args:
        messages_path: Base path for messages directory
        language: Language code (e.g., "en", "fr")
        
    Returns:
        Complete path to language message file
        
    Example:
        build_message_path("/app/locale", "en") -> "/app/locale/en.yaml"
        build_message_path("C:\\app\\locale", "en") -> "C:\\app\\locale\\en.yaml"
    """
    if isinstance(messages_path, str):
        messages_path = Path(messages_path)
    
    return str(messages_path / f"{language}.yaml")


def create_repeater_key_name(key_path: Union[str, Path]) -> str:
    """
    Create a repeater key name from a path in an OS-agnostic way.
    
    This function replaces the hardcoded "/" splitting logic used in common.py
    for generating repeater key names.
    
    Args:
        key_path: Path string containing keys separated by path separators
        
    Returns:
        Formatted key name string for repeater operations
        
    Example:
        create_repeater_key_name("key1/key2/key3") -> "['key1']['key2']"
        create_repeater_key_name("key1\\key2\\key3") -> "['key1']['key2']"  # Windows
    """
    if isinstance(key_path, str):
        key_path = Path(key_path)
    
    # Get all parts except the last one
    parts = list(key_path.parts)[:-1]
    
    return "".join([f"['{key}']" for key in parts])


def safe_path_exists(path: Union[str, Path]) -> bool:
    """
    Check if a path exists in an OS-agnostic way.
    
    Args:
        path: Path to check (string or Path object)
        
    Returns:
        True if path exists, False otherwise
    """
    if isinstance(path, str):
        path = Path(path)
    return path.exists()


def safe_mkdir(path: Union[str, Path], parents: bool = True, exist_ok: bool = True) -> None:
    """
    Create a directory in an OS-agnostic way.
    
    Args:
        path: Directory path to create (string or Path object)
        parents: Create parent directories if they don't exist (default: True)
        exist_ok: Don't raise error if directory already exists (default: True)
    """
    if isinstance(path, str):
        path = Path(path)
    path.mkdir(parents=parents, exist_ok=exist_ok)


def get_path_relative_to(path: Union[str, Path], base: Union[str, Path]) -> str:
    """
    Get path relative to a base directory in an OS-agnostic way.
    
    Args:
        path: Path to make relative (string or Path object)
        base: Base directory (string or Path object)
        
    Returns:
        Relative path as string
    """
    if isinstance(path, str):
        path = Path(path)
    if isinstance(base, str):
        base = Path(base)
    
    return str(path.relative_to(base))