"""Checks that the built source package ships the tests/ tree."""

from __future__ import annotations

import os
import tarfile
from pathlib import Path

import pytest

PROJECT_ROOT = Path(__file__).resolve().parents[2]


def dist_dir() -> Path:
    return Path(os.environ.get("DIST_DIR", PROJECT_ROOT / "dist"))


def source_archives(directory: Path) -> list[Path]:
    return sorted(directory.glob("*.tar.gz"))


@pytest.fixture
def source_archive() -> Path:
    directory = dist_dir()
    archives = source_archives(directory)
    if len(archives) != 1:
        pytest.skip(
            f"expected exactly one source archive in {directory}/ "
            f"(found {len(archives)}); run `make package` first"
        )
    return archives[0]


def test_source_package_includes_tests(source_archive: Path) -> None:
    with tarfile.open(source_archive, "r:gz") as archive:
        members = archive.getnames()

    test_members = [name for name in members if "/tests/" in name]
    assert test_members, f"package is missing tests/: {source_archive}"
