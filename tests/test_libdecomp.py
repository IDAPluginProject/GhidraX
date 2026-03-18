"""Tests for ghidra.core.libdecomp — Python port of libdecomp.cc."""
from __future__ import annotations

import os
import sys

import pytest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', 'python'))

from ghidra.core.libdecomp import (
    startDecompilerLibrary,
    shutdownDecompilerLibrary,
    getSpecPaths,
    _specpaths,
)


class TestStartShutdown:
    def test_start_no_args(self):
        startDecompilerLibrary()

    def test_start_with_none_sleighhome(self):
        startDecompilerLibrary(sleighhome=None)

    def test_start_with_extrapaths(self, tmp_path):
        d = tmp_path / "specs"
        d.mkdir()
        startDecompilerLibrary(extrapaths=[str(d)])
        paths = getSpecPaths().getPathList()
        assert any(str(d) in p for p in paths)

    def test_shutdown(self):
        shutdownDecompilerLibrary()

    def test_getSpecPaths_returns_filemanage(self):
        fm = getSpecPaths()
        from ghidra.core.filemanage import FileManage
        assert isinstance(fm, FileManage)


class TestScanForSleighDirectories:
    def test_scan_with_processors(self, tmp_path):
        # Build a mini Ghidra-like layout
        proc = tmp_path / "Ghidra" / "Processors" / "x86" / "data" / "languages"
        proc.mkdir(parents=True)
        (proc / "x86.sla").write_text("")

        startDecompilerLibrary(sleighhome=str(tmp_path))
        paths = getSpecPaths().getPathList()
        assert any("languages" in p for p in paths)

    def test_scan_nonexistent_dir(self):
        # Should not crash
        startDecompilerLibrary(sleighhome="/nonexistent/path/xyz")


if __name__ == '__main__':
    pytest.main([__file__, '-v'])
