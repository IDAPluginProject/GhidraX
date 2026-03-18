"""Tests for ghidra.core.filemanage — Python port of filemanage.cc."""
from __future__ import annotations

import os
import sys
import pytest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', 'python'))

from ghidra.core.filemanage import FileManage


class TestBasicConstruction:
    def test_empty(self):
        fm = FileManage()
        assert fm.getPathList() == []

    def test_addDir2Path(self, tmp_path):
        fm = FileManage()
        fm.addDir2Path(str(tmp_path))
        assert len(fm.getPathList()) == 1
        assert str(tmp_path) in fm.getPathList()[0]

    def test_addDir2Path_empty_string(self):
        fm = FileManage()
        fm.addDir2Path("")
        assert fm.getPathList() == []

    def test_addCurrentDir(self):
        fm = FileManage()
        fm.addCurrentDir()
        paths = fm.getPathList()
        assert len(paths) == 1
        assert os.path.isdir(paths[0])


class TestFindFile:
    def test_find_existing(self, tmp_path):
        (tmp_path / "hello.txt").write_text("hi")
        fm = FileManage()
        fm.addDir2Path(str(tmp_path))
        result = fm.findFile("hello.txt")
        assert result != ""
        assert "hello.txt" in result

    def test_find_nonexistent(self, tmp_path):
        fm = FileManage()
        fm.addDir2Path(str(tmp_path))
        result = fm.findFile("nosuchfile.xyz")
        assert result == ""

    def test_find_absolute_existing(self, tmp_path):
        f = tmp_path / "abs.txt"
        f.write_text("data")
        fm = FileManage()
        result = fm.findFile(str(f))
        assert result == str(f)

    def test_find_absolute_nonexistent(self):
        fm = FileManage()
        result = fm.findFile("/nonexistent/path/to/file.xyz")
        assert result == ""

    def test_find_multiple_paths(self, tmp_path):
        d1 = tmp_path / "dir1"
        d2 = tmp_path / "dir2"
        d1.mkdir()
        d2.mkdir()
        (d2 / "target.bin").write_bytes(b"\x00")
        fm = FileManage()
        fm.addDir2Path(str(d1))
        fm.addDir2Path(str(d2))
        result = fm.findFile("target.bin")
        assert result != ""
        assert "target.bin" in result


class TestMatchList:
    def test_suffix_match(self, tmp_path):
        (tmp_path / "foo.sla").write_text("")
        (tmp_path / "bar.sla").write_text("")
        (tmp_path / "baz.txt").write_text("")
        fm = FileManage()
        fm.addDir2Path(str(tmp_path))
        results = fm.matchList(".sla", isSuffix=True)
        assert len(results) == 2
        assert all(r.endswith(".sla") for r in results)

    def test_prefix_match(self, tmp_path):
        (tmp_path / "test_a.py").write_text("")
        (tmp_path / "test_b.py").write_text("")
        (tmp_path / "other.py").write_text("")
        fm = FileManage()
        fm.addDir2Path(str(tmp_path))
        results = fm.matchList("test_", isSuffix=False)
        assert len(results) == 2

    def test_no_match(self, tmp_path):
        (tmp_path / "hello.txt").write_text("")
        fm = FileManage()
        fm.addDir2Path(str(tmp_path))
        results = fm.matchList(".xyz", isSuffix=True)
        assert len(results) == 0


class TestMatchListDir:
    def test_skip_dotfiles(self, tmp_path):
        (tmp_path / ".hidden").write_text("")
        (tmp_path / "visible.txt").write_text("")
        results = FileManage.matchListDir(".txt", True, str(tmp_path), allowdot=False)
        assert len(results) == 1
        assert "visible.txt" in results[0]

    def test_allow_dotfiles(self, tmp_path):
        (tmp_path / ".hidden.txt").write_text("")
        (tmp_path / "visible.txt").write_text("")
        results = FileManage.matchListDir(".txt", True, str(tmp_path), allowdot=True)
        assert len(results) == 2

    def test_nonexistent_dir(self):
        results = FileManage.matchListDir(".txt", True, "/nonexistent/dir/xyz")
        assert results == []


class TestDirectoryList:
    def test_list_subdirs(self, tmp_path):
        (tmp_path / "sub1").mkdir()
        (tmp_path / "sub2").mkdir()
        (tmp_path / "file.txt").write_text("")
        results = FileManage.directoryList(str(tmp_path))
        assert len(results) == 2
        names = [os.path.basename(r) for r in results]
        assert "sub1" in names
        assert "sub2" in names

    def test_skip_hidden_dirs(self, tmp_path):
        (tmp_path / ".hidden").mkdir()
        (tmp_path / "visible").mkdir()
        results = FileManage.directoryList(str(tmp_path), allowdot=False)
        assert len(results) == 1
        assert "visible" in results[0]

    def test_allow_hidden_dirs(self, tmp_path):
        (tmp_path / ".hidden").mkdir()
        (tmp_path / "visible").mkdir()
        results = FileManage.directoryList(str(tmp_path), allowdot=True)
        assert len(results) == 2


class TestScanDirectoryRecursive:
    def test_find_nested(self, tmp_path):
        target = tmp_path / "a" / "b" / "target"
        target.mkdir(parents=True)
        results = FileManage.scanDirectoryRecursive("target", str(tmp_path), maxdepth=5)
        assert len(results) == 1
        assert "target" in results[0]

    def test_max_depth_limit(self, tmp_path):
        target = tmp_path / "a" / "b" / "c" / "target"
        target.mkdir(parents=True)
        results = FileManage.scanDirectoryRecursive("target", str(tmp_path), maxdepth=2)
        assert len(results) == 0

    def test_zero_depth(self, tmp_path):
        (tmp_path / "target").mkdir()
        results = FileManage.scanDirectoryRecursive("target", str(tmp_path), maxdepth=0)
        assert len(results) == 0


class TestSplitPath:
    def test_with_directory(self):
        path, base = FileManage.splitPath(os.path.join("some", "dir", "file.txt"))
        assert base == "file.txt"
        assert path != ""

    def test_basename_only(self):
        path, base = FileManage.splitPath("file.txt")
        assert base == "file.txt"
        assert path == ""

    def test_trailing_separator(self):
        path, base = FileManage.splitPath(os.path.join("some", "dir") + os.sep)
        assert base == "dir"


class TestStaticHelpers:
    def test_isSeparator(self):
        assert FileManage.isSeparator('/')
        assert FileManage.isSeparator('\\')
        assert not FileManage.isSeparator('a')

    def test_isDirectory(self, tmp_path):
        assert FileManage.isDirectory(str(tmp_path))
        assert not FileManage.isDirectory(str(tmp_path / "nonexistent"))

    def test_isAbsolutePath(self):
        assert not FileManage.isAbsolutePath("")
        assert not FileManage.isAbsolutePath("relative/path")
        if os.name == 'nt':
            assert FileManage.isAbsolutePath("C:\\Users")
        else:
            assert FileManage.isAbsolutePath("/usr/bin")


if __name__ == '__main__':
    pytest.main([__file__, '-v'])
