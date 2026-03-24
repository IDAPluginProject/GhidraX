"""
File and path management utilities.
Corresponds to filemanage.hh / filemanage.cc.

Uses Python's pathlib for cross-platform path handling.
"""
from __future__ import annotations

import os
from pathlib import Path
from typing import List


class FileManage:
    """Generic class for searching files and managing paths.

    Mirrors the C++ FileManage class but uses Python's pathlib
    for cross-platform compatibility.
    """

    separator: str = os.sep

    def __init__(self) -> None:
        self._pathlist: List[Path] = []

    def addDir2Path(self, path: str) -> None:
        """Add a directory to the search path."""
        if path:
            p = Path(path)
            self._pathlist.append(p)

    def addCurrentDir(self) -> None:
        """Add the current working directory to the search path."""
        self._pathlist.append(Path.cwd())

    def findFile(self, name: str) -> str:
        """Search through paths to find a file with the given name.

        Returns the full path if found, empty string otherwise.
        """
        p = Path(name)
        if p.is_absolute():
            if p.exists():
                return str(p)
            return ""
        for directory in self._pathlist:
            candidate = directory / name
            if candidate.exists():
                return str(candidate)
        return ""

    def matchList(self, match: str, isSuffix: bool) -> List[str]:
        """List files matching a pattern across all search paths.

        If isSuffix is True, matches files ending with 'match'.
        Otherwise matches files starting with 'match'.
        """
        results: List[str] = []
        for directory in self._pathlist:
            results.extend(
                self.matchListDir(match, isSuffix, str(directory), allowdot=False)
            )
        return results

    @staticmethod
    def isSeparator(c: str) -> bool:
        """Check if a character is a path separator."""
        return c in ('/', '\\')

    @staticmethod
    def isDirectory(path: str) -> bool:
        """Check if a path is a directory."""
        return Path(path).is_dir()

    @staticmethod
    def isAbsolutePath(full: str) -> bool:
        """Check if a path is absolute."""
        if not full:
            return False
        return Path(full).is_absolute()

    @staticmethod
    def matchListDir(match: str, isSuffix: bool, dirname: str,
                     allowdot: bool = False) -> List[str]:
        """List files in a directory matching a pattern.

        If isSuffix is True, matches files ending with 'match'.
        Otherwise matches files starting with 'match'.
        """
        results: List[str] = []
        dirpath = Path(dirname)
        if not dirpath.is_dir():
            return results
        try:
            for entry in dirpath.iterdir():
                name = entry.name
                if not allowdot and name.startswith('.'):
                    continue
                if len(name) < len(match):
                    continue
                if isSuffix:
                    if name.endswith(match):
                        results.append(str(entry))
                else:
                    if name.startswith(match):
                        results.append(str(entry))
        except PermissionError:
            pass
        return results

    @staticmethod
    def directoryList(dirname: str, allowdot: bool = False) -> List[str]:
        """List all subdirectories under the given directory."""
        results: List[str] = []
        dirpath = Path(dirname)
        if not dirpath.is_dir():
            return results
        try:
            for entry in dirpath.iterdir():
                if entry.is_dir():
                    name = entry.name
                    if name in ('.', '..'):
                        continue
                    if not allowdot and name.startswith('.'):
                        continue
                    results.append(str(entry))
        except PermissionError:
            pass
        return results

    @staticmethod
    def scanDirectoryRecursive(matchname: str, rootpath: str,
                               maxdepth: int) -> List[str]:
        """Recursively scan for directories matching a name."""
        results: List[str] = []
        if maxdepth <= 0:
            return results
        subdirs = FileManage.directoryList(rootpath)
        for curpath in subdirs:
            basename = Path(curpath).name
            if basename == matchname:
                results.append(curpath)
            else:
                results.extend(
                    FileManage.scanDirectoryRecursive(matchname, curpath, maxdepth - 1)
                )
        return results

    @staticmethod
    def splitPath(full: str) -> tuple[str, str]:
        """Split a full path into (directory, basename).

        Returns (path, base) where path ends with separator if non-empty.
        """
        p = Path(full.rstrip('/\\'))
        parent = str(p.parent)
        base = p.name
        if parent == '.':
            return ("", base)
        if not parent.endswith(os.sep) and not parent.endswith('/'):
            parent += os.sep
        return (parent, base)

    def getPathList(self) -> List[str]:
        """Get the current search path list."""
        return [str(p) for p in self._pathlist]
