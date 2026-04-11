import os
from typing import List


class FileManage:
    """Generic class for searching files and managing paths."""

    separator: str = "\\" if os.name == "nt" else "/"
    separatorClass: str = "/\\" if os.name == "nt" else "/"

    def __init__(self) -> None:
        self._pathlist: List[str] = []

    @staticmethod
    def _storeString(out: List[str] | None, value: str) -> None:
        if out is None:
            return
        if out:
            out[0] = value
        else:
            out.append(value)

    @classmethod
    def _normalizeDirectory(cls, path: str) -> str:
        if path and not cls.isSeparator(path[-1]):
            return path + cls.separator
        return path

    @staticmethod
    def _lastSeparator(full: str, end: int) -> int:
        if end < 0:
            return -1
        pos = -1
        for ch in FileManage.separatorClass:
            pos = max(pos, full.rfind(ch, 0, end + 1))
        return pos

    @classmethod
    def buildPath(cls, pathels: List[str], level: int) -> str:
        """Build an absolute path using elements from pathels in reverse order."""
        pieces: List[str] = []
        for i in range(len(pathels) - 1, level - 1, -1):
            pieces.append(cls.separator)
            pieces.append(pathels[i])
        return "".join(pieces)

    @classmethod
    def testDevelopmentPath(
        cls, pathels: List[str], level: int, root_out: List[str] | None = None
    ):
        """Determine if pathels[level] is part of a Ghidra development layout."""
        if level + 2 >= len(pathels):
            cls._storeString(root_out, "")
            return False if root_out is not None else (False, "")
        parent = pathels[level + 1]
        if len(parent) < 11 or parent[:7] != "ghidra." or parent[-4:] != ".git":
            cls._storeString(root_out, "")
            return False if root_out is not None else (False, "")
        root = cls.buildPath(pathels, level + 2)
        cls._storeString(root_out, root)
        testpaths1 = cls.scanDirectoryRecursive("ghidra.git", root, 1)
        if len(testpaths1) != 1:
            return False if root_out is not None else (False, root)
        testpaths2 = cls.scanDirectoryRecursive("Ghidra", testpaths1[0], 1)
        result = len(testpaths2) == 1
        return result if root_out is not None else (result, root)

    @classmethod
    def testInstallPath(
        cls, pathels: List[str], level: int, root_out: List[str] | None = None
    ):
        """Determine if pathels[level] is part of a Ghidra install layout."""
        if level + 1 >= len(pathels):
            cls._storeString(root_out, "")
            return False if root_out is not None else (False, "")
        root = cls.buildPath(pathels, level + 1)
        cls._storeString(root_out, root)
        testpaths1 = cls.scanDirectoryRecursive("server", root, 1)
        if len(testpaths1) != 1:
            return False if root_out is not None else (False, root)
        testpaths2 = cls.scanDirectoryRecursive("server.conf", testpaths1[0], 1)
        result = len(testpaths2) == 1
        return result if root_out is not None else (result, root)

    def addDir2Path(self, path: str) -> None:
        """Add a directory to the search path."""
        if path:
            self._pathlist.append(self._normalizeDirectory(path))

    def addCurrentDir(self) -> None:
        """Add the current working directory to the search path."""
        try:
            dirname = os.getcwd()
        except OSError:
            return
        self.addDir2Path(dirname)

    def findFile(self, name: str) -> str:
        """Search through paths to find the file with the given name."""
        if not name:
            return ""
        if self.isSeparator(name[0]):
            if os.path.isfile(name):
                return name
            return ""
        for directory in self._pathlist:
            candidate = directory + name
            if os.path.isfile(candidate):
                return candidate
        return ""

    def matchList(
        self, match: str, isSuffix: bool = True, recursive: bool = False
    ) -> List[str]:
        """List files matching a pattern across all search paths."""
        results: List[str] = []
        for directory in self._pathlist:
            if recursive:
                pending = [directory]
                while pending:
                    curdir = pending.pop(0)
                    results.extend(
                        self.matchListDir(match, isSuffix, curdir, allowdot=False)
                    )
                    pending.extend(self.directoryList(curdir))
            else:
                results.extend(
                    self.matchListDir(match, isSuffix, directory, allowdot=False)
                )
        return results

    @staticmethod
    def isSeparator(c: str) -> bool:
        """Check if a character is a path separator."""
        if os.name == "nt":
            return c in ("/", "\\")
        return c == FileManage.separator

    @staticmethod
    def isDirectory(path: str) -> bool:
        """Check if a path is a directory."""
        return os.path.isdir(path)

    @staticmethod
    def isAbsolutePath(full: str) -> bool:
        """Check if a path is absolute using the native FileManage rule."""
        if not full:
            return False
        return full[0] == FileManage.separator

    @staticmethod
    def matchListDir(
        match: str, isSuffix: bool, dirname: str, allowdot: bool = False
    ) -> List[str]:
        """Look through files in a directory for those matching match."""
        results: List[str] = []
        if not dirname:
            return results
        dirfinal = FileManage._normalizeDirectory(dirname)
        try:
            entries = os.listdir(dirfinal)
        except OSError:
            return results
        for fullname in entries:
            if len(match) <= len(fullname) and (allowdot or fullname[0] != "."):
                if isSuffix:
                    if fullname.endswith(match):
                        results.append(dirfinal + fullname)
                elif fullname.startswith(match):
                    results.append(dirfinal + fullname)
        return results

    @staticmethod
    def directoryList(dirname: str, allowdot: bool = False) -> List[str]:
        """List full pathnames of all directories under dirname."""
        results: List[str] = []
        if not dirname:
            return results
        dirfinal = FileManage._normalizeDirectory(dirname)
        try:
            entries = os.listdir(dirfinal)
        except OSError:
            return results
        for fullname in entries:
            if fullname in (".", ".."):
                continue
            path = dirfinal + fullname
            if not os.path.isdir(path):
                continue
            if allowdot or fullname[0] != ".":
                results.append(path)
        return results

    @staticmethod
    def scanDirectoryRecursive(
        matchname: str, rootpath: str, maxdepth: int
    ) -> List[str]:
        """Recursively scan for directories matching a name."""
        results: List[str] = []
        if maxdepth == 0:
            return results
        subdir = FileManage.directoryList(rootpath)
        for curpath in subdir:
            pos = FileManage._lastSeparator(curpath, len(curpath) - 1)
            if pos == -1:
                pos = 0
            else:
                pos += 1
            if curpath[pos:] == matchname:
                results.append(curpath)
            else:
                results.extend(
                    FileManage.scanDirectoryRecursive(matchname, curpath, maxdepth - 1)
                )
        return results

    @staticmethod
    def splitPath(
        full: str, path_out: List[str] | None = None, base_out: List[str] | None = None
    ) -> tuple[str, str]:
        """Split full into its path and basename components."""
        if not full:
            FileManage._storeString(path_out, "")
            FileManage._storeString(base_out, "")
            return ("", "")
        end = len(full) - 1
        if FileManage.isSeparator(full[-1]):
            end = len(full) - 2
        pos = FileManage._lastSeparator(full, end)
        if pos == -1:
            path = ""
            base = full
        else:
            base = full[pos + 1 : pos + 1 + (end - pos)]
            path = full[: pos + 1]
        FileManage._storeString(path_out, path)
        FileManage._storeString(base_out, base)
        return (path, base)

    @classmethod
    def discoverGhidraRoot(cls, argv0: str) -> str:
        """Find the root of the Ghidra distribution based on argv0."""
        pathels: List[str] = []
        cur = argv0
        skiplevel = 0
        isAbs = cls.isAbsolutePath(cur)

        while True:
            sizebefore = len(cur)
            cur, base = cls.splitPath(cur)
            if len(cur) == sizebefore:
                break
            if base == ".":
                skiplevel += 1
            elif base == "..":
                skiplevel += 2
            if skiplevel > 0:
                skiplevel -= 1
            else:
                pathels.append(base)

        if not isAbs:
            curdir = FileManage()
            curdir.addCurrentDir()
            if curdir._pathlist:
                cur = curdir._pathlist[0]
                while True:
                    sizebefore = len(cur)
                    cur, base = cls.splitPath(cur)
                    if len(cur) == sizebefore:
                        break
                    pathels.append(base)

        for i, piece in enumerate(pathels):
            if piece != "Ghidra":
                continue
            dev_ok, root = cls.testDevelopmentPath(pathels, i)
            if dev_ok:
                return root
            install_ok, root = cls.testInstallPath(pathels, i)
            if install_ok:
                return root
        return ""

    def getPathList(self) -> List[str]:
        """Get the current search path list."""
        return list(self._pathlist)
