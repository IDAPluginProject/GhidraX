"""
Library initialization for the decompiler engine.
Corresponds to libdecomp.hh / libdecomp.cc.

Provides startup and shutdown routines for the decompiler library.
"""
from __future__ import annotations

from typing import List, Optional

from ghidra.core.capability import CapabilityPoint
from ghidra.core.filemanage import FileManage


def startDecompilerLibrary(sleighhome: Optional[str] = None,
                           extrapaths: Optional[List[str]] = None) -> None:
    """Initialize all decompiler capabilities and register sleigh specifications.

    If a Ghidra root directory is provided via *sleighhome*, it is scanned
    for SLEIGH specification directories.  Additional paths can be supplied
    via *extrapaths*.
    """
    CapabilityPoint.initializeAll()

    if sleighhome is not None:
        _scanForSleighDirectories(sleighhome)

    if extrapaths:
        for p in extrapaths:
            _specpaths.addDir2Path(p)


def shutdownDecompilerLibrary() -> None:
    """Release any resources held by the decompiler library."""
    pass


# ---------------------------------------------------------------------------
# Internal spec-path management (simplified version of SleighArchitecture
# static spec scanning)
# ---------------------------------------------------------------------------

_specpaths = FileManage()


def getSpecPaths() -> FileManage:
    """Get the global specification search paths."""
    return _specpaths


def _scanForSleighDirectories(rootpath: str) -> None:
    """Scan a Ghidra root directory for SLEIGH specification paths.

    Looks for directories named ``Processors`` under rootpath and adds
    them to the global spec search paths.
    """
    results = FileManage.scanDirectoryRecursive("Processors", rootpath, maxdepth=3)
    for proc_dir in results:
        subdirs = FileManage.directoryList(proc_dir)
        for sd in subdirs:
            lang_dirs = FileManage.scanDirectoryRecursive("data", sd, maxdepth=2)
            for lang in lang_dirs:
                _specpaths.addDir2Path(lang)
            languages_dirs = FileManage.scanDirectoryRecursive("languages", sd, maxdepth=2)
            for lang in languages_dirs:
                _specpaths.addDir2Path(lang)
