"""
Corresponds to: raw_arch.hh / raw_arch.cc

Bare bones capability for treating a file as a raw executable image.
Provides RawBinaryArchitecture and RawBinaryArchitectureCapability.
"""

from __future__ import annotations

import io
import os
from typing import Optional, TYPE_CHECKING

from ghidra.core.error import LowlevelError
from ghidra.arch.sleigh_arch import SleighArchitecture
from ghidra.arch.architecture import ArchitectureCapability

if TYPE_CHECKING:
    pass


# =========================================================================
# RawLoadImage  (minimal — just enough to open a raw binary file)
# =========================================================================

class RawLoadImage:
    """Minimal load-image that reads a raw binary file.

    Mirrors the C++ RawLoadImage from loadimage.hh.
    """

    def __init__(self, filename: str) -> None:
        self._filename: str = filename
        self._data: bytes = b""
        self._space = None
        self._adjustvma: int = 0

    def open(self) -> None:
        """Read the raw binary file into memory."""
        if not os.path.isfile(self._filename):
            raise LowlevelError(f"Unable to open raw binary file: {self._filename}")
        with open(self._filename, "rb") as f:
            self._data = f.read()

    def adjustVma(self, adjust: int) -> None:
        self._adjustvma = adjust

    def attachToSpace(self, spc) -> None:
        """Attach the default code space to this loader."""
        self._space = spc

    def getFileName(self) -> str:
        return self._filename

    def getArchType(self) -> str:
        return "raw"

    def loadFill(self, buf: bytearray, size: int, addr) -> None:
        """Load *size* bytes at *addr* into *buf*. Pad with zero if unavailable."""
        offset = addr.getOffset() - self._adjustvma
        for i in range(size):
            idx = offset + i
            if 0 <= idx < len(self._data):
                buf[i] = self._data[idx]
            else:
                buf[i] = 0


# =========================================================================
# RawBinaryArchitectureCapability
# =========================================================================

class RawBinaryArchitectureCapability(ArchitectureCapability):
    """Extension point for building an Architecture that reads raw images."""

    def __init__(self) -> None:
        super().__init__()
        self.name = "raw"

    def buildArchitecture(self, filename: str, target: str,
                          estream: Optional[io.StringIO] = None):
        return RawBinaryArchitecture(filename, target, estream)

    def isFileMatch(self, filename: str) -> bool:
        # Raw binary can always match as a fallback
        return True

    def isXmlMatch(self, doc) -> bool:
        if doc is None:
            return False
        if hasattr(doc, 'tag'):
            return doc.tag == "raw_savefile"
        return False


# =========================================================================
# RawBinaryArchitecture
# =========================================================================

class RawBinaryArchitecture(SleighArchitecture):
    """Architecture that reads its binary as a raw file.

    Mirrors the C++ RawBinaryArchitecture.
    """

    def __init__(self, fname: str = "", targ: str = "",
                 estream: Optional[io.StringIO] = None) -> None:
        super().__init__(fname, targ, estream)
        self.adjustvma: int = 0

    def buildLoader(self, store=None) -> None:
        """Build a RawLoadImage from the filename."""
        self.collectSpecFiles(self.errorstream)
        ldr = RawLoadImage(self.getFilename())
        ldr.open()
        if self.adjustvma != 0:
            ldr.adjustVma(self.adjustvma)
        self.loader = ldr

    def resolveArchitecture(self) -> None:
        """For raw binary, the target is used directly."""
        self.archid = self.getTarget()
        super().resolveArchitecture()

    def postSpecFile(self) -> None:
        """Attach the default code space to the loader after spec loading."""
        if hasattr(super(), 'postSpecFile'):
            super().postSpecFile()
        if self.loader is not None and hasattr(self.loader, 'attachToSpace'):
            spc = self.getDefaultCodeSpace()
            if spc is not None:
                self.loader.attachToSpace(spc)

    def encode(self, encoder) -> None:
        """Encode the raw architecture state."""
        if hasattr(encoder, 'openElement'):
            encoder.openElement("raw_savefile")
        if hasattr(self, 'encodeHeader'):
            self.encodeHeader(encoder)
        if hasattr(encoder, 'writeUnsignedInteger'):
            encoder.writeUnsignedInteger("adjustvma", self.adjustvma)
        if self.types is not None and hasattr(self.types, 'encodeCoreTypes'):
            self.types.encodeCoreTypes(encoder)
        super().encode(encoder)
        if hasattr(encoder, 'closeElement'):
            encoder.closeElement("raw_savefile")

    def restoreXml(self, store=None) -> None:
        """Restore raw architecture from XML store."""
        if store is None:
            return
        el = None
        if hasattr(store, 'getTag'):
            el = store.getTag("raw_savefile")
        if el is None:
            raise LowlevelError("Could not find raw_savefile tag")
        if hasattr(self, 'restoreXmlHeader'):
            self.restoreXmlHeader(el)
        adj = el.get("adjustvma", "0") if hasattr(el, 'get') else "0"
        try:
            self.adjustvma = int(adj, 0)
        except (ValueError, TypeError):
            self.adjustvma = 0
