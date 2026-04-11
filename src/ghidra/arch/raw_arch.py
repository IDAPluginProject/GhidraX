"""
Corresponds to: raw_arch.hh / raw_arch.cc

Bare bones capability for treating a file as a raw executable image.
Provides RawBinaryArchitecture and RawBinaryArchitectureCapability.
"""

from __future__ import annotations

import io
import os
from typing import Optional, TYPE_CHECKING

from ghidra.arch.loadimage import DataUnavailError, LoadImage
from ghidra.core.error import LowlevelError
from ghidra.core.marshal import AttributeId, ElementId
from ghidra.core.space import AddrSpace
from ghidra.arch.sleigh_arch import SleighArchitecture
from ghidra.arch.architecture import ArchitectureCapability

if TYPE_CHECKING:
    pass


ELEM_RAW_SAVEFILE = ElementId("raw_savefile", 237)
ATTRIB_ADJUSTVMA = AttributeId("adjustvma", 103)


# =========================================================================
# RawLoadImage  (minimal — just enough to open a raw binary file)
# =========================================================================

class RawLoadImage(LoadImage):
    """Raw-binary load image matching `loadimage.hh`.

    Mirrors the native `RawLoadImage` constructor/open/loadFill semantics.
    """

    def __init__(self, filename: str) -> None:
        super().__init__(filename)
        self.vma: int = 0
        self.thefile = None
        self.filesize: int = 0
        self.spaceid = None

    def open(self) -> None:
        """Open the raw image file and cache its size."""
        if self.thefile is not None:
            raise LowlevelError("loadimage is already open")
        try:
            self.thefile = open(self.getFileName(), "rb")
        except OSError as exc:
            raise LowlevelError("Unable to open raw image file: " + self.getFileName()) from exc
        self.thefile.seek(0, io.SEEK_END)
        self.filesize = self.thefile.tell()

    def adjustVma(self, adjust: int) -> None:
        self.vma += AddrSpace.addressToByte(adjust, self.spaceid.getWordSize())

    def attachToSpace(self, spc) -> None:
        self.spaceid = spc

    def getArchType(self) -> str:
        return "unknown"

    def loadFill(self, buf: bytearray, size: int, addr) -> None:
        curaddr = addr.getOffset() - self.vma
        offset = 0
        remaining = size
        while remaining > 0:
            if curaddr >= self.filesize:
                if offset == 0:
                    break
                for i in range(offset, offset + remaining):
                    buf[i] = 0
                return
            readsize = remaining
            if curaddr + readsize > self.filesize:
                readsize = self.filesize - curaddr
            self.thefile.seek(curaddr)
            chunk = self.thefile.read(readsize)
            buf[offset:offset + readsize] = chunk
            offset += readsize
            remaining -= readsize
            curaddr += readsize
        if remaining > 0:
            raise DataUnavailError(f"Unable to load {remaining} bytes at {addr.printRaw()}")

    def __del__(self) -> None:
        if self.thefile is not None:
            self.thefile.close()
            self.thefile = None


# =========================================================================
# RawBinaryArchitectureCapability
# =========================================================================

class RawBinaryArchitectureCapability(ArchitectureCapability):
    """Extension point for building an Architecture that reads raw images."""

    def __init__(self) -> None:
        super().__init__()
        self.name = "raw"

    def __copy__(self):
        raise TypeError("RawBinaryArchitectureCapability is non-copyable")

    def __deepcopy__(self, memo):
        raise TypeError("RawBinaryArchitectureCapability is non-copyable")

    def __del__(self) -> None:
        SleighArchitecture.shutdown()

    def buildArchitecture(self, filename: str, target: str,
                          estream: Optional[io.StringIO] = None):
        return RawBinaryArchitecture(filename, target, estream)

    def isFileMatch(self, filename: str) -> bool:
        # Raw binary can always match as a fallback
        return True

    def isXmlMatch(self, doc) -> bool:
        return doc.getRoot().getName() == "raw_savefile"


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

    def buildLoader(self, store) -> None:
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
        super().postSpecFile()
        self.loader.attachToSpace(self.getDefaultCodeSpace())

    def encode(self, encoder) -> None:
        """Encode the raw architecture state."""
        encoder.openElement(ELEM_RAW_SAVEFILE)
        self.encodeHeader(encoder)
        encoder.writeUnsignedInteger(ATTRIB_ADJUSTVMA, self.adjustvma)
        self.types.encodeCoreTypes(encoder)
        super().encode(encoder)
        encoder.closeElement(ELEM_RAW_SAVEFILE)

    def restoreXml(self, store) -> None:
        """Restore raw architecture from XML store."""
        el = store.getTag("raw_savefile")
        if el is None:
            raise LowlevelError("Could not find raw_savefile tag")
        self.restoreXmlHeader(el)
        self.adjustvma = int(el.getAttributeValue("adjustvma"), 0)
        children = el.getChildren()
        idx = 0
        if idx < len(children) and children[idx].getName() == "coretypes":
            store.registerTag(children[idx])
            idx += 1
        self.init(store)
        if idx < len(children):
            store.registerTag(children[idx])
            super().restoreXml(store)
