"""
Corresponds to: xml_arch.hh / xml_arch.cc

Extension to read executables based on an XML format.
Provides XmlArchitecture and XmlArchitectureCapability.
"""

from __future__ import annotations

import io
import os
from typing import Optional, TYPE_CHECKING

from ghidra.arch.architecture import Architecture, ArchitectureCapability
from ghidra.arch.sleigh_arch import SleighArchitecture
from ghidra.core.error import LowlevelError
from ghidra.core.marshal import (
    AttributeId,
    ELEM_BINARYIMAGE,
    ELEM_CORETYPES,
    ELEM_SPECEXTENSIONS,
    ElementId,
)

if TYPE_CHECKING:
    pass


ELEM_XML_SAVEFILE = ElementId("xml_savefile", 236)
ATTRIB_ADJUSTVMA = AttributeId("adjustvma", 103)


# =========================================================================
# XmlArchitectureCapability
# =========================================================================

class XmlArchitectureCapability(ArchitectureCapability):
    """Extension for building an XML format capable Architecture."""

    def __init__(self) -> None:
        super().__init__()
        self.name = "xml"

    def __copy__(self):
        raise TypeError("XmlArchitectureCapability is non-copyable")

    def __deepcopy__(self, memo):
        raise TypeError("XmlArchitectureCapability is non-copyable")

    def __del__(self) -> None:
        SleighArchitecture.shutdown()

    def buildArchitecture(self, filename: str, target: str,
                          estream: Optional[io.StringIO] = None):
        return XmlArchitecture(filename, target, estream)

    def isFileMatch(self, filename: str) -> bool:
        if not os.path.isfile(filename):
            return False
        try:
            with open(filename, "r", encoding="utf-8", errors="ignore") as f:
                while True:
                    ch = f.read(1)
                    if ch == "":
                        return False
                    if not ch.isspace():
                        break
                return ch == "<" and f.read(1) == "b" and f.read(1) == "i"
        except OSError:
            return False

    def isXmlMatch(self, doc) -> bool:
        return doc.getRoot().getName() == ELEM_XML_SAVEFILE.getName()


# =========================================================================
# XmlArchitecture
# =========================================================================

class XmlArchitecture(SleighArchitecture):
    """An Architecture that loads executables using an XML format.

    The XML file contains a <binaryimage> element with hex-encoded byte
    chunks and optional symbol information.
    """

    def __init__(self, fname: str, targ: str,
                 estream: Optional[io.StringIO] = None) -> None:
        super().__init__(fname, targ, estream)
        self.adjustvma: int = 0

    def buildLoader(self, store) -> None:
        from ghidra.arch.loadimage_xml import LoadImageXml

        self.collectSpecFiles(self.errorstream)

        el = store.getTag(ELEM_BINARYIMAGE.getName())
        if el is None:
            doc = store.openDocument(self.getFilename())
            store.registerTag(doc.getRoot())
            el = store.getTag(ELEM_BINARYIMAGE.getName())

        if el is None:
            raise LowlevelError("Could not find binaryimage tag")

        self.loader = LoadImageXml(self.getFilename(), el)

    @staticmethod
    def _parseImageXml(ldr, el) -> None:
        """Parse a <binaryimage> XML element and populate the LoadImageXml."""
        from ghidra.core.address import Address

        for child in el:
            tag = child.tag
            if tag == "bytechunk":
                # Extract hex content
                space_name = child.get("space", "ram")
                offset = int(child.get("offset", "0"), 0)
                readonly = child.get("readonly", "false").lower() == "true"
                content = child.get("content", "")
                if not content:
                    content = (child.text or "").strip()
                cleaned = content.replace("\n", "").replace(" ", "")
                if cleaned:
                    data = bytes.fromhex(cleaned)
                    # Create a minimal address (space is just a name placeholder)
                    addr = Address(space_name, offset) if isinstance(space_name, str) else Address(space_name, offset)
                    ldr.addChunk(addr, data, readonly)
            elif tag == "symbol":
                space_name = child.get("space", "ram")
                offset = int(child.get("offset", "0"), 0)
                name = child.get("name", "")
                if name:
                    addr = Address(space_name, offset) if isinstance(space_name, str) else Address(space_name, offset)
                    ldr.addSymbol(addr, name)

    def postSpecFile(self) -> None:
        Architecture.postSpecFile(self)
        self.loader.open(self.translate)
        if self.adjustvma != 0:
            self.loader.adjustVma(self.adjustvma)

    def encode(self, encoder) -> None:
        encoder.openElement(ELEM_XML_SAVEFILE)
        self.encodeHeader(encoder)
        encoder.writeUnsignedInteger(ATTRIB_ADJUSTVMA, self.adjustvma)
        self.loader.encode(encoder)
        self.types.encodeCoreTypes(encoder)
        SleighArchitecture.encode(self, encoder)
        encoder.closeElement(ELEM_XML_SAVEFILE)

    def restoreXml(self, store) -> None:
        el = store.getTag(ELEM_XML_SAVEFILE.getName())
        if el is None:
            raise LowlevelError("Could not find xml_savefile tag")
        self.restoreXmlHeader(el)
        self.adjustvma = int(el.getAttributeValue(ATTRIB_ADJUSTVMA.getName()), 0)
        children = el.getChildren()
        idx = 0
        if idx < len(children) and children[idx].getName() == ELEM_BINARYIMAGE.getName():
            store.registerTag(children[idx])
            idx += 1
        if idx < len(children) and children[idx].getName() == ELEM_SPECEXTENSIONS.getName():
            store.registerTag(children[idx])
            idx += 1
        if idx < len(children) and children[idx].getName() == ELEM_CORETYPES.getName():
            store.registerTag(children[idx])
            idx += 1
        self.init(store)
        if idx < len(children):
            store.registerTag(children[idx])
            SleighArchitecture.restoreXml(self, store)
