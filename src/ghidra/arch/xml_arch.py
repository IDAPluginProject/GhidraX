"""
Corresponds to: xml_arch.hh / xml_arch.cc

Extension to read executables based on an XML format.
Provides XmlArchitecture and XmlArchitectureCapability.
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
# XmlArchitectureCapability
# =========================================================================

class XmlArchitectureCapability(ArchitectureCapability):
    """Extension for building an XML format capable Architecture."""

    def __init__(self) -> None:
        super().__init__()
        self.name = "xml"

    def buildArchitecture(self, filename: str, target: str,
                          estream: Optional[io.StringIO] = None):
        return XmlArchitecture(filename, target, estream)

    def isFileMatch(self, filename: str) -> bool:
        """Check if file starts with '<bi' (likely <binaryimage>)."""
        if not os.path.isfile(filename):
            return False
        try:
            with open(filename, "r", encoding="utf-8", errors="ignore") as f:
                header = f.read(10).lstrip()
                return header.startswith("<bi")
        except OSError:
            return False

    def isXmlMatch(self, doc) -> bool:
        if doc is None:
            return False
        if hasattr(doc, 'tag'):
            return doc.tag == "xml_savefile"
        return False


# =========================================================================
# XmlArchitecture
# =========================================================================

class XmlArchitecture(SleighArchitecture):
    """An Architecture that loads executables using an XML format.

    The XML file contains a <binaryimage> element with hex-encoded byte
    chunks and optional symbol information.
    """

    def __init__(self, fname: str = "", targ: str = "",
                 estream: Optional[io.StringIO] = None) -> None:
        super().__init__(fname, targ, estream)
        self.adjustvma: int = 0

    def buildLoader(self, store=None) -> None:
        """Build a LoadImageXml from the stored XML document."""
        from ghidra.arch.loadimage_xml import LoadImageXml

        self.collectSpecFiles(self.errorstream)

        el = None
        if store is not None and hasattr(store, 'getTag'):
            el = store.getTag("binaryimage")

        if el is None:
            # Try to open the file directly and parse
            import xml.etree.ElementTree as ET
            try:
                tree = ET.parse(self.getFilename())
                root = tree.getroot()
                if root.tag == "binaryimage":
                    el = root
                elif store is not None and hasattr(store, 'registerTag'):
                    store.registerTag(root)
                    el = store.getTag("binaryimage") if hasattr(store, 'getTag') else root
            except (ET.ParseError, OSError) as e:
                raise LowlevelError(
                    f"Could not parse XML file: {self.getFilename()}: {e}") from e

        if el is None:
            raise LowlevelError("Could not find binaryimage tag")

        ldr = LoadImageXml(self.getFilename())
        # Parse chunks from the XML element
        if hasattr(el, '__iter__'):
            self._parseImageXml(ldr, el)
        self.loader = ldr

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
        """Open the image data using the translator."""
        if hasattr(super(), 'postSpecFile'):
            super().postSpecFile()
        if self.loader is not None and hasattr(self.loader, 'open'):
            if self.translate is not None:
                self.loader.open(self.translate)
        if self.adjustvma != 0 and self.loader is not None:
            self.loader.adjustVma(self.adjustvma)

    def encode(self, encoder) -> None:
        """Encode the XML architecture state."""
        if hasattr(encoder, 'openElement'):
            encoder.openElement("xml_savefile")
        if hasattr(self, 'encodeHeader'):
            self.encodeHeader(encoder)
        if hasattr(encoder, 'writeUnsignedInteger'):
            encoder.writeUnsignedInteger("adjustvma", self.adjustvma)
        if self.loader is not None and hasattr(self.loader, 'encode'):
            self.loader.encode(encoder)
        if self.types is not None and hasattr(self.types, 'encodeCoreTypes'):
            self.types.encodeCoreTypes(encoder)
        super().encode(encoder)
        if hasattr(encoder, 'closeElement'):
            encoder.closeElement("xml_savefile")

    def restoreXml(self, store=None) -> None:
        """Restore XML architecture from store."""
        if store is None:
            return
        el = None
        if hasattr(store, 'getTag'):
            el = store.getTag("xml_savefile")
        if el is None:
            raise LowlevelError("Could not find xml_savefile tag")
        if hasattr(self, 'restoreXmlHeader'):
            self.restoreXmlHeader(el)
        adj = el.get("adjustvma", "0") if hasattr(el, 'get') else "0"
        try:
            self.adjustvma = int(adj, 0)
        except (ValueError, TypeError):
            self.adjustvma = 0
