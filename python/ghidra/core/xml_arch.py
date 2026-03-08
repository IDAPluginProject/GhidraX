"""Extension to read executables based on an XML format.

This module mirrors the C++ xml_arch.hh/xml_arch.cc, providing:
- XmlArchitectureCapability: Extension for building an XML format capable Architecture
- XmlArchitecture: An Architecture that loads executables using an XML format
"""

from __future__ import annotations

from typing import Optional

from ghidra.core.xml import Document, DocumentStorage, DecoderError
from ghidra.core.marshal import ElementId


ELEM_XML_SAVEFILE = ElementId("xml_savefile", 236)


# =========================================================================
# XmlArchitectureCapability
# =========================================================================

class XmlArchitectureCapability:
    """Extension for building an XML format capable Architecture.

    This is a singleton capability that registers itself and can detect
    XML-based executable files.
    """

    _instance: Optional[XmlArchitectureCapability] = None

    def __init__(self) -> None:
        self.name: str = "xml"

    @classmethod
    def get_instance(cls) -> XmlArchitectureCapability:
        if cls._instance is None:
            cls._instance = XmlArchitectureCapability()
        return cls._instance

    def buildArchitecture(self, filename: str, target: str, estream=None):
        """Build an XmlArchitecture from the given filename and target."""
        return XmlArchitecture(filename, target, estream)

    def isFileMatch(self, filename: str) -> bool:
        """Check if the given file is an XML-based executable.

        Looks for a leading '<bi' which likely indicates a <binaryimage> tag.
        """
        try:
            with open(filename, 'r', encoding='utf-8') as f:
                data = f.read(64).lstrip()
                if len(data) >= 3 and data[0] == '<' and data[1] == 'b' and data[2] == 'i':
                    return True
        except (IOError, OSError):
            return False
        return False

    def isXmlMatch(self, doc: Document) -> bool:
        """Check if an already-parsed Document is an xml_savefile."""
        try:
            return doc.getRoot().getName() == "xml_savefile"
        except DecoderError:
            return False


# =========================================================================
# XmlArchitecture
# =========================================================================

class XmlArchitecture:
    """An Architecture that loads executables using an XML format.

    This wraps the SleighArchitecture base with XML-specific loading.
    """

    def __init__(self, fname: str, targ: str, estream=None) -> None:
        self._filename: str = fname
        self._target: str = targ
        self._estream = estream
        self._adjustvma: int = 0
        self._loader = None
        self._types = None
        self._translate = None

    def getFilename(self) -> str:
        return self._filename

    def buildLoader(self, store: DocumentStorage) -> None:
        """Build the loader from a DocumentStorage containing binaryimage."""
        el = store.getTag("binaryimage")
        if el is None:
            doc = store.openDocument(self._filename)
            store.registerTag(doc.getRoot())
            el = store.getTag("binaryimage")
        if el is None:
            raise DecoderError("Could not find binaryimage tag")
        # In a full implementation, this would create a LoadImageXml
        # self._loader = LoadImageXml(self._filename, el)

    def postSpecFile(self) -> None:
        """Read in image information (which uses translator)."""
        # In a full implementation:
        # super().postSpecFile()
        # self._loader.open(self._translate)
        # if self._adjustvma != 0:
        #     self._loader.adjustVma(self._adjustvma)
        pass

    def encode(self, encoder) -> None:
        """Prepend extra stuff to specify binary file and spec."""
        encoder.openElement(ELEM_XML_SAVEFILE)
        if hasattr(self, 'encodeHeader'):
            self.encodeHeader(encoder)
        encoder.writeUnsignedInteger('adjustvma', self._adjustvma)
        if self._loader is not None and hasattr(self._loader, 'encode'):
            self._loader.encode(encoder)
        if self._types is not None and hasattr(self._types, 'encodeCoreTypes'):
            self._types.encodeCoreTypes(encoder)
        encoder.closeElement(ELEM_XML_SAVEFILE)

    def restoreXml(self, store: DocumentStorage) -> None:
        """Restore the architecture from an xml_savefile document."""
        el = store.getTag("xml_savefile")
        if el is None:
            raise DecoderError("Could not find xml_savefile tag")

        if hasattr(self, 'restoreXmlHeader'):
            self.restoreXmlHeader(el)

        # Parse adjustvma attribute
        try:
            vma_str = el.getAttributeValue("adjustvma")
            self._adjustvma = int(vma_str, 0)
        except (DecoderError, ValueError):
            self._adjustvma = 0

        children = el.getChildren()
        idx = 0

        if idx < len(children) and children[idx].getName() == "binaryimage":
            store.registerTag(children[idx])
            idx += 1

        if idx < len(children) and children[idx].getName() == "specextensions":
            store.registerTag(children[idx])
            idx += 1

        if idx < len(children) and children[idx].getName() == "coretypes":
            store.registerTag(children[idx])
            idx += 1

        # In a full implementation: self.init(store)

        if idx < len(children):
            store.registerTag(children[idx])
            # In a full implementation: SleighArchitecture.restoreXml(store)


# Register the singleton
XmlArchitectureCapability.get_instance()
