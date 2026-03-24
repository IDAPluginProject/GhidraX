"""Lightweight XML parser and DOM model for marshaling data to and from the decompiler.

This module mirrors the C++ xml.hh/xml.cc, providing:
- Attributes: XML element attributes container
- ContentHandler: SAX interface (abstract base class)
- Element: DOM node
- Document: Document (extends Element)
- TreeHandler: SAX handler that builds a DOM tree
- DocumentStorage: Container for parsed XML documents
- DecoderError: Exception class
- Free functions: xml_parse, xml_tree, xml_escape, a_v, a_v_i, a_v_u, a_v_b, xml_readbool
"""

from __future__ import annotations

from abc import ABC, abstractmethod
from typing import List, Optional, Dict
from xml.sax import parseString
from xml.sax.handler import ContentHandler as SaxContentHandler


# =========================================================================
# DecoderError
# =========================================================================

class DecoderError(Exception):
    """An exception thrown by the XML parser."""

    def __init__(self, s: str = "") -> None:
        super().__init__(s)
        self.explain: str = s


# =========================================================================
# Attributes
# =========================================================================

class Attributes:
    """The attributes for a single XML element.

    A container for name/value pairs (of strings) for the formal attributes,
    as collected during parsing. Also holds the element name and a placeholder
    namespace URI.
    """

    bogus_uri: str = "http://unused.uri"

    def __init__(self, elementname: str) -> None:
        self._elementname: str = elementname
        self._name: List[str] = []
        self._value: List[str] = []

    def getelemURI(self) -> str:
        return Attributes.bogus_uri

    def getelemName(self) -> str:
        return self._elementname

    def add_attribute(self, nm: str, vl: str) -> None:
        self._name.append(nm)
        self._value.append(vl)

    def getLength(self) -> int:
        return len(self._name)

    def getURI(self, i: int) -> str:  # noqa: ARG002
        return Attributes.bogus_uri

    def getLocalName(self, i: int) -> str:
        return self._name[i]

    def getQName(self, i: int) -> str:
        return self._name[i]

    def getValue(self, i_or_name) -> str:
        """Get the value of the i-th attribute or by qualified name."""
        if isinstance(i_or_name, int):
            return self._value[i_or_name]
        for idx, nm in enumerate(self._name):
            if nm == i_or_name:
                return self._value[idx]
        return Attributes.bogus_uri


# =========================================================================
# ContentHandler
# =========================================================================

class ContentHandler(ABC):
    """The SAX interface for parsing XML documents.

    This is the formal interface for handling the low-level string pieces of
    an XML document as they are scanned by the parser.
    """

    @abstractmethod
    def setDocumentLocator(self, locator) -> None:
        pass

    @abstractmethod
    def startDocument(self) -> None:
        pass

    @abstractmethod
    def endDocument(self) -> None:
        pass

    @abstractmethod
    def startPrefixMapping(self, prefix: str, uri: str) -> None:
        pass

    @abstractmethod
    def endPrefixMapping(self, prefix: str) -> None:
        pass

    @abstractmethod
    def startElement(self, namespaceURI: str, localName: str,
                     qualifiedName: str, atts: Attributes) -> None:
        pass

    @abstractmethod
    def endElement(self, namespaceURI: str, localName: str,
                   qualifiedName: str) -> None:
        pass

    @abstractmethod
    def characters(self, text: str, start: int, length: int) -> None:
        pass

    @abstractmethod
    def ignorableWhitespace(self, text: str, start: int, length: int) -> None:
        pass

    @abstractmethod
    def setVersion(self, version: str) -> None:
        pass

    @abstractmethod
    def setEncoding(self, encoding: str) -> None:
        pass

    @abstractmethod
    def processingInstruction(self, target: str, data: str) -> None:
        pass

    @abstractmethod
    def skippedEntity(self, name: str) -> None:
        pass

    @abstractmethod
    def setError(self, errmsg: str) -> None:
        pass


# =========================================================================
# Element
# =========================================================================

class Element:
    """An XML element. A node in the DOM tree."""

    def __init__(self, par: Optional[Element] = None) -> None:
        self._name: str = ""
        self._content: str = ""
        self._attr: List[str] = []
        self._value: List[str] = []
        self._parent: Optional[Element] = par
        self._children: List[Element] = []

    def setName(self, nm: str) -> None:
        self._name = nm

    def addContent(self, text: str, start: int = 0, length: int = -1) -> None:
        if length < 0:
            self._content += text[start:]
        else:
            self._content += text[start:start + length]

    def addChild(self, child: Element) -> None:
        self._children.append(child)

    def addAttribute(self, nm: str, vl: str) -> None:
        self._attr.append(nm)
        self._value.append(vl)

    def getParent(self) -> Optional[Element]:
        return self._parent

    def getName(self) -> str:
        return self._name

    def getChildren(self) -> List[Element]:
        return self._children

    def getContent(self) -> str:
        return self._content

    def getAttributeValue(self, nm_or_i) -> str:
        """Get an attribute value by name or index.

        Throws DecoderError if attribute name is not found.
        """
        if isinstance(nm_or_i, int):
            return self._value[nm_or_i]
        for idx, a in enumerate(self._attr):
            if a == nm_or_i:
                return self._value[idx]
        raise DecoderError("Unknown attribute: " + str(nm_or_i))

    def getNumAttributes(self) -> int:
        return len(self._attr)

    def getAttributeName(self, i: int) -> str:
        return self._attr[i]


# =========================================================================
# Document
# =========================================================================

class Document(Element):
    """A complete in-memory XML document.

    This is actually just an Element object itself, with the document's root
    element as its only child.
    """

    def __init__(self) -> None:
        super().__init__(None)

    def getRoot(self) -> Element:
        if self._children:
            return self._children[0]
        raise DecoderError("Document has no root element")


# =========================================================================
# TreeHandler
# =========================================================================

class TreeHandler(ContentHandler):
    """A SAX interface implementation for constructing an in-memory DOM model.

    This implementation builds a DOM model of the XML stream being parsed,
    creating an Element object for each XML element tag in the stream.
    """

    def __init__(self, rt: Element) -> None:
        self._root: Element = rt
        self._cur: Element = rt
        self._error: str = ""

    def setDocumentLocator(self, locator) -> None:
        pass

    def startDocument(self) -> None:
        pass

    def endDocument(self) -> None:
        pass

    def startPrefixMapping(self, prefix: str, uri: str) -> None:
        pass

    def endPrefixMapping(self, prefix: str) -> None:
        pass

    def startElement(self, namespaceURI: str, localName: str,
                     qualifiedName: str, atts: Attributes) -> None:
        newel = Element(self._cur)
        self._cur.addChild(newel)
        self._cur = newel
        newel.setName(localName)
        for i in range(atts.getLength()):
            newel.addAttribute(atts.getLocalName(i), atts.getValue(i))

    def endElement(self, namespaceURI: str, localName: str,
                   qualifiedName: str) -> None:
        self._cur = self._cur.getParent()

    def characters(self, text: str, start: int, length: int) -> None:
        self._cur.addContent(text, start, length)

    def ignorableWhitespace(self, text: str, start: int, length: int) -> None:
        pass

    def setVersion(self, version: str) -> None:
        pass

    def setEncoding(self, encoding: str) -> None:
        pass

    def processingInstruction(self, target: str, data: str) -> None:
        pass

    def skippedEntity(self, name: str) -> None:
        pass

    def setError(self, errmsg: str) -> None:
        self._error = errmsg

    def getError(self) -> str:
        return self._error


# =========================================================================
# DocumentStorage
# =========================================================================

class DocumentStorage:
    """A container for parsed XML documents.

    This holds multiple XML documents that have already been parsed. Documents
    can be put in this container via parseDocument() or openDocument().
    Specific XML Elements can be looked up by name via getTag().
    """

    def __init__(self) -> None:
        self._doclist: List[Document] = []
        self._tagmap: Dict[str, Element] = {}

    def parseDocument(self, s) -> Document:
        """Parse an XML document from the given stream or string.

        Uses Python's built-in XML parser to build the DOM tree.
        """
        if isinstance(s, str):
            data = s
        elif isinstance(s, bytes):
            data = s
        else:
            data = s.read()
        doc = xml_tree_from_string(data)
        self._doclist.append(doc)
        return doc

    def openDocument(self, filename: str) -> Document:
        """Open and parse an XML file."""
        try:
            with open(filename, 'r', encoding='utf-8') as f:
                data = f.read()
        except IOError as exc:
            raise DecoderError("Unable to open xml document " + filename) from exc
        return self.parseDocument(data)

    def registerTag(self, el: Element) -> None:
        """Register the given XML Element under its tag name."""
        self._tagmap[el.getName()] = el

    def getTag(self, nm: str) -> Optional[Element]:
        """Retrieve a registered XML Element by name."""
        return self._tagmap.get(nm, None)


# =========================================================================
# SAX Adapter: bridges Python's xml.sax to our ContentHandler/TreeHandler
# =========================================================================

class _SaxAdapter(SaxContentHandler):
    """Internal adapter that bridges Python's xml.sax to our TreeHandler."""

    def __init__(self, handler: ContentHandler) -> None:
        super().__init__()
        self._handler = handler

    def startDocument(self):
        self._handler.startDocument()

    def endDocument(self):
        self._handler.endDocument()

    def startElement(self, name, attrs):
        atts = Attributes(name)
        for aname in attrs.getNames():
            atts.add_attribute(aname, attrs.getValue(aname))
        self._handler.startElement("", name, name, atts)

    def endElement(self, name):
        self._handler.endElement("", name, name)

    def characters(self, content):
        self._handler.characters(content, 0, len(content))

    def ignorableWhitespace(self, whitespace):
        self._handler.ignorableWhitespace(whitespace, 0, len(whitespace))

    def processingInstruction(self, target, data):
        self._handler.processingInstruction(target, data)

    def skippedEntity(self, name):
        self._handler.skippedEntity(name)


# =========================================================================
# Free functions
# =========================================================================

def xml_parse(data, hand: ContentHandler, dbg: int = 0) -> int:
    """Start-up the XML parser given input data and a handler.

    Uses Python's built-in SAX parser instead of the C++ Bison parser.
    Returns 0 on success, non-zero on error.
    """
    adapter = _SaxAdapter(hand)
    try:
        if isinstance(data, str):
            raw = data.encode('utf-8')
        elif isinstance(data, bytes):
            raw = data
        else:
            raw = data.read()
            if isinstance(raw, str):
                raw = raw.encode('utf-8')
        parseString(raw, adapter)
        return 0
    except (Exception,) as e:  # noqa: BLE001
        hand.setError(str(e))
        return 1


def xml_tree(data) -> Document:
    """Parse the given XML data into an in-memory document.

    Accepts a string, bytes, or file-like object.
    Returns the in-memory XML document.
    """
    return xml_tree_from_string(data)


def xml_tree_from_string(data) -> Document:
    """Parse XML data (string, bytes, or stream) into a Document."""
    doc = Document()
    hand = TreeHandler(doc)
    res = xml_parse(data, hand)
    if res != 0:
        raise DecoderError(hand.getError())
    return doc


def xml_escape(s: str) -> str:
    """Escape characters with special XML meaning.

    Makes the following substitutions:
      '<'  => "&lt;"
      '>'  => "&gt;"
      '&'  => "&amp;"
      '"'  => "&quot;"
      "'"  => "&apos;"
    """
    result = []
    for ch in s:
        if ch == '<':
            result.append("&lt;")
        elif ch == '>':
            result.append("&gt;")
        elif ch == '&':
            result.append("&amp;")
        elif ch == '"':
            result.append("&quot;")
        elif ch == "'":
            result.append("&apos;")
        else:
            result.append(ch)
    return "".join(result)


def a_v(attr: str, val: str) -> str:
    """Output an XML attribute name/value pair as a string."""
    return f' {attr}="{xml_escape(val)}"'


def a_v_i(attr: str, val: int) -> str:
    """Output the given signed integer as an XML attribute value."""
    return f' {attr}="{val}"'


def a_v_u(attr: str, val: int) -> str:
    """Output the given unsigned integer as an XML attribute value (hex)."""
    return f' {attr}="0x{val:x}"'


def a_v_b(attr: str, val: bool) -> str:
    """Output the given boolean value as an XML attribute."""
    return f' {attr}="{"true" if val else "false"}"'


def xml_readbool(attr: str) -> bool:
    """Read an XML attribute value as a boolean.

    Recognizes "true", "yes", and "1" as True. Anything else is False.
    """
    if not attr:
        return False
    firstc = attr[0]
    if firstc == 't':
        return True
    if firstc == '1':
        return True
    if firstc == 'y':
        return True
    return False
