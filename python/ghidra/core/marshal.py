"""
Corresponds to: marshal.hh / marshal.cc

Encoder/Decoder abstractions and AttributeId/ElementId labelling system.
Provides both XML-based and packed binary serialization formats.
"""

from __future__ import annotations

import io
from abc import ABC, abstractmethod
from typing import TYPE_CHECKING, Optional
from xml.etree.ElementTree import Element, parse as xml_parse, fromstring as xml_fromstring

from ghidra.core.opcodes import OpCode, get_opname, get_opcode

if TYPE_CHECKING:
    from ghidra.core.space import AddrSpace, AddrSpaceManager


# =========================================================================
# AttributeId
# =========================================================================

class AttributeId:
    """An annotation for a data element being transferred to/from a stream.

    Parallels the XML concept of an attribute on an element.
    """
    _lookup: dict[str, int] = {}
    _list: list[AttributeId] = []

    def __init__(self, name: str, id_: int, scope: int = 0) -> None:
        self.name: str = name
        self.id: int = id_
        AttributeId._lookup[name] = id_
        AttributeId._list.append(self)

    def getName(self) -> str:
        return self.name

    def getId(self) -> int:
        return self.id

    def __eq__(self, other: object) -> bool:
        if isinstance(other, AttributeId):
            return self.id == other.id
        if isinstance(other, int):
            return self.id == other
        return NotImplemented

    def __ne__(self, other: object) -> bool:
        result = self.__eq__(other)
        if result is NotImplemented:
            return result
        return not result

    def __hash__(self) -> int:
        return hash(self.id)

    def __repr__(self) -> str:
        return f"AttributeId({self.name!r}, {self.id})"

    @staticmethod
    def find(name: str, scope: int = 0) -> int:
        return AttributeId._lookup.get(name, 0)

    @staticmethod
    def initialize() -> None:
        pass  # All registrations happen at import-time in Python


# =========================================================================
# ElementId
# =========================================================================

class ElementId:
    """An annotation for a specific collection of hierarchical data.

    Parallels the XML concept of an element.
    """
    _lookup: dict[str, int] = {}
    _list: list[ElementId] = []

    def __init__(self, name: str, id_: int, scope: int = 0) -> None:
        self.name: str = name
        self.id: int = id_
        ElementId._lookup[name] = id_
        ElementId._list.append(self)

    def getName(self) -> str:
        return self.name

    def getId(self) -> int:
        return self.id

    def __eq__(self, other: object) -> bool:
        if isinstance(other, ElementId):
            return self.id == other.id
        if isinstance(other, int):
            return self.id == other
        return NotImplemented

    def __ne__(self, other: object) -> bool:
        result = self.__eq__(other)
        if result is NotImplemented:
            return result
        return not result

    def __hash__(self) -> int:
        return hash(self.id)

    def __repr__(self) -> str:
        return f"ElementId({self.name!r}, {self.id})"

    @staticmethod
    def find(name: str, scope: int = 0) -> int:
        return ElementId._lookup.get(name, 0)

    @staticmethod
    def initialize() -> None:
        pass


# =========================================================================
# Well-known AttributeIds and ElementIds (global singletons)
# These are defined across many C++ files; we centralise them here.
# =========================================================================

ATTRIB_UNKNOWN = AttributeId("unknown", 0)
ATTRIB_CONTENT = AttributeId("content", 1)
ATTRIB_ALIGN = AttributeId("align", 2)
ATTRIB_BIGENDIAN = AttributeId("bigendian", 3)
ATTRIB_CONSTRUCTOR = AttributeId("constructor", 4)
ATTRIB_DESTRUCTOR = AttributeId("destructor", 5)
ATTRIB_EXTRAPOP = AttributeId("extrapop", 6)
ATTRIB_FORMAT = AttributeId("format", 7)
ATTRIB_HIDDENRETPARM = AttributeId("hiddenretparm", 8)
ATTRIB_ID = AttributeId("id", 9)
ATTRIB_INDEX = AttributeId("index", 10)
ATTRIB_INDIRECTSTORAGE = AttributeId("indirectstorage", 11)
ATTRIB_METATYPE = AttributeId("metatype", 12)
ATTRIB_MODEL = AttributeId("model", 13)
ATTRIB_NAME = AttributeId("name", 14)
ATTRIB_NAMELOCK = AttributeId("namelock", 15)
ATTRIB_OFFSET = AttributeId("offset", 16)
ATTRIB_READONLY = AttributeId("readonly", 17)
ATTRIB_REF = AttributeId("ref", 18)
ATTRIB_SIZE = AttributeId("size", 19)
ATTRIB_SPACE = AttributeId("space", 20)
ATTRIB_THISPTR = AttributeId("thisptr", 21)
ATTRIB_TYPE = AttributeId("type", 22)
ATTRIB_TYPELOCK = AttributeId("typelock", 23)
ATTRIB_VAL = AttributeId("val", 24)
ATTRIB_VALUE = AttributeId("value", 25)
ATTRIB_WORDSIZE = AttributeId("wordsize", 26)

# From address.cc
ATTRIB_FIRST = AttributeId("first", 27)
ATTRIB_LAST = AttributeId("last", 28)
ATTRIB_UNIQ = AttributeId("uniq", 29)

# From varnode.cc
ATTRIB_ADDRTIED = AttributeId("addrtied", 30)
ATTRIB_GRP = AttributeId("grp", 31)
ATTRIB_INPUT = AttributeId("input", 32)
ATTRIB_PERSISTS = AttributeId("persists", 33)
ATTRIB_UNAFF = AttributeId("unaff", 34)

# From translate.cc
ATTRIB_CODE = AttributeId("code", 43)
ATTRIB_CONTAIN = AttributeId("contain", 44)
ATTRIB_DEFAULTSPACE = AttributeId("defaultspace", 45)
ATTRIB_UNIQBASE = AttributeId("uniqbase", 46)

# From space.cc
ATTRIB_BASE = AttributeId("base", 89)
ATTRIB_DEADCODEDELAY = AttributeId("deadcodedelay", 90)
ATTRIB_DELAY = AttributeId("delay", 91)
ATTRIB_LOGICALSIZE = AttributeId("logicalsize", 92)
ATTRIB_PHYSICAL = AttributeId("physical", 93)
ATTRIB_PIECE = AttributeId("piece", 94)

# Well-known ElementIds
ELEM_UNKNOWN = ElementId("unknown", 0)

# From address.cc
ELEM_ADDR = ElementId("addr", 11)
ELEM_RANGE = ElementId("range", 12)
ELEM_RANGELIST = ElementId("rangelist", 13)
ELEM_REGISTER = ElementId("register", 14)
ELEM_SEQNUM = ElementId("seqnum", 15)
ELEM_VARNODE = ElementId("varnode", 16)

# From translate.cc
ELEM_OP = ElementId("op", 27)
ELEM_SLEIGH = ElementId("sleigh", 28)
ELEM_SPACE = ElementId("space", 29)
ELEM_SPACEID = ElementId("spaceid", 30)
ELEM_SPACES = ElementId("spaces", 31)
ELEM_SPACE_BASE = ElementId("space_base", 32)
ELEM_SPACE_OTHER = ElementId("space_other", 33)
ELEM_SPACE_OVERLAY = ElementId("space_overlay", 34)
ELEM_SPACE_UNIQUE = ElementId("space_unique", 35)
ELEM_TRUNCATE_SPACE = ElementId("truncate_space", 36)

# From marshal.cc (common elements)
ELEM_DATA = ElementId("data", 1)
ELEM_INPUT = ElementId("input", 2)
ELEM_OFF = ElementId("off", 3)
ELEM_OUTPUT = ElementId("output", 4)
ELEM_RETURNADDRESS = ElementId("returnaddress", 5)
ELEM_SYMBOL = ElementId("symbol", 6)
ELEM_TARGET = ElementId("target", 7)
ELEM_VAL = ElementId("val", 8)
ELEM_VALUE = ElementId("value", 9)
ELEM_VOID = ElementId("void", 10)

# From database.cc
ATTRIB_CAT = AttributeId("cat", 61)
ATTRIB_FIELD = AttributeId("field", 62)
ATTRIB_MERGE = AttributeId("merge", 63)
ATTRIB_SCOPEIDBYNAME = AttributeId("scopeidbyname", 64)
ATTRIB_VOLATILE = AttributeId("volatile", 65)

# From variable.cc
ATTRIB_CLASS = AttributeId("class", 66)
ATTRIB_REPREF = AttributeId("repref", 67)
ATTRIB_SYMREF = AttributeId("symref", 68)

# From block.cc
ATTRIB_ALTINDEX = AttributeId("altindex", 75)
ATTRIB_DEPTH = AttributeId("depth", 76)
ATTRIB_END = AttributeId("end", 77)
ATTRIB_OPCODE = AttributeId("opcode", 78)
ATTRIB_REV = AttributeId("rev", 79)
ELEM_COLLISION = ElementId("collision", 67)
ELEM_DB = ElementId("db", 68)
ELEM_EQUATESYMBOL = ElementId("equatesymbol", 69)
ELEM_EXTERNREFSYMBOL = ElementId("externrefsymbol", 70)
ELEM_FACETSYMBOL = ElementId("facetsymbol", 71)
ELEM_FUNCTIONSHELL = ElementId("functionshell", 72)
ELEM_HASH = ElementId("hash", 73)
ELEM_HOLE = ElementId("hole", 74)
ELEM_LABELSYM = ElementId("labelsym", 75)
ELEM_MAPSYM = ElementId("mapsym", 76)
ELEM_PARENT = ElementId("parent", 77)
ELEM_PROPERTY_CHANGEPOINT = ElementId("property_changepoint", 78)
ELEM_RANGEEQUALSSYMBOLS = ElementId("rangeequalssymbols", 79)
ELEM_SCOPE = ElementId("scope", 80)
ELEM_SYMBOLLIST = ElementId("symbollist", 81)

# From variable.cc
ELEM_HIGH = ElementId("high", 82)

# From block.cc
ELEM_BHEAD = ElementId("bhead", 102)
ELEM_BLOCK = ElementId("block", 103)
ELEM_BLOCKEDGE = ElementId("blockedge", 104)
ELEM_EDGE = ElementId("edge", 105)

# From op.cc
ELEM_IOP = ElementId("iop", 113)
ELEM_UNIMPL = ElementId("unimpl", 114)

# From funcdata.cc
ATTRIB_NOCODE = AttributeId("nocode", 84)
ELEM_AST = ElementId("ast", 115)
ELEM_FUNCTION = ElementId("function", 116)
ELEM_HIGHLIST = ElementId("highlist", 117)
ELEM_JUMPTABLELIST = ElementId("jumptablelist", 118)
ELEM_VARNODES = ElementId("varnodes", 119)

# From fspec.cc
ELEM_PROTOTYPE = ElementId("prototype", 169)

# From comment.cc
ELEM_COMMENT = ElementId("comment", 86)
ELEM_COMMENTDB = ElementId("commentdb", 87)
ELEM_TEXT = ElementId("text", 88)

# From cpool.cc
ATTRIB_A = AttributeId("a", 80)
ATTRIB_B = AttributeId("b", 81)
ATTRIB_LENGTH = AttributeId("length", 82)
ATTRIB_TAG = AttributeId("tag", 83)
ELEM_CONSTANTPOOL = ElementId("constantpool", 109)
ELEM_CPOOLREC = ElementId("cpoolrec", 110)
ELEM_REF = ElementId("ref", 111)
ELEM_TOKEN = ElementId("token", 112)

# From globalcontext.cc
ELEM_CONTEXT_DATA = ElementId("context_data", 120)
ELEM_CONTEXT_POINTS = ElementId("context_points", 121)
ELEM_CONTEXT_POINTSET = ElementId("context_pointset", 122)
ELEM_CONTEXT_SET = ElementId("context_set", 123)
ELEM_SET = ElementId("set", 124)
ELEM_TRACKED_POINTSET = ElementId("tracked_pointset", 125)
ELEM_TRACKED_SET = ElementId("tracked_set", 126)

# From jumptable.cc
ATTRIB_LABEL = AttributeId("label", 131)
ATTRIB_NUM = AttributeId("num", 132)
ELEM_BASICOVERRIDE = ElementId("basicoverride", 211)
ELEM_DEST = ElementId("dest", 212)
ELEM_JUMPTABLE = ElementId("jumptable", 213)
ELEM_LOADTABLE = ElementId("loadtable", 214)
ELEM_NORMADDR = ElementId("normaddr", 215)
ELEM_NORMHASH = ElementId("normhash", 216)
ELEM_STARTVAL = ElementId("startval", 217)

# From prefersplit.cc
ELEM_PREFERSPLIT = ElementId("prefersplit", 225)

# From pcodeinject.cc
ELEM_INST = ElementId("inst", 98)

# From override.cc
ELEM_OVERRIDE = ElementId("override", 223)

# From varmap.cc
ELEM_LOCALDB = ElementId("localdb", 228)

# From architecture.cc
ATTRIB_REVERSEJUSTIFY = AttributeId("reversejustify", 111)
ELEM_RULE = ElementId("rule", 153)

# From fspec.cc
ATTRIB_MAXSIZE = AttributeId("maxsize", 120)
ATTRIB_MINSIZE = AttributeId("minsize", 121)
ATTRIB_POINTERMAX = AttributeId("pointermax", 124)
ATTRIB_THISBEFORERETPOINTER = AttributeId("thisbeforeretpointer", 200)
ATTRIB_SEPARATEFLOAT = AttributeId("separatefloat", 125)
ATTRIB_STACKSHIFT = AttributeId("stackshift", 126)
ATTRIB_STRATEGY = AttributeId("strategy", 127)
ATTRIB_VOIDLOCK = AttributeId("voidlock", 129)
ATTRIB_CUSTOM = AttributeId("custom", 114)
ATTRIB_DOTDOTDOT = AttributeId("dotdotdot", 115)
ATTRIB_EXTENSION = AttributeId("extension", 116)
ATTRIB_HASTHIS = AttributeId("hasthis", 117)
ATTRIB_INLINE = AttributeId("inline", 118)
ATTRIB_KILLEDBYCALL = AttributeId("killedbycall", 119)
ATTRIB_MODELLOCK = AttributeId("modellock", 122)
ATTRIB_NORETURN = AttributeId("noreturn", 123)
ELEM_GROUP = ElementId("group", 160)
ELEM_INTERNALLIST = ElementId("internallist", 161)
ELEM_PENTRY = ElementId("pentry", 162)
ELEM_RETURNSYM = ElementId("returnsym", 163)
ELEM_UNAFFECTED = ElementId("unaffected", 164)
ELEM_KILLEDBYCALL = ElementId("killedbycall", 165)
ELEM_RETPARAM = ElementId("retparam", 166)
ELEM_PARAM = ElementId("param", 167)
ELEM_LIKELYTRASH = ElementId("likelytrash", 168)
ELEM_INJECT = ElementId("inject", 170)
ELEM_INTERNAL_STORAGE = ElementId("internal_storage", 171)
ELEM_LOCALRANGE = ElementId("localrange", 172)
ELEM_PARAMRANGE = ElementId("paramrange", 173)
ELEM_PCODE = ElementId("pcode", 174)

# From marshal.cc (high-numbered)
ATTRIB_STORAGE = AttributeId("storage", 149)
ATTRIB_STACKSPILL = AttributeId("stackspill", 150)

# From modelrules.cc
ATTRIB_SIZES = AttributeId("sizes", 151)
ATTRIB_MAX_PRIMITIVES = AttributeId("maxprimitives", 153)
ATTRIB_REVERSESIGNIF = AttributeId("reversesignif", 154)
ATTRIB_MATCHSIZE = AttributeId("matchsize", 155)
ATTRIB_AFTER_BYTES = AttributeId("afterbytes", 156)
ATTRIB_AFTER_STORAGE = AttributeId("afterstorage", 157)
ATTRIB_FILL_ALTERNATE = AttributeId("fillalternate", 158)
ELEM_DATATYPE = ElementId("datatype", 273)
ELEM_CONSUME = ElementId("consume", 274)
ELEM_CONSUME_EXTRA = ElementId("consume_extra", 275)
ELEM_CONVERT_TO_PTR = ElementId("convert_to_ptr", 276)
ELEM_GOTO_STACK = ElementId("goto_stack", 277)
ELEM_JOIN = ElementId("join", 278)
ELEM_DATATYPE_AT = ElementId("datatype_at", 279)
ELEM_POSITION = ElementId("position", 280)
ELEM_VARARGS = ElementId("varargs", 281)
ELEM_HIDDEN_RETURN = ElementId("hidden_return", 282)
ELEM_JOIN_PER_PRIMITIVE = ElementId("join_per_primitive", 283)
ELEM_JOIN_DUAL_CLASS = ElementId("join_dual_class", 285)
ELEM_EXTRA_STACK = ElementId("extra_stack", 287)
ELEM_CONSUME_REMAINING = ElementId("consume_remaining", 288)

# from transform.cc
ATTRIB_VECTOR_LANE_SIZES = AttributeId("vector_lane_sizes", 130)

# from loadimage_xml.cc
ATTRIB_ARCH = AttributeId("arch", 135)
ELEM_BINARYIMAGE = ElementId("binaryimage", 230)
ELEM_BYTECHUNK = ElementId("bytechunk", 231)

# from fspec.cc (continued)
ELEM_RESOLVEPROTOTYPE = ElementId("resolveprototype", 289)
ELEM_MODEL = ElementId("model", 290)

# from stringmanage.cc
ELEM_STRINGMANAGE = ElementId("stringmanage", 291)
ELEM_STRING = ElementId("string", 292)
ELEM_BYTES = ElementId("bytes", 293)
ATTRIB_TRUNC = AttributeId("trunc", 201)

# from userop.cc
ATTRIB_INPUTOP = AttributeId("inputop", 86)
ATTRIB_OUTPUTOP = AttributeId("outputop", 87)
ATTRIB_USEROP = AttributeId("userop", 88)
ATTRIB_FARPOINTER = AttributeId("farpointer", 202)
ELEM_CONSTRESOLVE = ElementId("constresolve", 127)
ELEM_JUMPASSIST = ElementId("jumpassist", 128)
ELEM_SEGMENTOP = ElementId("segmentop", 129)

# from pcodeinject.cc
ATTRIB_PARAMSHIFT = AttributeId("paramshift", 73)
ATTRIB_TARGETOP = AttributeId("targetop", 74)
ELEM_ADDR_PCODE = ElementId("addr_pcode", 89)
ELEM_BODY = ElementId("body", 90)
ELEM_CALLFIXUP = ElementId("callfixup", 91)
ELEM_CALLOTHERFIXUP = ElementId("callotherfixup", 92)
ELEM_CASE_PCODE = ElementId("case_pcode", 93)
ELEM_CONTEXT = ElementId("context", 94)
ELEM_DEFAULT_PCODE = ElementId("default_pcode", 95)
ELEM_INJECT = ElementId("inject", 96)
ELEM_INJECTDEBUG = ElementId("injectdebug", 97)
ELEM_INST = ElementId("inst", 98)
ELEM_PAYLOAD = ElementId("payload", 99)
ELEM_PCODE = ElementId("pcode", 100)
ELEM_SIZE_PCODE = ElementId("size_pcode", 101)

# from paramid.cc
ELEM_PARAMMEASURES = ElementId("parammeasures", 106)
ELEM_PROTO = ElementId("proto", 107)
ELEM_RANK = ElementId("rank", 108)

# =========================================================================
# Decoder (abstract base)
# =========================================================================

class Decoder(ABC):
    """A class for reading structured data from a stream.

    All data is loosely structured as with an XML document.
    """

    def __init__(self, spc_manager: Optional[AddrSpaceManager] = None) -> None:
        self.spcManager: Optional[AddrSpaceManager] = spc_manager

    def getAddrSpaceManager(self) -> Optional[AddrSpaceManager]:
        return self.spcManager

    @abstractmethod
    def ingestStream(self, s: str) -> None: ...

    @abstractmethod
    def peekElement(self) -> int: ...

    @abstractmethod
    def openElement(self, elemId: Optional[ElementId] = None) -> int: ...

    @abstractmethod
    def closeElement(self, id_: int) -> None: ...

    @abstractmethod
    def closeElementSkipping(self, id_: int) -> None: ...

    @abstractmethod
    def getNextAttributeId(self) -> int: ...

    @abstractmethod
    def getIndexedAttributeId(self, attribId: AttributeId) -> int: ...

    @abstractmethod
    def rewindAttributes(self) -> None: ...

    @abstractmethod
    def readBool(self, attribId: Optional[AttributeId] = None) -> bool: ...

    @abstractmethod
    def readSignedInteger(self, attribId: Optional[AttributeId] = None) -> int: ...

    @abstractmethod
    def readSignedIntegerExpectString(self, expect_or_attribId, expect_str: Optional[str] = None,
                                       expectval: int = 0) -> int: ...

    @abstractmethod
    def readUnsignedInteger(self, attribId: Optional[AttributeId] = None) -> int: ...

    @abstractmethod
    def readString(self, attribId: Optional[AttributeId] = None) -> str: ...

    @abstractmethod
    def readSpace(self, attribId: Optional[AttributeId] = None) -> AddrSpace: ...

    @abstractmethod
    def readOpcode(self, attribId: Optional[AttributeId] = None) -> OpCode: ...

    def skipElement(self) -> None:
        elemId = self.openElement()
        self.closeElementSkipping(elemId)


# =========================================================================
# Encoder (abstract base)
# =========================================================================

class Encoder(ABC):
    """A class for writing structured data to a stream."""

    @abstractmethod
    def openElement(self, elemId: ElementId) -> None: ...

    @abstractmethod
    def closeElement(self, elemId: ElementId) -> None: ...

    @abstractmethod
    def writeBool(self, attribId: AttributeId, val: bool) -> None: ...

    @abstractmethod
    def writeSignedInteger(self, attribId: AttributeId, val: int) -> None: ...

    @abstractmethod
    def writeUnsignedInteger(self, attribId: AttributeId, val: int) -> None: ...

    @abstractmethod
    def writeString(self, attribId: AttributeId, val: str) -> None: ...

    @abstractmethod
    def writeStringIndexed(self, attribId: AttributeId, index: int, val: str) -> None: ...

    @abstractmethod
    def writeSpace(self, attribId: AttributeId, spc: AddrSpace) -> None: ...

    @abstractmethod
    def writeOpcode(self, attribId: AttributeId, opc: OpCode) -> None: ...


# =========================================================================
# XmlDecode – XML-based decoder using ElementTree
# =========================================================================

class XmlDecode(Decoder):
    """An XML-based decoder.

    The underlying transfer encoding is an XML document.
    """

    def __init__(self, spc_manager: Optional[AddrSpaceManager] = None,
                 root: Optional[Element] = None, scope: int = 0) -> None:
        super().__init__(spc_manager)
        self._root: Optional[Element] = root
        self._elStack: list[Element] = []
        self._iterStack: list[list[Element]] = []
        self._childIndexStack: list[int] = []
        self._attributeIndex: int = -1
        self._scope: int = scope
        self._attrKeys: list[str] = []

    def ingestStream(self, s: str) -> None:
        self._root = xml_fromstring(s)

    def _currentElement(self) -> Element:
        return self._elStack[-1]

    def _findMatchingAttribute(self, el: Element, attrib_name: str) -> int:
        keys = list(el.attrib.keys())
        for i, k in enumerate(keys):
            if k == attrib_name:
                return i
        return -1

    def peekElement(self) -> int:
        if not self._elStack:
            if self._root is not None:
                return ElementId.find(self._root.tag, self._scope)
            return 0
        parent = self._currentElement()
        children = list(parent)
        idx = self._childIndexStack[-1]
        if idx >= len(children):
            return 0
        child = children[idx]
        return ElementId.find(child.tag, self._scope)

    def openElement(self, elemId: Optional[ElementId] = None) -> int:
        if not self._elStack:
            el = self._root
        else:
            parent = self._currentElement()
            children = list(parent)
            idx = self._childIndexStack[-1]
            if idx >= len(children):
                from ghidra.core.error import DecoderError
                raise DecoderError("No more child elements")
            el = children[idx]
            self._childIndexStack[-1] = idx + 1

        self._elStack.append(el)
        self._childIndexStack.append(0)
        self._attributeIndex = -1
        self._attrKeys = list(el.attrib.keys())

        found_id = ElementId.find(el.tag, self._scope)
        if elemId is not None and found_id != elemId.id:
            from ghidra.core.error import DecoderError
            raise DecoderError(f"Expected element <{elemId.name}>, got <{el.tag}>")
        return found_id

    def closeElement(self, id_: int) -> None:
        self._elStack.pop()
        self._childIndexStack.pop()
        self._attributeIndex = -1
        if self._elStack:
            self._attrKeys = list(self._elStack[-1].attrib.keys())

    def closeElementSkipping(self, id_: int) -> None:
        self.closeElement(id_)

    def getNextAttributeId(self) -> int:
        el = self._currentElement()
        keys = list(el.attrib.keys())
        self._attributeIndex += 1
        if self._attributeIndex >= len(keys):
            self._attributeIndex = len(keys)
            return 0
        attr_name = keys[self._attributeIndex]
        return AttributeId.find(attr_name, self._scope)

    def getIndexedAttributeId(self, attribId: AttributeId) -> int:
        return 0  # Simplified

    def rewindAttributes(self) -> None:
        self._attributeIndex = -1

    def _getAttributeValue(self, attribId: Optional[AttributeId] = None) -> str:
        el = self._currentElement()
        if attribId is not None:
            val = el.attrib.get(attribId.name)
            if val is None:
                if attribId == ATTRIB_CONTENT:
                    return el.text or ""
                from ghidra.core.error import DecoderError
                raise DecoderError(f"Attribute '{attribId.name}' not found")
            self.rewindAttributes()
            return val
        # Use current attribute index
        keys = list(el.attrib.keys())
        if 0 <= self._attributeIndex < len(keys):
            return el.attrib[keys[self._attributeIndex]]
        from ghidra.core.error import DecoderError
        raise DecoderError("No current attribute to read")

    def readBool(self, attribId: Optional[AttributeId] = None) -> bool:
        val = self._getAttributeValue(attribId)
        return val.lower() in ("true", "1", "yes", "y")

    def readSignedInteger(self, attribId: Optional[AttributeId] = None) -> int:
        val = self._getAttributeValue(attribId)
        return int(val, 0)

    def readSignedIntegerExpectString(self, expect_or_attribId, expect_str=None, expectval=0):
        if isinstance(expect_or_attribId, AttributeId):
            val = self._getAttributeValue(expect_or_attribId)
            if val == expect_str:
                return expectval
            return int(val, 0)
        else:
            val = self._getAttributeValue()
            if val == expect_or_attribId:
                return expect_str if expect_str is not None else expectval
            return int(val, 0)

    def readUnsignedInteger(self, attribId: Optional[AttributeId] = None) -> int:
        val = self._getAttributeValue(attribId)
        return int(val, 0)

    def readString(self, attribId: Optional[AttributeId] = None) -> str:
        return self._getAttributeValue(attribId)

    def readSpace(self, attribId: Optional[AttributeId] = None) -> AddrSpace:
        name = self._getAttributeValue(attribId)
        if self.spcManager is None:
            from ghidra.core.error import DecoderError
            raise DecoderError("No address space manager for readSpace")
        return self.spcManager.getSpaceByName(name)

    def readOpcode(self, attribId: Optional[AttributeId] = None) -> OpCode:
        val = self._getAttributeValue(attribId)
        return get_opcode(val)


# =========================================================================
# XmlEncode – XML-based encoder
# =========================================================================

class XmlEncode(Encoder):
    """An XML-based encoder that writes to a StringIO stream."""

    def __init__(self, stream: Optional[io.StringIO] = None, do_format: bool = True) -> None:
        self._stream: io.StringIO = stream if stream is not None else io.StringIO()
        self._depth: int = 0
        self._tagStatus: int = 2  # 0=tag_start, 1=tag_content, 2=tag_stop
        self._doFormatting: bool = do_format
        self._elemStack: list[str] = []

    def getStream(self) -> io.StringIO:
        return self._stream

    def toString(self) -> str:
        return self._stream.getvalue()

    def _newLine(self) -> None:
        if self._doFormatting:
            self._stream.write("\n")
            self._stream.write("  " * self._depth)

    def openElement(self, elemId: ElementId) -> None:
        if self._tagStatus == 0:
            self._stream.write(">")
        self._newLine()
        self._stream.write(f"<{elemId.name}")
        self._elemStack.append(elemId.name)
        self._depth += 1
        self._tagStatus = 0  # tag_start

    def closeElement(self, elemId: ElementId) -> None:
        self._depth -= 1
        name = self._elemStack.pop()
        if self._tagStatus == 0:
            self._stream.write("/>")
        else:
            self._newLine()
            self._stream.write(f"</{name}>")
        self._tagStatus = 2  # tag_stop

    def writeBool(self, attribId: AttributeId, val: bool) -> None:
        self._stream.write(f' {attribId.name}="{str(val).lower()}"')

    def writeSignedInteger(self, attribId: AttributeId, val: int) -> None:
        self._stream.write(f' {attribId.name}="0x{val & 0xFFFFFFFFFFFFFFFF:x}"')

    def writeUnsignedInteger(self, attribId: AttributeId, val: int) -> None:
        self._stream.write(f' {attribId.name}="0x{val:x}"')

    def writeString(self, attribId: AttributeId, val: str) -> None:
        if attribId == ATTRIB_CONTENT:
            if self._tagStatus == 0:
                self._stream.write(">")
                self._tagStatus = 1
            self._stream.write(val)
        else:
            self._stream.write(f' {attribId.name}="{val}"')

    def writeStringIndexed(self, attribId: AttributeId, index: int, val: str) -> None:
        self._stream.write(f' {attribId.name}{index}="{val}"')

    def writeSpace(self, attribId: AttributeId, spc: AddrSpace) -> None:
        self._stream.write(f' {attribId.name}="{spc.getName()}"')

    def writeOpcode(self, attribId: AttributeId, opc: OpCode) -> None:
        self._stream.write(f' {attribId.name}="{get_opname(opc)}"')


# =========================================================================
# PackedFormat constants — mirrors C++ PackedFormat namespace
# =========================================================================

class _PF:
    """PackedFormat constants."""
    HEADER_MASK = 0xC0
    ELEMENT_START = 0x40
    ELEMENT_END = 0x80
    ATTRIBUTE = 0xC0
    HEADEREXTEND_MASK = 0x20
    ELEMENTID_MASK = 0x1F
    RAWDATA_MASK = 0x7F
    RAWDATA_BITSPERBYTE = 7
    RAWDATA_MARKER = 0x80
    TYPECODE_SHIFT = 4
    LENGTHCODE_MASK = 0x0F
    TYPECODE_BOOLEAN = 1
    TYPECODE_SIGNEDINT_POSITIVE = 2
    TYPECODE_SIGNEDINT_NEGATIVE = 3
    TYPECODE_UNSIGNEDINT = 4
    TYPECODE_ADDRESSSPACE = 5
    TYPECODE_SPECIALSPACE = 6
    TYPECODE_STRING = 7
    SPECIALSPACE_STACK = 0
    SPECIALSPACE_JOIN = 1
    SPECIALSPACE_FSPEC = 2
    SPECIALSPACE_IOP = 3
    SPECIALSPACE_SPACEBASE = 4


# =========================================================================
# PackedDecode – binary packed format decoder
# =========================================================================

class PackedDecode(Decoder):
    """A byte-based decoder for Ghidra's packed binary format.

    C++ ref: ``PackedDecode`` in marshal.hh / marshal.cc
    """

    def __init__(self, spc_manager: Optional[AddrSpaceManager] = None) -> None:
        super().__init__(spc_manager)
        self._buf: bytes = b""
        self._pos: int = 0          # endPos equivalent — next element boundary
        self._startPos: int = 0     # start of current element's attributes
        self._curPos: int = 0       # current attribute scan position
        self._attributeRead: bool = True

    # ------------------------------------------------------------------
    # Ingestion
    # ------------------------------------------------------------------

    def ingestStream(self, s: str) -> None:
        if isinstance(s, (bytes, bytearray)):
            self._buf = bytes(s)
        else:
            self._buf = s.encode("latin-1")
        self._pos = 0

    def ingestBytes(self, data: bytes) -> None:
        """Ingest raw packed bytes (convenience for protocol layer)."""
        # Append an ELEMENT_END sentinel so reads past the end don't crash
        self._buf = bytes(data) + bytes([_PF.ELEMENT_END])
        self._pos = 0

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    def _getByte(self, pos: int) -> int:
        if pos >= len(self._buf):
            from ghidra.core.error import DecoderError
            raise DecoderError("Unexpected end of packed stream")
        return self._buf[pos]

    def _readInteger(self, length: int) -> int:
        """Read a variable-length integer (7 bits per byte, MSB first)."""
        val = 0
        for _ in range(length):
            val <<= _PF.RAWDATA_BITSPERBYTE
            val |= (self._buf[self._curPos] & _PF.RAWDATA_MASK)
            self._curPos += 1
        return val

    def _readHeaderId(self, pos: int) -> tuple[int, int]:
        """Read element/attribute id from header byte at pos. Returns (id, new_pos)."""
        header = self._buf[pos]
        eid = header & _PF.ELEMENTID_MASK
        pos += 1
        if header & _PF.HEADEREXTEND_MASK:
            eid <<= _PF.RAWDATA_BITSPERBYTE
            eid |= (self._buf[pos] & _PF.RAWDATA_MASK)
            pos += 1
        return eid, pos

    def _skipAttribute(self) -> None:
        """Skip the attribute at _curPos (header + type + data)."""
        header = self._buf[self._curPos]
        self._curPos += 1
        if header & _PF.HEADEREXTEND_MASK:
            self._curPos += 1  # skip extension byte
        typeByte = self._buf[self._curPos]
        self._curPos += 1
        attribType = typeByte >> _PF.TYPECODE_SHIFT
        if attribType == _PF.TYPECODE_BOOLEAN or attribType == _PF.TYPECODE_SPECIALSPACE:
            return
        length = typeByte & _PF.LENGTHCODE_MASK
        if attribType == _PF.TYPECODE_STRING:
            length = self._readInteger(length)  # string length in bytes
        self._curPos += length

    def _findMatchingAttribute(self, attribId: AttributeId) -> None:
        """Scan from _startPos to find the attribute with the given id."""
        self._curPos = self._startPos
        while True:
            if self._curPos >= len(self._buf):
                break
            header = self._buf[self._curPos]
            if (header & _PF.HEADER_MASK) != _PF.ATTRIBUTE:
                break
            eid = header & _PF.ELEMENTID_MASK
            nextPos = self._curPos + 1
            if header & _PF.HEADEREXTEND_MASK:
                eid <<= _PF.RAWDATA_BITSPERBYTE
                eid |= (self._buf[nextPos] & _PF.RAWDATA_MASK)
            if eid == attribId.id:
                return  # found — _curPos points to start of this attribute
            self._skipAttribute()
        from ghidra.core.error import DecoderError
        raise DecoderError(f"Attribute {attribId.name} is not present")

    def _readTypeByte(self) -> int:
        """Consume attribute header + return type byte. Sets _attributeRead."""
        header = self._buf[self._curPos]
        self._curPos += 1
        if header & _PF.HEADEREXTEND_MASK:
            self._curPos += 1
        typeByte = self._buf[self._curPos]
        self._curPos += 1
        return typeByte

    # ------------------------------------------------------------------
    # Decoder interface
    # ------------------------------------------------------------------

    def peekElement(self) -> int:
        if self._pos >= len(self._buf):
            return 0
        header = self._buf[self._pos]
        if (header & _PF.HEADER_MASK) != _PF.ELEMENT_START:
            return 0
        eid, _ = self._readHeaderId(self._pos)
        return eid

    def openElement(self, elemId: Optional[ElementId] = None) -> int:
        if self._pos >= len(self._buf):
            if elemId is not None:
                from ghidra.core.error import DecoderError
                raise DecoderError(f"Expecting <{elemId.name}> but reached end of stream")
            return 0
        header = self._buf[self._pos]
        if (header & _PF.HEADER_MASK) != _PF.ELEMENT_START:
            if elemId is not None:
                from ghidra.core.error import DecoderError
                raise DecoderError(f"Expecting <{elemId.name}> but did not scan an element")
            return 0
        eid, newPos = self._readHeaderId(self._pos)
        self._pos = newPos
        self._startPos = self._pos
        self._curPos = self._pos
        # Skip over all attributes to find the end position
        while self._curPos < len(self._buf):
            h = self._buf[self._curPos]
            if (h & _PF.HEADER_MASK) != _PF.ATTRIBUTE:
                break
            self._skipAttribute()
        self._pos = self._curPos  # endPos = past all attributes
        self._curPos = self._startPos
        self._attributeRead = True

        if elemId is not None and eid != elemId.id:
            from ghidra.core.error import DecoderError
            raise DecoderError(f"Expecting <{elemId.name}> but id did not match")
        return eid

    def closeElement(self, id_: int) -> None:
        if self._pos >= len(self._buf):
            from ghidra.core.error import DecoderError
            raise DecoderError("Expecting element close but reached end of stream")
        header = self._buf[self._pos]
        if (header & _PF.HEADER_MASK) != _PF.ELEMENT_END:
            from ghidra.core.error import DecoderError
            raise DecoderError("Expecting element close")
        closeId, newPos = self._readHeaderId(self._pos)
        if closeId != id_:
            from ghidra.core.error import DecoderError
            raise DecoderError("Did not see expected closing element")
        self._pos = newPos

    def closeElementSkipping(self, id_: int) -> None:
        stack = [id_]
        while stack:
            if self._pos >= len(self._buf):
                from ghidra.core.error import DecoderError
                raise DecoderError("Unexpected end of stream during skip")
            header = self._buf[self._pos] & _PF.HEADER_MASK
            if header == _PF.ELEMENT_END:
                self.closeElement(stack.pop())
            elif header == _PF.ELEMENT_START:
                stack.append(self.openElement())
            else:
                from ghidra.core.error import DecoderError
                raise DecoderError("Corrupt packed stream")

    def getNextAttributeId(self) -> int:
        if not self._attributeRead:
            self._skipAttribute()
        if self._curPos >= len(self._buf):
            return 0
        header = self._buf[self._curPos]
        if (header & _PF.HEADER_MASK) != _PF.ATTRIBUTE:
            return 0
        eid = header & _PF.ELEMENTID_MASK
        if header & _PF.HEADEREXTEND_MASK:
            eid <<= _PF.RAWDATA_BITSPERBYTE
            eid |= (self._buf[self._curPos + 1] & _PF.RAWDATA_MASK)
        self._attributeRead = False
        return eid

    def getIndexedAttributeId(self, attribId: AttributeId) -> int:
        return 0

    def rewindAttributes(self) -> None:
        self._curPos = self._startPos
        self._attributeRead = True

    def readBool(self, attribId: Optional[AttributeId] = None) -> bool:
        if attribId is not None:
            self._findMatchingAttribute(attribId)
        typeByte = self._readTypeByte()
        self._attributeRead = True
        if (typeByte >> _PF.TYPECODE_SHIFT) != _PF.TYPECODE_BOOLEAN:
            from ghidra.core.error import DecoderError
            raise DecoderError("Expecting boolean attribute")
        result = (typeByte & _PF.LENGTHCODE_MASK) != 0
        if attribId is not None:
            self._curPos = self._startPos
        return result

    def readSignedInteger(self, attribId: Optional[AttributeId] = None) -> int:
        if attribId is not None:
            self._findMatchingAttribute(attribId)
        typeByte = self._readTypeByte()
        typeCode = typeByte >> _PF.TYPECODE_SHIFT
        if typeCode == _PF.TYPECODE_SIGNEDINT_POSITIVE:
            res = self._readInteger(typeByte & _PF.LENGTHCODE_MASK)
        elif typeCode == _PF.TYPECODE_SIGNEDINT_NEGATIVE:
            res = -self._readInteger(typeByte & _PF.LENGTHCODE_MASK)
        else:
            from ghidra.core.error import DecoderError
            raise DecoderError("Expecting signed integer attribute")
        self._attributeRead = True
        if attribId is not None:
            self._curPos = self._startPos
        return res

    def readSignedIntegerExpectString(self, expect_or_attribId,
                                       expect_str: Optional[str] = None,
                                       expectval: int = 0) -> int:
        if isinstance(expect_or_attribId, AttributeId):
            self._findMatchingAttribute(expect_or_attribId)
            # Peek type
            savedPos = self._curPos
            _h = self._buf[self._curPos]
            skip = 2 if (_h & _PF.HEADEREXTEND_MASK) else 1
            typeByte = self._buf[self._curPos + skip]
            typeCode = typeByte >> _PF.TYPECODE_SHIFT
            if typeCode == _PF.TYPECODE_STRING:
                val = self.readString()
                self._curPos = self._startPos
                if val != expect_str:
                    from ghidra.core.error import DecoderError
                    raise DecoderError(f'Expecting string "{expect_str}" but read "{val}"')
                return expectval
            else:
                self._curPos = savedPos
                res = self.readSignedInteger()
                self._curPos = self._startPos
                return res
        else:
            # expect_or_attribId is the expected string
            savedPos = self._curPos
            _h = self._buf[self._curPos]
            skip = 2 if (_h & _PF.HEADEREXTEND_MASK) else 1
            typeByte = self._buf[self._curPos + skip]
            typeCode = typeByte >> _PF.TYPECODE_SHIFT
            if typeCode == _PF.TYPECODE_STRING:
                val = self.readString()
                if val != expect_or_attribId:
                    from ghidra.core.error import DecoderError
                    raise DecoderError(f'Expecting string "{expect_or_attribId}" but read "{val}"')
                return expect_str if expect_str is not None else expectval
            else:
                self._curPos = savedPos
                return self.readSignedInteger()

    def readUnsignedInteger(self, attribId: Optional[AttributeId] = None) -> int:
        if attribId is not None:
            self._findMatchingAttribute(attribId)
        typeByte = self._readTypeByte()
        typeCode = typeByte >> _PF.TYPECODE_SHIFT
        if typeCode != _PF.TYPECODE_UNSIGNEDINT:
            from ghidra.core.error import DecoderError
            raise DecoderError("Expecting unsigned integer attribute")
        res = self._readInteger(typeByte & _PF.LENGTHCODE_MASK)
        self._attributeRead = True
        if attribId is not None:
            self._curPos = self._startPos
        return res

    def readString(self, attribId: Optional[AttributeId] = None) -> str:
        if attribId is not None:
            self._findMatchingAttribute(attribId)
        typeByte = self._readTypeByte()
        typeCode = typeByte >> _PF.TYPECODE_SHIFT
        if typeCode != _PF.TYPECODE_STRING:
            from ghidra.core.error import DecoderError
            raise DecoderError("Expecting string attribute")
        strLen = self._readInteger(typeByte & _PF.LENGTHCODE_MASK)
        result = self._buf[self._curPos:self._curPos + strLen].decode("utf-8", errors="replace")
        self._curPos += strLen
        self._attributeRead = True
        if attribId is not None:
            self._curPos = self._startPos
        return result

    def readSpace(self, attribId: Optional[AttributeId] = None) -> AddrSpace:
        if attribId is not None:
            self._findMatchingAttribute(attribId)
        typeByte = self._readTypeByte()
        typeCode = typeByte >> _PF.TYPECODE_SHIFT
        spc = None
        if typeCode == _PF.TYPECODE_ADDRESSSPACE:
            idx = self._readInteger(typeByte & _PF.LENGTHCODE_MASK)
            if self.spcManager is not None:
                spc = self.spcManager.getSpace(idx)
        elif typeCode == _PF.TYPECODE_SPECIALSPACE:
            code = typeByte & _PF.LENGTHCODE_MASK
            if self.spcManager is not None:
                if code == _PF.SPECIALSPACE_STACK:
                    spc = self.spcManager.getStackSpace()
                elif code == _PF.SPECIALSPACE_JOIN:
                    spc = self.spcManager.getJoinSpace()
        if spc is None:
            from ghidra.core.error import DecoderError
            raise DecoderError("Cannot resolve address space")
        self._attributeRead = True
        if attribId is not None:
            self._curPos = self._startPos
        return spc

    def readOpcode(self, attribId: Optional[AttributeId] = None) -> OpCode:
        val = self.readSignedInteger(attribId)
        if val < 0 or val >= OpCode.CPUI_MAX.value:
            from ghidra.core.error import DecoderError
            raise DecoderError("Bad encoded OpCode")
        return OpCode(val)


# =========================================================================
# PackedEncode – binary packed format encoder
# =========================================================================

class PackedEncode(Encoder):
    """A byte-based encoder for Ghidra's packed binary format.

    C++ ref: ``PackedEncode`` in marshal.hh / marshal.cc
    """

    def __init__(self, stream: Optional[io.BytesIO] = None) -> None:
        self._stream: io.BytesIO = stream if stream is not None else io.BytesIO()

    def getBytes(self) -> bytes:
        return self._stream.getvalue()

    def _writeHeader(self, header: int, eid: int) -> None:
        if eid > 0x1F:
            header |= _PF.HEADEREXTEND_MASK
            header |= (eid >> _PF.RAWDATA_BITSPERBYTE)
            extByte = (eid & _PF.RAWDATA_MASK) | _PF.RAWDATA_MARKER
            self._stream.write(bytes([header, extByte]))
        else:
            self._stream.write(bytes([header | eid]))

    def _writeInteger(self, typeByte: int, val: int) -> None:
        if val == 0:
            self._stream.write(bytes([typeByte]))
            return
        # Determine length code
        if val < 0x80:
            lenCode, sa = 1, 0
        elif val < 0x4000:
            lenCode, sa = 2, 7
        elif val < 0x200000:
            lenCode, sa = 3, 14
        elif val < 0x10000000:
            lenCode, sa = 4, 21
        elif val < 0x800000000:
            lenCode, sa = 5, 28
        elif val < 0x40000000000:
            lenCode, sa = 6, 35
        elif val < 0x2000000000000:
            lenCode, sa = 7, 42
        elif val < 0x100000000000000:
            lenCode, sa = 8, 49
        elif val < 0x8000000000000000:
            lenCode, sa = 9, 56
        else:
            lenCode, sa = 10, 63
        self._stream.write(bytes([typeByte | lenCode]))
        while sa >= 0:
            piece = ((val >> sa) & _PF.RAWDATA_MASK) | _PF.RAWDATA_MARKER
            self._stream.write(bytes([piece]))
            sa -= _PF.RAWDATA_BITSPERBYTE

    def openElement(self, elemId: ElementId) -> None:
        self._writeHeader(_PF.ELEMENT_START, elemId.id)

    def closeElement(self, elemId: ElementId) -> None:
        self._writeHeader(_PF.ELEMENT_END, elemId.id)

    def writeBool(self, attribId: AttributeId, val: bool) -> None:
        self._writeHeader(_PF.ATTRIBUTE, attribId.id)
        tb = (_PF.TYPECODE_BOOLEAN << _PF.TYPECODE_SHIFT) | (1 if val else 0)
        self._stream.write(bytes([tb]))

    def writeSignedInteger(self, attribId: AttributeId, val: int) -> None:
        self._writeHeader(_PF.ATTRIBUTE, attribId.id)
        if val < 0:
            tb = _PF.TYPECODE_SIGNEDINT_NEGATIVE << _PF.TYPECODE_SHIFT
            num = -val
        else:
            tb = _PF.TYPECODE_SIGNEDINT_POSITIVE << _PF.TYPECODE_SHIFT
            num = val
        self._writeInteger(tb, num)

    def writeUnsignedInteger(self, attribId: AttributeId, val: int) -> None:
        self._writeHeader(_PF.ATTRIBUTE, attribId.id)
        self._writeInteger(_PF.TYPECODE_UNSIGNEDINT << _PF.TYPECODE_SHIFT, val)

    def writeString(self, attribId: AttributeId, val: str) -> None:
        data = val.encode("utf-8")
        self._writeHeader(_PF.ATTRIBUTE, attribId.id)
        self._writeInteger(_PF.TYPECODE_STRING << _PF.TYPECODE_SHIFT, len(data))
        self._stream.write(data)

    def writeStringIndexed(self, attribId: AttributeId, index: int, val: str) -> None:
        data = val.encode("utf-8")
        self._writeHeader(_PF.ATTRIBUTE, attribId.id + index)
        self._writeInteger(_PF.TYPECODE_STRING << _PF.TYPECODE_SHIFT, len(data))
        self._stream.write(data)

    def writeSpace(self, attribId: AttributeId, spc: AddrSpace) -> None:
        self._writeHeader(_PF.ATTRIBUTE, attribId.id)
        spc_type = spc.getType() if hasattr(spc, 'getType') else -1
        from ghidra.core.space import IPTR_SPACEBASE, IPTR_JOIN, IPTR_IOP, IPTR_FSPEC
        if spc_type == IPTR_FSPEC:
            self._stream.write(bytes([(_PF.TYPECODE_SPECIALSPACE << _PF.TYPECODE_SHIFT) | _PF.SPECIALSPACE_FSPEC]))
        elif spc_type == IPTR_IOP:
            self._stream.write(bytes([(_PF.TYPECODE_SPECIALSPACE << _PF.TYPECODE_SHIFT) | _PF.SPECIALSPACE_IOP]))
        elif spc_type == IPTR_JOIN:
            self._stream.write(bytes([(_PF.TYPECODE_SPECIALSPACE << _PF.TYPECODE_SHIFT) | _PF.SPECIALSPACE_JOIN]))
        elif spc_type == IPTR_SPACEBASE:
            if hasattr(spc, 'isFormalStackSpace') and spc.isFormalStackSpace():
                self._stream.write(bytes([(_PF.TYPECODE_SPECIALSPACE << _PF.TYPECODE_SHIFT) | _PF.SPECIALSPACE_STACK]))
            else:
                self._stream.write(bytes([(_PF.TYPECODE_SPECIALSPACE << _PF.TYPECODE_SHIFT) | _PF.SPECIALSPACE_SPACEBASE]))
        else:
            idx = spc.getIndex() if hasattr(spc, 'getIndex') else 0
            self._writeInteger(_PF.TYPECODE_ADDRESSSPACE << _PF.TYPECODE_SHIFT, idx)

    def writeOpcode(self, attribId: AttributeId, opc: OpCode) -> None:
        self._writeHeader(_PF.ATTRIBUTE, attribId.id)
        self._writeInteger(_PF.TYPECODE_SIGNEDINT_POSITIVE << _PF.TYPECODE_SHIFT, int(opc))
