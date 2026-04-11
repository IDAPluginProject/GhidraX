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
from ghidra.core.xml import a_v, a_v_b, a_v_i, a_v_u, xml_escape

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

    @staticmethod
    def getList() -> list[AttributeId]:
        return AttributeId._list

    def __init__(self, name: str, id_: int, scope: int = 0) -> None:
        self.name: str = name
        self.id: int = id_
        if scope == 0:
            AttributeId.getList().append(self)

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
        if scope == 0:
            return AttributeId._lookup.get(name, ATTRIB_UNKNOWN.getId())
        return ATTRIB_UNKNOWN.getId()

    @staticmethod
    def initialize() -> None:
        thelist = AttributeId.getList()
        for attrib in thelist:
            AttributeId._lookup[attrib.name] = attrib.id
        thelist.clear()


# =========================================================================
# ElementId
# =========================================================================

class ElementId:
    """An annotation for a specific collection of hierarchical data.

    Parallels the XML concept of an element.
    """
    _lookup: dict[str, int] = {}
    _list: list[ElementId] = []

    @staticmethod
    def getList() -> list[ElementId]:
        return ElementId._list

    def __init__(self, name: str, id_: int, scope: int = 0) -> None:
        self.name: str = name
        self.id: int = id_
        if scope == 0:
            ElementId.getList().append(self)

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
        if scope == 0:
            return ElementId._lookup.get(name, ELEM_UNKNOWN.getId())
        return ELEM_UNKNOWN.getId()

    @staticmethod
    def initialize() -> None:
        thelist = ElementId.getList()
        for elem in thelist:
            ElementId._lookup[elem.name] = elem.id
        thelist.clear()


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
ATTRIB_CHAR = AttributeId("char", 49)
ATTRIB_CONTAIN = AttributeId("contain", 44)
ATTRIB_DEFAULTSPACE = AttributeId("defaultspace", 45)
ATTRIB_UNIQBASE = AttributeId("uniqbase", 46)
ATTRIB_UTF = AttributeId("utf", 59)

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

# From type.cc
ELEM_CORETYPES = ElementId("coretypes", 41)
ELEM_TYPEGRP = ElementId("typegrp", 62)

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

# From architecture.cc
ATTRIB_LOADERSYMBOLS = AttributeId("loadersymbols", 108)
ELEM_SAVE_STATE = ElementId("save_state", 154)

# From fspec.cc
ELEM_PROTOTYPE = ElementId("prototype", 169)

# From comment.cc
ELEM_COMMENT = ElementId("comment", 86)
ELEM_COMMENTDB = ElementId("commentdb", 87)
ELEM_TEXT = ElementId("text", 88)
ELEM_DEFAULT_SYMBOLS = ElementId("default_symbols", 136)

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
ELEM_OPTIONSLIST = ElementId("optionslist", 201)
ELEM_PARAM1 = ElementId("param1", 202)
ELEM_PARAM2 = ElementId("param2", 203)
ELEM_PARAM3 = ElementId("param3", 204)

# From architecture.cc
ATTRIB_ENABLE = AttributeId("enable", 104)
ATTRIB_GROUP = AttributeId("group", 105)
ATTRIB_GROWTH = AttributeId("growth", 106)
ATTRIB_REGISTER = AttributeId("register", 110)
ATTRIB_REVERSEJUSTIFY = AttributeId("reversejustify", 111)
ATTRIB_SIGNEXT = AttributeId("signext", 112)
ATTRIB_STYLE = AttributeId("style", 113)
ATTRIB_PARENT = AttributeId("parent", 109)
ELEM_ADDRESS_SHIFT_AMOUNT = ElementId("address_shift_amount", 130)
ELEM_AGGRESSIVETRIM = ElementId("aggressivetrim", 131)
ELEM_COMPILER_SPEC = ElementId("compiler_spec", 132)
ELEM_DATA_SPACE = ElementId("data_space", 133)
ELEM_DEFAULT_MEMORY_BLOCKS = ElementId("default_memory_blocks", 134)
ELEM_DEFAULT_PROTO = ElementId("default_proto", 135)
ELEM_EVAL_CALLED_PROTOTYPE = ElementId("eval_called_prototype", 137)
ELEM_EVAL_CURRENT_PROTOTYPE = ElementId("eval_current_prototype", 138)
ELEM_EXPERIMENTAL_RULES = ElementId("experimental_rules", 139)
ELEM_FUNCPTR = ElementId("funcptr", 141)
ELEM_GLOBAL = ElementId("global", 142)
ELEM_INCIDENTALCOPY = ElementId("incidentalcopy", 143)
ELEM_INFERPTRBOUNDS = ElementId("inferptrbounds", 144)
ELEM_MODELALIAS = ElementId("modelalias", 145)
ELEM_NOHIGHPTR = ElementId("nohighptr", 146)
ELEM_PROCESSOR_SPEC = ElementId("processor_spec", 147)
ELEM_PROGRAMCOUNTER = ElementId("programcounter", 148)
ELEM_PROPERTIES = ElementId("properties", 149)
ELEM_READONLY = ElementId("readonly", 151)
ELEM_REGISTER_DATA = ElementId("register_data", 152)
ELEM_SEGMENTED_ADDRESS = ElementId("segmented_address", 155)
ELEM_SPACEBASE = ElementId("spacebase", 156)
ELEM_SPECEXTENSIONS = ElementId("specextensions", 157)
ELEM_STACKPOINTER = ElementId("stackpointer", 158)
ELEM_VOLATILE = ElementId("volatile", 159)
ELEM_RULE = ElementId("rule", 153)

# From options.cc
ELEM_ALIASBLOCK = ElementId("aliasblock", 174)
ELEM_ALLOWCONTEXTSET = ElementId("allowcontextset", 175)
ELEM_ANALYZEFORLOOPS = ElementId("analyzeforloops", 176)
ELEM_COMMENTHEADER = ElementId("commentheader", 177)
ELEM_COMMENTINDENT = ElementId("commentindent", 178)
ELEM_COMMENTINSTRUCTION = ElementId("commentinstruction", 179)
ELEM_COMMENTSTYLE = ElementId("commentstyle", 180)
ELEM_CONVENTIONPRINTING = ElementId("conventionprinting", 181)
ELEM_CURRENTACTION = ElementId("currentaction", 182)
ELEM_DEFAULTPROTOTYPE = ElementId("defaultprototype", 183)
ELEM_ERRORREINTERPRETED = ElementId("errorreinterpreted", 184)
ELEM_ERRORTOOMANYINSTRUCTIONS = ElementId("errortoomanyinstructions", 185)
ELEM_ERRORUNIMPLEMENTED = ElementId("errorunimplemented", 186)
ELEM_EXTRAPOP = ElementId("extrapop", 187)
ELEM_IGNOREUNIMPLEMENTED = ElementId("ignoreunimplemented", 188)
ELEM_INDENTINCREMENT = ElementId("indentincrement", 189)
ELEM_INFERCONSTPTR = ElementId("inferconstptr", 190)
ELEM_INLINE = ElementId("inline", 191)
ELEM_INPLACEOPS = ElementId("inplaceops", 192)
ELEM_INTEGERFORMAT = ElementId("integerformat", 193)
ELEM_JUMPLOAD = ElementId("jumpload", 194)
ELEM_MAXINSTRUCTION = ElementId("maxinstruction", 195)
ELEM_MAXLINEWIDTH = ElementId("maxlinewidth", 196)
ELEM_NAMESPACESTRATEGY = ElementId("namespacestrategy", 197)
ELEM_NOCASTPRINTING = ElementId("nocastprinting", 198)
ELEM_NORETURN = ElementId("noreturn", 199)
ELEM_NULLPRINTING = ElementId("nullprinting", 200)
ELEM_PROTOEVAL = ElementId("protoeval", 205)
ELEM_SETACTION = ElementId("setaction", 206)
ELEM_SETLANGUAGE = ElementId("setlanguage", 207)
ELEM_STRUCTALIGN = ElementId("structalign", 208)
ELEM_TOGGLERULE = ElementId("togglerule", 209)
ELEM_WARNING = ElementId("warning", 210)
ELEM_SPLITDATATYPE = ElementId("splitdatatype", 270)
ELEM_JUMPTABLEMAX = ElementId("jumptablemax", 271)
ELEM_NANIGNORE = ElementId("nanignore", 272)
ELEM_BRACEFORMAT = ElementId("braceformat", 284)

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
ELEM_ENUM = ElementId("enum", 48)

# From marshal.cc (high-numbered)
ATTRIB_ADDRESS = AttributeId("address", 148)
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
ELEM_DATA_ORGANIZATION = ElementId("data_organization", 42)

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
ATTRIB_DYNAMIC = AttributeId("dynamic", 70)
ATTRIB_INCIDENTALCOPY = AttributeId("incidentalcopy", 71)
ATTRIB_INJECT = AttributeId("inject", 72)
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

AttributeId.initialize()
ElementId.initialize()

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

    def __del__(self) -> None:
        pass

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

    def __del__(self) -> None:
        pass

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

    def getCurrentXmlElement(self) -> Element:
        return self._currentElement()

    def __del__(self) -> None:
        self._root = None
        self._elStack.clear()
        self._iterStack.clear()
        self._childIndexStack.clear()
        self._attrKeys = []

    def ingestStream(self, s: str) -> None:
        self._root = xml_fromstring(s)

    def _currentElement(self) -> Element:
        return self._elStack[-1]

    def _findMatchingAttribute(self, el: Element, attrib_name: str) -> int:
        keys = list(el.attrib.keys())
        for i, k in enumerate(keys):
            if k == attrib_name:
                return i
        from ghidra.core.error import DecoderError
        raise DecoderError("Attribute missing: " + attrib_name)

    def peekElement(self) -> int:
        if not self._elStack:
            if self._root is None:
                return 0
            return ElementId.find(self._root.tag, self._scope)
        parent = self._currentElement()
        children = list(parent)
        idx = self._childIndexStack[-1]
        if idx >= len(children):
            return 0
        child = children[idx]
        return ElementId.find(child.tag, self._scope)

    def openElement(self, elemId: Optional[ElementId] = None) -> int:
        from ghidra.core.error import DecoderError

        if not self._elStack:
            if self._root is None:
                if elemId is None:
                    return 0
                raise DecoderError(f"Expecting <{elemId.name}> but reached end of document")
            el = self._root
            self._root = None
        else:
            parent = self._currentElement()
            children = list(parent)
            idx = self._childIndexStack[-1]
            if idx >= len(children):
                if elemId is None:
                    return 0
                raise DecoderError(
                    f"Expecting <{elemId.name}> but no remaining children in current element"
                )
            el = children[idx]
            self._childIndexStack[-1] = idx + 1

        found_id = ElementId.find(el.tag, self._scope)
        if elemId is not None and el.tag != elemId.name:
            raise DecoderError(f"Expecting <{elemId.name}> but got <{el.tag}>")

        self._elStack.append(el)
        self._childIndexStack.append(0)
        self._attributeIndex = -1
        self._attrKeys = list(el.attrib.keys())
        if elemId is not None:
            return elemId.id
        return found_id

    def closeElement(self, id_: int) -> None:
        self._elStack.pop()
        self._childIndexStack.pop()
        self._attributeIndex = 1000
        if self._elStack:
            self._attrKeys = list(self._elStack[-1].attrib.keys())
        else:
            self._attrKeys = []

    def closeElementSkipping(self, id_: int) -> None:
        self.closeElement(id_)

    def getNextAttributeId(self) -> int:
        el = self._currentElement()
        keys = list(el.attrib.keys())
        next_index = self._attributeIndex + 1
        if next_index >= len(keys):
            return 0
        self._attributeIndex = next_index
        attr_name = keys[self._attributeIndex]
        return AttributeId.find(attr_name, self._scope)

    def getIndexedAttributeId(self, attribId: AttributeId) -> int:
        from ghidra.core.error import LowlevelError

        el = self._currentElement()
        keys = list(el.attrib.keys())
        if self._attributeIndex < 0 or self._attributeIndex >= len(keys):
            return ATTRIB_UNKNOWN.getId()
        attribName = keys[self._attributeIndex]
        baseName = attribId.name
        if not attribName.startswith(baseName):
            return ATTRIB_UNKNOWN.getId()
        suffix = attribName[len(baseName):]
        try:
            val = int(suffix)
        except (ValueError, TypeError):
            val = 0
        if val == 0:
            raise LowlevelError("Bad indexed attribute: " + attribId.getName())
        return attribId.id + (val - 1)

    def rewindAttributes(self) -> None:
        self._attributeIndex = -1

    def _getAttributeValue(self, attribId: Optional[AttributeId] = None) -> str:
        el = self._currentElement()
        if attribId is not None:
            if attribId == ATTRIB_CONTENT:
                val = el.attrib.get(attribId.name)
                if val is not None:
                    return val
                return el.text or ""
            index = self._findMatchingAttribute(el, attribId.name)
            keys = list(el.attrib.keys())
            return el.attrib[keys[index]]
        # Use current attribute index
        keys = list(el.attrib.keys())
        if 0 <= self._attributeIndex < len(keys):
            return el.attrib[keys[self._attributeIndex]]
        from ghidra.core.error import DecoderError
        raise DecoderError("No current attribute to read")

    def readBool(self, attribId: Optional[AttributeId] = None) -> bool:
        from ghidra.core.xml import xml_readbool

        val = self._getAttributeValue(attribId)
        return xml_readbool(val)

    def readSignedInteger(self, attribId: Optional[AttributeId] = None) -> int:
        val = self._getAttributeValue(attribId)
        return int(val, 0)

    def readSignedIntegerExpectString(self, expect_or_attribId, expect_str=None, expectval=0):
        if isinstance(expect_or_attribId, AttributeId):
            val = self._getAttributeValue(expect_or_attribId)
            if val == expect_str:
                return expectval
            return int(val, 0)
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
        from ghidra.core.error import DecoderError

        name = self._getAttributeValue(attribId)
        if self.spcManager is None:
            raise DecoderError("No address space manager for readSpace")
        res = self.spcManager.getSpaceByName(name)
        if res is None:
            raise DecoderError("Unknown address space name: " + name)
        return res

    def readOpcode(self, attribId: Optional[AttributeId] = None) -> OpCode:
        from ghidra.core.error import DecoderError

        val = self._getAttributeValue(attribId)
        opc = get_opcode(val)
        if opc == OpCode.CPUI_BLANK:
            raise DecoderError("Bad encoded OpCode")
        return opc


# =========================================================================
# XmlEncode – XML-based encoder
# =========================================================================

class XmlEncode(Encoder):
    """An XML-based encoder that writes to a StringIO stream."""

    _SPACES = "\n                        "
    _MAX_SPACES = 24 + 1

    def __init__(self, stream, do_format: bool = True) -> None:
        self._stream = stream
        self._depth: int = 0
        self._tagStatus: int = 2  # 0=tag_start, 1=tag_content, 2=tag_stop
        self._doFormatting: bool = do_format
        self._elemStack: list[str] = []

    def getStream(self) -> io.StringIO:
        return self._stream

    def toString(self) -> str:
        return self._stream.getvalue()

    def newLine(self) -> None:
        if not self._doFormatting:
            return
        num_spaces = self._depth * 2 + 1
        if num_spaces > self._MAX_SPACES:
            num_spaces = self._MAX_SPACES
        self._stream.write(self._SPACES[:num_spaces])

    def openElement(self, elemId: ElementId) -> None:
        if self._tagStatus == 0:
            self._stream.write(">")
        else:
            self._tagStatus = 0
        self.newLine()
        self._stream.write(f"<{elemId.name}")
        self._elemStack.append(elemId.name)
        self._depth += 1
        self._tagStatus = 0  # tag_start

    def closeElement(self, elemId: ElementId) -> None:
        self._depth -= 1
        self._elemStack.pop()
        if self._tagStatus == 0:
            self._stream.write("/>")
            self._tagStatus = 2
            return
        if self._tagStatus != 1:
            self.newLine()
        else:
            self._tagStatus = 2
        self._stream.write(f"</{elemId.name}>")
        self._tagStatus = 2  # tag_stop

    def writeBool(self, attribId: AttributeId, val: bool) -> None:
        if attribId == ATTRIB_CONTENT:
            if self._tagStatus == 0:
                self._stream.write(">")
            self._stream.write("true" if val else "false")
            self._tagStatus = 1
            return
        self._stream.write(a_v_b(attribId.name, val))

    def writeSignedInteger(self, attribId: AttributeId, val: int) -> None:
        if attribId == ATTRIB_CONTENT:
            if self._tagStatus == 0:
                self._stream.write(">")
            self._stream.write(str(val))
            self._tagStatus = 1
            return
        self._stream.write(a_v_i(attribId.name, val))

    def writeUnsignedInteger(self, attribId: AttributeId, val: int) -> None:
        if attribId == ATTRIB_CONTENT:
            if self._tagStatus == 0:
                self._stream.write(">")
            self._stream.write(f"0x{val:x}")
            self._tagStatus = 1
            return
        self._stream.write(a_v_u(attribId.name, val))

    def writeString(self, attribId: AttributeId, val: str) -> None:
        if attribId == ATTRIB_CONTENT:
            if self._tagStatus == 0:
                self._stream.write(">")
            self._stream.write(xml_escape(val))
            self._tagStatus = 1
            return
        self._stream.write(a_v(attribId.name, val))

    def writeStringIndexed(self, attribId: AttributeId, index: int, val: str) -> None:
        self._stream.write(f' {attribId.name}{index + 1}="{xml_escape(val)}"')

    def writeSpace(self, attribId: AttributeId, spc: AddrSpace) -> None:
        name = spc.getName()
        if attribId == ATTRIB_CONTENT:
            if self._tagStatus == 0:
                self._stream.write(">")
            self._stream.write(xml_escape(name))
            self._tagStatus = 1
            return
        self._stream.write(a_v(attribId.name, name))

    def writeOpcode(self, attribId: AttributeId, opc: OpCode) -> None:
        name = get_opname(opc)
        if attribId == ATTRIB_CONTENT:
            if self._tagStatus == 0:
                self._stream.write(">")
            self._stream.write(name)
            self._tagStatus = 1
            return
        self._stream.write(f' {attribId.name}="{name}"')


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
    """A byte-based decoder for Ghidra's packed binary format."""

    BUFFER_SIZE = 1024

    class ByteChunk:
        def __init__(self, start: bytearray, end: int) -> None:
            self.start = start
            self.end = end

    class Position:
        def __init__(self, seq_iter: int = 0, current: int = 0, end: int = 0) -> None:
            self.seqIter = seq_iter
            self.current = current
            self.end = end

    def __init__(self, spc_manager: Optional[AddrSpaceManager]) -> None:
        super().__init__(spc_manager)
        self._inStream: list[PackedDecode.ByteChunk] = []
        self._startPos = PackedDecode.Position()
        self._curPos = PackedDecode.Position()
        self._endPos = PackedDecode.Position()
        self._attributeRead = True

    def __del__(self) -> None:
        if hasattr(self, "_inStream"):
            self._inStream.clear()

    def _copyPosition(self, pos: Position) -> Position:
        return PackedDecode.Position(pos.seqIter, pos.current, pos.end)

    def _resetStreamState(self) -> None:
        self._inStream = []
        self._startPos = PackedDecode.Position()
        self._curPos = PackedDecode.Position()
        self._endPos = PackedDecode.Position()
        self._attributeRead = True

    def _setPositionToStreamStart(self, pos: Position) -> None:
        pos.seqIter = 0
        if not self._inStream:
            pos.current = 0
            pos.end = 0
            return
        pos.current = 0
        pos.end = self._inStream[0].end

    def _raiseUnexpectedEndOfStream(self) -> None:
        from ghidra.core.error import DecoderError

        raise DecoderError("Unexpected end of stream")

    def _ingestRawBytes(self, data: bytes) -> None:
        self._resetStreamState()
        last_count = 0
        offset = 0
        while offset < len(data):
            buf = self.allocateNextInputBuffer(1)
            last_count = min(self.BUFFER_SIZE, len(data) - offset)
            buf[:last_count] = data[offset:offset + last_count]
            offset += last_count
        self.endIngest(last_count)
        self._startPos = self._copyPosition(self._endPos)
        self._curPos = self._copyPosition(self._endPos)
        self._attributeRead = True

    def ingestStream(self, s) -> None:
        raw = s.read() if hasattr(s, "read") else s
        if isinstance(raw, str):
            data = raw.encode("latin-1")
        else:
            data = bytes(raw)
        zero_pos = data.find(b"\0")
        if zero_pos != -1:
            data = data[:zero_pos]
        self._ingestRawBytes(data)

    def ingestBytes(self, data: bytes) -> None:
        self._ingestRawBytes(bytes(data))

    def getByte(self, pos: Position) -> int:
        if pos.seqIter >= len(self._inStream) or pos.current >= pos.end:
            self._raiseUnexpectedEndOfStream()
        return self._inStream[pos.seqIter].start[pos.current]

    def getBytePlus1(self, pos: Position) -> int:
        if pos.seqIter >= len(self._inStream) or pos.current >= pos.end:
            self._raiseUnexpectedEndOfStream()
        ptr = pos.current + 1
        if ptr == pos.end:
            next_iter = pos.seqIter + 1
            if next_iter == len(self._inStream) or self._inStream[next_iter].end == 0:
                self._raiseUnexpectedEndOfStream()
            return self._inStream[next_iter].start[0]
        if ptr > pos.end:
            self._raiseUnexpectedEndOfStream()
        return self._inStream[pos.seqIter].start[ptr]

    def getNextByte(self, pos: Position) -> int:
        res = self.getByte(pos)
        pos.current += 1
        if pos.current != pos.end:
            return res
        pos.seqIter += 1
        if pos.seqIter == len(self._inStream):
            self._raiseUnexpectedEndOfStream()
        pos.current = 0
        pos.end = self._inStream[pos.seqIter].end
        return res

    def advancePosition(self, pos: Position, skip: int) -> None:
        while pos.end - pos.current <= skip:
            skip -= pos.end - pos.current
            pos.seqIter += 1
            if pos.seqIter == len(self._inStream):
                self._raiseUnexpectedEndOfStream()
            pos.current = 0
            pos.end = self._inStream[pos.seqIter].end
        pos.current += skip

    def readInteger(self, length: int) -> int:
        res = 0
        while length > 0:
            res <<= _PF.RAWDATA_BITSPERBYTE
            res |= self.getNextByte(self._curPos) & _PF.RAWDATA_MASK
            length -= 1
        return res

    def readLengthCode(self, typeByte: int) -> int:
        return typeByte & _PF.LENGTHCODE_MASK

    def findMatchingAttribute(self, attribId: AttributeId) -> None:
        self._curPos = self._copyPosition(self._startPos)
        while True:
            header1 = self.getByte(self._curPos)
            if (header1 & _PF.HEADER_MASK) != _PF.ATTRIBUTE:
                break
            attr_id = header1 & _PF.ELEMENTID_MASK
            if (header1 & _PF.HEADEREXTEND_MASK) != 0:
                attr_id <<= _PF.RAWDATA_BITSPERBYTE
                attr_id |= self.getBytePlus1(self._curPos) & _PF.RAWDATA_MASK
            if attribId.getId() == attr_id:
                return
            self.skipAttribute()
        from ghidra.core.error import DecoderError

        raise DecoderError("Attribute " + attribId.getName() + " is not present")

    def skipAttribute(self) -> None:
        header1 = self.getNextByte(self._curPos)
        if (header1 & _PF.HEADEREXTEND_MASK) != 0:
            self.getNextByte(self._curPos)
        typeByte = self.getNextByte(self._curPos)
        attribType = typeByte >> _PF.TYPECODE_SHIFT
        if attribType == _PF.TYPECODE_BOOLEAN or attribType == _PF.TYPECODE_SPECIALSPACE:
            return
        length = self.readLengthCode(typeByte)
        if attribType == _PF.TYPECODE_STRING:
            length = self.readInteger(length)
        self.advancePosition(self._curPos, length)

    def skipAttributeRemaining(self, typeByte: int) -> None:
        attribType = typeByte >> _PF.TYPECODE_SHIFT
        if attribType == _PF.TYPECODE_BOOLEAN or attribType == _PF.TYPECODE_SPECIALSPACE:
            return
        length = self.readLengthCode(typeByte)
        if attribType == _PF.TYPECODE_STRING:
            length = self.readInteger(length)
        self.advancePosition(self._curPos, length)

    # ------------------------------------------------------------------
    # Decoder interface
    # ------------------------------------------------------------------

    def allocateNextInputBuffer(self, pad: int) -> bytearray:
        buf = bytearray(self.BUFFER_SIZE + pad)
        self._inStream.append(PackedDecode.ByteChunk(buf, self.BUFFER_SIZE))
        return buf

    def endIngest(self, bufPos: int) -> None:
        self._setPositionToStreamStart(self._endPos)
        if not self._inStream:
            return
        if bufPos == self.BUFFER_SIZE:
            endbuf = bytearray(1)
            self._inStream.append(PackedDecode.ByteChunk(endbuf, 1))
            bufPos = 0
        buf = self._inStream[-1].start
        buf[bufPos] = _PF.ELEMENT_END

    def peekElement(self) -> int:
        if not self._inStream or self._endPos.seqIter >= len(self._inStream):
            return 0
        header1 = self.getByte(self._endPos)
        if (header1 & _PF.HEADER_MASK) != _PF.ELEMENT_START:
            return 0
        elem_id = header1 & _PF.ELEMENTID_MASK
        if (header1 & _PF.HEADEREXTEND_MASK) != 0:
            elem_id <<= _PF.RAWDATA_BITSPERBYTE
            elem_id |= self.getBytePlus1(self._endPos) & _PF.RAWDATA_MASK
        return elem_id

    def openElement(self, elemId: Optional[ElementId] = None) -> int:
        if elemId is not None:
            elem_id = self.openElement()
            if elem_id != elemId.getId():
                from ghidra.core.error import DecoderError

                if elem_id == 0:
                    raise DecoderError(
                        "Expecting <" + elemId.getName() + "> but did not scan an element"
                    )
                raise DecoderError(
                    "Expecting <" + elemId.getName() + "> but id did not match"
                )
            return elem_id

        if not self._inStream or self._endPos.seqIter >= len(self._inStream):
            return 0
        header1 = self.getByte(self._endPos)
        if (header1 & _PF.HEADER_MASK) != _PF.ELEMENT_START:
            return 0
        self.getNextByte(self._endPos)
        elem_id = header1 & _PF.ELEMENTID_MASK
        if (header1 & _PF.HEADEREXTEND_MASK) != 0:
            elem_id <<= _PF.RAWDATA_BITSPERBYTE
            elem_id |= self.getNextByte(self._endPos) & _PF.RAWDATA_MASK
        self._startPos = self._copyPosition(self._endPos)
        self._curPos = self._copyPosition(self._endPos)
        header1 = self.getByte(self._curPos)
        while (header1 & _PF.HEADER_MASK) == _PF.ATTRIBUTE:
            self.skipAttribute()
            header1 = self.getByte(self._curPos)
        self._endPos = self._copyPosition(self._curPos)
        self._curPos = self._copyPosition(self._startPos)
        self._attributeRead = True
        return elem_id

    def closeElement(self, id_: int) -> None:
        header1 = self.getNextByte(self._endPos)
        if (header1 & _PF.HEADER_MASK) != _PF.ELEMENT_END:
            from ghidra.core.error import DecoderError

            raise DecoderError("Expecting element close")
        close_id = header1 & _PF.ELEMENTID_MASK
        if (header1 & _PF.HEADEREXTEND_MASK) != 0:
            close_id <<= _PF.RAWDATA_BITSPERBYTE
            close_id |= self.getNextByte(self._endPos) & _PF.RAWDATA_MASK
        if id_ != close_id:
            from ghidra.core.error import DecoderError

            raise DecoderError("Did not see expected closing element")

    def closeElementSkipping(self, id_: int) -> None:
        idstack = [id_]
        while idstack:
            header1 = self.getByte(self._endPos) & _PF.HEADER_MASK
            if header1 == _PF.ELEMENT_END:
                self.closeElement(idstack[-1])
                idstack.pop()
            elif header1 == _PF.ELEMENT_START:
                idstack.append(self.openElement())
            else:
                from ghidra.core.error import DecoderError

                raise DecoderError("Corrupt stream")

    def getNextAttributeId(self) -> int:
        if not self._attributeRead:
            self.skipAttribute()
        if self._curPos.seqIter >= len(self._inStream):
            return 0
        header1 = self.getByte(self._curPos)
        if (header1 & _PF.HEADER_MASK) != _PF.ATTRIBUTE:
            return 0
        attr_id = header1 & _PF.ELEMENTID_MASK
        if (header1 & _PF.HEADEREXTEND_MASK) != 0:
            attr_id <<= _PF.RAWDATA_BITSPERBYTE
            attr_id |= self.getBytePlus1(self._curPos) & _PF.RAWDATA_MASK
        self._attributeRead = False
        return attr_id

    def getIndexedAttributeId(self, attribId: AttributeId) -> int:
        return ATTRIB_UNKNOWN.getId()

    def rewindAttributes(self) -> None:
        self._curPos = self._copyPosition(self._startPos)
        self._attributeRead = True

    def readBool(self, attribId: Optional[AttributeId] = None) -> bool:
        if attribId is not None:
            self.findMatchingAttribute(attribId)
            res = self.readBool()
            self._curPos = self._copyPosition(self._startPos)
            return res
        header1 = self.getNextByte(self._curPos)
        if (header1 & _PF.HEADEREXTEND_MASK) != 0:
            self.getNextByte(self._curPos)
        typeByte = self.getNextByte(self._curPos)
        self._attributeRead = True
        if (typeByte >> _PF.TYPECODE_SHIFT) != _PF.TYPECODE_BOOLEAN:
            from ghidra.core.error import DecoderError

            raise DecoderError("Expecting boolean attribute")
        return (typeByte & _PF.LENGTHCODE_MASK) != 0

    def readSignedInteger(self, attribId: Optional[AttributeId] = None) -> int:
        if attribId is not None:
            self.findMatchingAttribute(attribId)
            res = self.readSignedInteger()
            self._curPos = self._copyPosition(self._startPos)
            return res
        header1 = self.getNextByte(self._curPos)
        if (header1 & _PF.HEADEREXTEND_MASK) != 0:
            self.getNextByte(self._curPos)
        typeByte = self.getNextByte(self._curPos)
        typeCode = typeByte >> _PF.TYPECODE_SHIFT
        if typeCode == _PF.TYPECODE_SIGNEDINT_POSITIVE:
            res = self.readInteger(self.readLengthCode(typeByte))
        elif typeCode == _PF.TYPECODE_SIGNEDINT_NEGATIVE:
            res = -self.readInteger(self.readLengthCode(typeByte))
        else:
            self.skipAttributeRemaining(typeByte)
            self._attributeRead = True
            from ghidra.core.error import DecoderError

            raise DecoderError("Expecting signed integer attribute")
        self._attributeRead = True
        return res

    def readSignedIntegerExpectString(
        self,
        expect_or_attribId,
        expect_str: Optional[str] = None,
        expectval: int = 0,
    ) -> int:
        if isinstance(expect_or_attribId, AttributeId):
            self.findMatchingAttribute(expect_or_attribId)
            res = self.readSignedIntegerExpectString(expect_str, expectval)
            self._curPos = self._copyPosition(self._startPos)
            return res

        tmpPos = self._copyPosition(self._curPos)
        header1 = self.getNextByte(tmpPos)
        if (header1 & _PF.HEADEREXTEND_MASK) != 0:
            self.getNextByte(tmpPos)
        typeByte = self.getNextByte(tmpPos)
        if (typeByte >> _PF.TYPECODE_SHIFT) == _PF.TYPECODE_STRING:
            val = self.readString()
            if val != expect_or_attribId:
                from ghidra.core.error import DecoderError

                raise DecoderError(
                    f'Expecting string "{expect_or_attribId}" but read "{val}"'
                )
            return expect_str if expect_str is not None else expectval
        return self.readSignedInteger()

    def readUnsignedInteger(self, attribId: Optional[AttributeId] = None) -> int:
        if attribId is not None:
            self.findMatchingAttribute(attribId)
            res = self.readUnsignedInteger()
            self._curPos = self._copyPosition(self._startPos)
            return res
        header1 = self.getNextByte(self._curPos)
        if (header1 & _PF.HEADEREXTEND_MASK) != 0:
            self.getNextByte(self._curPos)
        typeByte = self.getNextByte(self._curPos)
        if (typeByte >> _PF.TYPECODE_SHIFT) != _PF.TYPECODE_UNSIGNEDINT:
            self.skipAttributeRemaining(typeByte)
            self._attributeRead = True
            from ghidra.core.error import DecoderError

            raise DecoderError("Expecting unsigned integer attribute")
        res = self.readInteger(self.readLengthCode(typeByte))
        self._attributeRead = True
        return res

    def readString(self, attribId: Optional[AttributeId] = None) -> str:
        if attribId is not None:
            self.findMatchingAttribute(attribId)
            res = self.readString()
            self._curPos = self._copyPosition(self._startPos)
            return res
        header1 = self.getNextByte(self._curPos)
        if (header1 & _PF.HEADEREXTEND_MASK) != 0:
            self.getNextByte(self._curPos)
        typeByte = self.getNextByte(self._curPos)
        if (typeByte >> _PF.TYPECODE_SHIFT) != _PF.TYPECODE_STRING:
            self.skipAttributeRemaining(typeByte)
            self._attributeRead = True
            from ghidra.core.error import DecoderError

            raise DecoderError("Expecting string attribute")
        length = self.readInteger(self.readLengthCode(typeByte))
        self._attributeRead = True
        if length == 0:
            return ""

        curLen = self._curPos.end - self._curPos.current
        if curLen >= length:
            chunk = self._inStream[self._curPos.seqIter].start
            res = bytes(chunk[self._curPos.current:self._curPos.current + length])
            self.advancePosition(self._curPos, length)
            return res.decode("utf-8", errors="replace")

        res = bytearray()
        while length > 0:
            curLen = self._curPos.end - self._curPos.current
            if curLen > length:
                curLen = length
            chunk = self._inStream[self._curPos.seqIter].start
            res.extend(chunk[self._curPos.current:self._curPos.current + curLen])
            length -= curLen
            self.advancePosition(self._curPos, curLen)
        return bytes(res).decode("utf-8", errors="replace")

    def readSpace(self, attribId: Optional[AttributeId] = None) -> AddrSpace:
        if attribId is not None:
            self.findMatchingAttribute(attribId)
            res = self.readSpace()
            self._curPos = self._copyPosition(self._startPos)
            return res

        header1 = self.getNextByte(self._curPos)
        if (header1 & _PF.HEADEREXTEND_MASK) != 0:
            self.getNextByte(self._curPos)
        typeByte = self.getNextByte(self._curPos)
        typeCode = typeByte >> _PF.TYPECODE_SHIFT
        if typeCode == _PF.TYPECODE_ADDRESSSPACE:
            idx = self.readInteger(self.readLengthCode(typeByte))
            spc = self.spcManager.getSpace(idx) if self.spcManager is not None else None
            if spc is None:
                from ghidra.core.error import DecoderError

                raise DecoderError("Unknown address space index")
        elif typeCode == _PF.TYPECODE_SPECIALSPACE:
            specialCode = self.readLengthCode(typeByte)
            if specialCode == _PF.SPECIALSPACE_STACK:
                spc = self.spcManager.getStackSpace() if self.spcManager is not None else None
            elif specialCode == _PF.SPECIALSPACE_JOIN:
                spc = self.spcManager.getJoinSpace() if self.spcManager is not None else None
            else:
                from ghidra.core.error import DecoderError

                raise DecoderError("Cannot marshal special address space")
        else:
            self.skipAttributeRemaining(typeByte)
            self._attributeRead = True
            from ghidra.core.error import DecoderError

            raise DecoderError("Expecting space attribute")
        self._attributeRead = True
        return spc

    def readOpcode(self, attribId: Optional[AttributeId] = None) -> OpCode:
        if attribId is not None:
            self.findMatchingAttribute(attribId)
            opc = self.readOpcode()
            self._curPos = self._copyPosition(self._startPos)
            return opc
        val = self.readSignedInteger()
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

    def __init__(self, stream: io.BytesIO) -> None:
        self._stream: io.BytesIO = stream

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
