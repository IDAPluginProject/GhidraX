"""
Corresponds to: type.hh / type.cc

Classes for describing and printing data-types.
Core Datatype hierarchy and TypeFactory.
"""

from __future__ import annotations

from abc import abstractmethod
from enum import IntEnum
from typing import TYPE_CHECKING, Optional, List, Dict, Tuple

from ghidra.core.address import calc_mask
from ghidra.core.error import LowlevelError
from ghidra.core.marshal import (
    AttributeId, ElementId, Encoder, Decoder,
    ATTRIB_NAME, ATTRIB_SIZE, ATTRIB_METATYPE, ATTRIB_ID,
)

if TYPE_CHECKING:
    from ghidra.core.space import AddrSpace


def _coveringmask(val: int) -> int:
    """Return smallest number of form 2^n-1, >= the given value.

    C++ ref: coveringmask() in address.cc
    """
    res = val
    sz = 1
    while sz < 64:
        res = res | (res >> sz)
        sz <<= 1
    return res


def _subtype_result(subtype, newoff: int, out_holder=None):
    """Return Python-friendly or C++-style getSubType results.

    Native ``Datatype::getSubType`` returns the subtype directly and writes the
    adjusted offset through an out-parameter. Older Python ports returned a
    ``(subtype, newoff)`` tuple. Support both calling conventions.
    """
    if isinstance(out_holder, list):
        if out_holder:
            out_holder[0] = newoff
        else:
            out_holder.append(newoff)
        return subtype
    return subtype, newoff


# =========================================================================
# Metatype enums
# =========================================================================

class MetaType(IntEnum):
    """The core meta-types supported by the decompiler."""
    TYPE_PARTIALUNION = 0
    TYPE_PARTIALSTRUCT = 1
    TYPE_PARTIALENUM = 2
    TYPE_UNION = 3
    TYPE_STRUCT = 4
    TYPE_ENUM_INT = 5
    TYPE_ENUM_UINT = 6
    TYPE_ARRAY = 7
    TYPE_PTRREL = 8
    TYPE_PTR = 9
    TYPE_FLOAT = 10
    TYPE_CODE = 11
    TYPE_BOOL = 12
    TYPE_UINT = 13
    TYPE_INT = 14
    TYPE_UNKNOWN = 15
    TYPE_SPACEBASE = 16
    TYPE_VOID = 17


# Re-export for C-style access
TYPE_VOID = MetaType.TYPE_VOID
TYPE_SPACEBASE = MetaType.TYPE_SPACEBASE
TYPE_UNKNOWN = MetaType.TYPE_UNKNOWN
TYPE_INT = MetaType.TYPE_INT
TYPE_UINT = MetaType.TYPE_UINT
TYPE_BOOL = MetaType.TYPE_BOOL
TYPE_CODE = MetaType.TYPE_CODE
TYPE_FLOAT = MetaType.TYPE_FLOAT
TYPE_PTR = MetaType.TYPE_PTR
TYPE_PTRREL = MetaType.TYPE_PTRREL
TYPE_ARRAY = MetaType.TYPE_ARRAY
TYPE_ENUM_UINT = MetaType.TYPE_ENUM_UINT
TYPE_ENUM_INT = MetaType.TYPE_ENUM_INT
TYPE_STRUCT = MetaType.TYPE_STRUCT
TYPE_UNION = MetaType.TYPE_UNION
TYPE_PARTIALENUM = MetaType.TYPE_PARTIALENUM
TYPE_PARTIALSTRUCT = MetaType.TYPE_PARTIALSTRUCT
TYPE_PARTIALUNION = MetaType.TYPE_PARTIALUNION


class SubMetaType(IntEnum):
    """Specializations of the core meta-types."""
    SUB_PARTIALUNION = 0
    SUB_UNION = 1
    SUB_STRUCT = 2
    SUB_ARRAY = 3
    SUB_PTR_STRUCT = 4
    SUB_PTRREL = 5
    SUB_PTR = 6
    SUB_PTRREL_UNK = 7
    SUB_FLOAT = 8
    SUB_CODE = 9
    SUB_BOOL = 10
    SUB_UINT_UNICODE = 11
    SUB_INT_UNICODE = 12
    SUB_UINT_ENUM = 13
    SUB_UINT_PARTIALENUM = 14
    SUB_INT_ENUM = 15
    SUB_UINT_PLAIN = 16
    SUB_INT_PLAIN = 17
    SUB_UINT_CHAR = 18
    SUB_INT_CHAR = 19
    SUB_PARTIALSTRUCT = 20
    SUB_UNKNOWN = 21
    SUB_SPACEBASE = 22
    SUB_VOID = 23


class TypeClass(IntEnum):
    """Data-type classes for the purpose of assigning storage."""
    TYPECLASS_GENERAL = 0
    TYPECLASS_FLOAT = 1
    TYPECLASS_PTR = 2
    TYPECLASS_HIDDENRET = 3
    TYPECLASS_VECTOR = 4


# Re-export TypeClass members at module level
TYPECLASS_GENERAL = TypeClass.TYPECLASS_GENERAL
TYPECLASS_FLOAT = TypeClass.TYPECLASS_FLOAT
TYPECLASS_PTR = TypeClass.TYPECLASS_PTR
TYPECLASS_HIDDENRET = TypeClass.TYPECLASS_HIDDENRET
TYPECLASS_VECTOR = TypeClass.TYPECLASS_VECTOR


# Mapping from MetaType to default SubMetaType
_BASE2SUB: Dict[int, SubMetaType] = {
    MetaType.TYPE_VOID: SubMetaType.SUB_VOID,
    MetaType.TYPE_SPACEBASE: SubMetaType.SUB_SPACEBASE,
    MetaType.TYPE_UNKNOWN: SubMetaType.SUB_UNKNOWN,
    MetaType.TYPE_INT: SubMetaType.SUB_INT_PLAIN,
    MetaType.TYPE_UINT: SubMetaType.SUB_UINT_PLAIN,
    MetaType.TYPE_BOOL: SubMetaType.SUB_BOOL,
    MetaType.TYPE_CODE: SubMetaType.SUB_CODE,
    MetaType.TYPE_FLOAT: SubMetaType.SUB_FLOAT,
    MetaType.TYPE_PTR: SubMetaType.SUB_PTR,
    MetaType.TYPE_PTRREL: SubMetaType.SUB_PTRREL,
    MetaType.TYPE_ARRAY: SubMetaType.SUB_ARRAY,
    MetaType.TYPE_STRUCT: SubMetaType.SUB_STRUCT,
    MetaType.TYPE_UNION: SubMetaType.SUB_UNION,
    MetaType.TYPE_ENUM_INT: SubMetaType.SUB_INT_ENUM,
    MetaType.TYPE_ENUM_UINT: SubMetaType.SUB_UINT_ENUM,
    MetaType.TYPE_PARTIALENUM: SubMetaType.SUB_UINT_PARTIALENUM,
    MetaType.TYPE_PARTIALSTRUCT: SubMetaType.SUB_PARTIALSTRUCT,
    MetaType.TYPE_PARTIALUNION: SubMetaType.SUB_PARTIALUNION,
}


def metatype2string(mt: MetaType) -> str:
    _map = {
        TYPE_VOID: "void", TYPE_SPACEBASE: "spacebase", TYPE_UNKNOWN: "unknown",
        TYPE_INT: "int", TYPE_UINT: "uint", TYPE_BOOL: "bool",
        TYPE_CODE: "code", TYPE_FLOAT: "float", TYPE_PTR: "ptr",
        TYPE_PTRREL: "ptrrel", TYPE_ARRAY: "array", TYPE_STRUCT: "struct",
        TYPE_UNION: "union", TYPE_ENUM_INT: "enum", TYPE_ENUM_UINT: "enum",
        TYPE_PARTIALENUM: "partialenum", TYPE_PARTIALSTRUCT: "partialstruct",
        TYPE_PARTIALUNION: "partialunion",
    }
    return _map.get(mt, "unknown")


def string2metatype(s: str) -> MetaType:
    _map = {
        "void": TYPE_VOID, "spacebase": TYPE_SPACEBASE, "unknown": TYPE_UNKNOWN,
        "int": TYPE_INT, "uint": TYPE_UINT, "bool": TYPE_BOOL,
        "code": TYPE_CODE, "float": TYPE_FLOAT, "ptr": TYPE_PTR,
        "ptrrel": TYPE_PTRREL, "array": TYPE_ARRAY, "struct": TYPE_STRUCT,
        "union": TYPE_UNION, "enum": TYPE_ENUM_INT,
        "partialstruct": TYPE_PARTIALSTRUCT, "partialunion": TYPE_PARTIALUNION,
    }
    return _map.get(s, TYPE_UNKNOWN)


def string2typeclass(s: str) -> TypeClass:
    _map = {
        "general": TypeClass.TYPECLASS_GENERAL,
        "float": TypeClass.TYPECLASS_FLOAT,
        "ptr": TypeClass.TYPECLASS_PTR,
        "hiddenret": TypeClass.TYPECLASS_HIDDENRET,
        "vector": TypeClass.TYPECLASS_VECTOR,
    }
    return _map.get(s, TypeClass.TYPECLASS_GENERAL)


def metatype2typeclass(meta: MetaType) -> TypeClass:
    if meta == TYPE_FLOAT:
        return TypeClass.TYPECLASS_FLOAT
    if meta in (TYPE_PTR, TYPE_PTRREL):
        return TypeClass.TYPECLASS_PTR
    return TypeClass.TYPECLASS_GENERAL


# =========================================================================
# TypeField
# =========================================================================

class TypeField:
    """A field within a structure or union."""

    def __init__(self, ident: int = 0, offset: int = 0,
                 name: str = "", type_: Optional[Datatype] = None) -> None:
        self.ident: int = ident
        self.offset: int = offset
        self.name: str = name
        self.type: Optional[Datatype] = type_

    def __lt__(self, other: TypeField) -> bool:
        return self.offset < other.offset

    def __repr__(self) -> str:
        tname = self.type.getName() if self.type else "?"
        return f"TypeField({self.name}, off={self.offset}, type={tname})"


# =========================================================================
# Datatype (base class)
# =========================================================================

class Datatype:
    """The base datatype class for the decompiler.

    Used for symbols, function prototypes, type propagation, etc.
    """

    # Boolean properties
    coretype = 1
    chartype = 2
    enumtype = 4
    poweroftwo = 8
    utf16 = 16
    utf32 = 32
    opaque_string = 64
    variable_length = 128
    has_stripped = 0x100
    is_ptrrel = 0x200
    type_incomplete = 0x400
    needs_resolution = 0x800
    force_format = 0x7000
    truncate_bigendian = 0x8000
    pointer_to_array = 0x10000
    warning_issued = 0x20000

    def __init__(self, size: int = 0, align: int = -1,
                 metatype: MetaType = TYPE_UNKNOWN) -> None:
        self.id: int = 0
        self.size: int = size
        self.flags: int = 0
        self.name: str = ""
        self.displayName: str = ""
        self.metatype: MetaType = metatype
        self.submeta: SubMetaType = _BASE2SUB.get(metatype, SubMetaType.SUB_UNKNOWN)
        self.typedefImm: Optional[Datatype] = None
        self.alignment: int = align if align > 0 else 0
        self.alignSize: int = size

    # --- Property queries ---

    def isCoreType(self) -> bool:
        return (self.flags & Datatype.coretype) != 0

    def isCharPrint(self) -> bool:
        return (self.flags & (Datatype.chartype | Datatype.utf16 | Datatype.utf32 | Datatype.opaque_string)) != 0

    def isEnumType(self) -> bool:
        return (self.flags & Datatype.enumtype) != 0

    def isASCII(self) -> bool:
        return (self.flags & Datatype.chartype) != 0

    def isUTF16(self) -> bool:
        return (self.flags & Datatype.utf16) != 0

    def isUTF32(self) -> bool:
        return (self.flags & Datatype.utf32) != 0

    def isVariableLength(self) -> bool:
        return (self.flags & Datatype.variable_length) != 0

    def isOpaqueString(self) -> bool:
        return (self.flags & Datatype.opaque_string) != 0

    def isPointerToArray(self) -> bool:
        return (self.flags & Datatype.pointer_to_array) != 0

    def isPointerRel(self) -> bool:
        return (self.flags & Datatype.is_ptrrel) != 0

    def hasStripped(self) -> bool:
        return (self.flags & Datatype.has_stripped) != 0

    def isIncomplete(self) -> bool:
        return (self.flags & Datatype.type_incomplete) != 0

    def needsResolution(self) -> bool:
        return (self.flags & Datatype.needs_resolution) != 0

    def getInheritable(self) -> int:
        return self.flags & Datatype.coretype

    def getDisplayFormat(self) -> int:
        return (self.flags & Datatype.force_format) >> 12

    def setDisplayFormat(self, fmt: int) -> None:
        self.flags = (self.flags & ~Datatype.force_format) | ((fmt & 0x7) << 12)

    @staticmethod
    def encodeIntegerFormat(val: str) -> int:
        """Encode a display format string to an integer.

        C++ ref: Datatype::encodeIntegerFormat
        """
        _map = {"hex": 1, "dec": 2, "oct": 3, "bin": 4, "char": 5}
        if val in _map:
            return _map[val]
        raise ValueError(f"Unrecognized integer format: {val}")

    @staticmethod
    def decodeIntegerFormat(val: int) -> str:
        """Decode a display format integer to a string.

        C++ ref: Datatype::decodeIntegerFormat
        """
        _map = {1: "hex", 2: "dec", 3: "oct", 4: "bin", 5: "char"}
        if val in _map:
            return _map[val]
        raise ValueError("Unrecognized integer format encoding")

    def getMetatype(self) -> MetaType:
        return self.metatype

    def getSubMeta(self) -> SubMetaType:
        return self.submeta

    def getId(self) -> int:
        return self.id

    def getSize(self) -> int:
        return self.size

    def getAlignSize(self) -> int:
        return self.alignSize

    def getAlignment(self) -> int:
        return self.alignment

    def getName(self) -> str:
        return self.name

    def getDisplayName(self) -> str:
        return self.displayName if self.displayName else self.name

    def getTypedef(self) -> Optional[Datatype]:
        return self.typedefImm

    # --- Virtual methods ---

    def printRaw(self) -> str:
        return self.name if self.name else metatype2string(self.metatype)

    def getSubType(self, off: int, newoff=None):
        """Recover component data-type one-level down. Returns (subtype, newoff)."""
        return _subtype_result(None, off, newoff)

    def findTruncation(self, off: int, sz: int, op=None, slot: int = -1) -> Tuple[Optional[TypeField], int]:
        """Find an immediate subfield given a byte range.

        C++ ref: Datatype::findTruncation
        Returns (field, newoff) or (None, 0).
        """
        return None, 0

    def nearestArrayedComponentForward(self, off: int) -> Tuple[Optional[Datatype], int, int]:
        """Find first array component at or after offset.

        C++ ref: Datatype::nearestArrayedComponentForward
        Returns (subtype, newoff, elSize) or (None, 0, 0).
        """
        return None, 0, 0

    def nearestArrayedComponentBackward(self, off: int) -> Tuple[Optional[Datatype], int, int]:
        """Find last array component at or before offset.

        C++ ref: Datatype::nearestArrayedComponentBackward
        Returns (subtype, newoff, elSize) or (None, 0, 0).
        """
        return None, 0, 0

    def numDepend(self) -> int:
        return 0

    def getDepend(self, index: int) -> Optional[Datatype]:
        return None

    def getHoleSize(self, off: int) -> int:
        return 0

    def printNameBase(self, s: list) -> None:
        """Print short prefix of type name for variable naming.

        C++ ref: Datatype::printNameBase
        """
        if self.name:
            s.append(self.name[0])

    @abstractmethod
    def clone(self) -> Datatype:
        ...

    def compare(self, op: Datatype, level: int) -> int:
        """Order types for propagation."""
        if self.submeta != op.submeta:
            return -1 if self.submeta < op.submeta else 1
        if self.size != op.size:
            return -1 if self.size < op.size else 1
        return 0

    def compareDependency(self, op: Datatype) -> int:
        """Compare for storage in tree structure."""
        if self.submeta != op.submeta:
            return -1 if self.submeta < op.submeta else 1
        if self.size != op.size:
            return -1 if self.size < op.size else 1
        return 0

    def typeOrder(self, op: Datatype) -> int:
        if self is op:
            return 0
        return self.compare(op, 10)

    def typeOrderBool(self, op: Datatype) -> int:
        """Order types, treating bool as least preferred.

        C++ ref: Datatype::typeOrderBool
        """
        if self is op:
            return 0
        if self.metatype == TYPE_BOOL:
            return 1
        if op.metatype == TYPE_BOOL:
            return -1
        return self.compare(op, 10)

    def resolveInFlow(self, op, slot: int) -> Datatype:
        """Resolve data-type based on PcodeOp use (for unions).

        C++ ref: Datatype::resolveInFlow
        """
        return self

    def findResolve(self, op, slot: int) -> Datatype:
        """Find a previously resolved sub-type.

        C++ ref: Datatype::findResolve
        """
        return self

    def findCompatibleResolve(self, ct: Datatype) -> int:
        """Find a resolution compatible with the given data-type.

        C++ ref: Datatype::findCompatibleResolve
        Returns index or -1.
        """
        return -1

    def resolveTruncation(self, offset: int, op, slot: int) -> Tuple[Optional[TypeField], int]:
        """Resolve truncation for union-like types.

        C++ ref: Datatype::resolveTruncation
        Returns (field, newoff) or (None, 0).
        """
        return None, 0

    def isPtrsubMatching(self, off: int, extra: int, multiplier: int) -> bool:
        """Is this data-type suitable as input to a CPUI_PTRSUB op.

        C++ ref: Datatype::isPtrsubMatching
        """
        return False

    def getStripped(self) -> Optional[Datatype]:
        return None

    def isPieceStructured(self) -> bool:
        return False

    def isPrimitiveWhole(self) -> bool:
        """Is this made up of a single primitive.

        C++ ref: Datatype::isPrimitiveWhole
        """
        if not self.isPieceStructured():
            return True
        if self.metatype in (TYPE_ARRAY, TYPE_STRUCT):
            if self.numDepend() > 0:
                component = self.getDepend(0)
                if component is not None and component.getSize() == self.getSize():
                    return component.isPrimitiveWhole()
        return False

    def hasSameVariableBase(self, ct: Datatype) -> bool:
        """Are these the same variable length data-type.

        C++ ref: Datatype::hasSameVariableBase
        """
        if not self.isVariableLength() or not ct.isVariableLength():
            return False
        return self.getUnsizedId() == ct.getUnsizedId()

    def isFormalPointerRel(self) -> bool:
        """Is this a non-ephemeral TypePointerRel.

        C++ ref: Datatype::isFormalPointerRel
        """
        return (self.flags & (Datatype.is_ptrrel | Datatype.has_stripped)) == Datatype.is_ptrrel

    def getUnsizedId(self) -> int:
        """Get the type id without variable-length size adjustment.

        C++ ref: Datatype::getUnsizedId
        """
        if (self.flags & Datatype.variable_length) != 0:
            return Datatype.hashSize(self.id, self.size)
        return self.id

    @staticmethod
    def calcAlignSize(sz: int, align: int) -> int:
        """Calculate aligned size.

        C++ ref: Datatype::calcAlignSize
        """
        if align <= 0:
            return sz
        mod = sz % align
        if mod != 0:
            return sz + (align - mod)
        return sz

    def markComplete(self) -> None:
        self.flags &= ~Datatype.type_incomplete

    @staticmethod
    def hashName(nm: str) -> int:
        h = 123
        for ch in nm:
            h = (h * 301 + ord(ch)) & 0xFFFFFFFFFFFFFFFF
        return h

    @staticmethod
    def hashSize(id_: int, size: int) -> int:
        return (id_ * 0x100000001b3 + size) & 0xFFFFFFFFFFFFFFFF

    def __repr__(self) -> str:
        return f"{type(self).__name__}({self.name!r}, size={self.size}, meta={self.metatype.name})"


# =========================================================================
# Concrete Datatype subclasses
# =========================================================================

class TypeBase(Datatype):
    """Base class for the fundamental atomic types."""

    def __init__(self, size: int = 0, metatype: MetaType = TYPE_UNKNOWN,
                 name: str = "") -> None:
        super().__init__(size, -1, metatype)
        if name:
            self.name = name
            self.displayName = name

    def clone(self) -> TypeBase:
        t = TypeBase(self.size, self.metatype, self.name)
        t.id = self.id
        t.flags = self.flags
        t.submeta = self.submeta
        return t


class TypeChar(TypeBase):
    """Base type for character data-types (UTF-8 encoded)."""

    def __init__(self, name: str = "char") -> None:
        super().__init__(1, TYPE_INT, name)
        self.flags |= Datatype.chartype
        self.submeta = SubMetaType.SUB_INT_CHAR

    def clone(self) -> TypeChar:
        t = TypeChar(self.name)
        t.id = self.id
        t.flags = self.flags
        return t


class TypeUnicode(TypeBase):
    """The unicode data-type (wchar)."""

    def __init__(self, name: str = "wchar", size: int = 2,
                 metatype: MetaType = TYPE_INT) -> None:
        super().__init__(size, metatype, name)
        if size == 2:
            self.flags |= Datatype.utf16
            self.submeta = SubMetaType.SUB_INT_UNICODE
        elif size == 4:
            self.flags |= Datatype.utf32
            self.submeta = SubMetaType.SUB_INT_UNICODE

    def setflags(self) -> None:
        """Set encoding flags based on size.

        C++ ref: TypeUnicode::setflags
        """
        if self.size == 2:
            self.flags |= Datatype.utf16
        elif self.size == 4:
            self.flags |= Datatype.utf32
        elif self.size == 1:
            self.flags |= Datatype.chartype

    def clone(self) -> TypeUnicode:
        t = TypeUnicode(self.name, self.size, self.metatype)
        t.id = self.id
        t.flags = self.flags
        return t


class TypeVoid(Datatype):
    """Formal "void" data-type object."""

    def __init__(self) -> None:
        super().__init__(0, 1, TYPE_VOID)
        self.name = "void"
        self.displayName = "void"
        self.flags |= Datatype.coretype

    def clone(self) -> TypeVoid:
        t = TypeVoid()
        t.id = self.id
        return t


class TypePointer(Datatype):
    """Datatype object representing a pointer."""

    def __init__(self, size: int = 0, ptrto: Optional[Datatype] = None,
                 wordsize: int = 1, spaceid: Optional[AddrSpace] = None) -> None:
        super().__init__(size, -1, TYPE_PTR)
        self.ptrto: Optional[Datatype] = ptrto
        self.wordsize: int = wordsize
        self.spaceid: Optional[AddrSpace] = spaceid
        self.truncate: Optional[TypePointer] = None
        if ptrto is not None:
            self.flags = ptrto.getInheritable()
        self._calcSubmeta()

    def calcSubmeta(self) -> None:
        """C++ ref: TypePointer::calcSubmeta"""
        self._calcSubmeta()

    def _calcSubmeta(self) -> None:
        """C++ ref: TypePointer::calcSubmeta (internal)"""
        if self.ptrto is None:
            self.submeta = SubMetaType.SUB_PTR
            return
        mt = self.ptrto.getMetatype()
        if mt == TYPE_STRUCT:
            if self.ptrto.numDepend() > 1 or (hasattr(self.ptrto, 'isIncomplete') and self.ptrto.isIncomplete()):
                self.submeta = SubMetaType.SUB_PTR_STRUCT
            else:
                self.submeta = SubMetaType.SUB_PTR
        elif mt == TYPE_UNION:
            self.submeta = SubMetaType.SUB_PTR_STRUCT
        elif mt == TYPE_ARRAY:
            self.submeta = SubMetaType.SUB_PTR
            self.flags |= Datatype.pointer_to_array
        else:
            self.submeta = SubMetaType.SUB_PTR
        if hasattr(self.ptrto, 'needsResolution') and self.ptrto.needsResolution() and mt != TYPE_PTR:
            self.flags |= Datatype.needs_resolution

    def getPtrTo(self) -> Optional[Datatype]:
        return self.ptrto

    def getWordSize(self) -> int:
        return self.wordsize

    def getSpace(self) -> Optional[AddrSpace]:
        return self.spaceid

    def numDepend(self) -> int:
        return 1

    def getDepend(self, index: int) -> Optional[Datatype]:
        return self.ptrto

    def getSubType(self, off: int, newoff=None):
        if self.ptrto is not None:
            return _subtype_result(self.ptrto, off, newoff)
        return _subtype_result(None, off, newoff)

    def compare(self, op: Datatype, level: int) -> int:
        res = super().compare(op, level)
        if res != 0:
            return res
        if not isinstance(op, TypePointer):
            return 0
        if level <= 0:
            return 0
        if self.ptrto is not None and op.ptrto is not None:
            return self.ptrto.compare(op.ptrto, level - 1)
        return 0

    def compareDependency(self, op: Datatype) -> int:
        res = super().compareDependency(op)
        if res != 0:
            return res
        if not isinstance(op, TypePointer):
            return 0
        if self.wordsize != op.wordsize:
            return -1 if self.wordsize < op.wordsize else 1
        # Compare pointed-to types by id
        a_id = self.ptrto.getId() if self.ptrto else 0
        b_id = op.ptrto.getId() if op.ptrto else 0
        if a_id != b_id:
            return -1 if a_id < b_id else 1
        return 0

    def clone(self) -> TypePointer:
        t = TypePointer(self.size, self.ptrto, self.wordsize, self.spaceid)
        t.id = self.id
        t.flags = self.flags
        t.name = self.name
        t.displayName = self.displayName
        return t

    def printNameBase(self, s: list) -> None:
        """C++ ref: TypePointer::printNameBase — 'p' + base name."""
        s.append('p')
        if self.ptrto is not None:
            self.ptrto.printNameBase(s)

    def printRaw(self) -> str:
        base = self.ptrto.printRaw() if self.ptrto else "?"
        return f"{base} *"

    @staticmethod
    def testForArraySlack(dt: Datatype, off: int) -> bool:
        """Test if an out-of-bounds offset makes sense as array slack.

        C++ ref: TypePointer::testForArraySlack
        """
        if dt is None:
            return False
        if dt.getMetatype() == TYPE_ARRAY:
            base = dt.getDepend(0)
            if base is not None:
                align_sz = base.getAlignSize()
                if align_sz > 0 and off >= 0 and off < align_sz:
                    return True
        return False

    def downChain(self, off: int, allowArrayWrap: bool, typegrp: TypeFactory) -> Tuple[Optional[TypePointer], int, Optional[TypePointer], int]:
        """Walk down pointer chain to a sub-component.

        C++ ref: TypePointer::downChain
        Returns (result_ptr, new_off, parent_ptr, parent_off) or (None, off, None, 0).
        """
        if self.ptrto is None:
            return None, off, None, 0
        ptrto_size = self.ptrto.getAlignSize()
        par: Optional[TypePointer] = None
        parOff: int = 0
        if off < 0 or off >= ptrto_size:
            if ptrto_size != 0 and not self.ptrto.isVariableLength():
                if not allowArrayWrap:
                    return None, off, None, 0
                # Sign extend and wrap
                bit_width = self.size * 8
                mask = (1 << bit_width) - 1
                sign_off = off & mask
                if sign_off >= (1 << (bit_width - 1)):
                    sign_off -= (1 << bit_width)
                sign_off = sign_off % ptrto_size
                if sign_off < 0:
                    sign_off += ptrto_size
                off = sign_off
                if off == 0:
                    return self, off, None, 0

        if self.ptrto.isEnumType():
            tmp = typegrp.getBase(1, TYPE_UINT)
            off = 0
            return typegrp.getTypePointer(self.size, tmp, self.wordsize), off, None, 0

        meta = self.ptrto.getMetatype()
        is_array = (meta == TYPE_ARRAY)
        if is_array or meta == TYPE_STRUCT:
            par = self
            parOff = off

        pt, off = self.ptrto.getSubType(off)
        if pt is None:
            return None, off, par, parOff
        if not is_array:
            return typegrp.getTypePointerStripArray(self.size, pt, self.wordsize), off, par, parOff
        return typegrp.getTypePointer(self.size, pt, self.wordsize), off, par, parOff

    def isPtrsubMatching(self, off: int, extra: int, multiplier: int) -> bool:
        """Is this data-type suitable as input to a CPUI_PTRSUB op.

        C++ ref: TypePointer::isPtrsubMatching
        """
        if self.ptrto is None:
            return False
        meta = self.ptrto.getMetatype()
        if meta == TYPE_SPACEBASE:
            newoff = off * self.wordsize  # addressToByteInt
            subtype, newoff = self.ptrto.getSubType(newoff)
            if subtype is None or newoff != 0:
                return False
            extra_bytes = extra * self.wordsize
            if extra_bytes < 0 or extra_bytes >= subtype.getSize():
                if not TypePointer.testForArraySlack(subtype, extra_bytes):
                    return False
        elif meta == TYPE_ARRAY:
            if off != 0:
                return False
            mult_bytes = multiplier * self.wordsize
            if mult_bytes >= self.ptrto.getAlignSize():
                return False
        elif meta == TYPE_STRUCT:
            typesize = self.ptrto.getSize()
            mult_bytes = multiplier * self.wordsize
            if mult_bytes >= self.ptrto.getAlignSize():
                return False
            newoff = off * self.wordsize
            extra_bytes = extra * self.wordsize
            subtype, newoff = self.ptrto.getSubType(newoff)
            if subtype is not None:
                if newoff != 0:
                    return False
                if extra_bytes < 0 or extra_bytes >= subtype.getSize():
                    if not TypePointer.testForArraySlack(subtype, extra_bytes):
                        return False
            else:
                extra_bytes += newoff
                if (extra_bytes < 0 or extra_bytes >= typesize) and typesize != 0:
                    return False
        elif meta == TYPE_UNION:
            return False
        else:
            return False
        return True

    def resolveInFlow(self, op, slot: int) -> Datatype:
        """Resolve pointer-to-union based on PcodeOp use.

        C++ ref: TypePointer::resolveInFlow
        """
        if self.ptrto is not None and self.ptrto.getMetatype() == TYPE_UNION:
            fd = op.getParent().getFuncdata() if hasattr(op.getParent(), 'getFuncdata') else None
            if fd is not None:
                from ghidra.types.resolve import ResolvedUnion, ScoreUnionFields
                res = fd.getUnionField(self, op, slot)
                if res is not None:
                    return res.getDatatype()
                scoreFields = ScoreUnionFields(fd.getArch().types, self, op, slot)
                fd.setUnionField(self, op, slot, scoreFields.getResult())
                return scoreFields.getResult().getDatatype()
        return self

    def findResolve(self, op, slot: int) -> Datatype:
        """Find previously resolved pointer-to-union sub-type.

        C++ ref: TypePointer::findResolve
        """
        if self.ptrto is not None and self.ptrto.getMetatype() == TYPE_UNION:
            fd = op.getParent().getFuncdata() if hasattr(op.getParent(), 'getFuncdata') else None
            if fd is not None:
                res = fd.getUnionField(self, op, slot)
                if res is not None:
                    return res.getDatatype()
        return self

    def calcTruncate(self, typegrp: TypeFactory) -> None:
        """Assign a truncated pointer subcomponent if necessary.

        C++ ref: TypePointer::calcTruncate
        """
        if self.truncate is not None:
            return
        if self.ptrto is None or self.ptrto.getSize() <= 0:
            return
        # Check if the pointed-to type has a sub-type at offset 0
        # that is smaller than the pointed-to type
        sub, newoff = self.ptrto.getSubType(0)
        if sub is not None and sub.getSize() < self.ptrto.getSize() and newoff == 0:
            self.truncate = typegrp.getTypePointer(self.size, sub, self.wordsize)


class TypeArray(Datatype):
    """Datatype object representing an array of elements."""

    def __init__(self, num_elements: int = 0,
                 arrayof: Optional[Datatype] = None) -> None:
        if arrayof is not None:
            align_size = arrayof.getAlignSize()
            alignment = arrayof.getAlignment()
        else:
            align_size = 0
            alignment = -1
        super().__init__(num_elements * align_size, alignment, TYPE_ARRAY)
        self.arrayof: Optional[Datatype] = arrayof
        self.arraysize: int = num_elements
        if num_elements == 1:
            self.flags |= Datatype.needs_resolution

    def getBase(self) -> Optional[Datatype]:
        return self.arrayof

    def numElements(self) -> int:
        return self.arraysize

    def numDepend(self) -> int:
        return 1

    def getDepend(self, index: int) -> Optional[Datatype]:
        return self.arrayof

    def getSubType(self, off: int, newoff=None):
        if off >= self.size:
            return Datatype.getSubType(self, off, newoff)
        if self.arrayof is not None:
            align_sz = self.arrayof.getAlignSize()
            if align_sz > 0:
                resoff = off % align_sz
                return _subtype_result(self.arrayof, resoff, newoff)
        return _subtype_result(None, off, newoff)

    def getSubEntry(self, off: int, sz: int) -> Tuple[Optional[Datatype], int, int]:
        """Figure out what a byte range overlaps.

        C++ ref: TypeArray::getSubEntry
        Returns (subtype, newoff, element_index) or (None, off, 0).
        """
        if self.arrayof is None:
            return None, off, 0
        noff = off % self.arrayof.getAlignSize() if self.arrayof.getAlignSize() > 0 else off
        el = off // self.arrayof.getAlignSize() if self.arrayof.getAlignSize() > 0 else 0
        if noff + sz > self.arrayof.getSize():
            return None, off, 0
        return self.arrayof, noff, el

    def getHoleSize(self, off: int) -> int:
        """C++ ref: TypeArray::getHoleSize"""
        if self.arrayof is None:
            return 0
        align_sz = self.arrayof.getAlignSize()
        if align_sz <= 0:
            return 0
        noff = off % align_sz
        return self.arrayof.getHoleSize(noff)

    def compare(self, op: Datatype, level: int) -> int:
        res = super().compare(op, level)
        if res != 0:
            return res
        if not isinstance(op, TypeArray):
            return 0
        if self.arraysize != op.arraysize:
            return -1 if self.arraysize < op.arraysize else 1
        if level <= 0:
            return 0
        if self.arrayof and op.arrayof:
            return self.arrayof.compare(op.arrayof, level - 1)
        return 0

    def compareDependency(self, op: Datatype) -> int:
        res = super().compareDependency(op)
        if res != 0:
            return res
        if not isinstance(op, TypeArray):
            return 0
        if self.arraysize != op.arraysize:
            return -1 if self.arraysize < op.arraysize else 1
        a_id = self.arrayof.getId() if self.arrayof else 0
        b_id = op.arrayof.getId() if op.arrayof else 0
        if a_id != b_id:
            return -1 if a_id < b_id else 1
        return 0

    def clone(self) -> TypeArray:
        t = TypeArray(self.arraysize, self.arrayof)
        t.id = self.id
        t.flags = self.flags
        t.name = self.name
        return t

    def resolveInFlow(self, op, slot: int) -> Datatype:
        """Resolve single-element array based on PcodeOp context.

        C++ ref: TypeArray::resolveInFlow
        """
        fd = op.getParent().getFuncdata() if hasattr(op.getParent(), 'getFuncdata') else None
        if fd is not None:
            from ghidra.types.resolve import ResolvedUnion
            res = fd.getUnionField(self, op, slot)
            if res is not None:
                return res.getDatatype()
            fieldNum = TypeStruct.scoreSingleComponent(self, op, slot)
            compFill = ResolvedUnion(self, fieldNum, fd.getArch().types)
            fd.setUnionField(self, op, slot, compFill)
            return compFill.getDatatype()
        return self

    def findResolve(self, op, slot: int) -> Datatype:
        """Find previously resolved array sub-type.

        C++ ref: TypeArray::findResolve
        """
        fd = op.getParent().getFuncdata() if hasattr(op.getParent(), 'getFuncdata') else None
        if fd is not None:
            res = fd.getUnionField(self, op, slot)
            if res is not None:
                return res.getDatatype()
        return self.arrayof if self.arrayof is not None else self

    def findCompatibleResolve(self, ct: Datatype) -> int:
        """Find a resolution compatible with the given data-type.

        C++ ref: TypeArray::findCompatibleResolve
        """
        if self.arrayof is not None:
            if ct.needsResolution() and not self.arrayof.needsResolution():
                if ct.findCompatibleResolve(self.arrayof) >= 0:
                    return 0
            if self.arrayof is ct:
                return 0
        return -1

    def printNameBase(self, s: list) -> None:
        """C++ ref: TypeArray::printNameBase — 'a' + base name."""
        s.append('a')
        if self.arrayof is not None:
            self.arrayof.printNameBase(s)

    def printRaw(self) -> str:
        base = self.arrayof.printRaw() if self.arrayof else "?"
        return f"{base}[{self.arraysize}]"


class TypeEnum(TypeBase):
    """An enumerated Datatype: an integer with named values."""

    def __init__(self, size: int = 0, metatype: MetaType = TYPE_UINT,
                 name: str = "") -> None:
        super().__init__(size, metatype, name)
        self.flags |= Datatype.enumtype
        if metatype == TYPE_ENUM_INT:
            self.metatype = TYPE_INT
            self.submeta = SubMetaType.SUB_INT_ENUM
        else:
            self.metatype = TYPE_UINT
            self.submeta = SubMetaType.SUB_UINT_ENUM
        self.namemap: Dict[int, str] = {}

    def setNameMap(self, nmap: Dict[int, str]) -> None:
        self.namemap = dict(nmap)

    def hasNamedValue(self, val: int) -> bool:
        return val in self.namemap

    def getValueName(self, val: int) -> Optional[str]:
        return self.namemap.get(val)

    def getMatches(self, val: int) -> tuple:
        """Find a representation of a value as OR'd named enum constants.

        C++ ref: TypeEnum::getMatches
        Returns (matchnames: List[str], complement: bool).
        If matchnames is empty, no representation was found.
        """
        mask = calc_mask(self.size)
        for count in range(2):
            matchnames: list = []
            allmatch = True
            curval = val if count == 0 else (val ^ mask)
            if curval == 0:
                if curval in self.namemap:
                    matchnames.append(self.namemap[curval])
                else:
                    allmatch = False
            else:
                bitsleft = curval
                target = curval
                while target != 0:
                    # Find named value <= target with highest bits matching
                    best_key = None
                    for k in self.namemap:
                        if k <= target:
                            if best_key is None or k > best_key:
                                best_key = k
                    if best_key is None:
                        break
                    curv = best_key
                    diff = _coveringmask(bitsleft ^ curv)
                    if diff >= bitsleft:
                        break
                    if (curv & diff) == 0:
                        matchnames.append(self.namemap[curv])
                        bitsleft ^= curv
                        target = bitsleft
                    else:
                        target = curv & ~diff
                allmatch = (bitsleft == 0)
            if allmatch:
                return matchnames, (count == 1)
            val = val  # val stays the same, we use count to switch
        return [], False

    @staticmethod
    def assignValues(namelist: list, vallist: list, assignlist: list, te) -> Dict[int, str]:
        """Establish unique enumeration values for a TypeEnum.

        C++ ref: TypeEnum::assignValues
        Returns the value-to-name map.
        """
        mask = calc_mask(te.getSize())
        nmap: Dict[int, str] = {}
        maxval = 0
        # First pass: explicitly assigned values
        for i in range(len(namelist)):
            if assignlist[i]:
                v = vallist[i]
                if v > maxval:
                    maxval = v
                v &= mask
                if v in nmap:
                    raise ValueError(f'Enum "{te.getName()}": "{namelist[i]}" is a duplicate value')
                nmap[v] = namelist[i]
        # Second pass: auto-assign remaining names
        for i in range(len(namelist)):
            if not assignlist[i]:
                while True:
                    maxval += 1
                    v = maxval & mask
                    if v not in nmap:
                        break
                nmap[v] = namelist[i]
        return nmap

    def clone(self) -> TypeEnum:
        t = TypeEnum(self.size, self.metatype, self.name)
        t.id = self.id
        t.flags = self.flags
        t.namemap = dict(self.namemap)
        return t


class TypePartialEnum(TypeEnum):
    """A data-type that holds part of a TypeEnum and possible additional padding.

    C++ ref: TypePartialEnum
    """

    def __init__(self, parent_or_copy=None, off: int = 0, sz: int = 0,
                 strip: Optional[Datatype] = None) -> None:
        if isinstance(parent_or_copy, TypePartialEnum):
            # Copy constructor
            op = parent_or_copy
            super().__init__(op.size, TYPE_PARTIALENUM)
            self.id = op.id
            self.flags = op.flags
            self.namemap = dict(op.namemap)
            self._stripped = op._stripped
            self._parent = op._parent
            self._offset = op._offset
        else:
            # Normal constructor: TypePartialEnum(parent, off, sz, strip)
            parent = parent_or_copy
            super().__init__(sz, TYPE_PARTIALENUM)
            self.flags |= Datatype.has_stripped
            self._stripped = strip
            self._parent = parent
            self._offset = off

    def getOffset(self) -> int:
        return self._offset

    def getParent(self) -> TypeEnum:
        return self._parent

    def getStripped(self) -> Optional[Datatype]:
        return self._stripped

    def hasStripped(self) -> bool:
        return self._stripped is not None

    def hasNamedValue(self, val: int) -> bool:
        """C++ ref: TypePartialEnum::hasNamedValue"""
        val <<= 8 * self._offset
        return self._parent.hasNamedValue(val)

    def getMatches(self, val: int) -> tuple:
        """C++ ref: TypePartialEnum::getMatches

        Returns (matchnames, complement) with shift info embedded.
        The shiftAmount is self._offset * 8.
        """
        val <<= 8 * self._offset
        matchnames, complement = self._parent.getMatches(val)
        return matchnames, complement

    def getShiftAmount(self) -> int:
        """Return the bit shift amount for this partial enum."""
        return self._offset * 8

    def compare(self, op: Datatype, level: int = 10) -> int:
        """C++ ref: TypePartialEnum::compare"""
        res = Datatype.compare(self, op, level)
        if res != 0:
            return res
        if not isinstance(op, TypePartialEnum):
            return 0
        tp = op
        if self._offset != tp._offset:
            return -1 if self._offset < tp._offset else 1
        level -= 1
        if level < 0:
            if self.id == op.getId():
                return 0
            return -1 if self.id < op.getId() else 1
        return self._parent.compare(tp._parent, level)

    def compareDependency(self, op: Datatype) -> int:
        """C++ ref: TypePartialEnum::compareDependency"""
        if self.submeta != op.getSubMeta():
            return -1 if self.submeta < op.getSubMeta() else 1
        if not isinstance(op, TypePartialEnum):
            return op.getSize() - self.size
        tp = op
        if self._parent is not tp._parent:
            return -1 if id(self._parent) < id(tp._parent) else 1
        if self._offset != tp._offset:
            return -1 if self._offset < tp._offset else 1
        return op.getSize() - self.size

    def clone(self) -> TypePartialEnum:
        return TypePartialEnum(self)

    def printRaw(self) -> str:
        base = self._parent.printRaw() if self._parent else "??"
        return f"{base}[off={self._offset},sz={self.size}]"


class TypeStruct(Datatype):
    """Structure data-type, made up of component datatypes."""

    def __init__(self, name: str = "", size: int = 0) -> None:
        super().__init__(size, -1, TYPE_STRUCT)
        self.name = name
        self.displayName = name
        self.field: List[TypeField] = []

    def numDepend(self) -> int:
        return len(self.field)

    def getDepend(self, index: int) -> Optional[Datatype]:
        if 0 <= index < len(self.field):
            return self.field[index].type
        return None

    def getField(self, i: int) -> TypeField:
        return self.field[i]

    def numFields(self) -> int:
        return len(self.field)

    def getFieldIter(self, off: int) -> int:
        """Binary search for field containing offset.

        C++ ref: TypeStruct::getFieldIter
        Returns field index or -1 if not inside a field.
        """
        lo = 0
        hi = len(self.field) - 1
        while lo <= hi:
            mid = (lo + hi) // 2
            f = self.field[mid]
            if f.offset > off:
                hi = mid - 1
            else:
                if f.type is not None and (f.offset + f.type.getSize()) > off:
                    return mid
                lo = mid + 1
        return -1

    def getLowerBoundField(self, off: int) -> int:
        """Get index of last field at or before offset.

        C++ ref: TypeStruct::getLowerBoundField
        Returns field index or -1.
        """
        if not self.field:
            return -1
        lo = 0
        hi = len(self.field) - 1
        while lo < hi:
            mid = (lo + hi + 1) // 2
            if self.field[mid].offset > off:
                hi = mid - 1
            else:
                lo = mid
        if lo == hi and self.field[lo].offset <= off:
            return lo
        return -1

    def findTruncation(self, off: int, sz: int, op=None, slot: int = -1) -> Tuple[Optional[TypeField], int]:
        """Find field containing byte range [off, off+sz).

        C++ ref: TypeStruct::findTruncation
        Returns (field, newoff) or (None, 0).
        """
        i = self.getFieldIter(off)
        if i < 0:
            return None, 0
        f = self.field[i]
        noff = off - f.offset
        if f.type is not None and noff + sz > f.type.getSize():
            return None, 0
        return f, noff

    def getSubType(self, off: int, newoff=None):
        """C++ ref: TypeStruct::getSubType"""
        i = self.getFieldIter(off)
        if i < 0:
            return Datatype.getSubType(self, off, newoff)
        f = self.field[i]
        return _subtype_result(f.type, off - f.offset, newoff)

    def getHoleSize(self, off: int) -> int:
        """C++ ref: TypeStruct::getHoleSize"""
        i = self.getLowerBoundField(off)
        if i >= 0:
            f = self.field[i]
            noff = off - f.offset
            if f.type is not None and noff < f.type.getSize():
                return f.type.getHoleSize(noff)
        i += 1
        if i < len(self.field):
            return self.field[i].offset - off
        return self.getSize() - off

    def nearestArrayedComponentBackward(self, off: int) -> Tuple[Optional[Datatype], int, int]:
        """C++ ref: TypeStruct::nearestArrayedComponentBackward"""
        first_idx = self.getLowerBoundField(off)
        i = first_idx
        while i >= 0:
            f = self.field[i]
            diff = off - f.offset
            if diff > 128:
                break
            subtype = f.type
            if subtype is not None and subtype.getMetatype() == TYPE_ARRAY:
                base = subtype.getDepend(0)
                el_size = base.getAlignSize() if base is not None else 0
                return subtype, diff, el_size
            elif subtype is not None:
                remain = diff if (i == first_idx) else (subtype.getSize() - 1)
                res, suboff, el_sz = subtype.nearestArrayedComponentBackward(remain)
                if res is not None:
                    return subtype, diff, el_sz
            i -= 1
        return None, 0, 0

    def nearestArrayedComponentForward(self, off: int) -> Tuple[Optional[Datatype], int, int]:
        """C++ ref: TypeStruct::nearestArrayedComponentForward"""
        i = self.getLowerBoundField(off)
        remain = 0
        if i < 0:
            i += 1
            remain = 0
        else:
            f = self.field[i]
            remain = off - f.offset
            if remain != 0 and (f.type is None or f.type.getMetatype() != TYPE_STRUCT or remain >= f.type.getSize()):
                i += 1
                remain = 0
        while i < len(self.field):
            f = self.field[i]
            diff = f.offset - off
            if diff > 128:
                break
            subtype = f.type
            if subtype is not None and subtype.getMetatype() == TYPE_ARRAY:
                base = subtype.getDepend(0)
                el_size = base.getAlignSize() if base is not None else 0
                return subtype, -diff, el_size
            elif subtype is not None:
                res, suboff, el_sz = subtype.nearestArrayedComponentForward(remain)
                if res is not None:
                    return subtype, -diff, el_sz
            i += 1
            remain = 0
        return None, 0, 0

    def setFields(self, fields: List[TypeField]) -> None:
        self.field = sorted(fields, key=lambda f: f.offset)
        if self.field:
            last = self.field[-1]
            end = last.offset + (last.type.getSize() if last.type else 0)
            if end > self.size:
                self.size = end

    def compare(self, op: Datatype, level: int) -> int:
        """C++ ref: TypeStruct::compare — full field-level comparison."""
        res = super().compare(op, level)
        if res != 0:
            return res
        if not isinstance(op, TypeStruct):
            return 0
        nf = len(self.field)
        onf = len(op.field)
        if nf != onf:
            return onf - nf  # More fields = earlier in sort
        # First pass: compare offset, name, metatype
        for f1, f2 in zip(self.field, op.field):
            if f1.offset != f2.offset:
                return -1 if f1.offset < f2.offset else 1
            if f1.name != f2.name:
                return -1 if f1.name < f2.name else 1
            if f1.type is not None and f2.type is not None:
                if f1.type.getMetatype() != f2.type.getMetatype():
                    return -1 if f1.type.getMetatype() < f2.type.getMetatype() else 1
        level -= 1
        if level < 0:
            if self.id == op.getId():
                return 0
            return -1 if self.id < op.getId() else 1
        # Second pass: deep comparison
        for f1, f2 in zip(self.field, op.field):
            if f1.type is not None and f2.type is not None and f1.type is not f2.type:
                c = f1.type.compare(f2.type, level)
                if c != 0:
                    return c
        return 0

    def compareDependency(self, op: Datatype) -> int:
        """C++ ref: TypeStruct::compareDependency"""
        res = super().compareDependency(op)
        if res != 0:
            return res
        if not isinstance(op, TypeStruct):
            return 0
        nf = len(self.field)
        onf = len(op.field)
        if nf != onf:
            return onf - nf
        for f1, f2 in zip(self.field, op.field):
            if f1.offset != f2.offset:
                return -1 if f1.offset < f2.offset else 1
            if f1.name != f2.name:
                return -1 if f1.name < f2.name else 1
            if f1.type is not f2.type:
                # Compare by identity (pointer comparison in C++)
                id1 = id(f1.type) if f1.type else 0
                id2 = id(f2.type) if f2.type else 0
                if id1 != id2:
                    return -1 if id1 < id2 else 1
        return 0

    @staticmethod
    def scoreSingleComponent(parent: Datatype, op, slot: int) -> int:
        """Determine if a single-field struct should resolve to the field or the whole struct.

        C++ ref: TypeStruct::scoreSingleComponent
        Returns 0 to indicate the field, -1 to indicate the whole structure.
        """
        from ghidra.ir.op import OpCode
        opc = op.code() if hasattr(op, 'code') else None
        if opc == OpCode.CPUI_COPY or opc == OpCode.CPUI_INDIRECT:
            vn = op.getOut() if slot == 0 else op.getIn(0)
            if hasattr(vn, 'isTypeLock') and vn.isTypeLock() and vn.getType() is parent:
                return -1
        elif (opc == OpCode.CPUI_LOAD and slot == -1) or (opc == OpCode.CPUI_STORE and slot == 2):
            vn = op.getIn(1)
            if hasattr(vn, 'isTypeLock') and vn.isTypeLock():
                ct = vn.getTypeReadFacing(op) if hasattr(vn, 'getTypeReadFacing') else vn.getType()
                if ct is not None and ct.getMetatype() == TYPE_PTR and hasattr(ct, 'getPtrTo') and ct.getPtrTo() is parent:
                    return -1
        elif hasattr(op, 'isCall') and op.isCall():
            fd = op.getParent().getFuncdata() if hasattr(op.getParent(), 'getFuncdata') else None
            if fd is not None and hasattr(fd, 'getCallSpecs'):
                fc = fd.getCallSpecs(op)
                if fc is not None:
                    param = None
                    if slot >= 1 and hasattr(fc, 'isInputLocked') and fc.isInputLocked():
                        param = fc.getParam(slot - 1)
                    elif slot < 0 and hasattr(fc, 'isOutputLocked') and fc.isOutputLocked():
                        param = fc.getOutput()
                    if param is not None and hasattr(param, 'getType') and param.getType() is parent:
                        return -1
        return 0

    def resolveInFlow(self, op, slot: int) -> Datatype:
        """Resolve single-field struct based on PcodeOp context.

        C++ ref: TypeStruct::resolveInFlow
        """
        fd = op.getParent().getFuncdata() if hasattr(op.getParent(), 'getFuncdata') else None
        if fd is not None:
            from ghidra.types.resolve import ResolvedUnion
            res = fd.getUnionField(self, op, slot)
            if res is not None:
                return res.getDatatype()
            fieldNum = TypeStruct.scoreSingleComponent(self, op, slot)
            compFill = ResolvedUnion(self, fieldNum, fd.getArch().types)
            fd.setUnionField(self, op, slot, compFill)
            return compFill.getDatatype()
        return self

    def findResolve(self, op, slot: int) -> Datatype:
        """Find previously resolved struct sub-type.

        C++ ref: TypeStruct::findResolve
        """
        fd = op.getParent().getFuncdata() if hasattr(op.getParent(), 'getFuncdata') else None
        if fd is not None:
            res = fd.getUnionField(self, op, slot)
            if res is not None:
                return res.getDatatype()
        return self.field[0].type if self.field else self

    def findCompatibleResolve(self, ct: Datatype) -> int:
        """Find a resolution compatible with the given data-type.

        C++ ref: TypeStruct::findCompatibleResolve
        """
        if not self.field:
            return -1
        fieldType = self.field[0].type
        if fieldType is not None:
            if ct.needsResolution() and not fieldType.needsResolution():
                if ct.findCompatibleResolve(fieldType) >= 0:
                    return 0
            if fieldType is ct:
                return 0
        return -1

    @staticmethod
    def assignFieldOffsets(fields: list) -> tuple:
        """Assign offsets to fields in order so each starts at an aligned offset.

        C++ ref: TypeStruct::assignFieldOffsets
        Returns (newSize, newAlign).
        """
        offset = 0
        newAlign = 1
        for f in fields:
            if f.type is not None and f.type.getMetatype() == TYPE_VOID:
                raise ValueError("Illegal field data-type: void")
            if f.offset != -1:
                continue
            cursize = f.type.getAlignSize() if f.type is not None else 0
            align = f.type.getAlignment() if f.type is not None else 1
            if align > newAlign:
                newAlign = align
            align_mask = align - 1
            if align_mask > 0 and (offset & align_mask) != 0:
                offset = (offset - (offset & align_mask) + (align_mask + 1))
            f.offset = offset
            f.ident = offset
            offset += cursize
        newSize = Datatype.calcAlignSize(offset, newAlign)
        return newSize, newAlign

    def clone(self) -> TypeStruct:
        t = TypeStruct(self.name, self.size)
        t.id = self.id
        t.flags = self.flags
        t.field = list(self.field)
        return t

    def printRaw(self) -> str:
        return f"struct {self.name}"


class TypeUnion(Datatype):
    """An overlapping union of multiple datatypes."""

    def __init__(self, name: str = "", size: int = 0) -> None:
        super().__init__(size, -1, TYPE_UNION)
        self.name = name
        self.displayName = name
        self.field: List[TypeField] = []
        self.flags |= Datatype.needs_resolution

    def numDepend(self) -> int:
        return len(self.field)

    def getDepend(self, index: int) -> Optional[Datatype]:
        if 0 <= index < len(self.field):
            return self.field[index].type
        return None

    def getField(self, i: int) -> TypeField:
        return self.field[i]

    def numFields(self) -> int:
        return len(self.field)

    def setFields(self, fields: List[TypeField]) -> None:
        self.field = list(fields)
        for f in self.field:
            if f.type and f.type.getSize() > self.size:
                self.size = f.type.getSize()

    def findTruncation(self, off: int, sz: int, op=None, slot: int = -1) -> Tuple[Optional[TypeField], int]:
        """C++ ref: TypeUnion::findTruncation — delegates to resolveTruncation."""
        return self.resolveTruncation(off, op, slot)

    def resolveTruncation(self, offset: int, op, slot: int) -> Tuple[Optional[TypeField], int]:
        """Resolve truncation within union fields.

        C++ ref: TypeUnion::resolveTruncation
        """
        fd = op.getParent().getFuncdata() if (op is not None and hasattr(op.getParent(), 'getFuncdata')) else None
        if fd is not None:
            from ghidra.types.resolve import ScoreUnionFields
            from ghidra.ir.op import OpCode
            res = fd.getUnionField(self, op, slot)
            if res is not None:
                if res.getFieldNum() >= 0:
                    fld = self.getField(res.getFieldNum())
                    newoff = offset - fld.offset
                    return fld, newoff
            elif op.code() == OpCode.CPUI_SUBPIECE and slot == 1:
                scoreFields = ScoreUnionFields(fd.getArch().types, self, op, slot,
                                               unionType=self, offset=offset)
                fd.setUnionField(self, op, slot, scoreFields.getResult())
                if scoreFields.getResult().getFieldNum() >= 0:
                    return self.getField(scoreFields.getResult().getFieldNum()), 0
            else:
                scoreFields = ScoreUnionFields(fd.getArch().types, self, op, slot,
                                               unionType=self, offset=offset)
                fd.setUnionField(self, op, slot, scoreFields.getResult())
                if scoreFields.getResult().getFieldNum() >= 0:
                    fld = self.getField(scoreFields.getResult().getFieldNum())
                    newoff = offset - fld.offset
                    return fld, newoff
        return None, 0

    def resolveInFlow(self, op, slot: int) -> Datatype:
        """Resolve union based on PcodeOp context.

        C++ ref: TypeUnion::resolveInFlow
        """
        fd = op.getParent().getFuncdata() if hasattr(op.getParent(), 'getFuncdata') else None
        if fd is not None:
            from ghidra.types.resolve import ScoreUnionFields
            res = fd.getUnionField(self, op, slot)
            if res is not None:
                return res.getDatatype()
            scoreFields = ScoreUnionFields(fd.getArch().types, self, op, slot)
            fd.setUnionField(self, op, slot, scoreFields.getResult())
            return scoreFields.getResult().getDatatype()
        return self

    def findResolve(self, op, slot: int) -> Datatype:
        """Find previously resolved union sub-type.

        C++ ref: TypeUnion::findResolve
        """
        fd = op.getParent().getFuncdata() if hasattr(op.getParent(), 'getFuncdata') else None
        if fd is not None:
            res = fd.getUnionField(self, op, slot)
            if res is not None:
                return res.getDatatype()
        return self

    def findCompatibleResolve(self, ct: Datatype) -> int:
        """Find a resolution compatible with the given data-type.

        C++ ref: TypeUnion::findCompatibleResolve
        """
        if not ct.needsResolution():
            for i, f in enumerate(self.field):
                if f.type is ct and f.offset == 0:
                    return i
        else:
            for i, f in enumerate(self.field):
                if f.offset != 0:
                    continue
                ft = f.type
                if ft is None or ft.getSize() != ct.getSize():
                    continue
                if ft.needsResolution():
                    continue
                if ct.findCompatibleResolve(ft) >= 0:
                    return i
        return -1

    def compare(self, op: Datatype, level: int) -> int:
        """C++ ref: TypeUnion::compare"""
        res = super().compare(op, level)
        if res != 0:
            return res
        if not isinstance(op, TypeUnion):
            return 0
        nf = len(self.field)
        onf = len(op.field)
        if nf != onf:
            return onf - nf
        for f1, f2 in zip(self.field, op.field):
            if f1.name != f2.name:
                return -1 if f1.name < f2.name else 1
            if f1.type is not None and f2.type is not None:
                if f1.type.getMetatype() != f2.type.getMetatype():
                    return -1 if f1.type.getMetatype() < f2.type.getMetatype() else 1
        level -= 1
        if level < 0:
            if self.id == op.getId():
                return 0
            return -1 if self.id < op.getId() else 1
        for f1, f2 in zip(self.field, op.field):
            if f1.type is not None and f2.type is not None and f1.type is not f2.type:
                c = f1.type.compare(f2.type, level)
                if c != 0:
                    return c
        return 0

    def compareDependency(self, op: Datatype) -> int:
        """C++ ref: TypeUnion::compareDependency"""
        res = super().compareDependency(op)
        if res != 0:
            return res
        if not isinstance(op, TypeUnion):
            return 0
        nf = len(self.field)
        onf = len(op.field)
        if nf != onf:
            return onf - nf
        for f1, f2 in zip(self.field, op.field):
            if f1.name != f2.name:
                return -1 if f1.name < f2.name else 1
            if f1.type is not f2.type:
                id1 = id(f1.type) if f1.type else 0
                id2 = id(f2.type) if f2.type else 0
                if id1 != id2:
                    return -1 if id1 < id2 else 1
        return 0

    @staticmethod
    def assignFieldOffsets(fields: list, tu) -> tuple:
        """Assign offsets to union fields (all at offset 0), compute size and alignment.

        C++ ref: TypeUnion::assignFieldOffsets
        Returns (newSize, newAlign).
        """
        newSize = 0
        newAlign = 1
        for f in fields:
            ct = f.type
            if ct is None or ct.getMetatype() == TYPE_VOID:
                raise ValueError(f"Bad field data-type for union: {tu.getName()}")
            if not f.name:
                raise ValueError(f"Bad field name for union: {tu.getName()}")
            f.offset = 0
            end = ct.getSize()
            if end > newSize:
                newSize = end
            curAlign = ct.getAlignment()
            if curAlign > newAlign:
                newAlign = curAlign
        return newSize, newAlign

    def clone(self) -> TypeUnion:
        t = TypeUnion(self.name, self.size)
        t.id = self.id
        t.flags = self.flags
        t.field = list(self.field)
        return t

    def printRaw(self) -> str:
        return f"union {self.name}"


class TypePartialStruct(Datatype):
    """A data-type that holds part of a TypeStruct or TypeArray.

    C++ ref: TypePartialStruct
    """

    def __init__(self, container: Optional[Datatype] = None, offset: int = 0,
                 size: int = 0, stripped: Optional[Datatype] = None) -> None:
        super().__init__(size, 1, TYPE_PARTIALSTRUCT)
        self.flags |= Datatype.has_stripped
        self._stripped: Optional[Datatype] = stripped
        self._container: Optional[Datatype] = container
        self._offset: int = offset

    def getOffset(self) -> int:
        return self._offset

    def getParent(self) -> Optional[Datatype]:
        return self._container

    def getStripped(self) -> Optional[Datatype]:
        return self._stripped

    def getComponentForPtr(self) -> Optional[Datatype]:
        """Get array element data-type or stripped data-type.

        C++ ref: TypePartialStruct::getComponentForPtr
        """
        if self._container is not None and self._container.getMetatype() == TYPE_ARRAY:
            eltype = self._container.getDepend(0)
            if eltype is not None and eltype.getMetatype() != TYPE_UNKNOWN:
                if eltype.getAlignSize() > 0 and (self._offset % eltype.getAlignSize()) == 0:
                    return eltype
        return self._stripped

    def getSubType(self, off: int, newoff=None):
        """C++ ref: TypePartialStruct::getSubType"""
        size_left = self.size - off
        off += self._offset
        ct = self._container
        while ct is not None:
            result = ct.getSubType(off)
            if isinstance(result, tuple):
                ct, off = result
            else:
                ct = result
            if ct is None:
                break
            if ct.getSize() - off <= size_left:
                break
        return _subtype_result(ct, off, newoff)

    def getHoleSize(self, off: int) -> int:
        """C++ ref: TypePartialStruct::getHoleSize"""
        size_left = self.size - off
        off += self._offset
        if self._container is None:
            return 0
        res = self._container.getHoleSize(off)
        if res > size_left:
            res = size_left
        return res

    def compare(self, op: Datatype, level: int) -> int:
        res = super().compare(op, level)
        if res != 0:
            return res
        if not isinstance(op, TypePartialStruct):
            return 0
        if self._offset != op._offset:
            return -1 if self._offset < op._offset else 1
        level -= 1
        if level < 0:
            if self.id == op.getId():
                return 0
            return -1 if self.id < op.getId() else 1
        if self._container is not None and op._container is not None:
            return self._container.compare(op._container, level)
        return 0

    def compareDependency(self, op: Datatype) -> int:
        if self.submeta != op.getSubMeta():
            return -1 if self.submeta < op.getSubMeta() else 1
        if not isinstance(op, TypePartialStruct):
            return 0
        if self._container is not op._container:
            id1 = id(self._container) if self._container else 0
            id2 = id(op._container) if op._container else 0
            return -1 if id1 < id2 else 1
        if self._offset != op._offset:
            return -1 if self._offset < op._offset else 1
        return op.getSize() - self.size

    def clone(self) -> TypePartialStruct:
        t = TypePartialStruct(self._container, self._offset, self.size, self._stripped)
        t.id = self.id
        t.flags = self.flags
        return t

    def printRaw(self) -> str:
        base = self._container.printRaw() if self._container else "?"
        return f"{base}[off={self._offset},sz={self.size}]"


class TypePartialUnion(Datatype):
    """A data-type representing part of a TypeUnion.

    C++ ref: TypePartialUnion
    """

    def __init__(self, container: Optional[TypeUnion] = None, offset: int = 0,
                 size: int = 0, stripped: Optional[Datatype] = None) -> None:
        super().__init__(size, 1, TYPE_PARTIALUNION)
        self.flags |= (Datatype.needs_resolution | Datatype.has_stripped)
        self._stripped: Optional[Datatype] = stripped
        self._container: Optional[TypeUnion] = container
        self._offset: int = offset

    def getOffset(self) -> int:
        return self._offset

    def getParentUnion(self) -> Optional[TypeUnion]:
        return self._container

    def getStripped(self) -> Optional[Datatype]:
        return self._stripped

    def findTruncation(self, off: int, sz: int, op=None, slot: int = -1) -> Tuple[Optional[TypeField], int]:
        """C++ ref: TypePartialUnion::findTruncation"""
        if self._container is not None:
            return self._container.findTruncation(off + self._offset, sz, op, slot)
        return None, 0

    def numDepend(self) -> int:
        if self._container is not None:
            return self._container.numDepend()
        return 0

    def getDepend(self, index: int) -> Optional[Datatype]:
        if self._container is not None:
            res = self._container.getDepend(index)
            if res is not None and res.getSize() != self.size:
                return self._stripped
            return res
        return None

    def resolveInFlow(self, op, slot: int) -> Datatype:
        """C++ ref: TypePartialUnion::resolveInFlow"""
        cur_type: Optional[Datatype] = self._container
        cur_off = self._offset
        while cur_type is not None and cur_type.getSize() > self.size:
            if cur_type.getMetatype() == TYPE_UNION:
                field, cur_off = cur_type.resolveTruncation(cur_off, op, slot)
                cur_type = field.type if field is not None else None
            else:
                cur_type, cur_off = cur_type.getSubType(cur_off)
        if cur_type is not None and cur_type.getSize() == self.size:
            return cur_type
        return self._stripped if self._stripped is not None else self

    def findResolve(self, op, slot: int) -> Datatype:
        """C++ ref: TypePartialUnion::findResolve"""
        cur_type: Optional[Datatype] = self._container
        cur_off = self._offset
        while cur_type is not None and cur_type.getSize() > self.size:
            if cur_type.getMetatype() == TYPE_UNION:
                new_type = cur_type.findResolve(op, slot)
                cur_type = None if new_type is cur_type else new_type
            else:
                cur_type, cur_off = cur_type.getSubType(cur_off)
        if cur_type is not None and cur_type.getSize() == self.size:
            return cur_type
        return self._stripped if self._stripped is not None else self

    def findCompatibleResolve(self, ct: Datatype) -> int:
        """C++ ref: TypePartialUnion::findCompatibleResolve"""
        if self._container is not None:
            return self._container.findCompatibleResolve(ct)
        return -1

    def resolveTruncation(self, offset: int, op, slot: int) -> Tuple[Optional[TypeField], int]:
        """C++ ref: TypePartialUnion::resolveTruncation"""
        if self._container is not None:
            return self._container.resolveTruncation(offset + self._offset, op, slot)
        return None, 0

    def compare(self, op: Datatype, level: int) -> int:
        res = super().compare(op, level)
        if res != 0:
            return res
        if not isinstance(op, TypePartialUnion):
            return 0
        if self._offset != op._offset:
            return -1 if self._offset < op._offset else 1
        level -= 1
        if level < 0:
            if self.id == op.getId():
                return 0
            return -1 if self.id < op.getId() else 1
        if self._container is not None and op._container is not None:
            return self._container.compare(op._container, level)
        return 0

    def compareDependency(self, op: Datatype) -> int:
        if self.submeta != op.getSubMeta():
            return -1 if self.submeta < op.getSubMeta() else 1
        if not isinstance(op, TypePartialUnion):
            return 0
        if self._container is not op._container:
            id1 = id(self._container) if self._container else 0
            id2 = id(op._container) if op._container else 0
            return -1 if id1 < id2 else 1
        if self._offset != op._offset:
            return -1 if self._offset < op._offset else 1
        return op.getSize() - self.size

    def clone(self) -> TypePartialUnion:
        t = TypePartialUnion(self._container, self._offset, self.size, self._stripped)
        t.id = self.id
        t.flags = self.flags
        return t

    def printRaw(self) -> str:
        base = self._container.printRaw() if self._container else "?"
        return f"{base}[off={self._offset},sz={self.size}]"


class TypePointerRel(TypePointer):
    """Relative pointer: pointer with fixed offset into a container.

    C++ ref: TypePointerRel
    """

    def __init__(self, size: int = 0, ptrto: Optional[Datatype] = None,
                 ws: int = 1, parent: Optional[Datatype] = None,
                 offset: int = 0) -> None:
        super().__init__(size, ptrto, ws)
        self._parent: Optional[Datatype] = parent
        self._rel_offset: int = offset
        self._stripped_ptr: Optional[TypePointer] = None
        self.flags |= Datatype.is_ptrrel
        self.submeta = SubMetaType.SUB_PTRREL

    def getParent(self) -> Optional[Datatype]:
        return self._parent

    def getByteOffset(self) -> int:
        return self._rel_offset

    def getAddressOffset(self) -> int:
        return self._rel_offset // self.wordsize if self.wordsize > 1 else self._rel_offset

    def getStripped(self) -> Optional[TypePointer]:
        return self._stripped_ptr

    def markEphemeral(self, typegrp: TypeFactory) -> None:
        """Mark this as ephemeral, cache stripped pointer.

        C++ ref: TypePointerRel::markEphemeral
        """
        self._stripped_ptr = typegrp.getTypePointer(self.size, self.ptrto, self.wordsize)
        self.flags |= Datatype.has_stripped
        if self.ptrto is not None and self.ptrto.getMetatype() == TYPE_UNKNOWN:
            self.submeta = SubMetaType.SUB_PTRREL_UNK

    def evaluateThruParent(self, addr_off: int) -> bool:
        """Check if address offset should be displayed through parent.

        C++ ref: TypePointerRel::evaluateThruParent
        """
        if self._parent is None:
            return False
        off = (addr_off + self._rel_offset) & ((1 << (self.size * 8)) - 1)
        return 0 <= off < self._parent.getSize()

    def downChain(self, off: int, allowArrayWrap: bool, typegrp: TypeFactory) -> Tuple[Optional[TypePointer], int, Optional[TypePointer], int]:
        """C++ ref: TypePointerRel::downChain"""
        if self.ptrto is not None:
            ptrto_meta = self.ptrto.getMetatype()
            if off >= 0 and off < self.ptrto.getSize() and (ptrto_meta == TYPE_STRUCT or ptrto_meta == TYPE_ARRAY):
                return TypePointer.downChain(self, off, allowArrayWrap, typegrp)
        if self._parent is None:
            return None, off, None, 0
        rel_off = (off + self._rel_offset) & ((1 << (self.size * 8)) - 1)
        if rel_off < 0 or rel_off >= self._parent.getSize():
            return None, off, None, 0
        par: Optional[TypePointer] = None
        parOff: int = 0
        meta = self._parent.getMetatype()
        is_array = (meta == TYPE_ARRAY)
        if is_array or meta == TYPE_STRUCT:
            par = self
            parOff = rel_off
        pt, rel_off = self._parent.getSubType(rel_off)
        if pt is None:
            return None, off, par, parOff
        off = rel_off
        if not is_array:
            return typegrp.getTypePointerStripArray(self.size, pt, self.wordsize), off, par, parOff
        return typegrp.getTypePointer(self.size, pt, self.wordsize), off, par, parOff

    def isPtrsubMatching(self, off: int, extra: int, multiplier: int) -> bool:
        """C++ ref: TypePointerRel::isPtrsubMatching"""
        if self._parent is None:
            return False
        rel_off = (off + self._rel_offset) & ((1 << (self.size * 8)) - 1)
        if rel_off < 0 or rel_off >= self._parent.getSize():
            return False
        return True

    def compare(self, op: Datatype, level: int) -> int:
        res = TypePointer.compare(self, op, level)
        if res != 0:
            return res
        if not isinstance(op, TypePointerRel):
            return 0
        if self._rel_offset != op._rel_offset:
            return -1 if self._rel_offset < op._rel_offset else 1
        if self._parent is not None and op._parent is not None:
            level -= 1
            if level < 0:
                if self.id == op.getId():
                    return 0
                return -1 if self.id < op.getId() else 1
            return self._parent.compare(op._parent, level)
        return 0

    def compareDependency(self, op: Datatype) -> int:
        res = TypePointer.compareDependency(self, op)
        if res != 0:
            return res
        if not isinstance(op, TypePointerRel):
            return 0
        if self._rel_offset != op._rel_offset:
            return -1 if self._rel_offset < op._rel_offset else 1
        if self._parent is not op._parent:
            id1 = id(self._parent) if self._parent else 0
            id2 = id(op._parent) if op._parent else 0
            return -1 if id1 < id2 else 1
        return 0

    def clone(self) -> TypePointerRel:
        t = TypePointerRel(self.size, self.ptrto, self.wordsize, self._parent, self._rel_offset)
        t.id = self.id
        t.flags = self.flags
        t._stripped_ptr = self._stripped_ptr
        return t

    @staticmethod
    def getPtrToFromParent(base, off: int, typegrp):
        """Compute the pointed-to data-type starting from the parent container.

        C++ ref: TypePointerRel::getPtrToFromParent
        """
        if off > 0:
            curoff = off
            while True:
                sub = base.getSubType(curoff)
                if isinstance(sub, tuple):
                    base, curoff = sub
                else:
                    base = sub
                    curoff = 0
                if curoff == 0 or base is None:
                    break
            if base is None:
                base = typegrp.getBase(1, TYPE_UNKNOWN)
        else:
            base = typegrp.getBase(1, TYPE_UNKNOWN)
        return base

    def printRaw(self) -> str:
        base = self.ptrto.printRaw() if self.ptrto else "?"
        return f"{base} *+{self._rel_offset}"


class TypeCode(Datatype):
    """Data-type representing executable code (function prototype)."""

    def __init__(self, size: int = 1) -> None:
        super().__init__(size, -1, TYPE_CODE)
        self.name = "code"
        self.displayName = "code"
        self.proto = None  # FuncProto placeholder
        self.factory: Optional[TypeFactory] = None

    def getPrototype(self):
        """Get the function prototype, or None."""
        return self.proto

    def compareBasic(self, op: TypeCode) -> int:
        """Compare surface characteristics.

        C++ ref: TypeCode::compareBasic
        """
        if self.proto is None:
            if op.proto is not None:
                return 1  # Non-null proto is preferred
        elif op.proto is None:
            return -1
        return 0

    def getSubType(self, off: int, newoff=None):
        """C++ ref: TypeCode::getSubType"""
        if self.factory is not None and off == 0:
            # Return pointer to code type at offset 0
            return _subtype_result(None, off, newoff)
        return _subtype_result(None, off, newoff)

    def compare(self, op: Datatype, level: int) -> int:
        res = super().compare(op, level)
        if res != 0:
            return res
        if not isinstance(op, TypeCode):
            return 0
        return self.compareBasic(op)

    def compareDependency(self, op: Datatype) -> int:
        res = super().compareDependency(op)
        if res != 0:
            return res
        if not isinstance(op, TypeCode):
            return 0
        return self.compareBasic(op)

    def setPrototype(self, typegrp, fp=None, sig=None, voidtype=None):
        """Set the function prototype on this TypeCode.

        C++ ref: TypeCode::setPrototype (two overloads)
        Overload 1: setPrototype(typegrp, fp) — copy an existing FuncProto
        Overload 2: setPrototype(typegrp, sig=sig, voidtype=voidtype) — build from PrototypePieces
        """
        if sig is not None:
            # Overload 2: build from PrototypePieces
            self.factory = typegrp
            self.flags |= Datatype.variable_length
            from ghidra.fspec.fspec import FuncProto
            self.proto = FuncProto()
            if hasattr(self.proto, 'setInternal'):
                self.proto.setInternal(getattr(sig, 'model', None), voidtype)
            if hasattr(self.proto, 'updateAllTypes'):
                self.proto.updateAllTypes(sig)
            if hasattr(self.proto, 'setInputLock'):
                self.proto.setInputLock(True)
            if hasattr(self.proto, 'setOutputLock'):
                self.proto.setOutputLock(True)
        else:
            # Overload 1: copy existing FuncProto
            self.proto = None
            self.factory = None
            if fp is not None:
                self.factory = typegrp
                from ghidra.fspec.fspec import FuncProto
                self.proto = FuncProto()
                if hasattr(self.proto, 'copy'):
                    self.proto.copy(fp)

    def clone(self) -> TypeCode:
        t = TypeCode(self.size)
        t.id = self.id
        t.flags = self.flags
        if self.proto is not None:
            from ghidra.fspec.fspec import FuncProto
            t.proto = FuncProto()
            if hasattr(t.proto, 'copy'):
                t.proto.copy(self.proto)
        else:
            t.proto = None
        t.factory = self.factory
        return t


class TypeSpacebase(Datatype):
    """Special Datatype for symbol/type look-up into address spaces.

    C++ ref: TypeSpacebase
    """

    def __init__(self, spaceid: Optional[AddrSpace] = None,
                 localframe=None, glb=None, size: int = 0) -> None:
        super().__init__(size, 1, TYPE_SPACEBASE)
        self.spaceid: Optional[AddrSpace] = spaceid
        self.localframe = localframe  # Address of function (or None for global)
        self.glb = glb  # Architecture reference

    def getMap(self):
        """Get the symbol table (Scope) indexed by this.

        C++ ref: TypeSpacebase::getMap
        """
        if self.glb is None:
            return None
        symboltab = getattr(self.glb, 'symboltab', None)
        if symboltab is None:
            return None
        scope = symboltab.getGlobalScope() if hasattr(symboltab, 'getGlobalScope') else symboltab
        if scope is None:
            return None
        if self.localframe is None:
            return scope
        if hasattr(self.localframe, 'isInvalid') and self.localframe.isInvalid():
            return scope
        if hasattr(scope, 'queryFunction'):
            funcsym = scope.queryFunction(self.localframe)
            if funcsym is not None:
                if hasattr(funcsym, 'getFunction'):
                    fd = funcsym.getFunction()
                    if fd is not None and hasattr(fd, 'getScopeLocal'):
                        return fd.getScopeLocal()
                if hasattr(funcsym, 'getScopeLocal'):
                    return funcsym.getScopeLocal()
        return scope

    def getAddress(self, off: int, sz: int, point=None):
        """Construct an Address given an offset.

        C++ ref: TypeSpacebase::getAddress
        """
        if self.spaceid is not None:
            from ghidra.core.address import Address
            return Address(self.spaceid, off)
        return None

    def getSubType(self, off: int, newoff=None):
        """Lookup component type via symbol table.

        C++ ref: TypeSpacebase::getSubType
        """
        scope = self.getMap()
        ws = self.spaceid.getWordSize() if self.spaceid is not None and hasattr(self.spaceid, 'getWordSize') else 1
        addr_off = off if ws == 1 else off // ws
        addr = self.getAddress(addr_off, -1)
        if addr is None or scope is None or not hasattr(scope, 'queryContainer'):
            unknown = self.glb.types.getBase(1, TYPE_UNKNOWN) if self.glb is not None and hasattr(self.glb, 'types') else None
            return _subtype_result(unknown, 0, newoff)
        try:
            from ghidra.core.address import Address
            smallest = scope.queryContainer(addr, 1, Address())
        except Exception:
            smallest = None
        if smallest is None:
            unknown = self.glb.types.getBase(1, TYPE_UNKNOWN) if self.glb is not None and hasattr(self.glb, 'types') else None
            return _subtype_result(unknown, 0, newoff)
        suboff = (addr.getOffset() - smallest.getAddr().getOffset()) + smallest.getOffset()
        symbol = smallest.getSymbol() if hasattr(smallest, 'getSymbol') else None
        dt = symbol.getType() if symbol is not None and hasattr(symbol, 'getType') else None
        if dt is None and self.glb is not None and hasattr(self.glb, 'types'):
            dt = self.glb.types.getBase(1, TYPE_UNKNOWN)
        return _subtype_result(dt, suboff, newoff)

    def nearestArrayedComponentForward(self, off: int) -> Tuple[Optional[Datatype], int, int]:
        """C++ ref: TypeSpacebase::nearestArrayedComponentForward"""
        scope = self.getMap()
        if scope is None or self.spaceid is None or not hasattr(scope, 'queryContainer'):
            return None, 0, 0
        from ghidra.core.address import Address
        ws = self.spaceid.getWordSize() if hasattr(self.spaceid, 'getWordSize') else 1
        addr_off = off if ws == 1 else off // ws
        addr = self.getAddress(addr_off, -1)
        if addr is None:
            return None, 0, 0
        smallest = scope.queryContainer(addr, 1, Address())
        if smallest is None or smallest.getOffset() != 0:
            next_addr = addr + 32
        else:
            symbol = smallest.getSymbol()
            symbol_type = symbol.getType() if symbol is not None and hasattr(symbol, 'getType') else None
            if symbol_type is not None and symbol_type.getMetatype() == TYPE_STRUCT:
                struct_off = addr.getOffset() - smallest.getAddr().getOffset()
                res, _dummy_off, el_size = symbol_type.nearestArrayedComponentForward(struct_off)
                if res is not None:
                    return symbol_type, struct_off, el_size
            step = smallest.getSize() if hasattr(smallest, 'getSize') else 0
            step = step if ws == 1 else step // ws
            next_addr = smallest.getAddr() + step
        if next_addr < addr:
            return None, 0, 0
        smallest = scope.queryContainer(next_addr, 1, Address())
        if smallest is None or smallest.getOffset() != 0:
            return None, 0, 0
        symbol = smallest.getSymbol()
        symbol_type = symbol.getType() if symbol is not None and hasattr(symbol, 'getType') else None
        newoff_val = addr.getOffset() - smallest.getAddr().getOffset()
        if symbol_type is None:
            return None, 0, 0
        if symbol_type.getMetatype() == TYPE_ARRAY:
            base = symbol_type.getBase() if hasattr(symbol_type, 'getBase') else None
            el_size = base.getAlignSize() if base is not None and hasattr(base, 'getAlignSize') else 0
            return symbol_type, newoff_val, el_size
        if symbol_type.getMetatype() == TYPE_STRUCT:
            res, _dummy_off, el_size = symbol_type.nearestArrayedComponentForward(0)
            if res is not None:
                return symbol_type, newoff_val, el_size
        return None, 0, 0

    def nearestArrayedComponentBackward(self, off: int) -> Tuple[Optional[Datatype], int, int]:
        """C++ ref: TypeSpacebase::nearestArrayedComponentBackward"""
        subtype, newoff_val = self.getSubType(off)
        if subtype is None:
            return None, 0, 0
        if subtype.getMetatype() == TYPE_ARRAY:
            base = subtype.getBase() if hasattr(subtype, 'getBase') else None
            el_size = base.getAlignSize() if base is not None and hasattr(base, 'getAlignSize') else 0
            return subtype, newoff_val, el_size
        if subtype.getMetatype() == TYPE_STRUCT:
            res, _dummy_off, el_size = subtype.nearestArrayedComponentBackward(newoff_val)
            if res is not None:
                return subtype, newoff_val, el_size
        return None, 0, 0

    def compare(self, op: Datatype, level: int) -> int:
        res = super().compare(op, level)
        if res != 0:
            return res
        if not isinstance(op, TypeSpacebase):
            return 0
        if self.spaceid is not op.spaceid:
            id1 = id(self.spaceid) if self.spaceid else 0
            id2 = id(op.spaceid) if op.spaceid else 0
            return -1 if id1 < id2 else 1
        return 0

    def compareDependency(self, op: Datatype) -> int:
        res = super().compareDependency(op)
        if res != 0:
            return res
        if not isinstance(op, TypeSpacebase):
            return 0
        if self.spaceid is not op.spaceid:
            id1 = id(self.spaceid) if self.spaceid else 0
            id2 = id(op.spaceid) if op.spaceid else 0
            return -1 if id1 < id2 else 1
        return 0

    def clone(self) -> TypeSpacebase:
        t = TypeSpacebase(self.spaceid, self.localframe, self.glb, self.size)
        t.id = self.id
        t.flags = self.flags
        return t


# =========================================================================
# TypeFactory
# =========================================================================

class TypeFactory:
    """A container for Datatype objects.

    Manages creation, caching, and lookup of all data-types used
    during decompilation.
    """

    def __init__(self, glb=None) -> None:
        self._typeById: Dict[int, Datatype] = {}
        self._typeByName: Dict[str, Datatype] = {}
        self._nextId: int = 1
        self._sizeOfInt: int = 4
        self._sizeOfLong: int = 8
        self._sizeOfPointer: int = 8
        self._align: int = 1
        self._enumSize: int = 4
        self.glb = glb  # Architecture reference

        # Core types
        self._typeVoid: TypeVoid = TypeVoid()
        self._typeBool: Optional[Datatype] = None
        self._typeChar: Optional[TypeChar] = None
        self._defaultInt: Optional[Datatype] = None
        self._defaultUint: Optional[Datatype] = None
        self._defaultFloat: Optional[Datatype] = None

        # Size-indexed caches for fast lookup
        self._typecache: List[List[Datatype]] = [[] for _ in range(9)]
        self._typecache10: Optional[Datatype] = None
        self._typecache16: Optional[Datatype] = None

        self._cacheType(self._typeVoid)

    def _assignId(self, dt: Datatype) -> None:
        if dt.id == 0:
            dt.id = self._nextId
            self._nextId += 1

    def _cacheType(self, dt: Datatype) -> None:
        self._assignId(dt)
        self._typeById[dt.id] = dt
        if dt.name:
            self._typeByName[dt.name] = dt

    def clear(self) -> None:
        self._typeById.clear()
        self._typeByName.clear()
        self._nextId = 1
        self._typeVoid = TypeVoid()
        self._cacheType(self._typeVoid)

    # --- Core type accessors ---

    def getTypeVoid(self) -> TypeVoid:
        return self._typeVoid

    def getBase(self, size: int, metatype: MetaType, name: str = "") -> Datatype:
        """Get or create a base type of given size and metatype."""
        if not name:
            name = f"{metatype2string(metatype)}{size}"
        existing = self._typeByName.get(name)
        if existing is not None:
            return existing
        dt = TypeBase(size, metatype, name)
        self._cacheType(dt)
        return dt

    def getTypePointer(self, size: int, ptrto: Datatype, ws: int = 1) -> TypePointer:
        """Get or create a pointer type."""
        dt = TypePointer(size, ptrto, ws)
        dt.name = f"{ptrto.getName()} *"
        dt.displayName = dt.name
        self._cacheType(dt)
        return dt

    def getTypeArray(self, num_elements: int, arrayof: Datatype) -> TypeArray:
        """Get or create an array type."""
        dt = TypeArray(num_elements, arrayof)
        dt.name = f"{arrayof.getName()}[{num_elements}]"
        dt.displayName = dt.name
        self._cacheType(dt)
        return dt

    def getTypeStruct(self, name: str) -> TypeStruct:
        """Get or create a structure type."""
        existing = self._typeByName.get(name)
        if existing is not None and isinstance(existing, TypeStruct):
            return existing
        dt = TypeStruct(name)
        dt.flags |= Datatype.type_incomplete
        self._cacheType(dt)
        return dt

    def getTypeUnion(self, name: str) -> TypeUnion:
        """Get or create a union type."""
        existing = self._typeByName.get(name)
        if existing is not None and isinstance(existing, TypeUnion):
            return existing
        dt = TypeUnion(name)
        dt.flags |= Datatype.type_incomplete
        self._cacheType(dt)
        return dt

    def getTypeEnum(self, size: int, metatype: MetaType, name: str) -> TypeEnum:
        dt = TypeEnum(size, metatype, name)
        self._cacheType(dt)
        return dt

    def getTypeCode(self) -> TypeCode:
        tc = TypeCode()
        tc.factory = self
        return tc

    def getTypePointerStripArray(self, size: int, ptrto: Datatype, ws: int = 1) -> TypePointer:
        """Get pointer type, stripping single-element arrays.

        C++ ref: TypeFactory::getTypePointerStripArray
        """
        if ptrto.getMetatype() == TYPE_ARRAY:
            arr = ptrto
            if isinstance(arr, TypeArray) and arr.numElements() == 1:
                base = arr.getBase()
                if base is not None:
                    return self.getTypePointer(size, base, ws)
        return self.getTypePointer(size, ptrto, ws)

    def getTypePartialStruct(self, contain: Datatype, off: int, sz: int) -> TypePartialStruct:
        """Get or create a TypePartialStruct.

        C++ ref: TypeFactory::getTypePartialStruct
        """
        stripped = self.getBase(sz, TYPE_UNKNOWN)
        dt = TypePartialStruct(contain, off, sz, stripped)
        return self.findAdd(dt)

    def getTypePartialUnion(self, contain: TypeUnion, off: int, sz: int) -> TypePartialUnion:
        """Get or create a TypePartialUnion.

        C++ ref: TypeFactory::getTypePartialUnion
        """
        stripped = self.getBase(sz, TYPE_UNKNOWN)
        dt = TypePartialUnion(contain, off, sz, stripped)
        return self.findAdd(dt)

    def getTypePointerRel(self, size: int, ptrto: Datatype, parent: Datatype,
                          offset: int, ws: int = 1) -> TypePointerRel:
        """Get or create a relative pointer type.

        C++ ref: TypeFactory::getTypePointerRel
        """
        dt = TypePointerRel(size, ptrto, ws, parent, offset)
        dt.markEphemeral(self)
        return self.findAdd(dt)

    def getTypeSpacebase(self, spaceid, localframe=None) -> TypeSpacebase:
        """Get or create a spacebase type.

        C++ ref: TypeFactory::getTypeSpacebase
        """
        dt = TypeSpacebase(spaceid, localframe, self.glb, 0)
        self._cacheType(dt)
        return dt

    def findAdd(self, dt: Datatype) -> Datatype:
        """Find existing equivalent type or add new one.

        C++ ref: TypeFactory::findAdd
        Uses compareDependency to check for duplicates.
        """
        # Check for existing type with same dependency signature
        for existing in self._typeById.values():
            if type(existing) is type(dt) and existing.compareDependency(dt) == 0:
                if existing.getSize() == dt.getSize():
                    return existing
        self._cacheType(dt)
        return dt

    def getExactPiece(self, ct: Datatype, offset: int, size: int) -> Optional[Datatype]:
        """Get exact sub-piece of a data-type, drilling down through nested types.

        C++ ref: TypeFactory::getExactPiece
        """
        lastType: Optional[Datatype] = None
        lastOff: int = 0
        curOff: int = offset
        while ct is not None:
            if ct.getSize() < size + curOff:
                break
            if ct.getSize() == size:
                return ct
            if ct.getMetatype() == TYPE_UNION:
                if isinstance(ct, TypeUnion):
                    return self.getTypePartialUnion(ct, curOff, size)
                return None
            lastType = ct
            lastOff = curOff
            ct, curOff = ct.getSubType(curOff)
        if lastType is not None:
            meta = lastType.getMetatype()
            if meta == TYPE_STRUCT or meta == TYPE_ARRAY:
                return self.getTypePartialStruct(lastType, lastOff, size)
            elif lastType.isEnumType() and not lastType.hasStripped():
                if isinstance(lastType, TypeEnum):
                    return self.getTypePartialEnum(lastType, lastOff, size)
        return None

    def resizePointer(self, base_ptr: TypePointer, new_size: int) -> TypePointer:
        """Create a new pointer type with different size.

        C++ ref: TypeFactory::resizePointer
        """
        ptrto = base_ptr.getPtrTo()
        ws = base_ptr.getWordSize()
        if ptrto is None:
            ptrto = self.getTypeVoid()
        return self.getTypePointer(new_size, ptrto, ws)

    def concretize(self, ct: Datatype) -> Datatype:
        """Convert a data-type to a concrete form.

        C++ ref: TypeFactory::concretize
        Replaces TYPE_CODE with TYPE_UNKNOWN if size != 1.
        """
        if ct.getMetatype() == TYPE_CODE:
            if ct.getSize() != 1:
                return self.getBase(ct.getSize(), TYPE_UNKNOWN)
        return ct

    def recalcPointerSubmeta(self, base: Datatype, sub: SubMetaType) -> None:
        """Search for pointers to base with given sub-metatype and update to current correct value.

        C++ ref: TypeFactory::recalcPointerSubmeta
        """
        # Calculate what the correct submeta should be for pointers to base
        tmp = TypePointer(1, base, 0)
        curSub = tmp.submeta
        if curSub == sub:
            return  # Already correct
        for dt in list(self._typeById.values()):
            if not isinstance(dt, TypePointer):
                continue
            if dt.ptrto is not base:
                continue
            if dt.submeta == sub:
                dt.submeta = curSub

    def setupSizes(self, sizeOfInt: int = 4, sizeOfLong: int = 8,
                   sizeOfPointer: int = 8, align: int = 1,
                   enumSize: int = 4) -> None:
        """Configure platform-specific type sizes.

        C++ ref: TypeFactory::setupSizes
        """
        self._sizeOfInt = sizeOfInt
        self._sizeOfLong = sizeOfLong
        self._sizeOfPointer = sizeOfPointer
        self._align = align
        self._enumSize = enumSize

    def cacheCoreTypes(self) -> None:
        """Build fast-lookup caches for core types by size.

        C++ ref: TypeFactory::cacheCoreTypes
        """
        self._typecache = [[] for _ in range(9)]
        for dt in self._typeById.values():
            if not (dt.flags & Datatype.coretype):
                continue
            sz = dt.getSize()
            meta = dt.getMetatype()
            if meta in (TYPE_INT, TYPE_UINT, TYPE_UNKNOWN, TYPE_FLOAT, TYPE_BOOL) and 0 < sz <= 8:
                self._typecache[sz].append(dt)
            elif sz == 10:
                self._typecache10 = dt
            elif sz == 16:
                self._typecache16 = dt

    def getArch(self):
        """Get the Architecture reference."""
        return self.glb

    def getTypeChar(self) -> Optional[TypeChar]:
        return self._typeChar

    def getTypeBool(self) -> Optional[Datatype]:
        return self._typeBool

    def getDefaultInt(self) -> Optional[Datatype]:
        return self._defaultInt

    def getDefaultUint(self) -> Optional[Datatype]:
        return self._defaultUint

    def getEnumSize(self) -> int:
        return self._enumSize

    # --- Lookup ---

    def findById(self, id_: int) -> Optional[Datatype]:
        return self._typeById.get(id_)

    def findByName(self, name: str) -> Optional[Datatype]:
        return self._typeByName.get(name)

    # --- Core type setup ---

    def setCoreType(self, name: str, size: int, metatype: MetaType, ischar: bool = False) -> Datatype:
        """Set up a core type."""
        if ischar:
            if size == 1:
                dt = TypeChar(name)
            else:
                dt = TypeUnicode(name, size, metatype)
        else:
            dt = TypeBase(size, metatype, name)
        dt.flags |= Datatype.coretype
        self._cacheType(dt)

        if metatype == TYPE_VOID:
            self._typeVoid = dt  # type: ignore
        elif metatype == TYPE_BOOL:
            self._typeBool = dt
        elif ischar and size == 1:
            self._typeChar = dt  # type: ignore

        return dt

    def setupCoreTypes(self) -> None:
        """Set up standard core types."""
        self.setCoreType("void", 0, TYPE_VOID)
        self.setCoreType("bool", 1, TYPE_BOOL)
        self.setCoreType("uint1", 1, TYPE_UINT)
        self.setCoreType("uint2", 2, TYPE_UINT)
        self.setCoreType("uint4", 4, TYPE_UINT)
        self.setCoreType("uint8", 8, TYPE_UINT)
        self.setCoreType("int1", 1, TYPE_INT)
        self.setCoreType("int2", 2, TYPE_INT)
        self.setCoreType("int4", 4, TYPE_INT)
        self.setCoreType("int8", 8, TYPE_INT)
        self.setCoreType("float4", 4, TYPE_FLOAT)
        self.setCoreType("float8", 8, TYPE_FLOAT)
        self.setCoreType("float10", 10, TYPE_FLOAT)
        self.setCoreType("float16", 16, TYPE_FLOAT)
        self.setCoreType("char", 1, TYPE_INT, ischar=True)
        self.setCoreType("wchar2", 2, TYPE_INT, ischar=True)
        self.setCoreType("wchar4", 4, TYPE_INT, ischar=True)
        self.setCoreType("undefined", 1, TYPE_UNKNOWN)
        self.setCoreType("undefined2", 2, TYPE_UNKNOWN)
        self.setCoreType("undefined4", 4, TYPE_UNKNOWN)
        self.setCoreType("undefined8", 8, TYPE_UNKNOWN)
        self.setCoreType("code", 1, TYPE_CODE)
        self._defaultInt = self.findByName("int4")
        self._defaultUint = self.findByName("uint4")
        self._defaultFloat = self.findByName("float8")

    def getSizeOfInt(self) -> int:
        return self._sizeOfInt

    def getSizeOfLong(self) -> int:
        return self._sizeOfLong

    def getSizeOfPointer(self) -> int:
        return self._sizeOfPointer

    def getSizeOfAltPointer(self) -> int:
        """Get size of alternate (far) pointers, or 0 if none.

        C++ ref: TypeFactory::getSizeOfAltPointer
        """
        return getattr(self, '_sizeOfAltPointer', 0)

    def getBaseNoChar(self, s: int, m) -> 'Datatype':
        """Get atomic type excluding 'char'.

        C++ ref: TypeFactory::getBaseNoChar
        If size==1 and metatype==TYPE_INT, return a non-char int type instead of char.
        """
        if s == 1 and m == TYPE_INT:
            nochar = getattr(self, '_type_nochar', None)
            if nochar is not None:
                return nochar
        return self.getBase(s, m)

    def decodeType(self, decoder) -> Optional[Datatype]:
        """Decode a type reference from a stream and resolve it.

        C++ ref: ``TypeFactory::decodeType``

        The stream should contain a type reference element (e.g. <type> or <typeref>)
        with name/id/metatype/size attributes. We try to resolve by id first, then
        by name, and finally create a placeholder if not found.
        """
        elemId = decoder.openElement()
        name = ""
        type_id = 0
        size = 0
        metatype = TYPE_UNKNOWN
        while True:
            attribId = decoder.getNextAttributeId()
            if attribId == 0:
                break
            if attribId == ATTRIB_NAME.id:
                name = decoder.readString()
            elif attribId == ATTRIB_ID.id:
                type_id = decoder.readUnsignedInteger()
            elif attribId == ATTRIB_SIZE.id:
                size = decoder.readSignedInteger()
            elif attribId == ATTRIB_METATYPE.id:
                mt_str = decoder.readString()
                metatype = string2metatype(mt_str)
        decoder.closeElement(elemId)

        # Resolve by id
        if type_id != 0:
            dt = self.findById(type_id)
            if dt is not None:
                return dt
        # Resolve by name
        if name:
            dt = self.findByName(name)
            if dt is not None:
                return dt
        # Create placeholder
        if size > 0:
            return self.getBase(size, metatype, name or f"unk_{size}")
        return self.getBase(1, TYPE_UNKNOWN, name or "undefined")

    def decodeTypeWithCodeFlags(self, decoder, isConstructor: bool,
                                isDestructor: bool) -> Optional[Datatype]:
        """Decode a type with constructor/destructor flags.

        C++ ref: ``TypeFactory::decodeTypeWithCodeFlags``
        """
        dt = self.decodeType(decoder)
        # In a full implementation, the flags would modify the TypeCode
        return dt

    # --- Alignment ---

    def setDefaultAlignmentMap(self) -> None:
        """Set default alignment map.

        C++ ref: TypeFactory::setDefaultAlignmentMap
        """
        self._alignMap = [0, 1, 2, 2, 4, 4, 4, 4, 8]

    def getAlignment(self, size: int) -> int:
        """Return alignment for a primitive of the given size.

        C++ ref: TypeFactory::getAlignment
        """
        amap = getattr(self, '_alignMap', None)
        if amap is None or len(amap) == 0:
            self.setDefaultAlignmentMap()
            amap = self._alignMap
        if size >= len(amap):
            return amap[-1]
        return amap[size]

    def getPrimitiveAlignSize(self, size: int) -> int:
        """Return the aligned size for a primitive (consistent with sizeof).

        C++ ref: TypeFactory::getPrimitiveAlignSize
        """
        align = self.getAlignment(size)
        mod = size % align
        if mod != 0:
            size += (align - mod)
        return size

    # --- Mutation ---

    def setFields(self, fields: list, target, newSize: int, newAlign: int, flags: int = 0) -> None:
        """Set fields on an incomplete struct or union.

        C++ ref: TypeFactory::setFields (struct overload + union overload)
        """
        if not target.isIncomplete():
            raise ValueError("Can only set fields on an incomplete type")
        if isinstance(target, TypeStruct):
            target.setFields(fields)
            target.size = newSize
            target.alignment = newAlign
            target.flags &= ~Datatype.type_incomplete
            target.flags |= (flags & (Datatype.opaque_string | Datatype.variable_length | Datatype.type_incomplete))
            self.recalcPointerSubmeta(target, SubMetaType.SUB_PTR)
            self.recalcPointerSubmeta(target, SubMetaType.SUB_PTR_STRUCT)
        elif isinstance(target, TypeUnion):
            target.setFields(fields)
            target.size = newSize
            target.alignment = newAlign
            target.flags &= ~Datatype.type_incomplete
            target.flags |= (flags & (Datatype.variable_length | Datatype.type_incomplete))

    def setEnumValues(self, nmap: Dict[int, str], te: TypeEnum) -> None:
        """Set value-to-name map on an enumeration type.

        C++ ref: TypeFactory::setEnumValues
        """
        te.setNameMap(nmap)

    def setPrototype(self, fp, newCode: TypeCode, flags: int = 0) -> None:
        """Set prototype on an incomplete TypeCode.

        C++ ref: TypeFactory::setPrototype
        """
        if not newCode.isIncomplete():
            raise ValueError("Can only set prototype on incomplete data-type")
        newCode.setPrototype(self, fp)
        newCode.flags &= ~Datatype.type_incomplete
        newCode.flags |= (flags & (Datatype.variable_length | Datatype.type_incomplete))

    def setName(self, ct: Datatype, n: str) -> Datatype:
        """Rename a data-type.

        C++ ref: TypeFactory::setName
        """
        old_name = ct.name
        if old_name and old_name in self._typeByName and self._typeByName[old_name] is ct:
            del self._typeByName[old_name]
        ct.name = n
        ct.displayName = n
        if ct.id == 0:
            ct.id = Datatype.hashName(n)
            self._typeById[ct.id] = ct
        if n:
            self._typeByName[n] = ct
        return ct

    def setDisplayFormat(self, ct: Datatype, fmt: int) -> None:
        """Set display format on a data-type.

        C++ ref: TypeFactory::setDisplayFormat
        """
        ct.setDisplayFormat(fmt)

    def destroyType(self, ct: Datatype) -> None:
        """Remove a non-core data-type from the factory.

        C++ ref: TypeFactory::destroyType
        """
        if ct.isCoreType():
            raise ValueError("Cannot destroy core type")
        if ct.id in self._typeById:
            del self._typeById[ct.id]
        if ct.name and ct.name in self._typeByName and self._typeByName[ct.name] is ct:
            del self._typeByName[ct.name]

    def clearNoncore(self) -> None:
        """Delete all non-core data-types.

        C++ ref: TypeFactory::clearNoncore
        """
        to_remove = [dt for dt in self._typeById.values() if not dt.isCoreType()]
        for dt in to_remove:
            if dt.id in self._typeById:
                del self._typeById[dt.id]
            if dt.name and dt.name in self._typeByName and self._typeByName[dt.name] is dt:
                del self._typeByName[dt.name]
        self._warnings: list = []

    def clearCache(self) -> None:
        """Clear the matrix of commonly used atomic types.

        C++ ref: TypeFactory::clearCache
        """
        self._typecache = [[] for _ in range(9)]
        self._typecache10 = None
        self._typecache16 = None

    # --- Lookup ---

    def findByIdLocal(self, name: str, type_id: int) -> Optional[Datatype]:
        """Find data-type by name and/or id within this container.

        C++ ref: TypeFactory::findByIdLocal
        """
        if type_id != 0:
            return self._typeById.get(type_id)
        if name:
            return self._typeByName.get(name)
        return None

    def findNoName(self, ct: Datatype) -> Optional[Datatype]:
        """Find data-type without name, using functional comparators.

        C++ ref: TypeFactory::findNoName
        """
        for existing in self._typeById.values():
            if type(existing) is type(ct) and existing.compareDependency(ct) == 0:
                if existing.getSize() == ct.getSize():
                    return existing
        return None

    # --- Dependency ordering ---

    def orderRecurse(self, deporder: list, mark: set, ct: Datatype) -> None:
        """Recursively write out components in dependency order.

        C++ ref: TypeFactory::orderRecurse
        """
        if id(ct) in mark:
            return
        mark.add(id(ct))
        td = ct.getTypedef()
        if td is not None:
            self.orderRecurse(deporder, mark, td)
        n = ct.numDepend()
        for i in range(n):
            dep = ct.getDepend(i)
            if dep is not None:
                self.orderRecurse(deporder, mark, dep)
        deporder.append(ct)

    def dependentOrder(self) -> list:
        """Place all data-types in dependency order.

        C++ ref: TypeFactory::dependentOrder
        """
        deporder: list = []
        mark: set = set()
        for ct in self._typeById.values():
            self.orderRecurse(deporder, mark, ct)
        return deporder

    # --- Warnings ---

    def insertWarning(self, dt: Datatype, warn: str) -> None:
        """Add a warning associated with a data-type.

        C++ ref: TypeFactory::insertWarning
        """
        if dt.getId() == 0:
            raise ValueError("Can only issue warnings for named data-types")
        dt.flags |= Datatype.warning_issued
        if not hasattr(self, '_warnings'):
            self._warnings = []
        self._warnings.append((dt, warn))

    def removeWarning(self, dt: Datatype) -> None:
        """Remove all warnings for the given data-type.

        C++ ref: TypeFactory::removeWarning
        """
        if not hasattr(self, '_warnings'):
            return
        self._warnings = [(d, w) for d, w in self._warnings
                          if not (d.getId() == dt.getId() and d.getName() == dt.getName())]

    # --- Additional type creation ---

    def getTypedef(self, ct: Datatype, name: str, type_id: int = 0, fmt: int = 0) -> Datatype:
        """Find or create a typedef.

        C++ ref: TypeFactory::getTypedef
        """
        if type_id == 0:
            type_id = Datatype.hashName(name)
        existing = self.findByIdLocal(name, type_id)
        if existing is not None:
            if ct is not existing.getTypedef():
                raise ValueError(f"Trying to create typedef of existing type: {name}")
            return existing
        res = ct.clone()
        res.name = name
        res.displayName = name
        res.id = type_id
        res.flags &= ~Datatype.coretype
        res.typedefImm = ct
        res.setDisplayFormat(fmt)
        self._cacheType(res)
        return res

    def getTypePointerWithSpace(self, ptrTo: Datatype, spc, name: str) -> TypePointer:
        """Build a named pointer with an address space attribute.

        C++ ref: TypeFactory::getTypePointerWithSpace
        """
        size = spc.getAddrSize() if hasattr(spc, 'getAddrSize') else self._sizeOfPointer
        tp = TypePointer(size, ptrTo, 1)
        tp.spaceid = spc
        tp.name = name
        tp.displayName = name
        tp.id = Datatype.hashName(name)
        return self.findAdd(tp)

    def getTypePartialEnum(self, contain: TypeEnum, off: int, sz: int) -> TypePartialEnum:
        """Get or create a TypePartialEnum.

        C++ ref: TypeFactory::getTypePartialEnum
        """
        stripped = self.getBase(sz, TYPE_UNKNOWN)
        dt = TypePartialEnum(contain, off, sz, stripped)
        return self.findAdd(dt)

    def getTypeUnicode(self, name: str, sz: int, metatype: MetaType) -> Datatype:
        """Get or create a multi-byte character type.

        C++ ref: TypeFactory::getTypeUnicode
        """
        dt = TypeUnicode(name, sz, metatype)
        dt.id = Datatype.hashName(name)
        return self.findAdd(dt)

    def insert(self, dt: Datatype) -> None:
        """Internal method for inserting a new Datatype.

        C++ ref: TypeFactory::insert
        """
        self._cacheType(dt)

    def resolveIncompleteTypedefs(self) -> None:
        """Resolve typedefs that were initially defined on incomplete types.

        C++ ref: TypeFactory::resolveIncompleteTypedefs
        """
        incomplete = getattr(self, '_incompleteTypedef', [])
        remaining = []
        for dt in incomplete:
            td = dt.getTypedef()
            if td is not None and not td.isIncomplete():
                if dt.getMetatype() == TYPE_STRUCT and isinstance(dt, TypeStruct) and isinstance(td, TypeStruct):
                    self.setFields(td.field, dt, td.size, td.alignment, td.flags)
                elif dt.getMetatype() == TYPE_UNION and isinstance(dt, TypeUnion) and isinstance(td, TypeUnion):
                    self.setFields(td.field, dt, td.size, td.alignment, td.flags)
                elif dt.getMetatype() == TYPE_CODE and isinstance(dt, TypeCode) and isinstance(td, TypeCode):
                    self.setPrototype(td.proto, dt, td.flags)
                else:
                    remaining.append(dt)
                    continue
            else:
                remaining.append(dt)
        self._incompleteTypedef = remaining

    def __repr__(self) -> str:
        return f"TypeFactory({len(self._typeById)} types)"
