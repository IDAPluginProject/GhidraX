"""
Corresponds to: space.hh / space.cc

Classes for describing address spaces.
"""

from __future__ import annotations

import sys
from enum import IntEnum, IntFlag
from typing import TYPE_CHECKING, Optional, List

from ghidra.core.error import LowlevelError
from ghidra.core.marshal import (
    AttributeId, ElementId, Encoder, Decoder,
    ATTRIB_NAME, ATTRIB_INDEX, ATTRIB_SIZE, ATTRIB_WORDSIZE,
    ATTRIB_BIGENDIAN, ATTRIB_DELAY, ATTRIB_PHYSICAL,
    ATTRIB_CONTAIN,
    ATTRIB_BASE, ATTRIB_DEADCODEDELAY, ATTRIB_LOGICALSIZE,
    ATTRIB_PIECE, ATTRIB_SPACE, ATTRIB_OFFSET,
    ELEM_SPACE, ELEM_SPACE_BASE, ELEM_SPACE_UNIQUE, ELEM_SPACE_OTHER,
    ELEM_SPACE_OVERLAY, ELEM_SPACES,
)

if TYPE_CHECKING:
    from ghidra.core.translate import Translate


# =========================================================================
# spacetype enum
# =========================================================================

class SpaceType(IntEnum):
    """Fundamental address space types."""
    IPTR_CONSTANT = 0
    IPTR_PROCESSOR = 1
    IPTR_SPACEBASE = 2
    IPTR_INTERNAL = 3
    IPTR_FSPEC = 4
    IPTR_IOP = 5
    IPTR_JOIN = 6


# Re-export for C++-style access
IPTR_CONSTANT = SpaceType.IPTR_CONSTANT
IPTR_PROCESSOR = SpaceType.IPTR_PROCESSOR
IPTR_SPACEBASE = SpaceType.IPTR_SPACEBASE
IPTR_INTERNAL = SpaceType.IPTR_INTERNAL
IPTR_FSPEC = SpaceType.IPTR_FSPEC
IPTR_IOP = SpaceType.IPTR_IOP
IPTR_JOIN = SpaceType.IPTR_JOIN


_ADDRSPACE_CTOR_UNSET = object()


# =========================================================================
# AddrSpace
# =========================================================================

class AddrSpace:
    """A region where processor data is stored.

    An AddrSpace (Address Space) is an arbitrary sequence of bytes where
    a processor can store data. An integer offset paired with an AddrSpace
    forms the address of a byte.
    """

    # Space attribute flags
    big_endian = 1
    heritaged = 2
    does_deadcode = 4
    programspecific = 8
    reverse_justification = 16
    formal_stackspace = 0x20
    overlay = 0x40
    overlaybase = 0x80
    truncated = 0x100
    hasphysical = 0x200
    is_otherspace = 0x400
    has_nearpointers = 0x800

    def __init__(self, manager: Optional[AddrSpaceManager] = None,
                 trans: Optional[Translate] = None,
                 tp: SpaceType = IPTR_PROCESSOR,
                 name: str | object = _ADDRSPACE_CTOR_UNSET,
                 big_end: bool | object = _ADDRSPACE_CTOR_UNSET,
                 size: int | object = _ADDRSPACE_CTOR_UNSET,
                 word_size: int | object = _ADDRSPACE_CTOR_UNSET,
                 ind: int | object = _ADDRSPACE_CTOR_UNSET,
                 fl: int | object = _ADDRSPACE_CTOR_UNSET,
                 dl: int | object = _ADDRSPACE_CTOR_UNSET,
                 dead: int | object = _ADDRSPACE_CTOR_UNSET) -> None:
        partial_ctor = (
            name is _ADDRSPACE_CTOR_UNSET
            and big_end is _ADDRSPACE_CTOR_UNSET
            and size is _ADDRSPACE_CTOR_UNSET
            and word_size is _ADDRSPACE_CTOR_UNSET
            and ind is _ADDRSPACE_CTOR_UNSET
            and fl is _ADDRSPACE_CTOR_UNSET
            and dl is _ADDRSPACE_CTOR_UNSET
            and dead is _ADDRSPACE_CTOR_UNSET
        )
        name_val = "" if name is _ADDRSPACE_CTOR_UNSET else name
        big_end_val = False if big_end is _ADDRSPACE_CTOR_UNSET else big_end
        size_val = 0 if size is _ADDRSPACE_CTOR_UNSET else size
        word_size_val = 1 if word_size is _ADDRSPACE_CTOR_UNSET else word_size
        ind_val = 0 if ind is _ADDRSPACE_CTOR_UNSET else ind
        fl_val = 0 if fl is _ADDRSPACE_CTOR_UNSET else fl
        dl_val = 0 if dl is _ADDRSPACE_CTOR_UNSET else dl
        dead_val = 0 if dead is _ADDRSPACE_CTOR_UNSET else dead

        self._type: SpaceType = tp
        self._manage: Optional[AddrSpaceManager] = manager
        self._trans: Optional[Translate] = trans
        self._refcount: int = 0
        self._flags: int = 0
        self._name: str = name_val
        self._addressSize: int = size_val
        self._wordsize: int = word_size_val
        self._minimumPointerSize: int = 0
        self._index: int = ind_val
        self._delay: int = dl_val
        self._deadcodedelay: int = dead_val
        self._shortcut: str = ' '
        self._highest: int = 0
        self._pointerLowerBound: int = 0
        self._pointerUpperBound: int = 0

        if partial_ctor:
            self._flags = AddrSpace.heritaged | AddrSpace.does_deadcode
        else:
            self._flags = fl_val & AddrSpace.hasphysical
            if big_end_val:
                self._flags |= AddrSpace.big_endian
            self._flags |= AddrSpace.heritaged | AddrSpace.does_deadcode
            self.calcScaleMask()

    def calcScaleMask(self) -> None:
        """Calculate scale and mask based on addressSize and wordsize."""
        mask = 0xFFFFFFFFFFFFFFFF
        if self._addressSize >= 8:
            highest = mask
        else:
            highest = (1 << (self._addressSize * 8)) - 1
        highest = (highest * self._wordsize + (self._wordsize - 1)) & mask
        self._highest = highest
        self._pointerLowerBound = 0
        self._pointerUpperBound = highest
        buffer_size = 0x100 if self._addressSize < 3 else 0x1000
        self._pointerLowerBound += buffer_size
        self._pointerUpperBound = (self._pointerUpperBound - buffer_size) & mask

    # --- Attribute accessors ---

    def getName(self) -> str:
        return self._name

    def getManager(self) -> Optional[AddrSpaceManager]:
        return self._manage

    def getTrans(self) -> Optional[Translate]:
        return self._trans

    def getType(self) -> SpaceType:
        return self._type

    def getDelay(self) -> int:
        return self._delay

    def getDeadcodeDelay(self) -> int:
        return self._deadcodedelay

    def getIndex(self) -> int:
        return self._index

    def getWordSize(self) -> int:
        return self._wordsize

    def getAddrSize(self) -> int:
        return self._addressSize

    def getHighest(self) -> int:
        return self._highest

    def getPointerLowerBound(self) -> int:
        return self._pointerLowerBound

    def getPointerUpperBound(self) -> int:
        return self._pointerUpperBound

    def getMinimumPtrSize(self) -> int:
        return self._minimumPointerSize

    def wrapOffset(self, off: int) -> int:
        """Wrap *off* to the offset that fits into this space."""
        if 0 <= off <= self._highest:
            return off
        mod = self._highest + 1
        if mod == 0:
            return off  # Full 64-bit space
        res = off % mod
        if res < 0:
            res += mod
        return res

    def getShortcut(self) -> str:
        return self._shortcut

    def isHeritaged(self) -> bool:
        return (self._flags & AddrSpace.heritaged) != 0

    def doesDeadcode(self) -> bool:
        return (self._flags & AddrSpace.does_deadcode) != 0

    def hasPhysical(self) -> bool:
        return (self._flags & AddrSpace.hasphysical) != 0

    def isBigEndian(self) -> bool:
        return (self._flags & AddrSpace.big_endian) != 0

    def isReverseJustified(self) -> bool:
        return (self._flags & AddrSpace.reverse_justification) != 0

    def isFormalStackSpace(self) -> bool:
        return (self._flags & AddrSpace.formal_stackspace) != 0

    def isOverlay(self) -> bool:
        return (self._flags & AddrSpace.overlay) != 0

    def isOverlayBase(self) -> bool:
        return (self._flags & AddrSpace.overlaybase) != 0

    def isOtherSpace(self) -> bool:
        return (self._flags & AddrSpace.is_otherspace) != 0

    def isTruncated(self) -> bool:
        return (self._flags & AddrSpace.truncated) != 0

    def hasNearPointers(self) -> bool:
        return (self._flags & AddrSpace.has_nearpointers) != 0

    def setFlags(self, fl: int) -> None:
        self._flags |= fl

    def clearFlags(self, fl: int) -> None:
        self._flags &= ~fl

    def truncateSpace(self, newsize: int) -> None:
        self._flags |= AddrSpace.truncated
        self._addressSize = newsize
        self._minimumPointerSize = newsize
        self.calcScaleMask()

    # --- Virtual methods ---

    def numSpacebase(self) -> int:
        return 0

    def getSpacebase(self, i: int):
        raise LowlevelError(f"{self._name} space is not virtual and has no associated base register")

    def getSpacebaseFull(self, i: int):
        raise LowlevelError(f"{self._name} has no truncated registers")

    def stackGrowsNegative(self) -> bool:
        return True

    def getContain(self) -> Optional[AddrSpace]:
        return None

    def overlapJoin(self, offset: int, size: int,
                    point_space: Optional[AddrSpace], point_off: int, point_skip: int) -> int:
        if point_space != self:
            return -1
        dist = self.wrapOffset(point_off + point_skip - offset)
        if dist >= size:
            return -1
        return dist

    def encodeAttributes(self, encoder: Encoder, offset: int, size: int = -1) -> None:
        """Encode address attributes to a stream."""
        encoder.writeString(ATTRIB_SPACE, self._name)
        encoder.writeUnsignedInteger(ATTRIB_OFFSET, offset)
        if size >= 0:
            encoder.writeSignedInteger(ATTRIB_SIZE, size)

    def decodeAttributes(self, decoder: Decoder) -> tuple[int, int]:
        """Recover an offset and size. Returns (offset, size)."""
        offset = 0
        size = 0
        while True:
            attrib_id = decoder.getNextAttributeId()
            if attrib_id == 0:
                break
            if attrib_id == ATTRIB_OFFSET.id:
                offset = decoder.readUnsignedInteger()
            elif attrib_id == ATTRIB_SIZE.id:
                size = decoder.readUnsignedInteger()
        return offset, size

    def printRaw(self, offset: int) -> str:
        """Return a raw version of the address as a string."""
        return f"{self._shortcut}{offset:#x}"

    def printOffset(self, offset: int) -> str:
        """Write an address offset as a string."""
        return f"0x{offset:0{self._addressSize * 2}x}"

    def read(self, s: str) -> tuple[int, int]:
        """Read in an address (and possible size) from a string. Returns (offset, size)."""
        return int(s, 0), 0

    def decode(self, decoder: Decoder) -> None:
        """Recover the details of this space from a stream."""
        elem_id = decoder.openElement()
        self.decodeBasicAttributes(decoder)
        decoder.closeElement(elem_id)

    def decodeBasicAttributes(self, decoder: Decoder) -> None:
        """Read attributes for this space from an open XML element."""
        self._deadcodedelay = -1
        while True:
            attrib_id = decoder.getNextAttributeId()
            if attrib_id == 0:
                break
            if attrib_id == ATTRIB_NAME.id:
                self._name = decoder.readString()
            elif attrib_id == ATTRIB_INDEX.id:
                self._index = decoder.readSignedInteger()
            elif attrib_id == ATTRIB_SIZE.id:
                self._addressSize = decoder.readSignedInteger()
            elif attrib_id == ATTRIB_WORDSIZE.id:
                self._wordsize = decoder.readUnsignedInteger()
            elif attrib_id == ATTRIB_BIGENDIAN.id:
                if decoder.readBool():
                    self._flags |= AddrSpace.big_endian
            elif attrib_id == ATTRIB_DELAY.id:
                self._delay = decoder.readSignedInteger()
            elif attrib_id == ATTRIB_DEADCODEDELAY.id:
                self._deadcodedelay = decoder.readSignedInteger()
            elif attrib_id == ATTRIB_PHYSICAL.id:
                if decoder.readBool():
                    self._flags |= AddrSpace.hasphysical
        if self._deadcodedelay == -1:
            self._deadcodedelay = self._delay
        self.calcScaleMask()

    # --- Static methods ---

    @staticmethod
    def addressToByte(val: int, ws: int) -> int:
        return val * ws

    @staticmethod
    def byteToAddress(val: int, ws: int) -> int:
        return val // ws

    @staticmethod
    def addressToByteInt(val: int, ws: int) -> int:
        return val * ws

    @staticmethod
    def byteToAddressInt(val: int, ws: int) -> int:
        return val // ws

    @staticmethod
    def compareByIndex(a: AddrSpace, b: AddrSpace) -> bool:
        return a._index < b._index

    def __repr__(self) -> str:
        return f"AddrSpace({self._name!r}, index={self._index}, type={self._type.name})"


# =========================================================================
# ConstantSpace
# =========================================================================

class ConstantSpace(AddrSpace):
    """Special AddrSpace for representing constants during analysis."""

    NAME: str = "const"
    INDEX: int = 0

    def __init__(self, manager: Optional[AddrSpaceManager] = None,
                 trans: Optional[Translate] = None) -> None:
        super().__init__(manager, trans, IPTR_CONSTANT, ConstantSpace.NAME,
                         False, 8, 1, ConstantSpace.INDEX, 0, 0, 0)
        self.clearFlags(AddrSpace.heritaged | AddrSpace.does_deadcode | AddrSpace.big_endian)
        if sys.byteorder == "big":
            self.setFlags(AddrSpace.big_endian)
        self._shortcut = '#'

    def overlapJoin(self, offset, size, point_space, point_off, point_skip):
        return -1

    def printRaw(self, offset: int) -> str:
        return f"#{offset:#x}"

    def decode(self, decoder: Decoder) -> None:
        pass


# =========================================================================
# OtherSpace
# =========================================================================

class OtherSpace(AddrSpace):
    """Special AddrSpace for special/user-defined address spaces."""

    NAME: str = "OTHER"
    INDEX: int = 1

    def __init__(self, manager: Optional[AddrSpaceManager] = None,
                 trans: Optional[Translate] = None,
                 ind: int = -1) -> None:
        idx = ind if ind >= 0 else OtherSpace.INDEX
        super().__init__(manager, trans, IPTR_PROCESSOR, OtherSpace.NAME,
                         False, 8, 1, idx, 0, 0, 0)
        self.clearFlags(AddrSpace.heritaged | AddrSpace.does_deadcode)
        self.setFlags(AddrSpace.is_otherspace)
        self._shortcut = 'o'

    def printRaw(self, offset: int) -> str:
        return f"o{offset:#x}"


# =========================================================================
# UniqueSpace
# =========================================================================

class UniqueSpace(AddrSpace):
    """The pool of temporary storage registers."""

    NAME: str = "unique"
    SIZE: int = 4

    def __init__(self, manager: Optional[AddrSpaceManager] = None,
                 trans: Optional[Translate] = None,
                 ind: int = 0,
                 fl: int = 0) -> None:
        super().__init__(manager, trans, IPTR_INTERNAL, UniqueSpace.NAME,
                         False, UniqueSpace.SIZE, 1, ind, fl, 0, 0)
        self.setFlags(AddrSpace.hasphysical)
        self._shortcut = 'u'


# =========================================================================
# JoinSpace
# =========================================================================

class JoinSpace(AddrSpace):
    """The pool of logically joined variables."""

    NAME: str = "join"
    MAX_PIECES: int = 64

    def __init__(self, manager: Optional[AddrSpaceManager] = None,
                 trans: Optional[Translate] = None,
                 ind: int = 0) -> None:
        super().__init__(manager, trans, IPTR_JOIN, JoinSpace.NAME,
                         False, 8, 1, ind, 0, 0, 0)
        self.clearFlags(AddrSpace.heritaged)
        self._shortcut = 'j'

    def printRaw(self, offset: int) -> str:
        return f"j{offset:#x}"


# =========================================================================
# SpacebaseSpace
# =========================================================================

class SpacebaseSpace(AddrSpace):
    """A virtual space indexed by a base register."""

    def __init__(self, manager: Optional[AddrSpaceManager],
                 trans: Optional[Translate],
                 name: str = "",
                 ind: int = 0,
                 size: int = 0,
                 base: Optional[AddrSpace] = None,
                 dl: int = 0,
                 isFormal: bool = False) -> None:
        if trans is None or base is None or name == "":
            super().__init__(manager, trans, IPTR_SPACEBASE)
            self._flags |= AddrSpace.programspecific
            self._contain = None
            self._hasBaseRegister = False
            self._isNegativeStack = True
            self._baseloc = None
            self._baseOrig = None
            return

        super().__init__(
            manager,
            trans,
            IPTR_SPACEBASE,
            name,
            trans.isBigEndian(),
            size,
            base.getWordSize(),
            ind,
            0,
            dl,
            dl,
        )
        self._contain = base
        self._hasBaseRegister = False
        self._isNegativeStack = True
        self._baseloc = None
        self._baseOrig = None
        if isFormal:
            self.setFlags(AddrSpace.formal_stackspace)

    def setBaseRegister(self, data, truncSize: int, stackGrowth: bool) -> None:
        if self._hasBaseRegister:
            if self._baseloc != data or self._isNegativeStack != stackGrowth:
                raise LowlevelError(
                    "Attempt to assign more than one base register to space: " + self.getName()
                )
        self._hasBaseRegister = True
        self._isNegativeStack = stackGrowth
        self._baseOrig = data

        from ghidra.core.pcoderaw import VarnodeData

        baseloc = VarnodeData(data.space, data.offset, data.size)
        if truncSize != baseloc.size:
            if baseloc.space.isBigEndian():
                baseloc.offset += baseloc.size - truncSize
            baseloc.size = truncSize
        self._baseloc = baseloc

    def numSpacebase(self) -> int:
        return 1 if self._hasBaseRegister else 0

    def getSpacebase(self, i: int):
        if i != 0 or self._baseloc is None:
            raise IndexError("SpacebaseSpace has no spacebase at requested index")
        return self._baseloc

    def getSpacebaseFull(self, i: int):
        if i != 0 or self._baseOrig is None:
            raise IndexError("SpacebaseSpace has no full spacebase at requested index")
        return self._baseOrig

    def stackGrowsNegative(self) -> bool:
        return self._isNegativeStack

    def getContain(self) -> Optional[AddrSpace]:
        return self._contain

    def decode(self, decoder: Decoder) -> None:
        elem_id = decoder.openElement(ELEM_SPACE_BASE)
        self.decodeBasicAttributes(decoder)
        self._contain = decoder.readSpace(ATTRIB_CONTAIN)
        decoder.closeElement(elem_id)


# =========================================================================
# OverlaySpace
# =========================================================================

class OverlaySpace(AddrSpace):
    """An overlay space occupying the same memory as another address space."""

    def __init__(self, manager: Optional[AddrSpaceManager] = None,
                 trans: Optional[Translate] = None) -> None:
        super().__init__(manager, trans, IPTR_PROCESSOR)
        self._baseSpace: Optional[AddrSpace] = None

    def getContain(self) -> Optional[AddrSpace]:
        return self._baseSpace

    def decode(self, decoder: Decoder) -> None:
        elem_id = decoder.openElement(ELEM_SPACE_OVERLAY)
        self._name = decoder.readString(ATTRIB_NAME)
        self._index = decoder.readSignedInteger(ATTRIB_INDEX)
        self._baseSpace = decoder.readSpace(ATTRIB_BASE)
        decoder.closeElement(elem_id)

        assert self._baseSpace is not None
        self._addressSize = self._baseSpace.getAddrSize()
        self._wordsize = self._baseSpace.getWordSize()
        self._delay = self._baseSpace.getDelay()
        self._deadcodedelay = self._baseSpace.getDeadcodeDelay()
        self.calcScaleMask()
        self._flags |= AddrSpace.overlay
        if self._baseSpace.isBigEndian():
            self._flags |= AddrSpace.big_endian
        if self._baseSpace.hasPhysical():
            self._flags |= AddrSpace.hasphysical


# =========================================================================
# AddrSpaceManager
# =========================================================================

class AddrSpaceManager:
    """Container and manager for all address spaces.

    Corresponds to the AddrSpaceManager class from space.hh / translate.hh.
    """

    def __init__(self) -> None:
        self._spaces: List[AddrSpace] = []
        self._name2space: dict[str, AddrSpace] = {}
        self._defaultCodeSpace: Optional[AddrSpace] = None
        self._defaultDataSpace: Optional[AddrSpace] = None
        self._constantSpace: Optional[ConstantSpace] = None
        self._uniqueSpace: Optional[UniqueSpace] = None
        self._joinSpace: Optional[JoinSpace] = None
        self._iopSpace: Optional[AddrSpace] = None
        self._fspecSpace: Optional[AddrSpace] = None
        self._stackSpace: Optional[AddrSpace] = None
        self._resolvers: List[object | None] = []

    # --- Space insertion / lookup ---

    def _insertSpace(self, spc: AddrSpace) -> None:
        """Register an address space with the manager."""
        while len(self._spaces) <= spc.getIndex():
            self._spaces.append(None)  # type: ignore[arg-type]
        self._spaces[spc.getIndex()] = spc
        self._name2space[spc.getName()] = spc

    def setReverseJustified(self, spc: AddrSpace) -> None:
        spc.setFlags(AddrSpace.reverse_justification)

    def assignShortcut(self, spc: AddrSpace) -> None:
        if spc.getShortcut() != ' ':
            return

        tp = spc.getType()
        if tp == IPTR_CONSTANT:
            shortcut = '#'
        elif tp == IPTR_PROCESSOR:
            if spc.getName() == "register":
                shortcut = '%'
            else:
                shortcut = spc.getName()[0] if len(spc.getName()) != 0 else 'x'
        elif tp == IPTR_SPACEBASE:
            shortcut = 's'
        elif tp == IPTR_INTERNAL:
            shortcut = 'u'
        elif tp == IPTR_FSPEC:
            shortcut = 'f'
        elif tp == IPTR_JOIN:
            shortcut = 'j'
        elif tp == IPTR_IOP:
            shortcut = 'i'
        else:
            shortcut = 'x'

        if 'A' <= shortcut <= 'Z':
            shortcut = chr(ord(shortcut) + 0x20)

        collisionCount = 0
        while True:
            existing = self.getSpaceByShortcut(shortcut)
            if existing is None or existing is spc:
                spc._shortcut = shortcut
                return
            collisionCount += 1
            if collisionCount > 26:
                spc._shortcut = 'z'
                return
            shortcut = chr(ord(shortcut) + 1)
            if shortcut < 'a' or shortcut > 'z':
                shortcut = 'a'

    def insertSpace(self, spc: AddrSpace) -> None:
        nameTypeMismatch = False
        duplicateName = False
        duplicateId = False

        tp = spc.getType()
        if tp == IPTR_CONSTANT:
            if spc.getName() != ConstantSpace.NAME:
                nameTypeMismatch = True
            if spc.getIndex() != ConstantSpace.INDEX:
                raise LowlevelError("const space must be assigned index 0")
        elif tp == IPTR_INTERNAL:
            if spc.getName() != UniqueSpace.NAME:
                nameTypeMismatch = True
            duplicateName = self._uniqueSpace is not None
        elif tp == IPTR_FSPEC:
            if spc.getName() != "fspec":
                nameTypeMismatch = True
            duplicateName = self._fspecSpace is not None
        elif tp == IPTR_JOIN:
            if spc.getName() != JoinSpace.NAME:
                nameTypeMismatch = True
            duplicateName = self._joinSpace is not None
        elif tp == IPTR_IOP:
            if spc.getName() != "iop":
                nameTypeMismatch = True
            duplicateName = self._iopSpace is not None
        elif tp in (IPTR_SPACEBASE, IPTR_PROCESSOR):
            if tp == IPTR_SPACEBASE and spc.getName() == "stack":
                duplicateName = self._stackSpace is not None
            if spc.isOverlay():
                contain = spc.getContain()
                if contain is not None:
                    contain.setFlags(AddrSpace.overlaybase)
            elif spc.isOtherSpace():
                if spc.getIndex() != OtherSpace.INDEX:
                    raise LowlevelError("OTHER space must be assigned index 1")

        if spc.getIndex() < len(self._spaces):
            duplicateId = self._spaces[spc.getIndex()] is not None

        if not nameTypeMismatch and not duplicateName and not duplicateId:
            duplicateName = spc.getName() in self._name2space

        if nameTypeMismatch or duplicateName or duplicateId:
            errMsg = "Space " + spc.getName()
            if nameTypeMismatch:
                errMsg += " was initialized with wrong type"
            if duplicateName:
                errMsg += " was initialized more than once"
            if duplicateId:
                existing = self._spaces[spc.getIndex()]
                existing_name = existing.getName() if existing is not None else "unknown"
                errMsg += " was assigned as id duplicating: " + existing_name
            raise LowlevelError(errMsg)

        self._insertSpace(spc)
        if tp == IPTR_CONSTANT:
            self._constantSpace = spc  # type: ignore[assignment]
        elif tp == IPTR_INTERNAL:
            self._uniqueSpace = spc  # type: ignore[assignment]
        elif tp == IPTR_FSPEC:
            self._fspecSpace = spc
        elif tp == IPTR_JOIN:
            self._joinSpace = spc  # type: ignore[assignment]
        elif tp == IPTR_IOP:
            self._iopSpace = spc
        elif tp == IPTR_SPACEBASE and spc.getName() == "stack":
            self._stackSpace = spc
        spc._refcount += 1
        self.assignShortcut(spc)

    def copySpaces(self, op2) -> None:
        """Copy every space managed by another AddrSpaceManager."""
        for i in range(op2.numSpaces()):
            spc = op2.getSpace(i)
            if spc is not None:
                self.insertSpace(spc)
        self.setDefaultCodeSpace(op2.getDefaultCodeSpace())
        self.setDefaultDataSpace(op2.getDefaultDataSpace())

    def addSpacebasePointer(self, basespace: SpacebaseSpace, ptrdata, truncSize: int,
                            stackGrowth: bool) -> None:
        basespace.setBaseRegister(ptrdata, truncSize, stackGrowth)

    def setDeadcodeDelay(self, spc: AddrSpace, delaydelta: int) -> None:
        spc._deadcodedelay = delaydelta

    def setInferPtrBounds(self, range_: Range) -> None:
        spc = range_.getSpace()
        spc._pointerLowerBound = range_.getFirst()
        spc._pointerUpperBound = range_.getLast()

    def insertResolver(self, spc: AddrSpace, rsolv) -> None:
        ind = spc.getIndex()
        while len(self._resolvers) <= ind:
            self._resolvers.append(None)
        self._resolvers[ind] = rsolv

    def markNearPointers(self, spc: AddrSpace, size: int) -> None:
        spc.setFlags(AddrSpace.has_nearpointers)
        if spc.getMinimumPtrSize() == 0 and spc.getAddrSize() != size:
            spc._minimumPointerSize = size

    def getSpaceByName(self, name: str) -> AddrSpace:
        """Get a space by its name. Raises LowlevelError if not found."""
        spc = self._name2space.get(name)
        if spc is None:
            raise LowlevelError(f"Unknown address space: {name}")
        return spc

    def getSpaceByIndex(self, index: int) -> Optional[AddrSpace]:
        """Get a space by its integer index."""
        if 0 <= index < len(self._spaces):
            return self._spaces[index]
        return None

    def getSpaceByShortcut(self, sc: str) -> Optional[AddrSpace]:
        """Get a space by its shortcut character."""
        for spc in self._spaces:
            if spc is not None and spc.getShortcut() == sc:
                return spc
        return None

    def numSpaces(self) -> int:
        return len(self._spaces)

    def getSpace(self, i: int) -> Optional[AddrSpace]:
        if 0 <= i < len(self._spaces):
            return self._spaces[i]
        return None

    def getConstantSpace(self) -> ConstantSpace:
        assert self._constantSpace is not None
        return self._constantSpace

    def getDefaultCodeSpace(self) -> AddrSpace:
        assert self._defaultCodeSpace is not None
        return self._defaultCodeSpace

    def getDefaultDataSpace(self) -> AddrSpace:
        assert self._defaultDataSpace is not None
        return self._defaultDataSpace

    def getUniqueSpace(self) -> UniqueSpace:
        assert self._uniqueSpace is not None
        return self._uniqueSpace

    def getJoinSpace(self) -> JoinSpace:
        assert self._joinSpace is not None
        return self._joinSpace

    def getStackSpace(self) -> Optional[AddrSpace]:
        return self._stackSpace

    def setDefaultCodeSpace(self, spc: AddrSpace) -> None:
        self._defaultCodeSpace = spc

    def setDefaultDataSpace(self, spc: AddrSpace) -> None:
        self._defaultDataSpace = spc

    def parseAddressSimple(self, val: str):
        """Parse a hexadecimal address string with an optional space prefix."""
        from ghidra.core.address import Address

        col = val.find(":")
        if col == -1:
            spc = self.getDefaultDataSpace()
            col = 0
        else:
            spcName = val[:col]
            spc = self.getSpaceByName(spcName)
            if spc is None:
                raise LowlevelError("Unknown address space: " + spcName)
            col += 1
        if col + 2 <= len(val) and val[col:col + 2] == "0x":
            col += 2
        off = int(val[col:], 16)
        return Address(spc, AddrSpace.addressToByte(off, spc.getWordSize()))

    def renormalizeJoinAddress(self, addr, size: int) -> None:
        """Re-evaluate a join address in terms of its new offset and size."""
        pass  # Placeholder – full implementation requires JoinRecord tracking

    def __repr__(self) -> str:
        names = [s.getName() for s in self._spaces if s is not None]
        return f"AddrSpaceManager(spaces={names})"
