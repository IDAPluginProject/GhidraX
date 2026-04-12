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
    ATTRIB_CONTAIN, ATTRIB_DEFAULTSPACE,
    ATTRIB_BASE, ATTRIB_DEADCODEDELAY, ATTRIB_LOGICALSIZE,
    ATTRIB_PIECE, ATTRIB_SPACE, ATTRIB_OFFSET, ATTRIB_UNKNOWN,
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
_SPACE_ORDER_MAX = object()


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
        encoder.writeSpace(ATTRIB_SPACE, self)
        encoder.writeUnsignedInteger(ATTRIB_OFFSET, offset)
        if size >= 0:
            encoder.writeSignedInteger(ATTRIB_SIZE, size)

    def decodeAttributes(self, decoder: Decoder) -> tuple[int, int]:
        """Recover an offset and size. Returns (offset, size)."""
        offset = 0
        size = 0
        found_offset = False
        while True:
            attrib_id = decoder.getNextAttributeId()
            if attrib_id == 0:
                break
            if attrib_id == ATTRIB_OFFSET.id:
                found_offset = True
                offset = decoder.readUnsignedInteger()
            elif attrib_id == ATTRIB_SIZE.id:
                size = decoder.readSignedInteger()
        if not found_offset:
            raise LowlevelError("Address is missing offset")
        return offset, size

    def printRaw(self, offset: int) -> str:
        """Return a raw version of the address as a string."""
        sz = self.getAddrSize()
        if sz > 4:
            if (offset >> 32) == 0:
                sz = 4
            elif (offset >> 48) == 0:
                sz = 6
        res = f"0x{self.byteToAddress(offset, self._wordsize):0{2 * sz}x}"
        if self._wordsize > 1:
            cut = offset % self._wordsize
            if cut != 0:
                res += f"+{cut}"
        return res

    def printOffset(self, offset: int) -> str:
        """Write an address offset as a string."""
        return f"0x{offset:x}"

    def read(self, s: str) -> tuple[int, int]:
        """Read in an address (and possible size) from a string. Returns (offset, size)."""
        def get_offset_size(ptr: str, offset: int) -> tuple[int, int]:
            size = -1
            val = 0
            if ptr.startswith(':'):
                rest = ptr[1:]
                plus_pos = rest.find('+')
                if plus_pos == -1:
                    size = int(rest, 0)
                else:
                    size = int(rest[:plus_pos], 0)
                    val = int(rest[plus_pos + 1:], 0)
            elif ptr.startswith('+'):
                val = int(ptr[1:], 0)
            return size, offset + val

        append = min((pos for pos in (s.find(':'), s.find('+')) if pos != -1), default=-1)
        try:
            if self._trans is None:
                raise LowlevelError("No translator available")
            if append == -1:
                point = self._trans.getRegister(s)
            else:
                point = self._trans.getRegister(s[:append])
            offset = point.offset
            size = point.size
        except LowlevelError:
            if self._manage is None:
                raise
            offset = self.addressToByte(int(s if append == -1 else s[:append], 0), self._wordsize)
            size = self._manage.getDefaultCodeSpace().getAddrSize()
            if append == -1:
                return offset, size

        if append != -1:
            explicit_size, offset = get_offset_size(s[append:], offset)
            if explicit_size != -1:
                size = explicit_size
        return offset, size

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
        # C++ signed integer division truncates toward zero; Python // floors.
        return val // ws if val >= 0 else -((-val) // ws)

    @staticmethod
    def compareByIndex(a: AddrSpace, b: AddrSpace) -> bool:
        return a._index < b._index

    def __repr__(self) -> str:
        return f"AddrSpace({self._name!r}, index={self._index}, type={self._type.name})"


class JoinRecord:
    """Describe how a logical value is split across multiple physical pieces."""

    __slots__ = ("_pieces", "_unified")

    def __init__(self, pieces=None, unified=None) -> None:
        self._pieces = [] if pieces is None else pieces
        self._unified = unified

    def numPieces(self) -> int:
        return len(self._pieces)

    def isFloatExtension(self) -> bool:
        return len(self._pieces) == 1

    def getPiece(self, i: int):
        return self._pieces[i]

    def getUnified(self):
        return self._unified

    def __lt__(self, other) -> bool:
        if not isinstance(other, JoinRecord):
            return NotImplemented
        if self._unified.size != other._unified.size:
            return self._unified.size < other._unified.size
        i = 0
        while True:
            if len(self._pieces) == i:
                return len(other._pieces) > i
            if len(other._pieces) == i:
                return False
            if self._pieces[i] != other._pieces[i]:
                return self._pieces[i] < other._pieces[i]
            i += 1

    def getEquivalentAddress(self, offset: int):
        from ghidra.core.address import Address

        if self._unified is None or offset < self._unified.offset:
            return Address(), -1
        small_off = int(offset - self._unified.offset)
        if self._pieces[0].space.isBigEndian():
            pos = 0
            while pos < len(self._pieces):
                piece_size = self._pieces[pos].size
                if small_off < piece_size:
                    break
                small_off -= piece_size
                pos += 1
            if pos == len(self._pieces):
                return Address(), -1
        else:
            pos = len(self._pieces) - 1
            while pos >= 0:
                piece_size = self._pieces[pos].size
                if small_off < piece_size:
                    break
                small_off -= piece_size
                pos -= 1
            if pos < 0:
                return Address(), -1
        piece = self._pieces[pos]
        return Address(piece.space, piece.offset + small_off), pos

    @staticmethod
    def mergeSequence(seq, trans: Translate) -> None:
        from ghidra.core.pcoderaw import VarnodeData

        i = 1
        while i < len(seq):
            hi = seq[i - 1]
            lo = seq[i]
            if hi.isContiguous(lo):
                break
            i += 1
        if i >= len(seq):
            return

        res = [VarnodeData(seq[0].space, seq[0].offset, seq[0].size)]
        i = 1
        last_is_informal = False
        while i < len(seq):
            hi = res[-1]
            lo = seq[i]
            if hi.isContiguous(lo):
                hi.offset = hi.offset if hi.space.isBigEndian() else lo.offset
                hi.size += lo.size
                if hi.space.getType() != IPTR_SPACEBASE:
                    last_is_informal = len(trans.getExactRegisterName(hi.space, hi.offset, hi.size)) == 0
            else:
                if last_is_informal:
                    break
                res.append(VarnodeData(lo.space, lo.offset, lo.size))
            i += 1
        if last_is_informal:
            return
        seq[:] = res


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
        return f"0x{offset:x}"

    def decode(self, decoder: Decoder) -> None:
        raise LowlevelError("Should never decode the constant space")


# =========================================================================
# OtherSpace
# =========================================================================

class OtherSpace(AddrSpace):
    """Special AddrSpace for special/user-defined address spaces."""

    NAME: str = "OTHER"
    INDEX: int = 1

    def __init__(self, manager: Optional[AddrSpaceManager] = None,
                 trans: Optional[Translate] = None,
                 ind: int | object = _ADDRSPACE_CTOR_UNSET) -> None:
        if ind is _ADDRSPACE_CTOR_UNSET:
            super().__init__(manager, trans, IPTR_PROCESSOR)
        else:
            super().__init__(manager, trans, IPTR_PROCESSOR, OtherSpace.NAME,
                             False, 8, 1, OtherSpace.INDEX, 0, 0, 0)
        self.clearFlags(AddrSpace.heritaged | AddrSpace.does_deadcode)
        self.setFlags(AddrSpace.is_otherspace)
        self._shortcut = 'o'

    def printRaw(self, offset: int) -> str:
        return f"0x{offset:x}"


# =========================================================================
# UniqueSpace
# =========================================================================

class UniqueSpace(AddrSpace):
    """The pool of temporary storage registers."""

    NAME: str = "unique"
    SIZE: int = 4

    def __init__(self, manager: Optional[AddrSpaceManager] = None,
                 trans: Optional[Translate] = None,
                 ind: int | object = _ADDRSPACE_CTOR_UNSET,
                 fl: int | object = _ADDRSPACE_CTOR_UNSET) -> None:
        if ind is _ADDRSPACE_CTOR_UNSET and fl is _ADDRSPACE_CTOR_UNSET:
            super().__init__(manager, trans, IPTR_INTERNAL)
        else:
            ind_val = 0 if ind is _ADDRSPACE_CTOR_UNSET else ind
            fl_val = 0 if fl is _ADDRSPACE_CTOR_UNSET else fl
            big_end = trans.isBigEndian() if trans is not None and hasattr(trans, "isBigEndian") else False
            super().__init__(manager, trans, IPTR_INTERNAL, UniqueSpace.NAME,
                             big_end, UniqueSpace.SIZE, 1, ind_val, fl_val, 0, 0)
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
        big_end = trans.isBigEndian() if trans is not None and hasattr(trans, "isBigEndian") else False
        super().__init__(manager, trans, IPTR_JOIN, JoinSpace.NAME,
                         big_end, 8, 1, ind, 0, 0, 0)
        self.clearFlags(AddrSpace.heritaged)
        self._shortcut = 'j'

    def printRaw(self, offset: int) -> str:
        rec = self.getManager().findJoin(offset)
        szsum = 0
        pieces = []
        for i in range(rec.numPieces()):
            vdat = rec.getPiece(i)
            szsum += vdat.size
            pieces.append(vdat.space.printRaw(vdat.offset))
        if rec.numPieces() == 1:
            szsum = rec.getUnified().size
            return "{" + ",".join(pieces) + f":{szsum}" + "}"
        return "{" + ",".join(pieces) + "}"

    def encodeAttributes(self, encoder: Encoder, offset: int, size: int = -1) -> None:
        rec = self.getManager().findJoin(offset)
        encoder.writeSpace(ATTRIB_SPACE, self)
        num = rec.numPieces()
        if num > JoinSpace.MAX_PIECES:
            raise LowlevelError("Exceeded maximum pieces in one join address")
        for i in range(num):
            vdata = rec.getPiece(i)
            encoder.writeStringIndexed(
                ATTRIB_PIECE,
                i,
                f"{vdata.space.getName()}:0x{vdata.offset:x}:{vdata.size}",
            )
        if num == 1:
            encoder.writeUnsignedInteger(ATTRIB_LOGICALSIZE, rec.getUnified().size)

    def overlapJoin(self, offset: int, size: int,
                    point_space: Optional[AddrSpace], point_off: int, point_skip: int) -> int:
        if point_space is self:
            piece_record = self.getManager().findJoin(point_off)
            addr, _ = piece_record.getEquivalentAddress(point_off + point_skip)
            point_space = addr.getSpace()
            point_off = addr.getOffset()
        else:
            if point_space.getType() == IPTR_CONSTANT:
                return -1
            point_off = point_space.wrapOffset(point_off + point_skip)

        join_record = self.getManager().findJoin(offset)
        if self.isBigEndian():
            start_piece = 0
            end_piece = join_record.numPieces()
            direction = 1
        else:
            start_piece = join_record.numPieces() - 1
            end_piece = -1
            direction = -1

        bytes_accum = 0
        for i in range(start_piece, end_piece, direction):
            vdata = join_record.getPiece(i)
            if (
                vdata.space is point_space
                and point_off >= vdata.offset
                and point_off <= vdata.offset + (vdata.size - 1)
            ):
                res = int(point_off - vdata.offset) + bytes_accum
                if res >= size:
                    return -1
                return res
            bytes_accum += vdata.size
        return -1

    def decodeAttributes(self, decoder: Decoder) -> tuple[int, int]:
        from ghidra.core.pcoderaw import VarnodeData

        pieces: list[VarnodeData] = []
        sizesum = 0
        logicalsize = 0
        while True:
            attrib_id = decoder.getNextAttributeId()
            if attrib_id == 0:
                break
            if attrib_id == ATTRIB_LOGICALSIZE.id:
                logicalsize = decoder.readUnsignedInteger()
                continue
            if attrib_id == ATTRIB_UNKNOWN.id:
                attrib_id = decoder.getIndexedAttributeId(ATTRIB_PIECE)
            if attrib_id < ATTRIB_PIECE.getId():
                continue
            pos = int(attrib_id - ATTRIB_PIECE.getId())
            if pos > JoinSpace.MAX_PIECES:
                continue
            while len(pieces) <= pos:
                pieces.append(VarnodeData())
            vdat = pieces[pos]

            attr_val = decoder.readString()
            offpos = attr_val.find(":")
            if offpos == -1:
                point = self.getTrans().getRegister(attr_val)
                copied = VarnodeData(point.space, point.offset, point.size)
                copied.setSpaceFromConst(point.getSpaceFromConst())
                pieces[pos] = copied
                vdat = copied
            else:
                szpos = attr_val.find(":", offpos + 1)
                if szpos == -1:
                    raise LowlevelError("join address piece attribute is malformed")
                spcname = attr_val[:offpos]
                vdat.space = self.getManager().getSpaceByName(spcname)
                vdat.offset = int(attr_val[offpos + 1:szpos], 0)
                vdat.size = int(attr_val[szpos + 1:], 0)
            sizesum += vdat.size

        rec = self.getManager().findAddJoin(pieces, logicalsize)
        return rec.getUnified().offset, rec.getUnified().size

    def read(self, s: str) -> tuple[int, int]:
        from ghidra.core.pcoderaw import VarnodeData

        pieces: list[VarnodeData] = []
        szsum = 0
        i = 0
        while i < len(s):
            pieces.append(VarnodeData())
            token = ""
            while i < len(s) and s[i] != ",":
                token += s[i]
                i += 1
            i += 1
            try:
                point = self.getTrans().getRegister(token)
                copied = VarnodeData(point.space, point.offset, point.size)
                copied.setSpaceFromConst(point.getSpaceFromConst())
                pieces[-1] = copied
            except LowlevelError:
                try_shortcut = token[0]
                spc = self.getManager().getSpaceByShortcut(try_shortcut)
                if spc is None:
                    raise LowlevelError("Could not parse join string")
                suboff, subsize = spc.read(token[1:])
                pieces[-1].space = spc
                pieces[-1].offset = suboff
                pieces[-1].size = subsize
            szsum += pieces[-1].size
        rec = self.getManager().findAddJoin(pieces, 0)
        return rec.getUnified().offset, szsum

    def decode(self, decoder: Decoder) -> None:
        raise LowlevelError("Should never decode join space")


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

        from ghidra.core.pcoderaw import VarnodeData

        self._baseOrig = VarnodeData(data.space, data.offset, data.size)
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
            raise LowlevelError("No base register specified for space: " + self.getName())
        return self._baseloc

    def getSpacebaseFull(self, i: int):
        if i != 0 or self._baseOrig is None:
            raise LowlevelError("No base register specified for space: " + self.getName())
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
        self.setFlags(AddrSpace.overlay)

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
        self._destroyed: bool = False
        self._spaces: List[AddrSpace] = []
        self._name2space: dict[str, AddrSpace] = {}
        self._shortcut2Space: dict[str, AddrSpace] = {}
        self._defaultCodeSpace: Optional[AddrSpace] = None
        self._defaultDataSpace: Optional[AddrSpace] = None
        self._constantSpace: Optional[ConstantSpace] = None
        self._uniqueSpace: Optional[UniqueSpace] = None
        self._joinSpace: Optional[JoinSpace] = None
        self._iopSpace: Optional[AddrSpace] = None
        self._fspecSpace: Optional[AddrSpace] = None
        self._stackSpace: Optional[AddrSpace] = None
        self._resolvers: List[object | None] = []
        self._joinallocate: int = 0
        self._join_by_key: dict[tuple[object, ...], JoinRecord] = {}
        self._splitlist: List[JoinRecord] = []

    def __del__(self) -> None:
        if getattr(self, "_destroyed", True):
            return
        self._destroyed = True

        for spc in getattr(self, "_spaces", []):
            if spc is None:
                continue
            refcount = getattr(spc, "_refcount", 0)
            if refcount > 0:
                spc._refcount = refcount - 1

        self._spaces.clear()
        self._name2space.clear()
        self._shortcut2Space.clear()
        self._resolvers.clear()
        self._join_by_key.clear()
        self._splitlist.clear()
        self._constantSpace = None
        self._defaultCodeSpace = None
        self._defaultDataSpace = None
        self._iopSpace = None
        self._fspecSpace = None
        self._joinSpace = None
        self._stackSpace = None
        self._uniqueSpace = None

    # --- Space insertion / lookup ---

    def _insertSpace(self, spc: AddrSpace) -> None:
        """Register an address space with the manager."""
        while len(self._spaces) <= spc.getIndex():
            self._spaces.append(None)  # type: ignore[arg-type]
        self._spaces[spc.getIndex()] = spc
        self._name2space[spc.getName()] = spc

    def decodeSpace(self, decoder: Decoder, trans: Optional[Translate]) -> AddrSpace:
        elem_id = decoder.peekElement()
        if elem_id == ELEM_SPACE_BASE.id:
            spc = SpacebaseSpace(self, trans)
        elif elem_id == ELEM_SPACE_UNIQUE.id:
            spc = UniqueSpace(self, trans)
        elif elem_id == ELEM_SPACE_OTHER.id:
            spc = OtherSpace(self, trans)
        elif elem_id == ELEM_SPACE_OVERLAY.id:
            spc = OverlaySpace(self, trans)
        else:
            spc = AddrSpace(self, trans, IPTR_PROCESSOR)
        spc.decode(decoder)
        return spc

    def decodeSpaces(self, decoder: Decoder, trans: Optional[Translate]) -> None:
        self.insertSpace(ConstantSpace(self, trans))

        elem_id = decoder.openElement(ELEM_SPACES)
        default_name = decoder.readString(ATTRIB_DEFAULTSPACE)
        while decoder.peekElement() != 0:
            self.insertSpace(self.decodeSpace(decoder, trans))
        decoder.closeElement(elem_id)

        spc = self._name2space.get(default_name)
        if spc is None:
            raise LowlevelError("Bad 'defaultspace' attribute: " + default_name)
        self.setDefaultCodeSpace(spc.getIndex())

    def setReverseJustified(self, spc: AddrSpace) -> None:
        spc.setFlags(AddrSpace.reverse_justification)

    def assignShortcut(self, spc: AddrSpace) -> None:
        if spc.getShortcut() != ' ':
            self._shortcut2Space.setdefault(spc.getShortcut(), spc)
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
            existing = self._shortcut2Space.get(shortcut)
            if existing is None:
                self._shortcut2Space[shortcut] = spc
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
        self.setDefaultCodeSpace(op2.getDefaultCodeSpace().getIndex())
        self.setDefaultDataSpace(op2.getDefaultDataSpace().getIndex())

    def addSpacebasePointer(self, basespace: SpacebaseSpace, ptrdata, truncSize: int,
                            stackGrowth: bool) -> None:
        basespace.setBaseRegister(ptrdata, truncSize, stackGrowth)

    def setDeadcodeDelay(self, spc: AddrSpace, delaydelta: int) -> None:
        spc._deadcodedelay = delaydelta

    def truncateSpace(self, tag) -> None:
        spc = self.getSpaceByName(tag.getName())
        if spc is None:
            raise LowlevelError("Unknown space in <truncate_space> command: " + tag.getName())
        spc.truncateSpace(tag.getSize())

    def constructFloatExtensionAddress(self, realaddr, realsize: int, logicalsize: int):
        from ghidra.core.pcoderaw import VarnodeData

        if logicalsize == realsize:
            return realaddr
        pieces = [VarnodeData(realaddr.getSpace(), realaddr.getOffset(), realsize)]
        join = self.findAddJoin(pieces, logicalsize)
        return join.getUnified().getAddr()

    def constructJoinAddress(self, translate, hiaddr, hisz: int, loaddr, losz: int):
        from ghidra.core.pcoderaw import VarnodeData

        hitp = hiaddr.getSpace().getType()
        lotp = loaddr.getSpace().getType()
        usejoinspace = True
        if (
            ((hitp != IPTR_SPACEBASE) and (hitp != IPTR_PROCESSOR))
            or ((lotp != IPTR_SPACEBASE) and (lotp != IPTR_PROCESSOR))
        ):
            raise LowlevelError("Trying to join in appropriate locations")
        if (
            (hitp == IPTR_SPACEBASE)
            or (lotp == IPTR_SPACEBASE)
            or (hiaddr.getSpace() == self.getDefaultCodeSpace())
            or (loaddr.getSpace() == self.getDefaultCodeSpace())
        ):
            usejoinspace = False
        if hiaddr.isContiguous(hisz, loaddr, losz):
            if not usejoinspace:
                if hiaddr.isBigEndian():
                    return hiaddr
                return loaddr
            if hiaddr.isBigEndian():
                if translate.getRegisterName(hiaddr.getSpace(), hiaddr.getOffset(), hisz + losz) != "":
                    return hiaddr
            else:
                if translate.getRegisterName(loaddr.getSpace(), loaddr.getOffset(), hisz + losz) != "":
                    return loaddr
        pieces = [VarnodeData(), VarnodeData()]
        pieces[0].space = hiaddr.getSpace()
        pieces[0].offset = hiaddr.getOffset()
        pieces[0].size = hisz
        pieces[1].space = loaddr.getSpace()
        pieces[1].offset = loaddr.getOffset()
        pieces[1].size = losz
        join = self.findAddJoin(pieces, 0)
        return join.getUnified().getAddr()

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

    def getDefaultSize(self) -> int:
        return self._defaultCodeSpace.getAddrSize()  # type: ignore[union-attr]

    def getSpaceByName(self, name: str) -> Optional[AddrSpace]:
        return self._name2space.get(name)

    def getSpaceByIndex(self, index: int) -> Optional[AddrSpace]:
        """Get a space by its integer index."""
        if 0 <= index < len(self._spaces):
            return self._spaces[index]
        return None

    def getSpaceByShortcut(self, sc: str) -> Optional[AddrSpace]:
        return self._shortcut2Space.get(sc)

    def getIopSpace(self) -> Optional[AddrSpace]:
        return self._iopSpace

    def getFspecSpace(self) -> Optional[AddrSpace]:
        return self._fspecSpace

    def getJoinSpace(self) -> Optional[JoinSpace]:
        return self._joinSpace

    def getStackSpace(self) -> Optional[AddrSpace]:
        return self._stackSpace

    def getUniqueSpace(self) -> Optional[UniqueSpace]:
        return self._uniqueSpace

    def getDefaultCodeSpace(self) -> Optional[AddrSpace]:
        return self._defaultCodeSpace

    def getDefaultDataSpace(self) -> Optional[AddrSpace]:
        return self._defaultDataSpace

    def getConstantSpace(self) -> Optional[ConstantSpace]:
        return self._constantSpace

    def getConstant(self, val: int):
        from ghidra.core.address import Address

        return Address(self._constantSpace, val)

    def createConstFromSpace(self, spc: AddrSpace):
        from ghidra.core.address import Address

        return Address(self._constantSpace, id(spc))

    def resolveConstant(self, spc: AddrSpace, val: int, sz: int, point):
        from ghidra.core.address import Address

        ind = spc.getIndex()
        if ind < len(self._resolvers):
            resolve = self._resolvers[ind]
            if resolve is not None:
                return resolve.resolve(val, sz, point)
        fullEncoding = val
        val = AddrSpace.addressToByte(val, spc.getWordSize())
        val = spc.wrapOffset(val)
        return Address(spc, val), fullEncoding

    def numSpaces(self) -> int:
        return len(self._spaces)

    def getSpace(self, i: int) -> Optional[AddrSpace]:
        if i < 0:
            raise IndexError(i)
        return self._spaces[i]

    def findAddJoin(self, pieces, logicalsize: int):
        from ghidra.core.pcoderaw import VarnodeData

        if len(pieces) == 0:
            raise LowlevelError("Cannot create a join without pieces")
        if len(pieces) == 1 and logicalsize == 0:
            raise LowlevelError("Cannot create a single piece join without a logical size")

        if logicalsize != 0:
            if len(pieces) != 1:
                raise LowlevelError("Cannot specify logical size for multiple piece join")
            totalsize = logicalsize
        else:
            totalsize = 0
            for piece in pieces:
                totalsize += piece.size
            if totalsize == 0:
                raise LowlevelError("Cannot create a zero size join")

        copied_pieces = []
        for piece in pieces:
            copied_piece = VarnodeData(piece.space, piece.offset, piece.size)
            copied_piece.setSpaceFromConst(piece.getSpaceFromConst())
            copied_pieces.append(copied_piece)
        key = (totalsize, tuple(copied_pieces))
        existing = self._join_by_key.get(key)
        if existing is not None:
            return existing

        assert self._joinSpace is not None
        unified = VarnodeData(self._joinSpace, self._joinallocate, totalsize)
        record = JoinRecord(copied_pieces, unified)
        roundsize = (totalsize + 15) & ~0xF
        self._joinallocate += roundsize
        self._join_by_key[key] = record
        self._splitlist.append(record)
        return record

    def findJoin(self, offset: int):
        min_idx = 0
        max_idx = len(self._splitlist) - 1
        while min_idx <= max_idx:
            mid = (min_idx + max_idx) // 2
            rec = self._splitlist[mid]
            val = rec.getUnified().offset
            if val == offset:
                return rec
            if val < offset:
                min_idx = mid + 1
            else:
                max_idx = mid - 1
        raise LowlevelError("Unlinked join address")

    def setDefaultCodeSpace(self, index: int) -> None:
        if self._defaultCodeSpace is not None:
            raise LowlevelError("Default space set multiple times")
        if index >= len(self._spaces) or self._spaces[index] is None:
            raise LowlevelError("Bad index for default space")
        self._defaultCodeSpace = self._spaces[index]
        self._defaultDataSpace = self._defaultCodeSpace

    def setDefaultDataSpace(self, index: int) -> None:
        if self._defaultCodeSpace is None:
            raise LowlevelError("Default data space must be set after the code space")
        if index >= len(self._spaces) or self._spaces[index] is None:
            raise LowlevelError("Bad index for default data space")
        self._defaultDataSpace = self._spaces[index]

    def findJoinInternal(self, offset: int):
        min_idx = 0
        max_idx = len(self._splitlist) - 1
        while min_idx <= max_idx:
            mid = (min_idx + max_idx) // 2
            rec = self._splitlist[mid]
            val = rec.getUnified().offset
            if val + rec.getUnified().size <= offset:
                min_idx = mid + 1
            elif val > offset:
                max_idx = mid - 1
            else:
                return rec
        return None

    def getNextSpaceInOrder(self, spc):
        if spc is None:
            return self._spaces[0]
        if spc is _SPACE_ORDER_MAX:
            return None
        index = spc.getIndex() + 1
        while index < len(self._spaces):
            res = self._spaces[index]
            if res is not None:
                return res
            index += 1
        return _SPACE_ORDER_MAX

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
        from ghidra.core.pcoderaw import VarnodeData

        joinRecord = self.findJoinInternal(addr.getOffset())
        if joinRecord is None:
            raise LowlevelError("Join address not covered by a JoinRecord")
        unified = joinRecord.getUnified()
        if addr.getOffset() == unified.offset and size == unified.size:
            return
        addr1, pos1 = joinRecord.getEquivalentAddress(addr.getOffset())
        addr2, pos2 = joinRecord.getEquivalentAddress(addr.getOffset() + (size - 1))
        if addr2.isInvalid():
            raise LowlevelError("Join address range not covered")
        if pos1 == pos2:
            addr.assign(addr1)
            return

        def copy_piece(piece):
            new_piece = VarnodeData(piece.space, piece.offset, piece.size)
            new_piece.setSpaceFromConst(piece.getSpaceFromConst())
            return new_piece

        newPieces = []
        sizeTrunc1 = int(addr1.getOffset() - joinRecord._pieces[pos1].offset)
        sizeTrunc2 = (
            joinRecord._pieces[pos2].size
            - int(addr2.getOffset() - joinRecord._pieces[pos2].offset)
            - 1
        )
        if pos2 < pos1:
            newPieces.append(copy_piece(joinRecord._pieces[pos2]))
            pos2 += 1
            while pos2 <= pos1:
                newPieces.append(copy_piece(joinRecord._pieces[pos2]))
                pos2 += 1
            newPieces[-1].offset = addr1.getOffset()
            newPieces[-1].size -= sizeTrunc1
            newPieces[0].size -= sizeTrunc2
        else:
            newPieces.append(copy_piece(joinRecord._pieces[pos1]))
            pos1 += 1
            while pos1 <= pos2:
                newPieces.append(copy_piece(joinRecord._pieces[pos1]))
                pos1 += 1
            newPieces[0].offset = addr1.getOffset()
            newPieces[0].size -= sizeTrunc1
            newPieces[-1].size -= sizeTrunc2
        newJoinRecord = self.findAddJoin(newPieces, 0)
        addr.assign(newJoinRecord.getUnified().getAddr())

    def __repr__(self) -> str:
        names = [s.getName() for s in self._spaces if s is not None]
        return f"AddrSpaceManager(spaces={names})"
