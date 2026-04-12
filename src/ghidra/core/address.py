"""
Corresponds to: address.hh / address.cc

Classes for specifying addresses and other low-level constants.
"""

from __future__ import annotations

from enum import IntEnum
from io import StringIO
from typing import TYPE_CHECKING, Optional, Set

from ghidra.core.error import LowlevelError
from ghidra.core.space import (
    AddrSpace, AddrSpaceManager, SpaceType,
    IPTR_CONSTANT, IPTR_JOIN, _SPACE_ORDER_MAX,
)
from ghidra.core.marshal import (
    Encoder, Decoder, AttributeId, ElementId,
    ATTRIB_SPACE, ATTRIB_OFFSET, ATTRIB_SIZE, ATTRIB_FIRST, ATTRIB_LAST,
    ATTRIB_UNIQ, ATTRIB_NAME,
    ELEM_ADDR, ELEM_RANGE, ELEM_RANGELIST, ELEM_REGISTER, ELEM_SEQNUM, ELEM_VARNODE,
)

if TYPE_CHECKING:
    pass


def _space_sort_key(space) -> int:
    if space is None:
        return -1
    get_index = getattr(space, "getIndex", None)
    if callable(get_index):
        return get_index()
    return id(space)


# =========================================================================
# Precalculated masks indexed by size (0..8)
# =========================================================================

uintbmasks: list[int] = [
    0x0,
    0xFF,
    0xFFFF,
    0xFFFFFF,
    0xFFFFFFFF,
    0xFFFFFFFFFF,
    0xFFFFFFFFFFFF,
    0xFFFFFFFFFFFFFF,
    0xFFFFFFFFFFFFFFFF,
]


def calc_mask(size: int) -> int:
    """Return a value appropriate for masking off the first *size* bytes."""
    if size >= 8:
        return uintbmasks[8]
    return uintbmasks[size]


def pcode_right(val: int, sa: int) -> int:
    """Perform a CPUI_INT_RIGHT on the given val."""
    if sa >= 64:
        return 0
    return (val & 0xFFFFFFFFFFFFFFFF) >> sa


def pcode_left(val: int, sa: int) -> int:
    """Perform a CPUI_INT_LEFT on the given val."""
    if sa >= 64:
        return 0
    return (val << sa) & 0xFFFFFFFFFFFFFFFF


def minimalmask(val: int) -> int:
    """Calculate smallest mask that covers the given value."""
    if val > 0xFFFFFFFF:
        return 0xFFFFFFFFFFFFFFFF
    if val > 0xFFFF:
        return 0xFFFFFFFF
    if val > 0xFF:
        return 0xFFFF
    return 0xFF


def sign_extend(val: int, bit_or_sizein: int, sizeout: Optional[int] = None) -> int:
    """Sign extend a value.

    Two-argument form matches ``sign_extend(intb val,int4 bit)``.
    Three-argument form matches ``sign_extend(uintb in,int4 sizein,int4 sizeout)``.
    """
    if sizeout is not None:
        sizein = min(bit_or_sizein, 8)
        sizeout = min(sizeout, 8)
        sval = val & 0xFFFFFFFFFFFFFFFF
        sval = (sval << ((8 - sizein) * 8)) & 0xFFFFFFFFFFFFFFFF
        if sval >= (1 << 63):
            sval -= (1 << 64)
        sval >>= (sizeout - sizein) * 8
        res = sval & 0xFFFFFFFFFFFFFFFF
        res >>= (8 - sizeout) * 8
        return res

    bit = bit_or_sizein
    sa = 64 - (bit + 1)
    val = (val << sa) & 0xFFFFFFFFFFFFFFFF
    if val >= (1 << 63):
        val -= (1 << 64)
    val = val >> sa
    return val


def zero_extend(val: int, bit: int) -> int:
    """Clear all bits above given *bit*."""
    sa = 64 - (bit + 1)
    return ((val << sa) & 0xFFFFFFFFFFFFFFFF) >> sa


def signbit_negative(val: int, size: int) -> bool:
    """Return True if the sign-bit is set for a value of *size* bytes."""
    bit = (size * 8) - 1
    return (val >> bit) & 1 != 0


def uintb_negate(val: int, size: int) -> int:
    """Invert bits of the *sized* value."""
    mask = calc_mask(size)
    return (~val) & mask


def sign_extend_sized(val: int, sizein: int, sizeout: int) -> int:
    """Sign-extend a value between two byte sizes.

    Takes the first *sizein* bytes of *val* and sign-extends to *sizeout* bytes,
    keeping any more significant bytes zero.
    """
    return sign_extend(val, sizein, sizeout)


def byte_swap(val: int, size: int) -> int:
    """Return the given value with bytes swapped."""
    result = 0
    for i in range(size):
        result = (result << 8) | (val & 0xFF)
        val >>= 8
    return result


def leastsigbit_set(val: int) -> int:
    """Return index of least significant bit set in given value. -1 if none."""
    if val == 0:
        return -1
    idx = 0
    while (val & 1) == 0:
        val >>= 1
        idx += 1
    return idx


def mostsigbit_set(val: int) -> int:
    """Return index of most significant bit set in given value. -1 if none."""
    if val == 0:
        return -1
    idx = 0
    while val > 1:
        val >>= 1
        idx += 1
    return idx


def popcount(val: int) -> int:
    """Return the number of one bits in the given value."""
    return bin(val).count('1')


def count_leading_zeros(val: int) -> int:
    """Return the number of leading zero bits in a 64-bit value."""
    if val == 0:
        return 64
    n = 0
    if val <= 0x00000000FFFFFFFF:
        n += 32; val <<= 32
    if val <= 0x0000FFFFFFFFFFFF:
        n += 16; val <<= 16
    if val <= 0x00FFFFFFFFFFFFFF:
        n += 8; val <<= 8
    if val <= 0x0FFFFFFFFFFFFFFF:
        n += 4; val <<= 4
    if val <= 0x3FFFFFFFFFFFFFFF:
        n += 2; val <<= 2
    if val <= 0x7FFFFFFFFFFFFFFF:
        n += 1
    return n


def coveringmask(val: int) -> int:
    """Return a mask that covers the given value."""
    idx = mostsigbit_set(val)
    if idx < 0:
        return 0
    return (1 << (idx + 1)) - 1


def bit_transitions(val: int, sz: int) -> int:
    """Calculate the number of bit transitions in the sized value."""
    mask = calc_mask(sz)
    val &= mask
    count = 0
    prev_bit = val & 1
    for i in range(1, sz * 8):
        cur_bit = (val >> i) & 1
        if cur_bit != prev_bit:
            count += 1
        prev_bit = cur_bit
    return count


# =========================================================================
# Address
# =========================================================================

# Sentinel values for extremal addresses
_ADDR_MIN_SENTINEL = object()
_ADDR_MAX_SENTINEL = object()


class Address:
    """A low-level machine address for labelling bytes and data.

    Simply an address space (AddrSpace) and an offset within that space.
    """

    class MachExtreme(IntEnum):
        m_minimal = 0
        m_maximal = 1

    m_minimal = MachExtreme.m_minimal
    m_maximal = MachExtreme.m_maximal

    __slots__ = ('base', 'offset')

    def __init__(
        self,
        base: Optional[AddrSpace] | Address | MachExtreme = None,
        offset: int = 0,
    ) -> None:
        if isinstance(base, Address):
            self.base = base.base
            self.offset = base.offset
        elif isinstance(base, Address.MachExtreme):
            if base == self.m_minimal:
                self.base = None
                self.offset = 0
            else:
                self.base = _ADDR_MAX_SENTINEL  # type: ignore[assignment]
                self.offset = 0xFFFFFFFFFFFFFFFF
        elif base is _SPACE_ORDER_MAX:
            self.base = _ADDR_MAX_SENTINEL  # type: ignore[assignment]
            self.offset = 0xFFFFFFFFFFFFFFFF
        else:
            self.base = base
            self.offset = offset

    @classmethod
    def from_extreme(cls, ex: MachExtreme) -> Address:
        """Create an extremal address (minimal or maximal)."""
        return cls(ex)

    def isInvalid(self) -> bool:
        return self.base is None

    def getAddrSize(self) -> int:
        assert self.base is not None and self.base is not _ADDR_MAX_SENTINEL
        return self.base.getAddrSize()

    def isBigEndian(self) -> bool:
        assert self.base is not None and self.base is not _ADDR_MAX_SENTINEL
        return self.base.isBigEndian()

    def printRaw(self, s=None):
        text: str
        if self.base is None:
            text = "invalid_addr"
        elif self.base is _ADDR_MAX_SENTINEL:
            text = "max_addr"
        elif s is None:
            try:
                text = self.base.printRaw(self.offset)
            except TypeError:
                buf = StringIO()
                self.base.printRaw(buf, self.offset)
                text = buf.getvalue()
        else:
            try:
                self.base.printRaw(s, self.offset)
            except TypeError:
                s.write(self.base.printRaw(self.offset))
            return None
        if s is not None:
            s.write(text)
            return None
        return text

    def read(self, s: str) -> int:
        assert self.base is not None
        off, sz = self.base.read(s)
        self.offset = off
        return sz

    def getSpace(self) -> Optional[AddrSpace]:
        return self.base

    def getOffset(self) -> int:
        return self.offset

    def getShortcut(self) -> str:
        assert self.base is not None
        return self.base.getShortcut()

    def assign(self, op2: Address) -> Address:
        self.base = op2.base
        self.offset = op2.offset
        return self

    def __eq__(self, other: object) -> bool:
        if not isinstance(other, Address):
            return NotImplemented
        return self.base is other.base and self.offset == other.offset

    def __ne__(self, other: object) -> bool:
        if not isinstance(other, Address):
            return NotImplemented
        return not self.__eq__(other)

    def __lt__(self, other: Address) -> bool:
        if self.base is not other.base:
            if self.base is None:
                return True
            if self.base is _ADDR_MAX_SENTINEL:
                return False
            if other.base is None:
                return False
            if other.base is _ADDR_MAX_SENTINEL:
                return True
            return self.base.getIndex() < other.base.getIndex()
        return self.offset < other.offset

    def __le__(self, other: Address) -> bool:
        if self.base is not other.base:
            if self.base is None:
                return True
            if self.base is _ADDR_MAX_SENTINEL:
                return False
            if other.base is None:
                return False
            if other.base is _ADDR_MAX_SENTINEL:
                return True
            return self.base.getIndex() < other.base.getIndex()
        return self.offset <= other.offset

    def __add__(self, off: int) -> Address:
        return Address(self.base, self.base.wrapOffset(self.offset + off))

    def __sub__(self, off: int) -> Address:
        return Address(self.base, self.base.wrapOffset(self.offset - off))

    def __hash__(self) -> int:
        base_id = id(self.base) if self.base is not None else 0
        return hash((base_id, self.offset))

    def __repr__(self) -> str:
        return f"Address({self.printRaw()})"

    def __str__(self) -> str:
        return self.printRaw()

    def containedBy(self, sz: int, op2: Address, sz2: int) -> bool:
        """Return True if the range (op2, sz2) contains (self, sz)."""
        if self.base is not op2.base:
            return False
        if op2.offset > self.offset:
            return False
        off1 = self.offset + (sz - 1)
        off2 = op2.offset + (sz2 - 1)
        return off2 >= off1

    def justifiedContain(self, sz: int, op2: Address, sz2: int, forceleft: bool = False) -> int:
        """Determine if op2 is the least significant part of self.
        Returns endian-aware offset, or -1.
        """
        if self.base is not op2.base:
            return -1
        if op2.offset < self.offset:
            return -1
        off1 = self.offset + (sz - 1)
        off2 = op2.offset + (sz2 - 1)
        if off2 > off1:
            return -1
        if self.base.isBigEndian() and not forceleft:
            return off1 - off2
        return op2.offset - self.offset

    def overlap(self, skip: int, op: Address, size: int) -> int:
        """Determine how self+skip falls in range [op, op+size).
        Returns offset into range, or -1.
        """
        if self.base is not op.base:
            return -1
        if self.base.getType() == IPTR_CONSTANT:
            return -1
        dist = self.base.wrapOffset(self.offset + skip - op.offset)
        if dist >= size:
            return -1
        return dist

    def overlapJoin(self, skip: int, op: Address, size: int) -> int:
        return op.getSpace().overlapJoin(op.getOffset(), size, self.base, self.offset, skip)

    def isContiguous(self, sz: int, loaddr: Address, losz: int) -> bool:
        """Does (self, sz) form a contiguous range with (loaddr, losz)?"""
        if self.base is not loaddr.base:
            return False
        if self.base.isBigEndian():
            nextoff = self.base.wrapOffset(self.offset + sz)
            return nextoff == loaddr.offset
        else:
            nextoff = self.base.wrapOffset(loaddr.offset + losz)
            return nextoff == self.offset

    def isConstant(self) -> bool:
        return self.base is not None and self.base.getType() == IPTR_CONSTANT

    def isJoin(self) -> bool:
        return self.base is not None and self.base.getType() == IPTR_JOIN

    def renormalize(self, size: int) -> None:
        if self.base is not None and self.base.getType() == IPTR_JOIN:
            mgr = self.base.getManager()
            if mgr is not None:
                mgr.renormalizeJoinAddress(self, size)

    def encode(self, encoder: Encoder, size: int = -1) -> None:
        encoder.openElement(ELEM_ADDR)
        if self.base is not None:
            if size >= 0:
                self.base.encodeAttributes(encoder, self.offset, size)
            else:
                self.base.encodeAttributes(encoder, self.offset)
        encoder.closeElement(ELEM_ADDR)

    @staticmethod
    def decode(decoder: Decoder, with_size: bool = False):
        """Decode an address (and optionally size) from a stream.

        If *with_size* is True, returns (Address, size).
        Otherwise returns just Address.
        """
        from ghidra.core.error import DecoderError
        from ghidra.core.pcoderaw import VarnodeData

        try:
            elem_id = decoder.openElement()
        except (DecoderError, IndexError):
            elem_id = 0

        if elem_id == 0:
            spc = None
            offset = 0
            size = 0
            found_offset = False
            decoder.rewindAttributes()
            while True:
                attrib_id = decoder.getNextAttributeId()
                if attrib_id == 0:
                    break
                if attrib_id == ATTRIB_SPACE.id:
                    spc = decoder.readSpace()
                elif attrib_id == ATTRIB_OFFSET.id:
                    offset = decoder.readUnsignedInteger()
                    found_offset = True
                elif attrib_id == ATTRIB_SIZE.id:
                    size = decoder.readSignedInteger()
                elif attrib_id == ATTRIB_NAME.id:
                    manage = decoder.getAddrSpaceManager()
                    trans = manage.getDefaultCodeSpace().getTrans()
                    point = trans.getRegister(decoder.readString())
                    spc = point.space
                    offset = point.offset
                    size = point.size
                    found_offset = True
            decoder.rewindAttributes()
            if spc is not None and not found_offset:
                raise LowlevelError("Address is missing offset")
            addr = Address(spc, offset)
        else:
            var = VarnodeData()
            var.decodeFromAttributes(decoder)
            decoder.closeElement(elem_id)
            addr = Address(var.space, var.offset)
            size = var.size
        if with_size:
            return addr, size
        return addr


# =========================================================================
# SeqNum
# =========================================================================

class SeqNum:
    """A class for uniquely labelling and comparing PcodeOps.

    Extends the address with a time (unique) field and an order field.
    """

    __slots__ = ('pc', 'uniq', 'order')

    def __init__(self, pc: Optional[Address | SeqNum | Address.MachExtreme] = None, uniq: int = 0) -> None:
        if isinstance(pc, SeqNum):
            self.pc = Address(pc.pc) if isinstance(pc.pc, Address) else pc.pc
            self.uniq = pc.uniq
        elif pc in (Address.m_minimal, Address.m_maximal):
            self.pc = Address(pc)
            self.uniq = 0 if pc == Address.m_minimal else 0xFFFFFFFFFFFFFFFF
        elif pc is None:
            self.pc = Address()
            self.uniq = uniq
        else:
            self.pc = Address(pc) if isinstance(pc, Address) else pc
            self.uniq = uniq
        self.order: int = 0

    @classmethod
    def from_extreme(cls, ex: Address.MachExtreme) -> SeqNum:
        return cls(ex)

    def getAddr(self) -> Address:
        return self.pc

    def getTime(self) -> int:
        return self.uniq

    def getOrder(self) -> int:
        return self.order

    def setOrder(self, ord_: int) -> None:
        self.order = ord_

    def __eq__(self, other: object) -> bool:
        if not isinstance(other, SeqNum):
            return NotImplemented
        return self.uniq == other.uniq

    def __ne__(self, other: object) -> bool:
        if not isinstance(other, SeqNum):
            return NotImplemented
        return self.uniq != other.uniq

    def __lt__(self, other: SeqNum) -> bool:
        if self.pc == other.pc:
            return self.uniq < other.uniq
        return self.pc < other.pc

    def __hash__(self) -> int:
        return hash(self.uniq)

    def __repr__(self) -> str:
        return f"{self.pc}:{self.uniq}"

    def encode(self, encoder: Encoder) -> None:
        encoder.openElement(ELEM_SEQNUM)
        self.pc.getSpace().encodeAttributes(encoder, self.pc.getOffset())
        encoder.writeUnsignedInteger(ATTRIB_UNIQ, self.uniq)
        encoder.closeElement(ELEM_SEQNUM)

    @staticmethod
    def decode(decoder: Decoder) -> SeqNum:
        uniq = 0xFFFFFFFFFFFFFFFF
        elem_id = decoder.openElement(ELEM_SEQNUM)
        pc = Address.decode(decoder)
        while True:
            attrib_id = decoder.getNextAttributeId()
            if attrib_id == 0:
                break
            if attrib_id == ATTRIB_UNIQ.id:
                uniq = decoder.readUnsignedInteger()
                break
        decoder.closeElement(elem_id)
        return SeqNum(pc, uniq)


# =========================================================================
# RangeProperties
# =========================================================================

class RangeProperties:
    """A partially parsed description of a Range."""

    def __init__(self) -> None:
        self.spaceName: str = ""
        self.first: int = 0
        self.last: int = 0
        self.isRegister: bool = False
        self.seenLast: bool = False

    def decode(self, decoder: Decoder) -> None:
        """Decode this from a stream."""
        from ghidra.core.error import DecoderError

        elem_id = decoder.openElement()
        if elem_id != ELEM_RANGE.id and elem_id != ELEM_REGISTER.id:
            raise DecoderError("Expecting <range> or <register> element")
        while True:
            attrib_id = decoder.getNextAttributeId()
            if attrib_id == 0:
                break
            if attrib_id == ATTRIB_SPACE.id:
                self.spaceName = decoder.readString()
            elif attrib_id == ATTRIB_FIRST.id:
                self.first = decoder.readUnsignedInteger()
            elif attrib_id == ATTRIB_LAST.id:
                self.last = decoder.readUnsignedInteger()
                self.seenLast = True
            elif attrib_id == ATTRIB_NAME.id:
                self.spaceName = decoder.readString()
                self.isRegister = True
        decoder.closeElement(elem_id)


# =========================================================================
# Range
# =========================================================================

class Range:
    """A contiguous range of bytes in some address space."""

    __slots__ = ('spc', 'first', 'last')

    def __init__(
        self,
        spc: Optional[AddrSpace | RangeProperties] = None,
        first: int | AddrSpaceManager = 0,
        last: int = 0,
    ) -> None:
        if isinstance(spc, RangeProperties):
            props = spc
            manage = first
            if not hasattr(manage, "getSpaceByName") or not hasattr(manage, "getDefaultCodeSpace"):
                raise TypeError("Range properties construction requires an AddrSpaceManager")
            built = self.from_properties(props, manage)
            self.spc = built.spc
            self.first = built.first
            self.last = built.last
            return
        self.spc = spc
        self.first = first if isinstance(first, int) else 0
        self.last = last

    @classmethod
    def from_properties(cls, props: RangeProperties, manage: AddrSpaceManager) -> Range:
        """Construct range out of basic properties."""
        if props.isRegister:
            trans = manage.getDefaultCodeSpace().getTrans()
            point = trans.getRegister(props.spaceName)
            return cls(point.space, point.offset, (point.offset - 1) + point.size)
        spc = manage.getSpaceByName(props.spaceName)
        if spc is None:
            raise LowlevelError("Undefined space: " + props.spaceName)
        first = props.first
        last = props.last
        if not props.seenLast:
            last = spc.getHighest()
        if first > spc.getHighest() or last > spc.getHighest() or last < first:
            raise LowlevelError("Illegal range tag")
        return cls(spc, first, last)

    def getSpace(self) -> Optional[AddrSpace]:
        return self.spc

    def getFirst(self) -> int:
        return self.first

    def getLast(self) -> int:
        return self.last

    def getFirstAddr(self) -> Address:
        return Address(self.spc, self.first)

    def getLastAddr(self) -> Address:
        return Address(self.spc, self.last)

    def getLastAddrOpen(self, manage: AddrSpaceManager) -> Address:
        """Get address of first byte after this Range."""
        curspc = self.spc
        curlast = self.last
        if curlast == curspc.getHighest():
            curspc = manage.getNextSpaceInOrder(curspc)
            curlast = 0
        else:
            curlast += 1
        if curspc is None:
            return Address.from_extreme(Address.m_maximal)
        return Address(curspc, curlast)

    def contains(self, addr: Address) -> bool:
        if self.spc is not addr.getSpace():
            return False
        if self.first > addr.getOffset():
            return False
        if self.last < addr.getOffset():
            return False
        return True

    def __lt__(self, other: Range) -> bool:
        self_idx = _space_sort_key(self.spc)
        other_idx = _space_sort_key(other.spc)
        if self_idx != other_idx:
            return self_idx < other_idx
        return self.first < other.first

    def __eq__(self, other: object) -> bool:
        if not isinstance(other, Range):
            return NotImplemented
        return (self.spc is other.spc and self.first == other.first
                and self.last == other.last)

    def __hash__(self) -> int:
        return hash((id(self.spc), self.first, self.last))

    def printBounds(self, s=None):
        """Print this Range to a stream."""
        sname = self.spc.getName() if self.spc else "?"
        text = f"{sname}: {self.first:x}-{self.last:x}"
        if s is not None:
            s.write(text)
            return None
        return text

    def encode(self, encoder: Encoder) -> None:
        encoder.openElement(ELEM_RANGE)
        encoder.writeString(ATTRIB_SPACE, self.spc.getName())
        encoder.writeUnsignedInteger(ATTRIB_FIRST, self.first)
        encoder.writeUnsignedInteger(ATTRIB_LAST, self.last)
        encoder.closeElement(ELEM_RANGE)

    def decodeFromAttributes(self, decoder: Decoder) -> None:
        """Reconstruct from attributes that may not be part of a <range> element."""
        self.spc = None
        seen_last = False
        self.first = 0
        self.last = 0
        while True:
            attrib_id = decoder.getNextAttributeId()
            if attrib_id == 0:
                break
            if attrib_id == ATTRIB_SPACE.id:
                self.spc = decoder.readSpace()
            elif attrib_id == ATTRIB_FIRST.id:
                self.first = decoder.readUnsignedInteger()
            elif attrib_id == ATTRIB_LAST.id:
                self.last = decoder.readUnsignedInteger()
                seen_last = True
            elif attrib_id == ATTRIB_NAME.id:
                manage = decoder.getAddrSpaceManager()
                trans = manage.getDefaultCodeSpace().getTrans()
                point = trans.getRegister(decoder.readString())
                self.spc = point.space
                self.first = point.offset
                self.last = (point.offset - 1) + point.size
                return
        if self.spc is None:
            raise LowlevelError("No address space indicated in range tag")
        if not seen_last:
            self.last = self.spc.getHighest()
        if self.first > self.spc.getHighest() or self.last > self.spc.getHighest() or self.last < self.first:
            raise LowlevelError("Illegal range tag")

    def decode(self, decoder: Decoder) -> None:
        """Reconstruct this object from a <range> or <register> element."""
        from ghidra.core.error import DecoderError

        elem_id = decoder.openElement()
        if elem_id != ELEM_RANGE.id and elem_id != ELEM_REGISTER.id:
            raise DecoderError("Expecting <range> or <register> element")
        self.decodeFromAttributes(decoder)
        decoder.closeElement(elem_id)


# =========================================================================
# RangeList
# =========================================================================

class RangeList:
    """A disjoint set of Ranges, possibly across multiple address spaces."""

    def __init__(self, other: Optional[RangeList] = None) -> None:
        if other is not None:
            self._ranges: list[Range] = [
                Range(r.spc, r.first, r.last) if isinstance(r, Range) else r for r in other._ranges
            ]
        else:
            self._ranges: list[Range] = []

    def _upper_bound(self, probe: Range) -> int:
        lo = 0
        hi = len(self._ranges)
        while lo < hi:
            mid = (lo + hi) // 2
            if probe < self._ranges[mid]:
                hi = mid
            else:
                lo = mid + 1
        return lo

    def begin(self):
        return iter(self._ranges)

    def end(self):
        return iter(())

    def clear(self) -> None:
        self._ranges.clear()

    def empty(self) -> bool:
        return len(self._ranges) == 0

    def numRanges(self) -> int:
        return len(self._ranges)

    def __iter__(self):
        return iter(self._ranges)

    def getFirstRange(self) -> Optional[Range]:
        return self._ranges[0] if self._ranges else None

    def getLastRange(self) -> Optional[Range]:
        return self._ranges[-1] if self._ranges else None

    def getRange(self, spaceid: AddrSpace, offset: int) -> Optional[Range]:
        if not self._ranges:
            return None
        iter_idx = self._upper_bound(Range(spaceid, offset, offset))
        if iter_idx == 0:
            return None
        r = self._ranges[iter_idx - 1]
        if r.spc is not spaceid:
            return None
        if r.last >= offset:
            return r
        return None

    def insertRange(self, spc: AddrSpace, first: int, last: int) -> None:
        """Insert a range of addresses."""
        iter1 = self._upper_bound(Range(spc, first, first))
        if iter1 != 0:
            iter1 -= 1
            candidate = self._ranges[iter1]
            if candidate.spc is not spc or candidate.last < first:
                iter1 += 1

        iter2 = self._upper_bound(Range(spc, last, last))

        for r in self._ranges[iter1:iter2]:
            if r.first < first:
                first = r.first
            if r.last > last:
                last = r.last
        self._ranges[iter1:iter2] = [Range(spc, first, last)]

    def removeRange(self, spc: AddrSpace, first: int, last: int) -> None:
        """Remove a range of addresses."""
        if not self._ranges:
            return

        iter1 = self._upper_bound(Range(spc, first, first))
        if iter1 != 0:
            iter1 -= 1
            candidate = self._ranges[iter1]
            if candidate.spc is not spc or candidate.last < first:
                iter1 += 1

        iter2 = self._upper_bound(Range(spc, last, last))

        replacement: list[Range] = []
        for r in self._ranges[iter1:iter2]:
            a = r.first
            b = r.last
            if a < first:
                replacement.append(Range(spc, a, first - 1))
            if b > last:
                replacement.append(Range(spc, last + 1, b))
        self._ranges[iter1:iter2] = replacement

    def merge(self, op2: RangeList) -> None:
        for r in op2._ranges:
            self.insertRange(r.spc, r.first, r.last)

    def inRange(self, addr: Address, size: int) -> bool:
        """Check if [addr, addr+size) is contained in some range."""
        if addr.isInvalid():
            return True
        if not self._ranges:
            return False

        iter_idx = self._upper_bound(Range(addr.getSpace(), addr.getOffset(), addr.getOffset()))
        if iter_idx == 0:
            return False
        r = self._ranges[iter_idx - 1]
        if r.spc is not addr.getSpace():
            return False
        return r.last >= addr.getOffset() + size - 1

    def longestFit(self, addr: Address, maxsize: int) -> int:
        """Find size of biggest contiguous region containing given address."""
        if addr.isInvalid():
            return 0
        if not self._ranges:
            return 0
        offset = addr.getOffset()
        spc = addr.getSpace()
        iter_idx = self._upper_bound(Range(spc, offset, offset))
        if iter_idx == 0:
            return 0
        iter_idx -= 1
        sizeres = 0
        if self._ranges[iter_idx].last < offset:
            return sizeres
        while iter_idx != len(self._ranges):
            r = self._ranges[iter_idx]
            if r.spc is not spc:
                break
            if r.first > offset:
                break
            sizeres += r.last + 1 - offset
            offset = r.last + 1
            if sizeres >= maxsize:
                break
            iter_idx += 1
        return sizeres

    def getLastSignedRange(self, spaceid: AddrSpace) -> Optional[Range]:
        """Get the last Range viewing offsets as signed."""
        midway = spaceid.getHighest() // 2
        iter_idx = self._upper_bound(Range(spaceid, midway, midway))
        if iter_idx != 0:
            r = self._ranges[iter_idx - 1]
            if r.getSpace() is spaceid:
                return r

        iter_idx = self._upper_bound(Range(spaceid, spaceid.getHighest(), spaceid.getHighest()))
        if iter_idx != 0:
            r = self._ranges[iter_idx - 1]
            if r.getSpace() is spaceid:
                return r
        return None

    def printBounds(self, s=None):
        if s is None:
            buf = StringIO()
            self.printBounds(buf)
            return buf.getvalue()
        if not self._ranges:
            s.write("all\n")
            return None
        for r in self._ranges:
            r.printBounds(s)
            s.write("\n")
        return None

    def encode(self, encoder: Encoder) -> None:
        encoder.openElement(ELEM_RANGELIST)
        for r in self._ranges:
            r.encode(encoder)
        encoder.closeElement(ELEM_RANGELIST)

    def decode(self, decoder: Decoder) -> None:
        """Decode this RangeList from a <rangelist> element."""
        elem_id = decoder.openElement(ELEM_RANGELIST)
        while decoder.peekElement() != 0:
            r = Range()
            r.decode(decoder)
            insert_idx = self._upper_bound(Range(r.spc, r.first, r.first))
            if insert_idx != 0:
                prev = self._ranges[insert_idx - 1]
                if prev.spc is r.spc and prev.first == r.first:
                    continue
            self._ranges.insert(insert_idx, r)
        decoder.closeElement(elem_id)
