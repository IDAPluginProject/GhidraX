"""
Corresponds to: globalcontext.hh / globalcontext.cc

Map from addresses to context settings. Context is used to affect
disassembly depending on processor state (e.g. ARM/Thumb mode).
"""

from __future__ import annotations

from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from typing import Optional, List, Dict, Tuple, cast

from ghidra.core.address import Address, Range, RangeList
from ghidra.core.error import BadDataError, LowlevelError
from ghidra.core.pcoderaw import VarnodeData
from ghidra.core.space import AddrSpace
from ghidra.core.marshal import Decoder, Encoder

_UINTM_BYTES = 4
_UINTM_BITS = _UINTM_BYTES * 8
_UINTM_MASK = (1 << _UINTM_BITS) - 1


def _calc_mask(size: int) -> int:
    if size >= 8:
        return 0xFFFFFFFFFFFFFFFF
    return (1 << (size * 8)) - 1


class Token:
    """A multiple-byte sized chunk of pattern in a bitstream."""

    def __init__(self, nm: str, sz: int, be: bool, ind: int) -> None:
        self.name = nm
        self.size = sz
        self.bigendian = be
        self.index = ind

    def getSize(self) -> int:
        return self.size

    def isBigEndian(self) -> bool:
        return self.bigendian

    def getIndex(self) -> int:
        return self.index

    def getName(self) -> str:
        return self.name


@dataclass
class FixedHandle:
    """A handle that is fully resolved."""

    space: Optional[AddrSpace] = None
    size: int = 0
    offset_space: Optional[AddrSpace] = None
    offset_offset: int = 0
    offset_size: int = 0
    temp_space: Optional[AddrSpace] = None
    temp_offset: int = 0


@dataclass
class ConstructState:
    ct: object | None = None
    hand: FixedHandle = field(default_factory=FixedHandle)
    resolve: List[ConstructState | None] = field(default_factory=list)
    parent: Optional[ConstructState] = None
    length: int = 0
    offset: int = 0


@dataclass
class ContextSet:
    """Instructions for setting a global context value."""

    sym: object | None = None
    point: Optional[ConstructState] = None
    num: int = 0
    mask: int = 0
    value: int = 0
    flow: bool = False


class TrackedContext:
    """A tracked register value at a specific code point.

    C++ ref: TrackedContext in globalcontext.hh
    """

    def __init__(self) -> None:
        self.loc: VarnodeData = VarnodeData()
        self.val: int = 0

    def encode(self, encoder: Encoder) -> None:
        """Encode as a <set> element.

        C++ ref: TrackedContext::encode
        """
        from ghidra.core.marshal import ELEM_SET, ATTRIB_VAL
        encoder.openElement(ELEM_SET)
        self.loc.space.encodeAttributes(encoder, self.loc.offset, self.loc.size)
        encoder.writeUnsignedInteger(ATTRIB_VAL, self.val)
        encoder.closeElement(ELEM_SET)

    def decode(self, decoder: Decoder) -> None:
        """Decode from a <set> element.

        C++ ref: TrackedContext::decode
        """
        from ghidra.core.marshal import ELEM_SET, ATTRIB_VAL
        elemId = decoder.openElement(ELEM_SET)
        self.loc.decodeFromAttributes(decoder)
        self.val = decoder.readUnsignedInteger(ATTRIB_VAL)
        decoder.closeElement(elemId)


class ContextBitRange:
    """Description of a context variable as a range of bits within the context blob.

    A context variable is a contiguous range of bits that can be set or read
    from a context blob (an array of bytes).
    """

    def __init__(self, sbit: Optional[int] = None, ebit: Optional[int] = None) -> None:
        self.word: int = 0
        self.startbit: int = 0
        self.endbit: int = 0
        self.shift: int = 0
        self.mask: int = 0
        if sbit is None and ebit is None:
            return
        if sbit is None or ebit is None:
            raise TypeError("ContextBitRange requires both sbit and ebit")
        self.word = sbit // _UINTM_BITS
        self.startbit = sbit - self.word * _UINTM_BITS
        self.endbit = ebit - self.word * _UINTM_BITS
        self.shift = _UINTM_BITS - self.endbit - 1
        self.mask = (_UINTM_MASK >> (self.startbit + self.shift)) & _UINTM_MASK

    def getShift(self) -> int:
        return self.shift

    def getMask(self) -> int:
        return self.mask

    def getWord(self) -> int:
        return self.word

    def setValue(self, vec: List[int], val: int) -> None:
        """Set the value of this variable in a context blob."""
        while len(vec) <= self.word:
            vec.append(0)
        newval = vec[self.word] & _UINTM_MASK
        range_mask = (self.mask << self.shift) & _UINTM_MASK
        newval &= (~range_mask) & _UINTM_MASK
        newval |= ((val & self.mask) << self.shift) & _UINTM_MASK
        vec[self.word] = newval

    def getValue(self, vec: List[int]) -> int:
        """Get the value of this variable from a context blob."""
        if self.word >= len(vec):
            return 0
        return ((vec[self.word] & _UINTM_MASK) >> self.shift) & self.mask


class ContextDatabase(ABC):
    """Abstract interface for the context database.

    A ContextDatabase stores context variable settings associated with
    address ranges. Different implementations may store the data in
    different ways (e.g. in memory, or via Ghidra's database).
    """

    @abstractmethod
    def getVariable(self, name: str) -> ContextBitRange:
        """Get the bit range for a named context variable."""
        ...

    def setVariable(self, name: str, addr: Address, val: int) -> None:
        """Set a context variable at a specific address."""
        bitrange = self.getVariable(name)
        num = bitrange.getWord()
        mask = bitrange.getMask() << bitrange.getShift()
        contvec: List[List[int]] = []
        self.getRegionToChangePoint(contvec, addr, num, mask)
        for ctx in contvec:
            bitrange.setValue(ctx, val)

    def setVariableRegion(self, name: str, addr1: Address, addr2: Address, val: int) -> None:
        """Set a context variable over a range of addresses."""
        bitrange = self.getVariable(name)
        vec: List[List[int]] = []
        self.getRegionForSet(
            vec,
            addr1,
            addr2,
            bitrange.getWord(),
            bitrange.getMask() << bitrange.getShift(),
        )
        for ctx in vec:
            bitrange.setValue(ctx, val)

    @abstractmethod
    def getContext(
        self,
        addr: Address,
        first: Optional[List[int]] = None,
        last: Optional[List[int]] = None,
    ) -> List[int]:
        """Retrieve the context blob for a given address."""
        ...

    @abstractmethod
    def registerVariable(self, name: str, sbit: int, ebit: int) -> None:
        """Register a new context variable occupying the given bit range."""
        ...

    @abstractmethod
    def getContextSize(self) -> int:
        """Return the number of words in the context blob."""
        ...

    @abstractmethod
    def getDefaultValue(self) -> List[int]:
        """Return the default context blob."""
        ...

    @abstractmethod
    def getTrackedDefault(self) -> List[TrackedContext]:
        """Get the default tracked register set."""
        ...

    @abstractmethod
    def getTrackedSet(self, addr: Address) -> List[TrackedContext]:
        """Get tracked register set at the given address."""
        ...

    @abstractmethod
    def createSet(self, addr1: Address, addr2: Address) -> List[TrackedContext]:
        """Create tracked register storage for an address range."""
        ...

    @abstractmethod
    def encode(self, encoder: Encoder) -> None:
        """Encode database state."""
        ...

    @abstractmethod
    def decode(self, decoder: Decoder) -> None:
        """Decode database state."""
        ...

    @abstractmethod
    def decodeFromSpec(self, decoder: Decoder) -> None:
        """Decode database state from specification data."""
        ...

    @staticmethod
    def encodeTracked(encoder: Encoder, addr: Address, vec: List[TrackedContext]) -> None:
        """Encode tracked register values for a specific address.

        C++ ref: ContextDatabase::encodeTracked
        """
        from ghidra.core.marshal import ELEM_TRACKED_POINTSET
        if not vec:
            return
        encoder.openElement(ELEM_TRACKED_POINTSET)
        addr.getSpace().encodeAttributes(encoder, addr.getOffset())
        for tc in vec:
            tc.encode(encoder)
        encoder.closeElement(ELEM_TRACKED_POINTSET)

    @staticmethod
    def decodeTracked(decoder: Decoder, vec: List[TrackedContext]) -> None:
        """Decode tracked register values from a stream.

        C++ ref: ContextDatabase::decodeTracked
        """
        vec.clear()
        while decoder.peekElement() != 0:
            tc = TrackedContext()
            tc.decode(decoder)
            vec.append(tc)

    def setVariableDefault(self, name: str, val: int) -> None:
        """Provide a default value for a context variable."""
        bitrange = self.getVariable(name)
        bitrange.setValue(self.getDefaultValue(), val)

    def getDefaultValueByName(self, name: str) -> int:
        """Retrieve the default value for a context variable by name."""
        bitrange = self.getVariable(name)
        return bitrange.getValue(self.getDefaultValue())

    def getVariableValue(self, name: str, addr: Address) -> int:
        """Retrieve the value for a context variable at a specific address."""
        bitrange = self.getVariable(name)
        context = self.getContext(addr)
        return bitrange.getValue(context)

    def setContextChangePoint(self, addr: Address, num: int, mask: int, value: int) -> None:
        """Set context value starting at addr up to next explicit change.

        C++ ref: ContextDatabase::setContextChangePoint
        """
        contvec: List[List[int]] = []
        self.getRegionToChangePoint(contvec, addr, num, mask)
        for ctx in contvec:
            val = ctx[num]
            val &= ~mask
            val |= value
            ctx[num] = val

    def setContextRegion(self, addr1: Address, addr2: Address, num: int, mask: int, value: int) -> None:
        """Set context value over an explicit address range.

        C++ ref: ContextDatabase::setContextRegion
        """
        vec: List[List[int]] = []
        self.getRegionForSet(vec, addr1, addr2, num, mask)
        for ctx in vec:
            ctx[num] = (ctx[num] & ~mask) | value

    def getTrackedValue(self, mem: VarnodeData, point: Address) -> int:
        """Get tracked register value at a specific address.

        C++ ref: ContextDatabase::getTrackedValue
        """
        tset = self.getTrackedSet(point)
        endoff = mem.offset + mem.size - 1
        for tcont in tset:
            if tcont.loc.space is not mem.space:
                continue
            if tcont.loc.offset > mem.offset:
                continue
            tendoff = tcont.loc.offset + tcont.loc.size - 1
            if tendoff < endoff:
                continue
            res = tcont.val
            if tcont.loc.space.isBigEndian():
                if endoff != tendoff:
                    res >>= (8 * (tendoff - mem.offset))
            else:
                if mem.offset != tcont.loc.offset:
                    res >>= (8 * (mem.offset - tcont.loc.offset))
            res &= _calc_mask(mem.size)
            return res
        return 0

    @abstractmethod
    def getRegionForSet(self, res: list, addr1: Address, addr2: Address, num: int, mask: int) -> None:
        """Get context blobs in region [addr1, addr2). Override in subclass."""
        ...

    @abstractmethod
    def getRegionToChangePoint(self, res: list, addr: Address, num: int, mask: int) -> None:
        """Get context blobs from addr to next change point. Override in subclass."""
        ...

    def __del__(self) -> None:
        return None


class ContextInternal(ContextDatabase):
    """A simple in-memory implementation of ContextDatabase.

    Stores context as a default blob plus address-specific overrides.
    """

    class FreeArray:
        """A context blob plus the mask of definitively set variables."""

        def __init__(self) -> None:
            self.array: List[int] = []
            self.mask: List[int] = []
            self.size: int = 0

        def __del__(self) -> None:
            return None

        def reset(self, sz: int) -> None:
            """Resize while preserving existing values and masks."""
            old_array = self.array
            old_mask = self.mask
            new_array: List[int] = []
            new_mask: List[int] = []
            if sz != 0:
                new_array = [0] * sz
                new_mask = [0] * sz
                min_size = min(sz, len(old_array), len(old_mask))
                for i in range(min_size):
                    new_array[i] = old_array[i] & _UINTM_MASK
                    new_mask[i] = old_mask[i] & _UINTM_MASK
            self.array = new_array
            self.mask = new_mask
            self.size = sz

        def assign(self, op2: ContextInternal.FreeArray) -> ContextInternal.FreeArray:
            """Clone values from another blob, but clear definitive-set masks."""
            new_size = max(op2.size, len(op2.array))
            self.size = new_size
            self.array = list(op2.array[:new_size])
            if len(self.array) < new_size:
                self.array.extend([0] * (new_size - len(self.array)))
            self.mask = [0] * new_size
            return self

    def __init__(self) -> None:
        self._variables: Dict[str, ContextBitRange] = {}
        self._contextSize: int = 0  # Number of 32-bit words in context
        self._defaultFreeArray = self.FreeArray()
        self._defaultContext: List[int] = self._defaultFreeArray.array
        # Mapping from (space_index, offset) -> context blob override
        self._contextMap: Dict[Tuple[int, int], ContextInternal.FreeArray | List[int]] = {}
        self._trackDefault: List[TrackedContext] = []
        # Mapping from (space_index, offset) -> tracked register set
        self._trackMap: Dict[Tuple[int, int], List[TrackedContext]] = {}
        self._spaceByIndex: Dict[int, AddrSpace] = {}

    def __del__(self) -> None:
        return None

    def _syncDefaultFreeArray(self) -> None:
        if self._defaultFreeArray.array is not self._defaultContext:
            self._defaultFreeArray.array = self._defaultContext
        self._defaultFreeArray.size = len(self._defaultContext)
        mask_len = len(self._defaultFreeArray.mask)
        if mask_len < self._defaultFreeArray.size:
            self._defaultFreeArray.mask.extend([0] * (self._defaultFreeArray.size - mask_len))
        elif mask_len > self._defaultFreeArray.size:
            del self._defaultFreeArray.mask[self._defaultFreeArray.size:]

    def _rememberSpace(self, space: Optional[AddrSpace]) -> None:
        if space is not None:
            self._spaceByIndex[space.getIndex()] = space

    def _coerceFreeArray(self, key: Tuple[int, int]) -> ContextInternal.FreeArray:
        entry = self._contextMap[key]
        if isinstance(entry, self.FreeArray):
            if entry.size < self._contextSize:
                entry.reset(self._contextSize)
            return entry
        free = self.FreeArray()
        free.reset(max(self._contextSize, len(entry)))
        for i, val in enumerate(entry):
            free.array[i] = val & _UINTM_MASK
        self._contextMap[key] = free
        return free

    def _iterContextEntries(
        self,
        spc_idx: Optional[int] = None,
    ) -> List[Tuple[Tuple[int, int], ContextInternal.FreeArray]]:
        entries: List[Tuple[Tuple[int, int], ContextInternal.FreeArray]] = []
        for key in sorted(self._contextMap):
            if spc_idx is not None and key[0] != spc_idx:
                continue
            entries.append((key, self._coerceFreeArray(key)))
        return entries

    def _cloneContextValues(self, vec: List[int]) -> ContextInternal.FreeArray:
        free = self.FreeArray()
        free.reset(max(self._contextSize, len(vec)))
        for i, val in enumerate(vec[:free.size]):
            free.array[i] = val & _UINTM_MASK
        return free

    def _splitContext(self, addr: Address) -> ContextInternal.FreeArray:
        self._rememberSpace(addr.getSpace())
        key = (addr.getSpace().getIndex(), addr.getOffset())
        if key in self._contextMap:
            return self._coerceFreeArray(key)
        free = self._cloneContextValues(self.getContext(addr))
        self._contextMap[key] = free
        return free

    def registerVariable(self, name: str, sbit: int, ebit: int) -> None:
        if self._contextMap:
            raise LowlevelError("Cannot register new context variables after database is initialized")
        cbr = ContextBitRange(sbit, ebit)
        needed = sbit // _UINTM_BITS + 1
        if (ebit // _UINTM_BITS + 1) != needed:
            raise LowlevelError("Context variable does not fit in one word")
        if needed > self._contextSize:
            self._syncDefaultFreeArray()
            self._contextSize = needed
            self._defaultFreeArray.reset(self._contextSize)
            self._defaultContext = self._defaultFreeArray.array
        self._variables[name] = cbr

    def getVariable(self, name: str) -> ContextBitRange:
        cbr = self._variables.get(name)
        if cbr is None:
            raise LowlevelError(f"Non-existent context variable: {name}")
        return cbr

    def setVariable(self, name: str, addr: Address, val: int) -> None:
        super().setVariable(name, addr, val)

    def setVariableRegion(self, name: str, addr1: Address, addr2: Address, val: int) -> None:
        super().setVariableRegion(name, addr1, addr2, val)

    def getTrackedSet(self, addr: Address) -> List[TrackedContext]:
        """Get tracked register set at the given address."""
        self._rememberSpace(addr.getSpace())
        spc_idx = addr.getSpace().getIndex()
        addr_off = addr.getOffset()
        current: Optional[List[TrackedContext]] = None
        for (si, off), tracked in sorted(self._trackMap.items()):
            if si != spc_idx:
                continue
            if off <= addr_off:
                current = tracked
                continue
            break
        return self._trackDefault if current is None else current

    def getContext(
        self,
        addr: Address,
        first: Optional[List[int]] = None,
        last: Optional[List[int]] = None,
    ) -> List[int]:
        space = addr.getSpace()
        self._rememberSpace(space)
        spc_idx = space.getIndex()
        addr_off = addr.getOffset()
        lower_off: Optional[int] = None
        lower_ctx: Optional[ContextInternal.FreeArray] = None
        upper_off: Optional[int] = None
        for (si, off), ctx in self._iterContextEntries():
            if si != spc_idx:
                continue
            if off <= addr_off:
                lower_off = off
                lower_ctx = ctx
                continue
            upper_off = off
            break
        if first is not None:
            first[:] = [0 if lower_off is None else lower_off]
        if last is not None:
            last[:] = [space.getHighest() if upper_off is None else upper_off - 1]
        if lower_ctx is not None:
            return lower_ctx.array
        return self.getDefaultValue()

    def getContextSize(self) -> int:
        return self._contextSize

    def getDefaultValue(self) -> List[int]:
        self._syncDefaultFreeArray()
        if self._defaultFreeArray.size < self._contextSize:
            self._defaultFreeArray.reset(self._contextSize)
            self._defaultContext = self._defaultFreeArray.array
        return self._defaultContext

    def getTrackedDefault(self) -> List[TrackedContext]:
        return self._trackDefault

    def setVariableDefault(self, name: str, val: int) -> None:
        super().setVariableDefault(name, val)

    def getDefaultValueByName(self, name: str) -> int:
        return super().getDefaultValueByName(name)

    def getRegionForSet(self, res: list, addr1: Address, addr2: Address, num: int, mask: int) -> None:
        """Get context blobs in range [addr1, addr2).

        C++ ref: ContextInternal::getRegionForSet
        """
        self._splitContext(addr1)
        spc_idx = addr1.getSpace().getIndex()
        beg_off = addr1.getOffset()
        end_off: Optional[int] = None
        if not addr2.isInvalid():
            self._splitContext(addr2)
            end_off = addr2.getOffset()
        for (si, off), ctx in self._iterContextEntries():
            if si != spc_idx:
                continue
            if off < beg_off:
                continue
            if end_off is not None and off >= end_off:
                break
            if len(ctx.mask) <= num:
                ctx.reset(max(ctx.size, self._contextSize, num + 1))
            res.append(ctx.array)
            ctx.mask[num] |= mask & _UINTM_MASK

    def getRegionToChangePoint(self, res: list, addr: Address, num: int, mask: int) -> None:
        """Get context blobs from addr to next explicit change point.

        C++ ref: ContextInternal::getRegionToChangePoint
        """
        self._splitContext(addr)
        spc_idx = addr.getSpace().getIndex()
        beg_off = addr.getOffset()
        started = False
        for (si, off), ctx in self._iterContextEntries():
            if si != spc_idx:
                continue
            if off < beg_off:
                continue
            if len(ctx.mask) <= num:
                ctx.reset(max(ctx.size, self._contextSize, num + 1))
            if not started:
                res.append(ctx.array)
                ctx.mask[num] |= mask & _UINTM_MASK
                started = True
                continue
            if (ctx.mask[num] & mask) != 0:
                break
            res.append(ctx.array)

    def createSet(self, addr1: Address, addr2: Address) -> List[TrackedContext]:
        """Create a tracked set for the given address range.

        C++ ref: ContextInternal::createSet
        """
        self._rememberSpace(addr1.getSpace())
        spc_idx = addr1.getSpace().getIndex()
        beg_off = addr1.getOffset()
        end_off = addr2.getOffset() if not addr2.isInvalid() else None
        for key in list(self._trackMap.keys()):
            si, off = key
            if si != spc_idx:
                continue
            if off < beg_off:
                continue
            if end_off is not None and off >= end_off:
                continue
            del self._trackMap[key]
        key = (spc_idx, beg_off)
        self._trackMap[key] = []
        return self._trackMap[key]

    def encodeContext(self, encoder: Encoder, addr: Address, vec: List[int]) -> None:
        """Encode a single context block as a <context_pointset>.

        C++ ref: ContextInternal::encodeContext
        """
        from ghidra.core.marshal import ELEM_CONTEXT_POINTSET, ELEM_SET, ATTRIB_NAME, ATTRIB_VAL
        encoder.openElement(ELEM_CONTEXT_POINTSET)
        addr.getSpace().encodeAttributes(encoder, addr.getOffset())
        for name in sorted(self._variables):
            cbr = self._variables[name]
            val = cbr.getValue(vec)
            encoder.openElement(ELEM_SET)
            encoder.writeString(ATTRIB_NAME, name)
            encoder.writeUnsignedInteger(ATTRIB_VAL, val)
            encoder.closeElement(ELEM_SET)
        encoder.closeElement(ELEM_CONTEXT_POINTSET)

    def decodeContext(self, decoder: Decoder, addr1: Address, addr2: Address) -> None:
        """Decode context variable values from <set> elements.

        C++ ref: ContextInternal::decodeContext
        """
        from ghidra.core.marshal import ELEM_SET, ATTRIB_VAL, ATTRIB_NAME
        while decoder.peekElement() == ELEM_SET:
            subId = decoder.openElement()
            val = decoder.readUnsignedInteger(ATTRIB_VAL)
            var = self.getVariable(decoder.readString(ATTRIB_NAME))
            if addr1.isInvalid():
                defaultBuffer = self.getDefaultValue()
                for i in range(self._contextSize):
                    defaultBuffer[i] = 0
                vec = [defaultBuffer]
            else:
                vec: List[List[int]] = []
                self.getRegionForSet(
                    vec,
                    addr1,
                    addr2,
                    var.getWord(),
                    (var.getMask() << var.getShift()) & _UINTM_MASK,
                )
            for ctx in vec:
                var.setValue(ctx, val)
            decoder.closeElement(subId)

    def encode(self, encoder: Encoder) -> None:
        """Encode all context data as a <context_points> element.

        C++ ref: ContextInternal::encode
        """
        from ghidra.core.marshal import ELEM_CONTEXT_POINTS
        if not self._contextMap and not self._trackMap:
            return
        encoder.openElement(ELEM_CONTEXT_POINTS)
        for (spc_idx, off), ctx in self._iterContextEntries():
            space = self._resolveSpace(spc_idx)
            if space is None:
                raise LowlevelError(f"Unable to resolve address space index: {spc_idx}")
            self.encodeContext(encoder, Address(space, off), ctx.array)
        for (spc_idx, off), tset in sorted(self._trackMap.items()):
            space = self._resolveSpace(spc_idx)
            if space is None:
                raise LowlevelError(f"Unable to resolve address space index: {spc_idx}")
            self.encodeTracked(encoder, Address(space, off), tset)
        encoder.closeElement(ELEM_CONTEXT_POINTS)

    def decode(self, decoder: Decoder) -> None:
        """Decode from a <context_points> element.

        C++ ref: ContextInternal::decode
        """
        from ghidra.core.marshal import (ELEM_CONTEXT_POINTS, ELEM_CONTEXT_POINTSET,
                                         ELEM_TRACKED_POINTSET)
        elemId = decoder.openElement(ELEM_CONTEXT_POINTS)
        while decoder.peekElement() != 0:
            subId = decoder.openElement()
            if subId == ELEM_CONTEXT_POINTSET:
                attribId = decoder.getNextAttributeId()
                decoder.rewindAttributes()
                if attribId == 0:
                    self.decodeContext(decoder, Address(), Address())
                else:
                    vData = VarnodeData()
                    vData.decodeFromAttributes(decoder)
                    self.decodeContext(decoder, vData.getAddr(), Address())
            elif subId == ELEM_TRACKED_POINTSET:
                vData = VarnodeData()
                vData.decodeFromAttributes(decoder)
                tset = self.createSet(vData.getAddr(), Address())
                self.decodeTracked(decoder, tset)
            else:
                raise LowlevelError("Bad <context_points> tag")
            decoder.closeElement(subId)
        decoder.closeElement(elemId)

    def decodeFromSpec(self, decoder: Decoder) -> None:
        """Decode from a <context_data> element (from .cspec/.pspec).

        C++ ref: ContextInternal::decodeFromSpec
        """
        from ghidra.core.marshal import ELEM_CONTEXT_DATA, ELEM_CONTEXT_SET, ELEM_TRACKED_SET
        elemId = decoder.openElement(ELEM_CONTEXT_DATA)
        while decoder.peekElement() != 0:
            subId = decoder.openElement()
            rng = Range()
            rng.decodeFromAttributes(decoder)
            addr1 = rng.getFirstAddr()
            addr2 = rng.getLastAddrOpen(decoder.getAddrSpaceManager())
            if subId == ELEM_CONTEXT_SET:
                self.decodeContext(decoder, addr1, addr2)
            elif subId == ELEM_TRACKED_SET:
                tset = self.createSet(addr1, addr2)
                self.decodeTracked(decoder, tset)
            else:
                raise LowlevelError("Bad <context_data> tag")
            decoder.closeElement(subId)
        decoder.closeElement(elemId)

    def _resolveSpace(self, spc_idx: int) -> Optional[AddrSpace]:
        """Resolve a space by its index. Override if space manager is available."""
        return self._spaceByIndex.get(spc_idx)


class ContextCache:
    """Cache for a ContextDatabase to reduce repeated lookups.

    C++ ref: ContextCache in globalcontext.hh
    """

    def __init__(self, db: ContextDatabase) -> None:
        self._database: ContextDatabase = db
        self._curspace: Optional[AddrSpace] = None
        self._first: int = 0
        self._last: int = 0
        self._context: List[int] = []
        self._allowset: bool = True

    def getDatabase(self) -> ContextDatabase:
        return self._database

    def allowSet(self, val: bool) -> None:
        self._allowset = val

    def getContext(self, addr: Address, buf: List[int]) -> None:
        """Get context blob, using cache if possible.

        C++ ref: ContextCache::getContext
        """
        spc = addr.getSpace()
        off = addr.getOffset()
        if spc is not self._curspace or off < self._first or off > self._last:
            first: List[int] = []
            last: List[int] = []
            self._curspace = spc
            self._context = self._database.getContext(addr, first, last)
            self._first = first[0]
            self._last = last[0]
        buf.clear()
        buf.extend(self._context[:self._database.getContextSize()])

    def setContext(
        self,
        addr: Address,
        num_or_addr2: int | Address,
        mask_or_num: int,
        value_or_mask: int,
        value: Optional[int] = None,
    ) -> None:
        """Set context at a single point or across an explicit range."""
        if isinstance(num_or_addr2, Address):
            addr1 = addr
            addr2 = num_or_addr2
            num = mask_or_num
            mask = value_or_mask
            if value is None:
                raise TypeError("Range form of setContext requires a value")
            if not self._allowset:
                return
            self._database.setContextRegion(addr1, addr2, num, mask, value)
            off1 = addr1.getOffset()
            off2 = addr2.getOffset()
            if addr1.getSpace() is self._curspace and self._first <= off1 <= self._last:
                self._curspace = None
            if self._first <= off2 <= self._last:
                self._curspace = None
            if self._first >= off1 and self._first <= off2:
                self._curspace = None
            return

        num = num_or_addr2
        mask = mask_or_num
        if not self._allowset:
            return
        self._database.setContextChangePoint(addr, num, mask, value_or_mask)
        spc = addr.getSpace()
        off = addr.getOffset()
        if spc is self._curspace and self._first <= off <= self._last:
            self._curspace = None

    def setContextRange(self, addr1: Address, addr2: Address, num: int, mask: int, value: int) -> None:
        self.setContext(addr1, addr2, num, mask, value)


class ParserContext:
    """Context for parsing a single instruction."""

    uninitialized = 0
    disassembly = 1
    pcode = 2

    def __init__(self, ccache: ContextCache | None, trans: object | None) -> None:
        self.translate = trans
        self.parsestate = ParserContext.uninitialized
        self.const_space: Optional[AddrSpace] = None
        self.buf = bytearray(16)
        self.contcache = ccache
        if ccache is not None:
            self.contextsize = ccache.getDatabase().getContextSize()
            self.context: List[int] = [0] * self.contextsize
        else:
            self.contextsize = 0
            self.context = []
        self.contextcommit: List[ContextSet] = []
        self.addr = Address()
        self.naddr = Address()
        self.n2addr = Address()
        self.calladdr = Address()
        self.state: List[ConstructState] = []
        self.base_state: ConstructState | None = None
        self.alloc = 0
        self.delayslot = 0

    def __del__(self) -> None:
        self.context.clear()

    def getBuffer(self) -> bytearray:
        return self.buf

    def initialize(self, maxstate: int, maxparam: int, spc: AddrSpace | None) -> None:
        self.const_space = spc
        self.state = [ConstructState() for _ in range(maxstate)]
        if self.state:
            self.state[0].parent = None
        for entry in self.state:
            entry.resolve = [None] * maxparam
        self.base_state = self.state[0] if self.state else None

    def getParserState(self) -> int:
        return self.parsestate

    def setParserState(self, st: int) -> None:
        self.parsestate = st

    def deallocateState(self, walker: ParserWalkerChange) -> None:
        self.alloc = 1
        walker.context = self
        walker.baseState()

    def allocateOperand(self, i: int, walker: ParserWalkerChange) -> None:
        opstate = self.state[self.alloc]
        self.alloc += 1
        opstate.parent = walker.point
        opstate.ct = None
        cast(ConstructState, walker.point).resolve[i] = opstate
        walker.breadcrumb[walker.depth] += 1
        walker.depth += 1
        walker.point = opstate
        walker.breadcrumb[walker.depth] = 0

    def setAddr(self, ad: Address) -> None:
        self.addr = Address(ad)
        self.n2addr = Address()

    def setNaddr(self, ad: Address) -> None:
        self.naddr = Address(ad)

    def setCalladdr(self, ad: Address) -> None:
        self.calladdr = Address(ad)

    def addCommit(self, sym: object, num: int, mask: int, flow: bool, point: ConstructState) -> None:
        self.contextcommit.append(
            ContextSet(sym=sym, point=point, num=num, mask=mask, value=self.context[num] & mask, flow=flow)
        )

    def clearCommits(self) -> None:
        self.contextcommit.clear()

    def applyCommits(self) -> None:
        if not self.contextcommit:
            return
        from ghidra.sleigh.sleighbase import SleighSymbol

        walker = ParserWalker(self)
        walker.baseState()

        for entry in self.contextcommit:
            sym = entry.sym
            if getattr(sym, "getType")() == SleighSymbol.operand_symbol:
                i = sym.getIndex()
                target = cast(ConstructState, cast(ConstructState, entry.point).resolve[i])
                hand = target.hand
                commitaddr = Address(hand.space, hand.offset_offset)
            else:
                hand = FixedHandle()
                sym.getFixedHandle(hand, walker)
                commitaddr = Address(hand.space, hand.offset_offset)

            if commitaddr.isConstant():
                curspace = self.addr.getSpace()
                newoff = AddrSpace.addressToByte(commitaddr.getOffset(), curspace.getWordSize())
                commitaddr = Address(curspace, newoff)

            if entry.flow:
                self.contcache.setContext(commitaddr, entry.num, entry.mask, entry.value)
            else:
                nextaddr = commitaddr + 1
                if nextaddr.getOffset() < commitaddr.getOffset():
                    self.contcache.setContext(commitaddr, entry.num, entry.mask, entry.value)
                else:
                    self.contcache.setContextRange(commitaddr, nextaddr, entry.num, entry.mask, entry.value)

    def getAddr(self) -> Address:
        return self.addr

    def getNaddr(self) -> Address:
        return self.naddr

    def getN2addr(self) -> Address:
        if self.n2addr.isInvalid():
            if self.translate is None or self.parsestate == ParserContext.uninitialized:
                raise LowlevelError("inst_next2 not available in this context")
            length = self.translate.instructionLength(self.naddr)
            self.n2addr = self.naddr + length
        return self.n2addr

    def getDestAddr(self) -> Address:
        return self.calladdr

    def getRefAddr(self) -> Address:
        return self.calladdr

    def getCurSpace(self) -> AddrSpace | None:
        return self.addr.getSpace()

    def getConstSpace(self) -> AddrSpace | None:
        return self.const_space

    def getInstructionBytes(self, byteoff: int, numbytes: int, off: int) -> int:
        off += byteoff
        if off >= 16:
            raise BadDataError("Instruction is using more than 16 bytes")
        res = 0
        for i in range(numbytes):
            res = ((res << 8) | self.buf[off + i]) & _UINTM_MASK
        return res

    def getContextBytes(self, byteoff: int, numbytes: int) -> int:
        intstart = byteoff // _UINTM_BYTES
        res = self.context[intstart] & _UINTM_MASK
        byte_offset = byteoff % _UINTM_BYTES
        unused_bytes = _UINTM_BYTES - numbytes
        res = (res << (byte_offset * 8)) & _UINTM_MASK
        res >>= unused_bytes * 8
        remaining = numbytes - _UINTM_BYTES + byte_offset
        if remaining > 0 and intstart + 1 < self.contextsize:
            intstart += 1
            res2 = self.context[intstart] & _UINTM_MASK
            unused_bytes = _UINTM_BYTES - remaining
            res2 >>= unused_bytes * 8
            res |= res2
        return res

    def getInstructionBits(self, startbit: int, size: int, off: int) -> int:
        off += startbit // 8
        if off >= 16:
            raise BadDataError("Instruction is using more than 16 bytes")
        ptr_start = off
        startbit %= 8
        bytesize = (startbit + size - 1) // 8 + 1
        res = 0
        for i in range(bytesize):
            res = ((res << 8) | self.buf[ptr_start + i]) & _UINTM_MASK
        res = (res << (8 * (_UINTM_BYTES - bytesize) + startbit)) & _UINTM_MASK
        res >>= _UINTM_BITS - size
        return res

    def getContextBits(self, startbit: int, size: int) -> int:
        intstart = startbit // _UINTM_BITS
        res = self.context[intstart] & _UINTM_MASK
        bit_offset = startbit % _UINTM_BITS
        unused_bits = _UINTM_BITS - size
        res = (res << bit_offset) & _UINTM_MASK
        res >>= unused_bits
        remaining = size - _UINTM_BITS + bit_offset
        if remaining > 0 and intstart + 1 < self.contextsize:
            intstart += 1
            res2 = self.context[intstart] & _UINTM_MASK
            unused_bits = _UINTM_BITS - remaining
            res2 >>= unused_bits
            res |= res2
        return res

    def setContextWord(self, i: int, val: int, mask: int) -> None:
        self.context[i] = (self.context[i] & (~mask & _UINTM_MASK)) | (mask & val)

    def loadContext(self) -> None:
        self.contcache.getContext(self.addr, self.context)

    def getLength(self) -> int:
        return cast(ConstructState, self.base_state).length

    def setDelaySlot(self, val: int) -> None:
        self.delayslot = val

    def getDelaySlot(self) -> int:
        return self.delayslot


class ParserWalker:
    """Walk a ParserContext constructor tree."""

    def __init__(self, c: ParserContext, cross: ParserContext | None = None) -> None:
        self.const_context = c
        self.cross_context = cross
        self.point: ConstructState | None = None
        self.depth = 0
        self.breadcrumb = [0] * 32

    def getParserContext(self) -> ParserContext:
        return self.const_context

    def baseState(self) -> None:
        self.point = self.const_context.base_state
        self.depth = 0
        self.breadcrumb[0] = 0

    def setOutOfBandState(
        self,
        ct: object,
        index: int,
        tempstate: ConstructState,
        otherwalker: ParserWalker,
    ) -> None:
        pt = cast(ConstructState, otherwalker.point)
        curdepth = otherwalker.depth
        while getattr(pt, "ct") != ct:
            if curdepth <= 0:
                return
            curdepth -= 1
            pt = cast(ConstructState, pt.parent)
        sym = ct.getOperand(index)
        i = sym.getOffsetBase()
        if i < 0:
            tempstate.offset = pt.offset + sym.getRelativeOffset()
        else:
            tempstate.offset = cast(ConstructState, pt.resolve[index]).offset

        tempstate.ct = ct
        tempstate.length = pt.length
        self.point = tempstate
        self.depth = 0
        self.breadcrumb[0] = 0

    def isState(self) -> bool:
        return self.point is not None

    def pushOperand(self, i: int) -> None:
        self.breadcrumb[self.depth] = i + 1
        self.depth += 1
        self.point = cast(ConstructState, cast(ConstructState, self.point).resolve[i])
        self.breadcrumb[self.depth] = 0

    def popOperand(self) -> None:
        self.point = cast(ConstructState, self.point).parent
        self.depth -= 1

    def getOffset(self, i: int) -> int:
        if i < 0:
            return cast(ConstructState, self.point).offset
        op = cast(ConstructState, cast(ConstructState, self.point).resolve[i])
        return op.offset + op.length

    def getConstructor(self) -> object | None:
        return cast(ConstructState, self.point).ct

    def getOperand(self) -> int:
        return self.breadcrumb[self.depth]

    def getParentHandle(self) -> FixedHandle:
        return cast(ConstructState, self.point).hand

    def getFixedHandle(self, i: int) -> FixedHandle:
        return cast(ConstructState, cast(ConstructState, self.point).resolve[i]).hand

    def getCurSpace(self) -> AddrSpace | None:
        return self.const_context.getCurSpace()

    def getConstSpace(self) -> AddrSpace | None:
        return self.const_context.getConstSpace()

    def getAddr(self) -> Address:
        if self.cross_context is not None:
            return self.cross_context.getAddr()
        return self.const_context.getAddr()

    def getNaddr(self) -> Address:
        if self.cross_context is not None:
            return self.cross_context.getNaddr()
        return self.const_context.getNaddr()

    def getN2addr(self) -> Address:
        if self.cross_context is not None:
            return self.cross_context.getN2addr()
        return self.const_context.getN2addr()

    def getRefAddr(self) -> Address:
        if self.cross_context is not None:
            return self.cross_context.getRefAddr()
        return self.const_context.getRefAddr()

    def getDestAddr(self) -> Address:
        if self.cross_context is not None:
            return self.cross_context.getDestAddr()
        return self.const_context.getDestAddr()

    def getLength(self) -> int:
        return self.const_context.getLength()

    def getInstructionBytes(self, byteoff: int, numbytes: int) -> int:
        return self.const_context.getInstructionBytes(byteoff, numbytes, cast(ConstructState, self.point).offset)

    def getContextBytes(self, byteoff: int, numbytes: int) -> int:
        return self.const_context.getContextBytes(byteoff, numbytes)

    def getInstructionBits(self, startbit: int, size: int) -> int:
        return self.const_context.getInstructionBits(startbit, size, cast(ConstructState, self.point).offset)

    def getContextBits(self, startbit: int, size: int) -> int:
        return self.const_context.getContextBits(startbit, size)


class ParserWalkerChange(ParserWalker):
    """A ParserWalker that can modify the current parse tree."""

    def __init__(self, c: ParserContext) -> None:
        super().__init__(c)
        self.context = c

    def getParserContext(self) -> ParserContext:
        return self.context

    def getPoint(self) -> ConstructState | None:
        return self.point

    def setOffset(self, off: int) -> None:
        cast(ConstructState, self.point).offset = off

    def setConstructor(self, c: object) -> None:
        cast(ConstructState, self.point).ct = c

    def setCurrentLength(self, length: int) -> None:
        cast(ConstructState, self.point).length = length

    def calcCurrentLength(self, length: int, numopers: int) -> None:
        point = cast(ConstructState, self.point)
        length += point.offset
        for i in range(numopers):
            subpoint = cast(ConstructState, point.resolve[i])
            sublength = subpoint.length + subpoint.offset
            if sublength > length:
                length = sublength
        point.length = length - point.offset


class SleighError(LowlevelError):
    pass
