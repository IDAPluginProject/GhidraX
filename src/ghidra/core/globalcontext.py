"""
Corresponds to: globalcontext.hh / globalcontext.cc

Map from addresses to context settings. Context is used to affect
disassembly depending on processor state (e.g. ARM/Thumb mode).
"""

from __future__ import annotations

from abc import ABC, abstractmethod
from typing import Optional, List, Dict, Tuple

from ghidra.core.address import Address, Range, RangeList
from ghidra.core.pcoderaw import VarnodeData
from ghidra.core.space import AddrSpace
from ghidra.core.marshal import Decoder, Encoder


def _calc_mask(size: int) -> int:
    if size >= 8:
        return 0xFFFFFFFFFFFFFFFF
    return (1 << (size * 8)) - 1


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

    def __init__(self, sbit: int = 0, ebit: int = 0) -> None:
        self.word: int = sbit // 32
        self.startbit: int = sbit % 32
        self.endbit: int = ebit % 32
        self.shift: int = 31 - self.endbit
        self.mask: int = 0
        if sbit // 32 == ebit // 32:
            self.mask = (0xFFFFFFFF >> (self.startbit + 31 - self.endbit)) << self.shift
        else:
            self.mask = 0xFFFFFFFF >> self.startbit

    def setValue(self, vec: List[int], val: int) -> None:
        """Set the value of this variable in a context blob."""
        while len(vec) <= self.word:
            vec.append(0)
        vec[self.word] = (vec[self.word] & ~self.mask) | ((val << self.shift) & self.mask)

    def getValue(self, vec: List[int]) -> int:
        """Get the value of this variable from a context blob."""
        if self.word >= len(vec):
            return 0
        return (vec[self.word] & self.mask) >> self.shift


class ContextDatabase(ABC):
    """Abstract interface for the context database.

    A ContextDatabase stores context variable settings associated with
    address ranges. Different implementations may store the data in
    different ways (e.g. in memory, or via Ghidra's database).
    """

    @abstractmethod
    def getVariable(self, name: str) -> Optional[ContextBitRange]:
        """Get the bit range for a named context variable."""
        ...

    @abstractmethod
    def setVariable(self, name: str, addr: Address, val: int) -> None:
        """Set a context variable at a specific address."""
        ...

    @abstractmethod
    def setVariableRegion(self, name: str, addr1: Address, addr2: Address, val: int) -> None:
        """Set a context variable over a range of addresses."""
        ...

    @abstractmethod
    def getContext(self, addr: Address) -> List[int]:
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
    def getTrackedSet(self, addr: Address) -> List[TrackedContext]:
        """Get tracked register set at the given address."""
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

    def getRegionForSet(self, res: list, addr1: Address, addr2: Address, num: int, mask: int) -> None:
        """Get context blobs in region [addr1, addr2). Override in subclass."""
        pass

    def getRegionToChangePoint(self, res: list, addr: Address, num: int, mask: int) -> None:
        """Get context blobs from addr to next change point. Override in subclass."""
        pass


class ContextInternal(ContextDatabase):
    """A simple in-memory implementation of ContextDatabase.

    Stores context as a default blob plus address-specific overrides.
    """

    def __init__(self) -> None:
        self._variables: Dict[str, ContextBitRange] = {}
        self._contextSize: int = 0  # Number of 32-bit words in context
        self._defaultContext: List[int] = []
        # Mapping from (space_index, offset) -> context blob override
        self._contextMap: Dict[Tuple[int, int], List[int]] = {}
        # Mapping from (space_index, offset) -> tracked register set
        self._trackMap: Dict[Tuple[int, int], List[TrackedContext]] = {}

    def registerVariable(self, name: str, sbit: int, ebit: int) -> None:
        cbr = ContextBitRange(sbit, ebit)
        self._variables[name] = cbr
        needed = cbr.word + 1
        if needed > self._contextSize:
            self._contextSize = needed
            while len(self._defaultContext) < self._contextSize:
                self._defaultContext.append(0)

    def getVariable(self, name: str) -> Optional[ContextBitRange]:
        return self._variables.get(name)

    def setVariable(self, name: str, addr: Address, val: int) -> None:
        cbr = self._variables.get(name)
        if cbr is None:
            return
        key = (addr.getSpace().getIndex(), addr.getOffset())
        if key not in self._contextMap:
            self._contextMap[key] = list(self._defaultContext)
        cbr.setValue(self._contextMap[key], val)

    def setVariableRegion(self, name: str, addr1: Address, addr2: Address, val: int) -> None:
        """Set a context variable across an address range.

        C++ ref: ``ContextDatabase::setVariableRegion``
        Sets the variable at the start address and propagates to all existing
        context map entries within [addr1, addr2].
        """
        cbr = self._variables.get(name)
        if cbr is None:
            return
        spc_idx = addr1.getSpace().getIndex()
        beg_off = addr1.getOffset()
        end_off = addr2.getOffset()
        # Set at start address (ensures entry exists)
        key = (spc_idx, beg_off)
        if key not in self._contextMap:
            self._contextMap[key] = list(self._defaultContext)
        cbr.setValue(self._contextMap[key], val)
        # Propagate to all existing entries in range
        for (si, off), ctx in list(self._contextMap.items()):
            if si != spc_idx:
                continue
            if off > beg_off and off <= end_off:
                cbr.setValue(ctx, val)

    def getTrackedSet(self, addr: Address) -> List[TrackedContext]:
        """Get tracked register set at the given address."""
        key = (addr.getSpace().getIndex(), addr.getOffset())
        return self._trackMap.get(key, [])

    def getContext(self, addr: Address) -> List[int]:
        key = (addr.getSpace().getIndex(), addr.getOffset())
        return self._contextMap.get(key, list(self._defaultContext))

    def getContextSize(self) -> int:
        return self._contextSize

    def getDefaultValue(self) -> List[int]:
        return self._defaultContext

    def setVariableDefault(self, name: str, val: int) -> None:
        """Set a default value for a context variable."""
        cbr = self._variables.get(name)
        if cbr is None:
            return
        while len(self._defaultContext) <= cbr.word:
            self._defaultContext.append(0)
        cbr.setValue(self._defaultContext, val)

    def getDefaultValueByName(self, name: str) -> int:
        """Get the default value for a context variable by name."""
        cbr = self._variables.get(name)
        if cbr is None:
            return 0
        return cbr.getValue(self._defaultContext)

    def getRegionForSet(self, res: list, addr1: Address, addr2: Address, num: int, mask: int) -> None:
        """Get context blobs in range [addr1, addr2).

        C++ ref: ContextInternal::getRegionForSet
        """
        spc_idx = addr1.getSpace().getIndex()
        beg_off = addr1.getOffset()
        end_off = addr2.getOffset() if not addr2.isInvalid() else None
        key = (spc_idx, beg_off)
        if key not in self._contextMap:
            self._contextMap[key] = list(self._defaultContext)
        for (si, off), ctx in sorted(self._contextMap.items()):
            if si != spc_idx:
                continue
            if off < beg_off:
                continue
            if end_off is not None and off >= end_off:
                break
            res.append(ctx)

    def getRegionToChangePoint(self, res: list, addr: Address, num: int, mask: int) -> None:
        """Get context blobs from addr to next explicit change point.

        C++ ref: ContextInternal::getRegionToChangePoint
        """
        spc_idx = addr.getSpace().getIndex()
        beg_off = addr.getOffset()
        key = (spc_idx, beg_off)
        if key not in self._contextMap:
            self._contextMap[key] = list(self._defaultContext)
        started = False
        for (si, off), ctx in sorted(self._contextMap.items()):
            if si != spc_idx:
                continue
            if off < beg_off:
                continue
            if off == beg_off:
                res.append(ctx)
                started = True
                continue
            if not started:
                continue
            # Check if this is a definitive set point for this mask
            # In our simplified model, any existing entry is a change point
            break

    def createSet(self, addr1: Address, addr2: Address) -> List[TrackedContext]:
        """Create a tracked set for the given address range.

        C++ ref: ContextInternal::createSet
        """
        key = (addr1.getSpace().getIndex(), addr1.getOffset())
        self._trackMap[key] = []
        return self._trackMap[key]

    def encodeContext(self, encoder: Encoder, addr: Address, vec: List[int]) -> None:
        """Encode a single context block as a <context_pointset>.

        C++ ref: ContextInternal::encodeContext
        """
        from ghidra.core.marshal import ELEM_CONTEXT_POINTSET, ELEM_SET, ATTRIB_NAME, ATTRIB_VAL
        encoder.openElement(ELEM_CONTEXT_POINTSET)
        addr.getSpace().encodeAttributes(encoder, addr.getOffset())
        for name, cbr in self._variables.items():
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
        while True:
            subId = decoder.openElement()
            if subId == 0:
                break
            val = decoder.readUnsignedInteger(ATTRIB_VAL)
            name = decoder.readString(ATTRIB_NAME)
            var = self._variables.get(name)
            if var is None:
                decoder.closeElement(subId)
                continue
            if addr1.isInvalid():
                for i in range(len(self._defaultContext)):
                    self._defaultContext[i] = 0
                var.setValue(self._defaultContext, val)
            else:
                vec: List[List[int]] = []
                self.getRegionForSet(vec, addr1, addr2, var.word, var.mask)
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
        for (spc_idx, off), ctx in sorted(self._contextMap.items()):
            # Reconstruct address from key
            addr = Address(self._resolveSpace(spc_idx), off)
            self.encodeContext(encoder, addr, ctx)
        for (spc_idx, off), tset in sorted(self._trackMap.items()):
            addr = Address(self._resolveSpace(spc_idx), off)
            self.encodeTracked(encoder, addr, tset)
        encoder.closeElement(ELEM_CONTEXT_POINTS)

    def decode(self, decoder: Decoder) -> None:
        """Decode from a <context_points> element.

        C++ ref: ContextInternal::decode
        """
        from ghidra.core.marshal import (ELEM_CONTEXT_POINTS, ELEM_CONTEXT_POINTSET,
                                         ELEM_TRACKED_POINTSET)
        elemId = decoder.openElement(ELEM_CONTEXT_POINTS)
        while True:
            subId = decoder.openElement()
            if subId == 0:
                break
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
            decoder.closeElement(subId)
        decoder.closeElement(elemId)

    def decodeFromSpec(self, decoder: Decoder) -> None:
        """Decode from a <context_data> element (from .cspec/.pspec).

        C++ ref: ContextInternal::decodeFromSpec
        """
        from ghidra.core.marshal import ELEM_CONTEXT_DATA, ELEM_CONTEXT_SET, ELEM_TRACKED_SET
        elemId = decoder.openElement(ELEM_CONTEXT_DATA)
        while True:
            subId = decoder.openElement()
            if subId == 0:
                break
            rng = Range()
            rng.decodeFromAttributes(decoder)
            addr1 = rng.getFirstAddr()
            addr2 = rng.getLastAddrOpen(decoder.getAddrSpaceManager())
            if subId == ELEM_CONTEXT_SET:
                self.decodeContext(decoder, addr1, addr2)
            elif subId == ELEM_TRACKED_SET:
                tset = self.createSet(addr1, addr2)
                self.decodeTracked(decoder, tset)
            decoder.closeElement(subId)
        decoder.closeElement(elemId)

    def _resolveSpace(self, spc_idx: int) -> Optional[AddrSpace]:
        """Resolve a space by its index. Override if space manager is available."""
        return None


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

    def allowSet(self, val: bool) -> None:
        self._allowset = val

    def getDatabase(self) -> ContextDatabase:
        return self._database

    def getContext(self, addr: Address, buf: List[int]) -> None:
        """Get context blob, using cache if possible.

        C++ ref: ContextCache::getContext
        """
        spc = addr.getSpace()
        off = addr.getOffset()
        if spc is not self._curspace or off < self._first or off > self._last:
            self._curspace = spc
            self._context = self._database.getContext(addr)
            self._first = off
            self._last = off
        buf.clear()
        buf.extend(self._context)

    def setContext(self, addr: Address, num: int, mask: int, value: int) -> None:
        """Set context value at addr up to next change point.

        C++ ref: ContextCache::setContext (single address version)
        """
        if not self._allowset:
            return
        self._database.setContextChangePoint(addr, num, mask, value)
        spc = addr.getSpace()
        off = addr.getOffset()
        if spc is self._curspace and self._first <= off <= self._last:
            self._curspace = None

    def setContextRange(self, addr1: Address, addr2: Address, num: int, mask: int, value: int) -> None:
        """Set context value across an explicit range.

        C++ ref: ContextCache::setContext (range version)
        """
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
