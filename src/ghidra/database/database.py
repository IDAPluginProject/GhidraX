"""
Corresponds to: database.hh / database.cc

Symbol and Scope objects for the decompiler.
Core classes: SymbolEntry, Symbol, FunctionSymbol, Scope, ScopeInternal, Database.
"""

from __future__ import annotations

from abc import ABC, abstractmethod
import inspect
import os
from typing import TYPE_CHECKING, Optional, List, Dict, Iterator, Tuple

from ghidra.core.address import Address, RangeList
from ghidra.core.compression import crc_update
from ghidra.core.error import LowlevelError, RecovError
from ghidra.ir.varnode import Varnode

if TYPE_CHECKING:
    from ghidra.types.datatype import Datatype, TypeFactory
    from ghidra.core.space import AddrSpace
    from ghidra.core.marshal import Encoder, Decoder


_FIND_OVERLAP_DEBUG_ADDRS = {
    int(tok, 0) & ((1 << 64) - 1)
    for tok in os.environ.get("PYGHIDRA_FIND_OVERLAP_DEBUG_ADDRS", "").split(",")
    if tok.strip()
}
_FIND_OVERLAP_DEBUG_LOG = os.environ.get(
    "PYGHIDRA_FIND_OVERLAP_DEBUG_LOG",
    "D:/BIGAI/pyghidra/temp/python_find_overlap_debug.log",
)
_ADD_SYMBOL_DEBUG_ADDRS = {
    int(tok, 0) & ((1 << 64) - 1)
    for tok in os.environ.get("PYGHIDRA_ADD_SYMBOL_DEBUG_ADDRS", "").split(",")
    if tok.strip()
}
_ADD_SYMBOL_DEBUG_LOG = os.environ.get(
    "PYGHIDRA_ADD_SYMBOL_DEBUG_LOG",
    "D:/BIGAI/pyghidra/temp/python_add_symbol_debug.log",
)


def _range_list_debug_str(rangelist: RangeList) -> str:
    if rangelist is None or rangelist.empty():
        return "[]"
    parts = []
    for rng in rangelist:
        space = getattr(rng, "spc", None)
        space_name = space.getName() if space is not None and hasattr(space, "getName") else "?"
        parts.append(f"{space_name}[{rng.getFirst():#x},{rng.getLast():#x}]")
    return "[" + ", ".join(parts) + "]"


def _find_overlap_debug_enabled(addr: Address) -> bool:
    if not _FIND_OVERLAP_DEBUG_ADDRS or addr is None or addr.isInvalid():
        return False
    return (addr.getOffset() & ((1 << 64) - 1)) in _FIND_OVERLAP_DEBUG_ADDRS


def _add_symbol_debug_enabled(addr: Address) -> bool:
    if not _ADD_SYMBOL_DEBUG_ADDRS or addr is None or addr.isInvalid():
        return False
    return (addr.getOffset() & ((1 << 64) - 1)) in _ADD_SYMBOL_DEBUG_ADDRS


def _add_symbol_debug_log(name: str, addr: Address, usepoint: Optional[Address],
                          size: int, addrtied: bool, uselimit: RangeList) -> None:
    if not _add_symbol_debug_enabled(addr):
        return
    try:
        from ghidra.transform.action import Action
        idx = Action.getActiveTraceSerial()
    except Exception:
        idx = 0
    try:
        up = "invalid"
        if usepoint is not None and not usepoint.isInvalid():
            up = f"{usepoint.getOffset():#x}"
        with open(_ADD_SYMBOL_DEBUG_LOG, "a", encoding="utf-8") as fp:
            caller_names = []
            for frame in inspect.stack()[2:5]:
                caller_names.append(frame.function)
            fp.write(
                f"idx={idx} "
                f"addr={addr.getOffset():#x}:{size} name={name!r} "
                f"usepoint={up} addrtied={int(addrtied)} "
                f"uselimit={_range_list_debug_str(uselimit)} "
                f"caller={'/'.join(caller_names)}\n"
            )
    except OSError:
        return


def _find_overlap_debug_log(addr: Address, size: int, candidates: list["SymbolEntry"],
                            selected: Optional["SymbolEntry"],
                            visible_entries: Optional[list["SymbolEntry"]] = None) -> None:
    if not _find_overlap_debug_enabled(addr):
        return
    try:
        with open(_FIND_OVERLAP_DEBUG_LOG, "a", encoding="utf-8") as fp:
            fp.write(
                f"addr={addr.getOffset():#x}:{size} candidates={len(candidates)} "
                f"selected_id={id(selected) if selected is not None else 'None'}\n"
            )
            if visible_entries is not None:
                fp.write(f"  visible_entries={len(visible_entries)}\n")
                for idx, entry in enumerate(visible_entries[:8]):
                    sym = entry.getSymbol() if hasattr(entry, "getSymbol") else None
                    name = getattr(sym, "name", "?")
                    fp.write(
                        f"  visible[{idx}] entry_id={id(entry)} sym={name} "
                        f"start={entry.getFirst():#x} end={entry.getLast():#x} "
                        f"size={entry.getSize()} flags={entry.getAllFlags():#x} "
                        f"addrtied={int(entry.isAddrTied())} "
                        f"space_idx={entry.getAddr().getSpace().getIndex() if entry.getAddr().getSpace() is not None and hasattr(entry.getAddr().getSpace(), 'getIndex') else 'None'} "
                        f"uselimit={_range_list_debug_str(entry.getUseLimit())}\n"
                    )
            for idx, entry in enumerate(candidates):
                sym = entry.getSymbol() if hasattr(entry, "getSymbol") else None
                name = getattr(sym, "name", "?")
                fp.write(
                    f"  idx={idx} entry_id={id(entry)} sym={name} "
                    f"start={entry.getFirst():#x} end={entry.getLast():#x} "
                    f"size={entry.getSize()} flags={entry.getAllFlags():#x} "
                    f"addrtied={int(entry.isAddrTied())} "
                    f"uselimit={_range_list_debug_str(entry.getUseLimit())}"
                )
                if selected is entry:
                    fp.write(" selected=1")
                fp.write("\n")
    except OSError:
        return


def _remove_symbol_debug_log(sym: "Symbol") -> None:
    entries = getattr(sym, "mapentry", None)
    if not entries:
        return
    matched = []
    for entry in entries:
        addr = entry.getAddr() if hasattr(entry, "getAddr") else None
        if addr is not None and _add_symbol_debug_enabled(addr):
            matched.append(entry)
    if not matched:
        return
    try:
        from ghidra.transform.action import Action
        idx = Action.getActiveTraceSerial()
    except Exception:
        idx = 0
    try:
        with open(_ADD_SYMBOL_DEBUG_LOG, "a", encoding="utf-8") as fp:
            caller_names = []
            for frame in inspect.stack()[2:5]:
                caller_names.append(frame.function)
            for entry in matched:
                fp.write(
                    f"idx={idx} remove "
                    f"addr={entry.getAddr().getOffset():#x}:{entry.getSize()} "
                    f"name={sym.getName()!r} flags={sym.getFlags():#x} "
                    f"category={sym.getCategory()} "
                    f"caller={'/'.join(caller_names)}\n"
                )
    except OSError:
        return


# =========================================================================
# SymbolEntry
# =========================================================================

class SymbolEntry:
    """A storage location for a particular Symbol.

    Where a Symbol is stored, as a byte address and a size.
    """

    class EntryInitData:
        def __init__(self, sym: Symbol, exfl: int, spc: AddrSpace,
                     off: int, ul: RangeList) -> None:
            self.space: AddrSpace = spc
            self.symbol: Symbol = sym
            self.extraflags: int = exfl
            self.offset: int = off
            self.uselimit: RangeList = ul

    class EntrySubsort:
        def __init__(self, val: Address | bool | SymbolEntry.EntrySubsort | None = None) -> None:
            if isinstance(val, Address):
                self.useindex: int = val.getSpace().getIndex()
                self.useoffset: int = val.getOffset()
            elif isinstance(val, SymbolEntry.EntrySubsort):
                self.useindex = val.useindex
                self.useoffset = val.useoffset
            elif isinstance(val, bool):
                if val:
                    self.useindex = 0xFFFF
                    self.useoffset = 0
                else:
                    self.useindex = 0
                    self.useoffset = 0
            else:
                self.useindex = 0
                self.useoffset = 0

        def __lt__(self, op2: SymbolEntry.EntrySubsort) -> bool:
            if self.useindex != op2.useindex:
                return self.useindex < op2.useindex
            return self.useoffset < op2.useoffset

    def __init__(self, symbol: Symbol | SymbolEntry.EntryInitData, addr: Optional[Address] | int = None,
                 size: int = -1, offset: int = 0,
                 extraflags: int = 0, hash_: int | RangeList = 0) -> None:
        if isinstance(symbol, SymbolEntry.EntryInitData):
            if not isinstance(addr, int):
                raise TypeError("SymbolEntry EntryInitData constructor requires integer start offset")
            data = symbol
            self.symbol: Symbol = data.symbol
            self.extraflags: int = data.extraflags
            self.addr: Address = Address(data.space, addr)
            self.hash: int = 0
            self.offset: int = data.offset
            self.size: int = (size - addr) + 1
            self.uselimit: RangeList = RangeList(data.uselimit)
            return
        if isinstance(hash_, RangeList):
            if not isinstance(addr, int):
                raise TypeError("SymbolEntry dynamic constructor requires integer extra flags")
            self.symbol = symbol
            self.extraflags = addr
            self.addr = Address()
            self.hash = size
            self.offset = offset
            self.size = extraflags
            self.uselimit = RangeList(hash_)
            return
        self.symbol: Symbol = symbol
        self.extraflags: int = extraflags
        self.addr: Address = addr if addr is not None else Address()
        self.hash: int = hash_
        self.offset: int = offset
        self.size: int = size
        self.uselimit: RangeList = RangeList()

    def isPiece(self) -> bool:
        return (self.extraflags & (Varnode.precislo | Varnode.precishi)) != 0

    def isDynamic(self) -> bool:
        return self.addr.isInvalid()

    def isInvalid(self) -> bool:
        return self.addr.isInvalid() and self.hash == 0

    def getAllFlags(self) -> int:
        return self.extraflags | self.symbol.getFlags()

    def getOffset(self) -> int:
        return self.offset

    def getFirst(self) -> int:
        return self.addr.getOffset()

    def getLast(self) -> int:
        return self.addr.getOffset() + self.size - 1

    def getSubsort(self) -> SymbolEntry.EntrySubsort:
        res = SymbolEntry.EntrySubsort()
        if (self.symbol.getFlags() & Varnode.addrtied) == 0:
            range_ = self.uselimit.getFirstRange()
            if range_ is None:
                raise LowlevelError("Map entry with empty uselimit")
            res.useindex = range_.getSpace().getIndex()
            res.useoffset = range_.getFirst()
        return res

    def getSymbol(self) -> Symbol:
        return self.symbol

    def getAddr(self) -> Address:
        return self.addr

    def getHash(self) -> int:
        return self.hash

    def getSize(self) -> int:
        return self.size

    def inUse(self, usepoint: Address) -> bool:
        if self.isAddrTied():
            return True
        if usepoint is None or usepoint.isInvalid():
            return False
        return self.uselimit.inRange(usepoint, 1)

    def getUseLimit(self) -> RangeList:
        return self.uselimit

    def setUseLimit(self, uselim: RangeList) -> None:
        self.uselimit = RangeList(uselim)

    def isAddrTied(self) -> bool:
        return (self.symbol.getFlags() & Varnode.addrtied) != 0

    def updateType(self, vn) -> bool:
        if (self.symbol.getFlags() & Varnode.typelock) != 0:
            dt = self.getSizedType(vn.getAddr(), vn.getSize())
            if dt is not None:
                return vn.updateType(dt, True, True)
        return False

    def getFirstUseAddress(self) -> Address:
        first = self.uselimit.getFirstRange()
        if first is not None:
            return first.getFirstAddr()
        return Address()

    def getSizedType(self, addr: Address, sz: int) -> Optional[Datatype]:
        """Get the data-type associated with (a piece of) this.

        C++ ref: ``SymbolEntry::getSizedType``
        """
        if self.isDynamic():
            off = self.offset
        else:
            off = int(addr.getOffset() - self.addr.getOffset()) + self.offset
        cur = self.symbol.getType()
        scope = self.symbol.getScope()
        arch = scope.getArch()
        return arch.types.getExactPiece(cur, off, sz)

    def printEntry(self, s) -> None:
        s.write(self.symbol.getName())
        s.write(" : ")
        if self.addr.isInvalid():
            s.write("<dynamic>")
        else:
            s.write(self.addr.getShortcut())
            self.addr.printRaw(s)
        s.write(f":{self.symbol.getType().getSize()}")
        s.write(" ")
        s.write(self.symbol.getType().printRaw())
        s.write(" : ")
        self.uselimit.printBounds(s)

    def encode(self, encoder) -> None:
        """Encode this SymbolEntry to a stream.

        C++ ref: ``SymbolEntry::encode``
        """
        if self.isPiece():
            return
        if self.addr.isInvalid():
            from ghidra.core.marshal import ELEM_HASH, ATTRIB_VAL
            encoder.openElement(ELEM_HASH)
            encoder.writeUnsignedInteger(ATTRIB_VAL, self.hash)
            encoder.closeElement(ELEM_HASH)
        else:
            self.addr.encode(encoder)
        self.uselimit.encode(encoder)

    def decode(self, decoder) -> None:
        """Decode a SymbolEntry from a stream.

        C++ ref: ``SymbolEntry::decode``
        """
        from ghidra.core.marshal import ELEM_HASH, ATTRIB_VAL
        elemId = decoder.peekElement()
        if elemId == ELEM_HASH.id:
            decoder.openElement()
            self.hash = decoder.readUnsignedInteger(ATTRIB_VAL)
            self.addr = Address()
            decoder.closeElement(elemId)
        else:
            self.addr = Address.decode(decoder)
            self.hash = 0
        self.uselimit.decode(decoder)

    def __repr__(self) -> str:
        return (f"SymbolEntry(sym={self.symbol.name!r}, "
                f"addr={self.addr}, size={self.size})")


# =========================================================================
# Symbol
# =========================================================================

class Symbol:
    """The base class for a symbol in a symbol table or scope.

    At its most basic, a Symbol is a name and a data-type.
    """

    # Display flags
    force_hex = 1
    force_dec = 2
    force_oct = 3
    force_bin = 4
    force_char = 5
    size_typelock = 8
    isolate = 16
    merge_problems = 32
    is_this_ptr = 64

    # Categories
    no_category = -1
    function_parameter = 0
    equate = 1
    union_facet = 2
    fake_input = 3

    ID_BASE: int = 0x4000000000000000

    def __init__(self, scope: Optional[Scope] = None, name: str = "",
                 ct: Optional[Datatype] = None) -> None:
        self.scope: Optional[Scope] = scope
        self.name: str = name
        self.displayName: str = name
        self.type: Optional[Datatype] = ct
        self.nameDedup: int = 0
        self.flags: int = 0
        self.dispflags: int = 0
        self.category: int = Symbol.no_category
        self.catindex: int = 0
        self.symbolId: int = 0
        self.mapentry: List[SymbolEntry] = []
        self.wholeCount: int = 0
        self.depthScope: Optional[Scope] = None
        self.depthResolution: int = 0

    def getName(self) -> str:
        return self.name

    def getDisplayName(self) -> str:
        return self.displayName

    def getType(self) -> Optional[Datatype]:
        return self.type

    def getId(self) -> int:
        return self.symbolId

    def getFlags(self) -> int:
        return self.flags

    def getDisplayFormat(self) -> int:
        return self.dispflags & 7

    def setDisplayFormat(self, val: int) -> None:
        self.dispflags = (self.dispflags & 0xFFFFFFF8) | val

    def getCategory(self) -> int:
        return self.category

    def getCategoryIndex(self) -> int:
        return self.catindex

    def isTypeLocked(self) -> bool:
        return (self.flags & Varnode.typelock) != 0

    def isNameLocked(self) -> bool:
        return (self.flags & Varnode.namelock) != 0

    def isSizeTypeLocked(self) -> bool:
        return (self.dispflags & Symbol.size_typelock) != 0

    def isVolatile(self) -> bool:
        return (self.flags & Varnode.volatil) != 0

    def isThisPointer(self) -> bool:
        return (self.dispflags & Symbol.is_this_ptr) != 0

    def isIndirectStorage(self) -> bool:
        return (self.flags & Varnode.indirectstorage) != 0

    def isHiddenReturn(self) -> bool:
        return (self.flags & Varnode.hiddenretparm) != 0

    def isNameUndefined(self) -> bool:
        return len(self.name) == 15 and self.name.startswith("$$undef")

    def isMultiEntry(self) -> bool:
        return self.wholeCount > 1

    def hasMergeProblems(self) -> bool:
        return (self.dispflags & Symbol.merge_problems) != 0

    def isIsolated(self) -> bool:
        return (self.dispflags & Symbol.isolate) != 0

    def setIsolated(self, val: bool) -> None:
        if val:
            self.dispflags |= Symbol.isolate
            self.flags |= Varnode.typelock
            self.checkSizeTypeLock()
        else:
            self.dispflags &= ~Symbol.isolate

    def getScope(self) -> Optional[Scope]:
        return self.scope

    def numEntries(self) -> int:
        return len(self.mapentry)

    def getMapEntry(self, i_or_addr=None) -> Optional[SymbolEntry]:
        if i_or_addr is None:
            return self.mapentry[0] if self.mapentry else None
        if isinstance(i_or_addr, int):
            return self.mapentry[i_or_addr]
        for entry in self.mapentry:
            entryaddr = entry.getAddr()
            if i_or_addr.getSpace() != entryaddr.getSpace():
                continue
            if i_or_addr.getOffset() < entryaddr.getOffset():
                continue
            diff = int(i_or_addr.getOffset() - entryaddr.getOffset())
            if diff >= entry.getSize():
                continue
            return entry
        return None

    def getFirstWholeMap(self) -> Optional[SymbolEntry]:
        if not self.mapentry:
            raise LowlevelError("No mapping for symbol: " + self.name)
        return self.mapentry[0]

    def getMapEntryPosition(self, entry: SymbolEntry) -> int:
        pos = 0
        for tmp in self.mapentry:
            if tmp is entry:
                return pos
            if entry.getSize() == self.type.getSize():
                pos += 1
        return -1

    def getResolutionDepth(self, useScope: Optional[Scope]) -> int:
        if self.scope is useScope:
            return 0
        if useScope is None:
            point = self.scope
            count = 0
            while point is not None:
                count += 1
                point = point.getParent()
            return count - 1
        if self.depthScope is useScope:
            return self.depthResolution
        self.depthScope = useScope
        distinguishScope = self.scope.findDistinguishingScope(useScope)
        self.depthResolution = 0
        if distinguishScope is None:
            distinguishName = self.name
            terminatingScope = self.scope
        else:
            distinguishName = distinguishScope.getName()
            currentScope = self.scope
            while currentScope is not distinguishScope:
                self.depthResolution += 1
                currentScope = currentScope.getParent()
            self.depthResolution += 1
            terminatingScope = distinguishScope.getParent()
        if useScope.isNameUsed(distinguishName, terminatingScope):
            self.depthResolution += 1
        return self.depthResolution

    def getBytesConsumed(self) -> int:
        return self.type.getSize()

    def setName(self, nm: str) -> None:
        self.name = nm

    def setDisplayName(self, nm: str) -> None:
        self.displayName = nm

    def setType(self, ct) -> None:
        self.type = ct

    def setFlags(self, fl: int) -> None:
        self.flags |= fl

    def clearFlags(self, fl: int) -> None:
        self.flags &= ~fl

    def setCategory(self, cat: int, ind: int) -> None:
        self.category = cat
        self.catindex = ind

    def setTypeLock(self, val: bool) -> None:
        if val:
            self.flags |= Varnode.typelock
        else:
            self.flags &= ~Varnode.typelock

    def setNameLock(self, val: bool) -> None:
        if val:
            self.flags |= Varnode.namelock
        else:
            self.flags &= ~Varnode.namelock

    def setVolatile(self, val: bool) -> None:
        if val:
            self.flags |= Varnode.volatil
        else:
            self.flags &= ~Varnode.volatil

    def setThisPointer(self, val: bool) -> None:
        if val:
            self.dispflags |= Symbol.is_this_ptr
        else:
            self.dispflags &= ~Symbol.is_this_ptr

    def setMergeProblems(self) -> None:
        self.dispflags |= Symbol.merge_problems

    def checkSizeTypeLock(self) -> None:
        from ghidra.types.datatype import TYPE_UNKNOWN

        self.dispflags &= ~Symbol.size_typelock
        if self.isTypeLocked() and self.type.getMetatype() == TYPE_UNKNOWN:
            self.dispflags |= Symbol.size_typelock

    def setSizeTypeLock(self, val: bool) -> None:
        if val:
            self.dispflags |= Symbol.size_typelock
        else:
            self.dispflags &= ~Symbol.size_typelock

    def setScope(self, sc) -> None:
        self.scope = sc

    def encodeHeader(self, encoder) -> None:
        """Encode the header attributes of this Symbol.

        C++ ref: ``Symbol::encodeHeader``
        """
        from ghidra.core.marshal import (
            ATTRIB_NAME, ATTRIB_ID, ATTRIB_NAMELOCK, ATTRIB_TYPELOCK,
            ATTRIB_READONLY, ATTRIB_VOLATILE, ATTRIB_CAT, ATTRIB_INDEX,
            ATTRIB_INDIRECTSTORAGE, ATTRIB_HIDDENRETPARM, ATTRIB_THISPTR,
            ATTRIB_FORMAT, ATTRIB_MERGE,
        )
        from ghidra.types.datatype import Datatype

        encoder.writeString(ATTRIB_NAME, self.name)
        encoder.writeUnsignedInteger(ATTRIB_ID, self.getId())
        if (self.flags & Varnode.namelock) != 0:
            encoder.writeBool(ATTRIB_NAMELOCK, True)
        if (self.flags & Varnode.typelock) != 0:
            encoder.writeBool(ATTRIB_TYPELOCK, True)
        if (self.flags & Varnode.readonly) != 0:
            encoder.writeBool(ATTRIB_READONLY, True)
        if (self.flags & Varnode.volatil) != 0:
            encoder.writeBool(ATTRIB_VOLATILE, True)
        if (self.flags & Varnode.indirectstorage) != 0:
            encoder.writeBool(ATTRIB_INDIRECTSTORAGE, True)
        if (self.flags & Varnode.hiddenretparm) != 0:
            encoder.writeBool(ATTRIB_HIDDENRETPARM, True)
        if (self.dispflags & Symbol.isolate) != 0:
            encoder.writeBool(ATTRIB_MERGE, False)
        if (self.dispflags & Symbol.is_this_ptr) != 0:
            encoder.writeBool(ATTRIB_THISPTR, True)
        fmt = self.getDisplayFormat()
        if fmt != 0:
            encoder.writeString(ATTRIB_FORMAT, Datatype.decodeIntegerFormat(fmt))
        encoder.writeSignedInteger(ATTRIB_CAT, self.category)
        if self.category >= 0:
            encoder.writeUnsignedInteger(ATTRIB_INDEX, self.catindex)

    def encodeBody(self, encoder) -> None:
        """Encode the data-type for this Symbol.

        C++ ref: ``Symbol::encodeBody``
        """
        self.type.encodeRef(encoder)

    def encode(self, encoder) -> None:
        """Encode this Symbol to a stream.

        C++ ref: ``Symbol::encode``
        """
        from ghidra.core.marshal import ELEM_SYMBOL
        encoder.openElement(ELEM_SYMBOL)
        self.encodeHeader(encoder)
        self.encodeBody(encoder)
        encoder.closeElement(ELEM_SYMBOL)

    def decodeHeader(self, decoder) -> None:
        """Decode symbol header attributes from a stream.

        C++ ref: ``Symbol::decodeHeader``
        """
        from ghidra.core.marshal import (
            ATTRIB_CAT, ATTRIB_FORMAT, ATTRIB_HIDDENRETPARM, ATTRIB_ID,
            ATTRIB_INDIRECTSTORAGE, ATTRIB_MERGE, ATTRIB_NAME,
            ATTRIB_NAMELOCK, ATTRIB_READONLY, ATTRIB_TYPELOCK,
            ATTRIB_THISPTR, ATTRIB_VOLATILE, ATTRIB_LABEL, ATTRIB_INDEX,
        )
        from ghidra.types.datatype import Datatype
        self.name = ""
        self.displayName = ""
        self.category = Symbol.no_category
        self.symbolId = 0
        while True:
            attribId = decoder.getNextAttributeId()
            if attribId == 0:
                break
            if attribId == ATTRIB_CAT.id:
                self.category = decoder.readSignedInteger()
            elif attribId == ATTRIB_FORMAT.id:
                self.dispflags |= Datatype.encodeIntegerFormat(decoder.readString())
            elif attribId == ATTRIB_HIDDENRETPARM.id:
                if decoder.readBool():
                    self.flags |= Varnode.hiddenretparm
            elif attribId == ATTRIB_ID.id:
                self.symbolId = decoder.readUnsignedInteger()
                if (self.symbolId >> 56) == (Symbol.ID_BASE >> 56):
                    self.symbolId = 0
            elif attribId == ATTRIB_INDIRECTSTORAGE.id:
                if decoder.readBool():
                    self.flags |= Varnode.indirectstorage
            elif attribId == ATTRIB_MERGE.id:
                if not decoder.readBool():
                    self.dispflags |= Symbol.isolate
                    self.flags |= Varnode.typelock
            elif attribId == ATTRIB_NAME.id:
                self.name = decoder.readString()
            elif attribId == ATTRIB_NAMELOCK.id:
                if decoder.readBool():
                    self.flags |= Varnode.namelock
            elif attribId == ATTRIB_READONLY.id:
                if decoder.readBool():
                    self.flags |= Varnode.readonly
            elif attribId == ATTRIB_TYPELOCK.id:
                if decoder.readBool():
                    self.flags |= Varnode.typelock
            elif attribId == ATTRIB_THISPTR.id:
                if decoder.readBool():
                    self.dispflags |= Symbol.is_this_ptr
            elif attribId == ATTRIB_VOLATILE.id:
                if decoder.readBool():
                    self.flags |= Varnode.volatil
            elif attribId == ATTRIB_LABEL.id:
                self.displayName = decoder.readString()
        if self.category == Symbol.function_parameter:
            self.catindex = decoder.readUnsignedInteger(ATTRIB_INDEX)
        else:
            self.catindex = 0
        if not self.displayName:
            self.displayName = self.name

    def decodeBody(self, decoder) -> None:
        """Decode the data-type of this Symbol.

        C++ ref: ``Symbol::decodeBody``
        """
        self.type = self.scope.getArch().types.decodeType(decoder)
        self.checkSizeTypeLock()

    def decode(self, decoder) -> None:
        """Decode this Symbol from a stream.

        C++ ref: ``Symbol::decode``
        """
        from ghidra.core.marshal import ELEM_SYMBOL
        elemId = decoder.openElement(ELEM_SYMBOL)
        self.decodeHeader(decoder)
        self.decodeBody(decoder)
        decoder.closeElement(elemId)

    def __repr__(self) -> str:
        tname = self.type.getName() if self.type else "?"
        return f"Symbol({self.name!r}, type={tname}, id={self.symbolId:#x})"


# =========================================================================
# FunctionSymbol
# =========================================================================

class FunctionSymbol(Symbol):
    """A Symbol representing an executable function."""

    def __init__(self, scope: Optional[Scope] = None, name: str | int = "",
                 size: int = 1) -> None:
        if isinstance(name, int):
            size = name
            name = ""
        super().__init__(scope, name)
        self.fd = None  # Funcdata (set later)
        self.consumeSize: int = size
        self._buildType()

    def __del__(self) -> None:
        self.fd = None

    def _buildType(self) -> None:
        """Set default code type and lock flags."""
        if self.scope is not None and hasattr(self.scope, "getArch"):
            arch = self.scope.getArch()
            typegrp = getattr(arch, "types", None)
            if typegrp is not None and hasattr(typegrp, "getTypeCode"):
                self.type = typegrp.getTypeCode()
        self.flags |= Varnode.namelock | Varnode.typelock

    def getFunction(self):
        if self.fd is not None:
            return self.fd
        entry = self.getFirstWholeMap()
        from ghidra.analysis.funcdata import Funcdata

        self.fd = Funcdata(self.name, self.getDisplayName(), self.scope, entry.getAddr(), self)
        return self.fd

    def setFunction(self, fd) -> None:
        self.fd = fd

    def encode(self, encoder) -> None:
        """Encode a FunctionSymbol to a stream.

        C++ ref: ``FunctionSymbol::encode``
        """
        from ghidra.core.marshal import ELEM_FUNCTIONSHELL, ATTRIB_NAME, ATTRIB_ID

        if self.fd is not None:
            self.fd.encode(encoder, self.symbolId, False)
        else:
            encoder.openElement(ELEM_FUNCTIONSHELL)
            encoder.writeString(ATTRIB_NAME, self.name)
            if self.symbolId != 0:
                encoder.writeUnsignedInteger(ATTRIB_ID, self.symbolId)
            encoder.closeElement(ELEM_FUNCTIONSHELL)

    def getBytesConsumed(self) -> int:
        return self.consumeSize

    def setBytesConsumed(self, sz: int) -> None:
        self.consumeSize = sz

    def decode(self, decoder) -> None:
        """Decode a FunctionSymbol from a stream.

        C++ ref: ``FunctionSymbol::decode``
        """
        from ghidra.analysis.funcdata import Funcdata
        from ghidra.core.address import Address
        from ghidra.core.error import RecovError
        from ghidra.core.marshal import ELEM_FUNCTION, ATTRIB_NAME, ATTRIB_ID, ATTRIB_LABEL
        elemId = decoder.peekElement()
        if elemId == ELEM_FUNCTION.id:
            self.fd = Funcdata("", "", self.scope, Address(), self)
            try:
                self.symbolId = self.fd.decode(decoder)
            except RecovError as err:
                raise DuplicateFunctionError(self.fd.getAddress(), self.fd.getName()) from err
            self.name = self.fd.getName()
            self.displayName = self.fd.getDisplayName()
            if self.consumeSize < self.fd.getSize():
                if 1 < self.fd.getSize() <= 8:
                    self.consumeSize = self.fd.getSize()
        else:
            decoder.openElement()
            self.symbolId = 0
            while True:
                attribId = decoder.getNextAttributeId()
                if attribId == 0:
                    break
                if attribId == ATTRIB_NAME:
                    self.name = decoder.readString()
                elif attribId == ATTRIB_ID:
                    self.symbolId = decoder.readUnsignedInteger()
                elif attribId == ATTRIB_LABEL:
                    self.displayName = decoder.readString()
            decoder.closeElement(elemId)


# =========================================================================
# EquateSymbol
# =========================================================================

class EquateSymbol(Symbol):
    """A Symbol that holds equate information for a constant."""

    def __init__(self, scope: Optional[Scope] = None, name: str = "",
                 format_: int | None = None, val: int | None = None) -> None:
        super().__init__(scope, name)
        self.value: int = 0 if val is None else val
        self.category = Symbol.equate
        if format_ is not None:
            if self.scope is not None and hasattr(self.scope, "getArch"):
                from ghidra.types.datatype import TYPE_UNKNOWN

                self.type = self.scope.getArch().types.getBase(1, TYPE_UNKNOWN)
            self.dispflags |= format_

    def getValue(self) -> int:
        return self.value

    def isValueClose(self, op2Value: int, size: int) -> bool:
        from ghidra.core.address import calc_mask, sign_extend

        if self.value == op2Value:
            return True
        mask = calc_mask(size)
        maskValue = self.value & mask
        if maskValue != self.value:
            if self.value != sign_extend(maskValue, size, 8):
                return False
        if maskValue == (op2Value & mask):
            return True
        if maskValue == (~op2Value & mask):
            return True
        if maskValue == (-op2Value & mask):
            return True
        if maskValue == ((op2Value + 1) & mask):
            return True
        if maskValue == ((op2Value - 1) & mask):
            return True
        return False

    def encode(self, encoder) -> None:
        """Encode an EquateSymbol to a stream.

        C++ ref: ``EquateSymbol::encode``
        """
        from ghidra.core.marshal import ELEM_EQUATESYMBOL, ELEM_VALUE, ATTRIB_CONTENT

        encoder.openElement(ELEM_EQUATESYMBOL)
        self.encodeHeader(encoder)
        encoder.openElement(ELEM_VALUE)
        encoder.writeUnsignedInteger(ATTRIB_CONTENT, self.value)
        encoder.closeElement(ELEM_VALUE)
        encoder.closeElement(ELEM_EQUATESYMBOL)

    def decode(self, decoder) -> None:
        """Decode an EquateSymbol from a stream.

        C++ ref: ``EquateSymbol::decode``
        """
        from ghidra.core.marshal import ELEM_EQUATESYMBOL, ELEM_VALUE, ATTRIB_CONTENT
        from ghidra.types.datatype import TYPE_UNKNOWN

        elemId = decoder.openElement(ELEM_EQUATESYMBOL)
        self.decodeHeader(decoder)
        subId = decoder.openElement(ELEM_VALUE)
        self.value = decoder.readUnsignedInteger(ATTRIB_CONTENT)
        decoder.closeElement(subId)
        self.type = self.scope.getArch().types.getBase(1, TYPE_UNKNOWN)
        decoder.closeElement(elemId)

    def setValue(self, val: int) -> None:
        self.value = val


# =========================================================================
# LabSymbol
# =========================================================================

class LabSymbol(Symbol):
    """A Symbol that labels code internal to a function."""

    def __init__(self, scope: Optional[Scope] = None, name: str = "") -> None:
        super().__init__(scope, name)
        self._buildType()

    def _buildType(self) -> None:
        from ghidra.types.datatype import TYPE_UNKNOWN

        self.type = self.scope.getArch().types.getBase(1, TYPE_UNKNOWN)

    def getType(self):
        return self.type

    def encode(self, encoder) -> None:
        """Encode a LabSymbol to a stream.

        C++ ref: ``LabSymbol::encode``
        """
        from ghidra.core.marshal import ELEM_LABELSYM

        encoder.openElement(ELEM_LABELSYM)
        self.encodeHeader(encoder)
        encoder.closeElement(ELEM_LABELSYM)

    def decode(self, decoder) -> None:
        """Decode a LabSymbol from a stream.

        C++ ref: ``LabSymbol::decode``
        """
        from ghidra.core.marshal import ELEM_LABELSYM
        elemId = decoder.openElement(ELEM_LABELSYM)
        self.decodeHeader(decoder)
        decoder.closeElement(elemId)


# =========================================================================
# ExternRefSymbol
# =========================================================================

class ExternRefSymbol(Symbol):
    """A function Symbol referring to an external location."""

    def __init__(self, scope: Optional[Scope] = None,
                 ref: Optional[Address] = None, name: str = "") -> None:
        super().__init__(scope, name)
        self.refaddr: Address = ref if ref is not None else Address()
        if ref is not None:
            self._buildNameType()

    def getRefAddr(self) -> Address:
        return self.refaddr

    def setRefAddr(self, addr: Address) -> None:
        self.refaddr = addr

    def _buildNameType(self) -> None:
        typegrp = self.scope.getArch().types
        codetype = typegrp.getTypeCode()
        word_size = self.refaddr.getSpace().getWordSize()
        self.type = typegrp.getTypePointer(self.refaddr.getAddrSize(), codetype, word_size)
        if self.name == "":
            self.name = f"{self.refaddr.getShortcut()}{self.refaddr.printRaw()}_exref"
        if self.displayName == "":
            self.displayName = self.name
        self.flags |= Varnode.externref | Varnode.typelock

    def encode(self, encoder) -> None:
        """Encode an ExternRefSymbol to a stream.

        C++ ref: ``ExternRefSymbol::encode``
        """
        from ghidra.core.marshal import ELEM_EXTERNREFSYMBOL, ATTRIB_NAME

        encoder.openElement(ELEM_EXTERNREFSYMBOL)
        encoder.writeString(ATTRIB_NAME, self.name)
        self.refaddr.encode(encoder)
        encoder.closeElement(ELEM_EXTERNREFSYMBOL)

    def decode(self, decoder) -> None:
        """Decode an ExternRefSymbol from a stream.

        C++ ref: ``ExternRefSymbol::decode``
        """
        from ghidra.core.marshal import ELEM_EXTERNREFSYMBOL, ATTRIB_NAME, ATTRIB_LABEL
        elemId = decoder.openElement(ELEM_EXTERNREFSYMBOL)
        self.name = ""
        self.displayName = ""
        while True:
            attribId = decoder.getNextAttributeId()
            if attribId == 0:
                break
            if attribId == ATTRIB_NAME.id:
                self.name = decoder.readString()
            elif attribId == ATTRIB_LABEL.id:
                self.displayName = decoder.readString()
        self.refaddr = Address.decode(decoder)
        decoder.closeElement(elemId)
        self._buildNameType()


# =========================================================================
# SymbolCompareName
# =========================================================================

class SymbolCompareName:
    """Comparator for ordering Symbol objects by name then dedup id."""

    def __call__(self, sym1: Symbol, sym2: Symbol) -> bool:
        comp = (sym1.name > sym2.name) - (sym1.name < sym2.name)
        if comp < 0:
            return True
        if comp > 0:
            return False
        return sym1.nameDedup < sym2.nameDedup


# =========================================================================
# UnionFacetSymbol
# =========================================================================

class UnionFacetSymbol(Symbol):
    """A Symbol forcing a particular union field at a dynamic access point."""

    def __init__(self, scope: Optional[Scope] = None, name: str = "",
                 unionDt=None, fieldNum: int = -1) -> None:
        super().__init__(scope, name, unionDt)
        self.fieldNum: int = fieldNum
        self.category = Symbol.union_facet

    def getFieldNumber(self) -> int:
        return self.fieldNum

    def encode(self, encoder) -> None:
        from ghidra.core.marshal import ATTRIB_FIELD, ELEM_FACETSYMBOL

        encoder.openElement(ELEM_FACETSYMBOL)
        self.encodeHeader(encoder)
        encoder.writeSignedInteger(ATTRIB_FIELD, self.fieldNum)
        self.encodeBody(encoder)
        encoder.closeElement(ELEM_FACETSYMBOL)

    def decode(self, decoder) -> None:
        from ghidra.core.marshal import ATTRIB_FIELD, ELEM_FACETSYMBOL
        from ghidra.types.datatype import TYPE_PTR, TYPE_UNION

        elemId = decoder.openElement(ELEM_FACETSYMBOL)
        self.decodeHeader(decoder)
        self.fieldNum = decoder.readSignedInteger(ATTRIB_FIELD)
        self.decodeBody(decoder)
        decoder.closeElement(elemId)

        testType = self.type
        if testType is not None and testType.getMetatype() == TYPE_PTR and hasattr(testType, "getPtrTo"):
            testType = testType.getPtrTo()
        if testType is None or testType.getMetatype() != TYPE_UNION:
            raise LowlevelError("<unionfacetsymbol> does not have a union type")
        if self.fieldNum < -1 or self.fieldNum >= testType.numDepend():
            raise LowlevelError("<unionfacetsymbol> field attribute is out of bounds")


# =========================================================================
# MapIterator
# =========================================================================

class MapIterator:
    """Iterate over mapped SymbolEntry objects in native address-space order."""

    def __init__(
        self,
        m: Optional[List[List[SymbolEntry]]] | "MapIterator" = None,
        cm: int = 0,
        ci: int = 0,
    ) -> None:
        if isinstance(m, MapIterator):
            self.map = m.map
            self.curmap = m.curmap
            self.curiter = m.curiter
        else:
            self.map = m
            self.curmap = cm
            self.curiter = ci

    @staticmethod
    def _group_entries_by_space(entries_by_addr: Dict[tuple, List[SymbolEntry]]) -> List[List[SymbolEntry]]:
        grouped: List[List[SymbolEntry]] = []
        current_space = None
        current_group: Optional[List[SymbolEntry]] = None
        for (space_idx, _offset), entries in sorted(entries_by_addr.items()):
            if space_idx != current_space:
                current_space = space_idx
                current_group = []
                grouped.append(current_group)
            current_group.extend(entries)
        return grouped

    @classmethod
    def from_entry_maps(
        cls,
        entries_by_addr: Dict[tuple, List[SymbolEntry]],
        *,
        at_end: bool = False,
    ) -> "MapIterator":
        grouped = cls._group_entries_by_space(entries_by_addr)
        if at_end or not grouped:
            return cls(grouped, len(grouped), 0)
        return cls(grouped, 0, 0)

    def _is_end(self) -> bool:
        return self.map is None or self.curmap >= len(self.map)

    def deref(self) -> SymbolEntry:
        if self.map is None or self._is_end():
            raise LowlevelError("Dereferencing invalid MapIterator")
        return self.map[self.curmap][self.curiter]

    def preincrement(self) -> "MapIterator":
        if self.map is None or self._is_end():
            return self
        self.curiter += 1
        while self.curmap < len(self.map) and self.curiter >= len(self.map[self.curmap]):
            self.curmap += 1
            while self.curmap < len(self.map) and len(self.map[self.curmap]) == 0:
                self.curmap += 1
            if self.curmap < len(self.map):
                self.curiter = 0
        return self

    def postincrement(self, _i: int = 0) -> "MapIterator":
        tmp = MapIterator(self)
        self.preincrement()
        return tmp

    def assign(self, op2: "MapIterator") -> "MapIterator":
        self.map = op2.map
        self.curmap = op2.curmap
        self.curiter = op2.curiter
        return self

    def __eq__(self, op2: object) -> bool:
        if not isinstance(op2, MapIterator):
            return False
        if self.map is None or op2.map is None:
            return self.map is None and op2.map is None and self.curmap == op2.curmap and self.curiter == op2.curiter
        if self.curmap != op2.curmap:
            return False
        if self._is_end():
            return op2._is_end()
        if op2._is_end():
            return False
        return self.map[self.curmap][self.curiter] is op2.map[op2.curmap][op2.curiter]

    def __ne__(self, op2: object) -> bool:
        return not self == op2

    def __iter__(self) -> "MapIterator":
        return self

    def __next__(self) -> SymbolEntry:
        if self._is_end():
            raise StopIteration
        res = self.deref()
        self.preincrement()
        return res


# =========================================================================
# DuplicateFunctionError
# =========================================================================

class DuplicateFunctionError(RecovError):
    """Exception thrown when a function is added more than once."""

    def __init__(self, addr: Address, nm: str) -> None:
        super().__init__("Duplicate Function")
        self.address: Address = addr
        self.functionName: str = nm

    def getAddress(self) -> Address:
        return self.address

    def getFunctionName(self) -> str:
        return self.functionName


# =========================================================================
# Scope (abstract base)
# =========================================================================

class Scope(ABC):
    """A collection of Symbol objects within a single scope.

    Supports search by name, by storage address, insertion/removal
    of Symbols, and management of child scopes.
    """

    def __init__(self, id_: int = 0, name: str = "",
                 glb=None, fd=None, owner=None) -> None:
        self.uniqueId: int = id_
        self.name: str = name
        self.displayName: str = name
        self.glb = glb  # Architecture
        self.fd = fd    # Funcdata
        self.parent: Optional[Scope] = None
        self.owner: Optional[Scope] = owner
        self.children: Dict[int, Scope] = {}
        self.rangetree: RangeList = RangeList()
        self.debugon: bool = False

    def __del__(self) -> None:
        self.children.clear()

    def getName(self) -> str:
        return self.name

    def getDisplayName(self) -> str:
        return self.displayName

    def setDisplayName(self, nm: str) -> None:
        self.displayName = nm

    def getId(self) -> int:
        return self.uniqueId

    def getParent(self) -> Optional[Scope]:
        return self.parent

    def getFuncdata(self):
        return self.fd

    def getArch(self):
        return self.glb

    def numChildren(self) -> int:
        return len(self.children)

    def getChild(self, id_: int) -> Optional[Scope]:
        return self.children.get(id_)

    def attachScope(self, child: Scope) -> None:
        child.parent = self
        self.children[child.uniqueId] = child

    @staticmethod
    def hashScopeName(baseId: int, nm: str) -> int:
        reg1 = (baseId >> 32) & 0xFFFFFFFF
        reg2 = baseId & 0xFFFFFFFF
        reg1 = crc_update(reg1, 0xA9) & 0xFFFFFFFF
        reg2 = crc_update(reg2, reg1) & 0xFFFFFFFF
        for ch in nm:
            val = ord(ch) & 0xFF
            reg1 = crc_update(reg1, val) & 0xFFFFFFFF
            reg2 = crc_update(reg2, reg1) & 0xFFFFFFFF
        return ((reg1 << 32) | reg2) & 0xFFFFFFFFFFFFFFFF

    def detachScope(self, child_id: int) -> None:
        del self.children[child_id]

    @staticmethod
    def stackAddr(scope1: Optional["Scope"], scope2: Optional["Scope"],
                  addr: Address, usepoint: Address) -> Tuple[Optional["Scope"], Optional[SymbolEntry]]:
        if addr.isConstant():
            return None, None
        while scope1 is not None and scope1 is not scope2:
            entry = scope1.findAddr(addr, usepoint)
            if entry is not None:
                return scope1, entry
            if scope1.inScope(addr, 1, usepoint):
                return scope1, None
            scope1 = scope1.getParent()
        return None, None

    @staticmethod
    def stackContainer(scope1: Optional["Scope"], scope2: Optional["Scope"],
                       addr: Address, size: int,
                       usepoint: Address) -> Tuple[Optional["Scope"], Optional[SymbolEntry]]:
        if addr.isConstant():
            return None, None
        while scope1 is not None and scope1 is not scope2:
            entry = scope1.findContainer(addr, size, usepoint)
            if entry is not None:
                return scope1, entry
            if scope1.inScope(addr, size, usepoint):
                return scope1, None
            scope1 = scope1.getParent()
        return None, None

    @staticmethod
    def stackClosestFit(scope1: Optional["Scope"], scope2: Optional["Scope"],
                        addr: Address, size: int,
                        usepoint: Address) -> Tuple[Optional["Scope"], Optional[SymbolEntry]]:
        if addr.isConstant():
            return None, None
        while scope1 is not None and scope1 is not scope2:
            entry = scope1.findClosestFit(addr, size, usepoint)
            if entry is not None:
                return scope1, entry
            if scope1.inScope(addr, size, usepoint):
                return scope1, None
            scope1 = scope1.getParent()
        return None, None

    @staticmethod
    def stackFunction(scope1: Optional["Scope"], scope2: Optional["Scope"],
                      addr: Address) -> Tuple[Optional["Scope"], object]:
        if addr.isConstant():
            return None, None
        while scope1 is not None and scope1 is not scope2:
            fd = scope1.findFunction(addr)
            if fd is not None:
                return scope1, fd
            if scope1.inScope(addr, 1, Address()):
                return scope1, None
            scope1 = scope1.getParent()
        return None, None

    @staticmethod
    def stackExternalRef(scope1: Optional["Scope"], scope2: Optional["Scope"],
                         addr: Address) -> Tuple[Optional["Scope"], Optional[ExternRefSymbol]]:
        if addr.isConstant():
            return None, None
        while scope1 is not None and scope1 is not scope2:
            sym = scope1.findExternalRef(addr)
            if sym is not None:
                return scope1, sym
            scope1 = scope1.getParent()
        return None, None

    @staticmethod
    def stackCodeLabel(scope1: Optional["Scope"], scope2: Optional["Scope"],
                       addr: Address) -> Tuple[Optional["Scope"], Optional[LabSymbol]]:
        if addr.isConstant():
            return None, None
        while scope1 is not None and scope1 is not scope2:
            sym = scope1.findCodeLabel(addr)
            if sym is not None:
                return scope1, sym
            if scope1.inScope(addr, 1, Address()):
                return scope1, None
            scope1 = scope1.getParent()
        return None, None

    def resolveScope(self, nm: str, strategy: bool) -> Optional["Scope"]:
        import re

        if strategy:
            key = Scope.hashScopeName(self.uniqueId, nm)
            scope = self.children.get(key)
            if scope is not None and scope.name == nm:
                return scope
            return None
        if nm and "0" <= nm[0] <= "9":
            match = re.match(r"0[xX][0-9a-fA-F]+|[0-9]+", nm)
            if match is None:
                return None
            key = int(match.group(0), 0)
            return self.children.get(key)
        for _, scope in sorted(self.children.items()):
            if scope.name == nm:
                return scope
        return None

    # --- Abstract methods ---

    def addSymbol(self, sym_or_name, ct=None, addr=None, usepoint=None):
        """Add a pre-built Symbol, or create one and map it in a single step.

        C++ ref: ``Scope::addSymbol(const string &,Datatype *)`` and
        ``Scope::addSymbol(const string &,Datatype *,const Address &,const Address &)``.
        Python keeps the existing single-argument convenience form for pre-built Symbols.
        """
        add_direct = getattr(self, "_addSymbolDirect", None)

        if isinstance(sym_or_name, Symbol):
            if callable(add_direct):
                add_direct(sym_or_name)
            else:
                self.addSymbolInternal(sym_or_name)
            return None

        owner = self.owner if self.owner is not None else self
        if addr is None and usepoint is None:
            sym = Symbol(owner, sym_or_name, ct)
            if callable(add_direct):
                add_direct(sym)
            else:
                self.addSymbolInternal(sym)
            return sym

        if ct is not None and hasattr(ct, "hasStripped") and ct.hasStripped():
            ct = ct.getStripped()
        sym = Symbol(owner, sym_or_name, ct)
        if callable(add_direct):
            add_direct(sym)
        else:
            self.addSymbolInternal(sym)
        return self.addMapPoint(sym, addr, usepoint)

    @abstractmethod
    def removeSymbol(self, sym: Symbol) -> None:
        ...

    @abstractmethod
    def findByName(self, name: str, res=None) -> Optional[Symbol]:
        ...

    @abstractmethod
    def findAddr(self, addr: Address, usepoint: Address) -> Optional[SymbolEntry]:
        ...

    @abstractmethod
    def findContainer(self, addr: Address, size: int,
                      usepoint: Address) -> Optional[SymbolEntry]:
        ...

    @abstractmethod
    def addMapEntry(self, sym: Symbol, entry: SymbolEntry) -> SymbolEntry:
        ...

    @abstractmethod
    def buildSubScope(self, id_: int, nm: str) -> "Scope":
        ...

    @abstractmethod
    def addSymbolInternal(self, sym: Symbol) -> None:
        ...

    @abstractmethod
    def addMapInternal(self, sym: Symbol, exfl: int, addr: Address,
                       off: int, sz: int, uselim: RangeList) -> SymbolEntry:
        ...

    @abstractmethod
    def addDynamicMapInternal(self, sym: Symbol, exfl: int, hash_: int,
                              off: int, sz: int, uselim: RangeList) -> SymbolEntry:
        ...

    def restrictScope(self, fd) -> None:
        """Associate this scope with a specific function.

        C++ ref: ``Scope::restrictScope``
        """
        self.fd = fd

    def addRange(self, spc, first: int, last: int) -> None:
        """Add an address range to this scope's ownership.

        C++ ref: ``Scope::addRange``
        """
        self.rangetree.insertRange(spc, first, last)

    def removeRange(self, spc, first: int, last: int) -> None:
        """Remove an address range from this scope's ownership.

        C++ ref: ``Scope::removeRange``
        """
        self.rangetree.removeRange(spc, first, last)

    def isGlobal(self) -> bool:
        return self.fd is None

    def setOwner(self, owner) -> None:
        self.owner = owner

    def getOwner(self):
        return self.owner

    def getRangeTree(self) -> RangeList:
        return self.rangetree

    # --- Query methods (virtual in C++) ---

    def queryByName(self, name: str, res=None) -> Optional[Symbol]:
        if res is None:
            compat = []
            self.queryByName(name, compat)
            return compat[0] if compat else None
        self.findByName(name, res)
        if res:
            return None
        if self.parent is not None:
            self.parent.queryByName(name, res)
        return None

    def queryByAddr(self, addr: Address, usepoint: Address) -> Optional[SymbolEntry]:
        up = usepoint if usepoint else Address()
        basescope = self._mapQueryScope(addr, up)
        _, entry = Scope.stackAddr(basescope, None, addr, up)
        return entry

    def queryContainer(self, addr: Address, size: int, usepoint: Address) -> Optional[SymbolEntry]:
        up = usepoint if usepoint else Address()
        basescope = self._mapQueryScope(addr, up)
        _, entry = self._stackContainer(basescope, None, addr, size, up)
        return entry

    def queryFunction(self, name_or_addr) -> Optional[FunctionSymbol]:
        """Find a function by name or starting address.

        C++ ref: ``Scope::queryFunction`` in database.cc
        """
        if isinstance(name_or_addr, str):
            sym_list = []
            self.queryByName(name_or_addr, sym_list)
            for sym in sym_list:
                if isinstance(sym, FunctionSymbol):
                    return sym.getFunction()
            return None

        basescope = self._mapQueryScope(name_or_addr, Address())
        _, res = Scope.stackFunction(basescope, None, name_or_addr)
        return res

    def queryExternalRefFunction(self, addr: Address):
        """Find a function via an external reference at the given address."""
        basescope = self._mapQueryScope(addr, Address())
        foundscope, sym = Scope.stackExternalRef(basescope, None, addr)
        if sym is not None and foundscope is not None:
            return foundscope.resolveExternalRefFunction(sym)
        return None

    def queryCodeLabel(self, addr: Address) -> Optional[LabSymbol]:
        """Find a code label at the given address.

        C++ ref: ``Scope::queryCodeLabel`` in database.cc
        """
        basescope = self._mapQueryScope(addr, Address())
        _, res = Scope.stackCodeLabel(basescope, None, addr)
        return res

    def _mapQueryScope(self, addr: Address, usepoint: Address) -> 'Scope':
        db = getattr(getattr(self, 'glb', None), 'symboltab', None)
        if db is not None and hasattr(db, 'mapScope'):
            basescope = db.mapScope(self, addr, usepoint)
            if basescope is not None:
                return basescope
        return self

    def _stackContainer(self, scope1: Optional['Scope'], scope2: Optional['Scope'],
                        addr: Address, size: int, usepoint: Address):
        return Scope.stackContainer(scope1, scope2, addr, size, usepoint)

    def queryProperties(self, addr: Address, size: int, usepoint, flags_ref):
        """Query boolean properties of a memory range (base Scope implementation).

        C++ ref: ``Scope::queryProperties`` in database.cc
        Returns the SymbolEntry if found, else None.
        """
        from ghidra.ir.varnode import Varnode
        up = usepoint if usepoint else Address()
        basescope = self._mapQueryScope(addr, up)
        finalscope, entry = self._stackContainer(basescope, None, addr, size, up)
        db = getattr(getattr(self, 'glb', None), 'symboltab', None)
        if entry is not None:
            flags = entry.getAllFlags()
        elif finalscope is not None:
            flags = Varnode.mapped | Varnode.addrtied
            if finalscope.isGlobal():
                flags |= Varnode.persist
            if db is not None and hasattr(db, 'getProperty'):
                flags |= db.getProperty(addr)
        else:
            flags = db.getProperty(addr) if db is not None and hasattr(db, 'getProperty') else 0
        if isinstance(flags_ref, list) and flags_ref:
            flags_ref[0] = flags
        return entry

    # --- Symbol creation methods ---

    def addFunction(self, addr: Address, name: str) -> Optional[FunctionSymbol]:
        return None

    def addEquateSymbol(self, name: str, format_: int, val: int, addr: Address, hash_: int) -> Optional[EquateSymbol]:
        return None

    def addCodeLabel(self, addr: Address, name: str) -> Optional[LabSymbol]:
        return None

    def addDynamicSymbol(self, name: str, ct, addr: Address, hash_: int) -> Optional[Symbol]:
        return None

    def addExternalRef(self, addr: Address, refaddr: Address, name: str) -> Optional[ExternRefSymbol]:
        return None

    def addUnionFacetSymbol(self, name: str, ct, fieldNum: int, addr: Address, hash_: int) -> Optional[Symbol]:
        return None

    def addMapPoint(self, sym: Symbol, addr: Address, usepoint: Address) -> Optional[SymbolEntry]:
        return None

    def addMap(self, entry: SymbolEntry) -> SymbolEntry:
        if self.isGlobal():
            entry.symbol.flags |= Varnode.persist
        elif not entry.addr.isInvalid():
            db = getattr(getattr(self, "glb", None), "symboltab", None)
            glb_scope = db.getGlobalScope() if db is not None and hasattr(db, "getGlobalScope") else None
            if glb_scope is not None and glb_scope.inScope(entry.addr, 1, Address()):
                entry.symbol.flags |= Varnode.persist
                entry.uselimit.clear()

        consume_size = entry.symbol.getBytesConsumed()
        if entry.addr.isInvalid():
            return self.addDynamicMapInternal(entry.symbol, Varnode.mapped, entry.hash, 0, consume_size, entry.uselimit)

        if entry.uselimit.empty():
            entry.symbol.flags |= Varnode.addrtied
            db = getattr(getattr(self, "glb", None), "symboltab", None)
            if db is not None and hasattr(db, "getProperty"):
                entry.symbol.flags |= db.getProperty(entry.addr)

        res = self.addMapInternal(entry.symbol, Varnode.mapped, entry.addr, 0, consume_size, entry.uselimit)
        if entry.addr.isJoin():
            rec = self.glb.findJoin(entry.addr.getOffset())
            num = rec.numPieces()
            off = 0
            bigendian = entry.addr.isBigEndian()
            for j in range(num):
                i = j if bigendian else (num - 1 - j)
                vdat = rec.getPiece(i)
                if i == 0:
                    exfl = Varnode.precishi
                elif i == num - 1:
                    exfl = Varnode.precislo
                else:
                    exfl = Varnode.precislo | Varnode.precishi
                self.addMapInternal(entry.symbol, exfl, vdat.getAddr(), off, vdat.size, entry.uselimit)
                off += vdat.size
        return res

    def addMapSym(self, decoder) -> Optional[Symbol]:
        """Decode a ``<mapsym>`` element, create the Symbol and its SymbolEntry mappings.

        C++ ref: ``Scope::addMapSym``
        """
        from ghidra.core.marshal import (
            ELEM_MAPSYM, ELEM_SYMBOL, ELEM_EQUATESYMBOL, ELEM_FUNCTION,
            ELEM_FUNCTIONSHELL, ELEM_LABELSYM, ELEM_EXTERNREFSYMBOL,
            ELEM_FACETSYMBOL,
        )
        elemId = decoder.openElement(ELEM_MAPSYM)
        subId = decoder.peekElement()
        owner = self.owner if self.owner is not None else self
        if subId == ELEM_SYMBOL.id:
            sym = Symbol(owner)
        elif subId == ELEM_EQUATESYMBOL.id:
            sym = EquateSymbol(owner)
        elif subId in (ELEM_FUNCTION.id, ELEM_FUNCTIONSHELL.id):
            sym = FunctionSymbol(owner, getattr(self.glb, "min_funcsymbol_size", 1))
        elif subId == ELEM_LABELSYM.id:
            sym = LabSymbol(owner)
        elif subId == ELEM_EXTERNREFSYMBOL.id:
            sym = ExternRefSymbol(owner)
        elif subId == ELEM_FACETSYMBOL.id:
            sym = UnionFacetSymbol(owner)
        else:
            raise LowlevelError("Unknown symbol type")
        try:
            sym.decode(decoder)
        except RecovError:
            raise
        self.addSymbolInternal(sym)
        while decoder.peekElement() != 0:
            entry = SymbolEntry(sym)
            entry.decode(decoder)
            if entry.isInvalid():
                if self.glb is not None and hasattr(self.glb, "printMessage"):
                    self.glb.printMessage("WARNING: Throwing out symbol with invalid mapping: " + sym.getName())
                self.removeSymbol(sym)
                decoder.closeElement(elemId)
                return None
            self.addMap(entry)
        decoder.closeElement(elemId)
        return sym

    # --- Symbol modification ---

    @abstractmethod
    def renameSymbol(self, sym: Symbol, newname: str) -> None:
        ...

    @abstractmethod
    def retypeSymbol(self, sym: Symbol, ct) -> None:
        ...

    @abstractmethod
    def setAttribute(self, sym: Symbol, attr: int) -> None:
        ...

    @abstractmethod
    def clearAttribute(self, sym: Symbol, attr: int) -> None:
        ...

    @abstractmethod
    def setCategory(self, sym: Symbol, cat: int, ind: int) -> None:
        ...

    @abstractmethod
    def setDisplayFormat(self, sym: Symbol, val: int) -> None:
        ...

    def setSymbolId(self, sym: Symbol, id_: int) -> None:
        sym.symbolId = id_

    def setThisPointer(self, sym: Symbol, val: bool) -> None:
        sym.setThisPointer(val)

    def overrideSizeLockType(self, sym: Symbol, ct) -> None:
        """Change the data-type of a size-locked Symbol.

        An exception is thrown if the new data-type doesn't fit the size.

        C++ ref: ``Scope::overrideSizeLockType``
        """
        if sym.type.getSize() == ct.getSize():
            if not sym.isSizeTypeLocked():
                raise LowlevelError("Overriding symbol that is not size locked")
            sym.type = ct
            return
        raise LowlevelError("Overriding symbol with different type size")

    def resetSizeLockType(self, sym: Symbol) -> None:
        """Reset a size-locked Symbol's data-type back to UNKNOWN.

        The lock is preserved but the data-type is cleared.

        C++ ref: ``Scope::resetSizeLockType``
        """
        from ghidra.types.datatype import MetaType
        if sym.type.getMetatype() == MetaType.TYPE_UNKNOWN:
            return
        size = sym.type.getSize()
        sym.type = self.glb.types.getBase(size, MetaType.TYPE_UNKNOWN)

    @abstractmethod
    def removeSymbolMappings(self, sym: Symbol) -> None:
        ...

    # --- Scope query/search ---

    @abstractmethod
    def findOverlap(self, addr: Address, size: int) -> Optional[SymbolEntry]:
        ...

    def findClosestFit(self, addr: Address, size: int, usepoint: Address) -> Optional[SymbolEntry]:
        """Find the SymbolEntry whose size most closely matches the given range.

        C++ ref: ``ScopeInternal::findClosestFit``
        The entry must contain the start address. Prefer entries whose size
        is closest to the requested size (exact match preferred, then smallest
        larger, then largest smaller).
        """
        bestentry = None
        olddiff = -10000
        for entries_list in self._entriesByAddr.values():
            for entry in entries_list:
                if entry.addr.getSpace() is not addr.getSpace():
                    continue
                if entry.isDynamic():
                    continue
                if entry.getLast() < addr.getOffset():
                    continue
                if entry.getFirst() > addr.getOffset():
                    continue
                newdiff = entry.getSize() - size
                if (olddiff < 0 and newdiff > olddiff) or \
                   (olddiff >= 0 and newdiff >= 0 and newdiff < olddiff):
                    if entry.inUse(usepoint):
                        bestentry = entry
                        if newdiff == 0:
                            return bestentry
                        olddiff = newdiff
        return bestentry

    def findFunction(self, addr: Address) -> Optional[FunctionSymbol]:
        """Find a FunctionSymbol at the given address.

        C++ ref: ``ScopeInternal::findFunction`` in database.cc
        """
        entry = self.findAddr(addr, Address())
        if entry is not None:
            sym = entry.getSymbol()
            if isinstance(sym, FunctionSymbol):
                return sym
        return None

    def findExternalRef(self, addr: Address) -> Optional[ExternRefSymbol]:
        """Find an ExternRefSymbol at the given address.

        C++ ref: ``ScopeInternal::findExternalRef`` in database.cc
        """
        entry = self.findAddr(addr, Address())
        if entry is not None:
            sym = entry.getSymbol()
            if isinstance(sym, ExternRefSymbol):
                return sym
        return None

    def findCodeLabel(self, addr: Address) -> Optional[LabSymbol]:
        """Find a LabSymbol at the given address.

        C++ ref: ``ScopeInternal::findCodeLabel`` in database.cc
        """
        entry = self.findAddr(addr, Address())
        if entry is not None:
            sym = entry.getSymbol()
            if isinstance(sym, LabSymbol):
                return sym
        return None

    def findDistinguishingScope(self, op2: 'Scope') -> Optional['Scope']:
        """Find the first ancestor Scope not in common with *op2*.

        C++ ref: ``Scope::findDistinguishingScope``
        """
        if self is op2:
            return None
        if self.parent is op2:
            return self
        if op2.parent is self:
            return None
        if self.parent is op2.parent:
            return self
        thisPath = self.getScopePath()
        op2Path = op2.getScopePath()
        minLen = min(len(thisPath), len(op2Path))
        for i in range(minLen):
            if thisPath[i] is not op2Path[i]:
                return thisPath[i]
        if minLen < len(thisPath):
            return thisPath[minLen]
        if minLen < len(op2Path):
            return None
        return self

    # --- Scope hierarchy ---

    def isSubScope(self, other: 'Scope') -> bool:
        cur = self
        while cur is not None:
            if cur is other:
                return True
            cur = cur.parent
        return False

    def discoverScope(self, addr: Address, sz: int, usepoint: Address) -> Optional['Scope']:
        if addr.isConstant():
            return None
        basescope = self._mapQueryScope(addr, usepoint)
        while basescope is not None:
            if basescope.inScope(addr, sz, usepoint):
                return basescope
            basescope = basescope.getParent()
        return None

    def getFullName(self) -> str:
        """Get the full path name of this Scope.

        C++ ref: ``Scope::getFullName``
        """
        if self.parent is None:
            return ""
        fname = self.name
        scope = self.parent
        while scope is not None and scope.parent is not None:
            fname = scope.name + "::" + fname
            scope = scope.parent
        return fname

    def getScopePath(self) -> List['Scope']:
        parts = []
        cur = self
        while cur is not None:
            parts.append(cur)
            cur = cur.parent
        parts.reverse()
        return parts

    # --- Iterators ---

    @abstractmethod
    def begin(self):
        ...

    @abstractmethod
    def end(self):
        ...

    @abstractmethod
    def beginDynamic(self):
        ...

    @abstractmethod
    def endDynamic(self):
        ...

    def childrenBegin(self):
        return (scope for _, scope in sorted(self.children.items()))

    def childrenEnd(self):
        return iter(())

    # --- Scope-level operations ---

    @abstractmethod
    def clear(self) -> None:
        ...

    @abstractmethod
    def clearUnlocked(self) -> None:
        ...

    @abstractmethod
    def clearUnlockedCategory(self, cat: int) -> None:
        ...

    @abstractmethod
    def clearCategory(self, cat: int) -> None:
        ...

    @abstractmethod
    def adjustCaches(self) -> None:
        ...

    @abstractmethod
    def getCategorySize(self, cat: int) -> int:
        ...

    @abstractmethod
    def getCategorySymbol(self, cat: int, index: int) -> Optional[Symbol]:
        ...

    # --- Encode / Decode ---

    @abstractmethod
    def encode(self, encoder) -> None:
        ...

    @abstractmethod
    def decode(self, decoder) -> None:
        ...

    def encodeRecursive(self, encoder, onlyGlobal: bool = False) -> None:
        if onlyGlobal and not self.isGlobal():
            return
        self.encode(encoder)
        for child in self.childrenBegin():
            child.encodeRecursive(encoder, onlyGlobal)

    def decodeWrappingAttributes(self, decoder) -> None:
        pass

    # --- Misc ---

    def inScope(self, addr: Address, size: int, usepoint: Address) -> bool:
        return self.rangetree.inRange(addr, size)

    def inRange(self, addr: Address, size: int) -> bool:
        """Check if the given address range is owned by this Scope."""
        return self.rangetree.inRange(addr, size)

    def isNameUsed(self, name: str, scope: Optional['Scope'] = None) -> bool:
        if self.findByName(name) is not None:
            return True
        par = self.getParent()
        if par is None or par is scope:
            return False
        if par.getParent() is None:
            return False
        return par.isNameUsed(name, scope)

    @abstractmethod
    def resolveExternalRefFunction(self, sym: ExternRefSymbol) -> Optional[Funcdata]:
        ...

    def _findFirstByName(self, name: str) -> Optional[Symbol]:
        """Check if a symbol with the given name exists. Returns it or None."""
        return self.findByName(name)

    @abstractmethod
    def makeNameUnique(self, name: str) -> str:
        ...

    def buildDefaultName(self, sym, base: int, vn=None) -> str:
        """Create a default name for the given Symbol.

        C++ ref: ``Scope::buildDefaultName`` in database.cc
        """
        from ghidra.ir.varnode import Varnode as VN
        if vn is not None and not vn.isConstant():
            usepoint = Address()
            if not (hasattr(vn, 'isAddrTied') and vn.isAddrTied()) and self.fd is not None:
                usepoint = vn.getUsePoint(self.fd) if hasattr(vn, 'getUsePoint') else Address()
            high = vn.getHigh() if hasattr(vn, 'getHigh') else None
            if sym.getCategory() == Symbol.function_parameter or (high is not None and high.isInput()):
                index = -1
                if sym.getCategory() == Symbol.function_parameter:
                    index = sym.getCategoryIndex() + 1
                return self.buildVariableName(vn.getAddr(), usepoint, sym.getType(), index, vn.getFlags() | VN.input)
            return self.buildVariableName(vn.getAddr(), usepoint, sym.getType(), base, vn.getFlags())
        if hasattr(sym, 'mapentry') and sym.mapentry:
            entry = sym.mapentry[0]
            addr = entry.getAddr()
            usepoint = entry.getFirstUseAddress() if hasattr(entry, 'getFirstUseAddress') else Address()
            is_invalid = usepoint.isInvalid() if hasattr(usepoint, 'isInvalid') else True
            flags = VN.addrtied if is_invalid else 0
            if sym.getCategory() == Symbol.function_parameter:
                flags |= VN.input
                index = sym.getCategoryIndex() + 1
                return self.buildVariableName(addr, usepoint, sym.getType(), index, flags)
            return self.buildVariableName(addr, usepoint, sym.getType(), base, flags)
        return self.buildVariableName(Address(), Address(), sym.getType(), base, 0)

    def isReadOnly(self, addr: Address, size: int, usepoint: Address) -> bool:
        flags = [0]
        self.queryProperties(addr, size, usepoint, flags)
        return (flags[0] & Varnode.readonly) != 0

    @abstractmethod
    def buildUndefinedName(self) -> str:
        ...

    def _buildVariableNameImpl(self, addr: Address, pc: Address, ct, index: int, flags: int) -> str:
        """Build a variable name from address and flags.

        C++ ref: ``ScopeInternal::buildVariableName`` in database.cc
        """
        from ghidra.ir.varnode import Varnode as VN
        from ghidra.core.address import AddrSpace
        sz = 1 if ct is None else ct.getSize()

        def _regname() -> str:
            if self.glb is not None and hasattr(self.glb, 'translate') and self.glb.translate is not None:
                nm = self.glb.translate.getRegisterName(
                    addr.getSpace(), addr.getOffset(), sz
                ) if hasattr(self.glb.translate, 'getRegisterName') else ""
                return nm if nm else ""
            return ""

        if (flags & VN.unaffected) != 0:
            if (flags & VN.return_address) != 0:
                return self.makeNameUnique("unaff_retaddr")
            rn = _regname()
            if rn:
                return self.makeNameUnique(f"unaff_{rn}")
            return self.makeNameUnique(f"unaff_{addr.getOffset():08x}")

        if (flags & VN.persist) != 0:
            rn = _regname()
            if rn:
                return self.makeNameUnique(rn)
            s = ""
            if ct is not None and hasattr(ct, 'printNameBase'):
                buf = []
                ct.printNameBase(buf)
                s += "".join(buf)
            spacename = addr.getSpace().getName() if addr.getSpace() is not None else "mem"
            spacename = spacename[0].upper() + spacename[1:]
            s += spacename
            addrSize = addr.getAddrSize() if hasattr(addr, 'getAddrSize') else 4
            wordSize = addr.getSpace().getWordSize() if addr.getSpace() is not None and hasattr(addr.getSpace(), 'getWordSize') else 1
            off = AddrSpace.byteToAddress(addr.getOffset(), wordSize)
            s += f"{off:0{2*addrSize}x}"
            return self.makeNameUnique(s)

        if (flags & VN.input) != 0 and index < 0:
            rn = _regname()
            if rn:
                return self.makeNameUnique(f"in_{rn}")
            sn = addr.getSpace().getName() if addr.getSpace() is not None else "mem"
            return self.makeNameUnique(f"in_{sn}_{addr.getOffset():08x}")

        if (flags & VN.input) != 0:
            return self.makeNameUnique(f"param_{index}")

        if (flags & VN.addrtied) != 0:
            s = ""
            if ct is not None and hasattr(ct, 'printNameBase'):
                buf = []
                ct.printNameBase(buf)
                s += "".join(buf)
            spacename = addr.getSpace().getName() if addr.getSpace() is not None else "mem"
            spacename = spacename[0].upper() + spacename[1:]
            s += spacename
            addrSize = addr.getAddrSize() if hasattr(addr, 'getAddrSize') else 4
            wordSize = addr.getSpace().getWordSize() if addr.getSpace() is not None and hasattr(addr.getSpace(), 'getWordSize') else 1
            off = AddrSpace.byteToAddress(addr.getOffset(), wordSize)
            s += f"{off:0{2*addrSize}x}"
            return self.makeNameUnique(s)

        if (flags & VN.indirect_creation) != 0:
            rn = _regname()
            if rn:
                return self.makeNameUnique(f"extraout_{rn}")
            return self.makeNameUnique("extraout_var")

        # Local variable — printNameBase(list) appends a prefix character
        def _namebase(ct):
            buf = []
            if ct is not None and hasattr(ct, 'printNameBase'):
                ct.printNameBase(buf)
            return "".join(buf)

        s = _namebase(ct) + f"Var{index}"
        index += 1
        if self._findFirstByName(s) is not None:
            for _ in range(10):
                s2 = _namebase(ct) + f"Var{index}"
                index += 1
                if self._findFirstByName(s2) is None:
                    return s2
        return self.makeNameUnique(s)

    @abstractmethod
    def buildVariableName(self, addr: Address, pc: Address, ct, index: int, flags: int) -> str:
        ...

    def printBounds(self, s) -> None:
        self.rangetree.printBounds(s)

    @abstractmethod
    def printEntries(self, s) -> None:
        ...

    def turnOnDebug(self) -> None:
        self.debugon = True

    def turnOffDebug(self) -> None:
        self.debugon = False

    def __repr__(self) -> str:
        return f"Scope({self.name!r}, id={self.uniqueId:#x})"


# =========================================================================
# ScopeInternal - in-memory Scope implementation
# =========================================================================

class ScopeInternal(Scope):
    """An in-memory implementation of a Scope.

    Stores symbols in dictionaries for quick lookup by name and address.
    """

    def __init__(self, id_: int = 0, name: str = "",
                 glb=None, fd=None, owner=None) -> None:
        super().__init__(id_, name, glb, fd, owner)
        if self.owner is None:
            self.owner = self
        self._symbolsByName: Dict[str, List[Symbol]] = {}
        self._symbolsById: Dict[int, Symbol] = {}
        self._entriesByAddr: Dict[tuple, List[SymbolEntry]] = {}  # (space_idx, offset) -> entries
        self.dynamicentry: List[SymbolEntry] = []
        self._nextSymId: int = 0
        self._categoryMap: Dict[int, List[Optional[Symbol]]] = {}

    def __del__(self) -> None:
        if hasattr(self, "_symbolsById"):
            self.clear()
        super().__del__()

    def buildSubScope(self, id_: int, nm: str) -> Scope:
        return ScopeInternal(id_, nm, self.glb)

    def decodeHole(self, decoder) -> None:
        """Parse a ``<hole>`` element and apply its boolean properties."""
        from ghidra.core.address import Range
        from ghidra.core.marshal import ATTRIB_READONLY, ATTRIB_VOLATILE, ELEM_HOLE

        elem_id = decoder.openElement(ELEM_HOLE)
        flags = 0
        rng = Range()
        rng.decodeFromAttributes(decoder)
        decoder.rewindAttributes()
        while True:
            attrib_id = decoder.getNextAttributeId()
            if attrib_id == 0:
                break
            if attrib_id == ATTRIB_READONLY.id and decoder.readBool():
                flags |= Varnode.readonly
            elif attrib_id == ATTRIB_VOLATILE.id and decoder.readBool():
                flags |= Varnode.volatil
        if flags != 0:
            self.glb.symboltab.setPropertyRange(flags, rng)
        decoder.closeElement(elem_id)

    def decodeCollision(self, decoder) -> None:
        """Parse a ``<collision>`` element as an unmapped placeholder symbol."""
        from ghidra.core.marshal import ATTRIB_NAME, ELEM_COLLISION
        from ghidra.types.datatype import TYPE_INT

        elem_id = decoder.openElement(ELEM_COLLISION)
        nm = decoder.readString(ATTRIB_NAME)
        decoder.closeElement(elem_id)
        if self.findFirstByName(nm) is None:
            ct = self.glb.types.getBase(1, TYPE_INT)
            self.addSymbol(nm, ct)

    def categorySanity(self) -> None:
        """Clear any category containing holes, matching the native sanity pass."""
        for cat in list(self._categoryMap.keys()):
            symlist = self._categoryMap[cat]
            if not symlist:
                continue
            if any(sym is None for sym in symlist):
                for sym in list(symlist):
                    if sym is None:
                        continue
                    self.setCategory(sym, Symbol.no_category, 0)

    def _assignSymbolId(self, sym: Symbol) -> None:
        if sym.symbolId == 0:
            sym.symbolId = Symbol.ID_BASE + ((self.uniqueId & 0xFFFF) << 40) + self._nextSymId
            self._nextSymId += 1

    def addSymbol(self, sym_or_name, ct=None, addr=None, usepoint=None):
        return Scope.addSymbol(self, sym_or_name, ct, addr, usepoint)

    def insertNameTree(self, sym: Symbol) -> None:
        sym.nameDedup = 0
        symlist = self._symbolsByName.setdefault(sym.name, [])
        if symlist:
            sym.nameDedup = symlist[-1].nameDedup + 1
            if any(existing.nameDedup == sym.nameDedup for existing in symlist):
                raise LowlevelError("Could  not deduplicate symbol: " + sym.name)
        symlist.append(sym)

    def findFirstByName(self, nm: str) -> Optional[Symbol]:
        symlist = self._symbolsByName.get(nm)
        if not symlist:
            return None
        return symlist[0]

    def addSymbolInternal(self, sym: Symbol) -> None:
        """Register a Symbol in all index structures.

        C++ ref: ``ScopeInternal::addSymbolInternal``
        """
        self._assignSymbolId(sym)
        if not sym.name:
            sym.name = self.buildUndefinedName()
            sym.displayName = sym.name
        if sym.getType() is None:
            raise LowlevelError(sym.getName() + " symbol created with no type")
        if sym.getType().getSize() < 1:
            raise LowlevelError(sym.getName() + " symbol created with zero size type")
        sym.scope = self
        self._symbolsById[sym.symbolId] = sym
        self.insertNameTree(sym)
        if sym.category >= 0:
            if sym.category not in self._categoryMap:
                self._categoryMap[sym.category] = []
            lst = self._categoryMap[sym.category]
            if sym.category > 0:
                sym.catindex = len(lst)
            while len(lst) <= sym.catindex:
                lst.append(None)
            lst[sym.catindex] = sym

    def _addSymbolDirect(self, sym: Symbol) -> None:
        ScopeInternal.addSymbolInternal(self, sym)

    def removeSymbolMappings(self, sym: Symbol) -> None:
        for entry in list(sym.mapentry):
            if entry.isDynamic():
                try:
                    self.dynamicentry.remove(entry)
                except ValueError:
                    pass
                continue
            key = (entry.addr.getSpace().getIndex(), entry.addr.getOffset())
            elst = self._entriesByAddr.get(key)
            if elst is None:
                continue
            try:
                elst.remove(entry)
            except ValueError:
                pass
            if not elst:
                self._entriesByAddr.pop(key, None)
        sym.wholeCount = 0
        sym.mapentry.clear()

    def removeSymbol(self, sym: Symbol) -> None:
        _remove_symbol_debug_log(sym)
        if sym.category >= 0:
            lst = self._categoryMap.get(sym.category)
            if lst is not None and 0 <= sym.catindex < len(lst):
                lst[sym.catindex] = None
                while lst and lst[-1] is None:
                    lst.pop()
        self._symbolsById.pop(sym.symbolId, None)
        lst = self._symbolsByName.get(sym.name)
        if lst:
            try:
                lst.remove(sym)
            except ValueError:
                pass
            if not lst:
                self._symbolsByName.pop(sym.name, None)
        ScopeInternal.removeSymbolMappings(self, sym)

    def findByName(self, name: str, res=None) -> Optional[Symbol]:
        lst = self._symbolsByName.get(name)
        if res is not None:
            if lst:
                res.extend(lst)
            return None
        if lst:
            return lst[0]
        return None

    def findById(self, id_: int) -> Optional[Symbol]:
        return self._symbolsById.get(id_)

    @staticmethod
    def _entry_subsort_key(entry: SymbolEntry) -> Tuple[int, int]:
        try:
            subsort = entry.getSubsort()
            return (subsort.useindex, subsort.useoffset)
        except LowlevelError:
            return (0, 0)

    def _entries_at_address(self, addr: Address) -> List[SymbolEntry]:
        entries = self._entriesByAddr.get((addr.getSpace().getIndex(), addr.getOffset()))
        if not entries:
            return []
        return sorted(entries, key=self._entry_subsort_key)

    def _entries_in_space(self, addr: Address) -> List[SymbolEntry]:
        spc_index = addr.getSpace().getIndex()
        entries: List[SymbolEntry] = []
        for (space_index, _), entry_list in self._entriesByAddr.items():
            if space_index == spc_index:
                entries.extend(entry_list)
        return sorted(
            entries,
            key=lambda entry: (entry.getAddr().getOffset(), *self._entry_subsort_key(entry)),
        )

    def findAddr(self, addr: Address, usepoint: Address) -> Optional[SymbolEntry]:
        for entry in reversed(self._entries_at_address(addr)):
            if entry.inUse(usepoint):
                return entry
        return None

    def findContainer(self, addr: Address, size: int,
                      usepoint: Address) -> Optional[SymbolEntry]:
        """Find the smallest SymbolEntry containing the given range.

        C++ ref: ``ScopeInternal::findContainer``
        """
        bestentry = None
        oldsize = -1
        target_off = addr.offset
        end = target_off + size - 1
        for entry in reversed(self._entries_in_space(addr)):
            e_off = entry.addr.offset
            esz = entry.size
            if e_off > target_off:
                continue
            if e_off + esz - 1 < end:
                continue
            if esz < oldsize or oldsize == -1:
                if entry.inUse(usepoint):
                    bestentry = entry
                    if esz == size:
                        return bestentry
                    oldsize = esz
        return bestentry

    def addMapEntry(self, sym: Symbol, entry: SymbolEntry) -> SymbolEntry:
        entry.symbol = sym
        sym.mapentry.append(entry)
        if sym.type is not None and entry.size == sym.type.getSize():
            sym.wholeCount += 1
        if entry.isDynamic():
            self.dynamicentry.append(entry)
        else:
            if entry.uselimit.empty():
                sym.flags |= Varnode.addrtied
                db = getattr(getattr(self, "glb", None), "symboltab", None)
                if db is not None and entry.addr is not None and not entry.addr.isInvalid():
                    sym.flags |= db.getProperty(entry.addr)
            if self.isGlobal():
                sym.flags |= Varnode.persist
            key = (entry.addr.getSpace().getIndex(), entry.addr.getOffset())
            if key not in self._entriesByAddr:
                self._entriesByAddr[key] = []
            self._entriesByAddr[key].append(entry)
        return entry

    def addMapInternal(self, sym: Symbol, exfl: int, addr: Address,
                       off: int, sz: int, uselim: RangeList) -> SymbolEntry:
        lastaddress = addr + (sz - 1)
        if lastaddress.getOffset() < addr.getOffset():
            raise LowlevelError("Symbol " + sym.getName() + " extends beyond the end of the address space")
        entry = SymbolEntry(sym, addr, sz, off, exfl)
        entry.setUseLimit(uselim)
        return self.addMapEntry(sym, entry)

    def addDynamicMapInternal(self, sym: Symbol, exfl: int, hash_: int,
                              off: int, sz: int, uselim: RangeList) -> SymbolEntry:
        entry = SymbolEntry(sym, exfl, hash_, off, sz, uselim)
        return self.addMapEntry(sym, entry)

    def begin(self):
        return MapIterator.from_entry_maps(self._entriesByAddr)

    def end(self):
        return MapIterator.from_entry_maps(self._entriesByAddr, at_end=True)

    def beginDynamic(self):
        return iter(self.dynamicentry)

    def endDynamic(self):
        return iter(())

    def getCategorySize(self, cat: int) -> int:
        lst = self._categoryMap.get(cat)
        return len(lst) if lst else 0

    def getCategorySymbol(self, cat: int, index: int) -> Optional[Symbol]:
        lst = self._categoryMap.get(cat)
        if lst and 0 <= index < len(lst):
            return lst[index]
        return None

    def getAllSymbols(self) -> Iterator[Symbol]:
        return iter(self._symbolsById.values())

    def getSymbolList(self) -> List[Symbol]:
        return list(self._symbolsById.values())

    def beginMultiEntry(self) -> Iterator[Symbol]:
        multi_entry = [
            sym for sym in self._symbolsById.values()
            if sym.isMultiEntry()
        ]
        multi_entry.sort(key=lambda sym: (sym.getName(), sym.nameDedup, sym.symbolId))
        return iter(multi_entry)

    def endMultiEntry(self) -> Iterator[Symbol]:
        return iter(())

    def findFunction(self, addr: Address):
        """Find a FunctionSymbol by entry address."""
        for entry in self._entries_at_address(addr):
            sym = entry.getSymbol()
            if isinstance(sym, FunctionSymbol):
                return sym.getFunction()
        return None

    def findExternalRef(self, addr: Address) -> Optional[ExternRefSymbol]:
        for entry in self._entries_at_address(addr):
            sym = entry.getSymbol()
            return sym if isinstance(sym, ExternRefSymbol) else None
        return None

    def findCodeLabel(self, addr: Address) -> Optional[LabSymbol]:
        for entry in reversed(self._entries_at_address(addr)):
            if not entry.inUse(addr):
                continue
            sym = entry.getSymbol()
            return sym if isinstance(sym, LabSymbol) else None
        return None

    def resolveExternalRefFunction(self, sym: ExternRefSymbol) -> Optional[Funcdata]:
        return self.queryFunction(sym.getRefAddr())

    def buildVariableName(self, addr: Address, pc: Address, ct, index: int, flags: int) -> str:
        return Scope._buildVariableNameImpl(self, addr, pc, ct, index, flags)

    def buildUndefinedName(self) -> str:
        candidates = [
            name
            for name in getattr(self, "_symbolsByName", {}).keys()
            if len(name) == 15 and name.startswith("$$undef")
        ]
        if not candidates:
            return "$$undef00000000"
        symname = max(candidates)
        try:
            uniq = int(symname[7:], 16)
        except ValueError as err:
            raise LowlevelError("Error creating undefined name") from err
        return f"$$undef{uniq + 1:08x}"

    def makeNameUnique(self, name: str) -> str:
        if self._findFirstByName(name) is None:
            return name

        matching = sorted(
            candidate
            for candidate in getattr(self, "_symbolsByName", {}).keys()
            if candidate.startswith(name)
        )

        uniqid = None
        for candidate in reversed(matching):
            if candidate == name:
                break
            if len(candidate) < len(name) + 3 or candidate[len(name)] != "_":
                continue
            suffix = candidate[len(name) + 1 :]
            is_xform = suffix.startswith("x")
            digits = suffix[1:] if is_xform else suffix
            if not digits.isdigit():
                continue
            if is_xform and len(digits) != 5:
                continue
            if (not is_xform) and len(digits) != 2:
                continue
            uniqid = int(digits)
            break

        if uniqid is None:
            res_string = f"{name}_00"
        else:
            uniqid += 1
            if uniqid < 100:
                res_string = f"{name}_{uniqid:02d}"
            else:
                res_string = f"{name}_x{uniqid:05d}"

        if self._findFirstByName(res_string) is not None:
            raise LowlevelError("Unable to uniquify name: " + res_string)
        return res_string

    def addFunction(self, addr: Address, name: str) -> FunctionSymbol:
        """Create and add a FunctionSymbol."""
        overlap = self.queryContainer(addr, 1, Address())
        if overlap is not None:
            glb = getattr(self, "glb", None)
            if glb is not None and hasattr(glb, "printMessage"):
                glb.printMessage("WARNING: Function " + self.name + " overlaps object: " + overlap.getSymbol().getName())
        owner = self.owner if self.owner is not None else self
        fsym = FunctionSymbol(owner, name, getattr(self.glb, "min_funcsymbol_size", 1))
        self.addSymbolInternal(fsym)
        self.addMapPoint(fsym, addr, Address())
        return fsym

    def addCodeLabel(self, addr: Address, name: str) -> LabSymbol:
        """Create and add a code label symbol."""
        overlap = self.queryContainer(addr, 1, addr)
        if overlap is not None:
            glb = getattr(self, "glb", None)
            if glb is not None and hasattr(glb, "printMessage"):
                glb.printMessage("WARNING: Codelabel " + name + " overlaps object: " + overlap.getSymbol().getName())
        owner = self.owner if self.owner is not None else self
        lsym = LabSymbol(owner, name)
        self.addSymbolInternal(lsym)
        self.addMapPoint(lsym, addr, Address())
        return lsym

    def addDynamicSymbol(self, name: str, ct, addr: Address, hash_: int) -> Symbol:
        """Create a Symbol tied to a dynamic hash instead of fixed storage.

        C++ ref: ``Scope::addDynamicSymbol`` in database.cc
        """
        owner = self.owner if self.owner is not None else self
        sym = Symbol(owner, name, ct)
        self.addSymbolInternal(sym)
        rnglist = RangeList()
        if not addr.isInvalid():
            rnglist.insertRange(addr.getSpace(), addr.getOffset(), addr.getOffset())
        self.addDynamicMapInternal(sym, Varnode.mapped, hash_, 0, ct.getSize(), rnglist)
        return sym

    def addEquateSymbol(self, name: str, format_: int, val: int, addr: Address, hash_: int) -> EquateSymbol:
        """Create a dynamic equate Symbol.

        C++ ref: ``Scope::addEquateSymbol`` in database.cc
        """
        owner = self.owner if self.owner is not None else self
        sym = EquateSymbol(owner, name, format_, val)
        self.addSymbolInternal(sym)
        rnglist = RangeList()
        if not addr.isInvalid():
            rnglist.insertRange(addr.getSpace(), addr.getOffset(), addr.getOffset())
        self.addDynamicMapInternal(sym, Varnode.mapped, hash_, 0, 1, rnglist)
        return sym

    def addExternalRef(self, addr: Address, refaddr: Address, name: str) -> ExternRefSymbol:
        """Create an external-reference Symbol.

        C++ ref: ``Scope::addExternalRef`` in database.cc
        """
        owner = self.owner if self.owner is not None else self
        sym = ExternRefSymbol(owner, refaddr, name)
        self.addSymbolInternal(sym)
        entry = self.addMapPoint(sym, addr, Address())
        entry.symbol.clearFlags(Varnode.readonly)
        return sym

    def addUnionFacetSymbol(self, name: str, ct, fieldNum: int, addr: Address, hash_: int) -> Symbol:
        """Create a dynamic Symbol that forces a union-field interpretation.

        C++ ref: ``Scope::addUnionFacetSymbol`` in database.cc
        """
        owner = self.owner if self.owner is not None else self
        sym = UnionFacetSymbol(owner, name, ct, fieldNum)
        self.addSymbolInternal(sym)
        rnglist = RangeList()
        if not addr.isInvalid():
            rnglist.insertRange(addr.getSpace(), addr.getOffset(), addr.getOffset())
        self.addDynamicMapInternal(sym, Varnode.mapped, hash_, 0, 1, rnglist)
        return sym

    def addMapPoint(self, sym: Symbol, addr: Address, usepoint: Address) -> SymbolEntry:
        """Map an existing Symbol to a fixed address, optionally limited by a usepoint.

        C++ ref: ``Scope::addMapPoint`` in database.cc
        """
        size = sym.getBytesConsumed() if hasattr(sym, "getBytesConsumed") else 0
        entry = SymbolEntry(sym, addr, size)
        if usepoint is not None and not usepoint.isInvalid():
            entry.uselimit.insertRange(usepoint.getSpace(), usepoint.getOffset(), usepoint.getOffset())
        if type(self).addMapInternal is ScopeInternal.addMapInternal:
            return self.addMap(entry)
        return self.addMapEntry(sym, entry)

    def queryCodeLabel(self, addr: Address) -> Optional[LabSymbol]:
        """Find a code label symbol by exact address."""
        return super().queryCodeLabel(addr)

    def queryByAddr(self, addr: Address, usepoint: Address) -> Optional[SymbolEntry]:
        """Find a symbol entry that matches the given address and usepoint."""
        return super().queryByAddr(addr, usepoint)

    def queryProperties(self, addr: Address, size: int, usepoint, flags_ref):
        """Query boolean properties of the given address range.

        C++ ref: ``Scope::queryProperties`` in database.cc
        Returns the SymbolEntry if found, else None.
        """
        return super().queryProperties(addr, size, usepoint, flags_ref)

    def assignDefaultNames(self, base: int) -> int:
        """Assign default names to all unnamed symbols.

        C++ ref: ``ScopeInternal::assignDefaultNames`` in database.cc
        """
        ordered_symbols = []
        for name in sorted(self._symbolsByName):
            ordered_symbols.extend(self._symbolsByName[name])

        for sym in ordered_symbols:
            if sym.getName() <= "$$undef":
                continue
            if not sym.isNameUndefined():
                break
            nm = self.buildDefaultName(sym, base, None)
            self.renameSymbol(sym, nm)
            base += 1
        return base

    def renameSymbol(self, sym: Symbol, newname: str) -> None:
        """Rename a symbol.

        C++ ref: ``ScopeInternal::renameSymbol``
        """
        oldname = sym.name
        lst = self._symbolsByName.get(oldname)
        if lst:
            try:
                lst.remove(sym)
            except ValueError:
                pass
            if not lst:
                self._symbolsByName.pop(oldname, None)
        sym.name = newname
        sym.displayName = newname
        self.insertNameTree(sym)

    def retypeSymbol(self, sym: Symbol, ct) -> None:
        if ct.hasStripped():
            ct = ct.getStripped()
        if sym.type.getSize() == ct.getSize() or not sym.mapentry:
            sym.type = ct
            sym.checkSizeTypeLock()
            return
        if len(sym.mapentry) == 1:
            entry = sym.mapentry[-1]
            if entry.isAddrTied():
                addr = entry.getAddr()
                self.removeSymbolMappings(sym)
                sym.type = ct
                sym.checkSizeTypeLock()
                self.addMapPoint(sym, addr, Address())
                return
        raise RecovError("Unable to retype symbol: " + sym.name)

    def setAttribute(self, sym: Symbol, attr: int) -> None:
        attr &= (
            Varnode.typelock
            | Varnode.namelock
            | Varnode.readonly
            | Varnode.incidental_copy
            | Varnode.nolocalalias
            | Varnode.volatil
            | Varnode.indirectstorage
            | Varnode.hiddenretparm
        )
        sym.flags |= attr
        sym.checkSizeTypeLock()

    def clearAttribute(self, sym: Symbol, attr: int) -> None:
        attr &= (
            Varnode.typelock
            | Varnode.namelock
            | Varnode.readonly
            | Varnode.incidental_copy
            | Varnode.nolocalalias
            | Varnode.volatil
            | Varnode.indirectstorage
            | Varnode.hiddenretparm
        )
        sym.flags &= ~attr
        sym.checkSizeTypeLock()

    def setDisplayFormat(self, sym: Symbol, attr: int) -> None:
        sym.setDisplayFormat(attr)

    def setCategory(self, sym: Symbol, cat: int, ind: int) -> None:
        if sym.category >= 0:
            symlist = self._categoryMap.get(sym.category)
            if symlist is not None and 0 <= sym.catindex < len(symlist):
                symlist[sym.catindex] = None
                while symlist and symlist[-1] is None:
                    symlist.pop()

        sym.category = cat
        sym.catindex = ind
        if cat < 0:
            return

        symlist = self._categoryMap.setdefault(cat, [])
        if cat > 0:
            sym.catindex = len(symlist)
        while len(symlist) <= sym.catindex:
            symlist.append(None)
        symlist[sym.catindex] = sym

    def findOverlap(self, addr: Address, size: int) -> Optional[SymbolEntry]:
        """Find any symbol entry that overlaps the given range."""
        debug_enabled = _find_overlap_debug_enabled(addr)
        selected = None
        candidates = [] if debug_enabled else None
        visible_entries = [] if debug_enabled else None
        a_start = addr.getOffset()
        a_end = a_start + size - 1
        for entry in self._entries_in_space(addr):
            if visible_entries is not None:
                visible_entries.append(entry)
            e_start = entry.getFirst()
            e_end = entry.getLast()
            if e_start <= a_end and a_start <= e_end:
                if candidates is not None:
                    candidates.append(entry)
                    if selected is None:
                        selected = entry
                    continue
                return entry
        if candidates is not None:
            _find_overlap_debug_log(addr, size, candidates, selected, visible_entries)
        return selected

    def findClosestFit(self, addr: Address, size: int, usepoint: Address) -> Optional[SymbolEntry]:
        """Find the closest fitting symbol entry for the given range."""
        bestentry = None
        olddiff = -10000
        target_off = addr.offset
        for entry in reversed(self._entries_in_space(addr)):
            if entry.getLast() < target_off:
                continue
            newdiff = entry.getSize() - size
            better = False
            if olddiff < 0:
                better = newdiff > olddiff
            elif newdiff >= 0:
                better = newdiff < olddiff
            if better and entry.inUse(usepoint):
                bestentry = entry
                if newdiff == 0:
                    return bestentry
                olddiff = newdiff
        return bestentry

    def setProperties(self, addr: Address, size: int, flags: int) -> None:
        """Set boolean properties on an address range."""
        # Simplified: no-op for in-memory scope
        pass

    def adjustCaches(self) -> None:
        """Adjust internal caches after configuration changes.

        C++ ref: ``ScopeInternal::adjustCaches``
        """
        # In-memory scope doesn't need per-space maptable resizing
        pass

    def clear(self) -> None:
        """Remove all symbols from this scope.

        C++ ref: ``ScopeInternal::clear``
        """
        for sym in list(self._symbolsById.values()):
            self.removeSymbol(sym)
        self._nextSymId = 0

    def clearCategory(self, cat: int) -> None:
        """Remove all symbols in the given category.

        If *cat* < 0, remove all uncategorized symbols.

        C++ ref: ``ScopeInternal::clearCategory``
        """
        if cat >= 0:
            lst = self._categoryMap.get(cat, [])
            for sym in list(lst):
                self.removeSymbol(sym)
        else:
            for sym in list(self._symbolsById.values()):
                if sym.getCategory() >= 0:
                    continue
                self.removeSymbol(sym)

    def clearUnlocked(self) -> None:
        """Remove unlocked symbols; clear unlocked names on locked ones.

        Type-locked symbols are kept but their names are cleared if not
        name-locked. Size-type-locked symbols get their type reset.
        Equate symbols are always preserved.

        C++ ref: ``ScopeInternal::clearUnlocked``
        """
        for sym in list(self._symbolsById.values()):
            if sym.isTypeLocked():
                if not sym.isNameLocked():
                    if not sym.isNameUndefined():
                        self.renameSymbol(sym, self.buildUndefinedName())
                self.clearAttribute(sym, Varnode.nolocalalias if hasattr(Varnode, 'nolocalalias') else 0)
                if sym.isSizeTypeLocked():
                    self.resetSizeLockType(sym)
            elif sym.getCategory() == Symbol.equate:
                continue
            else:
                self.removeSymbol(sym)

    def clearUnlockedCategory(self, cat: int) -> None:
        """Remove unlocked symbols in the given category.

        C++ ref: ``ScopeInternal::clearUnlockedCategory``
        """
        if cat >= 0:
            lst = self._categoryMap.get(cat, [])
            for sym in list(lst):
                if sym.isTypeLocked():
                    if not sym.isNameLocked():
                        if not sym.isNameUndefined():
                            self.renameSymbol(sym, self.buildUndefinedName())
                    if sym.isSizeTypeLocked():
                        self.resetSizeLockType(sym)
                else:
                    self.removeSymbol(sym)
        else:
            for sym in list(self._symbolsById.values()):
                if sym.getCategory() >= 0:
                    continue
                if sym.isTypeLocked():
                    if not sym.isNameLocked():
                        if not sym.isNameUndefined():
                            self.renameSymbol(sym, self.buildUndefinedName())
                else:
                    self.removeSymbol(sym)

    def removeRange(self, spc, first: int, last: int) -> None:
        """Remove an address range from this scope's ownership.

        C++ ref: ``Scope::removeRange``
        """
        self.rangetree.removeRange(spc, first, last)

    def addRange(self, spc, first: int, last: int) -> None:
        """Add an address range to this scope's ownership.

        C++ ref: ``Scope::addRange``
        """
        self.rangetree.insertRange(spc, first, last)

    def encode(self, encoder) -> None:
        """Encode this scope and all its symbols to a stream.

        C++ ref: ``ScopeInternal::encode``
        """
        from ghidra.core.marshal import (
            ELEM_SCOPE, ELEM_PARENT, ELEM_SYMBOLLIST, ELEM_MAPSYM,
            ATTRIB_NAME, ATTRIB_ID, ATTRIB_TYPE,
        )
        encoder.openElement(ELEM_SCOPE)
        encoder.writeString(ATTRIB_NAME, self.name)
        encoder.writeUnsignedInteger(ATTRIB_ID, self.uniqueId)
        if self.parent is not None:
            encoder.openElement(ELEM_PARENT)
            encoder.writeUnsignedInteger(ATTRIB_ID, self.parent.getId())
            encoder.closeElement(ELEM_PARENT)
        self.rangetree.encode(encoder)
        if self._symbolsByName:
            encoder.openElement(ELEM_SYMBOLLIST)
            for name in sorted(self._symbolsByName):
                for sym in self._symbolsByName[name]:
                    symbolType = 0
                    if sym.mapentry:
                        e0 = sym.mapentry[0]
                        if e0.isDynamic():
                            if sym.getCategory() == Symbol.union_facet:
                                continue
                            symbolType = 2 if sym.getCategory() == Symbol.equate else 1
                    encoder.openElement(ELEM_MAPSYM)
                    if symbolType == 1:
                        encoder.writeString(ATTRIB_TYPE, "dynamic")
                    elif symbolType == 2:
                        encoder.writeString(ATTRIB_TYPE, "equate")
                    sym.encode(encoder)
                    for ent in sym.mapentry:
                        ent.encode(encoder)
                    encoder.closeElement(ELEM_MAPSYM)
            encoder.closeElement(ELEM_SYMBOLLIST)
        encoder.closeElement(ELEM_SCOPE)

    def decode(self, decoder) -> None:
        """Decode this scope's symbols from a stream.

        C++ ref: ``ScopeInternal::decode``
        """
        from ghidra.core.marshal import (
            ELEM_PARENT, ELEM_RANGELIST, ELEM_RANGEEQUALSSYMBOLS,
            ELEM_SYMBOLLIST, ELEM_MAPSYM, ELEM_HOLE, ELEM_COLLISION,
        )
        rangeequalssymbols = False
        subId = decoder.peekElement()
        if subId == ELEM_PARENT.id:
            decoder.skipElement()
            subId = decoder.peekElement()
        if subId == ELEM_RANGELIST.id:
            newrangetree = RangeList()
            newrangetree.decode(decoder)
            db = getattr(self.glb, "symboltab", None)
            if db is not None and hasattr(db, "setRange"):
                db.setRange(self, newrangetree)
            else:
                self.rangetree = newrangetree
        elif subId == ELEM_RANGEEQUALSSYMBOLS.id:
            decoder.openElement()
            decoder.closeElement(subId)
            rangeequalssymbols = True
        subId = decoder.openElement(ELEM_SYMBOLLIST)
        if subId != 0:
            while True:
                symId = decoder.peekElement()
                if symId == 0:
                    break
                if symId == ELEM_MAPSYM.id:
                    sym = self.addMapSym(decoder)
                    if rangeequalssymbols and sym is not None:
                        entry = sym.getFirstWholeMap()
                        db = getattr(self.glb, "symboltab", None)
                        if db is not None and hasattr(db, "addRange"):
                            db.addRange(self, entry.getAddr().getSpace(), entry.getFirst(), entry.getLast())
                        else:
                            self.addRange(entry.getAddr().getSpace(), entry.getFirst(), entry.getLast())
                elif symId == ELEM_HOLE.id:
                    self.decodeHole(decoder)
                elif symId == ELEM_COLLISION.id:
                    self.decodeCollision(decoder)
                else:
                    raise LowlevelError("Unknown symbollist tag")
            decoder.closeElement(subId)
        self.categorySanity()

    def printEntries(self, s) -> None:
        """Print all symbol entries to the given stream."""
        s.write(f"Scope {self.name}\n")
        for entry in self.begin():
            entry.printEntry(s)

    def getNumSymbols(self) -> int:
        return len(self._symbolsById)

    def getNextSymbolId(self) -> int:
        return self._nextSymId


# =========================================================================
# ScopeMapper
# =========================================================================

class ScopeMapper:
    """Address range tagged with the owning namespace Scope."""

    class NullSubsort:
        def __init__(self, val=None) -> None:
            pass

        def __lt__(self, op2) -> bool:
            return False

    linetype = Address
    subsorttype = NullSubsort

    def __init__(self, data: Scope, f: Address, l: Address) -> None:
        self.scope = data
        self.first = f
        self.last = l

    def getFirst(self) -> Address:
        return self.first

    def getLast(self) -> Address:
        return self.last

    def getSubsort(self) -> NullSubsort:
        return ScopeMapper.NullSubsort()

    def getScope(self) -> Scope:
        return self.scope


# =========================================================================
# Database
# =========================================================================

class Database:
    """The main symbol table container managing all Scopes.

    Contains the global scope and manages the full hierarchy of scopes
    (global, function-local, etc.).
    """

    def __init__(self, glb=None, idByNameHash: bool = False) -> None:
        self.glb = glb  # Architecture
        self._globalScope: Optional[ScopeInternal] = None
        self._scopeMap: Dict[int, Scope] = {}
        self._resolveMap: List[ScopeMapper] = []
        self._nextScopeId: int = 1
        self._flagbase: Dict = {}  # addr offset -> flags (simplified partmap)
        self._flagspace: Dict[int, object] = {}
        self.idByNameHash: bool = idByNameHash

    def __del__(self) -> None:
        if getattr(self, "_globalScope", None) is not None:
            self.deleteScope(self._globalScope)

    def clearResolve(self, scope: Scope) -> None:
        if scope is self._globalScope:
            return
        if getattr(scope, "fd", None) is not None:
            return
        self._resolveMap = [entry for entry in self._resolveMap if entry.getScope() is not scope]

    def clearReferences(self, scope: Scope) -> None:
        for child in list(scope.children.values()):
            self.clearReferences(child)
        self._scopeMap.pop(scope.uniqueId, None)
        self.clearResolve(scope)

    def fillResolve(self, scope: Scope) -> None:
        if scope is self._globalScope:
            return
        if getattr(scope, "fd", None) is not None:
            return
        for rng in scope.rangetree:
            self._resolveMap.append(
                ScopeMapper(scope, rng.getFirstAddr(), rng.getLastAddr())
            )

    def getGlobalScope(self) -> Optional[ScopeInternal]:
        return self._globalScope

    def setGlobalScope(self, scope: ScopeInternal) -> None:
        self._globalScope = scope
        self._scopeMap[scope.uniqueId] = scope

    def createGlobalScope(self, name: str = "global") -> ScopeInternal:
        scope = ScopeInternal(self._nextScopeId, name, self.glb)
        self._nextScopeId += 1
        self.setGlobalScope(scope)
        return scope

    def createScope(self, name: str, parent: Scope, fd=None) -> ScopeInternal:
        scope = ScopeInternal(self._nextScopeId, name, self.glb, fd)
        self._nextScopeId += 1
        self._scopeMap[scope.uniqueId] = scope
        parent.attachScope(scope)
        return scope

    def findCreateScopeFromSymbolName(
        self,
        fullname: str,
        delim: str,
        basename: Optional[List[str]] = None,
        start: Optional[Scope] = None,
    ) -> Scope:
        """Find or create nested scopes implied by a qualified symbol name.

        C++ ref: ``Database::findCreateScopeFromSymbolName``
        """
        if start is None:
            start = self._globalScope
        if start is None:
            raise LowlevelError("No global scope registered")

        mark = 0
        while True:
            endmark = fullname.find(delim, mark)
            if endmark == -1:
                break
            if not self.idByNameHash:
                raise LowlevelError("Scope name hashes not allowed")
            scopename = fullname[mark:endmark]
            nameId = Scope.hashScopeName(start.uniqueId, scopename)
            start = self.findCreateScope(nameId, scopename, start)
            mark = endmark + len(delim)

        base = fullname[mark:]
        if basename is not None:
            basename[:] = [base]
        return start

    def resolveScopeFromSymbolName(
        self,
        fullname: str,
        delim: str,
        basename: Optional[List[str]] = None,
        start: Optional[Scope] = None,
    ) -> Optional[Scope]:
        """Resolve nested scopes implied by a qualified symbol name.

        C++ ref: ``Database::resolveScopeFromSymbolName``
        """
        if start is None:
            start = self._globalScope
        if start is None:
            if basename is not None:
                basename[:] = [fullname]
            return None

        mark = 0
        while True:
            endmark = fullname.find(delim, mark)
            if endmark == -1:
                break
            if endmark == 0:
                start = self._globalScope
            else:
                start = start.resolveScope(fullname[mark:endmark], self.idByNameHash)
                if start is None:
                    if basename is not None:
                        basename[:] = [fullname[mark:]]
                    return None
            mark = endmark + len(delim)

        base = fullname[mark:]
        if basename is not None:
            basename[:] = [base]
        return start

    def attachScope(self, newscope: Scope, parent: Optional[Scope]) -> None:
        """Register a scope and attach it to its parent.

        C++ ref: ``Database::attachScope``
        """
        if parent is None:
            if self._globalScope is not None:
                raise LowlevelError("Multiple global scopes")
            if getattr(newscope, "name", "") != "":
                raise LowlevelError("Global scope does not have empty name")
            self._globalScope = newscope
            self._scopeMap[newscope.uniqueId] = newscope
            return
        if getattr(newscope, "name", "") == "":
            raise LowlevelError("Non-global scope has empty name")
        if newscope.uniqueId in self._scopeMap:
            fullname = newscope.getFullName()
            if not fullname:
                fullname = getattr(newscope, "name", "")
            raise RecovError("Duplicate scope id: " + fullname)
        self._scopeMap[newscope.uniqueId] = newscope
        parent.attachScope(newscope)

    def findScope(self, id_: int) -> Optional[Scope]:
        return self._scopeMap.get(id_)

    def resolveScope(self, id_or_addr) -> Optional[Scope]:
        """Find a Scope by id or address.

        If *id_or_addr* is an int, look up by scope id.
        If it is an Address, find the owning scope (falls back to global).

        C++ ref: ``Database::resolveScope``
        """
        if isinstance(id_or_addr, int):
            return self._scopeMap.get(id_or_addr)
        return self.mapScope(self._globalScope, id_or_addr, Address())

    def removeScope(self, scope: Scope) -> None:
        """Remove a scope and all its children."""
        for child_id in list(scope.children.keys()):
            child = scope.children[child_id]
            self.removeScope(child)
        self._scopeMap.pop(scope.uniqueId, None)
        if scope.parent is not None:
            scope.parent.detachScope(scope.uniqueId)

    def deleteScope(self, scope: Scope) -> None:
        """Delete a scope and all descendants.

        C++ ref: ``Database::deleteScope``
        """
        self.clearReferences(scope)
        if self._globalScope is scope:
            self._globalScope = None
            return
        parent = getattr(scope, "parent", None)
        if parent is None or scope.uniqueId not in parent.children:
            raise LowlevelError("Could not remove parent reference to: " + scope.name)
        parent.detachScope(scope.uniqueId)

    def renameScope(self, scope: Scope, newname: str) -> None:
        scope.name = newname
        scope.displayName = newname

    def mapScope(self, scope_or_qpoint, addr_or_spc=None, first_or_usepoint=None, last: int = 0):
        """Associate an address range with a scope, or map an address to a scope.

        Two signatures:
        - mapScope(scope, spc, first, last) — add address range to scope
        - mapScope(qpoint, addr, usepoint) — find scope owning addr

        C++ ref: ``Database::addRange`` / ``Database::mapScope``
        """
        if isinstance(addr_or_spc, Address):
            addr = addr_or_spc
            if not self._resolveMap:
                return scope_or_qpoint
            target_space = addr.getSpace()
            target_offset = addr.getOffset()
            for entry in self._resolveMap:
                first = entry.getFirst()
                last_addr = entry.getLast()
                if first.getSpace() is not target_space:
                    continue
                if first.getOffset() <= target_offset <= last_addr.getOffset():
                    return entry.getScope()
            return scope_or_qpoint
        # mapScope(scope, spc, first, last) — add range
        scope_or_qpoint.addRange(addr_or_spc, first_or_usepoint, last)

    def encode(self, encoder) -> None:
        """Encode the entire Database to a stream.

        C++ ref: ``Database::encode``
        """
        from ghidra.core.marshal import (
            ATTRIB_SCOPEIDBYNAME,
            ATTRIB_VAL,
            ELEM_DB,
            ELEM_PROPERTY_CHANGEPOINT,
        )
        encoder.openElement(ELEM_DB)
        if self.idByNameHash:
            encoder.writeBool(ATTRIB_SCOPEIDBYNAME, True)
        for key, val in sorted(self._flagbase.items(), key=lambda item: (item[0][0], item[0][1])):
            spc = self._flagspace.get(key[0])
            if spc is None:
                continue
            encoder.openElement(ELEM_PROPERTY_CHANGEPOINT)
            spc.encodeAttributes(encoder, key[1])
            encoder.writeUnsignedInteger(ATTRIB_VAL, val)
            encoder.closeElement(ELEM_PROPERTY_CHANGEPOINT)
        if self._globalScope is not None:
            self._globalScope.encodeRecursive(encoder, True)
        encoder.closeElement(ELEM_DB)

    def _parseParentTag(self, decoder) -> Scope:
        from ghidra.core.marshal import ELEM_PARENT, ATTRIB_ID

        elemId = decoder.openElement(ELEM_PARENT)
        parentId = decoder.readUnsignedInteger(ATTRIB_ID)
        parentScope = self.resolveScope(parentId)
        if parentScope is None:
            raise LowlevelError("Could not find scope matching id")
        decoder.closeElement(elemId)
        return parentScope

    def parseParentTag(self, decoder) -> Scope:
        return self._parseParentTag(decoder)

    def decodeScope(self, decoder, newScope: Scope) -> None:
        """Register and fill out a single Scope from a wrapped scope tag.

        C++ ref: ``Database::decodeScope``
        """
        from ghidra.core.marshal import ELEM_SCOPE

        elemId = decoder.openElement()
        if elemId == ELEM_SCOPE:
            parentScope = self._parseParentTag(decoder)
            self.attachScope(newScope, parentScope)
            newScope.decode(decoder)
        else:
            newScope.decodeWrappingAttributes(decoder)
            subId = decoder.openElement(ELEM_SCOPE)
            parentScope = self._parseParentTag(decoder)
            self.attachScope(newScope, parentScope)
            newScope.decode(decoder)
            decoder.closeElement(subId)
        decoder.closeElement(elemId)

    def decode(self, decoder) -> None:
        """Decode the Database from a stream.

        C++ ref: ``Database::decode``
        """
        from ghidra.core.pcoderaw import VarnodeData
        from ghidra.core.marshal import (
            ELEM_DB, ELEM_SCOPE, ELEM_PARENT, ELEM_PROPERTY_CHANGEPOINT,
            ATTRIB_NAME, ATTRIB_ID, ATTRIB_LABEL, ATTRIB_SCOPEIDBYNAME, ATTRIB_VAL,
        )
        elemId = decoder.openElement(ELEM_DB)
        self.idByNameHash = False
        for _ in range(100):
            attribId = decoder.getNextAttributeId()
            if attribId == 0:
                break
            if attribId == ATTRIB_SCOPEIDBYNAME.id:
                self.idByNameHash = decoder.readBool()
        while True:
            subId = decoder.peekElement()
            if subId != ELEM_PROPERTY_CHANGEPOINT.id:
                break
            decoder.openElement()
            val = decoder.readUnsignedInteger(ATTRIB_VAL)
            vdata = VarnodeData()
            vdata.decodeFromAttributes(decoder)
            addr = vdata.getAddr()
            if addr.getSpace() is not None:
                self._flagspace[id(addr.getSpace())] = addr.getSpace()
                self._flagbase[(id(addr.getSpace()), addr.getOffset())] = val
            decoder.closeElement(subId)
        # Read scopes
        while True:
            subId = decoder.openElement()
            if subId != ELEM_SCOPE.id:
                break
            name = ""
            scopeId = 0
            displayName = ""
            for _ in range(100):
                attribId = decoder.getNextAttributeId()
                if attribId == 0:
                    break
                if attribId == ATTRIB_NAME.id:
                    name = decoder.readString()
                elif attribId == ATTRIB_ID.id:
                    scopeId = decoder.readUnsignedInteger()
                elif attribId == ATTRIB_LABEL.id:
                    displayName = decoder.readString()
            parentScope = None
            parentId = decoder.peekElement()
            if parentId == ELEM_PARENT.id:
                pElem = decoder.openElement(ELEM_PARENT)
                pid = decoder.readUnsignedInteger(ATTRIB_ID)
                parentScope = self._scopeMap.get(pid)
                decoder.closeElement(pElem)
            newScope = self.findCreateScope(scopeId, name, parentScope)
            if displayName:
                newScope.displayName = displayName
            newScope.decode(decoder)
            decoder.closeElement(subId)
        decoder.closeElement(elemId)

    def clear(self) -> None:
        self._scopeMap.clear()
        self._globalScope = None

    def getNumScopes(self) -> int:
        return len(self._scopeMap)

    def getArch(self):
        return self.glb

    def getScopeMap(self) -> dict:
        return self._scopeMap

    def getNextScopeId(self) -> int:
        return self._nextScopeId

    def isReadOnly(self) -> bool:
        return getattr(self, '_readonly', False)

    def setReadOnly(self, val: bool) -> None:
        self._readonly = val

    def deleteSubScopes(self, scope) -> None:
        """Delete all child scopes of the given scope.

        C++ ref: ``Database::deleteSubScopes``
        """
        for child_id in list(scope.children.keys()):
            child = scope.children[child_id]
            self.clearReferences(child)
            scope.detachScope(child_id)

    def _clearReferences(self, scope) -> None:
        self.clearReferences(scope)

    def findCreateScope(self, id_: int, name: str, parent=None) -> Scope:
        """Find a Scope by id; create it if it doesn't exist.

        C++ ref: ``Database::findCreateScope``
        """
        res = self._scopeMap.get(id_)
        if res is not None:
            return res
        if self._globalScope is None:
            raise LowlevelError("No global scope registered")
        newscope = self._globalScope.buildSubScope(id_, name)
        self.attachScope(newscope, parent)
        return newscope

    def addRange(self, scope, spc, first: int, last: int) -> None:
        """Add an address range to a scope's ownership.

        C++ ref: ``Database::addRange``
        """
        self.clearResolve(scope)
        scope.addRange(spc, first, last)
        self.fillResolve(scope)

    def setRange(self, scope, rlist: RangeList) -> None:
        """Replace the full ownership range of a scope.

        C++ ref: ``Database::setRange``
        """
        if scope is None:
            return
        self.clearResolve(scope)
        scope.rangetree = RangeList(rlist)
        self.fillResolve(scope)

    def removeRange(self, scope, spc, first: int, last: int) -> None:
        """Remove an address range from a scope's ownership.

        C++ ref: ``Database::removeRange``
        """
        self.clearResolve(scope)
        scope.removeRange(spc, first, last)
        self.fillResolve(scope)

    def clearUnlocked(self, scope) -> None:
        """Recursively clear unlocked symbols in a scope and its children.

        C++ ref: ``Database::clearUnlocked``
        """
        for child in scope.childrenBegin():
            self.clearUnlocked(child)
        scope.clearUnlocked()

    def adjustCaches(self) -> None:
        """Inform all scopes of configuration changes.

        C++ ref: ``Database::adjustCaches``
        """
        for sc in self._scopeMap.values():
            sc.adjustCaches()

    def findByName(self, nm: str):
        for s in self._scopeMap.values():
            if hasattr(s, 'getName') and s.getName() == nm:
                return s
        return None

    def queryScopesBy(self, addr) -> list:
        result = []
        for s in self._scopeMap.values():
            result.append(s)
        return result

    def getScopeById(self, uid: int):
        return self._scopeMap.get(uid, None)

    def getProperty(self, addr: Address) -> int:
        """Get boolean properties associated with the given address.

        C++ ref: ``Database::getProperty`` — looks up flagbase partmap.
        """
        spc = addr.getSpace()
        if spc is None:
            return 0
        self._flagspace[id(spc)] = spc
        key = (id(spc), addr.getOffset())
        return self._flagbase.get(key, 0)

    def getProperties(self):
        """Return a snapshot of the current property map.

        C++ ref: ``Database::getProperties``
        """
        return dict(self._flagbase)

    def setProperties(self, newflags) -> None:
        """Replace the complete property map.

        C++ ref: ``Database::setProperties``
        """
        self._flagbase = dict(newflags)

    def decodeScopePath(self, decoder):
        """Decode a namespace path and create any missing scopes.

        C++ ref: ``Database::decodeScopePath``
        """
        from ghidra.core.error import DecoderError
        from ghidra.core.marshal import ELEM_PARENT, ELEM_VAL, ATTRIB_ID, ATTRIB_LABEL, ATTRIB_CONTENT

        curscope = self.getGlobalScope()
        if curscope is None:
            raise LowlevelError("No global scope registered")
        elemId = decoder.openElement(ELEM_PARENT)
        subId = decoder.openElement()
        decoder.closeElementSkipping(subId)
        while True:
            subId = decoder.openElement()
            if subId != ELEM_VAL.id:
                break
            displayName = ""
            scopeId = 0
            while True:
                attribId = decoder.getNextAttributeId()
                if attribId == 0:
                    break
                if attribId == ATTRIB_ID.id:
                    scopeId = decoder.readUnsignedInteger()
                elif attribId == ATTRIB_LABEL.id:
                    displayName = decoder.readString()
            name = decoder.readString(ATTRIB_CONTENT)
            if scopeId == 0:
                raise DecoderError("Missing name and id in scope")
            curscope = self.findCreateScope(scopeId, name, curscope)
            if displayName:
                curscope.setDisplayName(displayName)
            decoder.closeElement(subId)
        decoder.closeElement(elemId)
        return curscope

    def setPropertyRange(self, flags: int, rng) -> None:
        """Set boolean properties on an address range.

        C++ ref: ``Database::setPropertyRange`` in database.cc
        """
        if hasattr(rng, 'getFirstAddr') and hasattr(rng, 'getLastAddr'):
            first = rng.getFirstAddr()
            last = rng.getLastAddr()
        elif hasattr(rng, 'getFirst') and hasattr(rng, 'getLast') and hasattr(rng, 'getSpace'):
            spc = rng.getSpace()
            if spc is None:
                return
            start = rng.getFirst()
            end = rng.getLast()
            for off in range(start, end + 1):
                key = (id(spc), off)
                self._flagbase[key] = self._flagbase.get(key, 0) | flags
            return
        elif hasattr(rng, 'getSpace'):
            first = rng
            last = rng
        else:
            return
        spc = first.getSpace()
        if spc is None:
            return
        self._flagspace[id(spc)] = spc
        start = first.getOffset()
        end = last.getOffset() if last is not None else start
        for off in range(start, end + 1):
            key = (id(spc), off)
            self._flagbase[key] = self._flagbase.get(key, 0) | flags

    def clearPropertyRange(self, flags: int, rng) -> None:
        """Clear boolean properties on an address range.

        C++ ref: ``Database::clearPropertyRange`` in database.cc
        """
        if hasattr(rng, 'getFirstAddr') and hasattr(rng, 'getLastAddr'):
            first = rng.getFirstAddr()
            last = rng.getLastAddr()
        elif hasattr(rng, 'getFirst') and hasattr(rng, 'getLast') and hasattr(rng, 'getSpace'):
            spc = rng.getSpace()
            if spc is None:
                return
            start = rng.getFirst()
            end = rng.getLast()
            mask = ~flags & 0xFFFFFFFF
            for off in range(start, end + 1):
                key = (id(spc), off)
                if key in self._flagbase:
                    self._flagbase[key] &= mask
            return
        elif hasattr(rng, 'getSpace'):
            first = rng
            last = rng
        else:
            return
        spc = first.getSpace()
        if spc is None:
            return
        self._flagspace[id(spc)] = spc
        start = first.getOffset()
        end = last.getOffset() if last is not None else start
        mask = ~flags & 0xFFFFFFFF
        for off in range(start, end + 1):
            key = (id(spc), off)
            if key in self._flagbase:
                self._flagbase[key] &= mask

    def __repr__(self) -> str:
        n = len(self._scopeMap)
        return f"Database({n} scopes)"
