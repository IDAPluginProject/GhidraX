"""
Corresponds to: database.hh / database.cc

Symbol and Scope objects for the decompiler.
Core classes: SymbolEntry, Symbol, FunctionSymbol, Scope, ScopeInternal, Database.
"""

from __future__ import annotations

from abc import ABC, abstractmethod
from typing import TYPE_CHECKING, Optional, List, Dict, Iterator

from ghidra.core.address import Address, RangeList
from ghidra.core.error import LowlevelError, RecovError
from ghidra.ir.varnode import Varnode

if TYPE_CHECKING:
    from ghidra.types.datatype import Datatype, TypeFactory
    from ghidra.core.space import AddrSpace
    from ghidra.core.marshal import Encoder, Decoder


# =========================================================================
# SymbolEntry
# =========================================================================

class SymbolEntry:
    """A storage location for a particular Symbol.

    Where a Symbol is stored, as a byte address and a size.
    """

    def __init__(self, symbol: Symbol, addr: Optional[Address] = None,
                 size: int = 0, offset: int = 0,
                 extraflags: int = 0, hash_: int = 0) -> None:
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

    def getSymbol(self) -> Symbol:
        return self.symbol

    def getAddr(self) -> Address:
        return self.addr

    def getHash(self) -> int:
        return self.hash

    def getSize(self) -> int:
        return self.size

    def inUse(self, usepoint: Address) -> bool:
        if self.uselimit.empty():
            return True
        return self.uselimit.inRange(usepoint, 1)

    def getUseLimit(self) -> RangeList:
        return self.uselimit

    def setUseLimit(self, uselim: RangeList) -> None:
        self.uselimit = uselim

    def isAddrTied(self) -> bool:
        return (self.symbol.getFlags() & Varnode.addrtied) != 0

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
        if cur is None:
            return None
        scope = self.symbol.getScope() if hasattr(self.symbol, 'getScope') else None
        if scope is not None and hasattr(scope, 'getArch'):
            arch = scope.getArch()
            if arch is not None and hasattr(arch, 'types') and hasattr(arch.types, 'getExactPiece'):
                return arch.types.getExactPiece(cur, off, sz)
        # Fallback: exact match only
        if sz == cur.getSize() and off == 0:
            return cur
        return None

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

    def getName(self) -> str:
        return self.name

    def getDisplayName(self) -> str:
        return self.displayName if self.displayName else self.name

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
        return len(self.name) == 0 or self.name.startswith("$$undef")

    def isMultiEntry(self) -> bool:
        return self.wholeCount > 1

    def hasMergeProblems(self) -> bool:
        return (self.dispflags & Symbol.merge_problems) != 0

    def isIsolated(self) -> bool:
        return (self.dispflags & Symbol.isolate) != 0

    def setIsolated(self, val: bool) -> None:
        if val:
            self.dispflags |= Symbol.isolate
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
            if 0 <= i_or_addr < len(self.mapentry):
                return self.mapentry[i_or_addr]
            return None
        # Address lookup
        for entry in self.mapentry:
            if not entry.isDynamic():
                if entry.addr.getSpace() is i_or_addr.getSpace():
                    if entry.getFirst() <= i_or_addr.getOffset() <= entry.getLast():
                        return entry
        return None

    def getFirstWholeMap(self) -> Optional[SymbolEntry]:
        for entry in self.mapentry:
            if entry.offset == 0 and entry.size == (self.type.getSize() if self.type else 0):
                return entry
        return self.mapentry[0] if self.mapentry else None

    def getBytesConsumed(self) -> int:
        if self.type is not None:
            return self.type.getSize()
        return 0

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

    def setMergeProblems(self, val: bool) -> None:
        if val:
            self.dispflags |= Symbol.merge_problems
        else:
            self.dispflags &= ~Symbol.merge_problems

    def checkSizeTypeLock(self) -> bool:
        return self.isSizeTypeLocked()

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
            ATTRIB_FORMAT,
        )
        from ghidra.core.marshal import AttributeId
        ATTRIB_MERGE = AttributeId("merge", 200)

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
            fmt_names = {1: "hex", 2: "dec", 3: "oct", 4: "bin", 5: "char"}
            encoder.writeString(ATTRIB_FORMAT, fmt_names.get(fmt, "hex"))
        encoder.writeSignedInteger(ATTRIB_CAT, self.category)
        if self.category >= 0:
            encoder.writeUnsignedInteger(ATTRIB_INDEX, self.catindex)

    def encodeBody(self, encoder) -> None:
        """Encode the data-type for this Symbol.

        C++ ref: ``Symbol::encodeBody``
        """
        if self.type is not None and hasattr(self.type, 'encodeRef'):
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
            ATTRIB_CAT, ATTRIB_ID, ATTRIB_NAME, ATTRIB_READONLY,
            ATTRIB_VOLATILE, ATTRIB_MERGE,
        )
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
            elif attribId == ATTRIB_ID.id:
                self.symbolId = decoder.readUnsignedInteger()
                if (self.symbolId >> 56) == (Symbol.ID_BASE >> 56):
                    self.symbolId = 0
            elif attribId == ATTRIB_NAME.id:
                self.name = decoder.readString()
            elif attribId == ATTRIB_READONLY.id:
                if decoder.readBool():
                    self.flags |= Varnode.readonly
            elif attribId == ATTRIB_VOLATILE.id:
                if decoder.readBool():
                    self.flags |= Varnode.volatil
            elif attribId == ATTRIB_MERGE.id:
                if not decoder.readBool():
                    self.dispflags |= Symbol.isolate
                    self.flags |= Varnode.typelock
            # Other attributes consumed by iteration
        if self.category == Symbol.function_parameter:
            from ghidra.core.marshal import ATTRIB_INDEX
            try:
                self.catindex = decoder.readUnsignedInteger(ATTRIB_INDEX)
            except Exception:
                self.catindex = 0
        else:
            self.catindex = 0
        if not self.displayName:
            self.displayName = self.name

    def decodeBody(self, decoder) -> None:
        """Decode the data-type of this Symbol.

        C++ ref: ``Symbol::decodeBody``
        """
        if self.scope is not None and hasattr(self.scope, 'glb') and self.scope.glb is not None:
            arch = self.scope.glb
            if hasattr(arch, 'types') and arch.types is not None:
                try:
                    self.type = arch.types.decodeType(decoder)
                except Exception:
                    pass

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

    def __init__(self, scope: Optional[Scope] = None, name: str = "",
                 size: int = 1) -> None:
        super().__init__(scope, name)
        self.fd = None  # Funcdata (set later)
        self.consumeSize: int = size
        self._buildType()

    def _buildType(self) -> None:
        """Set default code type and lock flags."""
        if self.scope is not None and hasattr(self.scope, 'glb') and self.scope.glb is not None:
            arch = self.scope.glb
            if hasattr(arch, 'types') and arch.types is not None:
                try:
                    self.type = arch.types.getTypeCode()
                except Exception:
                    pass
        self.flags |= Varnode.namelock | Varnode.typelock

    def getFunction(self):
        return self.fd

    def setFunction(self, fd) -> None:
        self.fd = fd

    def getBytesConsumed(self) -> int:
        return self.consumeSize

    def setBytesConsumed(self, sz: int) -> None:
        self.consumeSize = sz

    def decode(self, decoder) -> None:
        """Decode a FunctionSymbol from a stream.

        C++ ref: ``FunctionSymbol::decode``
        """
        from ghidra.core.marshal import (
            ELEM_FUNCTION, ELEM_FUNCTIONSHELL,
            ATTRIB_NAME, ATTRIB_ID, ATTRIB_LABEL,
        )
        elemId = decoder.peekElement()
        if elemId == ELEM_FUNCTION.id:
            # Full function definition — decode the funcdata
            # For now, just read the shell-like attributes
            decoder.openElement()
            self.symbolId = 0
            while True:
                attribId = decoder.getNextAttributeId()
                if attribId == 0:
                    break
                if attribId == ATTRIB_NAME.id:
                    self.name = decoder.readString()
                elif attribId == ATTRIB_ID.id:
                    self.symbolId = decoder.readUnsignedInteger()
                elif attribId == ATTRIB_LABEL.id:
                    self.displayName = decoder.readString()
            # Skip any child elements
            decoder.closeElementSkipping(elemId)
        else:
            # functionshell
            decoder.openElement()
            self.symbolId = 0
            while True:
                attribId = decoder.getNextAttributeId()
                if attribId == 0:
                    break
                if attribId == ATTRIB_NAME.id:
                    self.name = decoder.readString()
                elif attribId == ATTRIB_ID.id:
                    self.symbolId = decoder.readUnsignedInteger()
                elif attribId == ATTRIB_LABEL.id:
                    self.displayName = decoder.readString()
            decoder.closeElement(elemId)
        if not self.displayName:
            self.displayName = self.name


# =========================================================================
# EquateSymbol
# =========================================================================

class EquateSymbol(Symbol):
    """A Symbol that holds equate information for a constant."""

    def __init__(self, scope: Optional[Scope] = None, name: str = "",
                 format_: int = 0, val: int = 0) -> None:
        super().__init__(scope, name)
        self.value: int = val
        self.category = Symbol.equate
        if format_ > 0:
            self.setDisplayFormat(format_)

    def getValue(self) -> int:
        return self.value

    def setValue(self, val: int) -> None:
        self.value = val


# =========================================================================
# LabSymbol
# =========================================================================

class LabSymbol(Symbol):
    """A Symbol that labels code internal to a function."""

    def __init__(self, scope: Optional[Scope] = None, name: str = "") -> None:
        super().__init__(scope, name)

    def getType(self) -> int:
        return 4  # label type

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

    def getRefAddr(self) -> Address:
        return self.refaddr

    def setRefAddr(self, addr: Address) -> None:
        self.refaddr = addr

    def decode(self, decoder) -> None:
        """Decode an ExternRefSymbol from a stream.

        C++ ref: ``ExternRefSymbol::decode``
        """
        from ghidra.core.marshal import ELEM_EXTERNREFSYMBOL, ATTRIB_NAME
        elemId = decoder.openElement(ELEM_EXTERNREFSYMBOL)
        self.name = ""
        self.displayName = ""
        while True:
            attribId = decoder.getNextAttributeId()
            if attribId == 0:
                break
            if attribId == ATTRIB_NAME.id:
                self.name = decoder.readString()
        self.refaddr = Address.decode(decoder)
        if not self.displayName:
            self.displayName = self.name
        decoder.closeElement(elemId)


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
                 glb=None, fd=None) -> None:
        self.uniqueId: int = id_
        self.name: str = name
        self.displayName: str = name
        self.glb = glb  # Architecture
        self.fd = fd    # Funcdata
        self.parent: Optional[Scope] = None
        self.owner: Optional[Scope] = None
        self.children: Dict[int, Scope] = {}
        self.rangetree: RangeList = RangeList()

    def getName(self) -> str:
        return self.name

    def getDisplayName(self) -> str:
        return self.displayName

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

    def detachScope(self, child_id: int) -> None:
        child = self.children.pop(child_id, None)
        if child is not None:
            child.parent = None

    # --- Abstract methods ---

    @abstractmethod
    def addSymbol(self, sym: Symbol) -> None:
        ...

    @abstractmethod
    def removeSymbol(self, sym: Symbol) -> None:
        ...

    @abstractmethod
    def findByName(self, name: str) -> Optional[Symbol]:
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

    def isGlobal(self) -> bool:
        return self.parent is None or self.fd is None

    def setOwner(self, owner) -> None:
        self.owner = owner

    def getOwner(self):
        return self.owner

    def getRangeTree(self) -> RangeList:
        return self.rangetree

    # --- Query methods (virtual in C++) ---

    def queryByName(self, name: str) -> Optional[Symbol]:
        return self.findByName(name)

    def queryByAddr(self, addr: Address, sz: int) -> Optional[Symbol]:
        entry = self.findAddr(addr, Address())
        return entry.getSymbol() if entry else None

    def queryContainer(self, addr: Address, size: int, usepoint: Address) -> Optional[SymbolEntry]:
        return self.findContainer(addr, size, usepoint)

    def queryFunction(self, addr: Address) -> Optional[FunctionSymbol]:
        """Find a function starting at the given address.

        C++ ref: ``Scope::queryFunction`` in database.cc
        """
        res = self.findFunction(addr) if hasattr(self, 'findFunction') else None
        if res is not None:
            return res
        if self.parent is not None:
            return self.parent.queryFunction(addr)
        return None

    def queryExternalRefFunction(self, addr: Address) -> Optional[ExternRefSymbol]:
        """Find an external reference at the given address."""
        res = self.findExternalRef(addr) if hasattr(self, 'findExternalRef') else None
        if res is not None:
            return res
        if self.parent is not None:
            return self.parent.queryExternalRefFunction(addr)
        return None

    def queryCodeLabel(self, addr: Address) -> Optional[LabSymbol]:
        """Find a code label at the given address.

        C++ ref: ``Scope::queryCodeLabel`` in database.cc
        """
        res = self.findCodeLabel(addr) if hasattr(self, 'findCodeLabel') else None
        if res is not None:
            return res
        if self.parent is not None:
            return self.parent.queryCodeLabel(addr)
        return None

    def queryProperties(self, addr: Address, size: int, usepoint, flags_ref) -> None:
        """Query boolean properties of a memory range (base Scope implementation).

        C++ ref: ``Scope::queryProperties`` in database.cc
        Delegates to findClosestFit/findAddr, then falls back to scope-based flags.
        """
        from ghidra.ir.varnode import Varnode
        up = usepoint if usepoint else Address()
        entry = self.findClosestFit(addr, size, up) if hasattr(self, 'findClosestFit') else None
        if entry is None and hasattr(self, 'findAddr'):
            entry = self.findAddr(addr, up)
        flags = 0
        if entry is not None:
            flags = entry.getAllFlags()
        else:
            flags = Varnode.mapped | Varnode.addrtied
            if self.isGlobal():
                flags |= Varnode.persist
            if hasattr(self, 'glb') and self.glb is not None:
                db = getattr(self.glb, 'symboltab', None)
                if db is not None and hasattr(db, 'getProperty'):
                    flags |= db.getProperty(addr)
        if isinstance(flags_ref, list) and flags_ref:
            flags_ref[0] = flags

    # --- Symbol creation methods ---

    def addFunction(self, addr: Address, name: str, size: int = 1) -> Optional[FunctionSymbol]:
        return None

    def addEquateSymbol(self, name: str, format_: int, val: int) -> Optional[EquateSymbol]:
        return None

    def addCodeLabel(self, addr: Address, name: str) -> Optional[LabSymbol]:
        return None

    def addDynamicSymbol(self, name: str, ct, addr: Address, hash_: int) -> Optional[Symbol]:
        return None

    def addExternalRef(self, addr: Address, refaddr: Address, name: str) -> Optional[ExternRefSymbol]:
        return None

    def addUnionFacetSymbol(self, name: str, ct, fieldNum: int) -> Optional[Symbol]:
        return None

    def addMapPoint(self, sym: Symbol, addr: Address, usepoint: Address) -> Optional[SymbolEntry]:
        return None

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
            sym = FunctionSymbol(owner)
        elif subId == ELEM_LABELSYM.id:
            sym = LabSymbol(owner)
        elif subId == ELEM_EXTERNREFSYMBOL.id:
            sym = ExternRefSymbol(owner)
        else:
            sym = Symbol(owner)
        try:
            sym.decode(decoder)
        except (RecovError, Exception):
            decoder.closeElement(elemId)
            return None
        self.addSymbol(sym)
        while decoder.peekElement() != 0:
            entry = SymbolEntry(sym)
            entry.decode(decoder)
            if entry.isInvalid():
                self.removeSymbol(sym)
                decoder.closeElement(elemId)
                return None
            self.addMapEntry(sym, entry)
        decoder.closeElement(elemId)
        return sym

    # --- Symbol modification ---

    def renameSymbol(self, sym: Symbol, newname: str) -> None:
        sym.setName(newname)

    def retypeSymbol(self, sym: Symbol, ct) -> None:
        sym.setType(ct)

    def setAttribute(self, sym: Symbol, attr: int) -> None:
        sym.setFlags(attr)

    def clearAttribute(self, sym: Symbol, attr: int) -> None:
        sym.clearFlags(attr)

    def setCategory(self, sym: Symbol, cat: int, ind: int) -> None:
        sym.setCategory(cat, ind)

    def setDisplayFormat(self, sym: Symbol, val: int) -> None:
        sym.setDisplayFormat(val)

    def setThisPointer(self, sym: Symbol, val: bool) -> None:
        sym.setThisPointer(val)

    def overrideSizeLockType(self, sym: Symbol, ct) -> None:
        """Change the data-type of a size-locked Symbol.

        An exception is thrown if the new data-type doesn't fit the size.

        C++ ref: ``Scope::overrideSizeLockType``
        """
        if sym.type is not None and ct is not None:
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
        if sym.type is None:
            return
        from ghidra.types.datatype import MetaType
        if sym.type.getMetatype() == MetaType.TYPE_UNKNOWN:
            return
        size = sym.type.getSize()
        if self.glb is not None and hasattr(self.glb, 'types') and self.glb.types is not None:
            sym.type = self.glb.types.getBase(size, MetaType.TYPE_UNKNOWN)
        else:
            sym.type = None

    def removeSymbolMappings(self, sym: Symbol) -> None:
        sym.mapentry.clear()

    # --- Scope query/search ---

    def findOverlap(self, addr: Address, size: int) -> Optional[SymbolEntry]:
        """Find a SymbolEntry whose range overlaps the given range.

        C++ ref: ``ScopeInternal::findOverlap``
        """
        end = addr.getOffset() + size - 1
        for entries_list in self._entriesByAddr.values():
            for entry in entries_list:
                if entry.addr.getSpace() is not addr.getSpace():
                    continue
                if entry.isDynamic():
                    continue
                eFirst = entry.getFirst()
                eLast = entry.getLast()
                # Check for overlap: ranges [eFirst, eLast] and [addr.getOffset(), end]
                if eFirst <= end and eLast >= addr.getOffset():
                    return entry
        return None

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
            if thisPath[i] != op2Path[i]:
                return thisPath[i] if isinstance(thisPath[i], Scope) else self
        if minLen < len(thisPath):
            return self
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
        return self

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

    def getScopePath(self) -> List[str]:
        parts = []
        cur = self
        while cur is not None:
            parts.append(cur.name)
            cur = cur.parent
        parts.reverse()
        return parts

    # --- Iterators ---

    def begin(self):
        return iter([])

    def end(self):
        return None

    def beginDynamic(self):
        return iter([])

    def endDynamic(self):
        return None

    def childrenBegin(self):
        return iter(self.children.values())

    def childrenEnd(self):
        return None

    # --- Scope-level operations ---

    def clear(self) -> None:
        pass

    def clearUnlocked(self) -> None:
        """Remove all symbols that are not type-locked.

        C++ ref: ``ScopeInternal::clearUnlocked`` in database.cc
        """
        from ghidra.ir.varnode import Varnode
        for sym in list(self._symbolsByName.values()):
            for s in list(sym):
                if s.isTypeLocked():
                    if not s.isNameLocked():
                        if not s.isNameUndefined():
                            self.renameSymbol(s, self.buildUndefinedName())
                    self.clearAttribute(s, Varnode.nolocalalias)
                    if hasattr(s, 'isSizeTypeLocked') and s.isSizeTypeLocked():
                        if hasattr(self, 'resetSizeLockType'):
                            self.resetSizeLockType(s)
                elif hasattr(s, 'getCategory') and s.getCategory() == Symbol.equate:
                    continue
                else:
                    self.removeSymbol(s)

    def clearUnlockedCategory(self, cat: int) -> None:
        """Remove unlocked symbols in a specific category.

        C++ ref: ``ScopeInternal::clearUnlockedCategory`` in database.cc
        """
        if cat < 0:
            self.clearUnlocked()
            return
        catlist = self._category.get(cat, [])
        for sym in list(catlist):
            if sym.isTypeLocked():
                if not sym.isNameLocked():
                    if not sym.isNameUndefined():
                        self.renameSymbol(sym, self.buildUndefinedName())
                if hasattr(sym, 'isSizeTypeLocked') and sym.isSizeTypeLocked():
                    if hasattr(self, 'resetSizeLockType'):
                        self.resetSizeLockType(sym)
            else:
                self.removeSymbol(sym)

    def clearCategory(self, cat: int) -> None:
        """Remove all symbols in a given category."""
        catlist = self._category.get(cat, [])
        for sym in list(catlist):
            self.removeSymbol(sym)

    def adjustCaches(self) -> None:
        pass

    def getCategorySize(self, cat: int) -> int:
        """Return the number of symbols in a given category.

        C++ ref: ``ScopeInternal::getCategorySize`` in database.cc
        """
        if cat < 0:
            return 0
        catlist = self._category.get(cat, [])
        return len(catlist)

    def getCategorySymbol(self, cat: int, index: int) -> Optional[Symbol]:
        """Return a specific symbol in a given category by index.

        C++ ref: ``ScopeInternal::getCategorySymbol`` in database.cc
        """
        if cat < 0:
            return None
        catlist = self._category.get(cat, [])
        if index < 0 or index >= len(catlist):
            return None
        return catlist[index]

    # --- Encode / Decode ---

    def encode(self, encoder) -> None:
        pass

    def decode(self, decoder) -> None:
        pass

    def encodeRecursive(self, encoder) -> None:
        self.encode(encoder)
        for child in self.children.values():
            child.encodeRecursive(encoder)

    def decodeWrappingAttributes(self, decoder) -> None:
        pass

    # --- Misc ---

    def inScope(self, addr: Address, size: int, usepoint: Address) -> bool:
        return self.findContainer(addr, size, usepoint) is not None

    def inRange(self, addr: Address, size: int) -> bool:
        """Check if the given address range is owned by this Scope."""
        return self.rangetree.inRange(addr, size)

    def isNameUsed(self, name: str, scope: Optional['Scope'] = None) -> bool:
        return self.findByName(name) is not None

    def isReadOnly(self) -> bool:
        return False

    def makeNameUnique(self, name: str) -> str:
        if not self.isNameUsed(name):
            return name
        i = 1
        while True:
            candidate = f"{name}_{i}"
            if not self.isNameUsed(candidate):
                return candidate
            i += 1

    def buildDefaultName(self, sym: Symbol, base: int, addr: Address) -> str:
        return f"DAT_{addr.getOffset():08x}"

    def buildUndefinedName(self) -> str:
        return "$$undef"

    def buildVariableName(self, addr: Address, pc: Address, ct, index: int, flags: int) -> str:
        return f"local_{addr.getOffset():x}"

    def printBounds(self, s) -> None:
        s.write(f"Scope {self.name}")

    def printEntries(self, s) -> None:
        pass

    def turnOnDebug(self) -> None:
        pass

    def turnOffDebug(self) -> None:
        pass

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
                 glb=None, fd=None) -> None:
        super().__init__(id_, name, glb, fd)
        self._symbolsByName: Dict[str, List[Symbol]] = {}
        self._symbolsById: Dict[int, Symbol] = {}
        self._entriesByAddr: Dict[tuple, List[SymbolEntry]] = {}  # (space_idx, offset) -> entries
        self._nextSymId: int = Symbol.ID_BASE
        self._categoryMap: Dict[int, List[Symbol]] = {}

    def _assignSymbolId(self, sym: Symbol) -> None:
        if sym.symbolId == 0:
            sym.symbolId = self._nextSymId
            self._nextSymId += 1

    def addSymbol(self, sym: Symbol) -> None:
        self._assignSymbolId(sym)
        sym.scope = self
        self._symbolsById[sym.symbolId] = sym
        if sym.name not in self._symbolsByName:
            self._symbolsByName[sym.name] = []
        self._symbolsByName[sym.name].append(sym)
        if sym.category != Symbol.no_category:
            if sym.category not in self._categoryMap:
                self._categoryMap[sym.category] = []
            lst = self._categoryMap[sym.category]
            sym.catindex = len(lst)
            lst.append(sym)

    def removeSymbol(self, sym: Symbol) -> None:
        self._symbolsById.pop(sym.symbolId, None)
        lst = self._symbolsByName.get(sym.name)
        if lst:
            try:
                lst.remove(sym)
            except ValueError:
                pass
        # Remove entries
        for entry in sym.mapentry:
            if not entry.isDynamic():
                key = (entry.addr.getSpace().getIndex(), entry.addr.getOffset())
                elst = self._entriesByAddr.get(key)
                if elst:
                    try:
                        elst.remove(entry)
                    except ValueError:
                        pass
        sym.mapentry.clear()

    def findByName(self, name: str) -> Optional[Symbol]:
        lst = self._symbolsByName.get(name)
        if lst:
            return lst[0]
        return None

    def findById(self, id_: int) -> Optional[Symbol]:
        return self._symbolsById.get(id_)

    def findAddr(self, addr: Address, usepoint: Address) -> Optional[SymbolEntry]:
        key = (addr.getSpace().getIndex(), addr.getOffset())
        entries = self._entriesByAddr.get(key)
        if entries is None:
            return None
        for entry in entries:
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
        end = addr.getOffset() + size - 1
        for entries_list in self._entriesByAddr.values():
            for entry in entries_list:
                if entry.addr.getSpace() is not addr.getSpace():
                    continue
                if entry.getFirst() > addr.getOffset():
                    continue
                if entry.getLast() < end:
                    continue
                esz = entry.getSize()
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
        if entry.offset == 0 and sym.type is not None and entry.size == sym.type.getSize():
            sym.wholeCount += 1
        if not entry.isDynamic():
            key = (entry.addr.getSpace().getIndex(), entry.addr.getOffset())
            if key not in self._entriesByAddr:
                self._entriesByAddr[key] = []
            self._entriesByAddr[key].append(entry)
        return entry

    def addSymbolInternal(self, sym: Symbol, addr: Address, size: int) -> SymbolEntry:
        """Convenience: add a symbol and its primary map entry."""
        self.addSymbol(sym)
        entry = SymbolEntry(sym, addr, size)
        return self.addMapEntry(sym, entry)

    def begin(self):
        for entries in self._entriesByAddr.values():
            for entry in entries:
                yield entry

    def beginDynamic(self):
        for sym in self._symbolsById.values():
            for entry in sym.mapentry:
                if entry.isDynamic():
                    yield entry

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

    def findFunction(self, addr: Address) -> Optional[FunctionSymbol]:
        """Find a FunctionSymbol by entry address."""
        for sym in self._symbolsById.values():
            if isinstance(sym, FunctionSymbol):
                for entry in sym.mapentry:
                    if entry.addr == addr:
                        return sym
        return None

    def addFunction(self, addr: Address, name: str, size: int = 1) -> FunctionSymbol:
        """Create and add a FunctionSymbol."""
        fsym = FunctionSymbol(self, name, size)
        entry = SymbolEntry(fsym, addr, size)
        self.addSymbol(fsym)
        self.addMapEntry(fsym, entry)
        return fsym

    def addCodeLabel(self, addr: Address, name: str) -> LabSymbol:
        """Create and add a code label symbol."""
        lsym = LabSymbol(self, name)
        entry = SymbolEntry(lsym, addr, 1)
        self.addSymbol(lsym)
        self.addMapEntry(lsym, entry)
        return lsym

    def queryCodeLabel(self, addr: Address) -> Optional[LabSymbol]:
        """Find a code label symbol by exact address."""
        entry = self.findAddr(addr, Address())
        if entry is None:
            return None
        sym = entry.getSymbol()
        return sym if isinstance(sym, LabSymbol) else None

    def queryByAddr(self, addr: Address, sz: int) -> Optional[Symbol]:
        """Find a symbol that covers the given address range."""
        entry = self.findContainer(addr, sz, Address())
        if entry is not None:
            return entry.getSymbol()
        return None

    def queryProperties(self, addr: Address, size: int, usepoint, flags_ref) -> None:
        """Query boolean properties of the given address range.

        C++ ref: ``Scope::queryProperties`` in database.cc
        """
        from ghidra.ir.varnode import Varnode
        up = usepoint if usepoint else Address()
        # Try to find a containing symbol entry
        entry = self.findClosestFit(addr, size, up)
        if entry is None:
            entry = self.findAddr(addr, up)
        flags = 0
        if entry is not None:
            flags = entry.getAllFlags()
        else:
            # No symbol found — set flags based on scope properties
            flags = Varnode.mapped | Varnode.addrtied
            if self.isGlobal():
                flags |= Varnode.persist
            # Add property flags from the database
            if hasattr(self, 'glb') and self.glb is not None:
                db = getattr(self.glb, 'symboltab', None)
                if db is not None and hasattr(db, 'getProperty'):
                    flags |= db.getProperty(addr)
        if isinstance(flags_ref, list) and flags_ref:
            flags_ref[0] = flags

    def renameSymbol(self, sym: Symbol, newname: str) -> None:
        """Rename a symbol."""
        oldname = sym.name
        lst = self._symbolsByName.get(oldname)
        if lst:
            try:
                lst.remove(sym)
            except ValueError:
                pass
        sym.setName(newname)
        if newname not in self._symbolsByName:
            self._symbolsByName[newname] = []
        self._symbolsByName[newname].append(sym)

    def retypeSymbol(self, sym: Symbol, ct) -> None:
        """Change the data-type of a symbol."""
        sym.setType(ct)

    def setAttribute(self, sym: Symbol, attr: int) -> None:
        sym.setFlags(attr)

    def clearAttribute(self, sym: Symbol, attr: int) -> None:
        sym.clearFlags(attr)

    def setCategory(self, sym: Symbol, cat: int, ind: int) -> None:
        sym.setCategory(cat, ind)

    def findOverlap(self, addr: Address, size: int) -> Optional[SymbolEntry]:
        """Find any symbol entry that overlaps the given range."""
        for entries_list in self._entriesByAddr.values():
            for entry in entries_list:
                if entry.addr.getSpace() is not addr.getSpace():
                    continue
                e_start = entry.getFirst()
                e_end = entry.getLast()
                a_start = addr.getOffset()
                a_end = a_start + size - 1
                if e_start <= a_end and a_start <= e_end:
                    return entry
        return None

    def findClosestFit(self, addr: Address, size: int, usepoint: Address) -> Optional[SymbolEntry]:
        """Find the closest fitting symbol entry for the given range."""
        return self.findContainer(addr, size, usepoint)

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
        self._nextSymId = Symbol.ID_BASE

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
        if self._symbolsById:
            encoder.openElement(ELEM_SYMBOLLIST)
            for sym in self._symbolsById.values():
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
                    if hasattr(ent, 'encode'):
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
        subId = decoder.peekElement()
        if subId == ELEM_PARENT.id:
            decoder.skipElement()
            subId = decoder.peekElement()
        if subId == ELEM_RANGELIST.id:
            newrangetree = RangeList()
            newrangetree.decode(decoder)
            self.rangetree = newrangetree
        elif subId == ELEM_RANGEEQUALSSYMBOLS.id:
            decoder.openElement()
            decoder.closeElement(subId)
        subId = decoder.openElement(ELEM_SYMBOLLIST)
        if subId != 0:
            while True:
                symId = decoder.peekElement()
                if symId == 0:
                    break
                if symId == ELEM_MAPSYM.id:
                    self.addMapSym(decoder)
                elif symId == ELEM_HOLE.id:
                    decoder.skipElement()
                elif symId == ELEM_COLLISION.id:
                    decoder.skipElement()
                else:
                    decoder.skipElement()
            decoder.closeElement(subId)

    def printEntries(self, s) -> None:
        """Print all symbol entries to the given stream."""
        s.write(f"Scope {self.name}\n")
        for entries in self._entriesByAddr.values():
            for entry in entries:
                sym = entry.getSymbol()
                s.write(f"  {sym.name}: {entry.addr} size={entry.size}\n")

    def getNumSymbols(self) -> int:
        return len(self._symbolsById)

    def getNextSymbolId(self) -> int:
        return self._nextSymId


# =========================================================================
# Database
# =========================================================================

class Database:
    """The main symbol table container managing all Scopes.

    Contains the global scope and manages the full hierarchy of scopes
    (global, function-local, etc.).
    """

    def __init__(self, glb=None) -> None:
        self.glb = glb  # Architecture
        self._globalScope: Optional[ScopeInternal] = None
        self._scopeMap: Dict[int, Scope] = {}
        self._nextScopeId: int = 1
        self._flagbase: Dict = {}  # addr offset -> flags (simplified partmap)

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
        # Address-based: check if any non-global scope owns the address
        if self._globalScope is not None:
            for sc in self._scopeMap.values():
                if sc is self._globalScope:
                    continue
                if sc.fd is not None:
                    continue  # Skip function scopes
                if sc.rangetree.inRange(id_or_addr, 1):
                    return sc
        return self._globalScope

    def removeScope(self, scope: Scope) -> None:
        """Remove a scope and all its children."""
        for child_id in list(scope.children.keys()):
            child = scope.children[child_id]
            self.removeScope(child)
        self._scopeMap.pop(scope.uniqueId, None)
        if scope.parent is not None:
            scope.parent.detachScope(scope.uniqueId)

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
            # mapScope(qpoint, addr, usepoint) — resolve
            return scope_or_qpoint
        # mapScope(scope, spc, first, last) — add range
        scope_or_qpoint.addRange(addr_or_spc, first_or_usepoint, last)

    def encode(self, encoder) -> None:
        """Encode the entire Database to a stream.

        C++ ref: ``Database::encode``
        """
        from ghidra.core.marshal import ELEM_DB
        encoder.openElement(ELEM_DB)
        if self._globalScope is not None:
            self._globalScope.encodeRecursive(encoder)
        encoder.closeElement(ELEM_DB)

    def decode(self, decoder) -> None:
        """Decode the Database from a stream.

        C++ ref: ``Database::decode``
        """
        from ghidra.core.marshal import (
            ELEM_DB, ELEM_SCOPE, ELEM_PARENT, ELEM_PROPERTY_CHANGEPOINT,
            ATTRIB_NAME, ATTRIB_ID, ATTRIB_LABEL,
        )
        elemId = decoder.openElement(ELEM_DB)
        # Skip property changepoints
        while True:
            subId = decoder.peekElement()
            if subId != ELEM_PROPERTY_CHANGEPOINT.id:
                break
            decoder.skipElement()
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
            self._clearReferences(child)
        scope.children.clear()

    def _clearReferences(self, scope) -> None:
        """Recursively clear scope references from the id map."""
        for child in scope.children.values():
            self._clearReferences(child)
        self._scopeMap.pop(scope.uniqueId, None)

    def findCreateScope(self, id_: int, name: str, parent=None) -> Scope:
        """Find a Scope by id; create it if it doesn't exist.

        C++ ref: ``Database::findCreateScope``
        """
        res = self._scopeMap.get(id_)
        if res is not None:
            return res
        newscope = ScopeInternal(id_, name, self.glb)
        self._scopeMap[newscope.uniqueId] = newscope
        if parent is not None:
            parent.attachScope(newscope)
        elif self._globalScope is None:
            self._globalScope = newscope
        return newscope

    def addRange(self, scope, spc, first: int, last: int) -> None:
        """Add an address range to a scope's ownership.

        C++ ref: ``Database::addRange``
        """
        scope.addRange(spc, first, last)

    def removeRange(self, scope, spc, first: int, last: int) -> None:
        """Remove an address range from a scope's ownership.

        C++ ref: ``Database::removeRange``
        """
        scope.removeRange(spc, first, last)

    def clearUnlocked(self, scope) -> None:
        """Recursively clear unlocked symbols in a scope and its children.

        C++ ref: ``Database::clearUnlocked``
        """
        for child in scope.children.values():
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
        key = (id(spc), addr.getOffset())
        return self._flagbase.get(key, 0)

    def setPropertyRange(self, flags: int, rng) -> None:
        """Set boolean properties on an address range.

        C++ ref: ``Database::setPropertyRange`` in database.cc
        """
        if hasattr(rng, 'getFirstAddr') and hasattr(rng, 'getLastAddr'):
            first = rng.getFirstAddr()
            last = rng.getLastAddr()
        elif hasattr(rng, 'getSpace'):
            first = rng
            last = rng
        else:
            return
        spc = first.getSpace()
        if spc is None:
            return
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
        elif hasattr(rng, 'getSpace'):
            first = rng
            last = rng
        else:
            return
        spc = first.getSpace()
        if spc is None:
            return
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
