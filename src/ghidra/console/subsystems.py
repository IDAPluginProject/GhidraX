"""
Ghidra-backed subsystem implementations.

Each subsystem proxies requests back to the Ghidra client over the binary protocol.
Corresponds to:
  - loadimage_ghidra.hh/cc
  - database_ghidra.hh/cc
  - typegrp_ghidra.hh/cc
  - comment_ghidra.hh/cc
  - string_ghidra.hh/cc
  - cpool_ghidra.hh/cc
  - ghidra_translate.hh/cc
  - ghidra_context.hh/cc
  - inject_ghidra.hh/cc
"""

from __future__ import annotations

import logging
from typing import TYPE_CHECKING, Optional, Dict, List

from ghidra.core.address import Address, Range, RangeList
from ghidra.core.globalcontext import ContextBitRange, ContextDatabase, TrackedContext
from ghidra.core.marshal import (
    PackedDecode, XmlDecode,
    ATTRIB_BIGENDIAN, ATTRIB_DEFAULTSPACE, ATTRIB_UNIQBASE,
    ATTRIB_CONTENT, ATTRIB_ID, ATTRIB_NAME, ATTRIB_OFFSET, ATTRIB_SIZE,
    ATTRIB_SPACE, ATTRIB_TYPE, ATTRIB_LABEL, ATTRIB_TARGETOP,
    ATTRIB_READONLY, ATTRIB_VOLATILE,
    ELEM_SLEIGH, ELEM_SPACES, ELEM_SPACE, ELEM_SPACE_BASE,
    ELEM_SPACE_OTHER, ELEM_SPACE_OVERLAY, ELEM_SPACE_UNIQUE,
    ELEM_HOLE, ELEM_MAPSYM, ELEM_SYMBOL, ELEM_FUNCTION,
    ELEM_FUNCTIONSHELL, ELEM_LABELSYM, ELEM_EXTERNREFSYMBOL,
    ELEM_EQUATESYMBOL, ELEM_FACETSYMBOL,
    ELEM_PARENT, ELEM_VAL,
    ELEM_COMMENT, ELEM_COMMENTDB,
    ELEM_TRACKED_POINTSET, ELEM_TRACKED_SET, ELEM_TRUNCATE_SPACE, ELEM_UNIMPL,
    ELEM_ADDR, ELEM_CALLFIXUP, ELEM_CALLOTHERFIXUP, ELEM_CASE_PCODE,
    ELEM_CONTEXT, ELEM_DEFAULT_PCODE, ELEM_INPUT, ELEM_OUTPUT,
    ELEM_PCODE, ELEM_SIZE_PCODE, ELEM_ADDR_PCODE,
)
from ghidra.arch.inject import InjectContext, InjectPayload, PcodeInjectLibrary
from ghidra.arch.loadimage import LoadImage, DataUnavailError
from ghidra.console.protocol import JavaError
from ghidra.core.error import LowlevelError, DecoderError, BadDataError, UnimplError
from ghidra.core.space import (
    AddrSpace, ConstantSpace, OtherSpace, OverlaySpace, SpacebaseSpace,
    UniqueSpace, IPTR_PROCESSOR,
)
from ghidra.core.translate import TruncationTag
from ghidra.database.comment import Comment, CommentDatabaseInternal
from ghidra.database.stringmanage import StringData, StringManager
from ghidra.database.cpool import ConstantPool, ConstantPoolInternal, CPoolRecord
from ghidra.database.database import (
    Scope, ScopeInternal, SymbolEntry, Symbol,
    ExternRefSymbol, LabSymbol, FunctionSymbol,
)
from ghidra.types.datatype import TypeFactory, Datatype
from ghidra.core.pcoderaw import VarnodeData
from ghidra.ir.varnode import Varnode

if TYPE_CHECKING:
    from ghidra.console.ghidra_arch import ArchitectureGhidra
    from ghidra.core.space import AddrSpace
    from ghidra.core.marshal import Encoder, Decoder
    from ghidra.analysis.funcdata import Funcdata

log = logging.getLogger(__name__)


# =========================================================================
# LoadImageGhidra
# =========================================================================

class LoadImageGhidra(LoadImage):
    """LoadImage that proxies byte requests to the Ghidra client.

    C++ ref: ``loadimage_ghidra.hh``
    """

    def __init__(self, glb: ArchitectureGhidra) -> None:
        super().__init__("ghidra_progam")
        self.glb: ArchitectureGhidra = glb
        self._glb: ArchitectureGhidra = glb

    def open(self) -> None:
        return None

    def close(self) -> None:
        return None

    def loadFill(self, buf: bytearray, size: int, addr: Address) -> None:
        try:
            data = self.glb.getBytes(size, addr)
            if data is not None:
                for i in range(min(size, len(data))):
                    buf[i] = data[i]
                for i in range(len(data), size):
                    buf[i] = 0
            else:
                for i in range(size):
                    buf[i] = 0
        except DataUnavailError:
            for i in range(size):
                buf[i] = 0

    def getArchType(self) -> str:
        return "ghidra"

    def adjustVma(self, adjust: int) -> None:
        raise LowlevelError("Cannot adjust GHIDRA virtual memory")


# =========================================================================
# ScopeGhidra
# =========================================================================

class ScopeGhidra(ScopeInternal):
    """Global scope that queries Ghidra for symbols on cache miss.

    C++ ref: ``database_ghidra.hh``
    """

    def __init__(self, glb: ArchitectureGhidra) -> None:
        super().__init__(0, "", glb)
        self._ghidra: ArchitectureGhidra = glb
        self._holes: RangeList = RangeList()
        self._spacerange: list[int] = []
        self._flagbaseDefault: Dict = {}
        self._cacheDirty: bool = False
        self.setOwner(self)

    def buildSubScope(self, id_: int, nm: str):
        return ScopeGhidraNamespace(id_, nm, self._ghidra)

    def reresolveScope(self, id_: int):
        if id_ == 0:
            return self
        symboltab = self._ghidra.symboltab
        cacheScope = symboltab.resolveScope(id_)
        if cacheScope is not None:
            return cacheScope
        decoder = PackedDecode(self._ghidra)
        if not self._ghidra.getNamespacePath(id_, decoder):
            raise LowlevelError("Could not get namespace info")
        return symboltab.decodeScopePath(decoder)

    def decodeHole(self, decoder: PackedDecode) -> None:
        hole_id = decoder.openElement(ELEM_HOLE)
        flags = 0
        rng = Range()
        rng.decodeFromAttributes(decoder)
        decoder.rewindAttributes()
        while True:
            attribId = decoder.getNextAttributeId()
            if attribId == 0:
                break
            if attribId == ATTRIB_READONLY.id and decoder.readBool():
                flags |= Varnode.readonly
            elif attribId == ATTRIB_VOLATILE.id and decoder.readBool():
                flags |= Varnode.volatil
        self._holes.insertRange(rng.getSpace(), rng.getFirst(), rng.getLast())
        decoder.closeElement(hole_id)
        if flags != 0:
            self._ghidra.symboltab.setPropertyRange(flags, rng)
            self._cacheDirty = True

    def _decodeHole(self, decoder: PackedDecode) -> None:
        self.decodeHole(decoder)

    def _createMappedSymbol(self, scope, sub_id: int) -> Symbol:
        owner = scope.getOwner() if hasattr(scope, "getOwner") and scope.getOwner() is not None else scope
        if sub_id == ELEM_SYMBOL.id:
            return Symbol(owner)
        if sub_id == ELEM_EQUATESYMBOL.id:
            return Symbol(owner)
        if sub_id in (ELEM_FUNCTION.id, ELEM_FUNCTIONSHELL.id):
            return FunctionSymbol(owner, "", getattr(self._ghidra, "min_funcsymbol_size", 1))
        if sub_id == ELEM_LABELSYM.id:
            return LabSymbol(owner, "")
        if sub_id == ELEM_EXTERNREFSYMBOL.id:
            return ExternRefSymbol(owner)
        if sub_id == ELEM_FACETSYMBOL.id:
            return Symbol(owner)
        raise LowlevelError(f"Unknown symbol type id {sub_id} in <mapsym>")

    def _addMapSym(self, scope, decoder: PackedDecode) -> Optional[Symbol]:
        mapsym_id = decoder.openElement(ELEM_MAPSYM)
        sub_id = decoder.peekElement()
        sym = self._createMappedSymbol(scope, sub_id)
        sym.decode(decoder)
        entries: List[SymbolEntry] = []
        while decoder.peekElement() != 0:
            entry = SymbolEntry(sym)
            entry.decode(decoder)
            if entry.isInvalid():
                decoder.closeElement(mapsym_id)
                return None
            entries.append(entry)
        decoder.closeElement(mapsym_id)

        if isinstance(sym, FunctionSymbol) and entries:
            target_addr = entries[0].getAddr()
            for old_sym in getattr(scope, "_symbolsByName", {}).get(sym.name, []):
                if isinstance(old_sym, FunctionSymbol):
                    old_entry = old_sym.getFirstWholeMap()
                    if old_entry is not None and old_entry.getAddr() == target_addr:
                        return old_sym

        if hasattr(scope, "_addSymbolDirect"):
            scope._addSymbolDirect(sym)
        else:
            scope.addSymbol(sym)
        for entry in entries:
            scope.addMapEntry(sym, entry)
        return sym

    def dump2Cache(self, decoder: PackedDecode) -> Optional[Symbol]:
        sym: Optional[Symbol] = None
        elemId = decoder.peekElement()
        if elemId == ELEM_HOLE.id:
            self.decodeHole(decoder)
            return None

        decoder.openElement()
        scopeId = decoder.readUnsignedInteger(ATTRIB_ID)
        scope = self.reresolveScope(scopeId)
        sym = self._addMapSym(scope, decoder)
        decoder.closeElement(elemId)

        if sym is not None:
            entry = sym.getFirstWholeMap()
            if entry is not None:
                if scope is not self:
                    spc = entry.getAddr().getSpace()
                    first = entry.getAddr().getOffset()
                    last = first + entry.getSize() - 1
                    self._holes.insertRange(spc, first, last)
                props = sym.getFlags() & (Varnode.readonly | Varnode.volatil)
                if props != 0:
                    rng = Range(entry.getAddr().getSpace(), entry.getFirst(), entry.getLast())
                    self._ghidra.symboltab.setPropertyRange(props, rng)
                    self._cacheDirty = True
        return sym

    def _dump2Cache(self, decoder: PackedDecode) -> Optional[Symbol]:
        return self.dump2Cache(decoder)

    def removeQuery(self, addr: Address) -> Optional[Symbol]:
        spc = addr.getSpace()
        if spc is None:
            return None
        ind = spc.getIndex()
        if ind >= len(self._spacerange):
            return None
        if self._spacerange[ind] == 0:
            return None
        if self._holes.inRange(addr, 1):
            return None
        decoder = PackedDecode(self._ghidra)
        if not self._ghidra.getMappedSymbolsXML(addr, decoder):
            return None
        return self.dump2Cache(decoder)

    def lockDefaultProperties(self) -> None:
        self._flagbaseDefault = self._ghidra.symboltab.getProperties()
        self._cacheDirty = False

    def __del__(self) -> None:
        return None

    def _cacheFindFirstByName(self, name: str) -> Optional[Symbol]:
        return ScopeInternal.findByName(self, name)

    def _cacheMakeNameUnique(self, name: str) -> str:
        if self._cacheFindFirstByName(name) is None:
            return name

        uniqid = None
        prefix = f"{name}_"
        for sym_name in self._symbolsByName.keys():
            if not sym_name.startswith(prefix):
                continue
            suffix = sym_name[len(prefix):]
            is_xform = suffix.startswith("x")
            digits = suffix[1:] if is_xform else suffix
            if not digits.isdigit():
                continue
            if is_xform:
                if len(digits) != 5:
                    continue
            elif len(digits) != 2:
                continue
            value = int(digits)
            if uniqid is None or value > uniqid:
                uniqid = value

        if uniqid is None:
            result = f"{name}_00"
        else:
            uniqid += 1
            if uniqid < 100:
                result = f"{name}_{uniqid:02d}"
            else:
                result = f"{name}_x{uniqid:05d}"
        if self._cacheFindFirstByName(result) is not None:
            raise LowlevelError(f"Unable to uniquify name: {result}")
        return result

    def buildVariableName(
        self,
        addr: Address,
        pc: Address,
        ct: Optional[Datatype],
        index: int,
        flags: int,
    ) -> str:
        from ghidra.core.space import AddrSpace

        sz = 1 if ct is None else ct.getSize()

        def _make_name_unique(name: str) -> str:
            return self._cacheMakeNameUnique(name)

        def _regname() -> str:
            if self.glb is not None and hasattr(self.glb, "translate") and self.glb.translate is not None:
                nm = self.glb.translate.getRegisterName(
                    addr.getSpace(), addr.getOffset(), sz
                ) if hasattr(self.glb.translate, "getRegisterName") else ""
                return nm if nm else ""
            return ""

        if (flags & Varnode.unaffected) != 0:
            if (flags & Varnode.return_address) != 0:
                return _make_name_unique("unaff_retaddr")
            rn = _regname()
            if rn:
                return _make_name_unique(f"unaff_{rn}")
            return _make_name_unique(f"unaff_{addr.getOffset():08x}")

        if (flags & Varnode.persist) != 0:
            rn = _regname()
            if rn:
                return _make_name_unique(rn)
            s = ""
            if ct is not None and hasattr(ct, "printNameBase"):
                buf = []
                ct.printNameBase(buf)
                s += "".join(buf)
            spacename = addr.getSpace().getName() if addr.getSpace() is not None else "mem"
            spacename = spacename[0].upper() + spacename[1:]
            s += spacename
            addrSize = addr.getAddrSize() if hasattr(addr, "getAddrSize") else 4
            wordSize = addr.getSpace().getWordSize() if addr.getSpace() is not None and hasattr(addr.getSpace(), "getWordSize") else 1
            off = AddrSpace.byteToAddress(addr.getOffset(), wordSize)
            s += f"{off:0{2 * addrSize}x}"
            return _make_name_unique(s)

        if (flags & Varnode.input) != 0 and index < 0:
            rn = _regname()
            if rn:
                return _make_name_unique(f"in_{rn}")
            sn = addr.getSpace().getName() if addr.getSpace() is not None else "mem"
            return _make_name_unique(f"in_{sn}_{addr.getOffset():08x}")

        if (flags & Varnode.input) != 0:
            return _make_name_unique(f"param_{index}")

        if (flags & Varnode.addrtied) != 0:
            s = ""
            if ct is not None and hasattr(ct, "printNameBase"):
                buf = []
                ct.printNameBase(buf)
                s += "".join(buf)
            spacename = addr.getSpace().getName() if addr.getSpace() is not None else "mem"
            spacename = spacename[0].upper() + spacename[1:]
            s += spacename
            addrSize = addr.getAddrSize() if hasattr(addr, "getAddrSize") else 4
            wordSize = addr.getSpace().getWordSize() if addr.getSpace() is not None and hasattr(addr.getSpace(), "getWordSize") else 1
            off = AddrSpace.byteToAddress(addr.getOffset(), wordSize)
            s += f"{off:0{2 * addrSize}x}"
            return _make_name_unique(s)

        if (flags & Varnode.indirect_creation) != 0:
            rn = _regname()
            if rn:
                return _make_name_unique(f"extraout_{rn}")
            return _make_name_unique("extraout_var")

        def _namebase(datatype: Optional[Datatype]) -> str:
            buf = []
            if datatype is not None and hasattr(datatype, "printNameBase"):
                datatype.printNameBase(buf)
            return "".join(buf)

        s = _namebase(ct) + f"Var{index}"
        index += 1
        if self._cacheFindFirstByName(s) is not None:
            for _ in range(10):
                s2 = _namebase(ct) + f"Var{index}"
                index += 1
                if self._cacheFindFirstByName(s2) is None:
                    return s2
        return _make_name_unique(s)

    def findAddr(self, addr: Address, usepoint: Address) -> Optional[SymbolEntry]:
        entry = super().findAddr(addr, usepoint)
        if entry is None:
            entry = super().findContainer(addr, 1, Address())
            if entry is not None:
                return None
            sym = self.removeQuery(addr)
            if sym is not None:
                entry = sym.getMapEntry(addr)
        if entry is not None and entry.getAddr() == addr:
            return entry
        return None

    def findContainer(self, addr: Address, size: int, usepoint: Address) -> Optional[SymbolEntry]:
        entry = Scope.findClosestFit(self, addr, size, usepoint)
        if entry is None:
            sym = self.removeQuery(addr)
            if sym is not None:
                entry = sym.getMapEntry(addr)
        if entry is not None:
            last = entry.getAddr().getOffset() + entry.getSize() - 1
            if last >= addr.getOffset() + size - 1:
                return entry
        return None

    def findClosestFit(self, addr: Address, size: int, usepoint: Address) -> Optional[SymbolEntry]:
        raise LowlevelError("findClosestFit unimplemented")

    def findFunction(self, addr: Address) -> Optional[Funcdata]:
        resFd = None
        entry = ScopeInternal.findAddr(self, addr, Address())
        if entry is not None:
            sym = entry.getSymbol()
            if isinstance(sym, FunctionSymbol):
                resFd = sym.getFunction()
        if resFd is None:
            entry = ScopeInternal.findContainer(self, addr, 1, Address())
            if entry is None:
                sym = self.removeQuery(addr)
                if isinstance(sym, FunctionSymbol):
                    resFd = sym.getFunction()
        return resFd

    def findExternalRef(self, addr: Address) -> Optional[ExternRefSymbol]:
        sym = None
        entry = ScopeInternal.findAddr(self, addr, Address())
        if entry is not None:
            entry_sym = entry.getSymbol()
            if isinstance(entry_sym, ExternRefSymbol):
                sym = entry_sym
        if sym is None:
            entry = ScopeInternal.findContainer(self, addr, 1, Address())
            if entry is None:
                remote_sym = self.removeQuery(addr)
                if isinstance(remote_sym, ExternRefSymbol):
                    sym = remote_sym
        return sym

    def findCodeLabel(self, addr: Address) -> Optional[LabSymbol]:
        entry = ScopeInternal.findAddr(self, addr, Address())
        if entry is not None:
            sym = entry.getSymbol()
            if isinstance(sym, LabSymbol):
                return sym
            return None
        label = self._ghidra.getCodeLabel(addr)
        if label:
            return ScopeInternal.addCodeLabel(self, addr, label)
        return None

    def resolveExternalRefFunction(self, sym: ExternRefSymbol) -> Optional[Funcdata]:
        resFd = None
        refaddr = sym.getRefAddr()
        basescope = self._ghidra.symboltab.mapScope(self, refaddr, Address())
        curscope = basescope
        visited = set()
        while curscope is not None and curscope is not self and id(curscope) not in visited:
            visited.add(id(curscope))
            resFd = curscope.findFunction(refaddr)
            if resFd is not None:
                return resFd
            if curscope.inScope(refaddr, 1, Address()):
                break
            curscope = curscope.getParent()
        entry = ScopeInternal.findAddr(self, refaddr, Address())
        if entry is not None:
            entry_sym = entry.getSymbol()
            if isinstance(entry_sym, FunctionSymbol):
                resFd = entry_sym.getFunction()
        if resFd is None:
            entry = sym.getFirstWholeMap()
            if entry is not None:
                decoder = PackedDecode(self._ghidra)
                if self._ghidra.getExternalRef(entry.getAddr(), decoder):
                    func_sym = self.dump2Cache(decoder)
                    if isinstance(func_sym, FunctionSymbol):
                        resFd = func_sym.getFunction()
        return resFd

    def findOverlap(self, addr: Address, size: int) -> Optional[SymbolEntry]:
        raise LowlevelError("findOverlap unimplemented")

    def findByName(self, nm: str, res=None) -> None:
        raise LowlevelError("findByName unimplemented")

    def isNameUsed(self, nm: str, op2: Optional[Scope] = None) -> bool:
        raise LowlevelError("isNameUsed unimplemented")

    def begin(self):
        raise LowlevelError("begin unimplemented")

    def end(self):
        raise LowlevelError("end unimplemented")

    def beginDynamic(self):
        raise LowlevelError("beginDynamic unimplemented")

    def endDynamic(self):
        raise LowlevelError("endDynamic unimplemented")

    def clearCategory(self, cat: int) -> None:
        raise LowlevelError("clearCategory unimplemented")

    def clearUnlockedCategory(self, cat: int) -> None:
        raise LowlevelError("clearUnlockedCategory unimplemented")

    def clearUnlocked(self) -> None:
        raise LowlevelError("clearUnlocked unimplemented")

    def restrictScope(self, fd) -> None:
        raise LowlevelError("restrictScope unimplemented")

    def removeSymbolMappings(self, symbol: Symbol) -> None:
        raise LowlevelError("removeSymbolMappings unimplemented")

    def removeSymbol(self, symbol: Symbol) -> None:
        raise LowlevelError("removeSymbol unimplemented")

    def renameSymbol(self, sym: Symbol, newname: str) -> None:
        raise LowlevelError("renameSymbol unimplemented")

    def retypeSymbol(self, sym: Symbol, ct: Optional[Datatype]) -> None:
        raise LowlevelError("retypeSymbol unimplemented")

    def makeNameUnique(self, nm: str) -> str:
        raise LowlevelError("makeNameUnique unimplemented")

    def encode(self, encoder) -> None:
        raise LowlevelError("encode unimplemented")

    def decode(self, decoder) -> None:
        raise LowlevelError("decode unimplemented")

    def printEntries(self, s) -> None:
        raise LowlevelError("printEntries unimplemented")

    def getCategorySize(self, cat: int) -> int:
        raise LowlevelError("getCategorySize unimplemented")

    def getCategorySymbol(self, cat: int, ind: int) -> Optional[Symbol]:
        raise LowlevelError("getCategorySymbol unimplemented")

    def setCategory(self, sym: Symbol, cat: int, ind: int) -> None:
        raise LowlevelError("setCategory unimplemented")

    def queryFunction(self, addr: Address) -> Optional[Funcdata]:
        """Query for a function at the given address, creating one if found remotely."""
        fd = self.findFunction(addr)
        if fd is not None:
            return fd
        decoder = PackedDecode(self._ghidra)
        if self._ghidra.getMappedSymbolsXML(addr, decoder):
            self.dump2Cache(decoder)
            return super().findFunction(addr)
        return None

    def _remoteQuery(self, addr: Address) -> Optional[SymbolEntry]:
        """Query the Ghidra client for symbols at addr."""
        sym = self.removeQuery(addr)
        if sym is None:
            return None
        return sym.getFirstWholeMap()

    def _parseResponse(self, resp: bytes, addr: Address) -> Optional[SymbolEntry]:
        """Decode a packed response from the Ghidra client and cache the result.

        Mirrors C++ ``ScopeGhidra::dump2Cache``.
        """
        decoder = PackedDecode(self._ghidra)
        decoder.ingestBytes(resp)
        sym = self.dump2Cache(decoder)
        if sym is None:
            return None
        return sym.getFirstWholeMap()

    def addRange(self, spc, first: int, last: int) -> None:
        super().addRange(spc, first, last)
        ind = spc.getIndex()
        while len(self._spacerange) <= ind:
            self._spacerange.append(0)
        self._spacerange[ind] = 1

    def removeRange(self, spc, first: int, last: int) -> None:
        raise LowlevelError("remove_range should not be performed on ghidra scope")

    def _addSymbolDirect(self, sym: Symbol) -> None:
        self._assignSymbolId(sym)
        if not sym.name:
            sym.name = self.buildUndefinedName()
            sym.displayName = sym.name
        sym.scope = self
        self._symbolsById[sym.symbolId] = sym
        if sym.name not in self._symbolsByName:
            self._symbolsByName[sym.name] = []
        self._symbolsByName[sym.name].append(sym)
        if sym.category >= 0:
            if sym.category not in self._categoryMap:
                self._categoryMap[sym.category] = []
            lst = self._categoryMap[sym.category]
            if sym.category > 0:
                sym.catindex = len(lst)
            while len(lst) <= sym.catindex:
                lst.append(None)
            lst[sym.catindex] = sym

    def addSymbolInternal(self, sym: Symbol) -> None:
        self._addSymbolDirect(sym)

    def addMapInternal(self, sym: Symbol, exfl: int, addr: Address, off: int, sz: int, uselim) -> SymbolEntry:
        raise LowlevelError("addMap unimplemented")

    def addDynamicMapInternal(self, sym: Symbol, exfl: int, hash_: int, off: int, sz: int, uselim) -> SymbolEntry:
        raise LowlevelError("addMap unimplemented")

    def _holes_insert(self, spc, first: int, last: int) -> None:
        """Record that address range [first,last] in spc has been queried."""
        self._holes.insertRange(spc, first, last)

    def _inHoles(self, addr: Address) -> bool:
        """Check if addr was already queried (in a hole)."""
        return self._holes.inRange(addr, 1)

    def clear(self) -> None:
        for sym in list(self._symbolsById.values()):
            ScopeInternal.removeSymbol(self, sym)
        self._nextSymId = Symbol.ID_BASE
        self._holes.clear()
        if self._cacheDirty:
            self._ghidra.symboltab.setProperties(self._flagbaseDefault)
            self._cacheDirty = False


class ScopeGhidraNamespace(ScopeInternal):
    def __init__(self, id_: int, nm: str, glb: ArchitectureGhidra) -> None:
        super().__init__(id_, nm, glb)
        self._ghidra: ArchitectureGhidra = glb

    def addMapInternal(self, sym: Symbol, exfl: int, addr: Address, off: int, sz: int, uselim) -> SymbolEntry:
        entry = SymbolEntry(sym, addr, sz, off, exfl)
        if uselim is not None:
            entry.setUseLimit(uselim)
        return self.addMapEntry(sym, entry)

    def addMapEntry(self, sym: Symbol, entry: SymbolEntry) -> SymbolEntry:
        res = super().addMapEntry(sym, entry)
        self.glb.symboltab.addRange(self, res.getAddr().getSpace(), res.getFirst(), res.getLast())
        return res

    def isNameUsed(self, nm: str, op2: Optional[Scope] = None) -> bool:
        if self._ghidra.isDynamicSymbolName(nm):
            return False
        other_id = op2.getId() if isinstance(op2, ScopeGhidraNamespace) else 0
        return self._ghidra.isNameUsed(nm, self.getId(), other_id)


# =========================================================================
# TypeFactoryGhidra
# =========================================================================

class TypeFactoryGhidra(TypeFactory):
    """TypeFactory that queries Ghidra for unknown types.

    C++ ref: ``typegrp_ghidra.hh``
    """

    def __init__(self, glb: ArchitectureGhidra) -> None:
        super().__init__(glb)
        self._ghidra: ArchitectureGhidra = glb

    def __del__(self) -> None:
        return None

    def findById(self, n: str | int, id_: Optional[int] = None, sz: Optional[int] = None) -> Optional[Datatype]:
        """Override: query Ghidra when a type isn't found locally."""
        if id_ is None:
            name = ""
            type_id = int(n)
        else:
            name = str(n)
            type_id = id_

        result = super().findById(type_id)
        if result is not None:
            return result
        decoder = PackedDecode(self._ghidra)
        try:
            if not self._ghidra.getDataType(name, type_id, decoder):
                return None
        except DecoderError as err:
            raise LowlevelError("Decoder error: " + err.explain)
        return self.decodeType(decoder)


# =========================================================================
# CommentDatabaseGhidra
# =========================================================================

class CommentDatabaseGhidra(CommentDatabaseInternal):
    """CommentDatabase that fetches comments from Ghidra on demand.

    C++ ref: ``comment_ghidra.hh``
    """

    def __init__(self, glb: ArchitectureGhidra) -> None:
        super().__init__()
        self._ghidra: ArchitectureGhidra = glb
        self._cachefilled: bool = False

    def clear(self) -> None:
        super().clear()
        self._cachefilled = False

    def fillCache(self, funcaddr: Address) -> None:
        if self._cachefilled:
            return
        self._cachefilled = True
        commentfilter = self._ghidra.print_.getHeaderComment()
        commentfilter |= self._ghidra.print_.getInstructionComment()
        if commentfilter == 0:
            return
        decoder = PackedDecode(self._ghidra)
        if self._ghidra.getComments(funcaddr, commentfilter, decoder):
            self._decodeComments(decoder)

    def _fillCache(self, funcaddr: Address) -> None:
        self.fillCache(funcaddr)

    def clearType(self, fad: Address, tp: int) -> None:
        super().clearType(fad, tp)

    def addComment(self, tp: int, fad: Address, ad: Address, txt: str) -> None:
        super().addComment(tp, fad, ad, txt)

    def addCommentNoDuplicate(self, tp: int, fad: Address, ad: Address, txt: str) -> bool:
        return super().addCommentNoDuplicate(tp, fad, ad, txt)

    def deleteComment(self, com: Comment) -> None:
        raise LowlevelError("deleteComment unimplemented")

    def beginComment(self, fad: Address):
        self.fillCache(fad)
        return super().beginComment(fad)

    def endComment(self, fad: Address):
        return super().endComment(fad)

    def encode(self, encoder) -> None:
        raise LowlevelError("commentdb::encode unimplemented")

    def decode(self, decoder) -> None:
        raise LowlevelError("CommentDatabaseGhidra::decode unimplemented")

    def _decodeComments(self, decoder: PackedDecode) -> None:
        """Decode <commentdb> packed response and add comments to cache.

        C++ ref: ``CommentDatabaseInternal::decode``
        """
        db_id = decoder.openElement(ELEM_COMMENTDB)
        while decoder.peekElement() != 0:
            cmt_id = decoder.openElement(ELEM_COMMENT)
            ctype_str = decoder.readString(ATTRIB_TYPE)
            ctype = Comment.encodeCommentType(ctype_str)
            faddr = Address.decode(decoder)
            caddr = Address.decode(decoder)
            text = ""
            sub = decoder.peekElement()
            if sub != 0:
                decoder.openElement()
                text = decoder.readString(ATTRIB_CONTENT)
                decoder.closeElement(sub)
            decoder.closeElement(cmt_id)
            self.addComment(ctype, faddr, caddr, text)
        decoder.closeElement(db_id)


# =========================================================================
# GhidraStringManager
# =========================================================================

class GhidraStringManager(StringManager):
    """StringManager that queries Ghidra for string data.

    C++ ref: ``string_ghidra.hh``
    """

    def __init__(self, glb: ArchitectureGhidra, max_chars: int = 2048) -> None:
        super().__init__(max_chars)
        self.glb: ArchitectureGhidra = glb
        self._ghidra: ArchitectureGhidra = glb
        self.testBuffer: Optional[bytearray] = bytearray(max_chars)

    def __del__(self) -> None:
        self.testBuffer = None

    def getStringData(self, addr: Address, charType: Datatype, isTrunc=None):
        cached = self._stringMap.get(addr)
        if cached is not None:
            return self._format_get_string_data_result(cached.byteData, cached.isTruncated, isTrunc)

        string_data = StringData()
        resp = self.glb.getStringData(addr, charType, self.maximumChars)
        if resp is not None:
            string_data.byteData, string_data.isTruncated = resp
        self._stringMap[addr] = string_data
        return self._format_get_string_data_result(string_data.byteData, string_data.isTruncated, isTrunc)


# =========================================================================
# ConstantPoolGhidra
# =========================================================================

class ConstantPoolGhidra(ConstantPool):
    """ConstantPool backed by a Ghidra client.

    C++ ref: ``cpool_ghidra.hh``
    """

    def __init__(self, glb: ArchitectureGhidra) -> None:
        super().__init__()
        self._ghidra: ArchitectureGhidra = glb
        self.cache: ConstantPoolInternal = ConstantPoolInternal()
        self._pool = self.cache._pool

    def createRecord(self, refs: List[int]) -> CPoolRecord:
        raise LowlevelError("Cannot access constant pool with this method")

    def getRecord(self, refs: List[int]) -> Optional[CPoolRecord]:
        cached = self.cache.getRecord(refs)
        if cached is not None:
            return cached
        decoder = PackedDecode(self._ghidra)
        try:
            success = self._ghidra.getCPoolRef(refs, decoder)
        except JavaError as err:
            raise LowlevelError("Error fetching constant pool record: " + err.explain) from err
        except DecoderError as err:
            raise LowlevelError("Error in constant pool record encoding: " + err.explain) from err
        if not success:
            raise LowlevelError(f"Could not retrieve constant pool record for reference: 0x{refs[0]:x}")
        try:
            rec = self.decodeRecord(refs, decoder, self._ghidra.types)
            self._pool = self.cache._pool
            return rec
        except DecoderError as err:
            raise LowlevelError("Error in constant pool record encoding: " + err.explain) from err

    def empty(self) -> bool:
        return False

    def clear(self) -> None:
        self.cache.clear()
        self._pool = self.cache._pool

    def decodeRecord(self, refs: List[int], decoder, typegrp) -> Optional[CPoolRecord]:
        return self.cache.decodeRecord(refs, decoder, typegrp)

    def storeRecord(self, refs: List[int], rec: CPoolRecord) -> None:
        self.cache.storeRecord(refs, rec)
        self._pool = self.cache._pool

    def encode(self, encoder) -> None:
        raise LowlevelError("Cannot access constant pool with this method")

    def decode(self, decoder, typegrp) -> None:
        raise LowlevelError("Cannot access constant pool with this method")


# =========================================================================
# GhidraTranslate
# =========================================================================

class GhidraTranslate:
    """Translate that queries Ghidra for p-code and register info.

    C++ ref: ``ghidra_translate.hh``

    This is a lightweight proxy. Real translation is done by the Ghidra client.
    """

    def __init__(self, glb: ArchitectureGhidra) -> None:
        self._glb: ArchitectureGhidra = glb
        self._nm2addr: Dict[str, VarnodeData] = {}
        self._addr2nm: Dict[VarnodeData, str] = {}
        self._spaces: list = []
        self._default_code_space = None
        self._default_data_space = None
        self._unique_space = None
        self._const_space = None
        self._stack_space = None
        self._unique_base: int = 0
        self._big_endian: bool = False

    def cacheRegister(self, nm: str, data: VarnodeData) -> VarnodeData:
        self._nm2addr[nm] = data
        self._addr2nm[data] = nm
        return self._nm2addr[nm]

    def _insertSpace(self, spc: AddrSpace) -> None:
        while len(self._spaces) <= spc.getIndex():
            self._spaces.append(None)
        self._spaces[spc.getIndex()] = spc
        if isinstance(spc, ConstantSpace):
            self._const_space = spc
        elif isinstance(spc, UniqueSpace):
            self._unique_space = spc
        elif isinstance(spc, SpacebaseSpace) and spc.getName() == "stack":
            self._stack_space = spc

    def _decodeSpace(self, decoder: Decoder) -> AddrSpace:
        elem_id = decoder.peekElement()
        if elem_id == ELEM_SPACE_BASE.id:
            spc = SpacebaseSpace(self, self)
        elif elem_id == ELEM_SPACE_UNIQUE.id:
            spc = UniqueSpace(self, self)
        elif elem_id == ELEM_SPACE_OTHER.id:
            spc = OtherSpace(self, self)
        elif elem_id == ELEM_SPACE_OVERLAY.id:
            spc = OverlaySpace(self, self)
        else:
            spc = AddrSpace(self, self, IPTR_PROCESSOR)
        spc.decode(decoder)
        return spc

    def _decodeSpaces(self, decoder: Decoder) -> None:
        self._insertSpace(ConstantSpace(self, self))

        elem_id = decoder.openElement(ELEM_SPACES)
        default_name = decoder.readString(ATTRIB_DEFAULTSPACE)
        while decoder.peekElement() != 0:
            self._insertSpace(self._decodeSpace(decoder))
        decoder.closeElement(elem_id)

        for spc in self._spaces:
            if spc is not None and spc.getName() == default_name:
                self._default_code_space = spc
                self._default_data_space = spc
                return
        raise LowlevelError("Bad 'defaultspace' attribute: " + default_name)

    def isBigEndian(self) -> bool:
        return self._big_endian

    def setBigEndian(self, val: bool) -> None:
        self._big_endian = val

    def getSpaceByName(self, name: str) -> AddrSpace:
        for spc in self._spaces:
            if spc is not None and spc.getName() == name:
                return spc
        raise LowlevelError("Unknown address space: " + name)

    def truncateSpace(self, tag: TruncationTag) -> None:
        try:
            spc = self.getSpaceByName(tag.getName())
        except LowlevelError as err:
            raise LowlevelError("Unknown space in <truncate_space> command: " + tag.getName()) from err
        spc.truncateSpace(tag.getSize())

    def decode(self, decoder: Decoder) -> None:
        elem_id = decoder.openElement(ELEM_SLEIGH)
        self.setBigEndian(decoder.readBool(ATTRIB_BIGENDIAN))
        self.setUniqueBase(decoder.readUnsignedInteger(ATTRIB_UNIQBASE))
        self._decodeSpaces(decoder)
        while decoder.peekElement() == ELEM_TRUNCATE_SPACE.id:
            tag = TruncationTag()
            tag.decode(decoder)
            self.truncateSpace(tag)
        decoder.closeElement(elem_id)

    def initialize(self, store) -> None:
        el = store.getTag("sleigh")
        if el is None:
            raise LowlevelError("Could not find ghidra sleigh tag")
        decoder = XmlDecode(self, el)
        self.decode(decoder)

    def getRegister(self, nm: str) -> VarnodeData:
        if nm in self._nm2addr:
            return self._nm2addr[nm]
        decoder = PackedDecode(self._glb)
        try:
            if not self._glb.getRegister(nm, decoder):
                raise LowlevelError("No register named " + nm)
        except DecoderError as err:
            raise LowlevelError("Error decoding response for query of register: " + nm + " -- " + err.explain)
        regaddr, regsize = Address.decode(decoder, with_size=True)
        vndata = VarnodeData(regaddr.getSpace(), regaddr.getOffset(), regsize)
        return self.cacheRegister(nm, vndata)

    def getRegisterName(self, space, offset: int, size: int) -> str:
        if space.getType() != IPTR_PROCESSOR:
            return ""
        vndata = VarnodeData(space, offset, size)
        if vndata in self._addr2nm:
            return self._addr2nm[vndata]
        nm = self._glb.getRegisterName(vndata)
        if len(nm) != 0:
            self.getRegister(nm)
        return nm

    def getExactRegisterName(self, space, offset: int, size: int) -> str:
        if space.getType() != IPTR_PROCESSOR:
            return ""
        vndata = VarnodeData(space, offset, size)
        if vndata in self._addr2nm:
            return self._addr2nm[vndata]
        nm = self._glb.getRegisterName(vndata)
        if len(nm) != 0 and self.getRegister(nm).size == size:
            return nm
        return ""

    def numSpaces(self) -> int:
        return len(self._spaces)

    def getSpace(self, i: int):
        if 0 <= i < len(self._spaces):
            return self._spaces[i]
        return None

    def getDefaultCodeSpace(self):
        return self._default_code_space

    def getDefaultDataSpace(self):
        return self._default_data_space

    def getConstantSpace(self):
        return self._const_space

    def getUniqueSpace(self):
        return self._unique_space

    def getStackSpace(self):
        return self._stack_space

    def getUniqueBase(self) -> int:
        return self._unique_base

    def setUniqueBase(self, val: int) -> None:
        self._unique_base = val

    def getAllRegisters(self) -> Dict[VarnodeData, str]:
        raise LowlevelError("Cannot currently get all registers through this interface")

    def getUserOpNames(self) -> list[str]:
        names = []
        index = 0
        while True:
            name = self._glb.getUserOpName(index)
            if not name:
                break
            names.append(name)
            index += 1
        return names

    def oneInstruction(self, emit, baseaddr: Address) -> int:
        decoder = PackedDecode(self._glb)
        try:
            success = self._glb.getPcode(baseaddr, decoder)
        except JavaError:
            raise LowlevelError(
                "Error generating pcode at address: "
                + baseaddr.getShortcut()
                + baseaddr.printRaw()
            )
        if not success:
            raise BadDataError(
                "No pcode could be generated at address: "
                + baseaddr.getShortcut()
                + baseaddr.printRaw()
            )

        elem_id = decoder.openElement()
        offset = decoder.readSignedInteger(ATTRIB_OFFSET)
        if elem_id == ELEM_UNIMPL.id:
            raise UnimplError("Instruction not implemented in pcode:\n " + baseaddr.printRaw(), offset)

        pc = Address.decode(decoder)
        while decoder.peekElement() != 0:
            emit.decodeOp(pc, decoder)
        return offset

    def instructionLength(self, baseaddr: Address) -> int:
        raise LowlevelError("Cannot currently get instruction length through this interface")

    def printAssembly(self, emit, baseaddr: Address) -> int:
        raise LowlevelError("Cannot dump assembly through this interface")


# =========================================================================
# ContextGhidra
# =========================================================================

class ContextGhidra(ContextDatabase):
    """Context database backed by the Ghidra client.

    C++ ref: ``ghidra_context.hh``
    """

    def __init__(self, glb: ArchitectureGhidra) -> None:
        self._glb: ArchitectureGhidra = glb
        self._cache: List[TrackedContext] = []

    def getVariable(self, nm: str) -> ContextBitRange:
        raise LowlevelError("getVariable should not be called for GHIDRA")

    def getRegionForSet(self, res: list, addr1: Address, addr2: Address, num: int, mask: int) -> None:
        raise LowlevelError("getRegionForSet should not be called for GHIDRA")

    def setVariable(self, nm: str, addr: Address, val: int) -> None:
        bitrange = self.getVariable(nm)
        contvec: List[List[int]] = []
        self.getRegionToChangePoint(contvec, addr, bitrange.word, bitrange.mask << bitrange.shift)
        for ctx in contvec:
            bitrange.setValue(ctx, val)

    def getRegionToChangePoint(self, res: list, addr: Address, num: int, mask: int) -> None:
        raise LowlevelError("getRegionToChangePoint should not be called for GHIDRA")

    def getDefaultValue(self) -> List[int]:
        raise LowlevelError("getDefaultValue should not be called for GHIDRA")

    def setVariableRegion(self, nm: str, addr1: Address, addr2: Address, val: int) -> None:
        bitrange = self.getVariable(nm)
        contvec: List[List[int]] = []
        self.getRegionForSet(contvec, addr1, addr2, bitrange.word, bitrange.mask << bitrange.shift)
        for ctx in contvec:
            bitrange.setValue(ctx, val)

    def __del__(self) -> None:
        return None

    def getTrackedSet(self, addr: Address) -> List[TrackedContext]:
        decoder = PackedDecode(self._glb)
        self._cache.clear()
        self._glb.getTrackedRegisters(addr, decoder)
        elem_id = decoder.openElement(ELEM_TRACKED_POINTSET)
        ContextDatabase.decodeTracked(decoder, self._cache)
        decoder.closeElement(elem_id)
        return self._cache

    def decode(self, decoder) -> None:
        decoder.skipElement()

    def decodeFromSpec(self, decoder) -> None:
        decoder.skipElement()

    def getContextSize(self) -> int:
        raise LowlevelError("getContextSize should not be called for GHIDRA")

    def getContext(self, addr: Address, first=None, last=None) -> List[int]:
        raise LowlevelError("getContext should not be called for GHIDRA")

    def registerVariable(self, nm: str, sbit: int, ebit: int) -> None:
        raise LowlevelError("registerVariable should not be called for GHIDRA")

    def encode(self, encoder) -> None:
        raise LowlevelError("context::encode should not be called for GHIDRA")

    def createSet(self, addr1: Address, addr2: Address) -> List[TrackedContext]:
        raise LowlevelError("createSet should not be called for GHIDRA")

    def getTrackedDefault(self) -> List[TrackedContext]:
        raise LowlevelError("getTrackedDefault should not be called for GHIDRA")


# =========================================================================
# InjectContextGhidra / InjectPayloadGhidra
# =========================================================================


class InjectContextGhidra(InjectContext):
    """Injection context that serializes itself for the Ghidra client."""

    def encode(self, encoder: Encoder) -> None:
        encoder.openElement(ELEM_CONTEXT)
        self.baseaddr.encode(encoder)
        self.calladdr.encode(encoder)
        if self.inputlist:
            encoder.openElement(ELEM_INPUT)
            for vn in self.inputlist:
                encoder.openElement(ELEM_ADDR)
                vn.space.encodeAttributes(encoder, vn.offset, vn.size)
                encoder.closeElement(ELEM_ADDR)
            encoder.closeElement(ELEM_INPUT)
        if self.output:
            encoder.openElement(ELEM_OUTPUT)
            for vn in self.output:
                encoder.openElement(ELEM_ADDR)
                vn.space.encodeAttributes(encoder, vn.offset, vn.size)
                encoder.closeElement(ELEM_ADDR)
            encoder.closeElement(ELEM_OUTPUT)
        encoder.closeElement(ELEM_CONTEXT)


class InjectPayloadGhidra(InjectPayload):
    """Placeholder payload whose implementation is provided by the Ghidra client."""

    def __init__(self, src: str, nm: str, tp: int) -> None:
        super().__init__(nm, tp)
        self.source = src

    def inject(self, context: InjectContext, emit) -> None:
        ghidra = context.glb
        decoder = PackedDecode(ghidra)
        try:
            if not ghidra.getPcodeInject(self.name, self.type, context, decoder):
                raise LowlevelError("Could not retrieve injection: " + self.name)
        except JavaError as err:
            raise LowlevelError("Injection error: " + err.explain)
        except DecoderError as err:
            raise LowlevelError("Error decoding injection: " + err.explain)
        elem_id = decoder.openElement()
        addr = Address.decode(decoder)
        while decoder.peekElement() != 0:
            emit.decodeOp(addr, decoder)
        decoder.closeElement(elem_id)

    def decode(self, decoder: Decoder) -> None:
        elem_id = decoder.openElement(ELEM_PCODE)
        self.decodePayloadAttributes(decoder)
        decoder.closeElementSkipping(elem_id)

    def printTemplate(self, s) -> None:
        raise LowlevelError("Printing not supported")

    def getSource(self) -> str:
        return self.source


class InjectCallfixupGhidra(InjectPayloadGhidra):
    """Call-fixup injection whose p-code is generated by the Ghidra client."""

    def __init__(self, src: str, nm: str) -> None:
        super().__init__(src, nm, InjectPayload.CALLFIXUP_TYPE)

    def decode(self, decoder: Decoder) -> None:
        elem_id = decoder.openElement(ELEM_CALLFIXUP)
        self.name = decoder.readString(ATTRIB_NAME)
        decoder.closeElementSkipping(elem_id)


class InjectCallotherGhidra(InjectPayloadGhidra):
    """Callother-fixup injection whose p-code is generated by the Ghidra client."""

    def __init__(self, src: str, nm: str) -> None:
        super().__init__(src, nm, InjectPayload.CALLOTHERFIXUP_TYPE)

    def decode(self, decoder: Decoder) -> None:
        elem_id = decoder.openElement(ELEM_CALLOTHERFIXUP)
        self.name = decoder.readString(ATTRIB_TARGETOP)
        sub_id = decoder.openElement()
        if sub_id != ELEM_PCODE.id:
            raise LowlevelError("<callotherfixup> does not contain a <pcode> tag")
        self.decodePayloadAttributes(decoder)
        self.decodePayloadParams(decoder)
        decoder.closeElementSkipping(sub_id)
        decoder.closeElement(elem_id)


class ExecutablePcodeGhidra(InjectPayloadGhidra):
    """Executable p-code placeholder whose implementation is fetched from Ghidra."""

    def __init__(self, glb, src: str, nm: str) -> None:
        super().__init__(src, nm, InjectPayload.EXECUTABLEPCODE_TYPE)
        self._glb = glb

    def inject(self, context: InjectContext, emit) -> None:
        ghidra = context.glb
        decoder = PackedDecode(ghidra)
        try:
            if not ghidra.getPcodeInject(self.name, self.type, context, decoder):
                raise LowlevelError("Could not retrieve pcode snippet: " + self.name)
        except JavaError as err:
            raise LowlevelError("Error getting pcode snippet: " + err.explain)
        except DecoderError as err:
            raise LowlevelError("Error in pcode snippet xml: " + err.explain)
        elem_id = decoder.openElement()
        addr = Address.decode(decoder)
        while decoder.peekElement() != 0:
            emit.decodeOp(addr, decoder)
        decoder.closeElement(elem_id)

    def decode(self, decoder: Decoder) -> None:
        elem_id = decoder.openElement()
        allowed = {
            ELEM_PCODE.id,
            ELEM_CASE_PCODE.id,
            ELEM_ADDR_PCODE.id,
            ELEM_DEFAULT_PCODE.id,
            ELEM_SIZE_PCODE.id,
        }
        if elem_id not in allowed:
            raise DecoderError(
                "Expecting <pcode>, <case_pcode>, <addr_pcode>, <default_pcode>, or <size_pcode>"
            )
        self.decodePayloadAttributes(decoder)
        self.decodePayloadParams(decoder)
        decoder.closeElementSkipping(elem_id)

    def printTemplate(self, s) -> None:
        raise LowlevelError("Printing not supported")


# =========================================================================
# PcodeInjectLibraryGhidra
# =========================================================================

class PcodeInjectLibraryGhidra(PcodeInjectLibrary):
    """P-code injection library backed by the Ghidra client.

    C++ ref: ``inject_ghidra.hh``
    """

    def __init__(self, glb: ArchitectureGhidra) -> None:
        super().__init__(glb, 0)
        self.contextCache = InjectContextGhidra()
        self.inst: List[object] = []
        self.contextCache.glb = glb

    def allocateInject(self, sourceName: str, name: str, tp: int) -> int:
        injectid = len(self._payloads)
        if tp == InjectPayload.CALLFIXUP_TYPE:
            payload = InjectCallfixupGhidra(sourceName, name)
        elif tp == InjectPayload.CALLOTHERFIXUP_TYPE:
            payload = InjectCallotherGhidra(sourceName, name)
        elif tp == InjectPayload.CALLMECHANISM_TYPE:
            payload = InjectPayloadGhidra(sourceName, name, InjectPayload.CALLMECHANISM_TYPE)
        elif tp == InjectPayload.EXECUTABLEPCODE_TYPE:
            payload = ExecutablePcodeGhidra(self.contextCache.glb, sourceName, name)
        else:
            raise LowlevelError("Bad injection type")
        self._payloads.append(payload)
        return injectid

    def registerInject(self, injectid: int) -> None:
        payload = self._payloads[injectid]
        self._namemap[payload.getName()] = injectid
        if payload.getType() == InjectPayload.CALLFIXUP_TYPE:
            self.registerCallFixup(payload.getName(), injectid)
        elif payload.getType() == InjectPayload.CALLOTHERFIXUP_TYPE:
            self.registerCallOtherFixup(payload.getName(), injectid)
        elif payload.getType() == InjectPayload.CALLMECHANISM_TYPE:
            self.registerCallMechanism(payload.getName(), injectid)
        elif payload.getType() == InjectPayload.EXECUTABLEPCODE_TYPE:
            self.registerExeScript(payload.getName(), injectid)
        else:
            raise LowlevelError("Unknown p-code inject type")

    def manualCallFixup(self, name: str, snippet: str) -> int:
        return 0

    def manualCallOtherFixup(self, name: str, outname: str, inname: list, snippet: str) -> int:
        return 0

    def getCachedContext(self) -> InjectContextGhidra:
        return self.contextCache

    def getBehaviors(self) -> list:
        if not self.inst:
            self.glb.collectBehaviors(self.inst)
        return self.inst
