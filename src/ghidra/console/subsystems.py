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

from ghidra.core.address import Address, Range
from ghidra.core.marshal import (
    PackedDecode,
    ATTRIB_CONTENT, ATTRIB_ID, ATTRIB_NAME, ATTRIB_OFFSET, ATTRIB_SIZE,
    ATTRIB_SPACE, ATTRIB_TYPE,
    ATTRIB_READONLY, ATTRIB_VOLATILE,
    ELEM_HOLE, ELEM_MAPSYM, ELEM_SYMBOL, ELEM_FUNCTION,
    ELEM_FUNCTIONSHELL, ELEM_LABELSYM, ELEM_EXTERNREFSYMBOL,
    ELEM_EQUATESYMBOL, ELEM_FACETSYMBOL,
    ELEM_COMMENT, ELEM_COMMENTDB,
    ELEM_TRACKED_POINTSET, ELEM_TRACKED_SET,
)
from ghidra.arch.loadimage import LoadImage, DataUnavailError
from ghidra.database.comment import Comment, CommentDatabaseInternal
from ghidra.database.stringmanage import StringManager
from ghidra.database.cpool import ConstantPoolInternal, CPoolRecord
from ghidra.database.database import (
    ScopeInternal, SymbolEntry, Symbol,
    ExternRefSymbol, LabSymbol, FunctionSymbol,
)
from ghidra.types.datatype import TypeFactory, Datatype

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
        super().__init__("ghidra")
        self._glb: ArchitectureGhidra = glb

    def loadFill(self, buf: bytearray, size: int, addr: Address) -> None:
        try:
            data = self._glb.getBytes(size, addr)
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
        self._cacheDirty: bool = False

    def lockDefaultProperties(self) -> None:
        self._cacheDirty = False

    def findAddr(self, addr: Address, usepoint: Address) -> Optional[SymbolEntry]:
        entry = super().findAddr(addr, usepoint)
        if entry is not None:
            return entry
        return self._remoteQuery(addr)

    def findContainer(self, addr: Address, size: int, usepoint: Address) -> Optional[SymbolEntry]:
        entry = super().findContainer(addr, size, usepoint)
        if entry is not None:
            return entry
        return self._remoteQuery(addr)

    def findFunction(self, addr: Address) -> Optional[Funcdata]:
        fd = super().findFunction(addr)
        if fd is not None:
            return fd
        self._remoteQuery(addr)
        return super().findFunction(addr)

    def findExternalRef(self, addr: Address) -> Optional[ExternRefSymbol]:
        result = super().findExternalRef(addr)
        if result is not None:
            return result
        resp = self._ghidra.getExternalRefXml(addr)
        if resp is not None:
            self._parseResponse(resp, addr)
            return super().findExternalRef(addr)
        return None

    def findCodeLabel(self, addr: Address) -> Optional[LabSymbol]:
        label = self._ghidra.getCodeLabel(addr)
        if label:
            return LabSymbol(self, label)
        return None

    def queryFunction(self, addr: Address) -> Optional[Funcdata]:
        """Query for a function at the given address, creating one if found remotely."""
        fd = self.findFunction(addr)
        if fd is not None:
            return fd
        resp = self._ghidra.getMappedSymbolsXml(addr)
        if resp is not None:
            self._parseResponse(resp, addr)
            return super().findFunction(addr)
        return None

    def _remoteQuery(self, addr: Address) -> Optional[SymbolEntry]:
        """Query the Ghidra client for symbols at addr."""
        resp = self._ghidra.getMappedSymbolsXml(addr)
        if resp is not None:
            return self._parseResponse(resp, addr)
        return None

    def _parseResponse(self, resp: bytes, addr: Address) -> Optional[SymbolEntry]:
        """Decode a packed response from the Ghidra client and cache the result.

        Mirrors C++ ``ScopeGhidra::dump2Cache``.
        """
        decoder = PackedDecode(self._ghidra)
        decoder.ingestBytes(resp)
        sym = self._dump2Cache(decoder)
        if sym is None:
            return None
        entry = sym.getFirstWholeMap()
        return entry

    def _dump2Cache(self, decoder: PackedDecode) -> Optional[Symbol]:
        """Build the global object described by the stream and put it in the cache.

        C++ ref: ``ScopeGhidra::dump2Cache``
        """
        elemId = decoder.peekElement()
        if elemId == ELEM_HOLE.id:
            self._decodeHole(decoder)
            return None

        # The outer element is a wrapper with ATTRIB_ID = scope id
        decoder.openElement()
        scope_id = 0
        try:
            scope_id = decoder.readUnsignedInteger(ATTRIB_ID)
        except Exception:
            pass

        # For now, all symbols go into *this* scope (global cache).
        # In the C++ version, reresolveScope(scope_id) would create
        # namespace scopes on demand. We use self as the target scope.
        scope = self

        sym = self._addMapSym(decoder)
        decoder.closeElement(elemId)

        if sym is not None:
            entry = sym.getFirstWholeMap()
            if entry is not None:
                # Mark the address range as queried so we don't re-query
                spc = entry.addr.getSpace()
                first = entry.addr.getOffset()
                last = first + entry.getSize() - 1
                self._holes_insert(spc, first, last)
        return sym

    def _addMapSym(self, decoder: PackedDecode) -> Optional[Symbol]:
        """Decode a <mapsym> element and add to scope cache.

        C++ ref: ``Scope::addMapSym``
        """
        mapsym_id = decoder.openElement(ELEM_MAPSYM)
        sub_id = decoder.peekElement()

        sym: Optional[Symbol] = None
        if sub_id == ELEM_SYMBOL.id:
            sym = Symbol(self)
        elif sub_id == ELEM_EQUATESYMBOL.id:
            sym = Symbol(self)  # EquateSymbol simplified
        elif sub_id in (ELEM_FUNCTION.id, ELEM_FUNCTIONSHELL.id):
            sym = FunctionSymbol(self, "", getattr(self._ghidra, 'min_funcsymbol_size', 1))
        elif sub_id == ELEM_LABELSYM.id:
            sym = LabSymbol(self, "")
        elif sub_id == ELEM_EXTERNREFSYMBOL.id:
            sym = ExternRefSymbol(self)
        elif sub_id == ELEM_FACETSYMBOL.id:
            sym = Symbol(self)  # UnionFacetSymbol simplified
        else:
            log.warning("Unknown symbol type id %d in <mapsym>", sub_id)
            decoder.closeElementSkipping(mapsym_id)
            return None

        try:
            sym.decode(decoder)
        except Exception as e:
            log.warning("Failed to decode symbol: %s", e)
            decoder.closeElementSkipping(mapsym_id)
            return None

        self.addSymbol(sym)

        # Decode subsequent SymbolEntry mappings
        while decoder.peekElement() != 0:
            entry = SymbolEntry(sym)
            try:
                entry.decode(decoder)
            except Exception as e:
                log.warning("Failed to decode map entry for %s: %s", sym.name, e)
                break
            self.addMapEntry(sym, entry)

        decoder.closeElement(mapsym_id)
        return sym

    def _decodeHole(self, decoder: PackedDecode) -> None:
        """Decode a <hole> element indicating no symbol at queried address.

        C++ ref: ``ScopeGhidra::decodeHole``
        """
        hole_id = decoder.openElement(ELEM_HOLE)
        # Decode range attributes (space, first, last)
        rng = Range()
        try:
            rng.decodeFromAttributes(decoder)
        except Exception:
            pass
        decoder.rewindAttributes()
        flags = 0
        while True:
            att = decoder.getNextAttributeId()
            if att == 0:
                break
            if att == ATTRIB_READONLY.id:
                if decoder.readBool():
                    flags |= 1  # Varnode::readonly
            elif att == ATTRIB_VOLATILE.id:
                if decoder.readBool():
                    flags |= 2  # Varnode::volatil
            # Other attributes are consumed by getNextAttributeId iteration
        if rng.spc is not None:
            self._holes_insert(rng.spc, rng.first, rng.last)
        decoder.closeElement(hole_id)

    def _holes_insert(self, spc, first: int, last: int) -> None:
        """Record that address range [first,last] in spc has been queried."""
        if not hasattr(self, '_holes'):
            self._holes: Dict[int, list] = {}
        idx = spc.getIndex() if hasattr(spc, 'getIndex') else 0
        if idx not in self._holes:
            self._holes[idx] = []
        self._holes[idx].append((first, last))

    def _inHoles(self, addr: Address) -> bool:
        """Check if addr was already queried (in a hole)."""
        if not hasattr(self, '_holes'):
            return False
        spc = addr.getSpace()
        idx = spc.getIndex() if hasattr(spc, 'getIndex') else 0
        ranges = self._holes.get(idx)
        if ranges is None:
            return False
        off = addr.getOffset()
        for (f, l) in ranges:
            if f <= off <= l:
                return True
        return False


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

    def findById(self, id_: int) -> Optional[Datatype]:
        """Override: query Ghidra when a type isn't found locally."""
        result = super().findById(id_)
        if result is not None:
            return result
        resp = self._ghidra.getDataTypeXml("", id_)
        if resp is not None:
            decoder = PackedDecode(self._ghidra)
            decoder.ingestBytes(resp)
            try:
                dt = self.decodeType(decoder)
                return dt
            except Exception as e:
                log.warning("Failed to decode type id=%d: %s", id_, e)
        return None


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

    def _fillCache(self, funcaddr: Address) -> None:
        if self._cachefilled:
            return
        # Query all comment types
        flags = (Comment.CommentType.user1 | Comment.CommentType.user2 |
                 Comment.CommentType.user3 | Comment.CommentType.header |
                 Comment.CommentType.warning | Comment.CommentType.warningheader)
        resp = self._ghidra.getCommentsXml(funcaddr, flags)
        if resp is not None:
            decoder = PackedDecode(self._ghidra)
            decoder.ingestBytes(resp)
            try:
                self._decodeComments(decoder)
            except Exception as e:
                log.warning("Failed to decode comments: %s", e)
        self._cachefilled = True

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
        self._ghidra: ArchitectureGhidra = glb

    def getStringData(self, addr: Address, charType: Datatype) -> tuple[bytes, bool]:
        resp = self._ghidra.getStringDataRaw(addr, charType, self.maximumChars)
        if resp is not None:
            return resp
        return (b"", False)


# =========================================================================
# ConstantPoolGhidra
# =========================================================================

class ConstantPoolGhidra(ConstantPoolInternal):
    """ConstantPool backed by a Ghidra client.

    C++ ref: ``cpool_ghidra.hh``
    """

    def __init__(self, glb: ArchitectureGhidra) -> None:
        super().__init__()
        self._ghidra: ArchitectureGhidra = glb

    def getRecord(self, refs: List[int]) -> Optional[CPoolRecord]:
        cached = super().getRecord(refs)
        if cached is not None:
            return cached
        resp = self._ghidra.getCPoolRefXml(refs)
        if resp is not None:
            decoder = PackedDecode(self._ghidra)
            decoder.ingestBytes(resp)
            try:
                rec = CPoolRecord()
                rec.decode(decoder, self._ghidra.types if hasattr(self._ghidra, 'types') else None)
                self.storeRecord(refs, rec)
                return rec
            except Exception as e:
                log.warning("Failed to decode cpool record: %s", e)
        return None

    def empty(self) -> bool:
        return False


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
        self._nm2addr: Dict[str, tuple] = {}  # name -> (space, offset, size)
        self._addr2nm: Dict[tuple, str] = {}  # (space_name, offset, size) -> name
        self._spaces: list = []
        self._default_code_space = None
        self._default_data_space = None
        self._unique_space = None
        self._const_space = None
        self._stack_space = None
        self._unique_base: int = 0

    def initialize(self, store=None) -> None:
        """Initialize from the tspec XML already parsed by Architecture."""
        return

    def getRegister(self, nm: str):
        """Get a register varnode by name, querying Ghidra if not cached."""
        if nm in self._nm2addr:
            return self._nm2addr[nm]
        resp = self._glb.getRegisterXml(nm)
        if resp is not None:
            decoder = PackedDecode(self._glb)
            decoder.ingestBytes(resp)
            try:
                addr_result = Address.decode(decoder, with_size=True)
                if isinstance(addr_result, tuple):
                    addr_obj, sz = addr_result
                else:
                    addr_obj, sz = addr_result, 0
                spc = addr_obj.getSpace()
                off = addr_obj.getOffset()
                entry = (spc, off, sz)
                self._nm2addr[nm] = entry
                key = (spc.getName() if spc else "", off, sz)
                self._addr2nm[key] = nm
                return entry
            except Exception as e:
                log.warning("Failed to decode register %s: %s", nm, e)
        return None

    def getRegisterName(self, space, offset: int, size: int) -> str:
        """Get register name by location, querying Ghidra if not cached."""
        key = (getattr(space, 'name', str(space)), offset, size)
        if key in self._addr2nm:
            return self._addr2nm[key]
        nm = self._glb.getRegisterName(space, offset, size)
        if nm:
            self._addr2nm[key] = nm
            return nm
        return ""

    def getExactRegisterName(self, space, offset: int, size: int) -> str:
        return self.getRegisterName(space, offset, size)

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


# =========================================================================
# ContextGhidra
# =========================================================================

class ContextGhidra:
    """Context database backed by the Ghidra client.

    C++ ref: ``ghidra_context.hh``
    """

    def __init__(self, glb: ArchitectureGhidra) -> None:
        self._glb: ArchitectureGhidra = glb

    def getTrackedSet(self, addr: Address) -> list:
        """Get tracked register values at addr by querying Ghidra."""
        resp = self._glb.getTrackedRegistersXml(addr)
        if resp is not None:
            decoder = PackedDecode(self._glb)
            decoder.ingestBytes(resp)
            try:
                return self._decodeTrackedSet(decoder)
            except Exception as e:
                log.warning("Failed to decode tracked registers: %s", e)
        return []

    def _decodeTrackedSet(self, decoder: PackedDecode) -> list:
        """Decode <tracked_pointset> packed response."""
        result = []
        tp_id = decoder.openElement(ELEM_TRACKED_POINTSET)
        while decoder.peekElement() != 0:
            set_id = decoder.openElement(ELEM_TRACKED_SET)
            # Each <set> has space, offset, size, val attributes
            spc_name = ""
            offset = 0
            size = 0
            val = 0
            while True:
                att = decoder.getNextAttributeId()
                if att == 0:
                    break
                if att == ATTRIB_SPACE.id:
                    spc_name = decoder.readString()
                elif att == ATTRIB_OFFSET.id:
                    offset = decoder.readUnsignedInteger()
                elif att == ATTRIB_SIZE.id:
                    size = decoder.readSignedInteger()
                elif att == ATTRIB_NAME.id:
                    # val attribute stored as 'val'
                    val = decoder.readUnsignedInteger()
                else:
                    decoder.readString()  # skip
            decoder.closeElement(set_id)
            result.append({'space': spc_name, 'offset': offset, 'size': size, 'val': val})
        decoder.closeElement(tp_id)
        return result

    def setVariable(self, nm: str, addr: Address, val: int) -> None:
        pass

    def getVariable(self, nm: str, addr: Address) -> int:
        return 0


# =========================================================================
# PcodeInjectLibraryGhidra
# =========================================================================

class PcodeInjectLibraryGhidra:
    """P-code injection library backed by the Ghidra client.

    C++ ref: ``inject_ghidra.hh``
    """

    CALLFIXUP_TYPE = 1
    CALLOTHERFIXUP_TYPE = 2
    CALLMECHANISM_TYPE = 3
    EXECUTABLEPCODE_TYPE = 4

    def __init__(self, glb: ArchitectureGhidra) -> None:
        self._glb: ArchitectureGhidra = glb
        self._payloads: dict = {}

    def registerCallFixup(self, name: str, fixup_id: int) -> None:
        self._payloads[name] = (self.CALLFIXUP_TYPE, fixup_id)

    def registerCallOtherFixup(self, name: str, fixup_id: int) -> None:
        self._payloads[name] = (self.CALLOTHERFIXUP_TYPE, fixup_id)

    def restoreXmlCallfixup(self, nm: str, decoder) -> int:
        return -1

    def restoreXmlCallotherfixup(self, nm: str, decoder) -> int:
        return -1

    def manualCallFixup(self, name: str, snippet: str) -> int:
        return -1

    def manualCallOtherFixup(self, name: str, outname: str, inname: list, snippet: str) -> int:
        return -1

    def getPayload(self, idx: int):
        return None

    def allocateInject(self, sourceName: str, name: str, tp: int) -> int:
        return -1
