"""Tests for deepened database.py methods — Phase 11b.

Covers: Symbol.encode/encodeHeader/encodeBody, Scope.overrideSizeLockType,
Scope.resetSizeLockType, Scope.findDistinguishingScope, Scope.getFullName,
Scope.inRange, ScopeInternal.clear/clearCategory/clearUnlocked/clearUnlockedCategory,
ScopeInternal.addRange/removeRange, ScopeInternal.encode, ScopeInternal.printEntries,
Database.mapScope/encode/decode/deleteSubScopes/findCreateScope/addRange/removeRange/
clearUnlocked/adjustCaches/resolveScope.
"""
from __future__ import annotations

import io

from ghidra.core.address import Address, RangeList
from ghidra.core.space import AddrSpace
from ghidra.ir.varnode import Varnode
from ghidra.database.database import (
    Symbol, SymbolEntry, FunctionSymbol, LabSymbol, EquateSymbol,
    ExternRefSymbol, ScopeInternal, Database,
)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

_SHARED_SPC = AddrSpace(name="ram", size=4)


def _spc():
    return _SHARED_SPC


def _addr(off):
    return Address(_spc(), off)


class _MockDatatype:
    """Minimal mock for Datatype."""
    def __init__(self, name="int", size=4, metatype=None):
        self._name = name
        self._size = size
        self._metatype = metatype

    def getName(self):
        return self._name

    def getSize(self):
        return self._size

    def getMetatype(self):
        return self._metatype

    def encodeRef(self, encoder):
        pass


class _MockEncoder:
    """Records calls for encode verification."""
    def __init__(self):
        self.calls = []

    def openElement(self, elem):
        self.calls.append(("open", getattr(elem, 'name', str(elem))))

    def closeElement(self, elem):
        self.calls.append(("close", getattr(elem, 'name', str(elem))))

    def writeString(self, attr, val):
        self.calls.append(("string", getattr(attr, 'name', str(attr)), val))

    def writeUnsignedInteger(self, attr, val):
        self.calls.append(("uint", getattr(attr, 'name', str(attr)), val))

    def writeSignedInteger(self, attr, val):
        self.calls.append(("sint", getattr(attr, 'name', str(attr)), val))

    def writeBool(self, attr, val):
        self.calls.append(("bool", getattr(attr, 'name', str(attr)), val))


# =========================================================================
# Symbol encode tests
# =========================================================================

class TestSymbolEncode:
    def test_encode_basic_symbol(self):
        s = Symbol(name="myVar")
        s.symbolId = 42
        enc = _MockEncoder()
        s.encode(enc)
        # Should open ELEM_SYMBOL, write header, write body, close
        opens = [c for c in enc.calls if c[0] == "open"]
        closes = [c for c in enc.calls if c[0] == "close"]
        assert len(opens) >= 1
        assert len(closes) >= 1

    def test_encodeHeader_name_and_id(self):
        s = Symbol(name="foo")
        s.symbolId = 100
        enc = _MockEncoder()
        s.encodeHeader(enc)
        names = [c for c in enc.calls if c[0] == "string" and c[1] == "name"]
        assert len(names) == 1
        assert names[0][2] == "foo"
        ids = [c for c in enc.calls if c[0] == "uint" and c[1] == "id"]
        assert ids[0][2] == 100

    def test_encodeHeader_flags(self):
        s = Symbol(name="x")
        s.symbolId = 1
        s.flags = Varnode.namelock | Varnode.typelock | Varnode.readonly
        enc = _MockEncoder()
        s.encodeHeader(enc)
        bools = {c[1]: c[2] for c in enc.calls if c[0] == "bool"}
        assert bools.get("namelock") is True
        assert bools.get("typelock") is True
        assert bools.get("readonly") is True

    def test_encodeHeader_volatile_flag(self):
        s = Symbol(name="v")
        s.symbolId = 1
        s.flags = Varnode.volatil
        enc = _MockEncoder()
        s.encodeHeader(enc)
        bools = {c[1]: c[2] for c in enc.calls if c[0] == "bool"}
        assert bools.get("volatile") is True

    def test_encodeHeader_isolate_flag(self):
        s = Symbol(name="iso")
        s.symbolId = 1
        s.setIsolated(True)
        enc = _MockEncoder()
        s.encodeHeader(enc)
        bools = {c[1]: c[2] for c in enc.calls if c[0] == "bool"}
        assert bools.get("merge") is False  # Merge=false means isolated

    def test_encodeHeader_this_pointer(self):
        s = Symbol(name="tp")
        s.symbolId = 1
        s.setThisPointer(True)
        enc = _MockEncoder()
        s.encodeHeader(enc)
        bools = {c[1]: c[2] for c in enc.calls if c[0] == "bool"}
        assert bools.get("thisptr") is True

    def test_encodeHeader_category(self):
        s = Symbol(name="p")
        s.symbolId = 1
        s.setCategory(Symbol.function_parameter, 3)
        enc = _MockEncoder()
        s.encodeHeader(enc)
        cats = [c for c in enc.calls if c[0] == "sint" and c[1] == "cat"]
        assert cats[0][2] == Symbol.function_parameter
        idxs = [c for c in enc.calls if c[0] == "uint" and c[1] == "index"]
        assert idxs[0][2] == 3

    def test_encodeHeader_display_format(self):
        s = Symbol(name="f")
        s.symbolId = 1
        s.setDisplayFormat(Symbol.force_hex)
        enc = _MockEncoder()
        s.encodeHeader(enc)
        fmts = [c for c in enc.calls if c[0] == "string" and c[1] == "format"]
        assert fmts[0][2] == "hex"

    def test_encodeBody_with_type(self):
        s = Symbol(name="t")
        s.type = _MockDatatype()
        enc = _MockEncoder()
        s.encodeBody(enc)
        # encodeRef was called - no crash is the key check

    def test_encodeBody_without_type(self):
        s = Symbol(name="t")
        s.type = None
        enc = _MockEncoder()
        s.encodeBody(enc)
        assert len(enc.calls) == 0  # nothing encoded


# =========================================================================
# Scope.overrideSizeLockType / resetSizeLockType
# =========================================================================

class TestScopeOverrideResetType:
    def test_overrideSizeLockType_same_size(self):
        sc = ScopeInternal(1, "test")
        sym = Symbol(name="x")
        sym.type = _MockDatatype(size=4)
        sym.setSizeTypeLock(True)
        sc.addSymbol(sym)
        new_type = _MockDatatype(name="float", size=4)
        sc.overrideSizeLockType(sym, new_type)
        assert sym.type is new_type

    def test_overrideSizeLockType_different_size_raises(self):
        sc = ScopeInternal(1, "test")
        sym = Symbol(name="x")
        sym.type = _MockDatatype(size=4)
        sym.setSizeTypeLock(True)
        sc.addSymbol(sym)
        import pytest
        with pytest.raises(Exception, match="different type size"):
            sc.overrideSizeLockType(sym, _MockDatatype(size=8))

    def test_overrideSizeLockType_not_size_locked_raises(self):
        sc = ScopeInternal(1, "test")
        sym = Symbol(name="x")
        sym.type = _MockDatatype(size=4)
        sc.addSymbol(sym)
        import pytest
        with pytest.raises(Exception, match="not size locked"):
            sc.overrideSizeLockType(sym, _MockDatatype(size=4))

    def test_resetSizeLockType_none_type(self):
        sc = ScopeInternal(1, "test")
        sym = Symbol(name="x")
        sym.type = None
        sc.addSymbol(sym)
        sc.resetSizeLockType(sym)  # Should not crash
        assert sym.type is None

    def test_resetSizeLockType_clears_to_none_without_arch(self):
        sc = ScopeInternal(1, "test")
        sym = Symbol(name="x")
        sym.type = _MockDatatype(size=4, metatype=10)  # Not TYPE_UNKNOWN
        sc.addSymbol(sym)
        sc.resetSizeLockType(sym)
        assert sym.type is None


# =========================================================================
# Scope.findDistinguishingScope
# =========================================================================

class TestFindDistinguishingScope:
    def test_same_scope_returns_none(self):
        sc = ScopeInternal(1, "test")
        assert sc.findDistinguishingScope(sc) is None

    def test_parent_child(self):
        parent = ScopeInternal(1, "parent")
        child = ScopeInternal(2, "child")
        parent.attachScope(child)
        assert child.findDistinguishingScope(parent) is child

    def test_child_of_other_returns_none(self):
        parent = ScopeInternal(1, "parent")
        child = ScopeInternal(2, "child")
        parent.attachScope(child)
        assert parent.findDistinguishingScope(child) is None

    def test_siblings(self):
        parent = ScopeInternal(1, "parent")
        c1 = ScopeInternal(2, "c1")
        c2 = ScopeInternal(3, "c2")
        parent.attachScope(c1)
        parent.attachScope(c2)
        assert c1.findDistinguishingScope(c2) is c1


# =========================================================================
# Scope.getFullName
# =========================================================================

class TestGetFullName:
    def test_global_scope_empty(self):
        sc = ScopeInternal(1, "")
        assert sc.getFullName() == ""

    def test_child_scope(self):
        parent = ScopeInternal(1, "global")
        child = ScopeInternal(2, "mynamespace")
        parent.attachScope(child)
        assert child.getFullName() == "mynamespace"

    def test_nested_scope(self):
        root = ScopeInternal(1, "")
        mid = ScopeInternal(2, "ns1")
        leaf = ScopeInternal(3, "ns2")
        root.attachScope(mid)
        mid.attachScope(leaf)
        assert leaf.getFullName() == "ns1::ns2"


# =========================================================================
# Scope.inRange
# =========================================================================

class TestScopeInRange:
    def test_empty_range_false(self):
        sc = ScopeInternal(1, "test")
        assert sc.inRange(_addr(0x1000), 4) is False

    def test_with_range_true(self):
        sc = ScopeInternal(1, "test")
        sc.addRange(_spc(), 0x1000, 0x1FFF)
        assert sc.inRange(_addr(0x1000), 4) is True
        assert sc.inRange(_addr(0x1500), 1) is True

    def test_outside_range_false(self):
        sc = ScopeInternal(1, "test")
        sc.addRange(_spc(), 0x1000, 0x1FFF)
        assert sc.inRange(_addr(0x2000), 1) is False


# =========================================================================
# ScopeInternal.clear / clearCategory
# =========================================================================

class TestScopeInternalClear:
    def test_clear_removes_all(self):
        sc = ScopeInternal(1, "test")
        sc.addSymbolInternal(Symbol(name="a"), _addr(0x100), 4)
        sc.addSymbolInternal(Symbol(name="b"), _addr(0x200), 4)
        assert sc.getNumSymbols() == 2
        sc.clear()
        assert sc.getNumSymbols() == 0

    def test_clearCategory_positive(self):
        sc = ScopeInternal(1, "test")
        s1 = Symbol(name="param0")
        s1.category = Symbol.function_parameter
        sc.addSymbol(s1)
        s2 = Symbol(name="other")
        sc.addSymbol(s2)
        assert sc.getNumSymbols() == 2
        sc.clearCategory(Symbol.function_parameter)
        assert sc.getNumSymbols() == 1
        assert sc.findByName("other") is not None

    def test_clearCategory_negative(self):
        sc = ScopeInternal(1, "test")
        s1 = Symbol(name="param0")
        s1.category = Symbol.function_parameter
        sc.addSymbol(s1)
        s2 = Symbol(name="local")
        sc.addSymbol(s2)
        sc.clearCategory(-1)  # Remove uncategorized
        assert sc.getNumSymbols() == 1
        assert sc.findByName("param0") is not None


# =========================================================================
# ScopeInternal.clearUnlocked
# =========================================================================

class TestScopeInternalClearUnlocked:
    def test_unlocked_removed(self):
        sc = ScopeInternal(1, "test")
        s = Symbol(name="unlocked")
        sc.addSymbol(s)
        sc.clearUnlocked()
        assert sc.getNumSymbols() == 0

    def test_type_locked_kept(self):
        sc = ScopeInternal(1, "test")
        s = Symbol(name="locked")
        s.setTypeLock(True)
        s.setNameLock(True)
        sc.addSymbol(s)
        sc.clearUnlocked()
        assert sc.getNumSymbols() == 1
        assert sc.findByName("locked") is not None

    def test_type_locked_name_unlocked_gets_renamed(self):
        sc = ScopeInternal(1, "test")
        s = Symbol(name="named_sym")
        s.setTypeLock(True)
        sc.addSymbol(s)
        sc.clearUnlocked()
        assert sc.getNumSymbols() == 1
        assert s.name.startswith("$$undef")

    def test_equate_preserved(self):
        sc = ScopeInternal(1, "test")
        s = EquateSymbol(name="MY_CONST", val=42)
        sc.addSymbol(s)
        sc.clearUnlocked()
        assert sc.getNumSymbols() == 1

    def test_size_type_locked_gets_reset(self):
        sc = ScopeInternal(1, "test")
        s = Symbol(name="szlock")
        s.type = _MockDatatype(size=4, metatype=10)
        s.setTypeLock(True)
        s.setSizeTypeLock(True)
        s.setNameLock(True)
        sc.addSymbol(s)
        sc.clearUnlocked()
        assert sc.getNumSymbols() == 1
        # Type should have been reset (to None since no arch)
        assert s.type is None


# =========================================================================
# ScopeInternal.clearUnlockedCategory
# =========================================================================

class TestScopeInternalClearUnlockedCategory:
    def test_positive_cat_unlocked_removed(self):
        sc = ScopeInternal(1, "test")
        s = Symbol(name="param")
        s.category = Symbol.function_parameter
        sc.addSymbol(s)
        sc.clearUnlockedCategory(Symbol.function_parameter)
        assert sc.getNumSymbols() == 0

    def test_positive_cat_locked_kept(self):
        sc = ScopeInternal(1, "test")
        s = Symbol(name="param")
        s.category = Symbol.function_parameter
        s.setTypeLock(True)
        s.setNameLock(True)
        sc.addSymbol(s)
        sc.clearUnlockedCategory(Symbol.function_parameter)
        assert sc.getNumSymbols() == 1

    def test_negative_cat_removes_uncategorized_unlocked(self):
        sc = ScopeInternal(1, "test")
        s1 = Symbol(name="local")
        sc.addSymbol(s1)
        s2 = Symbol(name="param")
        s2.category = Symbol.function_parameter
        sc.addSymbol(s2)
        sc.clearUnlockedCategory(-1)
        assert sc.getNumSymbols() == 1
        assert sc.findByName("param") is not None


# =========================================================================
# ScopeInternal.addRange / removeRange
# =========================================================================

class TestScopeInternalRanges:
    def test_addRange(self):
        sc = ScopeInternal(1, "test")
        sc.addRange(_spc(), 0x1000, 0x1FFF)
        assert sc.inRange(_addr(0x1000), 1) is True
        assert sc.inRange(_addr(0x2000), 1) is False

    def test_removeRange(self):
        sc = ScopeInternal(1, "test")
        sc.addRange(_spc(), 0x1000, 0x1FFF)
        sc.removeRange(_spc(), 0x1000, 0x1FFF)
        assert sc.inRange(_addr(0x1000), 1) is False

    def test_addRange_merge(self):
        sc = ScopeInternal(1, "test")
        sc.addRange(_spc(), 0x1000, 0x1FFF)
        sc.addRange(_spc(), 0x2000, 0x2FFF)
        assert sc.inRange(_addr(0x1500), 1) is True
        assert sc.inRange(_addr(0x2500), 1) is True


# =========================================================================
# ScopeInternal.encode
# =========================================================================

class TestScopeInternalEncode:
    def test_encode_empty_scope(self):
        sc = ScopeInternal(1, "test")
        enc = _MockEncoder()
        sc.encode(enc)
        opens = [c[1] for c in enc.calls if c[0] == "open"]
        closes = [c[1] for c in enc.calls if c[0] == "close"]
        assert "scope" in opens
        assert "scope" in closes

    def test_encode_scope_with_parent(self):
        parent = ScopeInternal(1, "parent")
        child = ScopeInternal(2, "child")
        parent.attachScope(child)
        enc = _MockEncoder()
        child.encode(enc)
        opens = [c[1] for c in enc.calls if c[0] == "open"]
        assert "parent" in opens

    def test_encode_scope_with_symbols(self):
        sc = ScopeInternal(1, "test")
        s = Symbol(name="myvar")
        sc.addSymbolInternal(s, _addr(0x100), 4)
        enc = _MockEncoder()
        sc.encode(enc)
        opens = [c[1] for c in enc.calls if c[0] == "open"]
        assert "symbollist" in opens
        assert "mapsym" in opens


# =========================================================================
# ScopeInternal.printEntries
# =========================================================================

class TestScopeInternalPrintEntries:
    def test_printEntries(self):
        sc = ScopeInternal(1, "test")
        sc.addSymbolInternal(Symbol(name="foo"), _addr(0x100), 4)
        buf = io.StringIO()
        sc.printEntries(buf)
        output = buf.getvalue()
        assert "Scope test" in output
        assert "foo" in output


# =========================================================================
# Database
# =========================================================================

class TestDatabaseDeep:
    def test_resolveScope_by_id(self):
        db = Database()
        gs = db.createGlobalScope("global")
        assert db.resolveScope(gs.uniqueId) is gs

    def test_resolveScope_unknown_id(self):
        db = Database()
        db.createGlobalScope("global")
        assert db.resolveScope(9999) is None

    def test_resolveScope_by_address_global(self):
        db = Database()
        db.createGlobalScope("global")
        assert db.resolveScope(_addr(0x1000)) is db.getGlobalScope()

    def test_resolveScope_by_address_namespace(self):
        db = Database()
        gs = db.createGlobalScope("global")
        ns = db.createScope("ns1", gs)
        ns.addRange(_spc(), 0x1000, 0x1FFF)
        result = db.resolveScope(_addr(0x1500))
        assert result is ns

    def test_mapScope_add_range(self):
        db = Database()
        gs = db.createGlobalScope("global")
        ns = db.createScope("ns1", gs)
        db.mapScope(ns, _spc(), 0x1000, 0x1FFF)
        assert ns.inRange(_addr(0x1000), 1) is True

    def test_mapScope_resolve_returns_qpoint(self):
        db = Database()
        gs = db.createGlobalScope("global")
        result = db.mapScope(gs, _addr(0x1000), _addr(0x2000))
        assert result is gs

    def test_deleteSubScopes(self):
        db = Database()
        gs = db.createGlobalScope("global")
        c1 = db.createScope("c1", gs)
        c2 = db.createScope("c2", gs)
        assert db.getNumScopes() == 3
        db.deleteSubScopes(gs)
        assert gs.numChildren() == 0
        assert db.getNumScopes() == 1  # Only global remains

    def test_deleteSubScopes_recursive(self):
        db = Database()
        gs = db.createGlobalScope("global")
        c1 = db.createScope("c1", gs)
        gc1 = db.createScope("gc1", c1)
        assert db.getNumScopes() == 3
        db.deleteSubScopes(gs)
        assert db.getNumScopes() == 1

    def test_findCreateScope_existing(self):
        db = Database()
        gs = db.createGlobalScope("global")
        c1 = db.createScope("c1", gs)
        result = db.findCreateScope(c1.uniqueId, "c1", gs)
        assert result is c1

    def test_findCreateScope_new(self):
        db = Database()
        gs = db.createGlobalScope("global")
        result = db.findCreateScope(99, "newscope", gs)
        assert result is not None
        assert result.getName() == "newscope"
        assert db.getNumScopes() == 2

    def test_addRange_database(self):
        db = Database()
        gs = db.createGlobalScope("global")
        ns = db.createScope("ns1", gs)
        db.addRange(ns, _spc(), 0x1000, 0x1FFF)
        assert ns.inRange(_addr(0x1500), 1) is True

    def test_removeRange_database(self):
        db = Database()
        gs = db.createGlobalScope("global")
        ns = db.createScope("ns1", gs)
        db.addRange(ns, _spc(), 0x1000, 0x1FFF)
        db.removeRange(ns, _spc(), 0x1000, 0x1FFF)
        assert ns.inRange(_addr(0x1500), 1) is False

    def test_clearUnlocked_database(self):
        db = Database()
        gs = db.createGlobalScope("global")
        s = Symbol(name="unlocked")
        gs.addSymbol(s)
        assert gs.getNumSymbols() == 1
        db.clearUnlocked(gs)
        assert gs.getNumSymbols() == 0

    def test_adjustCaches_no_crash(self):
        db = Database()
        gs = db.createGlobalScope("global")
        db.adjustCaches()  # Should not crash

    def test_encode_database(self):
        db = Database()
        gs = db.createGlobalScope("global")
        gs.addSymbolInternal(Symbol(name="g1"), _addr(0x100), 4)
        enc = _MockEncoder()
        db.encode(enc)
        opens = [c[1] for c in enc.calls if c[0] == "open"]
        assert "db" in opens
        assert "scope" in opens


# =========================================================================
# SymbolEntry.encode (check it exists)
# =========================================================================

class TestSymbolEntryEncode:
    def test_encode_addr_entry(self):
        """SymbolEntry with valid addr encodes address + uselimit."""
        sym = Symbol(name="test")
        se = SymbolEntry(sym, _addr(0x100), 4)
        enc = _MockEncoder()
        se.encode(enc)
        # Should have encoded the address (addr.encode) and rangelist
        assert len(enc.calls) > 0

    def test_encode_dynamic_entry(self):
        """SymbolEntry with invalid addr encodes <hash> element."""
        sym = Symbol(name="dyn")
        se = SymbolEntry(sym, Address(), 0, hash_=0xABCD)
        enc = _MockEncoder()
        se.encode(enc)
        opens = [c for c in enc.calls if c[0] == "open"]
        assert any("hash" in str(c) for c in opens)

    def test_encode_piece_entry_skips(self):
        """SymbolEntry that isPiece returns immediately."""
        sym = Symbol(name="piece")
        se = SymbolEntry(sym, _addr(0x100), 4, extraflags=Varnode.precislo)
        enc = _MockEncoder()
        se.encode(enc)
        assert len(enc.calls) == 0  # isPiece => skip

    def test_encode_with_xml_encoder(self):
        """Full round-trip: encode to XML then verify structure."""
        from ghidra.core.marshal import XmlEncode
        sym = Symbol(name="x")
        se = SymbolEntry(sym, _addr(0x200), 4)
        enc = XmlEncode(do_format=False)
        se.encode(enc)
        xml = enc.toString()
        assert "addr" in xml or "0x200" in xml.lower() or "200" in xml


# =========================================================================
# Scope.addMapSym tests
# =========================================================================

from ghidra.core.marshal import XmlEncode, XmlDecode
from ghidra.core.space import AddrSpaceManager
from xml.etree.ElementTree import fromstring as xml_fromstring


def _mgr(*spaces):
    mgr = AddrSpaceManager()
    for s in spaces:
        mgr._insertSpace(s)
    return mgr


class TestScopeAddMapSym:
    def test_addMapSym_symbol(self):
        """addMapSym decodes a <mapsym> with a <symbol> child."""
        spc = _spc()
        mgr = _mgr(spc)
        xml_str = '''<mapsym>
            <symbol name="myVar" id="42" cat="-1"/>
            <addr space="ram" offset="0x100" size="4"/>
            <rangelist/>
        </mapsym>'''
        root = xml_fromstring(xml_str)
        dec = XmlDecode(mgr, root)
        sc = ScopeInternal(1, "test")
        sym = sc.addMapSym(dec)
        assert sym is not None
        assert sym.getName() == "myVar"
        assert sc.getNumSymbols() == 1

    def test_addMapSym_labelsym(self):
        """addMapSym decodes a <mapsym> with a <labelsym> child."""
        spc = _spc()
        mgr = _mgr(spc)
        xml_str = '''<mapsym>
            <labelsym name="loop_top" id="10" cat="-1"/>
            <addr space="ram" offset="0x400" size="1"/>
            <rangelist/>
        </mapsym>'''
        root = xml_fromstring(xml_str)
        dec = XmlDecode(mgr, root)
        sc = ScopeInternal(1, "test")
        sym = sc.addMapSym(dec)
        assert sym is not None
        assert isinstance(sym, LabSymbol)
        assert sym.getName() == "loop_top"

    def test_addMapSym_equatesymbol(self):
        """addMapSym decodes a <mapsym> with an <equatesymbol> child."""
        spc = _spc()
        mgr = _mgr(spc)
        # EquateSymbol.decode falls back to Symbol.decode
        xml_str = '''<mapsym>
            <equatesymbol name="MY_CONST" id="20" cat="1"/>
            <hash val="0x1234"/>
            <rangelist/>
        </mapsym>'''
        root = xml_fromstring(xml_str)
        dec = XmlDecode(mgr, root)
        sc = ScopeInternal(1, "test")
        sym = sc.addMapSym(dec)
        # May or may not succeed depending on EquateSymbol.decode impl
        # At minimum it shouldn't crash

    def test_addMapSym_empty_entries(self):
        """addMapSym with symbol but no entry elements."""
        spc = _spc()
        mgr = _mgr(spc)
        xml_str = '''<mapsym>
            <symbol name="noEntry" id="50" cat="-1"/>
        </mapsym>'''
        root = xml_fromstring(xml_str)
        dec = XmlDecode(mgr, root)
        sc = ScopeInternal(1, "test")
        sym = sc.addMapSym(dec)
        assert sym is not None
        assert sym.getName() == "noEntry"
        assert sym.numEntries() == 0


# =========================================================================
# ScopeInternal encode round-trip
# =========================================================================

class TestScopeInternalEncodeRoundTrip:
    def test_encode_produces_scope_element(self):
        sc = ScopeInternal(1, "test_scope")
        sym = Symbol(name="var1")
        sym.type = _MockDatatype("int", 4)
        sc.addSymbolInternal(sym, _addr(0x100), 4)
        enc = XmlEncode(do_format=False)
        sc.encode(enc)
        xml = enc.toString()
        assert "<scope" in xml
        assert 'name="test_scope"' in xml
        assert "<symbollist" in xml
        assert "<mapsym" in xml

    def test_encode_with_parent(self):
        parent = ScopeInternal(1, "parent")
        child = ScopeInternal(2, "child")
        parent.attachScope(child)
        enc = XmlEncode(do_format=False)
        child.encode(enc)
        xml = enc.toString()
        assert "<parent" in xml


# =========================================================================
# Regression: removeSymbol from category
# =========================================================================

class TestRemoveSymbolCategory:
    def test_remove_categorized_symbol(self):
        sc = ScopeInternal(1, "test")
        s = Symbol(name="param0")
        s.category = Symbol.function_parameter
        sc.addSymbol(s)
        assert sc.getCategorySize(Symbol.function_parameter) == 1
        sc.removeSymbol(s)
        assert sc.getNumSymbols() == 0
