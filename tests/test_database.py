"""Tests for ghidra.database.database -- SymbolEntry, Symbol, ScopeInternal, Database."""
from __future__ import annotations

from ghidra.core.address import Address, RangeList
from ghidra.core.space import AddrSpace
from ghidra.ir.varnode import Varnode
from ghidra.database.database import SymbolEntry, Symbol


def _spc():
    return AddrSpace(name="ram", size=4)


def _addr(off):
    return Address(_spc(), off)


# ---------------------------------------------------------------------------
# Symbol
# ---------------------------------------------------------------------------

class TestSymbol:
    def test_defaults(self):
        s = Symbol()
        assert s.getName() == ""
        assert s.getType() is None
        assert s.getId() == 0
        assert s.getFlags() == 0
        assert s.getCategory() == Symbol.no_category
        assert s.getCategoryIndex() == 0
        assert s.numEntries() == 0
        assert s.isNameUndefined() is True

    def test_construction(self):
        s = Symbol(name="myVar")
        assert s.getName() == "myVar"
        assert s.getDisplayName() == "myVar"
        assert s.isNameUndefined() is False

    def test_display_format(self):
        s = Symbol()
        assert s.getDisplayFormat() == 0
        s.setDisplayFormat(Symbol.force_hex)
        assert s.getDisplayFormat() == Symbol.force_hex
        s.setDisplayFormat(Symbol.force_dec)
        assert s.getDisplayFormat() == Symbol.force_dec

    def test_type_lock(self):
        s = Symbol()
        assert s.isTypeLocked() is False
        s.setTypeLock(True)
        assert s.isTypeLocked() is True
        s.setTypeLock(False)
        assert s.isTypeLocked() is False

    def test_name_lock(self):
        s = Symbol()
        assert s.isNameLocked() is False
        s.setNameLock(True)
        assert s.isNameLocked() is True
        s.setNameLock(False)
        assert s.isNameLocked() is False

    def test_volatile(self):
        s = Symbol()
        assert s.isVolatile() is False
        s.setVolatile(True)
        assert s.isVolatile() is True

    def test_this_pointer(self):
        s = Symbol()
        assert s.isThisPointer() is False
        s.setThisPointer(True)
        assert s.isThisPointer() is True
        s.setThisPointer(False)
        assert s.isThisPointer() is False

    def test_isolated(self):
        s = Symbol()
        assert s.isIsolated() is False
        s.setIsolated(True)
        assert s.isIsolated() is True
        s.setIsolated(False)
        assert s.isIsolated() is False

    def test_merge_problems(self):
        s = Symbol()
        assert s.hasMergeProblems() is False
        s.setMergeProblems(True)
        assert s.hasMergeProblems() is True

    def test_size_type_lock(self):
        s = Symbol()
        assert s.isSizeTypeLocked() is False
        s.setSizeTypeLock(True)
        assert s.isSizeTypeLocked() is True

    def test_set_name(self):
        s = Symbol(name="old")
        s.setName("new")
        assert s.getName() == "new"

    def test_set_display_name(self):
        s = Symbol(name="x")
        s.setDisplayName("display_x")
        assert s.getDisplayName() == "display_x"

    def test_set_category(self):
        s = Symbol()
        s.setCategory(Symbol.function_parameter, 3)
        assert s.getCategory() == Symbol.function_parameter
        assert s.getCategoryIndex() == 3

    def test_set_flags(self):
        s = Symbol()
        s.setFlags(Varnode.typelock)
        assert s.isTypeLocked() is True
        s.clearFlags(Varnode.typelock)
        assert s.isTypeLocked() is False

    def test_multi_entry(self):
        s = Symbol()
        assert s.isMultiEntry() is False
        s.wholeCount = 3
        assert s.isMultiEntry() is True

    def test_category_constants(self):
        assert Symbol.no_category == -1
        assert Symbol.function_parameter == 0
        assert Symbol.equate == 1
        assert Symbol.union_facet == 2
        assert Symbol.fake_input == 3

    def test_display_flag_constants(self):
        assert Symbol.force_hex == 1
        assert Symbol.force_dec == 2
        assert Symbol.force_oct == 3
        assert Symbol.force_bin == 4
        assert Symbol.force_char == 5
        assert Symbol.size_typelock == 8
        assert Symbol.isolate == 16
        assert Symbol.merge_problems == 32
        assert Symbol.is_this_ptr == 64

    def test_name_undefined_prefix(self):
        s = Symbol(name="$$undef_foo")
        assert s.isNameUndefined() is True

    def test_get_map_entry_empty(self):
        s = Symbol()
        assert s.getMapEntry() is None
        assert s.getMapEntry(0) is None


# ---------------------------------------------------------------------------
# SymbolEntry
# ---------------------------------------------------------------------------

class TestSymbolEntry:
    def _make_sym(self, name="test"):
        return Symbol(name=name)

    def test_defaults(self):
        sym = self._make_sym()
        se = SymbolEntry(sym)
        assert se.getSymbol() is sym
        assert se.getSize() == 0
        assert se.getOffset() == 0
        assert se.getHash() == 0

    def test_construction(self):
        sym = self._make_sym()
        addr = _addr(0x1000)
        se = SymbolEntry(sym, addr=addr, size=4, offset=0)
        assert se.getAddr().getOffset() == 0x1000
        assert se.getSize() == 4
        assert se.getFirst() == 0x1000
        assert se.getLast() == 0x1003

    def test_is_dynamic(self):
        sym = self._make_sym()
        se_static = SymbolEntry(sym, addr=_addr(0x100), size=4)
        assert se_static.isDynamic() is False
        se_dynamic = SymbolEntry(sym)
        assert se_dynamic.isDynamic() is True

    def test_is_invalid(self):
        sym = self._make_sym()
        se = SymbolEntry(sym)
        assert se.isInvalid() is True
        se_hash = SymbolEntry(sym, hash_=0xDEAD)
        assert se_hash.isInvalid() is False

    def test_in_use_no_limit(self):
        sym = self._make_sym()
        se = SymbolEntry(sym, addr=_addr(0x100), size=4)
        assert se.inUse(_addr(0x500)) is True

    def test_use_limit(self):
        sym = self._make_sym()
        se = SymbolEntry(sym, addr=_addr(0x100), size=4)
        assert se.getUseLimit() is not None
        rl = RangeList()
        se.setUseLimit(rl)
        assert se.getUseLimit() is rl

    def test_repr(self):
        sym = self._make_sym("foo")
        se = SymbolEntry(sym, addr=_addr(0x100), size=4)
        r = repr(se)
        assert "foo" in r
        assert "size=4" in r
