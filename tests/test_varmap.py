"""Tests for ghidra.database.varmap -- NameRecommend, DynamicRecommend, TypeRecommend, RangeHint."""
from __future__ import annotations

from ghidra.core.address import Address
from ghidra.core.space import AddrSpace
from ghidra.database.varmap import NameRecommend, DynamicRecommend, TypeRecommend, RangeHint


def _spc():
    return AddrSpace(name="ram", size=4)


def _addr(off):
    return Address(_spc(), off)


# ---------------------------------------------------------------------------
# NameRecommend
# ---------------------------------------------------------------------------

class TestNameRecommend:
    def test_construction(self):
        nr = NameRecommend(_addr(0x100), _addr(0x200), 4, "myVar", 42)
        assert nr.getAddr().getOffset() == 0x100
        assert nr.getUseAddr().getOffset() == 0x200
        assert nr.getSize() == 4
        assert nr.getName() == "myVar"
        assert nr.getSymbolId() == 42


# ---------------------------------------------------------------------------
# DynamicRecommend
# ---------------------------------------------------------------------------

class TestDynamicRecommend:
    def test_construction(self):
        dr = DynamicRecommend(_addr(0x300), 0xDEAD, "dynVar", 99)
        assert dr.getAddress().getOffset() == 0x300
        assert dr.getHash() == 0xDEAD
        assert dr.getName() == "dynVar"
        assert dr.getSymbolId() == 99


# ---------------------------------------------------------------------------
# TypeRecommend
# ---------------------------------------------------------------------------

class TestTypeRecommend:
    def test_construction(self):
        sentinel = object()
        tr = TypeRecommend(_addr(0x400), sentinel)
        assert tr.getAddress().getOffset() == 0x400
        assert tr.getType() is sentinel


# ---------------------------------------------------------------------------
# RangeHint
# ---------------------------------------------------------------------------

class TestRangeHint:
    def test_defaults(self):
        rh = RangeHint()
        assert rh.start == 0
        assert rh.size == 0
        assert rh.sstart == 0
        assert rh.type is None
        assert rh.flags == 0
        assert rh.rangeType == 0
        assert rh.highind == 0

    def test_construction(self):
        rh = RangeHint(st=10, sz=4, sst=20, fl=RangeHint.typelock, rt=RangeHint.fixed)
        assert rh.start == 10
        assert rh.size == 4
        assert rh.sstart == 20
        assert rh.isTypeLock() is True
        assert rh.rangeType == RangeHint.fixed

    def test_type_constants(self):
        assert RangeHint.fixed == 0
        assert RangeHint.open == 1
        assert RangeHint.endpoint == 2

    def test_flag_constants(self):
        assert RangeHint.typelock == 1
        assert RangeHint.copy_constant == 2

    def test_is_type_lock(self):
        rh = RangeHint(fl=0)
        assert rh.isTypeLock() is False
        rh.flags = RangeHint.typelock
        assert rh.isTypeLock() is True

    def test_contain(self):
        a = RangeHint(sst=10, sz=20)
        b = RangeHint(sst=10, sz=5)
        assert a.contain(b) is True

    def test_contain_inner(self):
        a = RangeHint(sst=10, sz=20)
        b = RangeHint(sst=15, sz=5)
        assert a.contain(b) is True

    def test_contain_outside(self):
        a = RangeHint(sst=10, sz=5)
        b = RangeHint(sst=20, sz=5)
        assert a.contain(b) is False
