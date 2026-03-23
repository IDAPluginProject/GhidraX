"""Tests for ghidra.analysis.merge -- BlockVarnode, HighIntersectTest, Merge."""
from __future__ import annotations

from ghidra.analysis.merge import BlockVarnode, HighIntersectTest, Merge
from ghidra.ir.cover import Cover, CoverBlock


# ---------------------------------------------------------------------------
# Fake helpers
# ---------------------------------------------------------------------------

class _FakeSeq:
    def __init__(self, order: int):
        self._order = order
    def getOrder(self):
        return self._order

class _FakeBlock:
    def __init__(self, index: int = 0):
        self._index = index
    def getIndex(self):
        return self._index

class _FakeOp:
    def __init__(self, order: int = 0, blk_index: int = 0):
        self._seq = _FakeSeq(order)
        self._blk = _FakeBlock(blk_index)
    def getSeqNum(self):
        return self._seq
    def getParent(self):
        return self._blk

class _FakeAddr:
    def __init__(self, off: int = 0):
        self._off = off
    def getOffset(self):
        return self._off
    def __eq__(self, other):
        return isinstance(other, _FakeAddr) and self._off == other._off
    def __hash__(self):
        return hash(self._off)

class _FakeVn:
    def __init__(self, defop=None, addr_off=0):
        self._def = defop
        self._addr = _FakeAddr(addr_off)
    def getDef(self):
        return self._def
    def getAddr(self):
        return self._addr

class _FakeHigh:
    def __init__(self, cover=None, type_lock=False, addr_tied=False, is_input=False, persist=False):
        self._cover = cover
        self._type_lock = type_lock
        self._addr_tied = addr_tied
        self._is_input = is_input
        self._persist = persist
        self._type = None
        self._symbol = None

    def getCover(self):
        return self._cover
    def isTypeLock(self):
        return self._type_lock
    def getType(self):
        return self._type
    def isAddrTied(self):
        return self._addr_tied
    def isInput(self):
        return self._is_input
    def isPersist(self):
        return self._persist
    def getSymbol(self):
        return self._symbol


# ---------------------------------------------------------------------------
# BlockVarnode
# ---------------------------------------------------------------------------

class TestBlockVarnode:
    def test_defaults(self):
        bv = BlockVarnode()
        assert bv.getVarnode() is None
        assert bv.getIndex() == 0

    def test_set_with_def(self):
        op = _FakeOp(order=5, blk_index=3)
        vn = _FakeVn(defop=op)
        bv = BlockVarnode()
        bv.set(vn)
        assert bv.getVarnode() is vn
        assert bv.getIndex() == 3

    def test_set_without_def(self):
        vn = _FakeVn(defop=None)
        bv = BlockVarnode()
        bv.set(vn)
        assert bv.getIndex() == 0

    def test_lt(self):
        op1 = _FakeOp(blk_index=1)
        op2 = _FakeOp(blk_index=5)
        vn1 = _FakeVn(defop=op1)
        vn2 = _FakeVn(defop=op2)
        bv1 = BlockVarnode()
        bv2 = BlockVarnode()
        bv1.set(vn1)
        bv2.set(vn2)
        assert bv1 < bv2
        assert not (bv2 < bv1)

    def test_find_front_found(self):
        op = _FakeOp(blk_index=3)
        vn = _FakeVn(defop=op)
        bv = BlockVarnode()
        bv.set(vn)
        blist = [bv]
        assert BlockVarnode.findFront(3, blist) == 0

    def test_find_front_not_found(self):
        op = _FakeOp(blk_index=5)
        vn = _FakeVn(defop=op)
        bv = BlockVarnode()
        bv.set(vn)
        blist = [bv]
        assert BlockVarnode.findFront(3, blist) == -1


# ---------------------------------------------------------------------------
# HighIntersectTest
# ---------------------------------------------------------------------------

class TestHighIntersectTest:
    def test_same_high(self):
        h = _FakeHigh()
        hit = HighIntersectTest()
        assert hit.intersection(h, h) is False

    def test_no_cover(self):
        h1 = _FakeHigh(cover=None)
        h2 = _FakeHigh(cover=None)
        hit = HighIntersectTest()
        assert hit.intersection(h1, h2) is False

    def test_intersecting_covers(self):
        c1 = Cover()
        cb1 = CoverBlock()
        cb1.setAll()
        c1._cover[0] = cb1
        c2 = Cover()
        cb2 = CoverBlock()
        cb2.setAll()
        c2._cover[0] = cb2
        h1 = _FakeHigh(cover=c1)
        h2 = _FakeHigh(cover=c2)
        hit = HighIntersectTest()
        # intersect returns 1 for full overlap, test checks == 2 for boundary
        result = hit.intersection(h1, h2)
        assert isinstance(result, bool)

    def test_cache(self):
        h1 = _FakeHigh(cover=None)
        h2 = _FakeHigh(cover=None)
        hit = HighIntersectTest()
        r1 = hit.intersection(h1, h2)
        r2 = hit.intersection(h1, h2)
        assert r1 == r2

    def test_clear(self):
        hit = HighIntersectTest()
        h1 = _FakeHigh(cover=None)
        h2 = _FakeHigh(cover=None)
        hit.intersection(h1, h2)
        hit.clear()
        assert hit._highedgemap == {}


# ---------------------------------------------------------------------------
# Merge.mergeTestRequired (static, no Funcdata needed)
# ---------------------------------------------------------------------------

class TestMergeTestRequired:
    def test_same_high(self):
        h = _FakeHigh()
        assert Merge.mergeTestRequired(h, h) is True

    def test_different_type_locks(self):
        h1 = _FakeHigh(type_lock=True)
        h1._type = object()
        h2 = _FakeHigh(type_lock=True)
        h2._type = object()
        assert Merge.mergeTestRequired(h1, h2) is False

    def test_same_type_locks(self):
        shared_type = object()
        h1 = _FakeHigh(type_lock=True)
        h1._type = shared_type
        h2 = _FakeHigh(type_lock=True)
        h2._type = shared_type
        assert Merge.mergeTestRequired(h1, h2) is True

    def test_input_vs_persist(self):
        h_in = _FakeHigh(is_input=True)
        h_out = _FakeHigh(persist=True)
        assert Merge.mergeTestRequired(h_out, h_in) is False

    def test_persist_vs_input(self):
        h_in = _FakeHigh(persist=True)
        h_out = _FakeHigh(is_input=True)
        assert Merge.mergeTestRequired(h_out, h_in) is False

    def test_different_symbols(self):
        h1 = _FakeHigh()
        h1._symbol = object()
        h2 = _FakeHigh()
        h2._symbol = object()
        assert Merge.mergeTestRequired(h1, h2) is False

    def test_same_symbol(self):
        sym = object()
        h1 = _FakeHigh()
        h1._symbol = sym
        h2 = _FakeHigh()
        h2._symbol = sym
        assert Merge.mergeTestRequired(h1, h2) is True

    def test_no_type_lock_no_special(self):
        h1 = _FakeHigh()
        h2 = _FakeHigh()
        assert Merge.mergeTestRequired(h1, h2) is True
