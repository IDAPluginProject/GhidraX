"""Tests for ghidra.analysis.dynamic -- ToOpEdge + DynamicHash."""
from __future__ import annotations

from ghidra.core.address import Address
from ghidra.core.space import AddrSpace
from ghidra.analysis.dynamic import ToOpEdge, DynamicHash


def _spc():
    return AddrSpace(name="ram", size=4)


# ---------------------------------------------------------------------------
# Fake helpers
# ---------------------------------------------------------------------------

class _FakeSeq:
    def __init__(self, order: int):
        self._order = order
    def getOrder(self):
        return self._order
    def __lt__(self, other):
        return self._order < other._order

class _FakeOp:
    def __init__(self, opc: int = 0, order: int = 0):
        self._opc = opc
        self._seq = _FakeSeq(order)
    def code(self):
        return self._opc
    def getSeqNum(self):
        return self._seq
    def numInput(self):
        return 0
    def getIn(self, i):
        return None
    def getAddr(self):
        return Address(_spc(), 0x1000)


# ---------------------------------------------------------------------------
# ToOpEdge
# ---------------------------------------------------------------------------

class TestToOpEdge:
    def test_defaults(self):
        e = ToOpEdge()
        assert e.getOp() is None
        assert e.getSlot() == -1

    def test_with_op(self):
        op = _FakeOp(opc=5, order=10)
        e = ToOpEdge(op, slot=2)
        assert e.getOp() is op
        assert e.getSlot() == 2

    def test_hash(self):
        op = _FakeOp(opc=7)
        e = ToOpEdge(op, slot=1)
        h = e.hash(0)
        assert isinstance(h, int)
        assert h != 0

    def test_hash_none_op(self):
        e = ToOpEdge(None, 0)
        h = e.hash(42)
        assert isinstance(h, int)

    def test_lt_both_none(self):
        e1 = ToOpEdge(None, 0)
        e2 = ToOpEdge(None, 0)
        assert not (e1 < e2)

    def test_lt_one_none(self):
        op = _FakeOp(order=5)
        e1 = ToOpEdge(None, 0)
        e2 = ToOpEdge(op, 0)
        assert e1 < e2
        assert not (e2 < e1)

    def test_lt_ordering(self):
        op1 = _FakeOp(order=5)
        op2 = _FakeOp(order=10)
        e1 = ToOpEdge(op1, 0)
        e2 = ToOpEdge(op2, 0)
        assert e1 < e2
        assert not (e2 < e1)


# ---------------------------------------------------------------------------
# DynamicHash
# ---------------------------------------------------------------------------

class TestDynamicHash:
    def test_defaults(self):
        dh = DynamicHash()
        assert dh.getHash() == 0
        assert dh.getAddress().isInvalid()

    def test_set_hash(self):
        dh = DynamicHash()
        dh.setHash(0xDEADBEEF)
        assert dh.getHash() == 0xDEADBEEF

    def test_set_address(self):
        dh = DynamicHash()
        addr = Address(_spc(), 0x4000)
        dh.setAddress(addr)
        assert dh.getAddress().getOffset() == 0x4000

    def test_clear(self):
        dh = DynamicHash()
        dh.setHash(123)
        dh.setAddress(Address(_spc(), 0x1000))
        dh.clear()
        assert dh.getHash() == 0
        assert dh.getAddress().isInvalid()

    def test_calc_hash_op(self):
        dh = DynamicHash()
        op = _FakeOp(opc=3, order=7)
        dh.calcHashOp(op, 0)
        assert dh.getHash() != 0

    def test_get_slot_from_hash(self):
        assert DynamicHash.getSlotFromHash(0) == 0
        h = 0x1F << 32
        assert DynamicHash.getSlotFromHash(h) == 0x1F

    def test_get_method_from_hash(self):
        h = 0xF << 37
        assert DynamicHash.getMethodFromHash(h) == 0xF

    def test_get_position_from_hash(self):
        h = 0x3F << 41
        assert DynamicHash.getPositionFromHash(h) == 0x3F

    def test_get_total_from_hash(self):
        h = 0x3F << 47
        assert DynamicHash.getTotalFromHash(h) == 0x3F

    def test_get_is_not_attached(self):
        assert DynamicHash.getIsNotAttached(0) is False
        assert DynamicHash.getIsNotAttached(1 << 63) is True

    def test_get_comparable(self):
        h = 0xFFFFFFFFDEADBEEF
        assert DynamicHash.getComparable(h) == 0xDEADBEEF

    def test_clear_total_position(self):
        h_ref = [0xFFFFFFFFFFFFFFFF]
        DynamicHash.clearTotalPosition(h_ref)
        assert DynamicHash.getPositionFromHash(h_ref[0]) == 0
        assert DynamicHash.getTotalFromHash(h_ref[0]) == 0

    def test_dedup_varnodes(self):
        a, b, c = object(), object(), object()
        lst = [a, b, a, c, b]
        DynamicHash.dedupVarnodes(lst)
        assert lst == [a, b, c]

    def test_repr(self):
        dh = DynamicHash()
        dh.setHash(0xFF)
        assert "0xff" in repr(dh)

    def test_edges_getters(self):
        dh = DynamicHash()
        assert dh.getVnEdges() == []
        assert dh.getOpEdges() == []
        assert dh.getMarkOps() == []
