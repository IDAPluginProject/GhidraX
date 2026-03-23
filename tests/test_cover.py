"""Tests for ghidra.ir.cover -- CoverBlock + Cover."""
from __future__ import annotations

from ghidra.ir.cover import CoverBlock, Cover


# ---------------------------------------------------------------------------
# Fake PcodeOp for testing
# ---------------------------------------------------------------------------

class _FakeSeq:
    def __init__(self, order: int):
        self._order = order
    def getOrder(self) -> int:
        return self._order

class _FakeOp:
    def __init__(self, order: int, blk_index: int = 0):
        self._seq = _FakeSeq(order)
        self._blk_index = blk_index
    def getSeqNum(self):
        return self._seq
    def getParent(self):
        return _FakeBlock(self._blk_index)

class _FakeBlock:
    def __init__(self, index: int = 0):
        self._index = index
    def getIndex(self) -> int:
        return self._index


# ---------------------------------------------------------------------------
# CoverBlock
# ---------------------------------------------------------------------------

class TestCoverBlock:
    def test_empty(self):
        cb = CoverBlock()
        assert cb.empty()
        assert not cb.contain(None)

    def test_set_all(self):
        cb = CoverBlock()
        cb.setAll()
        assert not cb.empty()
        op = _FakeOp(5)
        assert cb.contain(op)

    def test_set_begin(self):
        cb = CoverBlock()
        op = _FakeOp(10)
        cb.setBegin(op)
        assert not cb.empty()

    def test_set_end(self):
        cb = CoverBlock()
        cb.setAll()
        op = _FakeOp(20)
        cb.setEnd(op)
        assert not cb.empty()

    def test_clear(self):
        cb = CoverBlock()
        cb.setAll()
        cb.clear()
        assert cb.empty()

    def test_contain_range(self):
        cb = CoverBlock()
        op_start = _FakeOp(5)
        op_end = _FakeOp(15)
        cb.setBegin(op_start)
        cb.setEnd(op_end)
        assert cb.contain(_FakeOp(10))
        assert cb.contain(_FakeOp(5))
        assert cb.contain(_FakeOp(15))

    def test_intersect_no_overlap(self):
        cb1 = CoverBlock()
        cb1.setBegin(_FakeOp(1))
        cb1.setEnd(_FakeOp(5))
        cb2 = CoverBlock()
        cb2.setBegin(_FakeOp(10))
        cb2.setEnd(_FakeOp(20))
        assert cb1.intersect(cb2) == 0

    def test_intersect_overlap(self):
        cb1 = CoverBlock()
        cb1.setBegin(_FakeOp(1))
        cb1.setEnd(_FakeOp(15))
        cb2 = CoverBlock()
        cb2.setBegin(_FakeOp(10))
        cb2.setEnd(_FakeOp(20))
        assert cb1.intersect(cb2) == 2

    def test_intersect_boundary(self):
        cb1 = CoverBlock()
        cb1.setBegin(_FakeOp(1))
        cb1.setEnd(_FakeOp(10))
        cb2 = CoverBlock()
        cb2.setBegin(_FakeOp(10))
        cb2.setEnd(_FakeOp(20))
        assert cb1.intersect(cb2) == 1

    def test_intersect_empty(self):
        cb1 = CoverBlock()
        cb2 = CoverBlock()
        cb2.setAll()
        assert cb1.intersect(cb2) == 0

    def test_merge_into_empty(self):
        cb1 = CoverBlock()
        cb2 = CoverBlock()
        cb2.setBegin(_FakeOp(5))
        cb2.setEnd(_FakeOp(15))
        cb1.merge(cb2)
        assert not cb1.empty()
        assert cb1.contain(_FakeOp(10))

    def test_merge_union(self):
        cb1 = CoverBlock()
        cb1.setBegin(_FakeOp(5))
        cb1.setEnd(_FakeOp(10))
        cb2 = CoverBlock()
        cb2.setBegin(_FakeOp(8))
        cb2.setEnd(_FakeOp(20))
        cb1.merge(cb2)
        assert cb1.contain(_FakeOp(5))
        assert cb1.contain(_FakeOp(20))

    def test_boundary(self):
        cb = CoverBlock()
        op_start = _FakeOp(5)
        op_end = _FakeOp(15)
        cb.setBegin(op_start)
        cb.setEnd(op_end)
        assert cb.boundary(_FakeOp(5)) & 1  # start boundary
        assert cb.boundary(_FakeOp(15)) & 2  # stop boundary
        assert cb.boundary(_FakeOp(10)) == 0  # interior

    def test_repr(self):
        cb = CoverBlock()
        assert "empty" in repr(cb)
        cb.setAll()
        assert "empty" not in repr(cb)


# ---------------------------------------------------------------------------
# Cover
# ---------------------------------------------------------------------------

class TestCover:
    def test_empty(self):
        c = Cover()
        assert c.getNumBlocks() == 0
        assert not c.containsBlock(0)

    def test_get_cover_block_missing(self):
        c = Cover()
        cb = c.getCoverBlock(99)
        assert cb.empty()

    def test_merge(self):
        c1 = Cover()
        c2 = Cover()
        cb = CoverBlock()
        cb.setAll()
        c2._cover[0] = cb
        c1.merge(c2)
        assert c1.containsBlock(0)

    def test_intersect_no_overlap(self):
        c1 = Cover()
        c2 = Cover()
        cb1 = CoverBlock()
        cb1.setBegin(_FakeOp(1))
        cb1.setEnd(_FakeOp(5))
        c1._cover[0] = cb1
        cb2 = CoverBlock()
        cb2.setBegin(_FakeOp(10))
        cb2.setEnd(_FakeOp(20))
        c2._cover[1] = cb2
        assert c1.intersect(c2) == 0

    def test_intersect_overlap(self):
        c1 = Cover()
        c2 = Cover()
        cb1 = CoverBlock()
        cb1.setAll()
        c1._cover[0] = cb1
        cb2 = CoverBlock()
        cb2.setAll()
        c2._cover[0] = cb2
        assert c1.intersect(c2) == 2

    def test_intersect_by_block(self):
        c1 = Cover()
        c2 = Cover()
        cb1 = CoverBlock()
        cb1.setAll()
        c1._cover[0] = cb1
        cb2 = CoverBlock()
        cb2.setAll()
        c2._cover[0] = cb2
        assert c1.intersectByBlock(0, c2) == 2
        assert c1.intersectByBlock(1, c2) == 0

    def test_intersect_list(self):
        c1 = Cover()
        c2 = Cover()
        cb1 = CoverBlock()
        cb1.setAll()
        c1._cover[0] = cb1
        cb2 = CoverBlock()
        cb2.setAll()
        c2._cover[0] = cb2
        result = c1.intersectList(c2, 1)
        assert 0 in result

    def test_clear(self):
        c = Cover()
        cb = CoverBlock()
        cb.setAll()
        c._cover[0] = cb
        c.clear()
        assert c.getNumBlocks() == 0

    def test_compare_to_same(self):
        c1 = Cover()
        c2 = Cover()
        cb = CoverBlock()
        cb.setAll()
        c1._cover[0] = cb
        c2._cover[0] = cb
        assert c1.compareTo(c2) == 0

    def test_iter(self):
        c = Cover()
        cb = CoverBlock()
        cb.setAll()
        c._cover[5] = cb
        items = list(c)
        assert len(items) == 1
        assert items[0][0] == 5

    def test_repr(self):
        c = Cover()
        cb = CoverBlock()
        cb.setAll()
        c._cover[3] = cb
        assert "blk3" in repr(c)
