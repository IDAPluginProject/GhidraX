"""Tests for ghidra.core.expression -- PcodeOpNode, TraverseNode, BooleanMatch, TermOrder, AddExpression."""
from __future__ import annotations

from ghidra.core.expression import (
    PcodeOpNode, TraverseNode, BooleanMatch,
    AdditiveEdge, TermOrder, AddExpression,
    functionalEquality, functionalDifference,
)


# ---------------------------------------------------------------------------
# PcodeOpNode
# ---------------------------------------------------------------------------

class TestPcodeOpNode:
    def test_construction(self):
        node = PcodeOpNode(op=None, slot=2)
        assert node.op is None
        assert node.slot == 2

    def test_default_slot(self):
        node = PcodeOpNode()
        assert node.slot == 0


# ---------------------------------------------------------------------------
# TraverseNode
# ---------------------------------------------------------------------------

class TestTraverseNode:
    def test_flags(self):
        tn = TraverseNode(vn=None, flags=TraverseNode.actionalt | TraverseNode.indirect)
        assert tn.flags & TraverseNode.actionalt
        assert tn.flags & TraverseNode.indirect

    def test_flag_constants(self):
        assert TraverseNode.actionalt == 1
        assert TraverseNode.indirect == 2
        assert TraverseNode.indirectalt == 4
        assert TraverseNode.lsb_truncated == 8
        assert TraverseNode.concat_high == 0x10


# ---------------------------------------------------------------------------
# BooleanMatch constants
# ---------------------------------------------------------------------------

class TestBooleanMatchConstants:
    def test_values(self):
        assert BooleanMatch.same == 1
        assert BooleanMatch.complementary == 2
        assert BooleanMatch.uncorrelated == 3


# ---------------------------------------------------------------------------
# AdditiveEdge
# ---------------------------------------------------------------------------

class _FakeVn:
    def __init__(self, offset=0, sz=4, written=False, free=False, const=False, inp=False):
        self._offset = offset
        self._size = sz
        self._written = written
        self._free = free
        self._const = const
        self._input = inp
        self._def = None
        self._desc = []

    def getOffset(self):
        return self._offset

    def getSize(self):
        return self._size

    def isWritten(self):
        return self._written

    def isFree(self):
        return self._free

    def isConstant(self):
        return self._const

    def isInput(self):
        return self._input

    def getDef(self):
        return self._def

    def loneDescend(self):
        return self._desc[0] if len(self._desc) == 1 else None

    def getAddr(self):
        return self._offset

    def getHigh(self):
        return None

    def termOrder(self, other):
        if self._offset < other._offset:
            return -1
        if self._offset > other._offset:
            return 1
        return 0


class _FakeOp:
    def __init__(self, opc=0, inputs=None):
        self._opc = opc
        self._inputs = inputs or []

    def code(self):
        return self._opc

    def getIn(self, i):
        return self._inputs[i]

    def numInput(self):
        return len(self._inputs)

    def getAddr(self):
        return 0

    def getOut(self):
        return None

    def isMarker(self):
        return False

    def isCall(self):
        return False

    def isBoolOutput(self):
        return False

    def isCommutative(self):
        return False

    def getSeqNum(self):
        class _Seq:
            def getTime(self):
                return 0
        return _Seq()


class TestAdditiveEdge:
    def test_basic(self):
        vn = _FakeVn(offset=42)
        op = _FakeOp(inputs=[vn])
        edge = AdditiveEdge(op, 0)
        assert edge.getVarnode() is vn
        assert edge.getOp() is op
        assert edge.getSlot() == 0
        assert edge.getMultiplier() is None


# ---------------------------------------------------------------------------
# functionalEquality / functionalDifference with simple varnodes
# ---------------------------------------------------------------------------

class TestFunctionalEquality:
    def test_same_object(self):
        vn = _FakeVn(offset=10, sz=4)
        assert functionalEquality(vn, vn) is True

    def test_same_constant(self):
        a = _FakeVn(offset=99, sz=4, const=True)
        b = _FakeVn(offset=99, sz=4, const=True)
        assert functionalEquality(a, b) is True

    def test_different_constant(self):
        a = _FakeVn(offset=1, sz=4, const=True)
        b = _FakeVn(offset=2, sz=4, const=True)
        assert functionalEquality(a, b) is False

    def test_different_size(self):
        a = _FakeVn(offset=1, sz=4, const=True)
        b = _FakeVn(offset=1, sz=8, const=True)
        assert functionalEquality(a, b) is False

    def test_free_varnodes(self):
        a = _FakeVn(offset=1, sz=4, free=True)
        b = _FakeVn(offset=1, sz=4, free=True)
        assert functionalEquality(a, b) is False


class TestFunctionalDifference:
    def test_same_object(self):
        vn = _FakeVn()
        assert functionalDifference(vn, vn, 1) is False

    def test_different_constants(self):
        a = _FakeVn(offset=1, sz=4, const=True)
        b = _FakeVn(offset=2, sz=4, const=True)
        assert functionalDifference(a, b, 1) is True

    def test_same_constants(self):
        a = _FakeVn(offset=5, sz=4, const=True)
        b = _FakeVn(offset=5, sz=4, const=True)
        assert functionalDifference(a, b, 1) is False

    def test_input_varnodes_not_different(self):
        a = _FakeVn(offset=1, sz=4, inp=True)
        b = _FakeVn(offset=1, sz=4, inp=True)
        assert functionalDifference(a, b, 1) is False

    def test_free_varnodes_not_different(self):
        a = _FakeVn(offset=1, sz=4, free=True)
        b = _FakeVn(offset=2, sz=4, free=True)
        assert functionalDifference(a, b, 1) is False
