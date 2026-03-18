"""Tests for ghidra.transform.condexe – Python port of condexe.cc."""
from __future__ import annotations

import pytest
import sys, os

sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', 'python'))

from ghidra.core.opcodes import OpCode
from ghidra.transform.condexe import (
    ConditionalExecution, RuleOrPredicate, _MultiPredicate,
)


# =========================================================================
# Lightweight stub infrastructure for unit testing condexe logic
# without a real Funcdata / heritage / block graph.
# =========================================================================

class StubVarnode:
    """Minimal Varnode stub."""
    _counter = 0

    def __init__(self, size=4, offset=0, is_const=False, is_free=False):
        StubVarnode._counter += 1
        self._id = StubVarnode._counter
        self._size = size
        self._offset = offset
        self._is_const = is_const
        self._is_free = is_free
        self._def_op = None
        self._descend = []
        self._addr_tied = False
        self._space = StubSpace()

    def getSize(self): return self._size
    def getOffset(self): return self._offset
    def isConstant(self): return self._is_const
    def isFree(self): return self._is_free
    def isWritten(self): return self._def_op is not None
    def getDef(self): return self._def_op
    def getDescend(self): return list(self._descend)
    def isAddrTied(self): return self._addr_tied
    def getSpace(self): return self._space
    def getAddr(self): return self._offset
    def loneDescend(self):
        return self._descend[0] if len(self._descend) == 1 else None
    def addDescend(self, op):
        self._descend.append(op)


class StubSpace:
    def __init__(self, idx=0, heritaged=True):
        self._idx = idx
        self._heritaged = heritaged
    def getIndex(self): return self._idx
    def isHeritaged(self): return self._heritaged


class StubOp:
    """Minimal PcodeOp stub."""
    _counter = 0

    def __init__(self, opc, inputs=None, output=None, parent=None):
        StubOp._counter += 1
        self._id = StubOp._counter
        self._opc = opc
        self._inputs = inputs or []
        self._output = output
        self._parent = parent
        self._is_branch = False
        self._is_call = False
        self._is_flow_break = False
        self._boolean_flip = False
        # Wire def
        if output is not None:
            output._def_op = self
        # Wire descend
        for inp in self._inputs:
            if inp is not None and hasattr(inp, 'addDescend'):
                inp.addDescend(self)

    def code(self): return self._opc
    def getIn(self, i): return self._inputs[i]
    def getOut(self): return self._output
    def numInput(self): return len(self._inputs)
    def getParent(self): return self._parent
    def isBranch(self): return self._is_branch
    def isCall(self): return self._is_call
    def isFlowBreak(self): return self._is_flow_break
    def isBooleanFlip(self): return self._boolean_flip
    def isIndirectCreation(self): return False
    def getAddr(self): return 0
    def getSlot(self, vn):
        for i, v in enumerate(self._inputs):
            if v is vn:
                return i
        return -1
    def compareOrder(self, other):
        if self._id < other._id: return -1
        if self._id > other._id: return 1
        return 0
    def getStart(self): return 0


class StubBlock:
    """Minimal BlockBasic stub."""
    _counter = 0

    def __init__(self):
        StubBlock._counter += 1
        self._index = StubBlock._counter
        self._in = []
        self._out = []
        self._ops = []
        self._immed_dom = None
        self._in_rev = []

    def getIndex(self): return self._index
    def sizeIn(self): return len(self._in)
    def sizeOut(self): return len(self._out)
    def getIn(self, i): return self._in[i]
    def getOut(self, i): return self._out[i]
    def getTrueOut(self): return self._out[1] if len(self._out) > 1 else None
    def getFalseOut(self): return self._out[0] if len(self._out) > 0 else None
    def lastOp(self): return self._ops[-1] if self._ops else None
    def getOpList(self): return list(self._ops)
    def getImmedDom(self): return self._immed_dom
    def getStart(self): return 0
    def getInRevIndex(self, i):
        if i < len(self._in_rev):
            return self._in_rev[i]
        return 0

    def addOp(self, op):
        self._ops.append(op)
        op._parent = self


class StubArch:
    def __init__(self, spaces=None):
        self._spaces = spaces or [StubSpace(0), StubSpace(1)]
    def numSpaces(self): return len(self._spaces)
    def getSpace(self, i):
        if i < len(self._spaces):
            return self._spaces[i]
        return None


class StubFuncdata:
    """Minimal Funcdata stub for ConditionalExecution."""
    def __init__(self, arch=None):
        self._arch = arch or StubArch()
        self._heritage_passes = {}
        self._destroyed = []
        self._removed_splits = []
    def getArch(self): return self._arch
    def numHeritagePasses(self, spc): return self._heritage_passes.get(spc.getIndex(), 0)
    def opDestroy(self, op): self._destroyed.append(op)
    def removeFromFlowSplit(self, block, flag): self._removed_splits.append((block, flag))
    def opUnsetInput(self, op, slot): pass
    def opSetInput(self, op, vn, slot):
        while len(op._inputs) <= slot:
            op._inputs.append(None)
        op._inputs[slot] = vn
    def opSetOpcode(self, op, opc): op._opc = opc
    def opRemoveInput(self, op, slot):
        if slot < len(op._inputs):
            op._inputs.pop(slot)
    def opInsertBegin(self, op, bl): bl._ops.insert(0, op)
    def opInsertEnd(self, op, bl): bl._ops.append(op)
    def opInsertBefore(self, op, before): pass
    def newOp(self, nInputs, addr):
        return StubOp(OpCode.CPUI_COPY, [None]*nInputs)
    def newUniqueOut(self, size, op):
        vn = StubVarnode(size)
        op._output = vn
        vn._def_op = op
        return vn
    def newVarnodeOut(self, size, addr, op):
        vn = StubVarnode(size)
        op._output = vn
        vn._def_op = op
        return vn
    def hasUnreachableBlocks(self): return False
    def getBasicBlocks(self): return StubBlockGraph()


class StubBlockGraph:
    def __init__(self, blocks=None):
        self._blocks = blocks or []
    def getSize(self): return len(self._blocks)
    def getBlock(self, i): return self._blocks[i]


# =========================================================================
# Tests – ConditionalExecution
# =========================================================================

class TestConditionalExecution:
    def test_heritage_array_built(self):
        spc0 = StubSpace(0, True)
        spc1 = StubSpace(1, False)
        arch = StubArch([spc0, spc1])
        fd = StubFuncdata(arch)
        fd._heritage_passes = {0: 1}
        ce = ConditionalExecution(fd)
        assert ce.heritageyes[0] is True
        assert ce.heritageyes[1] is False

    def test_testIBlock_rejects_wrong_shape(self):
        fd = StubFuncdata()
        ce = ConditionalExecution(fd)
        # Block with 1 in
        bl = StubBlock()
        bl._in = [StubBlock()]
        bl._out = [StubBlock(), StubBlock()]
        ce.iblock = bl
        assert ce._testIBlock() is False

    def test_testIBlock_rejects_no_cbranch(self):
        fd = StubFuncdata()
        ce = ConditionalExecution(fd)
        bl = StubBlock()
        bl._in = [StubBlock(), StubBlock()]
        bl._out = [StubBlock(), StubBlock()]
        # Add a non-CBRANCH op
        nop = StubOp(OpCode.CPUI_COPY)
        bl.addOp(nop)
        ce.iblock = bl
        assert ce._testIBlock() is False

    def test_testIBlock_accepts_valid(self):
        fd = StubFuncdata()
        ce = ConditionalExecution(fd)
        bl = StubBlock()
        bl._in = [StubBlock(), StubBlock()]
        bl._out = [StubBlock(), StubBlock()]
        boolvn = StubVarnode(1)
        addrvn = StubVarnode(4)
        cb = StubOp(OpCode.CPUI_CBRANCH, [addrvn, boolvn])
        bl.addOp(cb)
        ce.iblock = bl
        assert ce._testIBlock() is True
        assert ce.cbranch is cb

    def test_trial_rejects_simple_block(self):
        """A block with 1 in edge should fail trial."""
        fd = StubFuncdata()
        ce = ConditionalExecution(fd)
        bl = StubBlock()
        bl._in = [StubBlock()]
        bl._out = [StubBlock()]
        assert ce.trial(bl) is False


# =========================================================================
# Tests – _MultiPredicate
# =========================================================================

class TestMultiPredicate:
    def test_discover_zero_slot_basic(self):
        mp = _MultiPredicate()
        # Build: phi(COPY(0), otherVn)
        zero_const = StubVarnode(4, 0, is_const=True)
        copy_op = StubOp(OpCode.CPUI_COPY, [zero_const], StubVarnode(4))
        other_vn = StubVarnode(4)
        phi_out = StubVarnode(4)
        phi_op = StubOp(OpCode.CPUI_MULTIEQUAL, [copy_op._output, other_vn], phi_out)
        assert mp.discoverZeroSlot(phi_out) is True
        assert mp.zeroSlot == 0
        assert mp.otherVn is other_vn

    def test_discover_zero_slot_reversed(self):
        mp = _MultiPredicate()
        other_vn = StubVarnode(4)
        zero_const = StubVarnode(4, 0, is_const=True)
        copy_op = StubOp(OpCode.CPUI_COPY, [zero_const], StubVarnode(4))
        phi_out = StubVarnode(4)
        phi_op = StubOp(OpCode.CPUI_MULTIEQUAL, [other_vn, copy_op._output], phi_out)
        assert mp.discoverZeroSlot(phi_out) is True
        assert mp.zeroSlot == 1
        assert mp.otherVn is other_vn

    def test_discover_zero_slot_no_multiequal(self):
        mp = _MultiPredicate()
        vn = StubVarnode(4)
        StubOp(OpCode.CPUI_COPY, [StubVarnode(4)], vn)
        assert mp.discoverZeroSlot(vn) is False

    def test_discover_zero_slot_free_other(self):
        mp = _MultiPredicate()
        zero_const = StubVarnode(4, 0, is_const=True)
        copy_op = StubOp(OpCode.CPUI_COPY, [zero_const], StubVarnode(4))
        other_vn = StubVarnode(4, is_free=True)
        phi_out = StubVarnode(4)
        phi_op = StubOp(OpCode.CPUI_MULTIEQUAL, [copy_op._output, other_vn], phi_out)
        assert mp.discoverZeroSlot(phi_out) is False

    def test_discover_zero_slot_nonzero_const(self):
        mp = _MultiPredicate()
        nonzero_const = StubVarnode(4, 42, is_const=True)
        copy_op = StubOp(OpCode.CPUI_COPY, [nonzero_const], StubVarnode(4))
        other_vn = StubVarnode(4)
        phi_out = StubVarnode(4)
        phi_op = StubOp(OpCode.CPUI_MULTIEQUAL, [copy_op._output, other_vn], phi_out)
        assert mp.discoverZeroSlot(phi_out) is False

    def test_discover_zero_slot_unwritten(self):
        mp = _MultiPredicate()
        vn = StubVarnode(4)  # No def op
        assert mp.discoverZeroSlot(vn) is False


# =========================================================================
# Tests – RuleOrPredicate
# =========================================================================

class TestRuleOrPredicate:
    def test_get_op_list(self):
        rule = RuleOrPredicate("analysis")
        ops = rule.getOpList()
        assert OpCode.CPUI_INT_OR in ops
        assert OpCode.CPUI_INT_XOR in ops

    def test_apply_no_match(self):
        rule = RuleOrPredicate("analysis")
        fd = StubFuncdata()
        # INT_OR of two plain varnodes (no MULTIEQUAL pattern)
        vn0 = StubVarnode(4, 1)
        vn1 = StubVarnode(4, 2)
        out = StubVarnode(4)
        op = StubOp(OpCode.CPUI_INT_OR, [vn0, vn1], out)
        assert rule.applyOp(op, fd) == 0

    def test_init(self):
        rule = RuleOrPredicate("test_group")
        assert rule._group == "test_group"
        assert rule._name == "orpredicate"


# =========================================================================
# Tests – ConditionalExecution edge cases
# =========================================================================

class TestConditionalExecutionEdge:
    def test_empty_heritage(self):
        """No heritage passes at all."""
        arch = StubArch([StubSpace(0, True)])
        fd = StubFuncdata(arch)
        ce = ConditionalExecution(fd)
        assert ce.heritageyes == [False]

    def test_heritage_with_passes(self):
        """One space with passes, one without."""
        spc0 = StubSpace(0, True)
        spc1 = StubSpace(1, True)
        arch = StubArch([spc0, spc1])
        fd = StubFuncdata(arch)
        fd._heritage_passes = {0: 2, 1: 0}
        ce = ConditionalExecution(fd)
        assert ce.heritageyes[0] is True
        assert ce.heritageyes[1] is False

    def test_testRemovability_multiequal(self):
        """MULTIEQUAL with valid descend should be removable."""
        fd = StubFuncdata()
        ce = ConditionalExecution(fd)
        ce.heritageyes = [True, True]
        ibl = StubBlock()
        ce.iblock = ibl
        out_vn = StubVarnode(4)
        in0 = StubVarnode(4)
        in1 = StubVarnode(4)
        phi = StubOp(OpCode.CPUI_MULTIEQUAL, [in0, in1], out_vn, ibl)
        # Add a COPY reader in a different block
        other_bl = StubBlock()
        copy_out = StubVarnode(4)
        copy_op = StubOp(OpCode.CPUI_COPY, [out_vn], copy_out, other_bl)
        # testMultiRead should pass for non-iblock COPY
        assert ce._testRemovability(phi) is True

    def test_testRemovability_load_rejected(self):
        """LOAD op should not be removable."""
        fd = StubFuncdata()
        ce = ConditionalExecution(fd)
        ce.heritageyes = [True]
        ibl = StubBlock()
        ce.iblock = ibl
        spc_vn = StubVarnode(4)
        addr_vn = StubVarnode(4)
        out_vn = StubVarnode(4)
        load_op = StubOp(OpCode.CPUI_LOAD, [spc_vn, addr_vn], out_vn, ibl)
        assert ce._testRemovability(load_op) is False

    def test_testRemovability_indirect_rejected(self):
        """INDIRECT op should not be removable."""
        fd = StubFuncdata()
        ce = ConditionalExecution(fd)
        ce.iblock = StubBlock()
        in0 = StubVarnode(4)
        in1 = StubVarnode(4)
        out = StubVarnode(4)
        ind = StubOp(OpCode.CPUI_INDIRECT, [in0, in1], out, ce.iblock)
        assert ce._testRemovability(ind) is False


if __name__ == '__main__':
    pytest.main([__file__, '-v'])
