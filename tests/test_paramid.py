"""Tests for ghidra.fspec.paramid – Python port of paramid.cc."""
from __future__ import annotations

import pytest
import sys, os

sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', 'python'))

from ghidra.core.opcodes import OpCode
from ghidra.fspec.paramid import (
    ParamMeasure, ParamIDAnalysis, ParamRank, ParamIDIO, MAXDEPTH,
)


# =========================================================================
# Lightweight stub infrastructure
# =========================================================================

class StubSpace:
    def __init__(self, name="ram", idx=0):
        self._name = name
        self._idx = idx
    def getName(self): return self._name
    def getIndex(self): return self._idx
    def encodeAttributes(self, enc, off, sz): pass


class StubAddress:
    def __init__(self, space=None, offset=0):
        self._space = space or StubSpace()
        self._offset = offset
    def getSpace(self): return self._space
    def getOffset(self): return self._offset
    def isInvalid(self): return self._offset == 0xFFFFFFFF
    def encode(self, enc): pass


class StubVarnode:
    _counter = 0

    def __init__(self, size=4, offset=0, is_input=False):
        StubVarnode._counter += 1
        self._id = StubVarnode._counter
        self._size = size
        self._offset = offset
        self._is_input = is_input
        self._def_op = None
        self._descend = []
        self._space = StubSpace()
        self._type = None

    def getSize(self): return self._size
    def getOffset(self): return self._offset
    def isInput(self): return self._is_input
    def isWritten(self): return self._def_op is not None
    def getDef(self): return self._def_op
    def getDescend(self): return list(self._descend)
    def getOut(self): return None
    def getSpace(self): return self._space
    def getAddr(self): return StubAddress(self._space, self._offset)
    def getType(self): return self._type

    def addDescend(self, op):
        self._descend.append(op)


class StubBlock:
    def __init__(self):
        self._loop_in = set()

    def isLoopIn(self, slot):
        return slot in self._loop_in


class StubOp:
    _counter = 0

    def __init__(self, opc, inputs=None, output=None, parent=None):
        StubOp._counter += 1
        self._id = StubOp._counter
        self._opc = opc
        self._inputs = inputs or []
        self._output = output
        self._parent = parent or StubBlock()
        if output is not None:
            output._def_op = self
        for inp in self._inputs:
            if inp is not None and hasattr(inp, 'addDescend'):
                inp.addDescend(self)

    def code(self): return self._opc
    def getIn(self, i): return self._inputs[i]
    def getOut(self): return self._output
    def numInput(self): return len(self._inputs)
    def getParent(self): return self._parent
    def getSlot(self, vn):
        for i, v in enumerate(self._inputs):
            if v is vn:
                return i
        return -1
    def getOpcode(self):
        return self


# =========================================================================
# Tests – ParamRank enum
# =========================================================================

class TestParamRank:
    def test_rank_values(self):
        assert ParamRank.BESTRANK == 1
        assert ParamRank.DIRECTREAD == 2
        assert ParamRank.WORSTRANK == 7

    def test_rank_ordering(self):
        assert ParamRank.BESTRANK < ParamRank.DIRECTREAD
        assert ParamRank.DIRECTREAD < ParamRank.SUBFNPARAM
        assert ParamRank.SUBFNPARAM < ParamRank.INDIRECT
        assert ParamRank.INDIRECT < ParamRank.WORSTRANK


class TestParamIDIO:
    def test_io_values(self):
        assert ParamIDIO.INPUT == 0
        assert ParamIDIO.OUTPUT == 1


# =========================================================================
# Tests – ParamMeasure construction
# =========================================================================

class TestParamMeasureInit:
    def test_basic_construction(self):
        addr = StubAddress()
        pm = ParamMeasure(addr, 4, None, ParamIDIO.INPUT)
        assert pm.vndata.size == 4
        assert pm.io == ParamIDIO.INPUT
        assert pm.rank == ParamRank.WORSTRANK
        assert pm.numcalls == 0

    def test_output_construction(self):
        addr = StubAddress(offset=0x100)
        pm = ParamMeasure(addr, 8, None, ParamIDIO.OUTPUT)
        assert pm.io == ParamIDIO.OUTPUT
        assert pm.vndata.offset == 0x100


# =========================================================================
# Tests – walkforward (INPUT rank calculation)
# =========================================================================

class TestWalkForward:
    def test_direct_read_branch(self):
        """Varnode used as input0 of BRANCH → DIRECTREAD."""
        addr = StubAddress()
        pm = ParamMeasure(addr, 4, None, ParamIDIO.INPUT)
        vn = StubVarnode(4, is_input=True)
        StubOp(OpCode.CPUI_BRANCH, [vn])
        pm.calculateRank(True, vn, None)
        assert pm.getMeasure() == ParamRank.DIRECTREAD

    def test_direct_read_cbranch_slot0(self):
        """Varnode used as input0 of CBRANCH → DIRECTREAD."""
        addr = StubAddress()
        pm = ParamMeasure(addr, 4, None, ParamIDIO.INPUT)
        vn = StubVarnode(4, is_input=True)
        other = StubVarnode(1)
        StubOp(OpCode.CPUI_CBRANCH, [vn, other])
        pm.calculateRank(True, vn, None)
        assert pm.getMeasure() == ParamRank.DIRECTREAD

    def test_direct_read_cbranch_slot1(self):
        """Varnode used as input1 of CBRANCH → DIRECTREAD."""
        addr = StubAddress()
        pm = ParamMeasure(addr, 4, None, ParamIDIO.INPUT)
        vn = StubVarnode(1, is_input=True)
        other = StubVarnode(4)
        StubOp(OpCode.CPUI_CBRANCH, [other, vn])
        pm.calculateRank(True, vn, None)
        assert pm.getMeasure() == ParamRank.DIRECTREAD

    def test_subfn_param(self):
        """Varnode used as non-target input of CALL → SUBFNPARAM."""
        addr = StubAddress()
        pm = ParamMeasure(addr, 4, None, ParamIDIO.INPUT)
        vn = StubVarnode(4, is_input=True)
        target = StubVarnode(4)
        StubOp(OpCode.CPUI_CALL, [target, vn])
        pm.calculateRank(True, vn, None)
        assert pm.getMeasure() == ParamRank.SUBFNPARAM
        assert pm.numcalls == 1

    def test_call_target_is_directread(self):
        """Varnode used as input0 (target) of CALL → DIRECTREAD."""
        addr = StubAddress()
        pm = ParamMeasure(addr, 4, None, ParamIDIO.INPUT)
        vn = StubVarnode(4, is_input=True)
        arg = StubVarnode(4)
        StubOp(OpCode.CPUI_CALL, [vn, arg])
        pm.calculateRank(True, vn, None)
        assert pm.getMeasure() == ParamRank.DIRECTREAD

    def test_return_is_thisfnreturn(self):
        """Varnode used by RETURN → THISFNRETURN."""
        addr = StubAddress()
        pm = ParamMeasure(addr, 4, None, ParamIDIO.INPUT)
        vn = StubVarnode(4, is_input=True)
        StubOp(OpCode.CPUI_RETURN, [StubVarnode(4), vn])
        pm.calculateRank(True, vn, None)
        assert pm.getMeasure() == ParamRank.THISFNRETURN

    def test_indirect_rank(self):
        """Varnode used by INDIRECT → INDIRECT."""
        addr = StubAddress()
        pm = ParamMeasure(addr, 4, None, ParamIDIO.INPUT)
        vn = StubVarnode(4, is_input=True)
        StubOp(OpCode.CPUI_INDIRECT, [vn, StubVarnode(4)])
        pm.calculateRank(True, vn, None)
        assert pm.getMeasure() == ParamRank.INDIRECT

    def test_callother_directread(self):
        """Varnode used by CALLOTHER → DIRECTREAD."""
        addr = StubAddress()
        pm = ParamMeasure(addr, 4, None, ParamIDIO.INPUT)
        vn = StubVarnode(4, is_input=True)
        StubOp(OpCode.CPUI_CALLOTHER, [vn])
        pm.calculateRank(True, vn, None)
        assert pm.getMeasure() == ParamRank.DIRECTREAD

    def test_default_op_directread(self):
        """Varnode used by a generic op (INT_ADD) → DIRECTREAD."""
        addr = StubAddress()
        pm = ParamMeasure(addr, 4, None, ParamIDIO.INPUT)
        vn = StubVarnode(4, is_input=True)
        other = StubVarnode(4)
        StubOp(OpCode.CPUI_INT_ADD, [vn, other])
        pm.calculateRank(True, vn, None)
        assert pm.getMeasure() == ParamRank.DIRECTREAD

    def test_no_descend_stays_worst(self):
        """Varnode with no readers stays at WORSTRANK."""
        addr = StubAddress()
        pm = ParamMeasure(addr, 4, None, ParamIDIO.INPUT)
        vn = StubVarnode(4, is_input=True)
        pm.calculateRank(True, vn, None)
        assert pm.getMeasure() == ParamRank.WORSTRANK

    def test_ignoreop_skipped(self):
        """An op matching ignoreop is skipped during walkforward."""
        addr = StubAddress()
        pm = ParamMeasure(addr, 4, None, ParamIDIO.INPUT)
        vn = StubVarnode(4, is_input=True)
        op = StubOp(OpCode.CPUI_INT_ADD, [vn, StubVarnode(4)])
        pm.calculateRank(True, vn, op)
        assert pm.getMeasure() == ParamRank.WORSTRANK


# =========================================================================
# Tests – walkbackward (OUTPUT rank calculation)
# =========================================================================

class TestWalkBackward:
    def test_input_varnode_is_thisfnparam(self):
        """Output vn defined as input → THISFNPARAM."""
        addr = StubAddress()
        pm = ParamMeasure(addr, 4, None, ParamIDIO.OUTPUT)
        vn = StubVarnode(4, is_input=True)
        pm.calculateRank(True, vn, None)
        assert pm.getMeasure() == ParamRank.THISFNPARAM

    def test_unwritten_is_thisfnparam(self):
        """Output vn that's not written → THISFNPARAM."""
        addr = StubAddress()
        pm = ParamMeasure(addr, 4, None, ParamIDIO.OUTPUT)
        vn = StubVarnode(4)
        pm.calculateRank(True, vn, None)
        assert pm.getMeasure() == ParamRank.THISFNPARAM

    def test_indirect_output(self):
        """Output vn defined by INDIRECT → INDIRECT."""
        addr = StubAddress()
        pm = ParamMeasure(addr, 4, None, ParamIDIO.OUTPUT)
        out_vn = StubVarnode(4)
        StubOp(OpCode.CPUI_INDIRECT, [StubVarnode(4), StubVarnode(4)], out_vn)
        pm.calculateRank(True, out_vn, None)
        assert pm.getMeasure() == ParamRank.INDIRECT

    def test_return_output_is_subfnreturn(self):
        """Output vn defined by RETURN → SUBFNRETURN."""
        addr = StubAddress()
        pm = ParamMeasure(addr, 4, None, ParamIDIO.OUTPUT)
        out_vn = StubVarnode(4)
        StubOp(OpCode.CPUI_RETURN, [StubVarnode(4)], out_vn)
        pm.calculateRank(True, out_vn, None)
        assert pm.getMeasure() == ParamRank.SUBFNRETURN


# =========================================================================
# Tests – best vs worst rank selection
# =========================================================================

class TestBestWorst:
    def test_best_picks_min(self):
        """With best=True, rank should be the minimum seen."""
        addr = StubAddress()
        pm = ParamMeasure(addr, 4, None, ParamIDIO.INPUT)
        vn = StubVarnode(4, is_input=True)
        # Two readers: one DIRECTREAD, one INDIRECT
        StubOp(OpCode.CPUI_INT_ADD, [vn, StubVarnode(4)])
        StubOp(OpCode.CPUI_INDIRECT, [vn, StubVarnode(4)])
        pm.calculateRank(True, vn, None)
        assert pm.getMeasure() == ParamRank.DIRECTREAD

    def test_worst_picks_max(self):
        """With best=False, rank should be the maximum seen."""
        addr = StubAddress()
        pm = ParamMeasure(addr, 4, None, ParamIDIO.INPUT)
        vn = StubVarnode(4, is_input=True)
        StubOp(OpCode.CPUI_INT_ADD, [vn, StubVarnode(4)])
        StubOp(OpCode.CPUI_INDIRECT, [vn, StubVarnode(4)])
        pm.calculateRank(False, vn, None)
        assert pm.getMeasure() == ParamRank.INDIRECT


# =========================================================================
# Tests – savePretty
# =========================================================================

class TestSavePretty:
    def test_basic_output(self):
        spc = StubSpace("register")
        addr = StubAddress(spc, 0x100)
        pm = ParamMeasure(addr, 4, None, ParamIDIO.INPUT)
        s = pm.savePretty()
        assert "register" in s
        assert "256" in s  # 0x100
        assert "4" in s
        assert "7" in s  # WORSTRANK


# =========================================================================
# Tests – constants
# =========================================================================

class TestConstants:
    def test_maxdepth(self):
        assert MAXDEPTH == 10


if __name__ == '__main__':
    pytest.main([__file__, '-v'])
