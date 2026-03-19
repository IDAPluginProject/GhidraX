"""Tests for ghidra.transform.nzmask -- getNZMaskLocal."""
from __future__ import annotations

from ghidra.core.opcodes import OpCode
from ghidra.core.address import calc_mask
from ghidra.transform.nzmask import getNZMaskLocal


# ---------------------------------------------------------------------------
# Mock classes
# ---------------------------------------------------------------------------

class _MockVarnode:
    def __init__(self, size, nzm=None, offset=0, const=False):
        self._size = size
        self._nzm = nzm if nzm is not None else calc_mask(size)
        self._offset = offset
        self._const = const

    def getSize(self):
        return self._size

    def getNZMask(self):
        return self._nzm

    def getOffset(self):
        return self._offset

    def isConstant(self):
        return self._const


class _MockOp:
    def __init__(self, opc, out_size, inputs):
        self._opc = opc
        self._inputs = inputs
        self._out = _MockVarnode(out_size) if out_size > 0 else None

    def code(self):
        return self._opc

    def getOut(self):
        return self._out

    def getIn(self, i):
        return self._inputs[i]

    def numInput(self):
        return len(self._inputs)

    def getParent(self):
        return None


# ---------------------------------------------------------------------------
# Tests
# ---------------------------------------------------------------------------

class TestGetNZMaskLocal:
    def test_no_output(self):
        op = _MockOp(OpCode.CPUI_COPY, 0, [])
        assert getNZMaskLocal(op) == 0

    def test_bool_ops(self):
        for opc in (OpCode.CPUI_INT_EQUAL, OpCode.CPUI_INT_NOTEQUAL,
                     OpCode.CPUI_INT_SLESS, OpCode.CPUI_INT_LESS,
                     OpCode.CPUI_BOOL_NEGATE, OpCode.CPUI_BOOL_AND,
                     OpCode.CPUI_BOOL_OR, OpCode.CPUI_BOOL_XOR):
            inp = _MockVarnode(4, 0xFF)
            op = _MockOp(opc, 1, [inp, inp])
            assert getNZMaskLocal(op) == 1, f"Failed for {opc}"

    def test_copy(self):
        inp = _MockVarnode(4, 0xAB)
        op = _MockOp(OpCode.CPUI_COPY, 4, [inp])
        assert getNZMaskLocal(op) == 0xAB

    def test_int_zext(self):
        inp = _MockVarnode(2, 0xFF)
        op = _MockOp(OpCode.CPUI_INT_ZEXT, 4, [inp])
        assert getNZMaskLocal(op) == 0xFF

    def test_int_and(self):
        a = _MockVarnode(4, 0xFF00)
        b = _MockVarnode(4, 0x00FF)
        op = _MockOp(OpCode.CPUI_INT_AND, 4, [a, b])
        assert getNZMaskLocal(op) == 0

    def test_int_or(self):
        a = _MockVarnode(4, 0xFF00)
        b = _MockVarnode(4, 0x00FF)
        op = _MockOp(OpCode.CPUI_INT_OR, 4, [a, b])
        assert getNZMaskLocal(op) == 0xFFFF

    def test_int_xor(self):
        a = _MockVarnode(4, 0xFF00)
        b = _MockVarnode(4, 0x00FF)
        op = _MockOp(OpCode.CPUI_INT_XOR, 4, [a, b])
        assert getNZMaskLocal(op) == 0xFFFF

    def test_int_left_const(self):
        a = _MockVarnode(4, 0xFF)
        shift = _MockVarnode(4, calc_mask(4), 8, const=True)
        op = _MockOp(OpCode.CPUI_INT_LEFT, 4, [a, shift])
        assert getNZMaskLocal(op) == 0xFF00

    def test_int_right_const(self):
        a = _MockVarnode(4, 0xFF00)
        shift = _MockVarnode(4, calc_mask(4), 8, const=True)
        op = _MockOp(OpCode.CPUI_INT_RIGHT, 4, [a, shift])
        assert getNZMaskLocal(op) == 0xFF

    def test_subpiece(self):
        a = _MockVarnode(4, 0xAABBCCDD)
        sub = _MockVarnode(4, calc_mask(4), 1, const=True)
        op = _MockOp(OpCode.CPUI_SUBPIECE, 2, [a, sub])
        result = getNZMaskLocal(op)
        expected = (0xAABBCCDD >> 8) & calc_mask(2)
        assert result == expected

    def test_piece(self):
        hi = _MockVarnode(2, 0xAA)
        lo = _MockVarnode(2, 0xBB)
        op = _MockOp(OpCode.CPUI_PIECE, 4, [hi, lo])
        result = getNZMaskLocal(op)
        expected = (0xAA << 16) | 0xBB
        assert result == expected

    def test_int_negate(self):
        a = _MockVarnode(4, 0xFF)
        op = _MockOp(OpCode.CPUI_INT_NEGATE, 4, [a])
        assert getNZMaskLocal(op) == calc_mask(4)

    def test_indirect(self):
        a = _MockVarnode(4, 0xFF)
        op = _MockOp(OpCode.CPUI_INDIRECT, 4, [a, a])
        assert getNZMaskLocal(op) == calc_mask(4)
