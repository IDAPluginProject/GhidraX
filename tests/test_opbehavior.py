"""
Phase 4: Unit tests for OpBehavior + constant folding.
Tests integer, boolean, floating-point, and composite p-code operation behaviors.
"""

import sys
import os
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', 'python'))

import struct
import pytest
from ghidra.core.opcodes import OpCode
from ghidra.core.opbehavior import (
    OpBehavior, EvaluationError,
    OpBehaviorCopy,
    OpBehaviorEqual, OpBehaviorNotEqual,
    OpBehaviorIntSless, OpBehaviorIntSlessEqual,
    OpBehaviorIntLess, OpBehaviorIntLessEqual,
    OpBehaviorIntZext, OpBehaviorIntSext,
    OpBehaviorIntAdd, OpBehaviorIntSub,
    OpBehaviorIntCarry, OpBehaviorIntScarry, OpBehaviorIntSborrow,
    OpBehaviorInt2Comp, OpBehaviorIntNegate,
    OpBehaviorIntXor, OpBehaviorIntAnd, OpBehaviorIntOr,
    OpBehaviorIntLeft, OpBehaviorIntRight, OpBehaviorIntSright,
    OpBehaviorIntMult, OpBehaviorIntDiv, OpBehaviorIntSdiv,
    OpBehaviorIntRem, OpBehaviorIntSrem,
    OpBehaviorBoolNegate, OpBehaviorBoolXor, OpBehaviorBoolAnd, OpBehaviorBoolOr,
    OpBehaviorPiece, OpBehaviorSubpiece,
    OpBehaviorPtradd, OpBehaviorPtrsub,
    OpBehaviorPopcount, OpBehaviorLzcount,
    OpBehaviorFloatEqual, OpBehaviorFloatNotEqual,
    OpBehaviorFloatLess, OpBehaviorFloatLessEqual,
    OpBehaviorFloatNan, OpBehaviorFloatAdd, OpBehaviorFloatSub,
    OpBehaviorFloatMult, OpBehaviorFloatDiv,
    OpBehaviorFloatNeg, OpBehaviorFloatAbs, OpBehaviorFloatSqrt,
    OpBehaviorFloatInt2Float, OpBehaviorFloatTrunc,
    OpBehaviorFloatCeil, OpBehaviorFloatFloor, OpBehaviorFloatRound,
)


def f2i(f):
    """Convert float to its IEEE-754 32-bit integer encoding."""
    return struct.unpack('<I', struct.pack('<f', f))[0]

def d2i(d):
    """Convert double to its IEEE-754 64-bit integer encoding."""
    return struct.unpack('<Q', struct.pack('<d', d))[0]

def i2f(i):
    """Convert 32-bit integer encoding back to float."""
    return struct.unpack('<f', struct.pack('<I', i & 0xFFFFFFFF))[0]

def i2d(i):
    """Convert 64-bit integer encoding back to double."""
    return struct.unpack('<d', struct.pack('<Q', i & 0xFFFFFFFFFFFFFFFF))[0]


# =========================================================================
# OpBehavior base
# =========================================================================

class TestOpBehaviorBase:
    def test_register_instructions(self):
        inst = OpBehavior.registerInstructions()
        assert inst[OpCode.CPUI_COPY] is not None
        assert inst[OpCode.CPUI_INT_ADD] is not None
        assert isinstance(inst[OpCode.CPUI_COPY], OpBehaviorCopy)

    def test_special_ops(self):
        inst = OpBehavior.registerInstructions()
        assert inst[OpCode.CPUI_LOAD].isSpecial()
        assert inst[OpCode.CPUI_STORE].isSpecial()
        assert inst[OpCode.CPUI_BRANCH].isSpecial()
        assert inst[OpCode.CPUI_CALL].isSpecial()

    def test_unary_binary_classification(self):
        assert OpBehaviorCopy().isUnary()
        assert not OpBehaviorIntAdd().isUnary()

    def test_base_raises(self):
        b = OpBehavior(OpCode.CPUI_LOAD, False, True)
        with pytest.raises(EvaluationError):
            b.evaluateUnary(4, 4, 0)
        with pytest.raises(EvaluationError):
            b.evaluateBinary(4, 4, 0, 0)


# =========================================================================
# Copy
# =========================================================================

class TestCopy:
    def test_copy_truncate(self):
        op = OpBehaviorCopy()
        assert op.evaluateUnary(4, 8, 0x123456789ABCDEF0) == 0x9ABCDEF0

    def test_copy_identity(self):
        op = OpBehaviorCopy()
        assert op.evaluateUnary(4, 4, 42) == 42

    def test_recover(self):
        op = OpBehaviorCopy()
        assert op.recoverInputUnary(4, 0xABCD, 2) == 0xABCD & 0xFFFF


# =========================================================================
# Integer comparisons
# =========================================================================

class TestIntComparisons:
    def test_equal(self):
        op = OpBehaviorEqual()
        assert op.evaluateBinary(1, 4, 10, 10) == 1
        assert op.evaluateBinary(1, 4, 10, 11) == 0

    def test_not_equal(self):
        op = OpBehaviorNotEqual()
        assert op.evaluateBinary(1, 4, 10, 10) == 0
        assert op.evaluateBinary(1, 4, 10, 11) == 1

    def test_unsigned_less(self):
        op = OpBehaviorIntLess()
        assert op.evaluateBinary(1, 4, 5, 10) == 1
        assert op.evaluateBinary(1, 4, 10, 5) == 0
        assert op.evaluateBinary(1, 4, 5, 5) == 0

    def test_unsigned_less_equal(self):
        op = OpBehaviorIntLessEqual()
        assert op.evaluateBinary(1, 4, 5, 10) == 1
        assert op.evaluateBinary(1, 4, 5, 5) == 1
        assert op.evaluateBinary(1, 4, 10, 5) == 0

    def test_signed_less(self):
        op = OpBehaviorIntSless()
        # -1 (0xFFFFFFFF) < 0 in signed
        assert op.evaluateBinary(1, 4, 0xFFFFFFFF, 0) == 1
        assert op.evaluateBinary(1, 4, 0, 0xFFFFFFFF) == 0

    def test_signed_less_equal(self):
        op = OpBehaviorIntSlessEqual()
        assert op.evaluateBinary(1, 4, 0xFFFFFFFF, 0xFFFFFFFF) == 1
        assert op.evaluateBinary(1, 4, 0xFFFFFFFF, 0) == 1


# =========================================================================
# Integer extension
# =========================================================================

class TestIntExtension:
    def test_zext(self):
        op = OpBehaviorIntZext()
        assert op.evaluateUnary(4, 2, 0xFFFF) == 0xFFFF
        assert op.evaluateUnary(4, 1, 0x80) == 0x80

    def test_zext_recover(self):
        op = OpBehaviorIntZext()
        assert op.recoverInputUnary(4, 0x0000ABCD, 2) == 0xABCD

    def test_sext_positive(self):
        op = OpBehaviorIntSext()
        assert op.evaluateUnary(4, 2, 0x007F) == 0x007F

    def test_sext_negative(self):
        op = OpBehaviorIntSext()
        # 0x80 as 1-byte => -128 => sign-extended to 4 bytes = 0xFFFFFF80
        assert op.evaluateUnary(4, 1, 0x80) == 0xFFFFFF80

    def test_sext_16to32(self):
        op = OpBehaviorIntSext()
        # 0xFFFF as 2-byte => -1 => 0xFFFFFFFF
        assert op.evaluateUnary(4, 2, 0xFFFF) == 0xFFFFFFFF

    def test_sext_recover(self):
        op = OpBehaviorIntSext()
        assert op.recoverInputUnary(4, 0xFFFFFF80, 1) == 0x80


# =========================================================================
# Integer arithmetic
# =========================================================================

class TestIntArithmetic:
    def test_add(self):
        op = OpBehaviorIntAdd()
        assert op.evaluateBinary(4, 4, 10, 20) == 30

    def test_add_overflow(self):
        op = OpBehaviorIntAdd()
        assert op.evaluateBinary(4, 4, 0xFFFFFFFF, 1) == 0

    def test_add_recover(self):
        op = OpBehaviorIntAdd()
        # out = in1 + in2 => in_unknown = out - in_known
        assert op.recoverInputBinary(0, 4, 30, 4, 20) == 10

    def test_sub(self):
        op = OpBehaviorIntSub()
        assert op.evaluateBinary(4, 4, 20, 10) == 10

    def test_sub_underflow(self):
        op = OpBehaviorIntSub()
        assert op.evaluateBinary(4, 4, 0, 1) == 0xFFFFFFFF

    def test_sub_recover_slot0(self):
        op = OpBehaviorIntSub()
        # out = in1 - in2; slot=0 => in1 = out + in2
        assert op.recoverInputBinary(0, 4, 10, 4, 20) == 30

    def test_sub_recover_slot1(self):
        op = OpBehaviorIntSub()
        # out = in1 - in2; slot=1 => in2 = in1 - out
        assert op.recoverInputBinary(1, 4, 10, 4, 20) == 10

    def test_mult(self):
        op = OpBehaviorIntMult()
        assert op.evaluateBinary(4, 4, 7, 6) == 42

    def test_mult_overflow(self):
        op = OpBehaviorIntMult()
        assert op.evaluateBinary(4, 4, 0x10000, 0x10000) == 0

    def test_div(self):
        op = OpBehaviorIntDiv()
        assert op.evaluateBinary(4, 4, 42, 7) == 6

    def test_div_by_zero(self):
        op = OpBehaviorIntDiv()
        with pytest.raises(EvaluationError):
            op.evaluateBinary(4, 4, 42, 0)

    def test_sdiv_positive(self):
        op = OpBehaviorIntSdiv()
        assert op.evaluateBinary(4, 4, 42, 7) == 6

    def test_sdiv_negative(self):
        op = OpBehaviorIntSdiv()
        # -42 / 7 = -6 in 4 bytes
        neg42 = (0x100000000 - 42) & 0xFFFFFFFF
        result = op.evaluateBinary(4, 4, neg42, 7)
        # -6 as unsigned 4-byte
        expected = (0x100000000 - 6) & 0xFFFFFFFF
        assert result == expected

    def test_sdiv_by_zero(self):
        op = OpBehaviorIntSdiv()
        with pytest.raises(EvaluationError):
            op.evaluateBinary(4, 4, 42, 0)

    def test_rem(self):
        op = OpBehaviorIntRem()
        assert op.evaluateBinary(4, 4, 43, 7) == 1

    def test_rem_by_zero(self):
        op = OpBehaviorIntRem()
        with pytest.raises(EvaluationError):
            op.evaluateBinary(4, 4, 43, 0)

    def test_srem(self):
        op = OpBehaviorIntSrem()
        assert op.evaluateBinary(4, 4, 43, 7) == 1

    def test_srem_negative(self):
        op = OpBehaviorIntSrem()
        # -43 % 7 = -1 (C truncation semantics)
        neg43 = (0x100000000 - 43) & 0xFFFFFFFF
        result = op.evaluateBinary(4, 4, neg43, 7)
        expected = (0x100000000 - 1) & 0xFFFFFFFF
        assert result == expected

    def test_srem_by_zero(self):
        op = OpBehaviorIntSrem()
        with pytest.raises(EvaluationError):
            op.evaluateBinary(4, 4, 43, 0)


# =========================================================================
# Carry / overflow
# =========================================================================

class TestCarryOverflow:
    def test_carry(self):
        op = OpBehaviorIntCarry()
        assert op.evaluateBinary(1, 4, 0xFFFFFFFF, 1) == 1
        assert op.evaluateBinary(1, 4, 1, 1) == 0

    def test_scarry(self):
        op = OpBehaviorIntScarry()
        # 0x7FFFFFFF + 1 = signed overflow
        assert op.evaluateBinary(1, 4, 0x7FFFFFFF, 1) == 1
        assert op.evaluateBinary(1, 4, 1, 1) == 0

    def test_sborrow(self):
        op = OpBehaviorIntSborrow()
        # 0x80000000 - 1 = signed underflow
        assert op.evaluateBinary(1, 4, 0x80000000, 1) == 1
        assert op.evaluateBinary(1, 4, 5, 3) == 0


# =========================================================================
# Unary integer
# =========================================================================

class TestUnaryInt:
    def test_2comp(self):
        op = OpBehaviorInt2Comp()
        assert op.evaluateUnary(4, 4, 1) == 0xFFFFFFFF
        assert op.evaluateUnary(4, 4, 0) == 0

    def test_2comp_recover(self):
        op = OpBehaviorInt2Comp()
        assert op.recoverInputUnary(4, 0xFFFFFFFF, 4) == 1

    def test_negate(self):
        op = OpBehaviorIntNegate()
        assert op.evaluateUnary(4, 4, 0) == 0xFFFFFFFF
        assert op.evaluateUnary(4, 4, 0xFFFFFFFF) == 0

    def test_negate_recover(self):
        op = OpBehaviorIntNegate()
        assert op.recoverInputUnary(4, 0xFFFFFFFF, 4) == 0


# =========================================================================
# Bitwise
# =========================================================================

class TestBitwise:
    def test_xor(self):
        op = OpBehaviorIntXor()
        assert op.evaluateBinary(4, 4, 0xFF00FF00, 0x0F0F0F0F) == 0xF00FF00F

    def test_and(self):
        op = OpBehaviorIntAnd()
        assert op.evaluateBinary(4, 4, 0xFF00FF00, 0x0F0F0F0F) == 0x0F000F00

    def test_or(self):
        op = OpBehaviorIntOr()
        assert op.evaluateBinary(4, 4, 0xFF00FF00, 0x0F0F0F0F) == 0xFF0FFF0F


# =========================================================================
# Shifts
# =========================================================================

class TestShifts:
    def test_left(self):
        op = OpBehaviorIntLeft()
        assert op.evaluateBinary(4, 4, 1, 4) == 16

    def test_left_overflow(self):
        op = OpBehaviorIntLeft()
        assert op.evaluateBinary(4, 4, 1, 32) == 0

    def test_left_recover(self):
        op = OpBehaviorIntLeft()
        assert op.recoverInputBinary(0, 4, 16, 4, 4) == 1

    def test_right(self):
        op = OpBehaviorIntRight()
        assert op.evaluateBinary(4, 4, 0x80000000, 4) == 0x08000000

    def test_right_overflow(self):
        op = OpBehaviorIntRight()
        assert op.evaluateBinary(4, 4, 0x80000000, 32) == 0

    def test_right_recover(self):
        op = OpBehaviorIntRight()
        assert op.recoverInputBinary(0, 4, 0x08000000, 4, 4) == 0x80000000

    def test_sright_positive(self):
        op = OpBehaviorIntSright()
        assert op.evaluateBinary(4, 4, 0x40000000, 4) == 0x04000000

    def test_sright_negative(self):
        op = OpBehaviorIntSright()
        # 0x80000000 >> 4 with sign extension
        result = op.evaluateBinary(4, 4, 0x80000000, 4)
        assert result == 0xF8000000

    def test_sright_large_shift(self):
        op = OpBehaviorIntSright()
        # Shift >= bits => all sign bits
        result = op.evaluateBinary(4, 4, 0x80000000, 32)
        assert result == 0xFFFFFFFF
        result2 = op.evaluateBinary(4, 4, 0x40000000, 32)
        assert result2 == 0


# =========================================================================
# Boolean
# =========================================================================

class TestBoolean:
    def test_negate(self):
        op = OpBehaviorBoolNegate()
        assert op.evaluateUnary(1, 1, 0) == 1
        assert op.evaluateUnary(1, 1, 1) == 0
        assert op.evaluateUnary(1, 1, 2) == 1  # only bit 0 matters

    def test_xor(self):
        op = OpBehaviorBoolXor()
        assert op.evaluateBinary(1, 1, 0, 0) == 0
        assert op.evaluateBinary(1, 1, 1, 0) == 1
        assert op.evaluateBinary(1, 1, 1, 1) == 0

    def test_and(self):
        op = OpBehaviorBoolAnd()
        assert op.evaluateBinary(1, 1, 1, 1) == 1
        assert op.evaluateBinary(1, 1, 1, 0) == 0
        assert op.evaluateBinary(1, 1, 0, 0) == 0

    def test_or(self):
        op = OpBehaviorBoolOr()
        assert op.evaluateBinary(1, 1, 0, 0) == 0
        assert op.evaluateBinary(1, 1, 1, 0) == 1
        assert op.evaluateBinary(1, 1, 1, 1) == 1


# =========================================================================
# Composite
# =========================================================================

class TestComposite:
    def test_piece(self):
        op = OpBehaviorPiece()
        # PIECE(0xAB, 0xCD) with sizein=1 => 0xABCD
        assert op.evaluateBinary(2, 1, 0xAB, 0xCD) == 0xABCD

    def test_piece_4byte(self):
        op = OpBehaviorPiece()
        assert op.evaluateBinary(8, 4, 0x12345678, 0x9ABCDEF0) == 0x123456789ABCDEF0

    def test_subpiece(self):
        op = OpBehaviorSubpiece()
        # SUBPIECE(0x12345678, 0) => low 2 bytes = 0x5678
        assert op.evaluateBinary(2, 4, 0x12345678, 0) == 0x5678

    def test_subpiece_offset(self):
        op = OpBehaviorSubpiece()
        # SUBPIECE(0x12345678, 2) => bytes 2..3 = 0x1234
        assert op.evaluateBinary(2, 4, 0x12345678, 2) == 0x1234

    def test_ptradd(self):
        op = OpBehaviorPtradd()
        # base + index * element_size
        assert op.evaluateTernary(4, 4, 0x1000, 5, 4) == 0x1014

    def test_ptrsub(self):
        op = OpBehaviorPtrsub()
        assert op.evaluateBinary(4, 4, 0x1000, 0x10) == 0x1010


# =========================================================================
# Popcount / Lzcount
# =========================================================================

class TestBitCount:
    def test_popcount_zero(self):
        op = OpBehaviorPopcount()
        assert op.evaluateUnary(4, 4, 0) == 0

    def test_popcount_all_ones(self):
        op = OpBehaviorPopcount()
        assert op.evaluateUnary(4, 4, 0xFFFFFFFF) == 32

    def test_popcount_mixed(self):
        op = OpBehaviorPopcount()
        assert op.evaluateUnary(4, 4, 0xAAAAAAAA) == 16

    def test_lzcount_zero(self):
        op = OpBehaviorLzcount()
        assert op.evaluateUnary(4, 4, 0) == 32

    def test_lzcount_msb_set(self):
        op = OpBehaviorLzcount()
        assert op.evaluateUnary(4, 4, 0x80000000) == 0

    def test_lzcount_one(self):
        op = OpBehaviorLzcount()
        assert op.evaluateUnary(4, 4, 1) == 31

    def test_lzcount_2byte(self):
        op = OpBehaviorLzcount()
        assert op.evaluateUnary(4, 2, 0x0100) == 7


# =========================================================================
# Floating-point operations
# =========================================================================

class TestFloat:
    def test_float_equal(self):
        op = OpBehaviorFloatEqual()
        a = d2i(3.14)
        b = d2i(3.14)
        c = d2i(2.71)
        assert op.evaluateBinary(1, 8, a, b) == 1
        assert op.evaluateBinary(1, 8, a, c) == 0

    def test_float_not_equal(self):
        op = OpBehaviorFloatNotEqual()
        a = d2i(3.14)
        b = d2i(2.71)
        assert op.evaluateBinary(1, 8, a, b) == 1
        assert op.evaluateBinary(1, 8, a, a) == 0

    def test_float_less(self):
        op = OpBehaviorFloatLess()
        a = d2i(1.0)
        b = d2i(2.0)
        assert op.evaluateBinary(1, 8, a, b) == 1
        assert op.evaluateBinary(1, 8, b, a) == 0

    def test_float_less_equal(self):
        op = OpBehaviorFloatLessEqual()
        a = d2i(1.0)
        b = d2i(1.0)
        assert op.evaluateBinary(1, 8, a, b) == 1

    def test_float_add(self):
        op = OpBehaviorFloatAdd()
        a = d2i(1.5)
        b = d2i(2.5)
        result = op.evaluateBinary(8, 8, a, b)
        assert abs(i2d(result) - 4.0) < 1e-10

    def test_float_sub(self):
        op = OpBehaviorFloatSub()
        a = d2i(5.0)
        b = d2i(2.0)
        result = op.evaluateBinary(8, 8, a, b)
        assert abs(i2d(result) - 3.0) < 1e-10

    def test_float_mult(self):
        op = OpBehaviorFloatMult()
        a = d2i(3.0)
        b = d2i(4.0)
        result = op.evaluateBinary(8, 8, a, b)
        assert abs(i2d(result) - 12.0) < 1e-10

    def test_float_div(self):
        op = OpBehaviorFloatDiv()
        a = d2i(10.0)
        b = d2i(4.0)
        result = op.evaluateBinary(8, 8, a, b)
        assert abs(i2d(result) - 2.5) < 1e-10

    def test_float_neg(self):
        op = OpBehaviorFloatNeg()
        a = d2i(3.14)
        result = op.evaluateUnary(8, 8, a)
        assert abs(i2d(result) - (-3.14)) < 1e-10

    def test_float_abs(self):
        op = OpBehaviorFloatAbs()
        a = d2i(-3.14)
        result = op.evaluateUnary(8, 8, a)
        assert abs(i2d(result) - 3.14) < 1e-10

    def test_float_sqrt(self):
        op = OpBehaviorFloatSqrt()
        a = d2i(9.0)
        result = op.evaluateUnary(8, 8, a)
        assert abs(i2d(result) - 3.0) < 1e-10

    def test_float_int2float(self):
        op = OpBehaviorFloatInt2Float()
        result = op.evaluateUnary(8, 4, 42)
        assert abs(i2d(result) - 42.0) < 1e-10

    def test_float_trunc(self):
        op = OpBehaviorFloatTrunc()
        a = d2i(3.99)
        result = op.evaluateUnary(4, 8, a)
        assert result == 3

    def test_float_ceil(self):
        op = OpBehaviorFloatCeil()
        a = d2i(3.1)
        result = op.evaluateUnary(8, 8, a)
        assert abs(i2d(result) - 4.0) < 1e-10

    def test_float_floor(self):
        op = OpBehaviorFloatFloor()
        a = d2i(3.9)
        result = op.evaluateUnary(8, 8, a)
        assert abs(i2d(result) - 3.0) < 1e-10

    def test_float_round(self):
        op = OpBehaviorFloatRound()
        a = d2i(3.5)
        result = op.evaluateUnary(8, 8, a)
        val = i2d(result)
        assert abs(val - 4.0) < 1e-10

    def test_float_nan(self):
        op = OpBehaviorFloatNan()
        a = d2i(float('nan'))
        assert op.evaluateUnary(1, 8, a) == 1
        b = d2i(1.0)
        assert op.evaluateUnary(1, 8, b) == 0
