"""Tests for ghidra.core.float_format — C++ faithful FloatFormat port."""
from __future__ import annotations

import math
import os
import struct
import sys

import pytest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', 'python'))

from ghidra.core.float_format import FloatFormat, FloatClass


# ── IEEE 754 known encodings ──────────────────────────────────────────────

F32_POS_ZERO = 0x00000000
F32_NEG_ZERO = 0x80000000
F32_POS_INF = 0x7F800000
F32_NEG_INF = 0xFF800000
F32_QNAN = 0x7FC00000
F32_ONE = 0x3F800000
F32_NEG_ONE = 0xBF800000
F32_TWO = 0x40000000
F32_HALF = 0x3F000000
F32_PI = 0x40490FDB       # ~3.14159274...
F32_SMALLEST_NORMAL = 0x00800000
F32_LARGEST_DENORM = 0x007FFFFF

F64_POS_ZERO = 0x0000000000000000
F64_NEG_ZERO = 0x8000000000000000
F64_POS_INF = 0x7FF0000000000000
F64_NEG_INF = 0xFFF0000000000000
F64_QNAN = 0x7FF8000000000000
F64_ONE = 0x3FF0000000000000
F64_NEG_ONE = 0xBFF0000000000000
F64_TWO = 0x4000000000000000
F64_PI = 0x400921FB54442D18


class TestConstructor:
    def test_float32_params(self):
        ff = FloatFormat(4)
        assert ff.size == 4
        assert ff.signbit_pos == 31
        assert ff.exp_pos == 23
        assert ff.exp_size == 8
        assert ff.frac_pos == 0
        assert ff.frac_size == 23
        assert ff.bias == 127
        assert ff.jbitimplied is True
        assert ff.maxexponent == 255

    def test_float64_params(self):
        ff = FloatFormat(8)
        assert ff.size == 8
        assert ff.signbit_pos == 63
        assert ff.exp_size == 11
        assert ff.frac_size == 52
        assert ff.bias == 1023
        assert ff.maxexponent == 2047

    def test_half_precision(self):
        ff = FloatFormat(2)
        assert ff.frac_size == 10
        assert ff.exp_size == 5
        assert ff.bias == 15

    def test_precision_calc(self):
        ff = FloatFormat(4)
        assert ff.decimalMinPrecision == int(math.floor(23 * 0.30103))
        assert ff.decimalMaxPrecision == int(math.ceil(24 * 0.30103)) + 1


class TestExtraction:
    def test_extract_sign_positive(self):
        ff = FloatFormat(4)
        assert ff.extractSign(F32_ONE) is False

    def test_extract_sign_negative(self):
        ff = FloatFormat(4)
        assert ff.extractSign(F32_NEG_ONE) is True

    def test_extract_exponent_one(self):
        ff = FloatFormat(4)
        assert ff.extractExponentCode(F32_ONE) == 127

    def test_extract_exponent_two(self):
        ff = FloatFormat(4)
        assert ff.extractExponentCode(F32_TWO) == 128

    def test_extract_fractional_code_one(self):
        ff = FloatFormat(4)
        # 1.0 has frac = 0, top-aligned = 0
        frac = ff.extractFractionalCode(F32_ONE)
        assert frac == 0

    def test_extract_fractional_code_pi(self):
        ff = FloatFormat(4)
        frac = ff.extractFractionalCode(F32_PI)
        assert frac != 0  # pi has nonzero fractional


class TestGetHostFloat:
    def test_positive_zero(self):
        ff = FloatFormat(4)
        val, cls = ff.getHostFloat(F32_POS_ZERO)
        assert val == 0.0
        assert cls == FloatClass.zero

    def test_negative_zero(self):
        ff = FloatFormat(4)
        val, cls = ff.getHostFloat(F32_NEG_ZERO)
        assert val == 0.0
        assert math.copysign(1.0, val) < 0
        assert cls == FloatClass.zero

    def test_positive_infinity(self):
        ff = FloatFormat(4)
        val, cls = ff.getHostFloat(F32_POS_INF)
        assert math.isinf(val) and val > 0
        assert cls == FloatClass.infinity

    def test_negative_infinity(self):
        ff = FloatFormat(4)
        val, cls = ff.getHostFloat(F32_NEG_INF)
        assert math.isinf(val) and val < 0
        assert cls == FloatClass.infinity

    def test_nan(self):
        ff = FloatFormat(4)
        val, cls = ff.getHostFloat(F32_QNAN)
        assert math.isnan(val)
        assert cls == FloatClass.nan

    def test_one(self):
        ff = FloatFormat(4)
        val, cls = ff.getHostFloat(F32_ONE)
        assert abs(val - 1.0) < 1e-7
        assert cls == FloatClass.normalized

    def test_neg_one(self):
        ff = FloatFormat(4)
        val, cls = ff.getHostFloat(F32_NEG_ONE)
        assert abs(val - (-1.0)) < 1e-7

    def test_two(self):
        ff = FloatFormat(4)
        val, cls = ff.getHostFloat(F32_TWO)
        assert abs(val - 2.0) < 1e-7

    def test_denormalized(self):
        ff = FloatFormat(4)
        val, cls = ff.getHostFloat(F32_LARGEST_DENORM)
        assert cls == FloatClass.denormalized
        assert val > 0
        assert val < struct.unpack('<f', struct.pack('<I', F32_SMALLEST_NORMAL))[0]

    def test_float64_one(self):
        ff = FloatFormat(8)
        val, cls = ff.getHostFloat(F64_ONE)
        assert val == 1.0
        assert cls == FloatClass.normalized

    def test_float64_pi(self):
        ff = FloatFormat(8)
        val, cls = ff.getHostFloat(F64_PI)
        assert abs(val - math.pi) < 1e-15


class TestGetEncoding:
    def test_encode_zero(self):
        ff = FloatFormat(4)
        enc = ff.getEncoding(0.0)
        assert enc == F32_POS_ZERO

    def test_encode_neg_zero(self):
        ff = FloatFormat(4)
        enc = ff.getEncoding(-0.0)
        assert enc == F32_NEG_ZERO

    def test_encode_inf(self):
        ff = FloatFormat(4)
        enc = ff.getEncoding(float('inf'))
        assert enc == F32_POS_INF

    def test_encode_neg_inf(self):
        ff = FloatFormat(4)
        enc = ff.getEncoding(float('-inf'))
        assert enc == F32_NEG_INF

    def test_encode_nan(self):
        ff = FloatFormat(4)
        enc = ff.getEncoding(float('nan'))
        # Should be a NaN encoding (exponent all ones, frac nonzero)
        exp = ff.extractExponentCode(enc)
        assert exp == ff.maxexponent
        frac = ff.extractFractionalCode(enc)
        assert frac != 0

    def test_encode_one(self):
        ff = FloatFormat(4)
        enc = ff.getEncoding(1.0)
        assert enc == F32_ONE

    def test_encode_neg_one(self):
        ff = FloatFormat(4)
        enc = ff.getEncoding(-1.0)
        assert enc == F32_NEG_ONE

    def test_encode_two(self):
        ff = FloatFormat(4)
        enc = ff.getEncoding(2.0)
        assert enc == F32_TWO

    def test_roundtrip_float32(self):
        ff = FloatFormat(4)
        for val in [0.5, 1.0, -1.0, 2.0, 100.0, 0.1, -3.14]:
            enc = ff.getEncoding(val)
            decoded, _ = ff.getHostFloat(enc)
            # Should match float32 precision
            expected = struct.unpack('<f', struct.pack('<f', val))[0]
            assert abs(decoded - expected) < 1e-7, f"Roundtrip failed for {val}"

    def test_roundtrip_float64(self):
        ff = FloatFormat(8)
        for val in [0.5, 1.0, -1.0, 2.0, math.pi, math.e, -123.456]:
            enc = ff.getEncoding(val)
            decoded, _ = ff.getHostFloat(enc)
            assert decoded == val, f"Roundtrip failed for {val}"

    def test_encode_very_small(self):
        ff = FloatFormat(4)
        enc = ff.getEncoding(1e-45)
        val, cls = ff.getHostFloat(enc)
        # Either denormalized or zero
        assert cls in (FloatClass.denormalized, FloatClass.zero)

    def test_encode_very_large(self):
        ff = FloatFormat(4)
        enc = ff.getEncoding(1e39)
        assert enc == F32_POS_INF


class TestConvertEncoding:
    def test_f32_to_f64_one(self):
        f32 = FloatFormat(4)
        f64 = FloatFormat(8)
        enc64 = f64.convertEncoding(F32_ONE, f32)
        val, _ = f64.getHostFloat(enc64)
        assert val == 1.0

    def test_f64_to_f32_one(self):
        f32 = FloatFormat(4)
        f64 = FloatFormat(8)
        enc32 = f32.convertEncoding(F64_ONE, f64)
        val, _ = f32.getHostFloat(enc32)
        assert abs(val - 1.0) < 1e-7

    def test_f32_to_f64_inf(self):
        f32 = FloatFormat(4)
        f64 = FloatFormat(8)
        enc64 = f64.convertEncoding(F32_POS_INF, f32)
        val, cls = f64.getHostFloat(enc64)
        assert math.isinf(val)
        assert cls == FloatClass.infinity

    def test_f32_to_f64_nan(self):
        f32 = FloatFormat(4)
        f64 = FloatFormat(8)
        enc64 = f64.convertEncoding(F32_QNAN, f32)
        val, cls = f64.getHostFloat(enc64)
        assert math.isnan(val)
        assert cls == FloatClass.nan

    def test_f32_to_f64_zero(self):
        f32 = FloatFormat(4)
        f64 = FloatFormat(8)
        enc64 = f64.convertEncoding(F32_POS_ZERO, f32)
        val, cls = f64.getHostFloat(enc64)
        assert val == 0.0
        assert cls == FloatClass.zero

    def test_f64_to_f32_roundtrip(self):
        f32 = FloatFormat(4)
        f64 = FloatFormat(8)
        # Encode pi in f64, convert to f32, decode
        enc64 = f64.getEncoding(math.pi)
        enc32 = f32.convertEncoding(enc64, f64)
        val, _ = f32.getHostFloat(enc32)
        expected = struct.unpack('<f', struct.pack('<f', math.pi))[0]
        assert abs(val - expected) < 1e-6


class TestRoundToNearestEven:
    def test_no_rounding_needed(self):
        signif = 0x8000000000000000  # exactly 1.0 in top-aligned
        result, rounded = FloatFormat.roundToNearestEven(signif, 11)
        assert rounded is False

    def test_round_up(self):
        # Set bits that trigger rounding up
        signif = 0xFFFFFFFFFFFFFFFF
        result, rounded = FloatFormat.roundToNearestEven(signif, 11)
        assert rounded is True


class TestPcodeOps:
    def setup_method(self):
        self.f32 = FloatFormat(4)
        self.enc_one = F32_ONE
        self.enc_two = F32_TWO
        self.enc_half = F32_HALF
        self.enc_neg_one = F32_NEG_ONE

    def test_opEqual(self):
        assert self.f32.opEqual(self.enc_one, self.enc_one) == 1
        assert self.f32.opEqual(self.enc_one, self.enc_two) == 0

    def test_opNotEqual(self):
        assert self.f32.opNotEqual(self.enc_one, self.enc_two) == 1
        assert self.f32.opNotEqual(self.enc_one, self.enc_one) == 0

    def test_opLess(self):
        assert self.f32.opLess(self.enc_one, self.enc_two) == 1
        assert self.f32.opLess(self.enc_two, self.enc_one) == 0

    def test_opLessEqual(self):
        assert self.f32.opLessEqual(self.enc_one, self.enc_one) == 1
        assert self.f32.opLessEqual(self.enc_one, self.enc_two) == 1
        assert self.f32.opLessEqual(self.enc_two, self.enc_one) == 0

    def test_opNan(self):
        assert self.f32.opNan(F32_QNAN) == 1
        assert self.f32.opNan(self.enc_one) == 0

    def test_opAdd(self):
        result = self.f32.opAdd(self.enc_one, self.enc_one)
        val, _ = self.f32.getHostFloat(result)
        assert abs(val - 2.0) < 1e-7

    def test_opSub(self):
        result = self.f32.opSub(self.enc_two, self.enc_one)
        val, _ = self.f32.getHostFloat(result)
        assert abs(val - 1.0) < 1e-7

    def test_opMult(self):
        result = self.f32.opMult(self.enc_two, self.enc_two)
        val, _ = self.f32.getHostFloat(result)
        assert abs(val - 4.0) < 1e-7

    def test_opDiv(self):
        result = self.f32.opDiv(self.enc_one, self.enc_two)
        val, _ = self.f32.getHostFloat(result)
        assert abs(val - 0.5) < 1e-7

    def test_opNeg(self):
        result = self.f32.opNeg(self.enc_one)
        val, _ = self.f32.getHostFloat(result)
        assert abs(val - (-1.0)) < 1e-7

    def test_opAbs(self):
        result = self.f32.opAbs(self.enc_neg_one)
        val, _ = self.f32.getHostFloat(result)
        assert abs(val - 1.0) < 1e-7

    def test_opSqrt(self):
        enc_four = self.f32.getEncoding(4.0)
        result = self.f32.opSqrt(enc_four)
        val, _ = self.f32.getHostFloat(result)
        assert abs(val - 2.0) < 1e-7

    def test_opTrunc(self):
        enc_3_7 = self.f32.getEncoding(3.7)
        result = self.f32.opTrunc(enc_3_7, 4)
        assert result == 3

    def test_opTrunc_negative(self):
        enc = self.f32.getEncoding(-3.7)
        result = self.f32.opTrunc(enc, 4)
        # -3 as unsigned 32-bit
        assert result == ((-3) & 0xFFFFFFFF)

    def test_opCeil(self):
        enc = self.f32.getEncoding(1.1)
        result = self.f32.opCeil(enc)
        val, _ = self.f32.getHostFloat(result)
        assert abs(val - 2.0) < 1e-7

    def test_opFloor(self):
        enc = self.f32.getEncoding(1.9)
        result = self.f32.opFloor(enc)
        val, _ = self.f32.getHostFloat(result)
        assert abs(val - 1.0) < 1e-7

    def test_opRound(self):
        enc = self.f32.getEncoding(1.5)
        result = self.f32.opRound(enc)
        val, _ = self.f32.getHostFloat(result)
        assert abs(val - 2.0) < 1e-7

    def test_opInt2Float(self):
        result = self.f32.opInt2Float(42, 4)
        val, _ = self.f32.getHostFloat(result)
        assert abs(val - 42.0) < 1e-7

    def test_opInt2Float_signed(self):
        # -1 as unsigned 32-bit = 0xFFFFFFFF
        result = self.f32.opInt2Float(0xFFFFFFFF, 4)
        val, _ = self.f32.getHostFloat(result)
        assert abs(val - (-1.0)) < 1e-7

    def test_opFloat2Float(self):
        f64 = FloatFormat(8)
        enc32 = self.f32.getEncoding(1.0)
        enc64 = self.f32.opFloat2Float(enc32, f64)
        val, _ = f64.getHostFloat(enc64)
        assert val == 1.0


class TestPrintDecimal:
    def test_integer_value(self):
        ff = FloatFormat(8)
        s = ff.printDecimal(1.0)
        assert '1' in s

    def test_pi(self):
        ff = FloatFormat(8)
        s = ff.printDecimal(math.pi)
        assert s.startswith('3.14')

    def test_scientific(self):
        ff = FloatFormat(8)
        s = ff.printDecimal(1.0, forcesci=True)
        assert 'e' in s.lower()

    def test_float32_precision(self):
        ff = FloatFormat(4)
        s = ff.printDecimal(0.1)
        # Should have limited precision for float32
        assert len(s) < 20


class TestCountLeadingZeros:
    def test_zero(self):
        assert FloatFormat._count_leading_zeros(0) == 64

    def test_one(self):
        assert FloatFormat._count_leading_zeros(1) == 63

    def test_msb(self):
        assert FloatFormat._count_leading_zeros(1 << 63) == 0

    def test_half(self):
        assert FloatFormat._count_leading_zeros(1 << 31) == 32


if __name__ == '__main__':
    pytest.main([__file__, '-v'])
