"""Tests for ghidra.core.int128 – Python port of multiprecision.cc."""
from __future__ import annotations

import pytest
import sys, os

sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', 'python'))

from ghidra.core.int128 import (
    set_u128, leftshift128, rightshift128, add128, subtract128,
    mult128, mult64to128, div128by64, udiv128,
    uless128, ulessequal128, count_leading_zeros,
    MASK128, MASK64,
)


# =========================================================================
# Tests – set_u128
# =========================================================================

class TestSetU128:
    def test_small(self):
        assert set_u128(42) == 42

    def test_zero(self):
        assert set_u128(0) == 0

    def test_max64(self):
        assert set_u128(MASK64) == MASK64

    def test_overflow_truncation(self):
        assert set_u128(MASK128 + 1) == 0

    def test_large(self):
        val = (1 << 127) | 0xFF
        assert set_u128(val) == val


# =========================================================================
# Tests – leftshift128
# =========================================================================

class TestLeftShift128:
    def test_shift_zero(self):
        assert leftshift128(1, 0) == 1

    def test_shift_one(self):
        assert leftshift128(1, 1) == 2

    def test_shift_64(self):
        assert leftshift128(1, 64) == (1 << 64)

    def test_shift_127(self):
        assert leftshift128(1, 127) == (1 << 127)

    def test_shift_128_wraps(self):
        assert leftshift128(1, 128) == 0

    def test_large_value(self):
        val = 0xDEADBEEF
        assert leftshift128(val, 32) == (val << 32)


# =========================================================================
# Tests – rightshift128
# =========================================================================

class TestRightShift128:
    def test_shift_zero(self):
        assert rightshift128(0xFF, 0) == 0xFF

    def test_shift_one(self):
        assert rightshift128(0xFF, 1) == 0x7F

    def test_shift_64(self):
        val = 1 << 64
        assert rightshift128(val, 64) == 1

    def test_shift_all(self):
        assert rightshift128(MASK128, 128) == 0


# =========================================================================
# Tests – add128
# =========================================================================

class TestAdd128:
    def test_simple(self):
        assert add128(3, 5) == 8

    def test_carry(self):
        assert add128(MASK64, 1) == (1 << 64)

    def test_overflow_wraps(self):
        assert add128(MASK128, 1) == 0

    def test_large(self):
        a = 1 << 127
        b = 1 << 126
        assert add128(a, b) == a + b


# =========================================================================
# Tests – subtract128
# =========================================================================

class TestSubtract128:
    def test_simple(self):
        assert subtract128(10, 3) == 7

    def test_zero(self):
        assert subtract128(5, 5) == 0

    def test_underflow_wraps(self):
        assert subtract128(0, 1) == MASK128

    def test_large(self):
        a = 1 << 100
        b = 1 << 50
        assert subtract128(a, b) == (a - b)


# =========================================================================
# Tests – uless128 / ulessequal128
# =========================================================================

class TestCompare128:
    def test_less_true(self):
        assert uless128(5, 10) is True

    def test_less_false_equal(self):
        assert uless128(10, 10) is False

    def test_less_false_greater(self):
        assert uless128(10, 5) is False

    def test_lessequal_true_less(self):
        assert ulessequal128(5, 10) is True

    def test_lessequal_true_equal(self):
        assert ulessequal128(10, 10) is True

    def test_lessequal_false(self):
        assert ulessequal128(10, 5) is False

    def test_large_values(self):
        a = (1 << 127) - 1
        b = 1 << 127
        assert uless128(a, b) is True
        assert ulessequal128(b, a) is False


# =========================================================================
# Tests – mult128 / mult64to128
# =========================================================================

class TestMult128:
    def test_simple(self):
        assert mult128(3, 7) == 21

    def test_overflow(self):
        assert mult128(MASK128, 2) == MASK128 - 1

    def test_mult64to128(self):
        a = MASK64
        b = 2
        assert mult64to128(a, b) == a * b

    def test_mult64to128_max(self):
        a = MASK64
        b = MASK64
        result = mult64to128(a, b)
        assert result == a * b
        assert result < (1 << 128)


# =========================================================================
# Tests – div128by64
# =========================================================================

class TestDiv128by64:
    def test_simple(self):
        q, r = div128by64(10, 3)
        assert q == 3
        assert r == 1

    def test_exact(self):
        q, r = div128by64(100, 10)
        assert q == 10
        assert r == 0

    def test_divide_by_zero(self):
        q, r = div128by64(100, 0)
        assert q == 0
        assert r == 0

    def test_large(self):
        n = 1 << 100
        d = 1 << 50
        q, r = div128by64(n, d)
        assert q == (1 << 50)
        assert r == 0


# =========================================================================
# Tests – udiv128
# =========================================================================

class TestUdiv128:
    def test_simple(self):
        q, r = udiv128(10, 3)
        assert q == 3
        assert r == 1

    def test_exact(self):
        q, r = udiv128(1000, 100)
        assert q == 10
        assert r == 0

    def test_divide_by_zero(self):
        from ghidra.core.error import LowlevelError
        with pytest.raises(LowlevelError, match="divide by 0"):
            udiv128(100, 0)

    def test_large_numerator(self):
        n = (1 << 127) + (1 << 64) + 42
        d = 1 << 64
        q, r = udiv128(n, d)
        assert q == n // d
        assert r == n % d

    def test_denom_larger(self):
        q, r = udiv128(5, 100)
        assert q == 0
        assert r == 5

    def test_128bit_both(self):
        n = MASK128
        d = 1 << 100
        q, r = udiv128(n, d)
        assert q * d + r == n


# =========================================================================
# Tests – count_leading_zeros
# =========================================================================

class TestCountLeadingZeros:
    def test_zero(self):
        assert count_leading_zeros(0) == 64

    def test_one(self):
        assert count_leading_zeros(1) == 63

    def test_msb(self):
        assert count_leading_zeros(1 << 63) == 0

    def test_all_ones(self):
        assert count_leading_zeros(MASK64) == 0

    def test_power_of_two(self):
        assert count_leading_zeros(1 << 32) == 31

    def test_small(self):
        assert count_leading_zeros(0xFF) == 56

    def test_half(self):
        assert count_leading_zeros(1 << 31) == 32


if __name__ == '__main__':
    pytest.main([__file__, '-v'])
