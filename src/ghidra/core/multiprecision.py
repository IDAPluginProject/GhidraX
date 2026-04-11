"""
Corresponds to: multiprecision.hh / multiprecision.cc

This module exposes the C++-style 128-bit helpers that operate on two
64-bit words stored least-significant-word first. For compatibility with
existing Python callers, the original scalar helpers from ``int128`` are
still accepted where that surface previously existed.
"""

from __future__ import annotations

from collections.abc import MutableSequence, Sequence

from ghidra.core import int128 as _int128

MASK128 = _int128.MASK128
MASK64 = _int128.MASK64
count_leading_zeros = _int128.count_leading_zeros
leftshift128 = _int128.leftshift128
rightshift128 = _int128.rightshift128
mult128 = _int128.mult128
mult64to128 = _int128.mult64to128
div128by64 = _int128.div128by64


def _is_scalar_u128(value) -> bool:
    return isinstance(value, int)


def _words_to_u128(words: Sequence[int]) -> int:
    return (int(words[0]) & MASK64) | ((int(words[1]) & MASK64) << 64)


def _store_u128(words: MutableSequence[int], value: int) -> None:
    value &= MASK128
    words[0] = value & MASK64
    words[1] = (value >> 64) & MASK64


def set_u128(res_or_val, val: int | None = None):
    """Set a 128-bit value from a 64-bit value.

    C++ ref: ``set_u128(uint8 *res,uint8 val)`` in multiprecision.hh.
    When called with a single integer argument, preserve the existing Python
    scalar helper behavior and return the masked 128-bit integer.
    """

    if val is None:
        if not _is_scalar_u128(res_or_val):
            raise TypeError("single-argument set_u128 expects an integer value")
        return _int128.set_u128(int(res_or_val))
    res = res_or_val
    res[0] = int(val) & MASK64
    res[1] = 0


def add128(in1, in2, out: MutableSequence[int] | None = None):
    """128-bit unsigned addition."""

    if out is None:
        if not (_is_scalar_u128(in1) and _is_scalar_u128(in2)):
            raise TypeError("out must be provided for word-array add128 inputs")
        return _int128.add128(int(in1), int(in2))
    _store_u128(out, _int128.add128(_words_to_u128(in1), _words_to_u128(in2)))


def subtract128(in1, in2, out: MutableSequence[int] | None = None):
    """128-bit unsigned subtraction."""

    if out is None:
        if not (_is_scalar_u128(in1) and _is_scalar_u128(in2)):
            raise TypeError("out must be provided for word-array subtract128 inputs")
        return _int128.subtract128(int(in1), int(in2))
    _store_u128(out, _int128.subtract128(_words_to_u128(in1), _words_to_u128(in2)))


def uless128(in1, in2) -> bool:
    """128-bit unsigned less-than comparison."""

    if _is_scalar_u128(in1) and _is_scalar_u128(in2):
        return _int128.uless128(int(in1), int(in2))
    return _words_to_u128(in1) < _words_to_u128(in2)


def ulessequal128(in1, in2) -> bool:
    """128-bit unsigned less-than-or-equal comparison."""

    if _is_scalar_u128(in1) and _is_scalar_u128(in2):
        return _int128.ulessequal128(int(in1), int(in2))
    return _words_to_u128(in1) <= _words_to_u128(in2)


def udiv128(
    numer,
    denom,
    quotient_res: MutableSequence[int] | None = None,
    remainder_res: MutableSequence[int] | None = None,
):
    """128-bit unsigned division.

    C++ ref: ``udiv128(uint8 *numer,uint8 *denom,uint8 *quotient_res,uint8 *remainder_res)``.
    With only 2 integer arguments, preserve the existing Python scalar helper
    and return ``(quotient, remainder)``.
    """

    if quotient_res is None and remainder_res is None:
        if not (_is_scalar_u128(numer) and _is_scalar_u128(denom)):
            raise TypeError(
                "quotient_res and remainder_res must be provided for word-array udiv128 inputs"
            )
        return _int128.udiv128(int(numer), int(denom))
    if quotient_res is None or remainder_res is None:
        raise TypeError("quotient_res and remainder_res must both be provided")
    quotient, remainder = _int128.udiv128(
        _words_to_u128(numer), _words_to_u128(denom)
    )
    _store_u128(quotient_res, quotient)
    _store_u128(remainder_res, remainder)


__all__ = [
    "MASK128",
    "MASK64",
    "set_u128",
    "leftshift128",
    "rightshift128",
    "add128",
    "subtract128",
    "mult128",
    "mult64to128",
    "div128by64",
    "udiv128",
    "uless128",
    "ulessequal128",
    "count_leading_zeros",
]
