"""
Corresponds to: multiprecision.hh / multiprecision.cc

Re-exports from ghidra.core.int128, which contains the full implementation
of multi-precision (128-bit) integer arithmetic.
"""

from ghidra.core.int128 import (  # noqa: F401
    set_u128, leftshift128, rightshift128,
    add128, subtract128, mult128, mult64to128,
    div128by64, udiv128,
    uless128, ulessequal128,
    count_leading_zeros,
    MASK128, MASK64,
)
