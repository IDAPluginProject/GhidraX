"""
128-bit integer arithmetic helpers for division optimization rules.
Corresponds to the 128-bit operations in ruleaction.cc (set_u128, leftshift128, add128, etc.)
"""


def set_u128(val: int) -> int:
    """Create a 128-bit unsigned value."""
    return val & ((1 << 128) - 1)


def leftshift128(val: int, sa: int) -> int:
    """Left-shift a 128-bit value."""
    return (val << sa) & ((1 << 128) - 1)


def rightshift128(val: int, sa: int) -> int:
    """Right-shift a 128-bit value."""
    return val >> sa


def add128(a: int, b: int) -> int:
    """Add two 128-bit values."""
    return (a + b) & ((1 << 128) - 1)


def mult128(a: int, b: int) -> int:
    """Multiply two values, result up to 128 bits."""
    return (a * b) & ((1 << 128) - 1)


def mult64to128(a: int, b: int) -> int:
    """Multiply two 64-bit values, returning full 128-bit result."""
    return (a & 0xFFFFFFFFFFFFFFFF) * (b & 0xFFFFFFFFFFFFFFFF)


def div128by64(dividend: int, divisor: int) -> tuple:
    """Divide 128-bit by 64-bit, returning (quotient, remainder)."""
    if divisor == 0:
        return (0, 0)
    q = dividend // divisor
    r = dividend % divisor
    return (q & ((1 << 128) - 1), r & 0xFFFFFFFFFFFFFFFF)


MASK128 = (1 << 128) - 1
MASK64 = (1 << 64) - 1


def subtract128(a: int, b: int) -> int:
    """Subtract two 128-bit unsigned values (a - b) mod 2^128."""
    return (a - b) & MASK128


def uless128(a: int, b: int) -> bool:
    """128-bit unsigned less-than comparison."""
    return (a & MASK128) < (b & MASK128)


def ulessequal128(a: int, b: int) -> bool:
    """128-bit unsigned less-than-or-equal comparison."""
    return (a & MASK128) <= (b & MASK128)


def udiv128(numer: int, denom: int) -> tuple:
    """Divide 128-bit by 128-bit unsigned, returning (quotient, remainder).

    Both values are treated as unsigned 128-bit integers.
    Raises LowlevelError on divide by zero.
    """
    numer = numer & MASK128
    denom = denom & MASK128
    if denom == 0:
        from ghidra.core.error import LowlevelError
        raise LowlevelError("divide by 0")
    q = numer // denom
    r = numer % denom
    return (q & MASK128, r & MASK128)


def count_leading_zeros(val: int) -> int:
    """Return the number of leading zero bits in a 64-bit value."""
    val = val & MASK64
    if val == 0:
        return 64
    n = 0
    if val <= 0x00000000FFFFFFFF:
        n += 32; val <<= 32
    if val <= 0x0000FFFFFFFFFFFF:
        n += 16; val <<= 16
    if val <= 0x00FFFFFFFFFFFFFF:
        n += 8; val <<= 8
    if val <= 0x0FFFFFFFFFFFFFFF:
        n += 4; val <<= 4
    if val <= 0x3FFFFFFFFFFFFFFF:
        n += 2; val <<= 2
    if val <= 0x7FFFFFFFFFFFFFFF:
        n += 1
    return n


def calcDivisor(n: int, y: int, xsize: int) -> int:
    """Calculate the actual divisor from multiply-high constant and shift.
    
    Given a multiply-high division pattern: (x * y) >> n
    The actual divisor d satisfies: y ≈ 2^n / d
    So d ≈ 2^n / y (rounded).
    """
    if y == 0:
        return 0
    power = 1 << n
    d = (power + y - 1) // y  # Ceiling division
    # Verify: d * y should be close to 2^n
    product = d * y
    if abs(product - power) <= d:
        return d
    return 0
