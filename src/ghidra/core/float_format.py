"""
Corresponds to: float.hh / float.cc

Support for decoding different floating-point formats.
Uses Python's native float (IEEE 754 double) for host representation.
"""

from __future__ import annotations

import math
from enum import IntEnum

from ghidra.core.address import calc_mask


class FloatClass(IntEnum):
    """The various classes of floating-point encodings."""
    normalized = 0
    infinity = 1
    zero = 2
    nan = 3
    denormalized = 4


class FloatFormat:
    """Encoding information for a single floating-point format.

    Supports manipulation of a single floating-point encoding following
    the IEEE 754 standard.
    """

    def __init__(self, sz: int) -> None:
        self.size: int = sz
        self.signbit_pos: int = 0
        self.frac_pos: int = 0
        self.frac_size: int = 0
        self.exp_pos: int = 0
        self.exp_size: int = 0
        self.bias: int = 0
        self.maxexponent: int = 0
        self.jbitimplied: bool = True
        self.decimalMinPrecision: int = 0
        self.decimalMaxPrecision: int = 0

        # Set up default IEEE 754 parameters based on size
        if sz == 4:
            self.signbit_pos = 31
            self.exp_pos = 23
            self.exp_size = 8
            self.frac_pos = 0
            self.frac_size = 23
            self.bias = 127
            self.jbitimplied = True
        elif sz == 8:
            self.signbit_pos = 63
            self.exp_pos = 52
            self.exp_size = 11
            self.frac_pos = 0
            self.frac_size = 52
            self.bias = 1023
            self.jbitimplied = True
        self.maxexponent = (1 << self.exp_size) - 1
        self._calcPrecision()

    def _calcPrecision(self) -> None:
        """Calculate the decimal precision of this format.

        Matches C++ calcPrecision: uses frac_size directly (not +1 for jbit).
        """
        self.decimalMinPrecision = int(math.floor(self.frac_size * 0.30103))
        self.decimalMaxPrecision = int(math.ceil((self.frac_size + 1) * 0.30103)) + 1

    def getSize(self) -> int:
        return self.size

    # --- Extraction helpers (C++ faithful) ---

    _INTB_BITS: int = 64  # C++ uses 8*sizeof(uintb) = 64

    def extractFractionalCode(self, x: int) -> int:
        """Extract fractional code aligned to top of 64-bit word (C++ faithful)."""
        x >>= self.frac_pos
        x &= (1 << self.frac_size) - 1
        x <<= (self._INTB_BITS - self.frac_size)
        return x

    def extractFractionalCodeRaw(self, x: int) -> int:
        """Extract raw fractional bits (not aligned)."""
        mask = (1 << self.frac_size) - 1
        return (x >> self.frac_pos) & mask

    def extractSign(self, x: int) -> bool:
        return ((x >> self.signbit_pos) & 1) != 0

    def extractExponentCode(self, x: int) -> int:
        mask = (1 << self.exp_size) - 1
        return (x >> self.exp_pos) & mask

    def _setFractionalCode(self, x: int, code: int) -> int:
        """Set fractional code from top-aligned 64-bit value (C++ faithful)."""
        code >>= (self._INTB_BITS - self.frac_size)
        code <<= self.frac_pos
        x |= code
        return x

    def _setSign(self, x: int, sign: bool) -> int:
        if sign:
            x |= (1 << self.signbit_pos)
        else:
            x &= ~(1 << self.signbit_pos)
        return x

    def _setExponentCode(self, x: int, code: int) -> int:
        mask = (1 << self.exp_size) - 1
        x &= ~(mask << self.exp_pos)
        x |= (code & mask) << self.exp_pos
        return x

    # --- Public API matching C++ method names ---

    def calcPrecision(self) -> None:
        """C++ ref: FloatFormat::calcPrecision"""
        self._calcPrecision()

    @staticmethod
    def createFloat(sign: bool, signif: int, exp: int) -> float:
        """C++ ref: FloatFormat::createFloat"""
        return FloatFormat._createFloat(sign, signif, exp)

    @staticmethod
    def extractExpSig(x: float) -> tuple[FloatClass, bool, int, int]:
        """C++ ref: FloatFormat::extractExpSig"""
        return FloatFormat._extractExpSig(x)

    def setFractionalCode(self, x: int, code: int) -> int:
        """C++ ref: FloatFormat::setFractionalCode"""
        return self._setFractionalCode(x, code)

    def setSign(self, x: int, sign: bool) -> int:
        """C++ ref: FloatFormat::setSign"""
        return self._setSign(x, sign)

    def setExponentCode(self, x: int, code: int) -> int:
        """C++ ref: FloatFormat::setExponentCode"""
        return self._setExponentCode(x, code)

    def getZeroEncoding(self, sgn: bool) -> int:
        """C++ ref: FloatFormat::getZeroEncoding"""
        return self._getZeroEncoding(sgn)

    def getInfinityEncoding(self, sgn: bool) -> int:
        """C++ ref: FloatFormat::getInfinityEncoding"""
        return self._getInfinityEncoding(sgn)

    def getNaNEncoding(self, sgn: bool) -> int:
        """C++ ref: FloatFormat::getNaNEncoding"""
        return self._getNaNEncoding(sgn)

    # --- Conversion to/from host float ---

    @staticmethod
    def _createFloat(sign: bool, signif: int, exp: int) -> float:
        """Create a float from sign, significand, and exponent (C++ faithful)."""
        BITS = 64
        signif >>= 1  # Throw away 1 bit of precision
        precis = BITS - 1
        res = float(signif)
        expchange = exp - precis + 1
        res = math.ldexp(res, expchange)
        if sign:
            res = -res
        return res

    @staticmethod
    def _extractExpSig(x: float) -> tuple[FloatClass, bool, int, int]:
        """Extract sign, significand, exponent from host float (C++ faithful).

        Returns (floatclass, sign, significand, exponent).
        """
        BITS = 64
        sgn = math.copysign(1.0, x) < 0
        if x == 0.0:
            return FloatClass.zero, sgn, 0, 0
        if math.isinf(x):
            return FloatClass.infinity, sgn, 0, 0
        if math.isnan(x):
            return FloatClass.nan, sgn, 0, 0
        if sgn:
            x = -x
        norm, e = math.frexp(x)  # norm between 0.5 and 1.0
        norm = math.ldexp(norm, BITS - 1)  # norm between 2^62 and 2^63
        signif = int(norm)
        signif <<= 1
        signif &= (1 << BITS) - 1
        e -= 1  # Normalization between 1 and 2
        return FloatClass.normalized, sgn, signif, e

    def getHostFloat(self, encoding: int) -> tuple[float, FloatClass]:
        """Convert an encoding into host's double (C++ faithful).

        Returns (float_value, float_class).
        """
        BITS = self._INTB_BITS
        sgn = self.extractSign(encoding)
        frac = self.extractFractionalCode(encoding)  # Top-aligned
        exp = self.extractExponentCode(encoding)
        normal = True

        if exp == 0:
            if frac == 0:
                return (-0.0 if sgn else 0.0), FloatClass.zero
            normal = False
            ftype = FloatClass.denormalized
        elif exp == self.maxexponent:
            if frac == 0:
                return (float('-inf') if sgn else float('inf')), FloatClass.infinity
            return float('nan'), FloatClass.nan
        else:
            ftype = FloatClass.normalized

        # Get "true" exponent and fractional
        exp -= self.bias
        if normal and self.jbitimplied:
            frac >>= 1  # Make room for 1 jbit
            highbit = 1 << (BITS - 1)
            frac |= highbit  # Stick bit in at top
        return self._createFloat(sgn, frac, exp), ftype

    def getEncoding(self, host: float) -> int:
        """Convert host's double into this encoding (C++ faithful)."""
        BITS = self._INTB_BITS
        ftype, sgn, signif, exp = self._extractExpSig(host)
        if ftype == FloatClass.zero:
            return self._getZeroEncoding(sgn)
        if ftype == FloatClass.infinity:
            return self._getInfinityEncoding(sgn)
        if ftype == FloatClass.nan:
            return self._getNaNEncoding(sgn)

        exp += self.bias

        if exp < -self.frac_size:
            return self._getZeroEncoding(sgn)

        if exp < 1:  # Must be denormalized
            signif, _ = self.roundToNearestEven(signif, BITS - self.frac_size - exp)
            if (signif >> (BITS - 1)) == 0:
                signif = 1 << (BITS - 1)
                exp += 1
            res = self._getZeroEncoding(sgn)
            shifted = signif >> (-exp)
            return self._setFractionalCode(res, shifted)

        signif, rounded = self.roundToNearestEven(signif, BITS - self.frac_size - 1)
        if rounded and (signif >> (BITS - 1)) == 0:
            signif = 1 << (BITS - 1)
            exp += 1

        if exp >= self.maxexponent:
            return self._getInfinityEncoding(sgn)

        if self.jbitimplied and exp != 0:
            signif <<= 1  # Cut off top bit (which should be 1)
            signif &= (1 << BITS) - 1

        res = 0
        res = self._setFractionalCode(res, signif)
        res = self._setExponentCode(res, exp)
        return self._setSign(res, sgn)

    def convertEncoding(self, encoding: int, formin: FloatFormat) -> int:
        """Convert an encoding from another FloatFormat to this one (C++ faithful)."""
        BITS = self._INTB_BITS
        sgn = formin.extractSign(encoding)
        signif = formin.extractFractionalCode(encoding)
        exp = formin.extractExponentCode(encoding)

        if exp == formin.maxexponent:
            if signif != 0:
                return self._getNaNEncoding(sgn)
            return self._getInfinityEncoding(sgn)

        if exp == 0:  # incoming is subnormal
            if signif == 0:
                return self._getZeroEncoding(sgn)
            lz = self._count_leading_zeros(signif)
            signif = (signif << lz) & ((1 << BITS) - 1)
            exp = -formin.bias - lz
        else:  # incoming is normal
            exp -= formin.bias
            if self.jbitimplied:
                signif = (1 << (BITS - 1)) | (signif >> 1)

        exp += self.bias

        if exp < -self.frac_size:
            return self._getZeroEncoding(sgn)

        if exp < 1:  # Must be denormalized
            signif, _ = self.roundToNearestEven(signif, BITS - self.frac_size - exp)
            if (signif >> (BITS - 1)) == 0:
                signif = 1 << (BITS - 1)
                exp += 1
            res = self._getZeroEncoding(sgn)
            return self._setFractionalCode(res, signif >> (-exp))

        signif, rounded = self.roundToNearestEven(signif, BITS - self.frac_size - 1)
        if rounded and (signif >> (BITS - 1)) == 0:
            signif = 1 << (BITS - 1)
            exp += 1

        if exp >= self.maxexponent:
            return self._getInfinityEncoding(sgn)

        if self.jbitimplied and exp != 0:
            signif <<= 1
            signif &= (1 << BITS) - 1

        res = 0
        res = self._setFractionalCode(res, signif)
        res = self._setExponentCode(res, exp)
        return self._setSign(res, sgn)

    def _getZeroEncoding(self, sgn: bool) -> int:
        """IEEE 754 zero encoding."""
        res = 0
        res = self._setFractionalCode(res, 0)
        res = self._setExponentCode(res, 0)
        return self._setSign(res, sgn)

    def _getInfinityEncoding(self, sgn: bool) -> int:
        """IEEE 754 infinity encoding."""
        res = 0
        res = self._setFractionalCode(res, 0)
        res = self._setExponentCode(res, self.maxexponent)
        return self._setSign(res, sgn)

    def _getNaNEncoding(self, sgn: bool) -> int:
        """IEEE 754 quiet NaN encoding."""
        res = 0
        mask = 1 << (self._INTB_BITS - 1)  # Create "quiet" NaN
        res = self._setFractionalCode(res, mask)
        res = self._setExponentCode(res, self.maxexponent)
        return self._setSign(res, sgn)

    @staticmethod
    def roundToNearestEven(signif: int, lowbitpos: int) -> tuple[int, bool]:
        """Round a significand to the nearest even value.

        Returns (rounded_signif, did_round_up).
        """
        BITS = 64
        lowbitmask = (1 << lowbitpos) if lowbitpos < BITS else 0
        midbitmask = 1 << (lowbitpos - 1)
        epsmask = midbitmask - 1
        odd = (signif & lowbitmask) != 0
        if (signif & midbitmask) != 0 and ((signif & epsmask) != 0 or odd):
            signif = (signif + midbitmask) & ((1 << BITS) - 1)
            return signif, True
        return signif, False

    @staticmethod
    def _count_leading_zeros(val: int) -> int:
        """Count leading zeros in a 64-bit value."""
        if val == 0:
            return 64
        n = 0
        for shift in [32, 16, 8, 4, 2, 1]:
            if val >> (64 - shift) == 0:
                n += shift
                val <<= shift
                val &= (1 << 64) - 1
        return n

    # --- P-code floating-point operations ---

    def _toHost(self, a: int) -> float:
        val, _ = self.getHostFloat(a)
        return val

    def _fromHost(self, val: float) -> int:
        return self.getEncoding(val)

    def opEqual(self, a: int, b: int) -> int:
        return 1 if self._toHost(a) == self._toHost(b) else 0

    def opNotEqual(self, a: int, b: int) -> int:
        return 1 if self._toHost(a) != self._toHost(b) else 0

    def opLess(self, a: int, b: int) -> int:
        return 1 if self._toHost(a) < self._toHost(b) else 0

    def opLessEqual(self, a: int, b: int) -> int:
        return 1 if self._toHost(a) <= self._toHost(b) else 0

    def opNan(self, a: int) -> int:
        return 1 if math.isnan(self._toHost(a)) else 0

    def opAdd(self, a: int, b: int) -> int:
        return self._fromHost(self._toHost(a) + self._toHost(b))

    def opDiv(self, a: int, b: int) -> int:
        bv = self._toHost(b)
        if bv == 0.0:
            return self._getInfinityEncoding(self._toHost(a) < 0)
        return self._fromHost(self._toHost(a) / bv)

    def opMult(self, a: int, b: int) -> int:
        return self._fromHost(self._toHost(a) * self._toHost(b))

    def opSub(self, a: int, b: int) -> int:
        return self._fromHost(self._toHost(a) - self._toHost(b))

    def opNeg(self, a: int) -> int:
        return self._fromHost(-self._toHost(a))

    def opAbs(self, a: int) -> int:
        return self._fromHost(abs(self._toHost(a)))

    def opSqrt(self, a: int) -> int:
        return self._fromHost(math.sqrt(self._toHost(a)))

    def opTrunc(self, a: int, sizeout: int) -> int:
        val = self._toHost(a)
        ival = int(math.trunc(val))
        mask = calc_mask(sizeout)
        return ival & mask

    def opCeil(self, a: int) -> int:
        return self._fromHost(math.ceil(self._toHost(a)))

    def opFloor(self, a: int) -> int:
        return self._fromHost(math.floor(self._toHost(a)))

    def opRound(self, a: int) -> int:
        val = self._toHost(a)
        rounded = math.copysign(math.floor(abs(val) + 0.5), val)
        return self._fromHost(rounded)

    def opInt2Float(self, a: int, sizein: int) -> int:
        mask = calc_mask(sizein)
        a &= mask
        # Treat as signed
        if a >= (1 << (sizein * 8 - 1)):
            a -= (1 << (sizein * 8))
        return self._fromHost(float(a))

    def opFloat2Float(self, a: int, outformat: FloatFormat) -> int:
        return outformat.convertEncoding(a, self)

    def printDecimal(self, host: float, forcesci: bool = False) -> str:
        """Print with minimum digits for unique round-trip (C++ faithful)."""
        for prec in range(self.decimalMinPrecision, self.decimalMaxPrecision + 1):
            if forcesci:
                s = f"{host:.{prec - 1}e}"
            else:
                s = f"{host:.{prec}g}"
            if prec == self.decimalMaxPrecision:
                return s
            try:
                if self.size <= 4:
                    import struct as _struct
                    roundtrip = _struct.unpack('<f', _struct.pack('<f', float(s)))[0]
                else:
                    roundtrip = float(s)
            except (ValueError, OverflowError):
                continue
            if roundtrip == host:
                return s
        return s  # type: ignore[possibly-undefined]
