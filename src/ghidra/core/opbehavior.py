"""
Corresponds to: opbehavior.hh / opbehavior.cc

Classes for describing the behavior of individual p-code operations.
Each OpBehavior subclass implements evaluateUnary/evaluateBinary for
one specific opcode.
"""

from __future__ import annotations

from typing import TYPE_CHECKING, Optional, List

from ghidra.core.error import LowlevelError
from ghidra.core.opcodes import OpCode, get_opname
from ghidra.core.address import calc_mask, signbit_negative, popcount, count_leading_zeros
from ghidra.core.types import to_signed, to_unsigned

if TYPE_CHECKING:
    from ghidra.core.translate import Translate


class EvaluationError(LowlevelError):
    """Exception thrown when emulation evaluation of an operator fails."""

    def __init__(self, s: str) -> None:
        super().__init__(s)


# =========================================================================
# OpBehavior base
# =========================================================================

class OpBehavior:
    """Base class encapsulating the action/behavior of specific pcode opcodes."""

    def __init__(self, opc: OpCode, isun: bool, isspec: bool = False) -> None:
        self._opcode: OpCode = opc
        self._isunary: bool = isun
        self._isspecial: bool = isspec

    def __del__(self) -> None:
        pass

    def getOpcode(self) -> OpCode:
        return self._opcode

    def isSpecial(self) -> bool:
        return self._isspecial

    def isUnary(self) -> bool:
        return self._isunary

    def evaluateUnary(self, sizeout: int, sizein: int, in1: int) -> int:
        raise EvaluationError(
            f"Unary emulation unimplemented for {get_opname(self._opcode)}"
        )

    def evaluateBinary(self, sizeout: int, sizein: int, in1: int, in2: int) -> int:
        raise EvaluationError(
            f"Binary emulation unimplemented for {get_opname(self._opcode)}"
        )

    def evaluateTernary(self, sizeout: int, sizein: int, in1: int, in2: int, in3: int) -> int:
        raise EvaluationError(
            f"Ternary emulation unimplemented for {get_opname(self._opcode)}"
        )

    def recoverInputBinary(self, slot: int, sizeout: int, out: int, sizein: int, inp: int) -> int:
        raise EvaluationError(
            "Cannot recover input parameter without loss of information"
        )

    def recoverInputUnary(self, sizeout: int, out: int, sizein: int) -> int:
        raise EvaluationError(
            "Cannot recover input parameter without loss of information"
        )

    @staticmethod
    def registerInstructions(
        inst: Optional[List[Optional["OpBehavior"]]] = None,
        trans: Optional[Translate] = None,
    ) -> List["OpBehavior"]:
        """Build all pcode behaviors, returning a list indexed by OpCode value."""
        if inst is not None and not isinstance(inst, list):
            trans = inst
            inst = None
        if inst is None:
            inst = [None] * OpCode.CPUI_MAX
        else:
            inst.clear()
            inst.extend([None] * OpCode.CPUI_MAX)
        inst[OpCode.CPUI_COPY] = OpBehaviorCopy()
        inst[OpCode.CPUI_LOAD] = OpBehavior(OpCode.CPUI_LOAD, False, True)
        inst[OpCode.CPUI_STORE] = OpBehavior(OpCode.CPUI_STORE, False, True)
        inst[OpCode.CPUI_BRANCH] = OpBehavior(OpCode.CPUI_BRANCH, False, True)
        inst[OpCode.CPUI_CBRANCH] = OpBehavior(OpCode.CPUI_CBRANCH, False, True)
        inst[OpCode.CPUI_BRANCHIND] = OpBehavior(OpCode.CPUI_BRANCHIND, False, True)
        inst[OpCode.CPUI_CALL] = OpBehavior(OpCode.CPUI_CALL, False, True)
        inst[OpCode.CPUI_CALLIND] = OpBehavior(OpCode.CPUI_CALLIND, False, True)
        inst[OpCode.CPUI_CALLOTHER] = OpBehavior(OpCode.CPUI_CALLOTHER, False, True)
        inst[OpCode.CPUI_RETURN] = OpBehavior(OpCode.CPUI_RETURN, False, True)
        inst[OpCode.CPUI_INT_EQUAL] = OpBehaviorEqual()
        inst[OpCode.CPUI_INT_NOTEQUAL] = OpBehaviorNotEqual()
        inst[OpCode.CPUI_INT_SLESS] = OpBehaviorIntSless()
        inst[OpCode.CPUI_INT_SLESSEQUAL] = OpBehaviorIntSlessEqual()
        inst[OpCode.CPUI_INT_LESS] = OpBehaviorIntLess()
        inst[OpCode.CPUI_INT_LESSEQUAL] = OpBehaviorIntLessEqual()
        inst[OpCode.CPUI_INT_ZEXT] = OpBehaviorIntZext()
        inst[OpCode.CPUI_INT_SEXT] = OpBehaviorIntSext()
        inst[OpCode.CPUI_INT_ADD] = OpBehaviorIntAdd()
        inst[OpCode.CPUI_INT_SUB] = OpBehaviorIntSub()
        inst[OpCode.CPUI_INT_CARRY] = OpBehaviorIntCarry()
        inst[OpCode.CPUI_INT_SCARRY] = OpBehaviorIntScarry()
        inst[OpCode.CPUI_INT_SBORROW] = OpBehaviorIntSborrow()
        inst[OpCode.CPUI_INT_2COMP] = OpBehaviorInt2Comp()
        inst[OpCode.CPUI_INT_NEGATE] = OpBehaviorIntNegate()
        inst[OpCode.CPUI_INT_XOR] = OpBehaviorIntXor()
        inst[OpCode.CPUI_INT_AND] = OpBehaviorIntAnd()
        inst[OpCode.CPUI_INT_OR] = OpBehaviorIntOr()
        inst[OpCode.CPUI_INT_LEFT] = OpBehaviorIntLeft()
        inst[OpCode.CPUI_INT_RIGHT] = OpBehaviorIntRight()
        inst[OpCode.CPUI_INT_SRIGHT] = OpBehaviorIntSright()
        inst[OpCode.CPUI_INT_MULT] = OpBehaviorIntMult()
        inst[OpCode.CPUI_INT_DIV] = OpBehaviorIntDiv()
        inst[OpCode.CPUI_INT_SDIV] = OpBehaviorIntSdiv()
        inst[OpCode.CPUI_INT_REM] = OpBehaviorIntRem()
        inst[OpCode.CPUI_INT_SREM] = OpBehaviorIntSrem()
        inst[OpCode.CPUI_BOOL_NEGATE] = OpBehaviorBoolNegate()
        inst[OpCode.CPUI_BOOL_XOR] = OpBehaviorBoolXor()
        inst[OpCode.CPUI_BOOL_AND] = OpBehaviorBoolAnd()
        inst[OpCode.CPUI_BOOL_OR] = OpBehaviorBoolOr()
        inst[OpCode.CPUI_FLOAT_EQUAL] = OpBehaviorFloatEqual(trans)
        inst[OpCode.CPUI_FLOAT_NOTEQUAL] = OpBehaviorFloatNotEqual(trans)
        inst[OpCode.CPUI_FLOAT_LESS] = OpBehaviorFloatLess(trans)
        inst[OpCode.CPUI_FLOAT_LESSEQUAL] = OpBehaviorFloatLessEqual(trans)
        inst[OpCode.CPUI_FLOAT_NAN] = OpBehaviorFloatNan(trans)
        inst[OpCode.CPUI_FLOAT_ADD] = OpBehaviorFloatAdd(trans)
        inst[OpCode.CPUI_FLOAT_DIV] = OpBehaviorFloatDiv(trans)
        inst[OpCode.CPUI_FLOAT_MULT] = OpBehaviorFloatMult(trans)
        inst[OpCode.CPUI_FLOAT_SUB] = OpBehaviorFloatSub(trans)
        inst[OpCode.CPUI_FLOAT_NEG] = OpBehaviorFloatNeg(trans)
        inst[OpCode.CPUI_FLOAT_ABS] = OpBehaviorFloatAbs(trans)
        inst[OpCode.CPUI_FLOAT_SQRT] = OpBehaviorFloatSqrt(trans)
        inst[OpCode.CPUI_FLOAT_INT2FLOAT] = OpBehaviorFloatInt2Float(trans)
        inst[OpCode.CPUI_FLOAT_FLOAT2FLOAT] = OpBehaviorFloatFloat2Float(trans)
        inst[OpCode.CPUI_FLOAT_TRUNC] = OpBehaviorFloatTrunc(trans)
        inst[OpCode.CPUI_FLOAT_CEIL] = OpBehaviorFloatCeil(trans)
        inst[OpCode.CPUI_FLOAT_FLOOR] = OpBehaviorFloatFloor(trans)
        inst[OpCode.CPUI_FLOAT_ROUND] = OpBehaviorFloatRound(trans)
        inst[OpCode.CPUI_MULTIEQUAL] = OpBehavior(OpCode.CPUI_MULTIEQUAL, False, True)
        inst[OpCode.CPUI_INDIRECT] = OpBehavior(OpCode.CPUI_INDIRECT, False, True)
        inst[OpCode.CPUI_PIECE] = OpBehaviorPiece()
        inst[OpCode.CPUI_SUBPIECE] = OpBehaviorSubpiece()
        inst[OpCode.CPUI_CAST] = OpBehavior(OpCode.CPUI_CAST, False, True)
        inst[OpCode.CPUI_PTRADD] = OpBehaviorPtradd()
        inst[OpCode.CPUI_PTRSUB] = OpBehaviorPtrsub()
        inst[OpCode.CPUI_SEGMENTOP] = OpBehavior(OpCode.CPUI_SEGMENTOP, False, True)
        inst[OpCode.CPUI_CPOOLREF] = OpBehavior(OpCode.CPUI_CPOOLREF, False, True)
        inst[OpCode.CPUI_NEW] = OpBehavior(OpCode.CPUI_NEW, False, True)
        inst[OpCode.CPUI_INSERT] = OpBehavior(OpCode.CPUI_INSERT, False)
        inst[OpCode.CPUI_EXTRACT] = OpBehavior(OpCode.CPUI_EXTRACT, False)
        inst[OpCode.CPUI_POPCOUNT] = OpBehaviorPopcount()
        inst[OpCode.CPUI_LZCOUNT] = OpBehaviorLzcount()
        return inst


# =========================================================================
# Concrete OpBehavior subclasses (integer operations)
# =========================================================================

class OpBehaviorCopy(OpBehavior):
    def __init__(self):
        super().__init__(OpCode.CPUI_COPY, True)

    def evaluateUnary(self, sizeout, sizein, in1):
        return in1

    def recoverInputUnary(self, sizeout, out, sizein):
        return out


class OpBehaviorEqual(OpBehavior):
    def __init__(self):
        super().__init__(OpCode.CPUI_INT_EQUAL, False)

    def evaluateBinary(self, sizeout, sizein, in1, in2):
        return 1 if in1 == in2 else 0


class OpBehaviorNotEqual(OpBehavior):
    def __init__(self):
        super().__init__(OpCode.CPUI_INT_NOTEQUAL, False)

    def evaluateBinary(self, sizeout, sizein, in1, in2):
        return 1 if in1 != in2 else 0


class OpBehaviorIntSless(OpBehavior):
    def __init__(self):
        super().__init__(OpCode.CPUI_INT_SLESS, False)

    def evaluateBinary(self, sizeout, sizein, in1, in2):
        if sizein <= 0:
            return 0
        mask = 0x80 << (8 * (sizein - 1))
        bit1 = in1 & mask
        bit2 = in2 & mask
        if bit1 != bit2:
            return 1 if bit1 != 0 else 0
        return 1 if in1 < in2 else 0


class OpBehaviorIntSlessEqual(OpBehavior):
    def __init__(self):
        super().__init__(OpCode.CPUI_INT_SLESSEQUAL, False)

    def evaluateBinary(self, sizeout, sizein, in1, in2):
        if sizein <= 0:
            return 0
        mask = 0x80 << (8 * (sizein - 1))
        bit1 = in1 & mask
        bit2 = in2 & mask
        if bit1 != bit2:
            return 1 if bit1 != 0 else 0
        return 1 if in1 <= in2 else 0


class OpBehaviorIntLess(OpBehavior):
    def __init__(self):
        super().__init__(OpCode.CPUI_INT_LESS, False)

    def evaluateBinary(self, sizeout, sizein, in1, in2):
        return 1 if in1 < in2 else 0


class OpBehaviorIntLessEqual(OpBehavior):
    def __init__(self):
        super().__init__(OpCode.CPUI_INT_LESSEQUAL, False)

    def evaluateBinary(self, sizeout, sizein, in1, in2):
        return 1 if in1 <= in2 else 0


class OpBehaviorIntZext(OpBehavior):
    def __init__(self):
        super().__init__(OpCode.CPUI_INT_ZEXT, True)

    def evaluateUnary(self, sizeout, sizein, in1):
        return in1

    def recoverInputUnary(self, sizeout, out, sizein):
        mask = calc_mask(sizein)
        if (mask & out) != out:
            raise EvaluationError("Output is not in range of zext operation")
        return out


class OpBehaviorIntSext(OpBehavior):
    def __init__(self):
        super().__init__(OpCode.CPUI_INT_SEXT, True)

    def evaluateUnary(self, sizeout, sizein, in1):
        mask_in = calc_mask(sizein)
        in1 &= mask_in
        if signbit_negative(in1, sizein):
            mask_out = calc_mask(sizeout)
            in1 |= (mask_out ^ mask_in)
        return in1 & calc_mask(sizeout)

    def recoverInputUnary(self, sizeout, out, sizein):
        masklong = calc_mask(sizeout)
        maskshort = calc_mask(sizein)
        if (out & (maskshort ^ (maskshort >> 1))) == 0:
            if (out & maskshort) != out:
                raise EvaluationError("Output is not in range of sext operation")
        else:
            if (out & (masklong ^ maskshort)) != (masklong ^ maskshort):
                raise EvaluationError("Output is not in range of sext operation")
        return out & maskshort


class OpBehaviorIntAdd(OpBehavior):
    def __init__(self):
        super().__init__(OpCode.CPUI_INT_ADD, False)

    def evaluateBinary(self, sizeout, sizein, in1, in2):
        return (in1 + in2) & calc_mask(sizeout)

    def recoverInputBinary(self, slot, sizeout, out, sizein, inp):
        return (out - inp) & calc_mask(sizeout)


class OpBehaviorIntSub(OpBehavior):
    def __init__(self):
        super().__init__(OpCode.CPUI_INT_SUB, False)

    def evaluateBinary(self, sizeout, sizein, in1, in2):
        return (in1 - in2) & calc_mask(sizeout)

    def recoverInputBinary(self, slot, sizeout, out, sizein, inp):
        if slot == 0:
            return (out + inp) & calc_mask(sizeout)
        return (inp - out) & calc_mask(sizeout)


class OpBehaviorIntCarry(OpBehavior):
    def __init__(self):
        super().__init__(OpCode.CPUI_INT_CARRY, False)

    def evaluateBinary(self, sizeout, sizein, in1, in2):
        mask = calc_mask(sizein)
        return 1 if in1 > ((in1 + in2) & mask) else 0


class OpBehaviorIntScarry(OpBehavior):
    def __init__(self):
        super().__init__(OpCode.CPUI_INT_SCARRY, False)

    def evaluateBinary(self, sizeout, sizein, in1, in2):
        res = in1 + in2
        shift = sizein * 8 - 1
        a = (in1 >> shift) & 1
        b = (in2 >> shift) & 1
        r = (res >> shift) & 1
        r ^= a
        a ^= b
        a ^= 1
        r &= a
        return r


class OpBehaviorIntSborrow(OpBehavior):
    def __init__(self):
        super().__init__(OpCode.CPUI_INT_SBORROW, False)

    def evaluateBinary(self, sizeout, sizein, in1, in2):
        res = in1 - in2
        shift = sizein * 8 - 1
        a = (in1 >> shift) & 1
        b = (in2 >> shift) & 1
        r = (res >> shift) & 1
        a ^= r
        r ^= b
        r ^= 1
        a &= r
        return a


class OpBehaviorInt2Comp(OpBehavior):
    def __init__(self):
        super().__init__(OpCode.CPUI_INT_2COMP, True)

    def evaluateUnary(self, sizeout, sizein, in1):
        return (~(in1 - 1)) & calc_mask(sizein)

    def recoverInputUnary(self, sizeout, out, sizein):
        mask = calc_mask(sizein)
        return ((~out) + 1) & mask


class OpBehaviorIntNegate(OpBehavior):
    def __init__(self):
        super().__init__(OpCode.CPUI_INT_NEGATE, True)

    def evaluateUnary(self, sizeout, sizein, in1):
        return (~in1) & calc_mask(sizein)

    def recoverInputUnary(self, sizeout, out, sizein):
        return (~out) & calc_mask(sizein)


class OpBehaviorIntXor(OpBehavior):
    def __init__(self):
        super().__init__(OpCode.CPUI_INT_XOR, False)

    def evaluateBinary(self, sizeout, sizein, in1, in2):
        return in1 ^ in2


class OpBehaviorIntAnd(OpBehavior):
    def __init__(self):
        super().__init__(OpCode.CPUI_INT_AND, False)

    def evaluateBinary(self, sizeout, sizein, in1, in2):
        return in1 & in2


class OpBehaviorIntOr(OpBehavior):
    def __init__(self):
        super().__init__(OpCode.CPUI_INT_OR, False)

    def evaluateBinary(self, sizeout, sizein, in1, in2):
        return in1 | in2


class OpBehaviorIntLeft(OpBehavior):
    def __init__(self):
        super().__init__(OpCode.CPUI_INT_LEFT, False)

    def evaluateBinary(self, sizeout, sizein, in1, in2):
        mask = calc_mask(sizeout)
        sa = int(in2)
        if sa >= sizeout * 8:
            return 0
        return (in1 << sa) & mask

    def recoverInputBinary(self, slot, sizeout, out, sizein, inp):
        sa = int(inp)
        if slot != 0 or sa >= sizeout * 8:
            return super().recoverInputBinary(slot, sizeout, out, sizein, inp)
        if ((out << (8 * sizeout - sa)) & calc_mask(sizeout)) != 0:
            raise EvaluationError("Output is not in range of left shift operation")
        return out >> sa


class OpBehaviorIntRight(OpBehavior):
    def __init__(self):
        super().__init__(OpCode.CPUI_INT_RIGHT, False)

    def evaluateBinary(self, sizeout, sizein, in1, in2):
        sa = int(in2)
        if sa >= sizeout * 8:
            return 0
        return (in1 & calc_mask(sizeout)) >> sa

    def recoverInputBinary(self, slot, sizeout, out, sizein, inp):
        sa = int(inp)
        if slot != 0 or sa >= sizeout * 8:
            return super().recoverInputBinary(slot, sizeout, out, sizein, inp)
        if (out >> (8 * sizein - sa)) != 0:
            raise EvaluationError("Output is not in range of right shift operation")
        return out << sa


class OpBehaviorIntSright(OpBehavior):
    def __init__(self):
        super().__init__(OpCode.CPUI_INT_SRIGHT, False)

    def evaluateBinary(self, sizeout, sizein, in1, in2):
        sa = int(in2)
        if sa >= sizeout * 8:
            return calc_mask(sizeout) if signbit_negative(in1, sizein) else 0
        if signbit_negative(in1, sizein):
            res = in1 >> sa
            mask = calc_mask(sizein)
            mask = (mask >> sa) ^ mask
            res |= mask
            return res
        return in1 >> sa

    def recoverInputBinary(self, slot, sizeout, out, sizein, inp):
        sa = int(inp)
        if slot != 0 or sa >= sizeout * 8:
            return super().recoverInputBinary(slot, sizeout, out, sizein, inp)
        testval = out >> (sizein * 8 - sa - 1)
        count = 0
        for _ in range(sa + 1):
            if (testval & 1) != 0:
                count += 1
            testval >>= 1
        if count != sa + 1:
            raise EvaluationError("Output is not in range of right shift operation")
        return out << sa


class OpBehaviorIntMult(OpBehavior):
    def __init__(self):
        super().__init__(OpCode.CPUI_INT_MULT, False)

    def evaluateBinary(self, sizeout, sizein, in1, in2):
        return (in1 * in2) & calc_mask(sizeout)


class OpBehaviorIntDiv(OpBehavior):
    def __init__(self):
        super().__init__(OpCode.CPUI_INT_DIV, False)

    def evaluateBinary(self, sizeout, sizein, in1, in2):
        if in2 == 0:
            raise EvaluationError("Divide by 0")
        return in1 // in2


class OpBehaviorIntSdiv(OpBehavior):
    def __init__(self):
        super().__init__(OpCode.CPUI_INT_SDIV, False)

    def evaluateBinary(self, sizeout, sizein, in1, in2):
        s2 = to_signed(in2, sizein)
        if s2 == 0:
            raise EvaluationError("Divide by 0")
        s1 = to_signed(in1, sizein)
        # Python integer division truncates towards negative infinity; C++ truncates towards zero
        import math
        result = int(math.trunc(s1 / s2))
        return to_unsigned(result, sizeout)


class OpBehaviorIntRem(OpBehavior):
    def __init__(self):
        super().__init__(OpCode.CPUI_INT_REM, False)

    def evaluateBinary(self, sizeout, sizein, in1, in2):
        if in2 == 0:
            raise EvaluationError("Remainder by 0")
        return in1 % in2


class OpBehaviorIntSrem(OpBehavior):
    def __init__(self):
        super().__init__(OpCode.CPUI_INT_SREM, False)

    def evaluateBinary(self, sizeout, sizein, in1, in2):
        s2 = to_signed(in2, sizein)
        if s2 == 0:
            raise EvaluationError("Remainder by 0")
        s1 = to_signed(in1, sizein)
        import math
        result = s1 - int(math.trunc(s1 / s2)) * s2
        return to_unsigned(result, sizeout)


# =========================================================================
# Boolean operations
# =========================================================================

class OpBehaviorBoolNegate(OpBehavior):
    def __init__(self):
        super().__init__(OpCode.CPUI_BOOL_NEGATE, True)

    def evaluateUnary(self, sizeout, sizein, in1):
        return in1 ^ 1


class OpBehaviorBoolXor(OpBehavior):
    def __init__(self):
        super().__init__(OpCode.CPUI_BOOL_XOR, False)

    def evaluateBinary(self, sizeout, sizein, in1, in2):
        return in1 ^ in2


class OpBehaviorBoolAnd(OpBehavior):
    def __init__(self):
        super().__init__(OpCode.CPUI_BOOL_AND, False)

    def evaluateBinary(self, sizeout, sizein, in1, in2):
        return in1 & in2


class OpBehaviorBoolOr(OpBehavior):
    def __init__(self):
        super().__init__(OpCode.CPUI_BOOL_OR, False)

    def evaluateBinary(self, sizeout, sizein, in1, in2):
        return in1 | in2


# =========================================================================
# Floating-point operations (delegate to FloatFormat)
# =========================================================================

class _FloatOpBase(OpBehavior):
    """Helper base for float operations that need a Translate reference."""

    def __init__(self, opc: OpCode, isun: bool, trans: Optional[Translate]) -> None:
        super().__init__(opc, isun)
        self._translate: Optional[Translate] = trans

    def _getFormat(self, size: int):
        if self._translate is None:
            return None
        return self._translate.getFloatFormat(size)

    def _evaluate_with_binary_format(self, sizeout: int, sizein: int, in1: int, in2: int, opname: str) -> int:
        fmt = self._getFormat(sizein)
        if fmt is None:
            return super().evaluateBinary(sizeout, sizein, in1, in2)
        return getattr(fmt, opname)(in1, in2)

    def _evaluate_with_unary_format(self, sizeout: int, sizein: int, in1: int, opname: str) -> int:
        fmt = self._getFormat(sizein)
        if fmt is None:
            return super().evaluateUnary(sizeout, sizein, in1)
        return getattr(fmt, opname)(in1)


class OpBehaviorFloatEqual(_FloatOpBase):
    def __init__(self, trans):
        super().__init__(OpCode.CPUI_FLOAT_EQUAL, False, trans)

    def evaluateBinary(self, sizeout, sizein, in1, in2):
        return self._evaluate_with_binary_format(sizeout, sizein, in1, in2, "opEqual")


class OpBehaviorFloatNotEqual(_FloatOpBase):
    def __init__(self, trans):
        super().__init__(OpCode.CPUI_FLOAT_NOTEQUAL, False, trans)

    def evaluateBinary(self, sizeout, sizein, in1, in2):
        return self._evaluate_with_binary_format(sizeout, sizein, in1, in2, "opNotEqual")


class OpBehaviorFloatLess(_FloatOpBase):
    def __init__(self, trans):
        super().__init__(OpCode.CPUI_FLOAT_LESS, False, trans)

    def evaluateBinary(self, sizeout, sizein, in1, in2):
        return self._evaluate_with_binary_format(sizeout, sizein, in1, in2, "opLess")


class OpBehaviorFloatLessEqual(_FloatOpBase):
    def __init__(self, trans):
        super().__init__(OpCode.CPUI_FLOAT_LESSEQUAL, False, trans)

    def evaluateBinary(self, sizeout, sizein, in1, in2):
        return self._evaluate_with_binary_format(sizeout, sizein, in1, in2, "opLessEqual")


class OpBehaviorFloatNan(_FloatOpBase):
    def __init__(self, trans):
        super().__init__(OpCode.CPUI_FLOAT_NAN, True, trans)

    def evaluateUnary(self, sizeout, sizein, in1):
        return self._evaluate_with_unary_format(sizeout, sizein, in1, "opNan")


class OpBehaviorFloatAdd(_FloatOpBase):
    def __init__(self, trans):
        super().__init__(OpCode.CPUI_FLOAT_ADD, False, trans)

    def evaluateBinary(self, sizeout, sizein, in1, in2):
        return self._evaluate_with_binary_format(sizeout, sizein, in1, in2, "opAdd")


class OpBehaviorFloatDiv(_FloatOpBase):
    def __init__(self, trans):
        super().__init__(OpCode.CPUI_FLOAT_DIV, False, trans)

    def evaluateBinary(self, sizeout, sizein, in1, in2):
        return self._evaluate_with_binary_format(sizeout, sizein, in1, in2, "opDiv")


class OpBehaviorFloatMult(_FloatOpBase):
    def __init__(self, trans):
        super().__init__(OpCode.CPUI_FLOAT_MULT, False, trans)

    def evaluateBinary(self, sizeout, sizein, in1, in2):
        return self._evaluate_with_binary_format(sizeout, sizein, in1, in2, "opMult")


class OpBehaviorFloatSub(_FloatOpBase):
    def __init__(self, trans):
        super().__init__(OpCode.CPUI_FLOAT_SUB, False, trans)

    def evaluateBinary(self, sizeout, sizein, in1, in2):
        return self._evaluate_with_binary_format(sizeout, sizein, in1, in2, "opSub")


class OpBehaviorFloatNeg(_FloatOpBase):
    def __init__(self, trans):
        super().__init__(OpCode.CPUI_FLOAT_NEG, True, trans)

    def evaluateUnary(self, sizeout, sizein, in1):
        return self._evaluate_with_unary_format(sizeout, sizein, in1, "opNeg")


class OpBehaviorFloatAbs(_FloatOpBase):
    def __init__(self, trans):
        super().__init__(OpCode.CPUI_FLOAT_ABS, True, trans)

    def evaluateUnary(self, sizeout, sizein, in1):
        return self._evaluate_with_unary_format(sizeout, sizein, in1, "opAbs")


class OpBehaviorFloatSqrt(_FloatOpBase):
    def __init__(self, trans):
        super().__init__(OpCode.CPUI_FLOAT_SQRT, True, trans)

    def evaluateUnary(self, sizeout, sizein, in1):
        return self._evaluate_with_unary_format(sizeout, sizein, in1, "opSqrt")


class OpBehaviorFloatInt2Float(_FloatOpBase):
    def __init__(self, trans):
        super().__init__(OpCode.CPUI_FLOAT_INT2FLOAT, True, trans)

    def evaluateUnary(self, sizeout, sizein, in1):
        fmt = self._getFormat(sizeout)
        if fmt is None:
            return super().evaluateUnary(sizeout, sizein, in1)
        return fmt.opInt2Float(in1, sizein)


class OpBehaviorFloatFloat2Float(_FloatOpBase):
    def __init__(self, trans):
        super().__init__(OpCode.CPUI_FLOAT_FLOAT2FLOAT, True, trans)

    def evaluateUnary(self, sizeout, sizein, in1):
        fmt_in = self._getFormat(sizein)
        fmt_out = self._getFormat(sizeout)
        if fmt_out is None or fmt_in is None:
            return super().evaluateUnary(sizeout, sizein, in1)
        return fmt_in.opFloat2Float(in1, fmt_out)


class OpBehaviorFloatTrunc(_FloatOpBase):
    def __init__(self, trans):
        super().__init__(OpCode.CPUI_FLOAT_TRUNC, True, trans)

    def evaluateUnary(self, sizeout, sizein, in1):
        fmt = self._getFormat(sizein)
        if fmt is None:
            return super().evaluateUnary(sizeout, sizein, in1)
        return fmt.opTrunc(in1, sizeout)


class OpBehaviorFloatCeil(_FloatOpBase):
    def __init__(self, trans):
        super().__init__(OpCode.CPUI_FLOAT_CEIL, True, trans)

    def evaluateUnary(self, sizeout, sizein, in1):
        return self._evaluate_with_unary_format(sizeout, sizein, in1, "opCeil")


class OpBehaviorFloatFloor(_FloatOpBase):
    def __init__(self, trans):
        super().__init__(OpCode.CPUI_FLOAT_FLOOR, True, trans)

    def evaluateUnary(self, sizeout, sizein, in1):
        return self._evaluate_with_unary_format(sizeout, sizein, in1, "opFloor")


class OpBehaviorFloatRound(_FloatOpBase):
    def __init__(self, trans):
        super().__init__(OpCode.CPUI_FLOAT_ROUND, True, trans)

    def evaluateUnary(self, sizeout, sizein, in1):
        return self._evaluate_with_unary_format(sizeout, sizein, in1, "opRound")


# =========================================================================
# Composite / special operations
# =========================================================================

class OpBehaviorPiece(OpBehavior):
    def __init__(self):
        super().__init__(OpCode.CPUI_PIECE, False)

    def evaluateBinary(self, sizeout, sizein, in1, in2):
        return (in1 << ((sizeout - sizein) * 8)) | in2


class OpBehaviorSubpiece(OpBehavior):
    def __init__(self):
        super().__init__(OpCode.CPUI_SUBPIECE, False)

    def evaluateBinary(self, sizeout, sizein, in1, in2):
        # in2 is the byte offset to truncate from
        val = in1 >> (int(in2) * 8)
        return val & calc_mask(sizeout)


class OpBehaviorPtradd(OpBehavior):
    def __init__(self):
        super().__init__(OpCode.CPUI_PTRADD, False)

    def evaluateTernary(self, sizeout, sizein, in1, in2, in3):
        return (in1 + in2 * in3) & calc_mask(sizeout)


class OpBehaviorPtrsub(OpBehavior):
    def __init__(self):
        super().__init__(OpCode.CPUI_PTRSUB, False)

    def evaluateBinary(self, sizeout, sizein, in1, in2):
        return (in1 + in2) & calc_mask(sizeout)


class OpBehaviorPopcount(OpBehavior):
    def __init__(self):
        super().__init__(OpCode.CPUI_POPCOUNT, True)

    def evaluateUnary(self, sizeout, sizein, in1):
        return popcount(in1)


class OpBehaviorLzcount(OpBehavior):
    def __init__(self):
        super().__init__(OpCode.CPUI_LZCOUNT, True)

    def evaluateUnary(self, sizeout, sizein, in1):
        return to_unsigned(count_leading_zeros(in1) - 8 * (8 - sizein), 8)
