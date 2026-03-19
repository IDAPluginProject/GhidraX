"""Tests for ghidra.types.cast -- IntPromotionCode, CastStrategy, CastStrategyC, CastStrategyJava."""
from __future__ import annotations

from ghidra.types.cast import (
    IntPromotionCode, CastStrategy, CastStrategyC, CastStrategyJava,
)
from ghidra.types.datatype import (
    Datatype, TypeFactory,
    TYPE_VOID, TYPE_UNKNOWN, TYPE_INT, TYPE_UINT, TYPE_BOOL, TYPE_FLOAT,
    TYPE_PTR, TYPE_STRUCT,
)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

class _MockType:
    def __init__(self, size=4, meta=TYPE_INT):
        self._size = size
        self._meta = meta

    def getSize(self):
        return self._size

    def getMetatype(self):
        return self._meta


class _MockVarnode:
    def __init__(self, size=4, const=False, written=False, tp=None, offset=0, explicit=False):
        self._size = size
        self._const = const
        self._written = written
        self._tp = tp
        self._def = None
        self._offset = offset
        self._explicit = explicit

    def getSize(self):
        return self._size

    def isConstant(self):
        return self._const

    def isWritten(self):
        return self._written

    def getType(self):
        return self._tp

    def getDef(self):
        return self._def

    def getOffset(self):
        return self._offset

    def getHighTypeReadFacing(self, op=None):
        return self._tp

    def isExplicit(self):
        return self._explicit

    def loneDescend(self):
        return None


class _MockOp:
    def __init__(self, inputs=None, out=None, opc=None):
        self._inputs = inputs or []
        self._out = out
        self._opc = opc

    def getIn(self, i):
        if i < len(self._inputs):
            return self._inputs[i]
        return None

    def getOut(self):
        return self._out

    def numInput(self):
        return len(self._inputs)

    def code(self):
        return self._opc

    def getSlot(self, vn):
        for i, v in enumerate(self._inputs):
            if v is vn:
                return i
        return -1

    def getOpcode(self):
        return None


class _MockTypeFactory:
    def getSizeOfInt(self):
        return 4

    def getBase(self, size, meta):
        return _MockType(size, meta)


# ---------------------------------------------------------------------------
# IntPromotionCode
# ---------------------------------------------------------------------------

class TestIntPromotionCode:
    def test_values(self):
        assert IntPromotionCode.NO_PROMOTION == -1
        assert IntPromotionCode.UNKNOWN_PROMOTION == 0
        assert IntPromotionCode.UNSIGNED_EXTENSION == 1
        assert IntPromotionCode.SIGNED_EXTENSION == 2
        assert IntPromotionCode.EITHER_EXTENSION == 3


# ---------------------------------------------------------------------------
# CastStrategyC
# ---------------------------------------------------------------------------

class TestCastStrategyC:
    def _make(self):
        cs = CastStrategyC()
        cs.setTypeFactory(_MockTypeFactory())
        return cs

    def test_defaults(self):
        cs = CastStrategyC()
        assert cs.tlst is None
        assert cs.promoteSize == 4

    def test_set_type_factory(self):
        cs = self._make()
        assert cs.promoteSize == 4

    def test_local_extension_const_int(self):
        cs = self._make()
        # offset=0 => high-bit not set => EITHER_EXTENSION
        vn = _MockVarnode(size=2, const=True, tp=_MockType(2, TYPE_INT), offset=0)
        result = cs.localExtensionType(vn, None)
        assert result == int(IntPromotionCode.EITHER_EXTENSION)

    def test_local_extension_const_int_highbit(self):
        cs = self._make()
        # offset=0x8000 => high-bit set for 2-byte => SIGNED_EXTENSION
        vn = _MockVarnode(size=2, const=True, tp=_MockType(2, TYPE_INT), offset=0x8000)
        result = cs.localExtensionType(vn, None)
        assert result == int(IntPromotionCode.SIGNED_EXTENSION)

    def test_local_extension_const_uint(self):
        cs = self._make()
        # offset=0 => high-bit not set => EITHER_EXTENSION
        vn = _MockVarnode(size=2, const=True, tp=_MockType(2, TYPE_UINT), offset=0)
        result = cs.localExtensionType(vn, None)
        assert result == int(IntPromotionCode.EITHER_EXTENSION)

    def test_local_extension_const_uint_highbit(self):
        cs = self._make()
        # offset=0x8000 => high-bit set for 2-byte => UNSIGNED_EXTENSION
        vn = _MockVarnode(size=2, const=True, tp=_MockType(2, TYPE_UINT), offset=0x8000)
        result = cs.localExtensionType(vn, None)
        assert result == int(IntPromotionCode.UNSIGNED_EXTENSION)

    def test_local_extension_explicit_int(self):
        cs = self._make()
        # Explicit non-const varnode with TYPE_INT => SIGNED_EXTENSION
        vn = _MockVarnode(size=2, const=False, tp=_MockType(2, TYPE_INT), explicit=True)
        result = cs.localExtensionType(vn, None)
        assert result == int(IntPromotionCode.SIGNED_EXTENSION)

    def test_local_extension_explicit_bool(self):
        cs = self._make()
        # Explicit non-const varnode with TYPE_BOOL => UNSIGNED_EXTENSION
        vn = _MockVarnode(size=1, const=False, tp=_MockType(1, TYPE_BOOL), explicit=True)
        result = cs.localExtensionType(vn, None)
        assert result == int(IntPromotionCode.UNSIGNED_EXTENSION)

    def test_local_extension_non_written_non_explicit(self):
        cs = self._make()
        # Non-const, non-written, non-explicit => UNKNOWN_PROMOTION
        vn = _MockVarnode(size=2, const=False, tp=_MockType(2, TYPE_INT))
        result = cs.localExtensionType(vn, None)
        assert result == int(IntPromotionCode.UNKNOWN_PROMOTION)

    def test_local_extension_no_type(self):
        cs = self._make()
        vn = _MockVarnode(size=2, const=False, tp=None)
        result = cs.localExtensionType(vn, None)
        assert result == int(IntPromotionCode.UNKNOWN_PROMOTION)

    def test_int_promotion_large_vn(self):
        cs = self._make()
        vn = _MockVarnode(size=4, tp=_MockType(4, TYPE_INT))
        result = cs.intPromotionType(vn)
        assert result == int(IntPromotionCode.NO_PROMOTION)

    def test_int_promotion_small_const(self):
        cs = self._make()
        # offset=0x8000 => high-bit set => SIGNED_EXTENSION for TYPE_INT
        vn = _MockVarnode(size=2, const=True, tp=_MockType(2, TYPE_INT), offset=0x8000)
        result = cs.intPromotionType(vn)
        assert result == int(IntPromotionCode.SIGNED_EXTENSION)

    def test_int_promotion_small_const_zero(self):
        cs = self._make()
        # offset=0 => high-bit not set => EITHER_EXTENSION
        vn = _MockVarnode(size=2, const=True, tp=_MockType(2, TYPE_INT), offset=0)
        result = cs.intPromotionType(vn)
        assert result == int(IntPromotionCode.EITHER_EXTENSION)

    def test_check_int_promotion_for_compare(self):
        cs = self._make()
        vn = _MockVarnode(size=2, tp=_MockType(2, TYPE_INT))
        op = _MockOp([vn])
        assert cs.checkIntPromotionForCompare(op, 0) is True

    def test_check_int_promotion_for_compare_large(self):
        cs = self._make()
        vn = _MockVarnode(size=4, tp=_MockType(4, TYPE_INT))
        op = _MockOp([vn])
        assert cs.checkIntPromotionForCompare(op, 0) is False

    def test_check_int_promotion_for_extension(self):
        cs = self._make()
        vn = _MockVarnode(size=2, tp=_MockType(2, TYPE_INT))
        op = _MockOp([vn])
        assert cs.checkIntPromotionForExtension(op) is True

    def test_is_extension_cast_implied_no_readop(self):
        cs = self._make()
        outvn = _MockVarnode(size=4, tp=_MockType(4, TYPE_INT))
        op = _MockOp([_MockVarnode(size=2, tp=_MockType(2, TYPE_INT))], out=outvn)
        # No readOp => False (non-explicit output with no read context)
        assert cs.isExtensionCastImplied(op, None) is False

    def test_is_extension_cast_implied_explicit_output(self):
        cs = self._make()
        outvn = _MockVarnode(size=4, tp=_MockType(4, TYPE_INT), explicit=True)
        op = _MockOp([_MockVarnode(size=2, tp=_MockType(2, TYPE_INT))], out=outvn)
        from ghidra.core.opcodes import OpCode
        readOp = _MockOp([outvn, _MockVarnode(size=4, tp=_MockType(4, TYPE_INT), explicit=True)], opc=OpCode.CPUI_INT_ADD)
        assert cs.isExtensionCastImplied(op, readOp) is False

    def test_cast_standard_same_type(self):
        cs = self._make()
        t = _MockType(4, TYPE_INT)
        assert cs.castStandard(t, t, True, True) is None

    def test_cast_standard_different_size(self):
        cs = self._make()
        t1 = _MockType(4, TYPE_INT)
        t2 = _MockType(2, TYPE_INT)
        assert cs.castStandard(t1, t2, True, True) is t1

    def test_cast_standard_same_meta(self):
        cs = self._make()
        t1 = _MockType(4, TYPE_INT)
        t2 = _MockType(4, TYPE_INT)
        assert cs.castStandard(t1, t2, True, True) is None

    def test_cast_standard_int_uint(self):
        cs = self._make()
        t1 = _MockType(4, TYPE_INT)
        t2 = _MockType(4, TYPE_UINT)
        assert cs.castStandard(t1, t2, True, False) is t1
        assert cs.castStandard(t1, t2, False, False) is None

    def test_cast_standard_float(self):
        cs = self._make()
        t_float = _MockType(4, TYPE_FLOAT)
        t_int = _MockType(4, TYPE_INT)
        assert cs.castStandard(t_float, t_int, False, False) is t_float
        assert cs.castStandard(t_int, t_float, False, False) is t_int

    def test_cast_standard_bool(self):
        cs = self._make()
        t_bool = _MockType(1, TYPE_BOOL)
        t_int = _MockType(1, TYPE_INT)
        assert cs.castStandard(t_bool, t_int, False, False) is t_bool

    def test_cast_standard_void_from(self):
        cs = self._make()
        t_void = _MockType(0, TYPE_VOID)
        t_int = _MockType(4, TYPE_INT)
        # Coming from void => cast needed to reqtype
        result = cs.castStandard(t_int, t_void, False, False)
        assert result is t_int

    def test_cast_standard_void_to(self):
        cs = self._make()
        t_void = _MockType(4, TYPE_VOID)
        t_int = _MockType(4, TYPE_INT)
        # Casting to void => no cast needed (after unwrap)
        result = cs.castStandard(t_void, t_int, False, False)
        assert result is None

    def test_is_subpiece_cast_ptr(self):
        cs = self._make()
        t_ptr = _MockType(4, TYPE_PTR)
        t_int = _MockType(4, TYPE_INT)
        assert cs.isSubpieceCast(t_ptr, t_int, 0) is True
        assert cs.isSubpieceCast(t_int, t_ptr, 0) is True

    def test_is_subpiece_cast_float(self):
        cs = self._make()
        t_float = _MockType(4, TYPE_FLOAT)
        t_int = _MockType(4, TYPE_INT)
        assert cs.isSubpieceCast(t_float, t_int, 0) is True

    def test_is_subpiece_cast_int_int_offset0(self):
        cs = self._make()
        t_small = _MockType(2, TYPE_INT)
        t_big = _MockType(4, TYPE_INT)
        assert cs.isSubpieceCast(t_small, t_big, 0) is True
        assert cs.isSubpieceCast(t_big, t_small, 0) is True  # Both INT, offset 0

    def test_is_subpiece_cast_nonzero_offset(self):
        cs = self._make()
        t_small = _MockType(2, TYPE_INT)
        t_big = _MockType(4, TYPE_INT)
        assert cs.isSubpieceCast(t_small, t_big, 2) is False  # Non-zero offset

    def test_is_sext_cast(self):
        cs = self._make()
        t_out = _MockType(4, TYPE_INT)
        t_in = _MockType(2, TYPE_INT)
        assert cs.isSextCast(t_out, t_in) is True

    def test_is_zext_cast(self):
        cs = self._make()
        t_out = _MockType(4, TYPE_UINT)
        t_in = _MockType(2, TYPE_UINT)
        assert cs.isZextCast(t_out, t_in) is True

    def test_is_sext_cast_struct(self):
        cs = self._make()
        t_out = _MockType(4, TYPE_INT)
        t_in = _MockType(2, TYPE_STRUCT)
        assert cs.isSextCast(t_out, t_in) is False

    def test_cares_about_char(self):
        cs = self._make()
        vn = _MockVarnode(1)
        assert cs.caresAboutCharRepresentation(vn, None) is False


# ---------------------------------------------------------------------------
# CastStrategyJava
# ---------------------------------------------------------------------------

class TestMarkExplicitUnsigned:
    """Tests for CastStrategy.markExplicitUnsigned."""

    def _make(self):
        cs = CastStrategyC()
        cs.setTypeFactory(_MockTypeFactory())
        return cs

    def test_non_inherits_sign_returns_false(self):
        cs = self._make()
        # Op whose opcode doesn't inherit sign
        class _NoInheritOpc:
            def inheritsSign(self): return False
            def inheritsSignFirstParamOnly(self): return False
        class _Op(_MockOp):
            def getOpcode(self): return _NoInheritOpc()
        vn = _MockVarnode(size=4, const=True, tp=_MockType(4, TYPE_UINT))
        op = _Op([vn], out=None)
        assert cs.markExplicitUnsigned(op, 0) is False

    def test_non_constant_returns_false(self):
        cs = self._make()
        class _InheritOpc:
            def inheritsSign(self): return True
            def inheritsSignFirstParamOnly(self): return False
        class _Op(_MockOp):
            def getOpcode(self): return _InheritOpc()
        vn = _MockVarnode(size=4, const=False, tp=_MockType(4, TYPE_UINT))
        op = _Op([vn], out=None)
        assert cs.markExplicitUnsigned(op, 0) is False

    def test_signed_meta_returns_false(self):
        cs = self._make()
        class _InheritOpc:
            def inheritsSign(self): return True
            def inheritsSignFirstParamOnly(self): return False
        class _Op(_MockOp):
            def getOpcode(self): return _InheritOpc()
        vn = _MockVarnode(size=4, const=True, tp=_MockType(4, TYPE_INT))
        op = _Op([vn, _MockVarnode(size=4, tp=_MockType(4, TYPE_INT))], out=None)
        assert cs.markExplicitUnsigned(op, 0) is False

    def test_both_unsigned_returns_false(self):
        cs = self._make()
        class _InheritOpc:
            def inheritsSign(self): return True
            def inheritsSignFirstParamOnly(self): return False
        class _Op(_MockOp):
            def getOpcode(self): return _InheritOpc()
        vn0 = _MockVarnode(size=4, const=True, tp=_MockType(4, TYPE_UINT))
        vn1 = _MockVarnode(size=4, const=False, tp=_MockType(4, TYPE_UINT))
        op = _Op([vn0, vn1], out=None)
        # Other side is also UINT => other side forces unsigned => False
        assert cs.markExplicitUnsigned(op, 0) is False

    def test_uint_const_with_signed_other_returns_true(self):
        cs = self._make()
        marked = []
        class _InheritOpc:
            def inheritsSign(self): return True
            def inheritsSignFirstParamOnly(self): return False
        class _Op(_MockOp):
            def getOpcode(self): return _InheritOpc()
        class _Vn(_MockVarnode):
            def setUnsignedPrint(self):
                marked.append(True)
        vn0 = _Vn(size=4, const=True, tp=_MockType(4, TYPE_UINT))
        vn1 = _MockVarnode(size=4, const=False, tp=_MockType(4, TYPE_INT))
        op = _Op([vn0, vn1], out=None)
        assert cs.markExplicitUnsigned(op, 0) is True
        assert len(marked) == 1


class TestMarkExplicitLongSize:
    """Tests for CastStrategy.markExplicitLongSize."""

    def _make(self):
        cs = CastStrategyC()
        cs.setTypeFactory(_MockTypeFactory())
        return cs

    def test_non_shift_returns_false(self):
        cs = self._make()
        class _NoShiftOpc:
            def isShiftOp(self): return False
        class _Op(_MockOp):
            def getOpcode(self): return _NoShiftOpc()
        vn = _MockVarnode(size=8, const=True, tp=_MockType(8, TYPE_UINT), offset=0xFF)
        op = _Op([vn])
        assert cs.markExplicitLongSize(op, 0) is False

    def test_slot_1_returns_false(self):
        cs = self._make()
        class _ShiftOpc:
            def isShiftOp(self): return True
        class _Op(_MockOp):
            def getOpcode(self): return _ShiftOpc()
        vn = _MockVarnode(size=8, const=True, tp=_MockType(8, TYPE_UINT), offset=0xFF)
        op = _Op([_MockVarnode(), vn])
        assert cs.markExplicitLongSize(op, 1) is False

    def test_small_const_returns_false(self):
        cs = self._make()
        class _ShiftOpc:
            def isShiftOp(self): return True
        class _Op(_MockOp):
            def getOpcode(self): return _ShiftOpc()
        # Size 4 <= promoteSize(4) => False
        vn = _MockVarnode(size=4, const=True, tp=_MockType(4, TYPE_UINT), offset=0xFF)
        op = _Op([vn])
        assert cs.markExplicitLongSize(op, 0) is False

    def test_large_value_returns_false(self):
        cs = self._make()
        class _ShiftOpc:
            def isShiftOp(self): return True
        class _Op(_MockOp):
            def getOpcode(self): return _ShiftOpc()
        # 8-byte with value that fills more than 32 bits => naturally a long
        vn = _MockVarnode(size=8, const=True, tp=_MockType(8, TYPE_UINT), offset=0x1_0000_0000)
        op = _Op([vn])
        assert cs.markExplicitLongSize(op, 0) is False

    def test_small_value_marks_long(self):
        cs = self._make()
        marked = []
        class _ShiftOpc:
            def isShiftOp(self): return True
        class _Op(_MockOp):
            def getOpcode(self): return _ShiftOpc()
        class _Vn(_MockVarnode):
            def setLongPrint(self):
                marked.append(True)
        # 8-byte constant with small value that fits in 32 bits
        vn = _Vn(size=8, const=True, tp=_MockType(8, TYPE_UINT), offset=0x7FFF)
        op = _Op([vn])
        assert cs.markExplicitLongSize(op, 0) is True
        assert len(marked) == 1


class TestIntPromotionTypeOpcodeSpecific:
    """Tests for opcode-specific intPromotionType logic."""

    def _make(self):
        cs = CastStrategyC()
        cs.setTypeFactory(_MockTypeFactory())
        return cs

    def _written_vn(self, size, tp, def_opc, def_inputs):
        """Create a written varnode with a def op."""
        vn = _MockVarnode(size=size, written=True, tp=tp)
        vn._def = _MockOp(inputs=def_inputs, opc=def_opc)
        return vn

    def test_explicit_small_no_promotion(self):
        cs = self._make()
        vn = _MockVarnode(size=2, tp=_MockType(2, TYPE_INT), explicit=True)
        assert cs.intPromotionType(vn) == int(IntPromotionCode.NO_PROMOTION)

    def test_int_and_unsigned_input(self):
        cs = self._make()
        from ghidra.core.opcodes import OpCode
        # INT_AND with input[1] being UINT constant with zero high-bit => UNSIGNED
        in0 = _MockVarnode(size=2, tp=_MockType(2, TYPE_INT), explicit=True)
        in1 = _MockVarnode(size=2, const=True, tp=_MockType(2, TYPE_UINT), offset=0x00FF)
        vn = self._written_vn(2, _MockType(2, TYPE_UINT), OpCode.CPUI_INT_AND, [in0, in1])
        result = cs.intPromotionType(vn)
        assert result == int(IntPromotionCode.UNSIGNED_EXTENSION)

    def test_int_right_unsigned_input(self):
        cs = self._make()
        from ghidra.core.opcodes import OpCode
        in0 = _MockVarnode(size=2, const=True, tp=_MockType(2, TYPE_UINT), offset=0x00FF)
        in1 = _MockVarnode(size=2, const=True, tp=_MockType(2, TYPE_INT), offset=1)
        vn = self._written_vn(2, _MockType(2, TYPE_UINT), OpCode.CPUI_INT_RIGHT, [in0, in1])
        result = cs.intPromotionType(vn)
        # input has EITHER_EXTENSION (const with zero high-bit), includes UNSIGNED
        assert (result & int(IntPromotionCode.UNSIGNED_EXTENSION)) != 0

    def test_int_sright_signed_input(self):
        cs = self._make()
        from ghidra.core.opcodes import OpCode
        in0 = _MockVarnode(size=2, const=True, tp=_MockType(2, TYPE_INT), offset=0x8000)
        in1 = _MockVarnode(size=2, const=True, tp=_MockType(2, TYPE_INT), offset=1)
        vn = self._written_vn(2, _MockType(2, TYPE_INT), OpCode.CPUI_INT_SRIGHT, [in0, in1])
        result = cs.intPromotionType(vn)
        assert result == int(IntPromotionCode.SIGNED_EXTENSION)

    def test_int_xor_both_unsigned(self):
        cs = self._make()
        from ghidra.core.opcodes import OpCode
        in0 = _MockVarnode(size=2, const=True, tp=_MockType(2, TYPE_UINT), offset=0x00FF)
        in1 = _MockVarnode(size=2, const=True, tp=_MockType(2, TYPE_UINT), offset=0x00FF)
        vn = self._written_vn(2, _MockType(2, TYPE_UINT), OpCode.CPUI_INT_XOR, [in0, in1])
        assert cs.intPromotionType(vn) == int(IntPromotionCode.UNSIGNED_EXTENSION)

    def test_int_negate_signed(self):
        cs = self._make()
        from ghidra.core.opcodes import OpCode
        in0 = _MockVarnode(size=2, const=True, tp=_MockType(2, TYPE_INT), offset=0x8000)
        vn = self._written_vn(2, _MockType(2, TYPE_INT), OpCode.CPUI_INT_NEGATE, [in0])
        assert cs.intPromotionType(vn) == int(IntPromotionCode.SIGNED_EXTENSION)

    def test_int_add_unknown(self):
        cs = self._make()
        from ghidra.core.opcodes import OpCode
        in0 = _MockVarnode(size=2, tp=_MockType(2, TYPE_INT), explicit=True)
        in1 = _MockVarnode(size=2, tp=_MockType(2, TYPE_INT), explicit=True)
        vn = self._written_vn(2, _MockType(2, TYPE_INT), OpCode.CPUI_INT_ADD, [in0, in1])
        assert cs.intPromotionType(vn) == int(IntPromotionCode.UNKNOWN_PROMOTION)

    def test_unknown_opcode_no_promotion(self):
        cs = self._make()
        from ghidra.core.opcodes import OpCode
        in0 = _MockVarnode(size=2, tp=_MockType(2, TYPE_INT), explicit=True)
        vn = self._written_vn(2, _MockType(2, TYPE_INT), OpCode.CPUI_COPY, [in0])
        assert cs.intPromotionType(vn) == int(IntPromotionCode.NO_PROMOTION)


class TestCheckPromotionDeepened:
    """Tests for deepened checkIntPromotionForCompare and checkIntPromotionForExtension."""

    def _make(self):
        cs = CastStrategyC()
        cs.setTypeFactory(_MockTypeFactory())
        return cs

    def test_compare_both_same_extension_no_cast(self):
        cs = self._make()
        # Both sides have EITHER_EXTENSION (small const with zero high bit)
        vn0 = _MockVarnode(size=2, const=True, tp=_MockType(2, TYPE_INT), offset=0)
        vn1 = _MockVarnode(size=2, const=True, tp=_MockType(2, TYPE_INT), offset=0)
        op = _MockOp([vn0, vn1])
        assert cs.checkIntPromotionForCompare(op, 0) is False

    def test_compare_unknown_needs_cast(self):
        cs = self._make()
        # Slot 0 is non-const, non-written, non-explicit => UNKNOWN => needs cast
        vn0 = _MockVarnode(size=2, tp=_MockType(2, TYPE_INT))
        vn1 = _MockVarnode(size=2, const=True, tp=_MockType(2, TYPE_INT), offset=0)
        op = _MockOp([vn0, vn1])
        assert cs.checkIntPromotionForCompare(op, 0) is True

    def test_extension_zext_matches_unsigned(self):
        cs = self._make()
        from ghidra.core.opcodes import OpCode
        # UINT constant with zero high-bit => EITHER_EXTENSION, includes UNSIGNED
        # ZEXT matches UNSIGNED => no cast needed
        vn = _MockVarnode(size=2, const=True, tp=_MockType(2, TYPE_UINT), offset=0x00FF)
        op = _MockOp([vn], opc=OpCode.CPUI_INT_ZEXT)
        assert cs.checkIntPromotionForExtension(op) is False

    def test_extension_sext_matches_signed(self):
        cs = self._make()
        from ghidra.core.opcodes import OpCode
        # INT constant with high-bit set => SIGNED_EXTENSION
        # SEXT matches SIGNED => no cast needed
        vn = _MockVarnode(size=2, const=True, tp=_MockType(2, TYPE_INT), offset=0x8000)
        op = _MockOp([vn], opc=OpCode.CPUI_INT_SEXT)
        assert cs.checkIntPromotionForExtension(op) is False

    def test_extension_zext_mismatch_signed(self):
        cs = self._make()
        from ghidra.core.opcodes import OpCode
        # INT constant with high-bit set => SIGNED_EXTENSION only
        # ZEXT doesn't match => needs cast
        vn = _MockVarnode(size=2, const=True, tp=_MockType(2, TYPE_INT), offset=0x8000)
        op = _MockOp([vn], opc=OpCode.CPUI_INT_ZEXT)
        assert cs.checkIntPromotionForExtension(op) is True


class TestIsExtensionCastImpliedDeepened:
    """Tests for deepened isExtensionCastImplied with readOp."""

    def _make(self):
        cs = CastStrategyC()
        cs.setTypeFactory(_MockTypeFactory())
        return cs

    def test_no_output_returns_false(self):
        cs = self._make()
        op = _MockOp([_MockVarnode()])
        assert cs.isExtensionCastImplied(op, None) is False

    def test_ptradd_readop_implied(self):
        cs = self._make()
        from ghidra.core.opcodes import OpCode
        outvn = _MockVarnode(size=4, tp=_MockType(4, TYPE_INT))
        op = _MockOp([_MockVarnode(size=2)], out=outvn)
        readOp = _MockOp([outvn], opc=OpCode.CPUI_PTRADD)
        assert cs.isExtensionCastImplied(op, readOp) is True

    def test_int_add_explicit_other_same_meta_implied(self):
        cs = self._make()
        from ghidra.core.opcodes import OpCode
        outvn = _MockVarnode(size=4, tp=_MockType(4, TYPE_INT))
        othervn = _MockVarnode(size=4, tp=_MockType(4, TYPE_INT), explicit=True)
        op = _MockOp([_MockVarnode(size=2)], out=outvn)
        readOp = _MockOp([outvn, othervn], opc=OpCode.CPUI_INT_ADD)
        assert cs.isExtensionCastImplied(op, readOp) is True

    def test_int_add_different_meta_not_implied(self):
        cs = self._make()
        from ghidra.core.opcodes import OpCode
        outvn = _MockVarnode(size=4, tp=_MockType(4, TYPE_INT))
        othervn = _MockVarnode(size=4, tp=_MockType(4, TYPE_UINT), explicit=True)
        op = _MockOp([_MockVarnode(size=2)], out=outvn)
        readOp = _MockOp([outvn, othervn], opc=OpCode.CPUI_INT_ADD)
        assert cs.isExtensionCastImplied(op, readOp) is False

    def test_unknown_readop_not_implied(self):
        cs = self._make()
        from ghidra.core.opcodes import OpCode
        outvn = _MockVarnode(size=4, tp=_MockType(4, TYPE_INT))
        op = _MockOp([_MockVarnode(size=2)], out=outvn)
        readOp = _MockOp([outvn], opc=OpCode.CPUI_COPY)
        assert cs.isExtensionCastImplied(op, readOp) is False


class TestCastStandardDeepened:
    """Tests for deeper castStandard logic (pointer unwrap, typedef, CODE)."""

    def _make(self):
        cs = CastStrategyC()
        cs.setTypeFactory(_MockTypeFactory())
        return cs

    def test_unknown_req_no_cast(self):
        cs = self._make()
        t_unk = _MockType(4, TYPE_UNKNOWN)
        t_int = _MockType(4, TYPE_INT)
        assert cs.castStandard(t_unk, t_int, True, True) is None

    def test_uint_from_bool_no_cast(self):
        cs = self._make()
        t_uint = _MockType(4, TYPE_UINT)
        t_bool = _MockType(4, TYPE_BOOL)
        # care_uint_int=True, BOOL is compatible with UINT
        assert cs.castStandard(t_uint, t_bool, True, True) is None

    def test_int_from_bool_no_cast(self):
        cs = self._make()
        t_int = _MockType(4, TYPE_INT)
        t_bool = _MockType(4, TYPE_BOOL)
        assert cs.castStandard(t_int, t_bool, True, True) is None

    def test_uint_not_care_int_from_unknown_no_cast(self):
        cs = self._make()
        t_uint = _MockType(4, TYPE_UINT)
        t_unk = _MockType(4, TYPE_UNKNOWN)
        assert cs.castStandard(t_uint, t_unk, False, False) is None

    def test_ptr_from_uint_no_care_ptr_uint(self):
        cs = self._make()
        t_uint = _MockType(4, TYPE_UINT)
        t_ptr = _MockType(4, TYPE_PTR)
        # req=UINT, cur=PTR, not care_ptr_uint => no cast
        assert cs.castStandard(t_uint, t_ptr, False, False) is None


class TestSubpieceCastEndian:
    """Tests for isSubpieceCastEndian."""

    def _make(self):
        cs = CastStrategyC()
        cs.setTypeFactory(_MockTypeFactory())
        return cs

    def test_little_endian_passthrough(self):
        cs = self._make()
        t_small = _MockType(2, TYPE_INT)
        t_big = _MockType(4, TYPE_INT)
        assert cs.isSubpieceCastEndian(t_small, t_big, 0, False) is True

    def test_big_endian_offset_adjustment(self):
        cs = self._make()
        t_small = _MockType(2, TYPE_INT)
        t_big = _MockType(4, TYPE_INT)
        # Big endian: offset 2 => tmpoff = 4-1-2 = 1 => non-zero => False
        assert cs.isSubpieceCastEndian(t_small, t_big, 2, True) is False

    def test_big_endian_offset_zero_adjusted(self):
        cs = self._make()
        t_small = _MockType(2, TYPE_INT)
        t_big = _MockType(4, TYPE_INT)
        # Big endian: offset 3 => tmpoff = 4-1-3 = 0 => True
        assert cs.isSubpieceCastEndian(t_small, t_big, 3, True) is True


class TestSextZextDeepened:
    """Tests for deepened isSextCast / isZextCast logic."""

    def _make(self):
        cs = CastStrategyC()
        cs.setTypeFactory(_MockTypeFactory())
        return cs

    def test_sext_output_float_false(self):
        cs = self._make()
        assert cs.isSextCast(_MockType(4, TYPE_FLOAT), _MockType(2, TYPE_INT)) is False

    def test_sext_input_uint_false(self):
        cs = self._make()
        # C isSextCast requires input to be INT or BOOL, not UINT
        assert cs.isSextCast(_MockType(4, TYPE_INT), _MockType(2, TYPE_UINT)) is False

    def test_sext_bool_input_true(self):
        cs = self._make()
        assert cs.isSextCast(_MockType(4, TYPE_INT), _MockType(1, TYPE_BOOL)) is True

    def test_zext_output_float_false(self):
        cs = self._make()
        assert cs.isZextCast(_MockType(4, TYPE_FLOAT), _MockType(2, TYPE_UINT)) is False

    def test_zext_input_int_false(self):
        cs = self._make()
        # C isZextCast requires input to be UINT or BOOL, not INT
        assert cs.isZextCast(_MockType(4, TYPE_UINT), _MockType(2, TYPE_INT)) is False

    def test_zext_bool_input_true(self):
        cs = self._make()
        assert cs.isZextCast(_MockType(4, TYPE_UINT), _MockType(1, TYPE_BOOL)) is True


class TestArithmeticOutputStandard:
    """Tests for deepened arithmeticOutputStandard."""

    def _make(self):
        cs = CastStrategyC()
        cs.setTypeFactory(_MockTypeFactory())
        return cs

    def test_bool_input_promoted_to_int(self):
        cs = self._make()
        vn0 = _MockVarnode(size=1, tp=_MockType(1, TYPE_BOOL))
        vn1 = _MockVarnode(size=4, tp=_MockType(4, TYPE_INT))
        op = _MockOp([vn0, vn1])
        result = cs.arithmeticOutputStandard(op)
        # Bool is promoted to INT; second input TYPE_INT should dominate
        assert result.getMetatype() == TYPE_INT

    def test_single_input(self):
        cs = self._make()
        vn0 = _MockVarnode(size=4, tp=_MockType(4, TYPE_UINT))
        op = _MockOp([vn0])
        result = cs.arithmeticOutputStandard(op)
        assert result.getMetatype() == TYPE_UINT


# ---------------------------------------------------------------------------
# CastStrategyJava
# ---------------------------------------------------------------------------

class TestCastStrategyJava:
    def _make(self):
        cs = CastStrategyJava()
        cs.setTypeFactory(_MockTypeFactory())
        return cs

    def test_ptr_ptr_no_cast(self):
        cs = self._make()
        t1 = _MockType(4, TYPE_PTR)
        t2 = _MockType(4, TYPE_PTR)
        assert cs.castStandard(t1, t2, True, True) is None

    def test_ptr_int_java_no_cast(self):
        cs = self._make()
        t_ptr = _MockType(4, TYPE_PTR)
        t_int = _MockType(4, TYPE_INT)
        # Java: any pointer type => no cast (JVM handles)
        result = cs.castStandard(t_ptr, t_int, False, True)
        assert result is None

    def test_void_no_cast(self):
        cs = self._make()
        t_void = _MockType(4, TYPE_VOID)
        t_int = _MockType(4, TYPE_INT)
        assert cs.castStandard(t_void, t_int, False, False) is None
        assert cs.castStandard(t_int, t_void, False, False) is None

    def test_different_size_cast(self):
        cs = self._make()
        t1 = _MockType(4, TYPE_INT)
        t2 = _MockType(2, TYPE_INT)
        assert cs.castStandard(t1, t2, False, False) is t1

    def test_unknown_no_cast(self):
        cs = self._make()
        t_unk = _MockType(4, TYPE_UNKNOWN)
        t_int = _MockType(4, TYPE_INT)
        assert cs.castStandard(t_unk, t_int, False, False) is None

    def test_uint_from_bool_no_cast(self):
        cs = self._make()
        assert cs.castStandard(_MockType(4, TYPE_UINT), _MockType(4, TYPE_BOOL), True, False) is None

    def test_int_uint_care_needs_cast(self):
        cs = self._make()
        t_int = _MockType(4, TYPE_INT)
        t_uint = _MockType(4, TYPE_UINT)
        assert cs.castStandard(t_int, t_uint, True, False) is t_int

    def test_java_zext_size_1_uint_true(self):
        cs = self._make()
        assert cs.isZextCast(_MockType(4, TYPE_INT), _MockType(1, TYPE_UINT)) is True

    def test_java_zext_size_2_short_no_charprint(self):
        cs = self._make()
        # size=2, not charPrint => False for Java
        assert cs.isZextCast(_MockType(4, TYPE_INT), _MockType(2, TYPE_UINT)) is False

    def test_java_zext_size_2_charprint(self):
        cs = self._make()
        class _CharType(_MockType):
            def isCharPrint(self): return True
        assert cs.isZextCast(_MockType(4, TYPE_INT), _CharType(2, TYPE_UINT)) is True

    def test_java_zext_size_1_int_byte_false(self):
        cs = self._make()
        # size=1, TYPE_INT => Java: cast is not zext for byte
        assert cs.isZextCast(_MockType(4, TYPE_INT), _MockType(1, TYPE_INT)) is False

    def test_java_zext_size_4_false(self):
        cs = self._make()
        # size >= 4 => False
        assert cs.isZextCast(_MockType(8, TYPE_INT), _MockType(4, TYPE_UINT)) is False
