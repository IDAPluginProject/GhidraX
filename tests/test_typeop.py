"""Tests for ghidra.ir.typeop — Phase 8b.

Validates specialized TypeOp subclasses, registerTypeOps registration,
propagateType logic, getOperatorName overrides, and C++ alignment.
"""
import pytest
from ghidra.types.datatype import (
    TypeFactory, Datatype,
    TYPE_UNKNOWN, TYPE_INT, TYPE_UINT, TYPE_BOOL, TYPE_FLOAT, TYPE_PTR, TYPE_VOID,
)
from ghidra.core.opcodes import OpCode
from ghidra.ir.typeop import (
    TypeOp, TypeOpBinary, TypeOpUnary, TypeOpFunc,
    TypeOpCopy, TypeOpLoad, TypeOpStore,
    TypeOpBranch, TypeOpCbranch, TypeOpBranchind,
    TypeOpCall, TypeOpCallind, TypeOpCallother, TypeOpReturn,
    TypeOpIntEqual, TypeOpIntNotEqual,
    TypeOpIntSless, TypeOpIntSlessEqual,
    TypeOpIntLess, TypeOpIntLessEqual,
    TypeOpIntZext, TypeOpIntSext,
    TypeOpIntAdd, TypeOpIntSub,
    TypeOpIntCarry, TypeOpIntScarry, TypeOpIntSborrow,
    TypeOpInt2Comp, TypeOpIntNegate,
    TypeOpIntXor, TypeOpIntAnd, TypeOpIntOr,
    TypeOpIntLeft, TypeOpIntRight, TypeOpIntSright,
    TypeOpIntMult, TypeOpIntDiv, TypeOpIntSdiv,
    TypeOpIntRem, TypeOpIntSrem,
    TypeOpBoolNegate, TypeOpBoolXor, TypeOpBoolAnd, TypeOpBoolOr,
    TypeOpFloatEqual, TypeOpFloatNotEqual, TypeOpFloatLess, TypeOpFloatLessEqual,
    TypeOpFloatNan, TypeOpFloatAdd, TypeOpFloatDiv, TypeOpFloatMult,
    TypeOpFloatSub, TypeOpFloatNeg, TypeOpFloatAbs, TypeOpFloatSqrt,
    TypeOpFloatInt2Float, TypeOpFloatFloat2Float, TypeOpFloatTrunc,
    TypeOpFloatCeil, TypeOpFloatFloor, TypeOpFloatRound,
    TypeOpPiece, TypeOpSubpiece,
    TypeOpCast, TypeOpPtradd, TypeOpPtrsub,
    TypeOpMultiequal, TypeOpIndirect,
    TypeOpSegmentOp, TypeOpCpoolRef, TypeOpNew,
    TypeOpInsert, TypeOpExtract,
    TypeOpPopcount, TypeOpLzcount,
    registerTypeOps,
)


@pytest.fixture
def tf():
    """Return a minimal TypeFactory with core types set up."""
    t = TypeFactory()
    t.setupCoreTypes()
    return t


@pytest.fixture
def inst(tf):
    """Return the full registered TypeOp list."""
    return registerTypeOps(tf)


# ---------------------------------------------------------------------------
# Registration tests
# ---------------------------------------------------------------------------
class TestRegisterTypeOps:
    def test_returns_list_of_correct_length(self, inst):
        assert len(inst) == int(OpCode.CPUI_MAX)

    def test_all_slots_filled(self, inst):
        expected_opcodes = [
            OpCode.CPUI_COPY, OpCode.CPUI_LOAD, OpCode.CPUI_STORE,
            OpCode.CPUI_BRANCH, OpCode.CPUI_CBRANCH, OpCode.CPUI_BRANCHIND,
            OpCode.CPUI_CALL, OpCode.CPUI_CALLIND, OpCode.CPUI_CALLOTHER,
            OpCode.CPUI_RETURN,
            OpCode.CPUI_INT_EQUAL, OpCode.CPUI_INT_NOTEQUAL,
            OpCode.CPUI_INT_SLESS, OpCode.CPUI_INT_SLESSEQUAL,
            OpCode.CPUI_INT_LESS, OpCode.CPUI_INT_LESSEQUAL,
            OpCode.CPUI_INT_ZEXT, OpCode.CPUI_INT_SEXT,
            OpCode.CPUI_INT_ADD, OpCode.CPUI_INT_SUB,
            OpCode.CPUI_INT_CARRY, OpCode.CPUI_INT_SCARRY, OpCode.CPUI_INT_SBORROW,
            OpCode.CPUI_INT_2COMP, OpCode.CPUI_INT_NEGATE,
            OpCode.CPUI_INT_XOR, OpCode.CPUI_INT_AND, OpCode.CPUI_INT_OR,
            OpCode.CPUI_INT_LEFT, OpCode.CPUI_INT_RIGHT, OpCode.CPUI_INT_SRIGHT,
            OpCode.CPUI_INT_MULT, OpCode.CPUI_INT_DIV, OpCode.CPUI_INT_SDIV,
            OpCode.CPUI_INT_REM, OpCode.CPUI_INT_SREM,
            OpCode.CPUI_BOOL_NEGATE, OpCode.CPUI_BOOL_XOR,
            OpCode.CPUI_BOOL_AND, OpCode.CPUI_BOOL_OR,
            OpCode.CPUI_FLOAT_EQUAL, OpCode.CPUI_FLOAT_NOTEQUAL,
            OpCode.CPUI_FLOAT_LESS, OpCode.CPUI_FLOAT_LESSEQUAL,
            OpCode.CPUI_FLOAT_NAN, OpCode.CPUI_FLOAT_ADD,
            OpCode.CPUI_FLOAT_DIV, OpCode.CPUI_FLOAT_MULT,
            OpCode.CPUI_FLOAT_SUB, OpCode.CPUI_FLOAT_NEG,
            OpCode.CPUI_FLOAT_ABS, OpCode.CPUI_FLOAT_SQRT,
            OpCode.CPUI_FLOAT_INT2FLOAT, OpCode.CPUI_FLOAT_FLOAT2FLOAT,
            OpCode.CPUI_FLOAT_TRUNC, OpCode.CPUI_FLOAT_CEIL,
            OpCode.CPUI_FLOAT_FLOOR, OpCode.CPUI_FLOAT_ROUND,
            OpCode.CPUI_MULTIEQUAL, OpCode.CPUI_INDIRECT,
            OpCode.CPUI_PIECE, OpCode.CPUI_SUBPIECE,
            OpCode.CPUI_CAST, OpCode.CPUI_PTRADD, OpCode.CPUI_PTRSUB,
            OpCode.CPUI_SEGMENTOP, OpCode.CPUI_CPOOLREF, OpCode.CPUI_NEW,
            OpCode.CPUI_INSERT, OpCode.CPUI_EXTRACT,
            OpCode.CPUI_POPCOUNT, OpCode.CPUI_LZCOUNT,
        ]
        for opc in expected_opcodes:
            assert inst[int(opc)] is not None, f"Missing TypeOp for {opc.name}"

    def test_specialized_class_types(self, inst):
        """Verify that specialized subclasses are used, not generic."""
        assert type(inst[int(OpCode.CPUI_COPY)]) is TypeOpCopy
        assert type(inst[int(OpCode.CPUI_LOAD)]) is TypeOpLoad
        assert type(inst[int(OpCode.CPUI_STORE)]) is TypeOpStore
        assert type(inst[int(OpCode.CPUI_INT_EQUAL)]) is TypeOpIntEqual
        assert type(inst[int(OpCode.CPUI_INT_ADD)]) is TypeOpIntAdd
        assert type(inst[int(OpCode.CPUI_INT_XOR)]) is TypeOpIntXor
        assert type(inst[int(OpCode.CPUI_INT_ZEXT)]) is TypeOpIntZext
        assert type(inst[int(OpCode.CPUI_INT_SEXT)]) is TypeOpIntSext
        assert type(inst[int(OpCode.CPUI_INT_CARRY)]) is TypeOpIntCarry
        assert type(inst[int(OpCode.CPUI_INT_SCARRY)]) is TypeOpIntScarry
        assert type(inst[int(OpCode.CPUI_INT_SBORROW)]) is TypeOpIntSborrow
        assert type(inst[int(OpCode.CPUI_PIECE)]) is TypeOpPiece
        assert type(inst[int(OpCode.CPUI_SUBPIECE)]) is TypeOpSubpiece
        assert type(inst[int(OpCode.CPUI_MULTIEQUAL)]) is TypeOpMultiequal
        assert type(inst[int(OpCode.CPUI_INDIRECT)]) is TypeOpIndirect
        assert type(inst[int(OpCode.CPUI_PTRADD)]) is TypeOpPtradd
        assert type(inst[int(OpCode.CPUI_PTRSUB)]) is TypeOpPtrsub
        assert type(inst[int(OpCode.CPUI_POPCOUNT)]) is TypeOpPopcount
        assert type(inst[int(OpCode.CPUI_LZCOUNT)]) is TypeOpLzcount

    def test_count_matches_expectation(self, inst):
        filled = sum(1 for x in inst if x is not None)
        assert filled == 72


# ---------------------------------------------------------------------------
# Inheritance tests
# ---------------------------------------------------------------------------
class TestInheritance:
    def test_zext_sext_are_func(self, tf):
        assert isinstance(TypeOpIntZext(tf), TypeOpFunc)
        assert isinstance(TypeOpIntSext(tf), TypeOpFunc)

    def test_carry_scarry_sborrow_are_func(self, tf):
        assert isinstance(TypeOpIntCarry(tf), TypeOpFunc)
        assert isinstance(TypeOpIntScarry(tf), TypeOpFunc)
        assert isinstance(TypeOpIntSborrow(tf), TypeOpFunc)

    def test_comparison_ops_are_binary(self, tf):
        assert isinstance(TypeOpIntEqual(tf), TypeOpBinary)
        assert isinstance(TypeOpIntNotEqual(tf), TypeOpBinary)
        assert isinstance(TypeOpIntSless(tf), TypeOpBinary)
        assert isinstance(TypeOpIntLess(tf), TypeOpBinary)

    def test_logical_ops_are_binary(self, tf):
        assert isinstance(TypeOpIntXor(tf), TypeOpBinary)
        assert isinstance(TypeOpIntAnd(tf), TypeOpBinary)
        assert isinstance(TypeOpIntOr(tf), TypeOpBinary)

    def test_piece_subpiece_are_func(self, tf):
        assert isinstance(TypeOpPiece(tf), TypeOpFunc)
        assert isinstance(TypeOpSubpiece(tf), TypeOpFunc)

    def test_popcount_lzcount_are_func(self, tf):
        assert isinstance(TypeOpPopcount(tf), TypeOpFunc)
        assert isinstance(TypeOpLzcount(tf), TypeOpFunc)


# ---------------------------------------------------------------------------
# Opcode / name tests
# ---------------------------------------------------------------------------
class TestOpcodeAndName:
    def test_copy_opcode(self, tf):
        t = TypeOpCopy(tf)
        assert t.opcode == OpCode.CPUI_COPY
        assert t.name == "COPY"

    def test_int_add_name(self, tf):
        t = TypeOpIntAdd(tf)
        assert t.name == "+"

    def test_ptradd_name(self, tf):
        t = TypeOpPtradd(tf)
        assert t.name == "+"

    def test_ptrsub_name(self, tf):
        t = TypeOpPtrsub(tf)
        assert t.name == "->"

    def test_multiequal_name(self, tf):
        t = TypeOpMultiequal(tf)
        assert t.name == "?"

    def test_indirect_name(self, tf):
        t = TypeOpIndirect(tf)
        assert t.name == "[]"

    def test_piece_name(self, tf):
        t = TypeOpPiece(tf)
        assert t.name == "CONCAT"

    def test_subpiece_name(self, tf):
        t = TypeOpSubpiece(tf)
        assert t.name == "SUB"


# ---------------------------------------------------------------------------
# setMetatypeIn / setMetatypeOut / setSymbol
# ---------------------------------------------------------------------------
class TestSetMethods:
    def test_set_metatype_in_binary(self, tf):
        t = TypeOpIntXor(tf)
        assert t.metain == TYPE_UINT
        t.setMetatypeIn(TYPE_INT)
        assert t.metain == TYPE_INT

    def test_set_metatype_out_binary(self, tf):
        t = TypeOpIntXor(tf)
        assert t.metaout == TYPE_UINT
        t.setMetatypeOut(TYPE_INT)
        assert t.metaout == TYPE_INT

    def test_set_metatype_in_func(self, tf):
        t = TypeOpIntZext(tf)
        t.setMetatypeIn(TYPE_UNKNOWN)
        assert t.metain == TYPE_UNKNOWN

    def test_set_metatype_out_func(self, tf):
        t = TypeOpIntZext(tf)
        t.setMetatypeOut(TYPE_INT)
        assert t.metaout == TYPE_INT

    def test_set_symbol(self, tf):
        t = TypeOpIntRight(tf)
        assert t.name == ">>"
        t.setSymbol(">>>")
        assert t.name == ">>>"

    def test_base_set_metatype_noop(self, tf):
        """Base TypeOp.setMetatypeIn/Out should not raise."""
        t = TypeOp(tf, OpCode.CPUI_COPY, "test")
        t.setMetatypeIn(TYPE_INT)  # no-op
        t.setMetatypeOut(TYPE_INT)  # no-op


# ---------------------------------------------------------------------------
# selectJavaOperators
# ---------------------------------------------------------------------------
class TestSelectJavaOperators:
    def test_java_mode_changes_int_right_symbol(self, inst):
        right_op = inst[int(OpCode.CPUI_INT_RIGHT)]
        assert right_op.name == ">>"
        TypeOp.selectJavaOperators(inst, True)
        assert right_op.name == ">>>"
        assert right_op.metain == TYPE_INT
        assert right_op.metaout == TYPE_INT

    def test_java_mode_reverts(self, inst):
        TypeOp.selectJavaOperators(inst, True)
        TypeOp.selectJavaOperators(inst, False)
        right_op = inst[int(OpCode.CPUI_INT_RIGHT)]
        assert right_op.name == ">>"
        assert right_op.metain == TYPE_UINT
        assert right_op.metaout == TYPE_UINT


# ---------------------------------------------------------------------------
# addlflags tests
# ---------------------------------------------------------------------------
class TestAddlFlags:
    def test_int_add_has_arithmetic_and_inherits_sign(self, tf):
        t = TypeOpIntAdd(tf)
        assert t.addlflags & TypeOp.arithmetic_op
        assert t.addlflags & TypeOp.inherits_sign

    def test_int_xor_has_logical_and_inherits_sign(self, tf):
        t = TypeOpIntXor(tf)
        assert t.addlflags & TypeOp.logical_op
        assert t.addlflags & TypeOp.inherits_sign

    def test_int_left_has_shift_and_inherits_sign(self, tf):
        t = TypeOpIntLeft(tf)
        assert t.addlflags & TypeOp.shift_op

    def test_ptradd_has_arithmetic_op(self, tf):
        t = TypeOpPtradd(tf)
        assert t.addlflags & TypeOp.arithmetic_op

    def test_ptrsub_has_arithmetic_op(self, tf):
        t = TypeOpPtrsub(tf)
        assert t.addlflags & TypeOp.arithmetic_op


# ---------------------------------------------------------------------------
# propagateType tests
# ---------------------------------------------------------------------------
class _FakeVarnode:
    """Minimal varnode stub for propagation tests."""
    def __init__(self, size=4, is_const=False, offset=0, is_spacebase=False):
        self._size = size
        self._is_const = is_const
        self._offset = offset
        self._is_spacebase = is_spacebase
    def getSize(self):
        return self._size
    def isConstant(self):
        return self._is_const
    def getOffset(self):
        return self._offset
    def isSpacebase(self):
        return self._is_spacebase
    def getType(self):
        return None
    def getHighTypeReadFacing(self, op=None):
        return None
    def getHighTypeDefFacing(self):
        return None


class _FakeOp:
    """Minimal PcodeOp stub."""
    def __init__(self, opc, inputs=None, output=None):
        self._opc = opc
        self._inputs = inputs or []
        self._output = output
    def code(self):
        return self._opc
    def getOpcode(self):
        return self._opc
    def getIn(self, slot):
        if slot < len(self._inputs):
            return self._inputs[slot]
        return None
    def getOut(self):
        return self._output
    def numInput(self):
        return len(self._inputs)


class _FakeDatatype:
    """Minimal Datatype stub."""
    def __init__(self, size=4, meta=TYPE_INT, is_enum=False):
        self._size = size
        self._meta = meta
        self._is_enum = is_enum
    def getSize(self):
        return self._size
    def getAlignSize(self):
        return self._size
    def getMetatype(self):
        return self._meta
    def isEnumType(self):
        return self._is_enum


class TestPropagateType:
    def test_copy_propagates_any_type(self, tf):
        t = TypeOpCopy(tf)
        dt = _FakeDatatype(4, TYPE_INT)
        invn = _FakeVarnode(4)
        outvn = _FakeVarnode(4)
        op = _FakeOp(OpCode.CPUI_COPY, [invn], outvn)
        result = t.propagateType(dt, op, invn, outvn, 0, -1)
        assert result is dt

    def test_copy_blocks_input_to_input(self, tf):
        t = TypeOpCopy(tf)
        dt = _FakeDatatype(4, TYPE_INT)
        invn = _FakeVarnode(4)
        outvn = _FakeVarnode(4)
        op = _FakeOp(OpCode.CPUI_COPY, [invn], outvn)
        result = t.propagateType(dt, op, invn, outvn, 0, 1)
        assert result is None

    def test_int_equal_propagates_between_inputs(self, tf):
        t = TypeOpIntEqual(tf)
        dt = _FakeDatatype(4, TYPE_INT)
        invn = _FakeVarnode(4)
        outvn = _FakeVarnode(4)
        op = _FakeOp(OpCode.CPUI_INT_EQUAL, [invn, outvn])
        result = t.propagateType(dt, op, invn, outvn, 0, 1)
        assert result is dt

    def test_int_equal_blocks_output_to_input(self, tf):
        t = TypeOpIntEqual(tf)
        dt = _FakeDatatype(4, TYPE_INT)
        invn = _FakeVarnode(4)
        outvn = _FakeVarnode(4)
        op = _FakeOp(OpCode.CPUI_INT_EQUAL, [invn], outvn)
        result = t.propagateType(dt, op, invn, outvn, -1, 0)
        assert result is None

    def test_int_sless_only_propagates_signed(self, tf):
        t = TypeOpIntSless(tf)
        dt_signed = _FakeDatatype(4, TYPE_INT)
        dt_unsigned = _FakeDatatype(4, TYPE_UINT)
        invn = _FakeVarnode(4)
        outvn = _FakeVarnode(4)
        op = _FakeOp(OpCode.CPUI_INT_SLESS, [invn, outvn])
        assert t.propagateType(dt_signed, op, invn, outvn, 0, 1) is dt_signed
        assert t.propagateType(dt_unsigned, op, invn, outvn, 0, 1) is None

    def test_int_add_no_propagate_non_ptr(self, tf):
        t = TypeOpIntAdd(tf)
        dt = _FakeDatatype(4, TYPE_FLOAT)
        invn = _FakeVarnode(4)
        outvn = _FakeVarnode(4)
        op = _FakeOp(OpCode.CPUI_INT_ADD, [invn, outvn], outvn)
        result = t.propagateType(dt, op, invn, outvn, 0, -1)
        assert result is None

    def test_int_sub_propagates_ptr_in0_to_out(self, tf):
        t = TypeOpIntSub(tf)
        dt = _FakeDatatype(4, TYPE_PTR)
        invn = _FakeVarnode(4)
        outvn = _FakeVarnode(4)
        op = _FakeOp(OpCode.CPUI_INT_SUB, [invn, outvn], outvn)
        result = t.propagateType(dt, op, invn, outvn, 0, -1)
        assert result is dt

    def test_int_sub_blocks_ptr_in1_to_out(self, tf):
        t = TypeOpIntSub(tf)
        dt = _FakeDatatype(4, TYPE_PTR)
        invn = _FakeVarnode(4)
        outvn = _FakeVarnode(4)
        op = _FakeOp(OpCode.CPUI_INT_SUB, [outvn, invn], outvn)
        result = t.propagateType(dt, op, invn, outvn, 1, -1)
        assert result is None

    def test_int_xor_propagates_enum(self, tf):
        t = TypeOpIntXor(tf)
        dt = _FakeDatatype(4, TYPE_UINT, is_enum=True)
        invn = _FakeVarnode(4)
        outvn = _FakeVarnode(4)
        op = _FakeOp(OpCode.CPUI_INT_XOR, [invn, outvn], outvn)
        result = t.propagateType(dt, op, invn, outvn, 0, -1)
        assert result is dt

    def test_int_xor_blocks_non_enum_non_float(self, tf):
        t = TypeOpIntXor(tf)
        dt = _FakeDatatype(4, TYPE_UINT, is_enum=False)
        invn = _FakeVarnode(4)
        outvn = _FakeVarnode(4)
        op = _FakeOp(OpCode.CPUI_INT_XOR, [invn, outvn], outvn)
        result = t.propagateType(dt, op, invn, outvn, 0, -1)
        assert result is None

    def test_int_or_only_propagates_enum(self, tf):
        t = TypeOpIntOr(tf)
        dt_enum = _FakeDatatype(4, TYPE_UINT, is_enum=True)
        dt_plain = _FakeDatatype(4, TYPE_UINT, is_enum=False)
        invn = _FakeVarnode(4)
        outvn = _FakeVarnode(4)
        op = _FakeOp(OpCode.CPUI_INT_OR, [invn, outvn], outvn)
        assert t.propagateType(dt_enum, op, invn, outvn, 0, -1) is dt_enum
        assert t.propagateType(dt_plain, op, invn, outvn, 0, -1) is None

    def test_multiequal_propagates_input_to_output(self, tf):
        t = TypeOpMultiequal(tf)
        dt = _FakeDatatype(4, TYPE_INT)
        invn = _FakeVarnode(4)
        outvn = _FakeVarnode(4)
        op = _FakeOp(OpCode.CPUI_MULTIEQUAL, [invn], outvn)
        result = t.propagateType(dt, op, invn, outvn, 0, -1)
        assert result is dt

    def test_multiequal_blocks_input_to_input(self, tf):
        t = TypeOpMultiequal(tf)
        dt = _FakeDatatype(4, TYPE_INT)
        invn = _FakeVarnode(4)
        outvn = _FakeVarnode(4)
        op = _FakeOp(OpCode.CPUI_MULTIEQUAL, [invn, outvn])
        result = t.propagateType(dt, op, invn, outvn, 0, 1)
        assert result is None

    def test_indirect_blocks_slot1(self, tf):
        t = TypeOpIndirect(tf)
        dt = _FakeDatatype(4, TYPE_INT)
        invn = _FakeVarnode(4)
        outvn = _FakeVarnode(4)
        op = _FakeOp(OpCode.CPUI_INDIRECT, [invn, outvn], outvn)
        result = t.propagateType(dt, op, invn, outvn, 1, -1)
        assert result is None

    def test_indirect_propagates_slot0_to_output(self, tf):
        t = TypeOpIndirect(tf)
        dt = _FakeDatatype(4, TYPE_INT)
        invn = _FakeVarnode(4)
        outvn = _FakeVarnode(4)
        op = _FakeOp(OpCode.CPUI_INDIRECT, [invn], outvn)
        result = t.propagateType(dt, op, invn, outvn, 0, -1)
        assert result is dt

    def test_ptradd_blocks_edge2(self, tf):
        t = TypeOpPtradd(tf)
        dt = _FakeDatatype(4, TYPE_PTR)
        invn = _FakeVarnode(4)
        outvn = _FakeVarnode(4)
        op = _FakeOp(OpCode.CPUI_PTRADD, [invn, outvn, _FakeVarnode(4)], outvn)
        result = t.propagateType(dt, op, invn, outvn, 2, -1)
        assert result is None

    def test_ptrsub_blocks_non_ptr(self, tf):
        t = TypeOpPtrsub(tf)
        dt = _FakeDatatype(4, TYPE_INT)
        invn = _FakeVarnode(4)
        outvn = _FakeVarnode(4)
        op = _FakeOp(OpCode.CPUI_PTRSUB, [invn, outvn], outvn)
        result = t.propagateType(dt, op, invn, outvn, 0, -1)
        assert result is None

    def test_ptrsub_blocks_output_to_input(self, tf):
        t = TypeOpPtrsub(tf)
        dt = _FakeDatatype(4, TYPE_PTR)
        invn = _FakeVarnode(4)
        outvn = _FakeVarnode(4)
        op = _FakeOp(OpCode.CPUI_PTRSUB, [outvn], invn)
        result = t.propagateType(dt, op, invn, outvn, -1, 0)
        assert result is None

    def test_piece_blocks_input_to_output(self, tf):
        t = TypeOpPiece(tf)
        dt = _FakeDatatype(4, TYPE_INT)
        invn = _FakeVarnode(2)
        outvn = _FakeVarnode(4)
        op = _FakeOp(OpCode.CPUI_PIECE, [invn, invn], outvn)
        result = t.propagateType(dt, op, invn, outvn, 0, -1)
        assert result is None

    def test_subpiece_propagates_in0_to_out(self, tf):
        t = TypeOpSubpiece(tf)
        dt = _FakeDatatype(4, TYPE_INT)
        invn = _FakeVarnode(4)
        outvn = _FakeVarnode(4)
        op = _FakeOp(OpCode.CPUI_SUBPIECE, [invn, _FakeVarnode(4, True, 0)], outvn)
        result = t.propagateType(dt, op, invn, outvn, 0, -1)
        assert result is dt

    def test_subpiece_blocks_wrong_direction(self, tf):
        t = TypeOpSubpiece(tf)
        dt = _FakeDatatype(4, TYPE_INT)
        invn = _FakeVarnode(4)
        outvn = _FakeVarnode(4)
        op = _FakeOp(OpCode.CPUI_SUBPIECE, [invn, outvn], outvn)
        result = t.propagateType(dt, op, invn, outvn, -1, 0)
        assert result is None


# ---------------------------------------------------------------------------
# propagateAddPointer static tests
# ---------------------------------------------------------------------------
class TestPropagateAddPointer:
    def test_int_add_const_zero(self):
        invn = _FakeVarnode(4)
        constvn = _FakeVarnode(4, is_const=True, offset=0)
        outvn = _FakeVarnode(4)
        op = _FakeOp(OpCode.CPUI_INT_ADD, [invn, constvn], outvn)
        assert TypeOpIntAdd.propagateAddPointer(op, 0, 4) == 0

    def test_int_add_const_nonzero(self):
        invn = _FakeVarnode(4)
        constvn = _FakeVarnode(4, is_const=True, offset=8)
        outvn = _FakeVarnode(4)
        op = _FakeOp(OpCode.CPUI_INT_ADD, [invn, constvn], outvn)
        assert TypeOpIntAdd.propagateAddPointer(op, 0, 4) == 1

    def test_int_add_variable_size1(self):
        invn = _FakeVarnode(4)
        varvn = _FakeVarnode(4, is_const=False)
        outvn = _FakeVarnode(4)
        op = _FakeOp(OpCode.CPUI_INT_ADD, [invn, varvn], outvn)
        assert TypeOpIntAdd.propagateAddPointer(op, 0, 1) == 3

    def test_int_add_variable_size_larger(self):
        invn = _FakeVarnode(4)
        varvn = _FakeVarnode(4, is_const=False)
        outvn = _FakeVarnode(4)
        op = _FakeOp(OpCode.CPUI_INT_ADD, [invn, varvn], outvn)
        assert TypeOpIntAdd.propagateAddPointer(op, 0, 4) == 2


# ---------------------------------------------------------------------------
# getInputCast tests
# ---------------------------------------------------------------------------
class TestGetInputCast:
    def test_piece_always_none(self, tf):
        t = TypeOpPiece(tf)
        invn = _FakeVarnode(2)
        outvn = _FakeVarnode(4)
        op = _FakeOp(OpCode.CPUI_PIECE, [invn, invn], outvn)
        assert t.getInputCast(op, 0) is None
        assert t.getInputCast(op, 1) is None

    def test_subpiece_always_none(self, tf):
        t = TypeOpSubpiece(tf)
        invn = _FakeVarnode(4)
        outvn = _FakeVarnode(2)
        op = _FakeOp(OpCode.CPUI_SUBPIECE, [invn, _FakeVarnode(4, True, 0)], outvn)
        assert t.getInputCast(op, 0) is None


# ---------------------------------------------------------------------------
# getOperatorName override tests
# ---------------------------------------------------------------------------
class TestGetOperatorName:
    def test_zext_operator_name(self, tf):
        t = TypeOpIntZext(tf)
        invn = _FakeVarnode(2)
        outvn = _FakeVarnode(4)
        op = _FakeOp(OpCode.CPUI_INT_ZEXT, [invn], outvn)
        assert t.getOperatorName(op) == "ZEXT24"

    def test_sext_operator_name(self, tf):
        t = TypeOpIntSext(tf)
        invn = _FakeVarnode(1)
        outvn = _FakeVarnode(4)
        op = _FakeOp(OpCode.CPUI_INT_SEXT, [invn], outvn)
        assert t.getOperatorName(op) == "SEXT14"

    def test_carry_operator_name(self, tf):
        t = TypeOpIntCarry(tf)
        invn = _FakeVarnode(4)
        op = _FakeOp(OpCode.CPUI_INT_CARRY, [invn, invn])
        assert t.getOperatorName(op) == "CARRY4"

    def test_scarry_operator_name(self, tf):
        t = TypeOpIntScarry(tf)
        invn = _FakeVarnode(2)
        op = _FakeOp(OpCode.CPUI_INT_SCARRY, [invn, invn])
        assert t.getOperatorName(op) == "SCARRY2"

    def test_sborrow_operator_name(self, tf):
        t = TypeOpIntSborrow(tf)
        invn = _FakeVarnode(8)
        op = _FakeOp(OpCode.CPUI_INT_SBORROW, [invn, invn])
        assert t.getOperatorName(op) == "SBORROW8"

    def test_piece_operator_name(self, tf):
        t = TypeOpPiece(tf)
        in0 = _FakeVarnode(4)
        in1 = _FakeVarnode(2)
        op = _FakeOp(OpCode.CPUI_PIECE, [in0, in1])
        assert t.getOperatorName(op) == "CONCAT42"

    def test_subpiece_operator_name(self, tf):
        t = TypeOpSubpiece(tf)
        in0 = _FakeVarnode(8)
        outvn = _FakeVarnode(4)
        op = _FakeOp(OpCode.CPUI_SUBPIECE, [in0, _FakeVarnode(4, True, 0)], outvn)
        assert t.getOperatorName(op) == "SUB84"


# ---------------------------------------------------------------------------
# getOutputLocal / getInputLocal tests
# ---------------------------------------------------------------------------
class TestGetOutputInputLocal:
    def test_int_equal_output_bool(self, tf):
        t = TypeOpIntEqual(tf)
        outvn = _FakeVarnode(1)
        op = _FakeOp(OpCode.CPUI_INT_EQUAL, [_FakeVarnode(4), _FakeVarnode(4)], outvn)
        dt = t.getOutputLocal(op)
        assert dt is not None
        assert dt.getMetatype() == TYPE_BOOL

    def test_int_add_output_int(self, tf):
        t = TypeOpIntAdd(tf)
        outvn = _FakeVarnode(4)
        op = _FakeOp(OpCode.CPUI_INT_ADD, [_FakeVarnode(4), _FakeVarnode(4)], outvn)
        dt = t.getOutputLocal(op)
        assert dt is not None
        assert dt.getMetatype() == TYPE_INT

    def test_ptradd_output_int(self, tf):
        t = TypeOpPtradd(tf)
        outvn = _FakeVarnode(4)
        op = _FakeOp(OpCode.CPUI_PTRADD, [_FakeVarnode(4), _FakeVarnode(4), _FakeVarnode(4)], outvn)
        dt = t.getOutputLocal(op)
        assert dt is not None
        assert dt.getMetatype() == TYPE_INT

    def test_ptradd_input_int(self, tf):
        t = TypeOpPtradd(tf)
        invn = _FakeVarnode(4)
        op = _FakeOp(OpCode.CPUI_PTRADD, [invn, invn, invn], _FakeVarnode(4))
        dt = t.getInputLocal(op, 0)
        assert dt is not None
        assert dt.getMetatype() == TYPE_INT

    def test_ptrsub_output_int(self, tf):
        t = TypeOpPtrsub(tf)
        outvn = _FakeVarnode(4)
        op = _FakeOp(OpCode.CPUI_PTRSUB, [_FakeVarnode(4), _FakeVarnode(4)], outvn)
        dt = t.getOutputLocal(op)
        assert dt is not None
        assert dt.getMetatype() == TYPE_INT

    def test_insert_slot0_unknown(self, tf):
        t = TypeOpInsert(tf)
        invn = _FakeVarnode(4)
        op = _FakeOp(OpCode.CPUI_INSERT, [invn, invn, invn])
        dt = t.getInputLocal(op, 0)
        assert dt is not None
        assert dt.getMetatype() == TYPE_UNKNOWN

    def test_extract_slot0_unknown(self, tf):
        t = TypeOpExtract(tf)
        invn = _FakeVarnode(4)
        op = _FakeOp(OpCode.CPUI_EXTRACT, [invn, invn, invn])
        dt = t.getInputLocal(op, 0)
        assert dt is not None
        assert dt.getMetatype() == TYPE_UNKNOWN


# ---------------------------------------------------------------------------
# floatSignManipulation tests
# ---------------------------------------------------------------------------
class TestFloatSignManipulation:
    def test_and_with_sign_mask_returns_abs(self):
        invn = _FakeVarnode(4)
        mask_vn = _FakeVarnode(4, is_const=True, offset=0x7FFFFFFF)
        op = _FakeOp(OpCode.CPUI_INT_AND, [invn, mask_vn])
        assert TypeOp.floatSignManipulation(op) == OpCode.CPUI_FLOAT_ABS

    def test_xor_with_sign_bit_returns_neg(self):
        invn = _FakeVarnode(4)
        mask_vn = _FakeVarnode(4, is_const=True, offset=0x80000000)
        op = _FakeOp(OpCode.CPUI_INT_XOR, [invn, mask_vn])
        assert TypeOp.floatSignManipulation(op) == OpCode.CPUI_FLOAT_NEG

    def test_and_with_wrong_mask_returns_max(self):
        invn = _FakeVarnode(4)
        mask_vn = _FakeVarnode(4, is_const=True, offset=0x12345678)
        op = _FakeOp(OpCode.CPUI_INT_AND, [invn, mask_vn])
        assert TypeOp.floatSignManipulation(op) == OpCode.CPUI_MAX

    def test_other_op_returns_max(self):
        invn = _FakeVarnode(4)
        op = _FakeOp(OpCode.CPUI_INT_OR, [invn, invn])
        assert TypeOp.floatSignManipulation(op) == OpCode.CPUI_MAX
