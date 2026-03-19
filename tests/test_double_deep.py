"""Tests for deepened double.py — SplitVarnode and Form classes."""
import pytest
import sys
import os

sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', 'python'))

from ghidra.analysis.double import (
    SplitVarnode, AddForm, SubForm, LogicalForm,
    Equal1Form, Equal2Form, Equal3Form,
    LessConstForm, LessThreeWay, ShiftForm, MultForm,
    PhiForm, IndirectForm, CopyForceForm,
    RuleDoubleIn, RuleDoubleOut, RuleDoubleLoad, RuleDoubleStore,
)
from ghidra.ir.op import OpCode


# ---------------------------------------------------------------------------
# Minimal mock objects
# ---------------------------------------------------------------------------

class MockAddr:
    def __init__(self, space=None, offset=0):
        self._space = space or MockSpace()
        self._offset = offset

    def getSpace(self):
        return self._space

    def getOffset(self):
        return self._offset


class MockSpace:
    def __init__(self, name='ram', big_endian=False):
        self._name = name
        self._big = big_endian

    def isBigEndian(self):
        return self._big

    def getName(self):
        return self._name


class MockSeqNum:
    def __init__(self, order=0):
        self._order = order

    def getOrder(self):
        return self._order


class MockVarnode:
    def __init__(self, size=4, offset=0, space=None, is_const=False,
                 is_written=False, is_input=False, is_free=False,
                 precis_hi=False, precis_lo=False,
                 addr_tied=False, addr_force=False):
        self._size = size
        self._offset = offset
        self._space = space or MockSpace()
        self._is_const = is_const
        self._is_written = is_written
        self._is_input = is_input
        self._is_free = is_free
        self._precis_hi = precis_hi
        self._precis_lo = precis_lo
        self._addr_tied = addr_tied
        self._addr_force = addr_force
        self._def = None
        self._descendants = []
        self._addr = MockAddr(self._space, self._offset)
        self._symbol_entry = None

    def getSize(self):
        return self._size

    def getOffset(self):
        return self._offset

    def getSpace(self):
        return self._space

    def getAddr(self):
        return self._addr

    def isConstant(self):
        return self._is_const

    def isWritten(self):
        return self._is_written

    def isInput(self):
        return self._is_input

    def isFree(self):
        return self._is_free

    def isPrecisHi(self):
        return self._precis_hi

    def isPrecisLo(self):
        return self._precis_lo

    def isAddrTied(self):
        return self._addr_tied

    def isAddrForce(self):
        return self._addr_force

    def setPrecisHi(self):
        self._precis_hi = True

    def setPrecisLo(self):
        self._precis_lo = True

    def getDef(self):
        return self._def

    def getDescendants(self):
        return list(self._descendants)

    def loneDescend(self):
        if len(self._descendants) == 1:
            return self._descendants[0]
        return None

    def getSymbolEntry(self):
        return self._symbol_entry

    def setWriteMask(self):
        pass


class MockPcodeOp:
    def __init__(self, opc=OpCode.CPUI_COPY, inputs=None, output=None,
                 parent=None, seq_order=0):
        self._code = opc
        self._inputs = inputs or []
        self._output = output
        self._parent = parent
        self._seq = MockSeqNum(seq_order)

    def code(self):
        return self._code

    def getIn(self, i):
        return self._inputs[i] if i < len(self._inputs) else None

    def getOut(self):
        return self._output

    def getParent(self):
        return self._parent

    def getSeqNum(self):
        return self._seq

    def getAddr(self):
        return MockAddr()

    def numInput(self):
        return len(self._inputs)

    def getSlot(self, vn):
        for i, inp in enumerate(self._inputs):
            if inp is vn:
                return i
        return -1


class MockBlock:
    def __init__(self, index=0):
        self._index = index
        self._immed_dom = None
        self._ops = []
        self._ins = []
        self._outs = []

    def getImmedDom(self):
        return self._immed_dom

    def getStart(self):
        return MockAddr()

    def isEntryPoint(self):
        return self._index == 0

    def sizeIn(self):
        return len(self._ins)

    def sizeOut(self):
        return len(self._outs)

    def getIn(self, i):
        return self._ins[i] if i < len(self._ins) else None

    def getOpList(self):
        return list(self._ops)

    def getTrueOut(self):
        return self._outs[0] if len(self._outs) > 0 else None

    def getFalseOut(self):
        return self._outs[1] if len(self._outs) > 1 else None

    def lastOp(self):
        return self._ops[-1] if self._ops else None


# ---------------------------------------------------------------------------
# SplitVarnode basic tests
# ---------------------------------------------------------------------------

class TestSplitVarnodeInit:
    def test_default_init(self):
        sv = SplitVarnode()
        assert sv.getLo() is None
        assert sv.getHi() is None
        assert sv.getWhole() is None
        assert sv.getSize() == 0

    def test_initAll_3arg(self):
        w = MockVarnode(size=8)
        lo = MockVarnode(size=4)
        hi = MockVarnode(size=4)
        sv = SplitVarnode()
        sv.initAll(w, lo, hi)
        assert sv.getWhole() is w
        assert sv.getLo() is lo
        assert sv.getHi() is hi
        assert sv.getSize() == 8

    def test_initAll_2arg_legacy(self):
        lo = MockVarnode(size=4)
        hi = MockVarnode(size=4)
        sv = SplitVarnode()
        sv.initAll(lo, hi)
        assert sv.getLo() is lo
        assert sv.getHi() is hi
        assert sv.getSize() == 8

    def test_initPartial_2arg(self):
        vn = MockVarnode(size=8)
        sv = SplitVarnode()
        sv.initPartial(8, vn)
        assert sv.getWhole() is vn
        assert sv.getSize() == 8
        assert sv.getLo() is None

    def test_initPartial_3arg(self):
        lo = MockVarnode(size=4)
        hi = MockVarnode(size=4)
        sv = SplitVarnode()
        sv.initPartial(8, lo, hi)
        assert sv.getLo() is lo
        assert sv.getHi() is hi
        assert sv.getSize() == 8

    def test_initPartialConst(self):
        sv = SplitVarnode()
        sv.initPartialConst(8, 0xDEADBEEF)
        assert sv.getSize() == 8
        assert sv._val == 0xDEADBEEF
        assert sv.getLo() is None


class TestSplitVarnodeAccessors:
    def test_hasBothPieces(self):
        sv = SplitVarnode()
        assert not sv.hasBothPieces()
        sv.lo = MockVarnode()
        assert not sv.hasBothPieces()
        sv.hi = MockVarnode()
        assert sv.hasBothPieces()

    def test_isConstant_whole(self):
        sv = SplitVarnode()
        sv.whole = MockVarnode(is_const=True)
        assert sv.isConstant()

    def test_isConstant_pieces(self):
        sv = SplitVarnode()
        sv.lo = MockVarnode(is_const=True)
        sv.hi = MockVarnode(is_const=True)
        assert sv.isConstant()

    def test_isConstant_mixed(self):
        sv = SplitVarnode()
        sv.lo = MockVarnode(is_const=True)
        sv.hi = MockVarnode(is_const=False)
        assert not sv.isConstant()

    def test_getConstValue(self):
        sv = SplitVarnode()
        sv.lo = MockVarnode(size=4, offset=0x1234, is_const=True)
        sv.hi = MockVarnode(size=4, offset=0xABCD, is_const=True)
        assert sv.getConstValue() == (0xABCD << 32) | 0x1234

    def test_exceedsConstPrecision_false(self):
        sv = SplitVarnode()
        sv.wholesize = 8
        assert not sv.exceedsConstPrecision()

    def test_exceedsConstPrecision_true(self):
        sv = SplitVarnode()
        sv.wholesize = 16
        assert sv.exceedsConstPrecision()


class TestSplitVarnodeInHand:
    def test_inHandHi_no_precis(self):
        sv = SplitVarnode()
        vn = MockVarnode(precis_hi=False)
        assert not sv.inHandHi(vn)

    def test_inHandLo_no_precis(self):
        sv = SplitVarnode()
        vn = MockVarnode(precis_lo=False)
        assert not sv.inHandLo(vn)

    def test_inHandLoNoHi_no_precis(self):
        sv = SplitVarnode()
        vn = MockVarnode(precis_lo=False)
        assert not sv.inHandLoNoHi(vn)


class TestSplitVarnodeAdjacentOffsets:
    def test_adjacent_constants(self):
        vn1 = MockVarnode(size=4, offset=0x100, is_const=True)
        vn2 = MockVarnode(size=4, offset=0x104, is_const=True)
        assert SplitVarnode.adjacentOffsets(vn1, vn2, 4)

    def test_non_adjacent_constants(self):
        vn1 = MockVarnode(size=4, offset=0x100, is_const=True)
        vn2 = MockVarnode(size=4, offset=0x108, is_const=True)
        assert not SplitVarnode.adjacentOffsets(vn1, vn2, 4)

    def test_const_vs_non_const(self):
        vn1 = MockVarnode(size=4, offset=0x100, is_const=True)
        vn2 = MockVarnode(size=4, offset=0x104, is_const=False)
        assert not SplitVarnode.adjacentOffsets(vn1, vn2, 4)


class TestSplitVarnodeVerifyMultNegOne:
    def test_not_mult(self):
        op = MockPcodeOp(opc=OpCode.CPUI_INT_ADD)
        assert not SplitVarnode.verifyMultNegOne(op)

    def test_mult_not_neg_one(self):
        c = MockVarnode(size=4, offset=5, is_const=True)
        op = MockPcodeOp(opc=OpCode.CPUI_INT_MULT, inputs=[MockVarnode(), c])
        assert not SplitVarnode.verifyMultNegOne(op)

    def test_mult_neg_one(self):
        c = MockVarnode(size=4, offset=0xFFFFFFFF, is_const=True)
        op = MockPcodeOp(opc=OpCode.CPUI_INT_MULT, inputs=[MockVarnode(), c])
        assert SplitVarnode.verifyMultNegOne(op)


class TestSplitVarnodeTrueFalse:
    def test_get_true_false_no_flip(self):
        bl = MockBlock()
        truebl = MockBlock(1)
        falsebl = MockBlock(2)
        bl._outs = [truebl, falsebl]
        boolop = MockPcodeOp(parent=bl)
        t, f = SplitVarnode.getTrueFalse(boolop, False)
        assert t is truebl
        assert f is falsebl

    def test_get_true_false_flip(self):
        bl = MockBlock()
        truebl = MockBlock(1)
        falsebl = MockBlock(2)
        bl._outs = [truebl, falsebl]
        boolop = MockPcodeOp(parent=bl)
        t, f = SplitVarnode.getTrueFalse(boolop, True)
        assert t is falsebl
        assert f is truebl


class TestSplitVarnodeOtherwiseEmpty:
    def test_empty_block(self):
        bl = MockBlock()
        bl._ins = [MockBlock()]  # sizeIn == 1
        branchop = MockPcodeOp(parent=bl)
        bl._ops = [branchop]
        assert SplitVarnode.otherwiseEmpty(branchop)

    def test_non_empty_block(self):
        bl = MockBlock()
        bl._ins = [MockBlock()]
        other = MockPcodeOp()
        branchop = MockPcodeOp(parent=bl)
        bl._ops = [other, branchop]
        assert not SplitVarnode.otherwiseEmpty(branchop)


class TestSplitVarnodeFindEarliestSplitPoint:
    def test_both_none(self):
        sv = SplitVarnode()
        assert sv.findEarliestSplitPoint() is None

    def test_both_written_same_block(self):
        bl = MockBlock()
        hi_op = MockPcodeOp(seq_order=10, parent=bl)
        lo_op = MockPcodeOp(seq_order=5, parent=bl)
        hi = MockVarnode(is_written=True)
        hi._def = hi_op
        lo = MockVarnode(is_written=True)
        lo._def = lo_op
        sv = SplitVarnode()
        sv.hi = hi
        sv.lo = lo
        result = sv.findEarliestSplitPoint()
        assert result is lo_op

    def test_diff_blocks(self):
        bl1 = MockBlock(0)
        bl2 = MockBlock(1)
        hi_op = MockPcodeOp(parent=bl1)
        lo_op = MockPcodeOp(parent=bl2)
        hi = MockVarnode(is_written=True)
        hi._def = hi_op
        lo = MockVarnode(is_written=True)
        lo._def = lo_op
        sv = SplitVarnode()
        sv.hi = hi
        sv.lo = lo
        assert sv.findEarliestSplitPoint() is None


class TestSplitVarnodeIsAddrTiedContiguous:
    def test_not_addr_tied(self):
        lo = MockVarnode(addr_tied=False)
        hi = MockVarnode(addr_tied=False)
        ok, addr = SplitVarnode.isAddrTiedContiguous(lo, hi)
        assert not ok

    def test_contiguous_little_endian(self):
        spc = MockSpace(big_endian=False)
        lo = MockVarnode(size=4, offset=0x100, space=spc, addr_tied=True)
        lo._addr = MockAddr(spc, 0x100)
        hi = MockVarnode(size=4, offset=0x104, space=spc, addr_tied=True)
        hi._addr = MockAddr(spc, 0x104)
        ok, addr = SplitVarnode.isAddrTiedContiguous(lo, hi)
        assert ok
        assert addr is lo._addr


class TestSplitVarnodePrepareBinaryOp:
    def test_no_existop(self):
        out = SplitVarnode()
        in1 = SplitVarnode()
        in2 = SplitVarnode()
        result = SplitVarnode.prepareBinaryOp(out, in1, in2)
        assert result is None

    def test_prepareBoolOp_both_not_feasible(self):
        in1 = SplitVarnode()
        in2 = SplitVarnode()
        testop = MockPcodeOp()
        assert not SplitVarnode.prepareBoolOp(in1, in2, testop)


class TestSplitVarnodeFindDefinitionPoint:
    def test_no_pieces(self):
        sv = SplitVarnode()
        assert not sv.findDefinitionPoint()

    def test_both_input(self):
        sv = SplitVarnode()
        sv.lo = MockVarnode(is_input=True)
        sv.hi = MockVarnode(is_input=True)
        assert sv.findDefinitionPoint()
        assert sv.defblock is None
        assert sv.defpoint is None

    def test_hi_only_none(self):
        sv = SplitVarnode()
        bl = MockBlock()
        op = MockPcodeOp(parent=bl)
        sv.lo = MockVarnode(is_written=True)
        sv.lo._def = op
        sv.hi = None
        assert sv.findDefinitionPoint()
        assert sv.defpoint is op

    def test_lo_const_returns_false(self):
        sv = SplitVarnode()
        sv.lo = MockVarnode(is_const=True)
        sv.hi = MockVarnode()
        assert not sv.findDefinitionPoint()


# ---------------------------------------------------------------------------
# Form class tests
# ---------------------------------------------------------------------------

class TestAddForm:
    def test_init(self):
        af = AddForm()
        assert af.inv is not None
        assert af.lo1 is None

    def test_applyRule_not_workishi(self):
        af = AddForm()
        sv = SplitVarnode()
        op = MockPcodeOp()
        assert not af.applyRule(sv, op, False, None)

    def test_applyRule_no_both_pieces(self):
        af = AddForm()
        sv = SplitVarnode()
        sv.lo = MockVarnode()
        op = MockPcodeOp()
        assert not af.applyRule(sv, op, True, None)


class TestSubForm:
    def test_init(self):
        sf = SubForm()
        assert sf.inv is not None

    def test_applyRule_not_workishi(self):
        sf = SubForm()
        sv = SplitVarnode()
        op = MockPcodeOp()
        assert not sf.applyRule(sv, op, False, None)


class TestLogicalForm:
    def test_init(self):
        lf = LogicalForm()
        assert lf.inv is not None

    def test_applyRule_workishi_returns_false(self):
        lf = LogicalForm()
        sv = SplitVarnode()
        op = MockPcodeOp()
        assert not lf.applyRule(sv, op, True, None)

    def test_applyRule_no_both_pieces(self):
        lf = LogicalForm()
        sv = SplitVarnode()
        sv.lo = MockVarnode()
        op = MockPcodeOp()
        assert not lf.applyRule(sv, op, False, None)


class TestEqual1Form:
    def test_applyRule_not_workishi(self):
        ef = Equal1Form()
        sv = SplitVarnode()
        op = MockPcodeOp()
        assert not ef.applyRule(sv, op, False, None)

    def test_applyRule_no_both_pieces(self):
        ef = Equal1Form()
        sv = SplitVarnode()
        sv.lo = MockVarnode()
        op = MockPcodeOp()
        assert not ef.applyRule(sv, op, True, None)


class TestEqual2Form:
    def test_applyRule_not_workishi(self):
        ef = Equal2Form()
        sv = SplitVarnode()
        op = MockPcodeOp()
        assert not ef.applyRule(sv, op, False, None)

    def test_applyRule_no_both_pieces(self):
        ef = Equal2Form()
        sv = SplitVarnode()
        sv.lo = MockVarnode()
        op = MockPcodeOp()
        assert not ef.applyRule(sv, op, True, None)


class TestEqual3Form:
    def test_verify_not_and(self):
        ef = Equal3Form()
        h = MockVarnode()
        l = MockVarnode()
        aop = MockPcodeOp(opc=OpCode.CPUI_INT_OR)
        assert not ef.verify(h, l, aop)

    def test_applyRule_not_workishi(self):
        ef = Equal3Form()
        sv = SplitVarnode()
        op = MockPcodeOp()
        assert not ef.applyRule(sv, op, False, None)


class TestLessConstForm:
    def test_applyRule_not_workishi(self):
        lc = LessConstForm()
        sv = SplitVarnode()
        op = MockPcodeOp()
        assert not lc.applyRule(sv, op, False, None)

    def test_applyRule_no_hi(self):
        lc = LessConstForm()
        sv = SplitVarnode()
        sv.lo = MockVarnode()
        op = MockPcodeOp()
        assert not lc.applyRule(sv, op, True, None)


class TestLessThreeWay:
    def test_applyRule_stub(self):
        lt = LessThreeWay()
        sv = SplitVarnode()
        op = MockPcodeOp()
        assert not lt.applyRule(sv, op, True, None)


class TestShiftForm:
    def test_applyRuleLeft_stub(self):
        sf = ShiftForm()
        sv = SplitVarnode()
        op = MockPcodeOp()
        assert not sf.applyRuleLeft(sv, op, True, None)

    def test_applyRuleRight_stub(self):
        sf = ShiftForm()
        sv = SplitVarnode()
        op = MockPcodeOp()
        assert not sf.applyRuleRight(sv, op, True, None)


class TestMultForm:
    def test_applyRule_stub(self):
        mf = MultForm()
        sv = SplitVarnode()
        op = MockPcodeOp()
        assert not mf.applyRule(sv, op, True, None)


class TestPhiForm:
    def test_applyRule_not_workishi(self):
        pf = PhiForm()
        sv = SplitVarnode()
        op = MockPcodeOp()
        assert not pf.applyRule(sv, op, False, None)

    def test_applyRule_not_multiequal(self):
        pf = PhiForm()
        sv = SplitVarnode()
        sv.lo = MockVarnode()
        sv.hi = MockVarnode()
        op = MockPcodeOp(opc=OpCode.CPUI_COPY)
        assert not pf.applyRule(sv, op, True, None)


class TestIndirectForm:
    def test_applyRule_not_workishi(self):
        idf = IndirectForm()
        sv = SplitVarnode()
        op = MockPcodeOp()
        assert not idf.applyRule(sv, op, False, None)

    def test_applyRule_not_indirect(self):
        idf = IndirectForm()
        sv = SplitVarnode()
        sv.lo = MockVarnode()
        sv.hi = MockVarnode()
        op = MockPcodeOp(opc=OpCode.CPUI_COPY)
        assert not idf.applyRule(sv, op, True, None)


class TestCopyForceForm:
    def test_applyRule_no_both_pieces(self):
        cf = CopyForceForm()
        sv = SplitVarnode()
        sv.lo = MockVarnode()
        op = MockPcodeOp()
        assert not cf.applyRule(sv, op, True, None)


# ---------------------------------------------------------------------------
# Rule class tests
# ---------------------------------------------------------------------------

class TestRuleDoubleIn:
    def test_init(self):
        r = RuleDoubleIn('test')
        assert r.getName() == 'doublein'
        assert r.getGroup() == 'test'

    def test_getOpList(self):
        r = RuleDoubleIn()
        assert int(OpCode.CPUI_SUBPIECE) in r.getOpList()

    def test_clone(self):
        r = RuleDoubleIn('grp')
        c = r.clone()
        assert isinstance(c, RuleDoubleIn)
        assert c.getGroup() == 'grp'

    def test_applyOp_no_output(self):
        r = RuleDoubleIn()
        op = MockPcodeOp(opc=OpCode.CPUI_SUBPIECE, output=None)
        assert r.applyOp(op, None) == 0

    def test_applyOp_no_precis(self):
        r = RuleDoubleIn()
        outvn = MockVarnode(precis_hi=False, precis_lo=False)
        op = MockPcodeOp(opc=OpCode.CPUI_SUBPIECE, output=outvn)
        assert r.applyOp(op, None) == 0


class TestRuleDoubleOut:
    def test_init(self):
        r = RuleDoubleOut('test')
        assert r.getName() == 'doubleout'

    def test_getOpList(self):
        r = RuleDoubleOut()
        assert int(OpCode.CPUI_PIECE) in r.getOpList()

    def test_clone(self):
        r = RuleDoubleOut('grp')
        c = r.clone()
        assert isinstance(c, RuleDoubleOut)

    def test_applyOp_no_output(self):
        r = RuleDoubleOut()
        op = MockPcodeOp(opc=OpCode.CPUI_PIECE, output=None)
        assert r.applyOp(op, None) == 0

    def test_applyOp_no_splits(self):
        r = RuleDoubleOut()
        outvn = MockVarnode(size=8)
        op = MockPcodeOp(opc=OpCode.CPUI_PIECE, output=outvn)
        assert r.applyOp(op, None) == 0


class TestRuleDoubleLoad:
    def test_init(self):
        r = RuleDoubleLoad('test')
        assert r.getName() == 'doubleload'

    def test_getOpList(self):
        r = RuleDoubleLoad()
        assert int(OpCode.CPUI_PIECE) in r.getOpList()


class TestRuleDoubleStore:
    def test_init(self):
        r = RuleDoubleStore('test')
        assert r.getName() == 'doublestore'

    def test_getOpList(self):
        r = RuleDoubleStore()
        assert int(OpCode.CPUI_STORE) in r.getOpList()


# ---------------------------------------------------------------------------
# SplitVarnode wholeList / findCopies
# ---------------------------------------------------------------------------

class TestWholeList:
    def test_empty(self):
        w = MockVarnode(size=8)
        splitvec = []
        SplitVarnode.wholeList(w, splitvec)
        assert len(splitvec) == 0

    def test_with_subpieces(self):
        w = MockVarnode(size=8)
        lo = MockVarnode(size=4, precis_lo=True)
        hi = MockVarnode(size=4, precis_hi=True)
        lo_const = MockVarnode(size=4, offset=0, is_const=True)
        hi_const = MockVarnode(size=4, offset=4, is_const=True)
        sub_lo = MockPcodeOp(opc=OpCode.CPUI_SUBPIECE, inputs=[w, lo_const], output=lo)
        sub_hi = MockPcodeOp(opc=OpCode.CPUI_SUBPIECE, inputs=[w, hi_const], output=hi)
        w._descendants = [sub_lo, sub_hi]
        splitvec = []
        SplitVarnode.wholeList(w, splitvec)
        assert len(splitvec) >= 1
        assert splitvec[0].getWhole() is w
        assert splitvec[0].getLo() is lo
        assert splitvec[0].getHi() is hi


# ---------------------------------------------------------------------------
# SplitVarnode findWholeSplitToPieces / findWholeBuiltFromPieces
# ---------------------------------------------------------------------------

class TestFindWholeSplitToPieces:
    def test_already_has_whole(self):
        bl = MockBlock()
        defop = MockPcodeOp(parent=bl)
        w = MockVarnode(size=8, is_written=True)
        w._def = defop
        sv = SplitVarnode()
        sv.whole = w
        sv.wholesize = 8
        assert sv.findWholeSplitToPieces()
        assert sv.defpoint is defop

    def test_no_pieces(self):
        sv = SplitVarnode()
        assert not sv.findWholeSplitToPieces()


class TestFindWholeBuiltFromPieces:
    def test_no_pieces(self):
        sv = SplitVarnode()
        assert not sv.findWholeBuiltFromPieces()

    def test_no_piece_op(self):
        sv = SplitVarnode()
        bl = MockBlock()
        lo_op = MockPcodeOp(parent=bl)
        sv.lo = MockVarnode(is_written=True)
        sv.lo._def = lo_op
        sv.hi = MockVarnode()
        sv.lo._descendants = []  # no PIECE descendants
        assert not sv.findWholeBuiltFromPieces()
