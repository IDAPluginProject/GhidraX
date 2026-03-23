"""Tests for deepened rule infrastructure: constseq, condexe, prefersplit, rulecompile, universal wiring."""
import pytest
import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', 'python'))


# =========================================================================
# constseq tests
# =========================================================================

class TestWriteNode:
    def test_basic_construction(self):
        from ghidra.analysis.constseq import WriteNode
        wn = WriteNode(0x100, None, 2)
        assert wn.offset == 0x100
        assert wn.op is None
        assert wn.slot == 2

    def test_default_construction(self):
        from ghidra.analysis.constseq import WriteNode
        wn = WriteNode()
        assert wn.offset == 0
        assert wn.op is None
        assert wn.slot == 0


class TestArraySequence:
    def test_constants(self):
        from ghidra.analysis.constseq import ArraySequence
        assert ArraySequence.MINIMUM_SEQUENCE_LENGTH == 4
        assert ArraySequence.MAXIMUM_SEQUENCE_LENGTH == 0x20000

    def test_basic_construction(self):
        from ghidra.analysis.constseq import ArraySequence
        seq = ArraySequence()
        assert seq.rootOp is None
        assert seq.charType is None
        assert seq.block is None
        assert seq.numElements == 0
        assert seq.moveOps == []
        assert seq.byteArray == []

    def test_construction_with_args(self):
        from ghidra.analysis.constseq import ArraySequence
        seq = ArraySequence(fd="fakefd", ct="chartype", root="rootop")
        assert seq._fd == "fakefd"
        assert seq.charType == "chartype"
        assert seq.rootOp == "rootop"


class TestStringSequence:
    def test_basic_construction(self):
        from ghidra.analysis.constseq import StringSequence
        seq = StringSequence()
        assert seq.rootOp is None
        assert seq._fd is None
        assert seq.moveOps == []
        assert seq.byteArray == []


class TestHeapSequence:
    def test_basic_construction(self):
        from ghidra.analysis.constseq import HeapSequence
        seq = HeapSequence()
        assert seq.rootOp is None
        assert seq._fd is None
        assert seq.moveOps == []
        assert seq.byteArray == []


class TestIndirectPair:
    def test_construction(self):
        from ghidra.analysis.constseq import IndirectPair
        pair = IndirectPair("vn1", "vn2")
        assert pair.inVn == "vn1"
        assert pair.outVn == "vn2"


class TestConstSequence:
    def test_basic_construction(self):
        from ghidra.analysis.constseq import ConstSequence
        cs = ConstSequence()
        assert cs._fd is None
        assert cs.getNumStrings() == 0
        assert cs.getArrays() == []

    def test_clear(self):
        from ghidra.analysis.constseq import ConstSequence
        cs = ConstSequence()
        cs.clear()
        assert cs.getNumStrings() == 0

    def test_analyze_block_none(self):
        from ghidra.analysis.constseq import ConstSequence
        cs = ConstSequence()
        assert cs.analyzeBlock(None) is False


# =========================================================================
# condexe tests
# =========================================================================

class TestMultiPredicate:
    def test_basic_construction(self):
        from ghidra.transform.condexe import _MultiPredicate
        mp = _MultiPredicate()
        assert mp.op is None
        assert mp.zeroSlot == 0
        assert mp.zeroBlock is None
        assert mp.condBlock is None
        assert mp.cbranch is None
        assert mp.otherVn is None
        assert mp.zeroPathIsTrue is False


class TestRuleOrPredicate:
    def test_oplist(self):
        from ghidra.transform.condexe import RuleOrPredicate
        from ghidra.core.opcodes import OpCode
        rop = RuleOrPredicate("test")
        ops = rop.getOpList()
        assert OpCode.CPUI_INT_OR in ops
        assert OpCode.CPUI_INT_XOR in ops
        assert len(ops) == 2


# =========================================================================
# prefersplit tests
# =========================================================================

class TestLanedRegister:
    def test_basic(self):
        from ghidra.analysis.prefersplit import LanedRegister
        lr = LanedRegister(16)
        assert lr.getWholeSize() == 16
        lr.addLaneSize(4)
        lr.addLaneSize(8)
        assert lr.supportsSplit(4) is True
        assert lr.supportsSplit(2) is False
        assert lr.getNumLanes(4) == 4
        assert lr.getNumLanes(8) == 2
        assert lr.getNumLanes(0) == 0


class TestPreferSplitRecord:
    def test_basic(self):
        from ghidra.analysis.prefersplit import PreferSplitRecord
        from ghidra.core.address import Address
        rec = PreferSplitRecord()
        rec.init(Address(None, 0x100), 4, 8)
        assert rec.getAddress() == Address(None, 0x100)
        assert rec.getSplitSize() == 4
        assert rec.getTotalSize() == 8
        assert rec.getNumLanes() == 2

    def test_zero_split(self):
        from ghidra.analysis.prefersplit import PreferSplitRecord
        rec = PreferSplitRecord()
        assert rec.getNumLanes() == 0


class TestPreferSplitManager:
    def test_basic_lifecycle(self):
        from ghidra.analysis.prefersplit import PreferSplitManager, PreferSplitRecord
        from ghidra.core.address import Address
        mgr = PreferSplitManager()
        assert mgr.numRecords() == 0

        rec = PreferSplitRecord()
        rec.init(Address(None, 0x100), 4, 8)
        mgr.addRecord(rec)
        assert mgr.numRecords() == 1
        assert mgr.hasSplit(Address(None, 0x100), 8) is True
        assert mgr.hasSplit(Address(None, 0x200), 8) is False

    def test_clear(self):
        from ghidra.analysis.prefersplit import PreferSplitManager, PreferSplitRecord
        from ghidra.core.address import Address
        mgr = PreferSplitManager()
        rec = PreferSplitRecord()
        rec.init(Address(None, 0), 2, 4)
        mgr.addRecord(rec)
        mgr.clear()
        assert mgr.numRecords() == 0

    def test_initialize_sorts(self):
        from ghidra.analysis.prefersplit import PreferSplitManager, PreferSplitRecord
        from ghidra.core.address import Address
        records = []
        r1 = PreferSplitRecord()
        r1.init(Address(None, 0x200), 4, 8)
        r2 = PreferSplitRecord()
        r2.init(Address(None, 0x100), 4, 8)
        records.append(r1)
        records.append(r2)
        PreferSplitManager.initialize(records)
        assert records[0].storage < records[1].storage or records[0].storage == records[1].storage

    def test_calc_mask(self):
        from ghidra.analysis.prefersplit import _calc_mask
        assert _calc_mask(1) == 0xFF
        assert _calc_mask(2) == 0xFFFF
        assert _calc_mask(4) == 0xFFFFFFFF
        assert _calc_mask(8) == 0xFFFFFFFFFFFFFFFF
        assert _calc_mask(16) == 0xFFFFFFFFFFFFFFFF

    def test_iptr_internal_constant(self):
        from ghidra.analysis.prefersplit import PreferSplitManager
        assert PreferSplitManager.IPTR_INTERNAL == 4

    def test_split_instance(self):
        from ghidra.analysis.prefersplit import PreferSplitManager
        inst = PreferSplitManager.SplitInstance(None, 4)
        assert inst.splitoffset == 4
        assert inst.vn is None
        assert inst.hi is None
        assert inst.lo is None


# =========================================================================
# rulecompile tests
# =========================================================================

class TestRuleLexer:
    def test_basic_tokenize(self):
        from ghidra.transform.rulecompile import RuleLexer
        lex = RuleLexer()
        lex.initialize("op1 INT_ADD")
        tok = lex.nextToken()
        # Should produce at least one non-EOF token
        assert tok is not None

    def test_empty_input(self):
        from ghidra.transform.rulecompile import RuleLexer
        lex = RuleLexer()
        lex.initialize("")
        tok = lex.nextToken()
        # EOF token
        assert tok is not None


class TestRuleCompile:
    def test_construction(self):
        from ghidra.transform.rulecompile import RuleCompile
        rc = RuleCompile()
        assert rc is not None


class TestRuleGeneric:
    def test_construction(self):
        from ghidra.transform.rulecompile import RuleGeneric
        from ghidra.core.opcodes import OpCode
        rg = RuleGeneric("testgroup", "testrule", [OpCode.CPUI_COPY], 0, None)
        assert rg._name == "testrule"
        assert rg.getGroup() == "testgroup"

    def test_getOpList(self):
        from ghidra.transform.rulecompile import RuleGeneric
        from ghidra.core.opcodes import OpCode
        rg = RuleGeneric("g", "n", [OpCode.CPUI_COPY, OpCode.CPUI_INT_ADD], 0, None)
        ops = rg.getOpList()
        assert len(ops) == 2
        assert OpCode.CPUI_COPY in ops
        assert OpCode.CPUI_INT_ADD in ops


# =========================================================================
# universal.py wiring tests
# =========================================================================

class TestUniversalDynamicRules:
    def test_extra_pool_rules_wiring_in_source(self):
        """Verify the universal.py source contains the extra_pool_rules wiring."""
        py_path = os.path.join(os.path.dirname(__file__), '..', 'python',
                               'ghidra', 'transform', 'universal.py')
        src = open(py_path).read()
        assert 'extra_pool_rules' in src
        assert 'conf.extra_pool_rules' in src

    def test_architecture_has_extra_pool_rules(self):
        """Architecture class should have extra_pool_rules attribute."""
        from ghidra.arch.architecture import Architecture
        # Can't fully instantiate, but check class definition
        import inspect
        source = inspect.getsource(Architecture.__init__)
        assert 'extra_pool_rules' in source


# =========================================================================
# RuleConditionalMove tests
# =========================================================================

class _MockVarnode:
    """Minimal Varnode mock for RuleConditionalMove tests."""
    def __init__(self, *, const_val=None, written=False, free=False, addr_tied=False):
        self._const = const_val is not None
        self._offset = const_val if const_val is not None else 0
        self._written = written
        self._free = free
        self._addr_tied = addr_tied
        self._def = None
    def isConstant(self): return self._const
    def getOffset(self): return self._offset
    def isWritten(self): return self._written
    def isFree(self): return self._free
    def isAddrTied(self): return self._addr_tied
    def getDef(self): return self._def
    def loneDescend(self): return None

class _MockOp:
    """Minimal PcodeOp mock for RuleConditionalMove tests."""
    def __init__(self, opcode, *, bool_output=False, parent=None):
        self._code = opcode
        self._bool_output = bool_output
        self._inputs = []
        self._parent = parent
    def code(self): return self._code
    def isBoolOutput(self): return self._bool_output
    def getIn(self, i): return self._inputs[i]
    def numInput(self): return len(self._inputs)
    def getParent(self): return self._parent
    def getEvalType(self): return 0  # not special


class TestRuleConditionalMoveCheckBoolean:
    def _rule(self):
        from ghidra.transform.ruleaction_batch2a import RuleConditionalMove
        return RuleConditionalMove

    def test_not_written_returns_none(self):
        cls = self._rule()
        vn = _MockVarnode(free=True)
        assert cls.checkBoolean(vn) is None

    def test_bool_output_op_returns_vn(self):
        from ghidra.core.opcodes import OpCode
        cls = self._rule()
        vn = _MockVarnode(written=True)
        op = _MockOp(OpCode.CPUI_INT_EQUAL, bool_output=True)
        vn._def = op
        result = cls.checkBoolean(vn)
        assert result is vn

    def test_copy_of_const_0_returns_const(self):
        from ghidra.core.opcodes import OpCode
        cls = self._rule()
        const0 = _MockVarnode(const_val=0)
        vn = _MockVarnode(written=True)
        op = _MockOp(OpCode.CPUI_COPY)
        op._inputs = [const0]
        vn._def = op
        result = cls.checkBoolean(vn)
        assert result is const0

    def test_copy_of_const_1_returns_const(self):
        from ghidra.core.opcodes import OpCode
        cls = self._rule()
        const1 = _MockVarnode(const_val=1)
        vn = _MockVarnode(written=True)
        op = _MockOp(OpCode.CPUI_COPY)
        op._inputs = [const1]
        vn._def = op
        result = cls.checkBoolean(vn)
        assert result is const1

    def test_copy_of_const_2_returns_none(self):
        from ghidra.core.opcodes import OpCode
        cls = self._rule()
        const2 = _MockVarnode(const_val=2)
        vn = _MockVarnode(written=True)
        op = _MockOp(OpCode.CPUI_COPY)
        op._inputs = [const2]
        vn._def = op
        assert cls.checkBoolean(vn) is None

    def test_non_bool_non_copy_returns_none(self):
        from ghidra.core.opcodes import OpCode
        cls = self._rule()
        vn = _MockVarnode(written=True)
        op = _MockOp(OpCode.CPUI_INT_ADD)
        vn._def = op
        assert cls.checkBoolean(vn) is None


class TestRuleConditionalMoveGatherExpression:
    def _rule(self):
        from ghidra.transform.ruleaction_batch2a import RuleConditionalMove
        return RuleConditionalMove

    def test_constant_always_propagates(self):
        cls = self._rule()
        vn = _MockVarnode(const_val=42)
        ops = []
        assert cls.gatherExpression(vn, ops, "root", "branch") is True
        assert len(ops) == 0

    def test_free_non_const_fails(self):
        cls = self._rule()
        vn = _MockVarnode(free=True)
        assert cls.gatherExpression(vn, [], "root", "branch") is False

    def test_addr_tied_fails(self):
        cls = self._rule()
        vn = _MockVarnode(addr_tied=True)
        assert cls.gatherExpression(vn, [], "root", "branch") is False

    def test_root_is_branch_always_ok(self):
        cls = self._rule()
        vn = _MockVarnode(written=True)
        sentinel = object()
        assert cls.gatherExpression(vn, [], sentinel, sentinel) is True

    def test_not_written_propagates(self):
        cls = self._rule()
        vn = _MockVarnode()  # not written, not free, not const
        assert cls.gatherExpression(vn, [], "root", "branch") is True

    def test_written_outside_branch_propagates(self):
        from ghidra.core.opcodes import OpCode
        cls = self._rule()
        vn = _MockVarnode(written=True)
        op = _MockOp(OpCode.CPUI_INT_ADD, parent="other_block")
        vn._def = op
        ops = []
        assert cls.gatherExpression(vn, ops, "root", "branch") is True
        assert len(ops) == 0


class TestMarshalConstants:
    def test_attrib_group_exists(self):
        from ghidra.core.marshal import ATTRIB_GROUP
        assert ATTRIB_GROUP is not None

    def test_attrib_enable_exists(self):
        from ghidra.core.marshal import ATTRIB_ENABLE
        assert ATTRIB_ENABLE is not None

    def test_elem_rule_exists(self):
        from ghidra.core.marshal import ELEM_RULE
        assert ELEM_RULE is not None
