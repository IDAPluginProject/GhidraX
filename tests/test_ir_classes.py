"""
Phase 2: Unit tests for IR layer classes.
Tests PcodeOp, PcodeOpBank, CoverBlock, Cover, HighVariable, VariableGroup, VariablePiece, PieceNode.
"""

import sys
import os
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', 'python'))

import pytest
from ghidra.core.space import AddrSpace, AddrSpaceManager, ConstantSpace, UniqueSpace, IPTR_PROCESSOR, IPTR_CONSTANT
from ghidra.core.address import Address, SeqNum
from ghidra.core.opcodes import OpCode
from ghidra.ir.op import PcodeOp, PcodeOpBank, PieceNode
from ghidra.ir.cover import CoverBlock, Cover
from ghidra.ir.varnode import Varnode
from ghidra.ir.variable import HighVariable, VariableGroup, VariablePiece
from ghidra.transform.ruleaction import RuleCollapseConstants


# =========================================================================
# Fixtures
# =========================================================================

@pytest.fixture
def spc_mgr():
    mgr = AddrSpaceManager()
    cs = ConstantSpace(mgr)
    mgr._insertSpace(cs)
    mgr._constantSpace = cs
    ram = AddrSpace(mgr, None, IPTR_PROCESSOR, "ram", False, 4, 1, 1,
                    AddrSpace.hasphysical | AddrSpace.heritaged | AddrSpace.does_deadcode, 0, 0)
    mgr._insertSpace(ram)
    mgr.setDefaultCodeSpace(ram)
    reg = AddrSpace(mgr, None, IPTR_PROCESSOR, "register", False, 4, 1, 2,
                    AddrSpace.hasphysical | AddrSpace.heritaged, 0, 0)
    mgr._insertSpace(reg)
    uniq = UniqueSpace(mgr, None, 3)
    mgr._insertSpace(uniq)
    mgr._uniqueSpace = uniq
    return mgr


@pytest.fixture
def ram(spc_mgr):
    return spc_mgr.getSpaceByName("ram")


@pytest.fixture
def reg(spc_mgr):
    return spc_mgr.getSpaceByName("register")


@pytest.fixture
def const_spc(spc_mgr):
    return spc_mgr.getConstantSpace()


# =========================================================================
# PcodeOp Tests
# =========================================================================

class TestPcodeOp:
    def test_creation(self, ram):
        sq = SeqNum(Address(ram, 0x1000), 0)
        op = PcodeOp(2, sq)
        assert op.numInput() == 2
        assert op.getOut() is None
        assert op.getAddr() == Address(ram, 0x1000)
        assert op.getSeqNum() is sq
        assert op.code() == OpCode.CPUI_BLANK

    def test_opcode_enum(self, ram):
        sq = SeqNum(Address(ram, 0x1000), 0)
        op = PcodeOp(2, sq)
        op.setOpcodeEnum(OpCode.CPUI_COPY)
        assert op.code() == OpCode.CPUI_COPY

    def test_input_output(self, ram, reg):
        sq = SeqNum(Address(ram, 0x1000), 0)
        op = PcodeOp(2, sq)
        vn_out = Varnode(4, Address(reg, 0), 0)
        vn_in0 = Varnode(4, Address(reg, 8), 1)
        vn_in1 = Varnode(4, Address(reg, 16), 2)

        op.setOutput(vn_out)
        op.setInput(vn_in0, 0)
        op.setInput(vn_in1, 1)

        assert op.getOut() is vn_out
        assert op.getIn(0) is vn_in0
        assert op.getIn(1) is vn_in1
        assert op.isAssignment()

    def test_get_slot(self, ram, reg):
        sq = SeqNum(Address(ram, 0x1000), 0)
        op = PcodeOp(3, sq)
        vn0 = Varnode(4, Address(reg, 0), 0)
        vn1 = Varnode(4, Address(reg, 8), 1)
        vn2 = Varnode(4, Address(reg, 16), 2)
        op.setInput(vn0, 0)
        op.setInput(vn1, 1)
        op.setInput(vn2, 2)

        assert op.getSlot(vn0) == 0
        assert op.getSlot(vn1) == 1
        assert op.getSlot(vn2) == 2

    def test_flags_basic(self, ram):
        sq = SeqNum(Address(ram, 0x1000), 0)
        op = PcodeOp(0, sq)
        assert not op.isDead()
        assert not op.isCall()
        assert not op.isMarker()
        assert not op.isBranch()

    def test_flags_set_clear(self, ram):
        sq = SeqNum(Address(ram, 0x1000), 0)
        op = PcodeOp(0, sq)
        op.setFlag(PcodeOp.call)
        assert op.isCall()
        op.clearFlag(PcodeOp.call)
        assert not op.isCall()

    def test_flags_dead(self, ram):
        sq = SeqNum(Address(ram, 0x1000), 0)
        op = PcodeOp(0, sq)
        op.setFlag(PcodeOp.dead)
        assert op.isDead()

    def test_flags_branch(self, ram):
        sq = SeqNum(Address(ram, 0x1000), 0)
        op = PcodeOp(0, sq)
        op.setFlag(PcodeOp.branch)
        assert op.isBranch()
        assert op.isFlowBreak()
        assert op.isCallOrBranch()

    def test_flags_returns(self, ram):
        sq = SeqNum(Address(ram, 0x1000), 0)
        op = PcodeOp(0, sq)
        op.setFlag(PcodeOp.returns)
        assert op.isFlowBreak()

    def test_flags_marker(self, ram):
        sq = SeqNum(Address(ram, 0x1000), 0)
        op = PcodeOp(0, sq)
        op.setFlag(PcodeOp.marker)
        assert op.isMarker()
        assert op.notPrinted()

    def test_flags_boolean_flip(self, ram):
        sq = SeqNum(Address(ram, 0x1000), 0)
        op = PcodeOp(0, sq)
        assert not op.isBooleanFlip()
        op.flipFlag(PcodeOp.boolean_flip)
        assert op.isBooleanFlip()
        op.flipFlag(PcodeOp.boolean_flip)
        assert not op.isBooleanFlip()

    def test_flags_mark(self, ram):
        sq = SeqNum(Address(ram, 0x1000), 0)
        op = PcodeOp(0, sq)
        assert not op.isMark()
        op.setMark()
        assert op.isMark()
        op.clearMark()
        assert not op.isMark()

    def test_additional_flags(self, ram):
        sq = SeqNum(Address(ram, 0x1000), 0)
        op = PcodeOp(0, sq)
        assert not op.isModified()
        op.setAdditionalFlag(PcodeOp.modified)
        assert op.isModified()
        op.clearAdditionalFlag(PcodeOp.modified)
        assert not op.isModified()

    def test_special_print(self, ram):
        sq = SeqNum(Address(ram, 0x1000), 0)
        op = PcodeOp(0, sq)
        assert not op.doesSpecialPrinting()
        op.setAdditionalFlag(PcodeOp.special_print)
        assert op.doesSpecialPrinting()

    def test_stop_type_propagation(self, ram):
        sq = SeqNum(Address(ram, 0x1000), 0)
        op = PcodeOp(0, sq)
        assert not op.stopsTypePropagation()
        op.setStopTypePropagation()
        assert op.stopsTypePropagation()
        op.clearStopTypePropagation()
        assert not op.stopsTypePropagation()

    def test_hold_output(self, ram):
        sq = SeqNum(Address(ram, 0x1000), 0)
        op = PcodeOp(0, sq)
        assert not op.holdOutput()
        op.setHoldOutput()
        assert op.holdOutput()

    def test_indirect_source(self, ram):
        sq = SeqNum(Address(ram, 0x1000), 0)
        op = PcodeOp(0, sq)
        assert not op.isIndirectSource()
        op.setIndirectSource()
        assert op.isIndirectSource()
        op.clearIndirectSource()
        assert not op.isIndirectSource()

    def test_eval_type(self, ram):
        sq = SeqNum(Address(ram, 0x1000), 0)
        op = PcodeOp(0, sq)
        op.setFlag(PcodeOp.binary)
        assert op.getEvalType() == PcodeOp.binary

    def test_halt_type(self, ram):
        sq = SeqNum(Address(ram, 0x1000), 0)
        op = PcodeOp(0, sq)
        op.setHaltType(PcodeOp.halt | PcodeOp.noreturn)
        assert op.getHaltType() == (PcodeOp.halt | PcodeOp.noreturn)

    def test_set_num_inputs(self, ram):
        sq = SeqNum(Address(ram, 0x1000), 0)
        op = PcodeOp(2, sq)
        assert op.numInput() == 2
        op.setNumInputs(4)
        assert op.numInput() == 4
        op.setNumInputs(1)
        assert op.numInput() == 1

    def test_remove_input(self, ram, reg):
        sq = SeqNum(Address(ram, 0x1000), 0)
        op = PcodeOp(3, sq)
        vn0 = Varnode(4, Address(reg, 0), 0)
        vn1 = Varnode(4, Address(reg, 8), 1)
        vn2 = Varnode(4, Address(reg, 16), 2)
        op.setInput(vn0, 0)
        op.setInput(vn1, 1)
        op.setInput(vn2, 2)
        op.removeInput(1)
        assert op.numInput() == 2
        assert op.getIn(0) is vn0
        assert op.getIn(1) is vn2

    def test_insert_input(self, ram, reg):
        sq = SeqNum(Address(ram, 0x1000), 0)
        op = PcodeOp(2, sq)
        vn0 = Varnode(4, Address(reg, 0), 0)
        vn1 = Varnode(4, Address(reg, 8), 1)
        op.setInput(vn0, 0)
        op.setInput(vn1, 1)
        op.insertInput(1)
        assert op.numInput() == 3
        assert op.getIn(0) is vn0
        assert op.getIn(1) is None
        assert op.getIn(2) is vn1

    def test_set_all_input(self, ram, reg):
        sq = SeqNum(Address(ram, 0x1000), 0)
        op = PcodeOp(0, sq)
        vn0 = Varnode(4, Address(reg, 0), 0)
        vn1 = Varnode(4, Address(reg, 8), 1)
        op.setAllInput([vn0, vn1])
        assert op.numInput() == 2
        assert op.getIn(0) is vn0
        assert op.getIn(1) is vn1

    def test_cse_hash(self, ram, reg, const_spc):
        sq1 = SeqNum(Address(ram, 0x1000), 0)
        op1 = PcodeOp(2, sq1)
        op1.setOpcodeEnum(OpCode.CPUI_INT_ADD)
        vn_out = Varnode(4, Address(reg, 0), 0)
        op1.setOutput(vn_out)
        vn_c = Varnode(4, Address(const_spc, 42), 1)
        vn_c.setFlags(Varnode.constant)
        op1.setInput(vn_c, 0)
        h = op1.getCseHash()
        assert h != 0

        # Same opcode + same constant input => same hash
        sq2 = SeqNum(Address(ram, 0x1004), 1)
        op2 = PcodeOp(2, sq2)
        op2.setOpcodeEnum(OpCode.CPUI_INT_ADD)
        vn_out2 = Varnode(4, Address(reg, 4), 2)
        op2.setOutput(vn_out2)
        op2.setInput(vn_c, 0)
        assert op2.getCseHash() == h

    def test_cse_hash_no_output(self, ram):
        sq = SeqNum(Address(ram, 0x1000), 0)
        op = PcodeOp(0, sq)
        op.setOpcodeEnum(OpCode.CPUI_BRANCH)
        assert op.getCseHash() == 0

    def test_cse_match(self, ram, reg):
        sq1 = SeqNum(Address(ram, 0x1000), 0)
        sq2 = SeqNum(Address(ram, 0x1004), 1)
        op1 = PcodeOp(1, sq1)
        op2 = PcodeOp(1, sq2)
        vn = Varnode(4, Address(reg, 0), 0)
        op1.setOpcodeEnum(OpCode.CPUI_COPY)
        op2.setOpcodeEnum(OpCode.CPUI_COPY)
        op1.setInput(vn, 0)
        op2.setInput(vn, 0)
        assert op1.isCseMatch(op2)

    def test_cse_match_different_opcode(self, ram, reg):
        sq1 = SeqNum(Address(ram, 0x1000), 0)
        sq2 = SeqNum(Address(ram, 0x1004), 1)
        op1 = PcodeOp(1, sq1)
        op2 = PcodeOp(1, sq2)
        vn = Varnode(4, Address(reg, 0), 0)
        op1.setOpcodeEnum(OpCode.CPUI_COPY)
        op2.setOpcodeEnum(OpCode.CPUI_INT_NEGATE)
        op1.setInput(vn, 0)
        op2.setInput(vn, 0)
        assert not op1.isCseMatch(op2)

    def test_compare_order_same_block(self, ram):
        """Two ops in the same block, different order."""
        class FakeBlock:
            def getIndex(self): return 0
        blk = FakeBlock()

        sq1 = SeqNum(Address(ram, 0x1000), 5)
        sq1.setOrder(5)
        sq2 = SeqNum(Address(ram, 0x1000), 10)
        sq2.setOrder(10)
        op1 = PcodeOp(0, sq1)
        op2 = PcodeOp(0, sq2)
        op1.setParent(blk)
        op2.setParent(blk)
        assert op1.compareOrder(op2) == -1
        assert op2.compareOrder(op1) == 1
        assert op1.compareOrder(op1) == 0

    def test_compare_order_different_block(self, ram):
        class FakeBlock:
            def __init__(self, idx): self._idx = idx
            def getIndex(self): return self._idx
        blk0 = FakeBlock(0)
        blk1 = FakeBlock(1)

        sq1 = SeqNum(Address(ram, 0x1000), 100)
        sq2 = SeqNum(Address(ram, 0x2000), 0)
        op1 = PcodeOp(0, sq1)
        op2 = PcodeOp(0, sq2)
        op1.setParent(blk0)
        op2.setParent(blk1)
        assert op1.compareOrder(op2) == -1
        assert op2.compareOrder(op1) == 1

    def test_collapsible(self, ram, reg):
        sq = SeqNum(Address(ram, 0x1000), 0)
        op = PcodeOp(1, sq)
        # No output => not collapsible
        assert not op.isCollapsible()
        # With output => collapsible
        vn = Varnode(4, Address(reg, 0), 0)
        op.setOutput(vn)
        assert op.isCollapsible()
        # nocollapse flag
        op.setFlag(PcodeOp.nocollapse)
        assert not op.isCollapsible()

    def test_get_eval_type_falls_back_from_opcode_behavior(self, ram, reg, const_spc):
        sq = SeqNum(Address(ram, 0x1000), 0)
        op = PcodeOp(2, sq)
        op.setOpcodeEnum(OpCode.CPUI_INT_ADD)
        op.setOutput(Varnode(4, Address(reg, 0), 0))
        op.setInput(Varnode(4, Address(const_spc, 1), 1), 0)
        op.setInput(Varnode(4, Address(const_spc, 2), 2), 1)

        assert op.getEvalType() == PcodeOp.binary

    def test_collapse_and_symbol_propagation_follow_cpp_semantics(self, ram, reg, const_spc):
        class _FakeSymbol:
            def isNameLocked(self):
                return False

        class _FakeEntry:
            def __init__(self):
                self._sym = _FakeSymbol()

            def getSymbol(self):
                return self._sym

        sq = SeqNum(Address(ram, 0x1000), 0)
        op = PcodeOp(2, sq)
        op.setOpcodeEnum(OpCode.CPUI_INT_ADD)
        op.setOutput(Varnode(4, Address(reg, 0), 0))

        vn0 = Varnode(4, Address(const_spc, 5), 1)
        vn1 = Varnode(4, Address(const_spc, 7), 2)
        entry = _FakeEntry()
        vn0.setSymbolEntry(entry)
        op.setInput(vn0, 0)
        op.setInput(vn1, 1)

        marked = [False]
        result = op.collapse(marked)

        assert result == 12
        assert marked[0] is True

        new_const = Varnode(4, Address(const_spc, result), 3)
        op.collapseConstantSymbol(new_const)
        assert new_const.getSymbolEntry() is entry

    def test_get_nzmask_local_multiequal_honors_cliploop(self, ram, reg, const_spc):
        class _LoopParent:
            def isLoopIn(self, i):
                return i == 1

        sq = SeqNum(Address(ram, 0x1000), 0)
        op = PcodeOp(2, sq)
        op.setOpcodeEnum(OpCode.CPUI_MULTIEQUAL)
        op.setOutput(Varnode(1, Address(reg, 0), 0))
        op.setInput(Varnode(1, Address(const_spc, 0x0F), 1), 0)
        op.setInput(Varnode(1, Address(const_spc, 0xF0), 2), 1)
        op.setParent(_LoopParent())

        assert op.getNZMaskLocal(True) == 0x0F
        assert op.getNZMaskLocal(False) == 0xFF


class TestRuleCollapseConstants:
    def test_rule_uses_pcodeop_collapse_and_propagates_symbol(self, ram, reg, const_spc):
        class _FakeSymbol:
            def isNameLocked(self):
                return False

        class _FakeEntry:
            def __init__(self):
                self._sym = _FakeSymbol()

            def getSymbol(self):
                return self._sym

        class _FakeData:
            def __init__(self):
                self.marked_no_collapse = False

            def newConstant(self, s, val):
                return Varnode(s, Address(const_spc, val), None)

            def opRemoveInput(self, op, i):
                op.removeInput(i)

            def opSetInput(self, op, vn, slot):
                op.setInput(vn, slot)

            def opSetOpcode(self, op, opc):
                op.setOpcodeEnum(opc)

            def opMarkNoCollapse(self, op):
                self.marked_no_collapse = True

        sq = SeqNum(Address(ram, 0x1000), 0)
        op = PcodeOp(2, sq)
        op.setOpcodeEnum(OpCode.CPUI_INT_ADD)
        op.setOutput(Varnode(4, Address(reg, 0), 0))

        vn0 = Varnode(4, Address(const_spc, 5), 1)
        vn1 = Varnode(4, Address(const_spc, 7), 2)
        entry = _FakeEntry()
        vn0.setSymbolEntry(entry)
        op.setInput(vn0, 0)
        op.setInput(vn1, 1)

        rule = RuleCollapseConstants("analysis")
        data = _FakeData()

        assert rule.applyOp(op, data) == 1
        assert data.marked_no_collapse is False
        assert op.code() == OpCode.CPUI_COPY
        assert op.numInput() == 1
        assert op.getIn(0).isConstant()
        assert op.getIn(0).getOffset() == 12
        assert op.getIn(0).getSymbolEntry() is entry

    def test_print_raw(self, ram, reg):
        sq = SeqNum(Address(ram, 0x1000), 0)
        op = PcodeOp(1, sq)
        op.setOpcodeEnum(OpCode.CPUI_COPY)
        vn_out = Varnode(4, Address(reg, 0), 0)
        vn_in = Varnode(4, Address(reg, 8), 1)
        op.setOutput(vn_out)
        op.setInput(vn_in, 0)
        s = op.printRaw()
        assert "COPY" in s

    def test_repr(self, ram):
        sq = SeqNum(Address(ram, 0x1000), 0)
        op = PcodeOp(0, sq)
        op.setOpcodeEnum(OpCode.CPUI_RETURN)
        r = repr(op)
        assert "RETURN" in r

    def test_get_repeat_slot(self, ram, reg):
        sq = SeqNum(Address(ram, 0x1000), 0)
        op = PcodeOp(3, sq)
        vn = Varnode(4, Address(reg, 0), 0)
        vn2 = Varnode(4, Address(reg, 8), 1)
        op.setInput(vn, 0)
        op.setInput(vn2, 1)
        op.setInput(vn, 2)
        assert op.getRepeatSlot(vn, 1, op) == 2
        assert op.getRepeatSlot(vn2, 2, op) == -1

    def test_call_without_spec(self, ram):
        sq = SeqNum(Address(ram, 0x1000), 0)
        op = PcodeOp(1, sq)
        op.setFlag(PcodeOp.call)
        assert op.isCallWithoutSpec()
        op.setFlag(PcodeOp.has_callspec)
        assert not op.isCallWithoutSpec()

    def test_indirect_creation_store(self, ram):
        sq = SeqNum(Address(ram, 0x1000), 0)
        op = PcodeOp(2, sq)
        assert not op.isIndirectCreation()
        assert not op.isIndirectStore()
        op.setFlag(PcodeOp.indirect_creation)
        assert op.isIndirectCreation()
        op.setFlag(PcodeOp.indirect_store)
        assert op.isIndirectStore()

    def test_ptrflow(self, ram):
        sq = SeqNum(Address(ram, 0x1000), 0)
        op = PcodeOp(0, sq)
        assert not op.isPtrFlow()
        op.setPtrFlow()
        assert op.isPtrFlow()

    def test_spacebase_ptr(self, ram):
        sq = SeqNum(Address(ram, 0x1000), 0)
        op = PcodeOp(0, sq)
        assert not op.usesSpacebasePtr()
        op.setFlag(PcodeOp.spacebase_ptr)
        assert op.usesSpacebasePtr()

    def test_partial_root(self, ram):
        sq = SeqNum(Address(ram, 0x1000), 0)
        op = PcodeOp(0, sq)
        assert not op.isPartialRoot()
        op.setPartialRoot()
        assert op.isPartialRoot()

    def test_no_indirect_collapse(self, ram):
        sq = SeqNum(Address(ram, 0x1000), 0)
        op = PcodeOp(0, sq)
        assert not op.noIndirectCollapse()
        op.setNoIndirectCollapse()
        assert op.noIndirectCollapse()

    def test_store_unmapped(self, ram):
        sq = SeqNum(Address(ram, 0x1000), 0)
        op = PcodeOp(0, sq)
        assert not op.isStoreUnmapped()
        op.setStoreUnmapped()
        assert op.isStoreUnmapped()


# =========================================================================
# PcodeOpBank Tests
# =========================================================================

class TestPcodeOpBank:
    def test_create(self, ram):
        bank = PcodeOpBank()
        assert bank.empty()
        op = bank.create(2, Address(ram, 0x1000))
        assert not bank.empty()
        assert op.numInput() == 2
        assert op.isDead()  # Newly created ops start dead

    def test_create_with_seqnum(self, ram):
        bank = PcodeOpBank()
        sq = SeqNum(Address(ram, 0x2000), 42)
        op = bank.create(1, sq)
        assert op.getSeqNum() is sq
        assert op.getAddr() == Address(ram, 0x2000)

    def test_mark_alive_dead(self, ram):
        bank = PcodeOpBank()
        op = bank.create(0, Address(ram, 0x1000))
        assert op.isDead()
        assert op in bank.getDeadList()
        assert op not in bank.getAliveList()

        bank.markAlive(op)
        assert not op.isDead()
        assert op not in bank.getDeadList()
        assert op in bank.getAliveList()

        bank.markDead(op)
        assert op.isDead()
        assert op in bank.getDeadList()
        assert op not in bank.getAliveList()

    def test_destroy(self, ram):
        bank = PcodeOpBank()
        op = bank.create(0, Address(ram, 0x1000))
        sq = op.getSeqNum()
        bank.destroy(op)
        assert bank.findOp(sq) is None
        assert bank.empty()

    def test_destroy_dead(self, ram):
        bank = PcodeOpBank()
        op1 = bank.create(0, Address(ram, 0x1000))
        op2 = bank.create(0, Address(ram, 0x1004))
        bank.markAlive(op2)
        bank.destroyDead()
        # op1 was dead, should be destroyed; op2 was alive, should remain
        assert bank.findOp(op1.getSeqNum()) is None
        assert bank.findOp(op2.getSeqNum()) is op2

    def test_find_op(self, ram):
        bank = PcodeOpBank()
        op = bank.create(0, Address(ram, 0x1000))
        sq = op.getSeqNum()
        assert bank.findOp(sq) is op
        bogus = SeqNum(Address(ram, 0xFFFF), 999)
        assert bank.findOp(bogus) is None

    def test_target(self, ram):
        bank = PcodeOpBank()
        op1 = bank.create(0, Address(ram, 0x1000))
        op2 = bank.create(0, Address(ram, 0x2000))
        found = bank.target(Address(ram, 0x2000))
        assert found is op2

    def test_code_lists(self, ram, reg):
        bank = PcodeOpBank()
        op_store = bank.create(2, Address(ram, 0x1000))
        op_store.setOpcodeEnum(OpCode.CPUI_STORE)
        bank.markAlive(op_store)
        bank._addToCodeList(op_store)

        op_load = bank.create(2, Address(ram, 0x1004))
        op_load.setOpcodeEnum(OpCode.CPUI_LOAD)
        bank.markAlive(op_load)
        bank._addToCodeList(op_load)

        op_ret = bank.create(1, Address(ram, 0x1008))
        op_ret.setOpcodeEnum(OpCode.CPUI_RETURN)
        bank.markAlive(op_ret)
        bank._addToCodeList(op_ret)

        assert op_store in bank.getStoreList()
        assert op_load in bank.getLoadList()
        assert op_ret in bank.getReturnList()

    def test_begin_by_opcode(self, ram):
        bank = PcodeOpBank()
        op_store = bank.create(0, Address(ram, 0x1000))
        op_store.setOpcodeEnum(OpCode.CPUI_STORE)
        bank.markAlive(op_store)
        bank._addToCodeList(op_store)

        ops = bank.beginByOpcode(OpCode.CPUI_STORE)
        assert op_store in ops

    def test_uniq_id(self, ram):
        bank = PcodeOpBank()
        assert bank.getUniqId() == 0
        bank.create(0, Address(ram, 0x1000))
        assert bank.getUniqId() == 1
        bank.create(0, Address(ram, 0x1000))
        assert bank.getUniqId() == 2

    def test_clear(self, ram):
        bank = PcodeOpBank()
        bank.create(0, Address(ram, 0x1000))
        bank.create(0, Address(ram, 0x1004))
        bank.clear()
        assert bank.empty()

    def test_insert_after_dead(self, ram):
        bank = PcodeOpBank()
        op1 = bank.create(0, Address(ram, 0x1000))
        op2 = bank.create(0, Address(ram, 0x1004))
        op3 = bank.create(0, Address(ram, 0x1008))
        # op3 should be inserted after op1 in dead list
        bank._deadlist.remove(op3)
        bank.insertAfterDead(op3, op1)
        dl = bank.getDeadList()
        assert dl.index(op3) == dl.index(op1) + 1

    def test_fallthru(self, ram):
        bank = PcodeOpBank()
        op1 = bank.create(0, Address(ram, 0x1000))
        op2 = bank.create(0, Address(ram, 0x1004))
        ft = bank.fallthru(op1)
        assert ft is op2


# =========================================================================
# CoverBlock Tests
# =========================================================================

class TestCoverBlock:
    def test_empty(self):
        cb = CoverBlock()
        assert cb.empty()

    def test_set_all(self):
        cb = CoverBlock()
        cb.setAll()
        assert not cb.empty()

    def test_clear(self):
        cb = CoverBlock()
        cb.setAll()
        cb.clear()
        assert cb.empty()

    def test_contain_whole_block(self, ram):
        cb = CoverBlock()
        cb.setAll()
        # Any point should be contained
        sq = SeqNum(Address(ram, 0x1000), 5)
        op = PcodeOp(0, sq)
        assert cb.contain(op)

    def test_contain_empty(self, ram):
        cb = CoverBlock()
        sq = SeqNum(Address(ram, 0x1000), 5)
        op = PcodeOp(0, sq)
        assert not cb.contain(op)

    def test_set_begin_end(self, ram):
        cb = CoverBlock()
        sq1 = SeqNum(Address(ram, 0x1000), 5)
        sq1.setOrder(5)
        sq2 = SeqNum(Address(ram, 0x1000), 15)
        sq2.setOrder(15)
        op1 = PcodeOp(0, sq1)
        op2 = PcodeOp(0, sq2)
        cb.setBegin(op1)
        cb.setEnd(op2)
        assert not cb.empty()

        # Point inside range
        sq_mid = SeqNum(Address(ram, 0x1000), 10)
        sq_mid.setOrder(10)
        op_mid = PcodeOp(0, sq_mid)
        assert cb.contain(op_mid)

        # Point outside range
        sq_out = SeqNum(Address(ram, 0x1000), 20)
        sq_out.setOrder(20)
        op_out = PcodeOp(0, sq_out)
        assert not cb.contain(op_out)

    def test_boundary(self, ram):
        cb = CoverBlock()
        sq1 = SeqNum(Address(ram, 0x1000), 5)
        sq1.setOrder(5)
        sq2 = SeqNum(Address(ram, 0x1000), 15)
        sq2.setOrder(15)
        op1 = PcodeOp(0, sq1)
        op2 = PcodeOp(0, sq2)
        cb.setBegin(op1)
        cb.setEnd(op2)

        assert cb.boundary(op1) & 1  # on start boundary
        assert cb.boundary(op2) & 2  # on stop boundary

        sq_mid = SeqNum(Address(ram, 0x1000), 10)
        sq_mid.setOrder(10)
        op_mid = PcodeOp(0, sq_mid)
        assert cb.boundary(op_mid) == 0  # interior

    def test_intersect_no_overlap(self, ram):
        cb1 = CoverBlock()
        cb2 = CoverBlock()
        sq1a = SeqNum(Address(ram, 0x1000), 0); sq1a.setOrder(1)
        sq1b = SeqNum(Address(ram, 0x1000), 1); sq1b.setOrder(5)
        sq2a = SeqNum(Address(ram, 0x1000), 2); sq2a.setOrder(10)
        sq2b = SeqNum(Address(ram, 0x1000), 3); sq2b.setOrder(15)
        op1a = PcodeOp(0, sq1a)
        op1b = PcodeOp(0, sq1b)
        op2a = PcodeOp(0, sq2a)
        op2b = PcodeOp(0, sq2b)
        cb1.setBegin(op1a)
        cb1.setEnd(op1b)
        cb2.setBegin(op2a)
        cb2.setEnd(op2b)
        assert cb1.intersect(cb2) == 0

    def test_intersect_overlap(self, ram):
        cb1 = CoverBlock()
        cb2 = CoverBlock()
        sq1a = SeqNum(Address(ram, 0x1000), 0); sq1a.setOrder(1)
        sq1b = SeqNum(Address(ram, 0x1000), 1); sq1b.setOrder(10)
        sq2a = SeqNum(Address(ram, 0x1000), 2); sq2a.setOrder(5)
        sq2b = SeqNum(Address(ram, 0x1000), 3); sq2b.setOrder(15)
        op1a = PcodeOp(0, sq1a)
        op1b = PcodeOp(0, sq1b)
        op2a = PcodeOp(0, sq2a)
        op2b = PcodeOp(0, sq2b)
        cb1.setBegin(op1a)
        cb1.setEnd(op1b)
        cb2.setBegin(op2a)
        cb2.setEnd(op2b)
        assert cb1.intersect(cb2) == 1

    def test_intersect_boundary_only(self, ram):
        cb1 = CoverBlock()
        cb2 = CoverBlock()
        sq1a = SeqNum(Address(ram, 0x1000), 0); sq1a.setOrder(1)
        sq1b = SeqNum(Address(ram, 0x1000), 1); sq1b.setOrder(10)
        sq2a = SeqNum(Address(ram, 0x1000), 2); sq2a.setOrder(10)
        sq2b = SeqNum(Address(ram, 0x1000), 3); sq2b.setOrder(20)
        op1a = PcodeOp(0, sq1a)
        op1b = PcodeOp(0, sq1b)
        op2a = PcodeOp(0, sq2a)
        op2b = PcodeOp(0, sq2b)
        cb1.setBegin(op1a)
        cb1.setEnd(op1b)
        cb2.setBegin(op2a)
        cb2.setEnd(op2b)
        assert cb1.intersect(cb2) == 2

    def test_intersect_empty(self):
        cb1 = CoverBlock()
        cb2 = CoverBlock()
        assert cb1.intersect(cb2) == 0
        cb1.setAll()
        assert cb1.intersect(cb2) == 0

    def test_merge(self, ram):
        cb1 = CoverBlock()
        cb2 = CoverBlock()
        sq1 = SeqNum(Address(ram, 0x1000), 0); sq1.setOrder(5)
        sq2 = SeqNum(Address(ram, 0x1000), 1); sq2.setOrder(10)
        sq3 = SeqNum(Address(ram, 0x1000), 2); sq3.setOrder(3)
        sq4 = SeqNum(Address(ram, 0x1000), 3); sq4.setOrder(15)
        op1 = PcodeOp(0, sq1)
        op2 = PcodeOp(0, sq2)
        op3 = PcodeOp(0, sq3)
        op4 = PcodeOp(0, sq4)
        cb1.setBegin(op1)
        cb1.setEnd(op2)
        cb2.setBegin(op3)
        cb2.setEnd(op4)
        cb1.merge(cb2)
        # Merged range should be [3..15]
        assert CoverBlock.getUIndex(cb1.start) == 3
        assert CoverBlock.getUIndex(cb1.stop) == 15

    def test_merge_into_empty(self, ram):
        cb1 = CoverBlock()
        cb2 = CoverBlock()
        sq1 = SeqNum(Address(ram, 0x1000), 5)
        sq2 = SeqNum(Address(ram, 0x1000), 10)
        op1 = PcodeOp(0, sq1)
        op2 = PcodeOp(0, sq2)
        cb2.setBegin(op1)
        cb2.setEnd(op2)
        cb1.merge(cb2)
        assert not cb1.empty()

    def test_merge_empty_into_nonempty(self, ram):
        cb1 = CoverBlock()
        cb2 = CoverBlock()
        sq1 = SeqNum(Address(ram, 0x1000), 0); sq1.setOrder(5)
        sq2 = SeqNum(Address(ram, 0x1000), 1); sq2.setOrder(10)
        op1 = PcodeOp(0, sq1)
        op2 = PcodeOp(0, sq2)
        cb1.setBegin(op1)
        cb1.setEnd(op2)
        cb1.merge(cb2)  # merge empty
        assert CoverBlock.getUIndex(cb1.start) == 5


# =========================================================================
# Cover Tests
# =========================================================================

class TestCover:
    def test_empty(self):
        c = Cover()
        assert c.getNumBlocks() == 0

    def test_clear(self, ram):
        c = Cover()
        cb = CoverBlock()
        cb.setAll()
        c._cover[0] = cb
        assert c.getNumBlocks() == 1
        c.clear()
        assert c.getNumBlocks() == 0

    def test_get_cover_block(self):
        c = Cover()
        cb = CoverBlock()
        cb.setAll()
        c._cover[3] = cb
        assert c.getCoverBlock(3) is cb
        assert c.getCoverBlock(99).empty()  # Missing block returns empty

    def test_merge(self, ram):
        c1 = Cover()
        c2 = Cover()
        cb1 = CoverBlock()
        cb1.setAll()
        c1._cover[0] = cb1

        cb2 = CoverBlock()
        cb2.setAll()
        c2._cover[1] = cb2

        c1.merge(c2)
        assert c1.containsBlock(0)
        assert c1.containsBlock(1)

    def test_intersect_no_overlap(self, ram):
        c1 = Cover()
        c2 = Cover()
        cb1 = CoverBlock()
        cb1.setAll()
        c1._cover[0] = cb1
        cb2 = CoverBlock()
        cb2.setAll()
        c2._cover[1] = cb2
        assert c1.intersect(c2) == 0

    def test_intersect_overlap(self, ram):
        c1 = Cover()
        c2 = Cover()
        cb1 = CoverBlock()
        cb1.setAll()
        c1._cover[0] = cb1
        cb2 = CoverBlock()
        cb2.setAll()
        c2._cover[0] = cb2
        assert c1.intersect(c2) == 1

    def test_intersect_by_block(self, ram):
        c1 = Cover()
        c2 = Cover()
        cb1 = CoverBlock()
        cb1.setAll()
        c1._cover[2] = cb1
        cb2 = CoverBlock()
        cb2.setAll()
        c2._cover[2] = cb2
        assert c1.intersectByBlock(2, c2) == 1
        assert c1.intersectByBlock(3, c2) == 0

    def test_contain(self, ram):
        class FakeBlock:
            def getIndex(self): return 0

        c = Cover()
        cb = CoverBlock()
        cb.setAll()
        c._cover[0] = cb

        sq = SeqNum(Address(ram, 0x1000), 5)
        op = PcodeOp(0, sq)
        op.setParent(FakeBlock())
        assert c.contain(op, 0)

    def test_intersect_list(self, ram):
        c1 = Cover()
        c2 = Cover()
        for i in range(5):
            cb = CoverBlock()
            cb.setAll()
            c1._cover[i] = cb
        for i in [1, 3, 5]:
            cb = CoverBlock()
            cb.setAll()
            c2._cover[i] = cb
        result = c1.intersectList(c2, 1)
        assert 1 in result
        assert 3 in result
        assert 5 not in result  # Only in c2, not in c1

    def test_compare_to(self):
        c1 = Cover()
        c2 = Cover()
        assert c1.compareTo(c2) == 0
        c1._cover[0] = CoverBlock()
        assert c1.compareTo(c2) == 1
        c2._cover[0] = CoverBlock()
        assert c1.compareTo(c2) == 0

    def test_iter(self, ram):
        c = Cover()
        for i in [3, 1, 2]:
            cb = CoverBlock()
            cb.setAll()
            c._cover[i] = cb
        blocks = list(c)
        assert len(blocks) == 3


# =========================================================================
# HighVariable Tests
# =========================================================================

class TestHighVariable:
    def test_creation(self, reg):
        vn = Varnode(4, Address(reg, 0), 0)
        hv = HighVariable(vn)
        assert hv.numInstances() == 1
        assert hv.getInstance(0) is vn
        assert hv.getNumMergeClasses() == 1

    def test_dirty_flags_on_creation(self, reg):
        vn = Varnode(4, Address(reg, 0), 0)
        hv = HighVariable(vn)
        assert (hv._highflags & HighVariable.flagsdirty) != 0
        assert (hv._highflags & HighVariable.namerepdirty) != 0
        assert (hv._highflags & HighVariable.typedirty) != 0
        assert (hv._highflags & HighVariable.coverdirty) != 0

    def test_mark(self, reg):
        vn = Varnode(4, Address(reg, 0), 0)
        hv = HighVariable(vn)
        hv.setMark()
        from ghidra.ir.varnode import Varnode as VN
        assert (hv._flags & VN.mark) != 0
        hv.clearMark()
        assert (hv._flags & VN.mark) == 0

    def test_vn_linked_to_high(self, reg):
        vn = Varnode(4, Address(reg, 0), 0)
        hv = HighVariable(vn)
        assert vn.getHigh() is hv


# =========================================================================
# VariableGroup Tests
# =========================================================================

class TestVariableGroup:
    def test_creation(self):
        vg = VariableGroup()
        assert vg.empty()
        assert vg.getSize() == 0

    def test_add_piece(self, reg):
        vg = VariableGroup()
        vn = Varnode(4, Address(reg, 0), 0)
        hv = HighVariable(vn)
        vp = VariablePiece(hv, 0)
        vp._group = vg
        vg.addPiece(vp)
        assert not vg.empty()
        assert vg.getSize() == 4

    def test_symbol_offset(self):
        vg = VariableGroup()
        assert vg.getSymbolOffset() == 0
        vg.setSymbolOffset(8)
        assert vg.getSymbolOffset() == 8


# =========================================================================
# VariablePiece Tests
# =========================================================================

class TestVariablePiece:
    def test_creation(self, reg):
        vn = Varnode(4, Address(reg, 0), 0)
        hv = HighVariable(vn)
        vp = VariablePiece(hv, 0)
        assert vp.getHigh() is hv
        assert vp.getOffset() == 0
        assert vp.getSize() == 4

    def test_group_auto_created(self, reg):
        vn = Varnode(4, Address(reg, 0), 0)
        hv = HighVariable(vn)
        vp = VariablePiece(hv, 0)
        assert vp.getGroup() is not None
        assert not vp.getGroup().empty()

    def test_intersection_update(self, reg):
        vn1 = Varnode(4, Address(reg, 0), 0)
        vn2 = Varnode(4, Address(reg, 0), 1)
        hv1 = HighVariable(vn1)
        hv2 = HighVariable(vn2)
        vp1 = VariablePiece(hv1, 0)
        hv1._piece = vp1  # Link piece to high so grp_high lookup works
        # Put vp2 in same group, overlapping
        vp2 = VariablePiece(hv2, 0, hv1)
        # Mark dirty and update
        hv1._highflags |= HighVariable.intersectdirty
        hv2._highflags |= HighVariable.intersectdirty
        vp1.updateIntersections()
        assert vp1.numIntersection() == 1
        assert vp1.getIntersection(0) is vp2

    def test_no_intersection_non_overlapping(self, reg):
        vn1 = Varnode(4, Address(reg, 0), 0)
        vn2 = Varnode(4, Address(reg, 4), 1)
        hv1 = HighVariable(vn1)
        hv2 = HighVariable(vn2)
        vp1 = VariablePiece(hv1, 0)
        hv1._piece = vp1
        vp2 = VariablePiece(hv2, 4, hv1)
        hv1._highflags |= HighVariable.intersectdirty
        vp1.updateIntersections()
        assert vp1.numIntersection() == 0


# =========================================================================
# PieceNode Tests
# =========================================================================

class TestPieceNode:
    def test_creation(self, ram, reg):
        sq = SeqNum(Address(ram, 0x1000), 0)
        op = PcodeOp(2, sq)
        op.setOpcodeEnum(OpCode.CPUI_PIECE)
        pn = PieceNode(op, 1, 0, True)
        assert pn.isLeaf()
        assert pn.getTypeOffset() == 0
        assert pn.getSlot() == 1
        assert pn.getOp() is op

    def test_non_leaf(self, ram):
        sq = SeqNum(Address(ram, 0x1000), 0)
        op = PcodeOp(2, sq)
        pn = PieceNode(op, 0, 4, False)
        assert not pn.isLeaf()
        assert pn.getTypeOffset() == 4
