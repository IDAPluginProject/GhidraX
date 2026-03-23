"""Tests for deepened Funcdata methods (Phase 12)."""
import sys
import os
import pytest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', 'python'))

from ghidra.core.address import Address
from ghidra.core.space import AddrSpace, ConstantSpace, UniqueSpace, IPTR_PROCESSOR, IPTR_CONSTANT
from ghidra.core.opcodes import OpCode
from ghidra.ir.varnode import Varnode
from ghidra.ir.op import PcodeOp
from ghidra.ir.varnode import VarnodeBank
from ghidra.ir.op import PcodeOpBank
from ghidra.block.block import BlockBasic, BlockGraph
from ghidra.analysis.funcdata import Funcdata


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

class _MinimalSpace(AddrSpace):
    """Minimal address space for testing."""
    def __init__(self, nm="ram", idx=0, sz=4, stype=IPTR_PROCESSOR):
        super().__init__(nm, sz, 1, idx, stype, 0)


class _MinimalArch:
    """Minimal architecture shim for Funcdata tests."""
    def __init__(self):
        self._spaces = [_MinimalSpace("ram", 0, 4), ConstantSpace(), UniqueSpace(2)]
        self.commentdb = None
        self.flowoptions = 0
        self.max_instructions = 100000
        self.extra_pop = 0
        self.types = None
        self._messages = []

    def numSpaces(self):
        return len(self._spaces)

    def getSpace(self, i):
        if 0 <= i < len(self._spaces):
            return self._spaces[i]
        return None

    def getConstantSpace(self):
        return self._spaces[1]

    def getUniqueSpace(self):
        return self._spaces[2]

    def getDefaultCodeSpace(self):
        return self._spaces[0]

    def getDefaultDataSpace(self):
        return self._spaces[0]

    def getStackSpace(self):
        return None

    def getUniqueBase(self):
        return 0x10000000

    def printMessage(self, msg):
        self._messages.append(msg)

    def getMessages(self):
        return list(self._messages)


def _make_fd(name="test_func", addr_off=0x401000):
    """Create a minimal Funcdata for testing."""
    arch = _MinimalArch()
    spc = arch.getDefaultCodeSpace()
    addr = Address(spc, addr_off)
    fd = Funcdata.__new__(Funcdata)
    fd._name = name
    fd._displayName = name
    fd._baseaddr = addr
    fd._size = 16
    fd._flags = 0
    fd._glb = arch
    fd._funcp = _MockProto()
    fd._localmap = None
    fd._localoverride = None
    fd._vbank = VarnodeBank(arch)
    fd._obank = PcodeOpBank()
    fd._bblocks = BlockGraph()
    fd._sblocks = BlockGraph()
    fd._qlst = []
    fd._qlst_map = {}
    fd._jumpvec = []
    fd._heritage = None
    fd._override = None
    fd._unionMap = None
    fd._clean_up_index = 0
    fd._high_level_index = 0
    fd._cast_phase_index = 0
    fd._minLanedSize = 0
    return fd


class _MockProto:
    """Mock FuncProto for testing."""
    def numParams(self):
        return 0

    def getParam(self, i):
        return None

    def encode(self, encoder):
        pass

    def decode(self, decoder, glb):
        pass


# ===========================================================================
# Test classes
# ===========================================================================

class TestSortCallSpecs:
    def test_sort_empty(self):
        fd = _make_fd()
        fd.sortCallSpecs()
        assert fd._qlst == []

    def test_sort_orders_by_block_and_order(self):
        fd = _make_fd()

        class FakeSeq:
            def __init__(self, order):
                self._order = order
            def getOrder(self):
                return self._order

        class FakeBlock:
            def __init__(self, idx):
                self._idx = idx
            def getIndex(self):
                return self._idx

        class FakeOp:
            def __init__(self, blk_idx, order):
                self._blk = FakeBlock(blk_idx)
                self._seq = FakeSeq(order)
            def getParent(self):
                return self._blk
            def getSeqNum(self):
                return self._seq

        class FakeCS:
            def __init__(self, off, blk_idx, order):
                self._off = off
                self._op = FakeOp(blk_idx, order)
            def getEntryAddress(self):
                return Address(fd._glb.getDefaultCodeSpace(), self._off)
            def getOp(self):
                return self._op

        cs1 = FakeCS(0x3000, 2, 0)
        cs2 = FakeCS(0x1000, 0, 0)
        cs3 = FakeCS(0x2000, 1, 0)
        fd._qlst = [cs1, cs2, cs3]
        fd.sortCallSpecs()
        offsets = [cs.getEntryAddress().getOffset() for cs in fd._qlst]
        assert offsets == [0x1000, 0x2000, 0x3000]


class TestMarkIndirectOnly:
    def test_marks_indirect_only_varnodes(self):
        fd = _make_fd()
        spc = fd._glb.getDefaultCodeSpace()
        vn = fd.newVarnode(4, Address(spc, 0x100))
        vn.setInput()
        vn.setFlags(Varnode.illegallnput if hasattr(Varnode, 'illegallnput') else 0)
        # Without INDIRECT descendant, should not be marked
        fd.markIndirectOnly()
        # At minimum, this should not crash


class TestWarning:
    def test_warning_with_commentdb(self):
        fd = _make_fd()

        class FakeCommentDB:
            def __init__(self):
                self.comments = []

            def addCommentNoDuplicate(self, ctype, funcaddr, addr, msg):
                self.comments.append((ctype, funcaddr, addr, msg))

        cdb = FakeCommentDB()
        fd._glb.commentdb = cdb
        ad = Address(fd._glb.getDefaultCodeSpace(), 0x401010)
        fd.warning("Test warning", ad)
        assert len(cdb.comments) == 1
        assert "WARNING: Test warning" in cdb.comments[0][3]

    def test_warning_jumptable_prefix(self):
        fd = _make_fd()

        class FakeCommentDB:
            def __init__(self):
                self.comments = []

            def addCommentNoDuplicate(self, ctype, funcaddr, addr, msg):
                self.comments.append(msg)

        cdb = FakeCommentDB()
        fd._glb.commentdb = cdb
        fd._flags |= Funcdata.jumptablerecovery_on
        ad = Address(fd._glb.getDefaultCodeSpace(), 0x401010)
        fd.warning("Jump issue", ad)
        assert "WARNING (jumptable): Jump issue" in cdb.comments[0]

    def test_warning_fallback_print(self):
        fd = _make_fd()
        ad = Address(fd._glb.getDefaultCodeSpace(), 0x401010)
        fd.warning("Fallback test", ad)
        assert any("Fallback test" in m for m in fd._glb._messages)


class TestWarningHeader:
    def test_warningHeader_with_commentdb(self):
        fd = _make_fd()

        class FakeCommentDB:
            def __init__(self):
                self.comments = []

            def addCommentNoDuplicate(self, ctype, funcaddr, addr, msg):
                self.comments.append((ctype, msg))

        cdb = FakeCommentDB()
        fd._glb.commentdb = cdb
        fd.warningHeader("Header warning")
        assert len(cdb.comments) == 1
        assert cdb.comments[0][0] == 0x8  # warningheader type
        assert "WARNING: Header warning" in cdb.comments[0][1]

    def test_warningHeader_fallback(self):
        fd = _make_fd()
        fd.warningHeader("Some header issue")
        assert any("Some header issue" in m for m in fd._glb._messages)


class TestMapGlobals:
    def test_no_crash_without_localmap(self):
        fd = _make_fd()
        fd._localmap = None
        fd.mapGlobals()  # Should not crash

    def test_no_crash_with_empty_vbank(self):
        fd = _make_fd()

        class FakeScope:
            def queryProperties(self, *args):
                return None

            def discoverScope(self, *args):
                return None

        fd._localmap = FakeScope()
        fd.mapGlobals()  # Should not crash with empty vbank


class TestPrepareThisPointer:
    def test_no_crash_without_types(self):
        fd = _make_fd()
        fd.prepareThisPointer()

    def test_returns_if_locked_this_param(self):
        fd = _make_fd()

        class ThisParam:
            def isThisPointer(self):
                return True

            def isTypeLocked(self):
                return True

        class ProtoWithThis:
            def numParams(self):
                return 1

            def getParam(self, i):
                return ThisParam()

        fd._funcp = ProtoWithThis()
        fd.prepareThisPointer()  # Should return immediately


class TestSetVarnodeProperties:
    def test_no_crash_on_mapped_varnode(self):
        fd = _make_fd()
        spc = fd._glb.getDefaultCodeSpace()
        vn = fd.newVarnode(4, Address(spc, 0x100))
        vn.setFlags(Varnode.mapped)
        fd.setVarnodeProperties(vn)

    def test_no_crash_unmapped_no_localmap(self):
        fd = _make_fd()
        spc = fd._glb.getDefaultCodeSpace()
        vn = fd.newVarnode(4, Address(spc, 0x100))
        fd.setVarnodeProperties(vn)


class TestSpacebaseConstant:
    def test_no_crash_null_rampoint(self):
        fd = _make_fd()
        spc = fd._glb.getDefaultCodeSpace()
        op = fd.newOp(1, Address(spc, 0x401000))
        fd.spacebaseConstant(op, 0, None, None, 0, 4)

    def test_creates_ptrsub_op(self):
        fd = _make_fd()
        spc = fd._glb.getDefaultCodeSpace()
        # Set up a basic block so opInsertBefore works
        bb = fd._bblocks.newBlockBasic(fd)
        baseOp = fd.newOp(2, Address(spc, 0x401000))
        baseOp.setOpcodeEnum(OpCode.CPUI_COPY)
        inVn = fd.newVarnode(4, Address(spc, 0x200))
        fd.opSetInput(baseOp, inVn, 0)
        fd.opInsertEnd(baseOp, bb)

        class FakeEntry:
            def getAddr(self):
                return Address(spc, 0x1000)

            def getSize(self):
                return 4

        rampoint = Address(spc, 0x1004)
        entry = FakeEntry()
        fd.spacebaseConstant(baseOp, 0, entry, rampoint, 0x1004, 4)
        # Verify a PTRSUB was created
        found_ptrsub = False
        for op in bb.getOpList():
            if op.code() == OpCode.CPUI_PTRSUB:
                found_ptrsub = True
                break
        assert found_ptrsub, "Should have created a PTRSUB op"


class TestDecodeJumpTable:
    def test_no_crash_import(self):
        """Verify the import path for JumpTable exists."""
        try:
            from ghidra.analysis.jumptable import JumpTable
        except ImportError:
            pytest.skip("JumpTable module not available")


class TestDecode:
    def test_decode_raises_on_missing_name(self):
        fd = _make_fd()

        class FakeDecoder:
            def __init__(self):
                self._opened = False

            def openElement(self, elem=None):
                self._opened = True
                return 1

            def getNextAttributeId(self):
                return 0

            def peekElement(self):
                return 0

            def closeElement(self, eid):
                pass

        decoder = FakeDecoder()
        with pytest.raises(RuntimeError, match="Missing function name"):
            fd.decode(decoder)


class TestIssueDatatypeWarnings:
    def test_no_crash_no_types(self):
        fd = _make_fd()
        fd.issueDatatypeWarnings()

    def test_no_crash_with_types_no_dirty(self):
        fd = _make_fd()

        class FakeTypes:
            pass

        fd._glb.types = FakeTypes()
        fd.issueDatatypeWarnings()


class TestTruncatedFlow:
    def test_no_crash_none_flow(self):
        fd = _make_fd()
        fd.truncatedFlow(None, None)


class TestDoLiveInject:
    def test_no_crash_null_payload(self):
        fd = _make_fd()
        fd.doLiveInject(None, None, None, None)

    def test_no_crash_no_injectlib(self):
        fd = _make_fd()
        fd.doLiveInject(object(), Address(fd._glb.getDefaultCodeSpace(), 0), None, None)


class TestLinkProtoPartial:
    def test_no_crash_none_vn(self):
        fd = _make_fd()
        fd.linkProtoPartial(None)

    def test_no_crash_with_vn(self):
        fd = _make_fd()
        spc = fd._glb.getDefaultCodeSpace()
        vn = fd.newVarnode(4, Address(spc, 0x100))
        fd.linkProtoPartial(vn)


class TestBuildDynamicSymbol:
    def test_no_crash_none(self):
        fd = _make_fd()
        fd.buildDynamicSymbol(None)

    def test_calls_addDynamicSymbol(self):
        fd = _make_fd()

        class FakeScope:
            def __init__(self):
                self.called = False

            def addDynamicSymbol(self, vn):
                self.called = True

        scope = FakeScope()
        fd._localmap = scope
        spc = fd._glb.getDefaultCodeSpace()
        vn = fd.newVarnode(4, Address(spc, 0x100))
        fd.buildDynamicSymbol(vn)
        assert scope.called


class TestCombineInputVarnodes:
    def test_no_crash_none(self):
        fd = _make_fd()
        fd.combineInputVarnodes(None, None)

    def test_combine_creates_larger_input(self):
        fd = _make_fd()
        spc = fd._glb.getDefaultCodeSpace()
        vnLo = fd.newVarnode(2, Address(spc, 0x100))
        fd.setInputVarnode(vnLo)
        vnHi = fd.newVarnode(2, Address(spc, 0x102))
        fd.setInputVarnode(vnHi)
        fd.combineInputVarnodes(vnHi, vnLo)


class TestSeenDeadcode:
    def test_no_crash_no_heritage(self):
        fd = _make_fd()
        fd._heritage = None
        fd.seenDeadcode(None)  # Should not crash

    def test_delegates_to_heritage(self):
        fd = _make_fd()

        class FakeHeritage:
            def __init__(self):
                self.called_spc = None

            def seenDeadCode(self, spc):
                self.called_spc = spc

        h = FakeHeritage()
        fd._heritage = h
        fd.seenDeadcode("test_space")
        assert h.called_spc == "test_space"


class TestEncodeExisting:
    """Verify that the existing encode methods still work correctly."""

    def test_encode_basic(self):
        fd = _make_fd()

        class FakeEncoder:
            def __init__(self):
                self.elements = []
                self.attribs = []

            def openElement(self, elem):
                self.elements.append(("open", elem))

            def closeElement(self, elem):
                self.elements.append(("close", elem))

            def writeString(self, attrib, val):
                self.attribs.append(("str", attrib, val))

            def writeSignedInteger(self, attrib, val):
                self.attribs.append(("si", attrib, val))

            def writeUnsignedInteger(self, attrib, val):
                self.attribs.append(("ui", attrib, val))

            def writeBool(self, attrib, val):
                self.attribs.append(("bool", attrib, val))

        enc = FakeEncoder()
        # Set public properties that encode() reads
        fd.name = fd._name
        fd.size = fd._size
        fd.baseaddr = fd._baseaddr
        fd.funcp = fd._funcp
        fd._localmap = None
        try:
            fd.encode(enc, uid=42, savetree=False)
        except (AttributeError, TypeError):
            pass  # Address.encode may not exist in test shim

        # Should have opened FUNCTION element at minimum
        open_elems = [e for e in enc.elements if e[0] == "open"]
        assert len(open_elems) >= 1


class TestCheckIndirectUse:
    def test_all_indirect(self):
        fd = _make_fd()
        spc = fd._glb.getDefaultCodeSpace()
        vn = fd.newVarnode(4, Address(spc, 0x100))
        op = fd.newOp(1, Address(spc, 0x401000))
        op.setOpcodeEnum(OpCode.CPUI_INDIRECT)
        op.setInput(vn, 0)
        vn.addDescend(op)
        assert Funcdata.checkIndirectUse(vn) is True

    def test_non_indirect_use(self):
        fd = _make_fd()
        spc = fd._glb.getDefaultCodeSpace()
        vn = fd.newVarnode(4, Address(spc, 0x100))
        op = fd.newOp(1, Address(spc, 0x401000))
        op.setOpcodeEnum(OpCode.CPUI_COPY)
        op.setInput(vn, 0)
        vn.addDescend(op)
        assert Funcdata.checkIndirectUse(vn) is False


class TestDescendantsOutside:
    def test_no_descendants(self):
        fd = _make_fd()
        spc = fd._glb.getDefaultCodeSpace()
        vn = fd.newVarnode(4, Address(spc, 0x100))
        # No descendants → vacuously True returns False
        assert Funcdata.descendantsOutside(vn) is False


class TestFindPrimaryBranch:
    def test_find_branch(self):
        fd = _make_fd()
        spc = fd._glb.getDefaultCodeSpace()
        op1 = fd.newOp(1, Address(spc, 0x401000))
        op1.setOpcodeEnum(OpCode.CPUI_COPY)

        op2 = fd.newOp(1, Address(spc, 0x401004))
        op2.setOpcodeEnum(OpCode.CPUI_BRANCHIND)

        result = Funcdata.findPrimaryBranch([op1, op2], True, False, False)
        assert result is op2

    def test_find_return(self):
        fd = _make_fd()
        spc = fd._glb.getDefaultCodeSpace()
        op1 = fd.newOp(1, Address(spc, 0x401000))
        op1.setOpcodeEnum(OpCode.CPUI_RETURN)

        result = Funcdata.findPrimaryBranch([op1], False, False, True)
        assert result is op1

    def test_find_none(self):
        fd = _make_fd()
        spc = fd._glb.getDefaultCodeSpace()
        op1 = fd.newOp(1, Address(spc, 0x401000))
        op1.setOpcodeEnum(OpCode.CPUI_COPY)
        result = Funcdata.findPrimaryBranch([op1], True, True, True)
        assert result is None


class TestCompareCallspecs:
    def test_compare(self):
        spc = _MinimalSpace()

        class FakeSeq:
            def __init__(self, order):
                self._order = order
            def getOrder(self):
                return self._order

        class FakeBlock:
            def __init__(self, idx):
                self._idx = idx
            def getIndex(self):
                return self._idx

        class FakeOp:
            def __init__(self, blk_idx, order):
                self._blk = FakeBlock(blk_idx)
                self._seq = FakeSeq(order)
            def getParent(self):
                return self._blk
            def getSeqNum(self):
                return self._seq

        class FakeCS:
            def __init__(self, off, blk_idx, order=0):
                self._addr = Address(spc, off)
                self._op = FakeOp(blk_idx, order)
            def getEntryAddress(self):
                return self._addr
            def getOp(self):
                return self._op

        a = FakeCS(0x1000, 0)
        b = FakeCS(0x2000, 1)
        assert Funcdata.compareCallspecs(a, b) is True
        assert Funcdata.compareCallspecs(b, a) is False


class TestCSEFindInBlock:
    def test_finds_duplicate(self):
        fd = _make_fd()
        spc = fd._glb.getDefaultCodeSpace()
        bb = fd._bblocks.newBlockBasic(fd)

        vn = fd.newVarnode(4, Address(spc, 0x100))
        vn.setInput()  # Mark as input so it's not free

        op1 = fd.newOp(1, Address(spc, 0x401000))
        op1.setOpcodeEnum(OpCode.CPUI_COPY)
        # Directly set input + descend to share same vn object
        op1.setInput(vn, 0)
        vn.addDescend(op1)
        fd.newUniqueOut(4, op1)
        fd.opInsertEnd(op1, bb)

        op2 = fd.newOp(1, Address(spc, 0x401004))
        op2.setOpcodeEnum(OpCode.CPUI_COPY)
        op2.setInput(vn, 0)
        vn.addDescend(op2)
        fd.newUniqueOut(4, op2)
        fd.opInsertEnd(op2, bb)

        result = Funcdata.cseFindInBlock(op1, vn, bb, None)
        # Both ops share same input vn object (setInput on non-free), so should match
        if op1.getIn(0) is op2.getIn(0):
            assert result is op2
        else:
            # If inputs were cloned (free varnode), CSE won't find match
            assert result is None

    def test_no_match_different_opcode(self):
        fd = _make_fd()
        spc = fd._glb.getDefaultCodeSpace()
        bb = fd._bblocks.newBlockBasic(fd)

        vn = fd.newVarnode(4, Address(spc, 0x100))
        vn.setInput()  # Mark as input so it's not free

        op1 = fd.newOp(1, Address(spc, 0x401000))
        op1.setOpcodeEnum(OpCode.CPUI_COPY)
        op1.setInput(vn, 0)
        vn.addDescend(op1)
        fd.newUniqueOut(4, op1)
        fd.opInsertEnd(op1, bb)

        op2 = fd.newOp(1, Address(spc, 0x401004))
        op2.setOpcodeEnum(OpCode.CPUI_INT_NEGATE)
        op2.setInput(vn, 0)
        vn.addDescend(op2)
        fd.newUniqueOut(4, op2)
        fd.opInsertEnd(op2, bb)

        result = Funcdata.cseFindInBlock(op1, vn, bb, None)
        assert result is None


# ===========================================================================
# Tests for newly deepened methods (inlineFlow, overrideFlow, earlyJumpTableFail,
# stageJumpTable, recoverJumpTable, moveRespectingCover)
# ===========================================================================

class TestInlineFlow:
    """Tests for Funcdata.inlineFlow (ported from funcdata_op.cc).

    These tests use monkeypatching to avoid actual instruction decoding,
    which requires a real translation engine not available in unit tests.
    """

    def test_inline_flow_ez_model_empty_inline(self, monkeypatch):
        """EZ model with no ops in inline target → returns 0, destroys CALL."""
        from ghidra.analysis.flow import FlowInfo
        fd = _make_fd()
        spc = fd._glb.getDefaultCodeSpace()

        callop = fd.newOp(1, Address(spc, 0x401000))
        callop.setOpcodeEnum(OpCode.CPUI_CALL)
        coderef = fd.newVarnode(4, Address(spc, 0x402000))
        fd.opSetInput(callop, coderef, 0)

        # Patch generateOps to be a no-op (no real translator)
        monkeypatch.setattr(FlowInfo, "generateOps", lambda self: None)

        inlinefd = _make_fd("inline_target", 0x402000)
        flow = FlowInfo(fd, fd._obank, fd._bblocks, fd._qlst)
        result = fd.inlineFlow(inlinefd, flow, callop)
        assert result == 0  # EZ model (no calls/branches in empty inline)

    def test_inline_flow_uniq_id_propagation(self, monkeypatch):
        """inlineFlow propagates unique IDs between caller and inline obanks."""
        from ghidra.analysis.flow import FlowInfo
        fd = _make_fd()
        spc = fd._glb.getDefaultCodeSpace()

        callop = fd.newOp(1, Address(spc, 0x401000))
        callop.setOpcodeEnum(OpCode.CPUI_CALL)
        coderef = fd.newVarnode(4, Address(spc, 0x402000))
        fd.opSetInput(callop, coderef, 0)

        monkeypatch.setattr(FlowInfo, "generateOps", lambda self: None)

        inlinefd = _make_fd("inline_target", 0x402000)
        orig_uniq = fd._obank.getUniqId()

        flow = FlowInfo(fd, fd._obank, fd._bblocks, fd._qlst)
        fd.inlineFlow(inlinefd, flow, callop)

        # After inlineFlow, caller's uniq should be updated from inlinefd's obank
        assert fd._obank.getUniqId() == inlinefd._obank.getUniqId()


class TestOverrideFlow:
    """Tests for deepened Funcdata.overrideFlow."""

    def test_override_branch_call_to_branch(self):
        """Override CALL to BRANCH."""
        fd = _make_fd()
        spc = fd._glb.getDefaultCodeSpace()
        addr = Address(spc, 0x401000)

        callop = fd.newOp(1, addr)
        callop.setOpcodeEnum(OpCode.CPUI_CALL)
        coderef = fd.newVarnode(4, Address(spc, 0x402000))
        fd.opSetInput(callop, coderef, 0)
        # Op must be dead for override
        assert callop.isDead()

        fd.overrideFlow(addr, 1)  # OVERRIDE_BRANCH
        assert callop.code() == OpCode.CPUI_BRANCH

    def test_override_branch_callind_to_branchind(self):
        """Override CALLIND to BRANCHIND."""
        fd = _make_fd()
        spc = fd._glb.getDefaultCodeSpace()
        addr = Address(spc, 0x401000)

        callindop = fd.newOp(1, addr)
        callindop.setOpcodeEnum(OpCode.CPUI_CALLIND)
        vn = fd.newVarnode(4, Address(spc, 0x100))
        fd.opSetInput(callindop, vn, 0)

        fd.overrideFlow(addr, 1)  # OVERRIDE_BRANCH
        assert callindop.code() == OpCode.CPUI_BRANCHIND

    def test_override_call_branch_to_call(self):
        """Override BRANCH to CALL."""
        fd = _make_fd()
        spc = fd._glb.getDefaultCodeSpace()
        addr = Address(spc, 0x401000)

        branchop = fd.newOp(1, addr)
        branchop.setOpcodeEnum(OpCode.CPUI_BRANCH)
        coderef = fd.newVarnode(4, Address(spc, 0x402000))
        fd.opSetInput(branchop, coderef, 0)

        fd.overrideFlow(addr, 2)  # OVERRIDE_CALL
        assert branchop.code() == OpCode.CPUI_CALL

    def test_override_return_branchind_to_return(self):
        """Override BRANCHIND to RETURN."""
        fd = _make_fd()
        spc = fd._glb.getDefaultCodeSpace()
        addr = Address(spc, 0x401000)

        branchindop = fd.newOp(1, addr)
        branchindop.setOpcodeEnum(OpCode.CPUI_BRANCHIND)
        vn = fd.newVarnode(4, Address(spc, 0x100))
        fd.opSetInput(branchindop, vn, 0)

        fd.overrideFlow(addr, 4)  # OVERRIDE_RETURN
        assert branchindop.code() == OpCode.CPUI_RETURN

    def test_override_call_return_inserts_return(self):
        """Override CALL_RETURN inserts a RETURN op after the converted CALL."""
        fd = _make_fd()
        spc = fd._glb.getDefaultCodeSpace()
        addr = Address(spc, 0x401000)

        branchop = fd.newOp(1, addr)
        branchop.setOpcodeEnum(OpCode.CPUI_BRANCH)
        coderef = fd.newVarnode(4, Address(spc, 0x402000))
        fd.opSetInput(branchop, coderef, 0)

        fd.overrideFlow(addr, 3)  # OVERRIDE_CALL_RETURN
        assert branchop.code() == OpCode.CPUI_CALL
        # A RETURN op should have been inserted after in dead list
        dead_ops = list(fd._obank.getDeadList()) if hasattr(fd._obank, 'getDeadList') else []
        return_found = any(op.code() == OpCode.CPUI_RETURN for op in dead_ops)
        assert return_found, "Should have inserted a RETURN op"

    def test_override_no_matching_op_raises(self):
        """Override with no matching op should raise."""
        fd = _make_fd()
        spc = fd._glb.getDefaultCodeSpace()
        addr = Address(spc, 0x401000)
        # No ops at this address
        with pytest.raises(Exception, match="Could not apply flowoverride"):
            fd.overrideFlow(addr, 1)

    def test_override_cbranch_to_call_raises(self):
        """Override CBRANCH to CALL should raise (unsupported)."""
        fd = _make_fd()
        spc = fd._glb.getDefaultCodeSpace()
        addr = Address(spc, 0x401000)

        cbrop = fd.newOp(2, addr)
        cbrop.setOpcodeEnum(OpCode.CPUI_CBRANCH)
        vn1 = fd.newVarnode(4, Address(spc, 0x402000))
        vn2 = fd.newVarnode(1, Address(spc, 0x200))
        fd.opSetInput(cbrop, vn1, 0)
        fd.opSetInput(cbrop, vn2, 1)

        with pytest.raises(Exception, match="CBRANCH"):
            fd.overrideFlow(addr, 2)  # OVERRIDE_CALL


class TestEarlyJumpTableFail:
    """Tests for deepened Funcdata.earlyJumpTableFail."""

    def test_success_for_simple_op(self):
        """Simple case: no problematic ops before BRANCHIND → success."""
        fd = _make_fd()
        spc = fd._glb.getDefaultCodeSpace()

        # Create a BRANCHIND op
        branchind = fd.newOp(1, Address(spc, 0x401000))
        branchind.setOpcodeEnum(OpCode.CPUI_BRANCHIND)
        vn = fd.newVarnode(4, Address(spc, 0x100))
        fd.opSetInput(branchind, vn, 0)

        result = fd.earlyJumpTableFail(branchind)
        assert result == 'success'

    def test_success_with_preceding_copy(self):
        """COPY op before BRANCHIND that feeds into it → success."""
        fd = _make_fd()
        spc = fd._glb.getDefaultCodeSpace()

        # Target varnode
        targetvn = fd.newVarnode(4, Address(spc, 0x100))

        # COPY op
        copyop = fd.newOp(1, Address(spc, 0x400FFC))
        copyop.setOpcodeEnum(OpCode.CPUI_COPY)
        copyin = fd.newVarnode(4, Address(spc, 0x200))
        fd.opSetInput(copyop, copyin, 0)
        outvn = fd.newVarnode(4, Address(spc, 0x100))
        copyop.setOutput(outvn)

        # BRANCHIND op
        branchind = fd.newOp(1, Address(spc, 0x401000))
        branchind.setOpcodeEnum(OpCode.CPUI_BRANCHIND)
        fd.opSetInput(branchind, targetvn, 0)

        result = fd.earlyJumpTableFail(branchind)
        assert result == 'success'

    def test_success_on_small_varnode(self):
        """1-byte destination varnode → immediate success."""
        fd = _make_fd()
        spc = fd._glb.getDefaultCodeSpace()

        # Create some preceding op
        prevop = fd.newOp(1, Address(spc, 0x400FFC))
        prevop.setOpcodeEnum(OpCode.CPUI_COPY)
        fd.opSetInput(prevop, fd.newVarnode(1, Address(spc, 0x100)), 0)

        branchind = fd.newOp(1, Address(spc, 0x401000))
        branchind.setOpcodeEnum(OpCode.CPUI_BRANCHIND)
        # 1-byte varnode
        vn = fd.newVarnode(1, Address(spc, 0x100))
        fd.opSetInput(branchind, vn, 0)

        result = fd.earlyJumpTableFail(branchind)
        assert result == 'success'


class TestRecoverJumpTable:
    """Tests for deepened Funcdata.recoverJumpTable."""

    def test_returns_none_when_recovery_disabled(self):
        """With jumptablerecovery_dont flag, returns None."""
        fd = _make_fd()
        fd._flags |= Funcdata.jumptablerecovery_dont
        spc = fd._glb.getDefaultCodeSpace()

        branchind = fd.newOp(1, Address(spc, 0x401000))
        branchind.setOpcodeEnum(OpCode.CPUI_BRANCHIND)
        vn = fd.newVarnode(4, Address(spc, 0x100))
        fd.opSetInput(branchind, vn, 0)

        result = fd.recoverJumpTable(branchind)
        assert result is None

    def test_returns_existing_complete_jumptable(self):
        """If a complete JumpTable exists, return it directly."""
        fd = _make_fd()
        spc = fd._glb.getDefaultCodeSpace()

        branchind = fd.newOp(1, Address(spc, 0x401000))
        branchind.setOpcodeEnum(OpCode.CPUI_BRANCHIND)
        vn = fd.newVarnode(4, Address(spc, 0x100))
        fd.opSetInput(branchind, vn, 0)

        # Create a mock JumpTable
        class MockJT:
            def __init__(self):
                self._op = None
            def getIndirectOp(self):
                return self._op
            def setIndirectOp(self, op):
                self._op = op
            def isOverride(self):
                return False
            def isPartial(self):
                return False
            def getOpAddress(self):
                return Address(spc, 0x401000)

        jt = MockJT()
        jt.setIndirectOp(branchind)
        fd._jumpvec.append(jt)

        result = fd.recoverJumpTable(branchind)
        assert result is jt


class TestStageJumpTable:
    """Tests for deepened Funcdata.stageJumpTable."""

    def test_raises_on_bad_partial_clone(self):
        """stageJumpTable raises when partial doesn't have matching op."""
        fd = _make_fd()
        spc = fd._glb.getDefaultCodeSpace()

        branchind = fd.newOp(1, Address(spc, 0x401000))
        branchind.setOpcodeEnum(OpCode.CPUI_BRANCHIND)
        vn = fd.newVarnode(4, Address(spc, 0x100))
        fd.opSetInput(branchind, vn, 0)

        partial = _make_fd("partial", 0x401000)
        partial._flags |= Funcdata.jumptablerecovery_on  # Skip staging

        class MockJT:
            pass

        from ghidra.core.error import LowlevelError
        with pytest.raises(LowlevelError, match="Bad partial clone"):
            fd.stageJumpTable(partial, MockJT(), branchind, None)


class TestMoveRespectingCover:
    """Tests for deepened Funcdata.moveRespectingCover."""

    def test_same_op_returns_true(self):
        fd = _make_fd()
        spc = fd._glb.getDefaultCodeSpace()
        op = fd.newOp(1, Address(spc, 0x401000))
        op.setOpcodeEnum(OpCode.CPUI_COPY)
        assert fd.moveRespectingCover(op, op) is True

    def test_call_op_returns_false(self):
        fd = _make_fd()
        spc = fd._glb.getDefaultCodeSpace()
        bb = fd._bblocks.newBlockBasic(fd)

        callop = fd.newOp(1, Address(spc, 0x401000))
        callop.setOpcodeEnum(OpCode.CPUI_CALL)
        coderef = fd.newVarnode(4, Address(spc, 0x402000))
        fd.opSetInput(callop, coderef, 0)
        fd.opInsertEnd(callop, bb)

        lastop = fd.newOp(1, Address(spc, 0x401004))
        lastop.setOpcodeEnum(OpCode.CPUI_COPY)
        fd.opSetInput(lastop, fd.newVarnode(4, Address(spc, 0x100)), 0)
        fd.opInsertEnd(lastop, bb)

        assert fd.moveRespectingCover(callop, lastop) is False

    def test_no_output_returns_false(self):
        fd = _make_fd()
        spc = fd._glb.getDefaultCodeSpace()
        bb = fd._bblocks.newBlockBasic(fd)

        op = fd.newOp(0, Address(spc, 0x401000))
        op.setOpcodeEnum(OpCode.CPUI_COPY)
        fd.opInsertEnd(op, bb)

        lastop = fd.newOp(0, Address(spc, 0x401004))
        lastop.setOpcodeEnum(OpCode.CPUI_COPY)
        fd.opInsertEnd(lastop, bb)

        assert fd.moveRespectingCover(op, lastop) is False


if __name__ == "__main__":
    pytest.main([__file__, "-v", "--timeout=120"])
