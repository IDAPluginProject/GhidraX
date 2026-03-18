"""
ConditionalExecution: Simplify control-flow with shared conditional expressions.
Corresponds to condexe.hh / condexe.cc.

Classes:
- **ConditionalExecution** — identifies and removes redundant CBRANCHs.
- **RuleOrPredicate** — simplifies predicated INT_OR constructs.
"""
from __future__ import annotations

from typing import Dict, List, Optional, TYPE_CHECKING

from ghidra.core.error import LowlevelError
from ghidra.core.expression import BooleanExpressionMatch
from ghidra.core.opcodes import OpCode

if TYPE_CHECKING:
    from ghidra.block.block import BlockBasic, FlowBlock
    from ghidra.ir.op import PcodeOp
    from ghidra.ir.varnode import Varnode
    from ghidra.analysis.funcdata import Funcdata


# =========================================================================
# ConditionalExecution
# =========================================================================

class ConditionalExecution:
    """Identify and remove redundant conditional branches.

    When two CBRANCHs branch on the same (or complementary) boolean,
    eliminate the second one and fix up data-flow (MULTIEQUALs, COPYs,
    SUBPIECEs, etc.).
    """

    def __init__(self, fd: Funcdata) -> None:
        self.fd: Funcdata = fd
        self.cbranch: Optional[PcodeOp] = None
        self.initblock: Optional[BlockBasic] = None
        self.iblock: Optional[BlockBasic] = None
        self.prea_inslot: int = 0
        self.init2a_true: bool = False
        self.iblock2posta_true: bool = False
        self.camethruposta_slot: int = 0
        self.posta_outslot: int = 0
        self.posta_block: Optional[BlockBasic] = None
        self.postb_block: Optional[BlockBasic] = None
        self.replacement: Dict[int, Varnode] = {}
        self.pullback: List[Optional[Varnode]] = []
        self.heritageyes: List[bool] = []
        self._buildHeritageArray()

    def _buildHeritageArray(self) -> None:
        glb = self.fd.getArch()
        n = glb.numSpaces()
        self.heritageyes = [False] * n
        for i in range(n):
            spc = glb.getSpace(i)
            if spc is None:
                continue
            idx = spc.getIndex()
            if not spc.isHeritaged():
                continue
            if self.fd.numHeritagePasses(spc) > 0:
                if idx < len(self.heritageyes):
                    self.heritageyes[idx] = True

    def _testIBlock(self) -> bool:
        if self.iblock.sizeIn() != 2:
            return False
        if self.iblock.sizeOut() != 2:
            return False
        self.cbranch = self.iblock.lastOp()
        if self.cbranch is None:
            return False
        if self.cbranch.code() != OpCode.CPUI_CBRANCH:
            return False
        return True

    def _findInitPre(self) -> bool:
        tmp = self.iblock.getIn(self.prea_inslot)
        last = self.iblock
        while tmp.sizeOut() == 1 and tmp.sizeIn() == 1:
            last = tmp
            tmp = tmp.getIn(0)
        if tmp.sizeOut() != 2:
            return False
        self.initblock = tmp
        other = self.iblock.getIn(1 - self.prea_inslot)
        while other.sizeOut() == 1 and other.sizeIn() == 1:
            other = other.getIn(0)
        if other is not self.initblock:
            return False
        if self.initblock is self.iblock:
            return False
        self.init2a_true = (self.initblock.getTrueOut() is last)
        return True

    def _verifySameCondition(self) -> bool:
        init_cbranch = self.initblock.lastOp()
        if init_cbranch is None:
            return False
        if init_cbranch.code() != OpCode.CPUI_CBRANCH:
            return False
        tester = BooleanExpressionMatch()
        if not tester.verifyCondition(self.cbranch, init_cbranch):
            return False
        if tester.getFlip():
            self.init2a_true = not self.init2a_true
        return True

    def _testOpRead(self, vn: Varnode, op: PcodeOp) -> bool:
        if op.getParent() is self.iblock:
            return True
        writeOp = vn.getDef()
        opc = writeOp.code()
        if opc in (OpCode.CPUI_COPY, OpCode.CPUI_SUBPIECE,
                   OpCode.CPUI_INT_ADD, OpCode.CPUI_PTRSUB):
            if opc in (OpCode.CPUI_INT_ADD, OpCode.CPUI_PTRSUB):
                if not writeOp.getIn(1).isConstant():
                    return False
            invn = writeOp.getIn(0)
            if invn.isWritten():
                upop = invn.getDef()
                if upop.getParent() is self.iblock and upop.code() != OpCode.CPUI_MULTIEQUAL:
                    return False
            elif invn.isFree():
                return False
            return True
        return False

    def _testMultiRead(self, vn: Varnode, op: PcodeOp) -> bool:
        if op.getParent() is self.iblock:
            if op.code() in (OpCode.CPUI_COPY, OpCode.CPUI_SUBPIECE):
                return True
            return False
        if op.code() == OpCode.CPUI_RETURN:
            if op.numInput() < 2 or op.getIn(1) is not vn:
                return False
        return True

    def _testRemovability(self, op: PcodeOp) -> bool:
        if op.code() == OpCode.CPUI_MULTIEQUAL:
            vn = op.getOut()
            for readop in vn.getDescend():
                if not self._testMultiRead(vn, readop):
                    return False
        else:
            if op.isFlowBreak() or op.isCall():
                return False
            opc = op.code()
            if opc in (OpCode.CPUI_LOAD, OpCode.CPUI_STORE, OpCode.CPUI_INDIRECT):
                return False
            vn = op.getOut()
            if vn is not None:
                if vn.isAddrTied():
                    return False
                has_no_descend = True
                for readop in vn.getDescend():
                    if not self._testOpRead(vn, readop):
                        return False
                    has_no_descend = False
                if has_no_descend:
                    spc_idx = vn.getSpace().getIndex()
                    if spc_idx < len(self.heritageyes) and not self.heritageyes[spc_idx]:
                        return False
        return True

    def _findPullback(self, inbranch: int) -> Optional[Varnode]:
        while len(self.pullback) <= inbranch:
            self.pullback.append(None)
        return self.pullback[inbranch]

    def _pullbackOp(self, op: PcodeOp, inbranch: int) -> Varnode:
        invn = self._findPullback(inbranch)
        if invn is not None:
            return invn
        invn = op.getIn(0)
        if invn.isWritten():
            defOp = invn.getDef()
            if defOp.getParent() is self.iblock:
                bl = self.iblock.getIn(inbranch)
                invn = defOp.getIn(inbranch)
            else:
                bl = self.iblock.getImmedDom()
        else:
            bl = self.iblock.getImmedDom()
        newOp = self.fd.newOp(op.numInput(), op.getAddr())
        origOutVn = op.getOut()
        outVn = self.fd.newVarnodeOut(origOutVn.getSize(), origOutVn.getAddr(), newOp)
        self.fd.opSetOpcode(newOp, op.code())
        self.fd.opSetInput(newOp, invn, 0)
        for i in range(1, op.numInput()):
            self.fd.opSetInput(newOp, op.getIn(i), i)
        self.fd.opInsertEnd(newOp, bl)
        while len(self.pullback) <= inbranch:
            self.pullback.append(None)
        self.pullback[inbranch] = outVn
        return outVn

    def _getNewMulti(self, op: PcodeOp, bl: BlockBasic) -> Varnode:
        newop = self.fd.newOp(bl.sizeIn(), bl.getStart())
        outvn = op.getOut()
        newoutvn = self.fd.newUniqueOut(outvn.getSize(), newop)
        self.fd.opSetOpcode(newop, OpCode.CPUI_MULTIEQUAL)
        for i in range(bl.sizeIn()):
            self.fd.opSetInput(newop, outvn, i)
        self.fd.opInsertBegin(newop, bl)
        return newoutvn

    def _resolveRead(self, op: PcodeOp, bl: BlockBasic) -> Varnode:
        if bl.sizeIn() == 1:
            slot = self.camethruposta_slot if bl.getInRevIndex(0) == self.posta_outslot else 1 - self.camethruposta_slot
            return self._resolveIblockRead(op, slot)
        return self._getNewMulti(op, bl)

    def _resolveIblockRead(self, op: PcodeOp, inbranch: int) -> Varnode:
        if op.code() == OpCode.CPUI_COPY:
            vn = op.getIn(0)
            if vn.isWritten():
                defOp = vn.getDef()
                if defOp.code() == OpCode.CPUI_MULTIEQUAL and defOp.getParent() is self.iblock:
                    op = defOp
                else:
                    pass
            else:
                return vn
        opc = op.code()
        if opc == OpCode.CPUI_MULTIEQUAL:
            return op.getIn(inbranch)
        elif opc in (OpCode.CPUI_SUBPIECE, OpCode.CPUI_INT_ADD, OpCode.CPUI_PTRSUB):
            return self._pullbackOp(op, inbranch)
        raise LowlevelError("Conditional execution: Illegal op in iblock")

    def _getMultiequalRead(self, op: PcodeOp, readop: PcodeOp, slot: int) -> Varnode:
        bl = readop.getParent()
        inbl = bl.getIn(slot)
        if inbl is not self.iblock:
            return self._getReplacementRead(op, inbl)
        s = self.camethruposta_slot if bl.getInRevIndex(slot) == self.posta_outslot else 1 - self.camethruposta_slot
        return self._resolveIblockRead(op, s)

    def _getReplacementRead(self, op: PcodeOp, bl: BlockBasic) -> Varnode:
        idx = bl.getIndex()
        if idx in self.replacement:
            return self.replacement[idx]
        curbl = bl
        while curbl.getImmedDom() is not self.iblock:
            curbl = curbl.getImmedDom()
            if curbl is None:
                raise LowlevelError("Conditional execution: Could not find dominator")
        cur_idx = curbl.getIndex()
        if cur_idx in self.replacement:
            self.replacement[idx] = self.replacement[cur_idx]
            return self.replacement[cur_idx]
        res = self._resolveRead(op, curbl)
        self.replacement[cur_idx] = res
        if curbl is not bl:
            self.replacement[idx] = res
        return res

    def _doReplacement(self, op: PcodeOp) -> None:
        self.replacement.clear()
        self.pullback.clear()
        vn = op.getOut()
        descend = list(vn.getDescend())
        for readop in descend:
            slot = readop.getSlot(vn)
            bl = readop.getParent()
            if bl is self.iblock:
                self.fd.opUnsetInput(readop, slot)
            else:
                if readop.code() == OpCode.CPUI_MULTIEQUAL:
                    rvn = self._getMultiequalRead(op, readop, slot)
                elif readop.code() == OpCode.CPUI_RETURN:
                    retvn = readop.getIn(1)
                    newcopyop = self.fd.newOp(1, readop.getAddr())
                    self.fd.opSetOpcode(newcopyop, OpCode.CPUI_COPY)
                    outvn = self.fd.newVarnodeOut(retvn.getSize(), retvn.getAddr(), newcopyop)
                    self.fd.opSetInput(readop, outvn, 1)
                    self.fd.opInsertBefore(newcopyop, readop)
                    readop = newcopyop
                    slot = 0
                    rvn = self._getReplacementRead(op, bl)
                else:
                    rvn = self._getReplacementRead(op, bl)
                self.fd.opSetInput(readop, rvn, slot)

    def _verify(self) -> bool:
        self.prea_inslot = 0
        self.posta_outslot = 0
        if not self._testIBlock():
            return False
        if not self._findInitPre():
            return False
        if not self._verifySameCondition():
            return False
        self.iblock2posta_true = (self.posta_outslot == 1)
        self.camethruposta_slot = self.prea_inslot if self.init2a_true == self.iblock2posta_true else 1 - self.prea_inslot
        self.posta_block = self.iblock.getOut(self.posta_outslot)
        self.postb_block = self.iblock.getOut(1 - self.posta_outslot)
        ops = list(self.iblock.getOpList()) if hasattr(self.iblock, 'getOpList') else []
        if ops:
            for op in reversed(ops[:-1]):
                if not self._testRemovability(op):
                    return False
        return True

    def trial(self, ib: BlockBasic) -> bool:
        """Test for a modifiable configuration around the given block."""
        self.iblock = ib
        return self._verify()

    def execute(self) -> None:
        """Eliminate the unnecessary path join at iblock."""
        ops = list(self.iblock.getOpList()) if hasattr(self.iblock, 'getOpList') else []
        for op in reversed(ops):
            if not op.isBranch():
                self._doReplacement(op)
            self.fd.opDestroy(op)
        self.fd.removeFromFlowSplit(self.iblock, self.posta_outslot != self.camethruposta_slot)


# =========================================================================
# RuleOrPredicate  (condexe.cc)
# =========================================================================

class _MultiPredicate:
    """Helper to mark up predicated INT_OR expressions."""

    def __init__(self) -> None:
        self.op: Optional[PcodeOp] = None
        self.zeroSlot: int = 0
        self.zeroBlock: Optional[FlowBlock] = None
        self.condBlock: Optional[FlowBlock] = None
        self.cbranch: Optional[PcodeOp] = None
        self.otherVn: Optional[Varnode] = None
        self.zeroPathIsTrue: bool = False

    def discoverZeroSlot(self, vn: Varnode) -> bool:
        if not vn.isWritten():
            return False
        self.op = vn.getDef()
        if self.op.code() != OpCode.CPUI_MULTIEQUAL:
            return False
        if self.op.numInput() != 2:
            return False
        for zs in range(2):
            self.zeroSlot = zs
            tmpvn = self.op.getIn(zs)
            if not tmpvn.isWritten():
                continue
            copyop = tmpvn.getDef()
            if copyop.code() != OpCode.CPUI_COPY:
                continue
            zerovn = copyop.getIn(0)
            if not zerovn.isConstant():
                continue
            if zerovn.getOffset() != 0:
                continue
            self.otherVn = self.op.getIn(1 - zs)
            if self.otherVn.isFree():
                return False
            return True
        return False

    def discoverCbranch(self) -> bool:
        baseBlock = self.op.getParent()
        self.zeroBlock = baseBlock.getIn(self.zeroSlot)
        otherBlock = baseBlock.getIn(1 - self.zeroSlot)
        if self.zeroBlock.sizeOut() == 1:
            if self.zeroBlock.sizeIn() != 1:
                return False
            self.condBlock = self.zeroBlock.getIn(0)
        elif self.zeroBlock.sizeOut() == 2:
            self.condBlock = self.zeroBlock
        else:
            return False
        if self.condBlock.sizeOut() != 2:
            return False
        if otherBlock.sizeOut() == 1:
            if otherBlock.sizeIn() != 1:
                return False
            if self.condBlock is not otherBlock.getIn(0):
                return False
        elif otherBlock.sizeOut() == 2:
            if self.condBlock is not otherBlock:
                return False
        else:
            return False
        self.cbranch = self.condBlock.lastOp()
        if self.cbranch is None:
            return False
        if self.cbranch.code() != OpCode.CPUI_CBRANCH:
            return False
        return True

    def discoverPathIsTrue(self) -> None:
        if self.condBlock.getTrueOut() is self.zeroBlock:
            self.zeroPathIsTrue = True
        elif self.condBlock.getFalseOut() is self.zeroBlock:
            self.zeroPathIsTrue = False
        else:
            self.zeroPathIsTrue = (self.condBlock.getTrueOut() is self.op.getParent())

    def discoverConditionalZero(self, vn: Varnode) -> bool:
        boolvn = self.cbranch.getIn(1)
        if not boolvn.isWritten():
            return False
        compareop = boolvn.getDef()
        opc = compareop.code()
        if opc == OpCode.CPUI_INT_NOTEQUAL:
            self.zeroPathIsTrue = not self.zeroPathIsTrue
        elif opc != OpCode.CPUI_INT_EQUAL:
            return False
        a1 = compareop.getIn(0)
        a2 = compareop.getIn(1)
        if a1 is vn:
            zerovn = a2
        elif a2 is vn:
            zerovn = a1
        else:
            return False
        if not zerovn.isConstant():
            return False
        if zerovn.getOffset() != 0:
            return False
        if hasattr(self.cbranch, 'isBooleanFlip') and self.cbranch.isBooleanFlip():
            self.zeroPathIsTrue = not self.zeroPathIsTrue
        return True


class RuleOrPredicate:
    """Simplify predication constructions involving INT_OR.

    Pattern:
        tmp1 = cond ? val1 : 0;
        tmp2 = cond ?  0 : val2;
        result = tmp1 | tmp2;
    Simplified to:
        newtmp = val1 ? val2;  (MULTIEQUAL)
        result = newtmp;
    """

    def __init__(self, g: str) -> None:
        self._group: str = g
        self._name: str = "orpredicate"

    def getOpList(self) -> list:
        return [OpCode.CPUI_INT_OR, OpCode.CPUI_INT_XOR]

    def _checkSingle(self, vn: Varnode, branch: _MultiPredicate,
                     op: PcodeOp, data: Funcdata) -> int:
        if vn.isFree():
            return 0
        if not branch.discoverCbranch():
            return 0
        if branch.op.getOut().loneDescend() is not op:
            return 0
        branch.discoverPathIsTrue()
        if not branch.discoverConditionalZero(vn):
            return 0
        if branch.zeroPathIsTrue:
            return 0
        data.opSetInput(branch.op, vn, branch.zeroSlot)
        data.opRemoveInput(op, 1)
        data.opSetOpcode(op, OpCode.CPUI_COPY)
        data.opSetInput(op, branch.op.getOut(), 0)
        return 1

    def applyOp(self, op: PcodeOp, data: Funcdata) -> int:
        branch0 = _MultiPredicate()
        branch1 = _MultiPredicate()
        test0 = branch0.discoverZeroSlot(op.getIn(0))
        test1 = branch1.discoverZeroSlot(op.getIn(1))
        if not test0 and not test1:
            return 0
        if not test0:
            return self._checkSingle(op.getIn(0), branch1, op, data)
        elif not test1:
            return self._checkSingle(op.getIn(1), branch0, op, data)
        if not branch0.discoverCbranch():
            return 0
        if not branch1.discoverCbranch():
            return 0
        if branch0.condBlock is branch1.condBlock:
            if branch0.zeroBlock is branch1.zeroBlock:
                return 0
        else:
            condmarker = BooleanExpressionMatch()
            if not condmarker.verifyCondition(branch0.cbranch, branch1.cbranch):
                return 0
            if condmarker.getMultiSlot() != -1:
                return 0
            branch0.discoverPathIsTrue()
            branch1.discoverPathIsTrue()
            finalBool = branch0.zeroPathIsTrue == branch1.zeroPathIsTrue
            if condmarker.getFlip():
                finalBool = not finalBool
            if finalBool:
                return 0
        order = branch0.op.compareOrder(branch1.op)
        if order == 0:
            return 0
        if order < 0:
            finalBlock = branch1.op.getParent()
            slot0SetsBranch0 = (branch1.zeroSlot == 0)
        else:
            finalBlock = branch0.op.getParent()
            slot0SetsBranch0 = (branch0.zeroSlot == 1)
        newMulti = data.newOp(2, finalBlock.getStart())
        data.opSetOpcode(newMulti, OpCode.CPUI_MULTIEQUAL)
        if slot0SetsBranch0:
            data.opSetInput(newMulti, branch0.otherVn, 0)
            data.opSetInput(newMulti, branch1.otherVn, 1)
        else:
            data.opSetInput(newMulti, branch1.otherVn, 0)
            data.opSetInput(newMulti, branch0.otherVn, 1)
        newvn = data.newUniqueOut(branch0.otherVn.getSize(), newMulti)
        data.opInsertBegin(newMulti, finalBlock)
        data.opRemoveInput(op, 1)
        data.opSetInput(op, newvn, 0)
        data.opSetOpcode(op, OpCode.CPUI_COPY)
        return 1
