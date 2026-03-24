"""
Remaining rules batch 2a: INDIRECT/MULTIEQUAL collapse rules + misc.
"""
from __future__ import annotations
from ghidra.transform.action import Rule
from ghidra.core.opcodes import OpCode
from ghidra.core.address import calc_mask
from ghidra.ir.op import PcodeOp


class RuleMultiCollapse(Rule):
    """Collapse MULTIEQUAL whose inputs all match the same value (including through chains)."""
    def __init__(self, g): super().__init__(g, 0, "multicollapse")
    def clone(self, gl):
        return RuleMultiCollapse(self._basegroup) if gl.contains(self._basegroup) else None
    def getOpList(self): return [OpCode.CPUI_MULTIEQUAL]
    def applyOp(self, op, data):
        for i in range(op.numInput()):
            if not op.getIn(i).isHeritageKnown():
                return 0
        # Build matchlist: start with direct inputs, expand through nested MULTIEQUALs
        matchlist = [op.getIn(i) for i in range(op.numInput())]
        defvn = None
        skipset = {id(op.getOut())}
        op.getOut().setMark()
        j = 0
        success = True
        while j < len(matchlist):
            copyr = matchlist[j]; j += 1
            if id(copyr) in skipset:
                continue  # Looping back = same value recurring
            if defvn is None:
                if not copyr.isWritten() or copyr.getDef().code() != OpCode.CPUI_MULTIEQUAL:
                    defvn = copyr  # This is the defining branch
            elif defvn is copyr:
                continue  # Matching branch
            elif copyr.isWritten() and copyr.getDef().code() == OpCode.CPUI_MULTIEQUAL:
                # Non-matching branch is a MULTIEQUAL: add its inputs for further matching
                skipset.add(id(copyr))
                copyr.setMark()
                newop = copyr.getDef()
                for i in range(newop.numInput()):
                    matchlist.append(newop.getIn(i))
            else:
                success = False
                break
        # Clear marks
        op.getOut().clearMark()
        for vid in skipset:
            pass  # Would clear marks on all skip varnodes
        if success and defvn is not None:
            data.totalReplace(op.getOut(), defvn)
            data.opDestroy(op)
            return 1
        return 0


class RuleIndirectCollapse(Rule):
    """Collapse INDIRECT when the indirect effect is a no-op."""
    def __init__(self, g): super().__init__(g, 0, "indirectcollapse")
    def clone(self, gl):
        return RuleIndirectCollapse(self._basegroup) if gl.contains(self._basegroup) else None
    def getOpList(self): return [OpCode.CPUI_INDIRECT]
    def applyOp(self, op, data):
        invn = op.getIn(0)
        outvn = op.getOut()
        if invn.getAddr() == outvn.getAddr() and invn.getSize() == outvn.getSize():
            if not op.isIndirectStore():
                data.totalReplace(outvn, invn)
                data.opDestroy(op)
                return 1
        return 0


class RulePullsubMulti(Rule):
    """Pull SUBPIECE through MULTIEQUAL."""
    def __init__(self, g): super().__init__(g, 0, "pullsub_multi")
    def clone(self, gl):
        return RulePullsubMulti(self._basegroup) if gl.contains(self._basegroup) else None
    def getOpList(self): return [OpCode.CPUI_SUBPIECE]

    @staticmethod
    def minMaxUse(vn):
        """Determine the range of bytes actually used from vn via SUBPIECE descendants.
        Returns (maxByte, minByte)."""
        inSize = vn.getSize()
        maxByte = -1
        minByte = inSize
        for op in vn.getDescendants():
            if op.code() == OpCode.CPUI_SUBPIECE:
                mn = int(op.getIn(1).getOffset())
                mx = mn + op.getOut().getSize() - 1
                if mn < minByte:
                    minByte = mn
                if mx > maxByte:
                    maxByte = mx
            else:
                maxByte = inSize - 1
                minByte = 0
                return (maxByte, minByte)
        return (maxByte, minByte)

    @staticmethod
    def replaceDescendants(origVn, newVn, maxByte, minByte, data):
        """Replace origVn with smaller newVn in all SUBPIECE descendants."""
        for op in list(origVn.getDescendants()):
            if op.code() == OpCode.CPUI_SUBPIECE:
                truncAmount = int(op.getIn(1).getOffset())
                outSize = op.getOut().getSize()
                data.opSetInput(op, newVn, 0)
                if newVn.getSize() == outSize:
                    data.opSetOpcode(op, OpCode.CPUI_COPY)
                    data.opRemoveInput(op, 1)
                elif newVn.getSize() > outSize:
                    newTrunc = truncAmount - minByte
                    if newTrunc != truncAmount:
                        data.opSetInput(op, data.newConstant(4, newTrunc), 1)

    @staticmethod
    def acceptableSize(size):
        """Return True if size is a suitable truncated size."""
        if size == 0:
            return False
        if size >= 8:
            return True
        return size in (1, 2, 4)

    @staticmethod
    def findSubpiece(basevn, outsize, shift):
        """Find a predefined SUBPIECE of basevn matching (outsize, shift)."""
        for prevop in basevn.getDescendants():
            if prevop.code() != OpCode.CPUI_SUBPIECE:
                continue
            if basevn.isInput():
                if prevop.getParent().getIndex() != 0:
                    continue
            if not basevn.isWritten():
                continue
            if basevn.getDef().getParent() is not prevop.getParent():
                continue
            if (prevop.getIn(0) is basevn and
                    prevop.getOut().getSize() == outsize and
                    int(prevop.getIn(1).getOffset()) == shift):
                return prevop.getOut()
        return None

    @staticmethod
    def buildSubpiece(basevn, outsize, shift, data):
        """Build a SUBPIECE op near the definition of basevn."""
        if basevn.isInput():
            bb = data.getBasicBlocks().getBlock(0)
            newaddr = bb.getStart()
        else:
            if not basevn.isWritten():
                return None
            newaddr = basevn.getDef().getAddr()
        new_op = data.newOp(2, newaddr)
        data.opSetOpcode(new_op, OpCode.CPUI_SUBPIECE)
        outvn = data.newUniqueOut(outsize, new_op)
        data.opSetInput(new_op, basevn, 0)
        data.opSetInput(new_op, data.newConstant(4, shift), 1)
        if basevn.isInput():
            data.opInsertBegin(new_op, data.getBasicBlocks().getBlock(0))
        else:
            data.opInsertAfter(new_op, basevn.getDef())
        return outvn

    def applyOp(self, op, data):
        invn = op.getIn(0)
        if not invn.isWritten(): return 0
        defop = invn.getDef()
        if defop.code() != OpCode.CPUI_MULTIEQUAL: return 0
        if not invn.loneDescend(): return 0
        # Pull SUBPIECE through: replace each MULTIEQUAL input with SUBPIECE of that input
        shift = int(op.getIn(1).getOffset())
        outsize = op.getOut().getSize()
        newinputs = []
        for i in range(defop.numInput()):
            inp = defop.getIn(i)
            subop = data.newOp(2, defop.getAddr())
            data.opSetOpcode(subop, OpCode.CPUI_SUBPIECE)
            outvn = data.newUniqueOut(outsize, subop)
            data.opSetInput(subop, inp, 0)
            data.opSetInput(subop, data.newConstant(4, shift), 1)
            data.opInsertBegin(subop, defop.getParent())
            newinputs.append(outvn)
        # Replace MULTIEQUAL output size
        data.opSetOpcode(defop, OpCode.CPUI_MULTIEQUAL)
        data.opSetAllInput(defop, newinputs)
        newoutvn = data.newUniqueOut(outsize, defop)
        data.totalReplace(op.getOut(), newoutvn)
        data.opDestroy(op)
        return 1


class RulePullsubIndirect(Rule):
    """Pull SUBPIECE through INDIRECT."""
    def __init__(self, g): super().__init__(g, 0, "pullsub_indirect")
    def clone(self, gl):
        return RulePullsubIndirect(self._basegroup) if gl.contains(self._basegroup) else None
    def getOpList(self): return [OpCode.CPUI_SUBPIECE]
    def applyOp(self, op, data):
        invn = op.getIn(0)
        if not invn.isWritten(): return 0
        if invn.getSize() > 8: return 0
        indir = invn.getDef()
        if indir.code() != OpCode.CPUI_INDIRECT: return 0
        from ghidra.core.space import IPTR_IOP
        if not hasattr(indir.getIn(1), 'getSpace'):
            return 0
        sp = indir.getIn(1).getSpace()
        if sp is None or sp.getType() != IPTR_IOP:
            return 0
        if hasattr(indir.getIn(1), 'getAddr') and hasattr(op, 'getOpFromConst'):
            targ_op = op.getOpFromConst(indir.getIn(1).getAddr())
        else:
            return 0
        if targ_op is None or targ_op.isDead():
            return 0
        if invn.isAddrForce():
            return 0
        maxByte, minByte = RulePullsubMulti.minMaxUse(invn)
        newSize = maxByte - minByte + 1
        if maxByte < minByte or newSize >= invn.getSize():
            return 0
        if not RulePullsubMulti.acceptableSize(newSize):
            return 0
        outvn = op.getOut()
        if hasattr(outvn, 'isPrecisLo') and (outvn.isPrecisLo() or outvn.isPrecisHi()):
            return 0

        consume = calc_mask(newSize) << (8 * minByte)
        consume = (~consume) & calc_mask(invn.getSize())
        indir_in0 = indir.getIn(0)
        indir_consume = indir_in0.getConsume() if hasattr(indir_in0, 'getConsume') else calc_mask(indir_in0.getSize())
        if (consume & indir_consume) != 0:
            return 0

        basevn = indir.getIn(0)
        small1 = RulePullsubMulti.findSubpiece(basevn, newSize, int(op.getIn(1).getOffset()))
        if small1 is None:
            small1 = RulePullsubMulti.buildSubpiece(basevn, newSize, int(op.getIn(1).getOffset()), data)
        if small1 is None:
            return 0

        new_ind = data.newOp(2, indir.getAddr())
        data.opSetOpcode(new_ind, OpCode.CPUI_INDIRECT)
        small2 = data.newUniqueOut(newSize, new_ind)
        data.opSetInput(new_ind, small1, 0)
        if hasattr(data, 'newVarnodeIop'):
            data.opSetInput(new_ind, data.newVarnodeIop(targ_op), 1)
        else:
            data.opSetInput(new_ind, indir.getIn(1), 1)
        data.opInsertBefore(new_ind, indir)

        RulePullsubMulti.replaceDescendants(invn, small2, maxByte, minByte, data)
        return 1


class RulePushMulti(Rule):
    """Push operation through MULTIEQUAL.

    Simplify two-branch MULTIEQUAL where both inputs are constructed in
    functionally equivalent ways. Remove one construction and move the
    other into the merge block.
    """
    def __init__(self, g): super().__init__(g, 0, "push_multi")
    def clone(self, gl):
        return RulePushMulti(self._basegroup) if gl.contains(self._basegroup) else None
    def getOpList(self): return [OpCode.CPUI_MULTIEQUAL]

    @staticmethod
    def findSubstitute(in1, in2, bb, earliest):
        """Find an existing MULTIEQUAL of in1,in2 in bb, or a CSE match."""
        from ghidra.core.expression import functionalEqualityLevel
        for desc_op in list(in1.getDescendants()):
            if desc_op.getParent() is not bb:
                continue
            if desc_op.code() != OpCode.CPUI_MULTIEQUAL:
                continue
            if desc_op.getIn(0) is not in1:
                continue
            if desc_op.getIn(1) is not in2:
                continue
            return desc_op
        if in1 is in2:
            return None
        buf1 = [None, None]
        buf2 = [None, None]
        if functionalEqualityLevel(in1, in2, buf1, buf2) != 0:
            return None
        op1 = in1.getDef()
        op2 = in2.getDef()
        from ghidra.analysis.funcdata import Funcdata
        for i in range(op1.numInput()):
            vn = op1.getIn(i)
            if vn.isConstant():
                continue
            if vn is op2.getIn(i):
                return Funcdata.cseFindInBlock(op1, vn, bb, earliest)
        return None

    def applyOp(self, op, data):
        from ghidra.core.expression import functionalEqualityLevel
        if op.numInput() != 2:
            return 0
        in1 = op.getIn(0)
        in2 = op.getIn(1)
        if not in1.isWritten():
            return 0
        if not in2.isWritten():
            return 0
        if in1.isSpacebase():
            return 0
        if in2.isSpacebase():
            return 0
        buf1 = [None, None]
        buf2 = [None, None]
        res = functionalEqualityLevel(in1, in2, buf1, buf2)
        if res < 0:
            return 0
        if res > 1:
            return 0
        op1 = in1.getDef()
        if op1.code() == OpCode.CPUI_SUBPIECE:
            return 0
        bl = op.getParent()
        earliest = bl.earliestUse(op.getOut()) if hasattr(bl, 'earliestUse') else None
        if op1.code() == OpCode.CPUI_COPY:
            if res == 0:
                return 0
            substitute = RulePushMulti.findSubstitute(buf1[0], buf2[0], bl, earliest)
            if substitute is None:
                return 0
            data.totalReplace(op.getOut(), substitute.getOut())
            data.opDestroy(op)
            return 1
        op2 = in2.getDef()
        if in1.loneDescend() is not op:
            return 0
        if in2.loneDescend() is not op:
            return 0
        outvn = op.getOut()
        data.opSetOutput(op1, outvn)
        data.opUninsert(op1)
        if res == 1:
            slot1 = op1.getSlot(buf1[0])
            substitute = RulePushMulti.findSubstitute(buf1[0], buf2[0], bl, earliest)
            if substitute is None:
                substitute = data.newOp(2, op.getAddr())
                data.opSetOpcode(substitute, OpCode.CPUI_MULTIEQUAL)
                if buf1[0].getAddr() == buf2[0].getAddr() and not buf1[0].isAddrTied():
                    data.newVarnodeOut(buf1[0].getSize(), buf1[0].getAddr(), substitute)
                else:
                    data.newUniqueOut(buf1[0].getSize(), substitute)
                data.opSetInput(substitute, buf1[0], 0)
                data.opSetInput(substitute, buf2[0], 1)
                data.opInsertBegin(substitute, bl)
            data.opSetInput(op1, substitute.getOut(), slot1)
            data.opInsertAfter(op1, substitute)
        else:
            data.opInsertBegin(op1, bl)
        data.opDestroy(op)
        data.opDestroy(op2)
        return 1


class RuleSelectCse(Rule):
    """Common subexpression elimination: if two ops in same block have same opcode and inputs, merge."""
    def __init__(self, g): super().__init__(g, 0, "selectcse")
    def clone(self, gl):
        return RuleSelectCse(self._basegroup) if gl.contains(self._basegroup) else None
    def getOpList(self): return [OpCode.CPUI_INT_AND, OpCode.CPUI_INT_OR, OpCode.CPUI_INT_XOR]
    def applyOp(self, op, data):
        bl = op.getParent()
        if bl is None: return 0
        opc = op.code()
        in0 = op.getIn(0)
        in1 = op.getIn(1)
        for other in bl.getOpList():
            if other is op: continue
            if other.code() != opc: continue
            if other.getIn(0) is in0 and other.getIn(1) is in1:
                data.totalReplace(op.getOut(), other.getOut())
                data.opDestroy(op)
                return 1
            if op.code() in (OpCode.CPUI_INT_AND, OpCode.CPUI_INT_OR, OpCode.CPUI_INT_XOR):
                if other.getIn(0) is in1 and other.getIn(1) is in0:
                    data.totalReplace(op.getOut(), other.getOut())
                    data.opDestroy(op)
                    return 1
        return 0


class RuleCollectTerms(Rule):
    """Collect terms: x + x => x * 2, x + x*c => x*(c+1)."""
    def __init__(self, g): super().__init__(g, 0, "collectterms")
    def clone(self, gl):
        return RuleCollectTerms(self._basegroup) if gl.contains(self._basegroup) else None
    def getOpList(self): return [OpCode.CPUI_INT_ADD]
    def applyOp(self, op, data):
        in0 = op.getIn(0)
        in1 = op.getIn(1)
        if in0 is in1:
            # x + x => x * 2
            data.opSetOpcode(op, OpCode.CPUI_INT_MULT)
            data.opSetInput(op, data.newConstant(in0.getSize(), 2), 1)
            return 1
        return 0


class RuleSubCommute(Rule):
    """Commute SUBPIECE with various operations (AND, OR, XOR, ADD, MULT, NEGATE, etc.)."""
    def __init__(self, g): super().__init__(g, 0, "subcommute")
    def clone(self, gl):
        return RuleSubCommute(self._basegroup) if gl.contains(self._basegroup) else None
    def getOpList(self): return [OpCode.CPUI_SUBPIECE]
    def applyOp(self, op, data):
        base = op.getIn(0)
        if not base.isWritten(): return 0
        offset = int(op.getIn(1).getOffset())
        outvn = op.getOut()
        insize = base.getSize()
        longform = base.getDef()
        opc = longform.code()
        # Determine which ops commute with SUBPIECE
        if opc in (OpCode.CPUI_INT_NEGATE, OpCode.CPUI_INT_XOR,
                   OpCode.CPUI_INT_AND, OpCode.CPUI_INT_OR):
            pass  # Bitwise ops commute at any offset
        elif opc in (OpCode.CPUI_INT_ADD, OpCode.CPUI_INT_MULT):
            if offset != 0: return 0  # Only commutes with least significant SUBPIECE
        elif opc in (OpCode.CPUI_INT_DIV, OpCode.CPUI_INT_REM):
            if offset != 0: return 0
            # Only commutes if inputs are zero-extended
            if not longform.getIn(0).isWritten(): return 0
            if longform.getIn(0).getDef().code() != OpCode.CPUI_INT_ZEXT: return 0
        elif opc in (OpCode.CPUI_INT_SDIV, OpCode.CPUI_INT_SREM):
            if offset != 0: return 0
            if not longform.getIn(0).isWritten(): return 0
            if longform.getIn(0).getDef().code() != OpCode.CPUI_INT_SEXT: return 0
        else:
            return 0
        # Make sure no other piece of base is getting used
        if base.loneDescend() is not op: return 0
        outsize = outvn.getSize()
        # Commute: replace each input with SUBPIECE of that input
        for i in range(longform.numInput()):
            invn = longform.getIn(i)
            if invn.isConstant():
                # Truncate constant
                val = invn.getOffset()
                if offset < 8:
                    val = (val >> (offset * 8)) & calc_mask(outsize)
                else:
                    val = 0
                newvn = data.newConstant(outsize, val)
            else:
                subop = data.newOp(2, op.getAddr())
                data.opSetOpcode(subop, OpCode.CPUI_SUBPIECE)
                newvn = data.newUniqueOut(outsize, subop)
                data.opSetInput(subop, invn, 0)
                data.opSetInput(subop, data.newConstant(4, offset), 1)
                data.opInsertBefore(subop, op)
            longform.setInput(newvn, i)
            newvn.addDescend(longform)
        # Change longform output size
        data.opSetOpcode(op, opc)
        for i in range(longform.numInput()):
            data.opSetInput(op, longform.getIn(i), i)
        # Resize output
        return 1


class RuleConditionalMove(Rule):
    """Simplify various conditional move situations.

    Converts 2-input MULTIEQUAL with diamond CFG into BOOL_AND/BOOL_OR,
    COPY, INT_ZEXT, or BOOL_NEGATE depending on the pattern.
    C++ ref: ``RuleConditionalMove`` in ruleaction.cc
    """
    def __init__(self, g): super().__init__(g, 0, "conditionalmove")
    def clone(self, gl):
        return RuleConditionalMove(self._basegroup) if gl.contains(self._basegroup) else None
    def getOpList(self): return [OpCode.CPUI_MULTIEQUAL]

    @staticmethod
    def checkBoolean(vn):
        """Check if a Varnode is a boolean value; return root or None.
        C++ ref: ``RuleConditionalMove::checkBoolean``
        """
        if not vn.isWritten():
            return None
        op = vn.getDef()
        if op.isBoolOutput():
            return vn
        if op.code() == OpCode.CPUI_COPY:
            invn = op.getIn(0)
            if invn.isConstant() and (invn.getOffset() & ~1) == 0:
                return invn
        return None

    @staticmethod
    def gatherExpression(vn, ops, root, branch):
        """Can the expression be propagated out of the branch? Collect ops to clone.
        C++ ref: ``RuleConditionalMove::gatherExpression``
        """
        if vn.isConstant():
            return True
        if vn.isFree() or vn.isAddrTied():
            return False
        if root is branch:
            return True
        if not vn.isWritten():
            return True
        op = vn.getDef()
        if op.getParent() is not branch:
            return True
        ops.append(op)
        pos = 0
        while pos < len(ops):
            cur = ops[pos]; pos += 1
            if cur.getEvalType() == PcodeOp.special:
                return False
            for i in range(cur.numInput()):
                inv = cur.getIn(i)
                if inv.isFree() and not inv.isConstant():
                    return False
                if inv.isWritten() and inv.getDef().getParent() is branch:
                    if inv.isAddrTied():
                        return False
                    if inv.loneDescend() is not cur:
                        return False
                    if len(ops) >= 4:
                        return False
                    ops.append(inv.getDef())
        return True

    @staticmethod
    def constructBool(vn, insertop, ops, data):
        """Reproduce the boolean expression, cloning ops if needed.
        C++ ref: ``RuleConditionalMove::constructBool``
        """
        if not ops:
            return vn
        ops.sort(key=lambda o: o.getSeqNum().getOrder())
        remap = {}
        resvn = None
        for orig in ops:
            dup = data.newOp(orig.numInput(), insertop.getAddr())
            data.opSetOpcode(dup, orig.code())
            outvn = data.newUniqueOut(orig.getOut().getSize(), dup)
            remap[id(orig.getOut())] = outvn
            resvn = outvn
            data.opInsertBefore(dup, insertop)
            for j in range(orig.numInput()):
                inv = orig.getIn(j)
                mapped = remap.get(id(inv))
                data.opSetInput(dup, mapped if mapped is not None else inv, j)
        return resvn

    def applyOp(self, op, data):
        if op.numInput() != 2:
            return 0
        bool0 = RuleConditionalMove.checkBoolean(op.getIn(0))
        if bool0 is None:
            return 0
        bool1 = RuleConditionalMove.checkBoolean(op.getIn(1))
        if bool1 is None:
            return 0
        bb = op.getParent()
        if bb.sizeIn() < 2:
            return 0
        inblock0 = bb.getIn(0)
        inblock1 = bb.getIn(1)
        if inblock0.sizeOut() == 1:
            if inblock0.sizeIn() != 1: return 0
            rootblock0 = inblock0.getIn(0)
        else:
            rootblock0 = inblock0
        if inblock1.sizeOut() == 1:
            if inblock1.sizeIn() != 1: return 0
            rootblock1 = inblock1.getIn(0)
        else:
            rootblock1 = inblock1
        if rootblock0 is not rootblock1:
            return 0
        cbranch = rootblock0.lastOp()
        if cbranch is None or cbranch.code() != OpCode.CPUI_CBRANCH:
            return 0
        opList0 = []
        if not RuleConditionalMove.gatherExpression(bool0, opList0, rootblock0, inblock0):
            return 0
        opList1 = []
        if not RuleConditionalMove.gatherExpression(bool1, opList1, rootblock0, inblock1):
            return 0
        if rootblock0 is not inblock0:
            path0istrue = (rootblock0.getTrueOut() is inblock0)
        else:
            path0istrue = (rootblock0.getTrueOut() is not inblock1)
        if cbranch.isBooleanFlip():
            path0istrue = not path0istrue
        # Both non-constant booleans
        if not bool0.isConstant() and not bool1.isConstant():
            return self._applyNonConst(op, data, bb, cbranch, bool0, bool1,
                                       opList0, opList1, inblock0, inblock1,
                                       rootblock0, path0istrue)
        # At least one constant — always transform
        data.opUninsert(op)
        sz = op.getOut().getSize()
        if bool0.isConstant() and bool1.isConstant():
            self._applyBothConst(op, data, bb, cbranch, bool0, bool1,
                                 sz, path0istrue)
        elif bool0.isConstant():
            self._applyOneConst(op, data, bb, cbranch, bool0, bool1,
                                opList1, sz, path0istrue, True)
        else:
            self._applyOneConst(op, data, bb, cbranch, bool1, bool0,
                                opList0, sz, path0istrue, False)
        return 1

    def _applyNonConst(self, op, data, bb, cbranch, bool0, bool1,
                       opList0, opList1, inblock0, inblock1, rootblock0, path0istrue):
        """Handle case where both MULTIEQUAL inputs are non-constant booleans."""
        if inblock0 is rootblock0:
            boolvn = cbranch.getIn(1)
            andor = path0istrue
            if boolvn is not op.getIn(0):
                if not boolvn.isWritten(): return 0
                neg = boolvn.getDef()
                if neg.code() != OpCode.CPUI_BOOL_NEGATE: return 0
                if neg.getIn(0) is not op.getIn(0): return 0
                andor = not andor
            opc = OpCode.CPUI_BOOL_OR if andor else OpCode.CPUI_BOOL_AND
            data.opUninsert(op)
            data.opSetOpcode(op, opc)
            data.opInsertBegin(op, bb)
            fv = RuleConditionalMove.constructBool(bool0, op, opList0, data)
            sv = RuleConditionalMove.constructBool(bool1, op, opList1, data)
            data.opSetInput(op, fv, 0); data.opSetInput(op, sv, 1)
            return 1
        elif inblock1 is rootblock0:
            boolvn = cbranch.getIn(1)
            andor = not path0istrue
            if boolvn is not op.getIn(1):
                if not boolvn.isWritten(): return 0
                neg = boolvn.getDef()
                if neg.code() != OpCode.CPUI_BOOL_NEGATE: return 0
                if neg.getIn(0) is not op.getIn(1): return 0
                andor = not andor
            opc = OpCode.CPUI_BOOL_OR if andor else OpCode.CPUI_BOOL_AND
            data.opUninsert(op)
            data.opSetOpcode(op, opc)
            data.opInsertBegin(op, bb)
            fv = RuleConditionalMove.constructBool(bool1, op, opList1, data)
            sv = RuleConditionalMove.constructBool(bool0, op, opList0, data)
            data.opSetInput(op, fv, 0); data.opSetInput(op, sv, 1)
            return 1
        return 0

    def _applyBothConst(self, op, data, bb, cbranch, bool0, bool1, sz, path0istrue):
        """Handle case where both MULTIEQUAL inputs are constant booleans."""
        if bool0.getOffset() == bool1.getOffset():
            data.opRemoveInput(op, 1)
            data.opSetOpcode(op, OpCode.CPUI_COPY)
            data.opSetInput(op, data.newConstant(sz, bool0.getOffset()), 0)
            data.opInsertBegin(op, bb)
        else:
            data.opRemoveInput(op, 1)
            boolvn = cbranch.getIn(1)
            needcomp = ((bool0.getOffset() == 0) == path0istrue)
            if sz == 1:
                data.opSetOpcode(op, OpCode.CPUI_BOOL_NEGATE if needcomp else OpCode.CPUI_COPY)
                data.opInsertBegin(op, bb)
                data.opSetInput(op, boolvn, 0)
            else:
                data.opSetOpcode(op, OpCode.CPUI_INT_ZEXT)
                data.opInsertBegin(op, bb)
                if needcomp:
                    boolvn = data.opBoolNegate(boolvn, op, False)
                data.opSetInput(op, boolvn, 0)

    def _applyOneConst(self, op, data, bb, cbranch, boolconst, boolother,
                       opListOther, _sz, path0istrue, const_is_0):
        """Handle case where one MULTIEQUAL input is constant, other is non-constant."""
        if const_is_0:
            needcomp = (path0istrue != (boolconst.getOffset() != 0))
            opc = OpCode.CPUI_BOOL_OR if (boolconst.getOffset() != 0) else OpCode.CPUI_BOOL_AND
        else:
            needcomp = (path0istrue == (boolconst.getOffset() != 0))
            opc = OpCode.CPUI_BOOL_OR if (boolconst.getOffset() != 0) else OpCode.CPUI_BOOL_AND
        data.opSetOpcode(op, opc)
        data.opInsertBegin(op, bb)
        boolvn = cbranch.getIn(1)
        if needcomp:
            boolvn = data.opBoolNegate(boolvn, op, False)
        body = RuleConditionalMove.constructBool(boolother, op, opListOther, data)
        data.opSetInput(op, boolvn, 0)
        data.opSetInput(op, body, 1)


class RuleFloatSign(Rule):
    """Clean up float sign: FLOAT_MULT(x, -1.0) => FLOAT_NEG(x)."""
    def __init__(self, g): super().__init__(g, 0, "floatsign")
    def clone(self, gl):
        return RuleFloatSign(self._basegroup) if gl.contains(self._basegroup) else None
    def getOpList(self): return [OpCode.CPUI_FLOAT_MULT]
    def applyOp(self, op, data):
        for slot in range(2):
            vn = op.getIn(slot)
            if not vn.isConstant(): continue
            # Check for -1.0 pattern (sign bit set, rest matches 1.0)
            sz = vn.getSize()
            val = vn.getOffset()
            if sz == 4 and val == 0xBF800000:  # -1.0f
                data.opSetOpcode(op, OpCode.CPUI_FLOAT_NEG)
                data.opSetInput(op, op.getIn(1 - slot), 0)
                data.opRemoveInput(op, 1)
                return 1
            if sz == 8 and val == 0xBFF0000000000000:  # -1.0
                data.opSetOpcode(op, OpCode.CPUI_FLOAT_NEG)
                data.opSetInput(op, op.getIn(1 - slot), 0)
                data.opRemoveInput(op, 1)
                return 1
        return 0


class RuleFloatSignCleanup(Rule):
    """Cleanup: FLOAT_ABS(FLOAT_NEG(x)) => FLOAT_ABS(x)."""
    def __init__(self, g): super().__init__(g, 0, "floatsigncleanup")
    def clone(self, gl):
        return RuleFloatSignCleanup(self._basegroup) if gl.contains(self._basegroup) else None
    def getOpList(self): return [OpCode.CPUI_FLOAT_ABS]
    def applyOp(self, op, data):
        invn = op.getIn(0)
        if not invn.isWritten(): return 0
        if invn.getDef().code() == OpCode.CPUI_FLOAT_NEG:
            if invn.loneDescend() is op:
                data.opSetInput(op, invn.getDef().getIn(0), 0)
                data.opDestroy(invn.getDef())
                return 1
        return 0


class RuleIgnoreNan(Rule):
    """Replace FLOAT_NAN with constant false when NaN-ignore mode is on."""
    def __init__(self, g): super().__init__(g, 0, "ignorenan")
    def clone(self, gl):
        return RuleIgnoreNan(self._basegroup) if gl.contains(self._basegroup) else None
    def getOpList(self): return [OpCode.CPUI_FLOAT_NAN]
    def applyOp(self, op, data):
        glb = data.getArch()
        if glb is None: return 0
        if not getattr(glb, 'nan_ignore_all', False): return 0
        outvn = op.getOut()
        if outvn is None: return 0
        data.opSetOpcode(op, OpCode.CPUI_COPY)
        data.opSetInput(op, data.newConstant(outvn.getSize(), 0), 0)
        return 1


class RuleInt2FloatCollapse(Rule):
    """Collapse INT2FLOAT followed by FLOAT2FLOAT."""
    def __init__(self, g): super().__init__(g, 0, "int2floatcollapse")
    def clone(self, gl):
        return RuleInt2FloatCollapse(self._basegroup) if gl.contains(self._basegroup) else None
    def getOpList(self): return [OpCode.CPUI_FLOAT_FLOAT2FLOAT]
    def applyOp(self, op, data):
        invn = op.getIn(0)
        if not invn.isWritten(): return 0
        if invn.getDef().code() != OpCode.CPUI_FLOAT_INT2FLOAT: return 0
        if not invn.loneDescend(): return 0
        origop = invn.getDef()
        data.opSetInput(op, origop.getIn(0), 0)
        data.opSetOpcode(op, OpCode.CPUI_FLOAT_INT2FLOAT)
        data.opDestroy(origop)
        return 1


class RuleUnsigned2Float(Rule):
    """Convert unsigned INT2FLOAT: if input is ZEXT, use the smaller input directly."""
    def __init__(self, g): super().__init__(g, 0, "unsigned2float")
    def clone(self, gl):
        return RuleUnsigned2Float(self._basegroup) if gl.contains(self._basegroup) else None
    def getOpList(self): return [OpCode.CPUI_FLOAT_INT2FLOAT]
    def applyOp(self, op, data):
        invn = op.getIn(0)
        if not invn.isWritten(): return 0
        defop = invn.getDef()
        if defop.code() == OpCode.CPUI_INT_ZEXT:
            if invn.loneDescend() is op:
                data.opSetInput(op, defop.getIn(0), 0)
                data.opDestroy(defop)
                return 1
        return 0
