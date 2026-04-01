"""
Remaining rules batch 2c: Pointer/type-dependent rules + LOAD/STORE rules.
These are the final 10 rules needed for 136/136 coverage.
"""
from __future__ import annotations
from ghidra.transform.action import Rule
from ghidra.core.opcodes import OpCode
from ghidra.core.address import calc_mask


class RulePushPtr(Rule):
    """Push pointer type information through INT_ADD.

    If one input to INT_ADD is a pointer, push (a + b) + c => a + (b + c)
    so that the pointer stays at the top level.
    """
    def __init__(self, g): super().__init__(g, 0, "pushptr")
    def clone(self, gl):
        return RulePushPtr(self._basegroup) if gl.contains(self._basegroup) else None
    def getOpList(self): return [OpCode.CPUI_INT_ADD]

    @staticmethod
    def buildVarnodeOut(vn, op, data):
        """Generate a duplicate Varnode as output of the given PcodeOp.

        C++ ref: RulePushPtr::buildVarnodeOut
        """
        from ghidra.core.space import IPTR_INTERNAL
        if vn.isAddrTied() or vn.getSpace().getType() == IPTR_INTERNAL:
            return data.newUniqueOut(vn.getSize(), op)
        return data.newVarnodeOut(vn.getSize(), vn.getAddr(), op)

    @staticmethod
    def collectDuplicateNeeds(dupList, vn):
        """Collect ops that need duplication because vn has multiple descendants."""
        if vn.isConstant():
            return
        if not vn.isWritten():
            return
        defOp = vn.getDef()
        if defOp.code() not in (OpCode.CPUI_INT_MULT, OpCode.CPUI_INT_LEFT):
            return
        if vn.loneDescend() is not None:
            return
        dupList.append(defOp)

    @staticmethod
    def duplicateNeed(defOp, data):
        """Duplicate an op so each descendant gets its own copy."""
        outvn = defOp.getOut()
        descList = list(outvn.getDescendants())
        for i in range(1, len(descList)):
            desc = descList[i]
            slot = desc.getSlot(outvn)
            newop = data.newOp(defOp.numInput(), desc.getAddr())
            data.opSetOpcode(newop, defOp.code())
            newout = data.newUniqueOut(outvn.getSize(), newop)
            for j in range(defOp.numInput()):
                data.opSetInput(newop, defOp.getIn(j), j)
            data.opInsertBefore(newop, desc)
            data.opSetInput(desc, newout, slot)

    def applyOp(self, op, data):
        if not hasattr(data, 'hasTypeRecoveryStarted') or not data.hasTypeRecoveryStarted():
            return 0
        from ghidra.types.datatype import TYPE_PTR
        vni = None
        slot = -1
        for s in range(op.numInput()):
            vni = op.getIn(s)
            tp = vni.getTypeReadFacing(op) if hasattr(vni, 'getTypeReadFacing') else None
            if tp is not None and hasattr(tp, 'getMetatype') and tp.getMetatype() == TYPE_PTR:
                slot = s
                break
        if slot < 0:
            return 0

        # Check evaluatePointerExpression equivalent
        if hasattr(RulePtrArith, 'evaluatePointerExpression'):
            if RulePtrArith.evaluatePointerExpression(op, slot) != 1:
                return 0
        else:
            return 0

        vn = op.getOut()
        vnadd2 = op.getIn(1 - slot)
        duplicateList = []
        if vn.loneDescend() is None:
            RulePushPtr.collectDuplicateNeeds(duplicateList, vnadd2)

        while True:
            descIter = list(vn.getDescendants())
            if not descIter:
                break
            decop = descIter[0]
            j = decop.getSlot(vn)
            vnadd1 = decop.getIn(1 - j)

            newop = data.newOp(2, decop.getAddr())
            data.opSetOpcode(newop, OpCode.CPUI_INT_ADD)
            newout = data.newUniqueOut(vnadd1.getSize(), newop)

            data.opSetInput(decop, vni, 0)
            data.opSetInput(decop, newout, 1)
            data.opSetInput(newop, vnadd1, 0)
            data.opSetInput(newop, vnadd2, 1)
            data.opInsertBefore(newop, decop)

        isAutoLive = vn.isAutoLive() if hasattr(vn, 'isAutoLive') else False
        if not isAutoLive:
            data.opDestroy(op)
        for dupOp in duplicateList:
            RulePushPtr.duplicateNeed(dupOp, data)
        return 1


class RuleStructOffset0(Rule):
    """Simplify PTRSUB with offset 0: ptr->field[0] => *ptr when field is at offset 0."""
    def __init__(self, g): super().__init__(g, 0, "structoffset0")
    def clone(self, gl):
        return RuleStructOffset0(self._basegroup) if gl.contains(self._basegroup) else None
    def getOpList(self): return [OpCode.CPUI_PTRSUB]
    def applyOp(self, op, data):
        if not op.getIn(1).isConstant():
            return 0
        if op.getIn(1).getOffset() != 0:
            return 0
        # PTRSUB(ptr, 0) => COPY(ptr) when accessing struct at offset 0
        data.opRemoveInput(op, 1)
        data.opSetOpcode(op, OpCode.CPUI_COPY)
        return 1


class AddTreeState:
    """Analyze pointer arithmetic ADD trees for conversion to PTRADD/PTRSUB.

    C++ ref: ruleaction.hh / ruleaction.cc — AddTreeState
    """

    def __init__(self, data, op, slot: int) -> None:
        from ghidra.core.address import calc_mask, sign_extend
        from ghidra.types.datatype import TYPE_PTR, TYPE_PTRREL, TYPE_ARRAY, TYPE_STRUCT, TYPE_SPACEBASE
        self.data = data
        self.baseOp = op
        self.baseSlot = slot
        self.biggestNonMultCoeff: int = 0
        self.ptr = op.getIn(slot)
        self.ct = self.ptr.getTypeReadFacing(op) if hasattr(self.ptr, 'getTypeReadFacing') else self.ptr.getType()
        self.ptrsize: int = self.ptr.getSize()
        self.ptrmask: int = calc_mask(self.ptrsize)
        self.baseType = self.ct.getPtrTo() if self.ct is not None and hasattr(self.ct, 'getPtrTo') else None
        self.multsum: int = 0
        self.nonmultsum: int = 0
        self.pRelType = None
        if self.ct is not None and hasattr(self.ct, 'isFormalPointerRel') and self.ct.isFormalPointerRel():
            self.pRelType = self.ct
            if hasattr(self.pRelType, 'getParent'):
                self.baseType = self.pRelType.getParent()
            if hasattr(self.pRelType, 'getAddressOffset'):
                self.nonmultsum = self.pRelType.getAddressOffset() & self.ptrmask
        self.size: int = 0
        if self.baseType is not None:
            if hasattr(self.baseType, 'isVariableLength') and self.baseType.isVariableLength():
                self.size = 0
            else:
                align = self.baseType.getAlignSize() if hasattr(self.baseType, 'getAlignSize') else self.baseType.getSize()
                ws = self.ct.getWordSize() if hasattr(self.ct, 'getWordSize') else 1
                self.size = align // ws if ws > 1 else align
        self.correct: int = 0
        self.offset: int = 0
        self.valid: bool = True
        self.preventDistribution: bool = False
        self.isDistributeUsed: bool = False
        self.isSubtype: bool = False
        self.distributeOp = None
        self.multiple: list = []
        self.coeff: list = []
        self.nonmult: list = []
        ws = self.ct.getWordSize() if self.ct is not None and hasattr(self.ct, 'getWordSize') else 1
        unitsize = ws  # addressToByteInt(1, ws)
        align = self.baseType.getAlignSize() if self.baseType is not None and hasattr(self.baseType, 'getAlignSize') else 0
        self.isDegenerate: bool = (0 < align <= unitsize)

    def clear(self) -> None:
        """Reset for a new ADD tree traversal."""
        self.multsum = 0
        self.nonmultsum = 0
        self.biggestNonMultCoeff = 0
        if self.pRelType is not None and hasattr(self.pRelType, 'getAddressOffset'):
            self.nonmultsum = self.pRelType.getAddressOffset() & self.ptrmask
        self.multiple.clear()
        self.coeff.clear()
        self.nonmult.clear()
        self.correct = 0
        self.offset = 0
        self.valid = True
        self.isDistributeUsed = False
        self.isSubtype = False
        self.distributeOp = None

    def initAlternateForm(self) -> bool:
        """Prepare analysis for alternate form of base pointer (TypePointerRel).

        C++ ref: AddTreeState::initAlternateForm
        """
        if self.pRelType is None:
            return False
        self.pRelType = None
        self.baseType = self.ct.getPtrTo() if self.ct is not None and hasattr(self.ct, 'getPtrTo') else None
        if self.baseType is not None and hasattr(self.baseType, 'isVariableLength') and self.baseType.isVariableLength():
            self.size = 0
        elif self.baseType is not None:
            align = self.baseType.getAlignSize() if hasattr(self.baseType, 'getAlignSize') else self.baseType.getSize()
            ws = self.ct.getWordSize() if hasattr(self.ct, 'getWordSize') else 1
            self.size = align // ws if ws > 1 else align
        else:
            self.size = 0
        ws = self.ct.getWordSize() if self.ct is not None and hasattr(self.ct, 'getWordSize') else 1
        unitsize = ws
        align = self.baseType.getAlignSize() if self.baseType is not None and hasattr(self.baseType, 'getAlignSize') else 0
        self.isDegenerate = (0 < align <= unitsize)
        self.preventDistribution = False
        self.clear()
        return True

    def hasMatchingSubType(self, off: int, arrayHint: int) -> tuple:
        """Find sub-component matching the given offset.

        C++ ref: AddTreeState::hasMatchingSubType
        Returns (found: bool, newoff: int)
        """
        if arrayHint == 0:
            if self.baseType is not None and hasattr(self.baseType, 'getSubType'):
                sub, newoff = self.baseType.getSubType(off)
                return (sub is not None, newoff)
            return (False, 0)

        # Try arrayed component search
        typeBefore = None
        offBefore = 0
        elSizeBefore = 0
        typeAfter = None
        offAfter = 0
        elSizeAfter = 0
        if self.baseType is not None and hasattr(self.baseType, 'nearestArrayedComponentBackward'):
            result = self.baseType.nearestArrayedComponentBackward(off)
            if result is not None and len(result) == 3:
                typeBefore, offBefore, elSizeBefore = result
        if typeBefore is not None:
            if arrayHint == 1 or elSizeBefore == arrayHint:
                ws = self.ct.getWordSize() if hasattr(self.ct, 'getWordSize') else 1
                sizeAddr = typeBefore.getSize() // ws if ws > 1 else typeBefore.getSize()
                if 0 <= offBefore < sizeAddr:
                    return (True, offBefore)

        if self.baseType is not None and hasattr(self.baseType, 'nearestArrayedComponentForward'):
            result = self.baseType.nearestArrayedComponentForward(off)
            if result is not None and len(result) == 3:
                typeAfter, offAfter, elSizeAfter = result

        if typeBefore is None and typeAfter is None:
            if self.baseType is not None and hasattr(self.baseType, 'getSubType'):
                sub, newoff = self.baseType.getSubType(off)
                return (sub is not None, newoff)
            return (False, 0)
        if typeBefore is None:
            return (True, offAfter)
        if typeAfter is None:
            return (True, offBefore)

        distBefore = abs(offBefore)
        distAfter = abs(offAfter)
        if arrayHint != 1:
            if elSizeBefore != arrayHint:
                distBefore += 0x1000
            if elSizeAfter != arrayHint:
                distAfter += 0x1000
        return (True, offAfter if distAfter < distBefore else offBefore)

    def checkMultTerm(self, vn, op, treeCoeff: int) -> bool:
        """Accumulate details of INT_MULT term and continue traversal if appropriate.

        C++ ref: AddTreeState::checkMultTerm
        """
        from ghidra.core.address import sign_extend
        vnconst = op.getIn(1)
        vnterm = op.getIn(0)
        if vnterm.isFree():
            self.valid = False
            return False
        if vnconst.isConstant():
            val = (vnconst.getOffset() * treeCoeff) & self.ptrmask
            sval = sign_extend(val, vn.getSize() * 8 - 1)
            rem = sval if self.size == 0 else sval % self.size
            if rem != 0:
                if val >= self.size and self.size != 0:
                    self.valid = False
                    return False
                if not self.preventDistribution:
                    if vnterm.isWritten() and vnterm.getDef().code() == OpCode.CPUI_INT_ADD:
                        if self.distributeOp is None:
                            self.distributeOp = op
                        return self.spanAddTree(vnterm.getDef(), val)
                vncoeff = (-sval) if sval < 0 else sval
                if vncoeff > self.biggestNonMultCoeff:
                    self.biggestNonMultCoeff = vncoeff
                return True
            else:
                if treeCoeff != 1:
                    self.isDistributeUsed = True
                self.multiple.append(vnterm)
                self.coeff.append(sval)
                return False
        if treeCoeff > self.biggestNonMultCoeff:
            self.biggestNonMultCoeff = treeCoeff
        return True

    def checkTerm(self, vn, treeCoeff: int) -> bool:
        """Accumulate details of given term and continue tree traversal.

        C++ ref: AddTreeState::checkTerm
        """
        from ghidra.core.address import sign_extend
        from ghidra.types.datatype import TYPE_ARRAY, TYPE_STRUCT
        if vn is self.ptr:
            return False
        if vn.isConstant():
            val = vn.getOffset() * treeCoeff
            sval = sign_extend(val, vn.getSize() * 8 - 1)
            rem = sval if self.size == 0 else (sval % self.size)
            if rem != 0:
                if treeCoeff != 1:
                    if self.baseType is not None:
                        mt = self.baseType.getMetatype()
                        if mt == TYPE_ARRAY or mt == TYPE_STRUCT:
                            self.isDistributeUsed = True
                self.nonmultsum += val
                self.nonmultsum &= self.ptrmask
                return True
            if treeCoeff != 1:
                self.isDistributeUsed = True
            self.multsum += val
            self.multsum &= self.ptrmask
            return False
        if vn.isWritten():
            defop = vn.getDef()
            if defop.code() == OpCode.CPUI_INT_ADD:
                return self.spanAddTree(defop, treeCoeff)
            if defop.code() == OpCode.CPUI_COPY:
                self.valid = False
                return False
            if defop.code() == OpCode.CPUI_INT_MULT:
                return self.checkMultTerm(vn, defop, treeCoeff)
        elif vn.isFree():
            self.valid = False
            return False
        if treeCoeff > self.biggestNonMultCoeff:
            self.biggestNonMultCoeff = treeCoeff
        return True

    def spanAddTree(self, op, treeCoeff: int) -> bool:
        """Walk the given sub-tree accumulating details.

        C++ ref: AddTreeState::spanAddTree
        """
        one_is_non = self.checkTerm(op.getIn(0), treeCoeff)
        if not self.valid:
            return False
        two_is_non = self.checkTerm(op.getIn(1), treeCoeff)
        if not self.valid:
            return False
        if self.pRelType is not None:
            if self.multsum != 0 or self.nonmultsum >= self.size or len(self.multiple) > 0:
                self.valid = False
                return False
        if one_is_non and two_is_non:
            return True
        if one_is_non:
            self.nonmult.append(op.getIn(0))
        if two_is_non:
            self.nonmult.append(op.getIn(1))
        return False

    def calcSubtype(self) -> None:
        """Calculate final sub-type offset.

        C++ ref: AddTreeState::calcSubtype
        """
        from ghidra.core.address import sign_extend
        from ghidra.types.datatype import TYPE_SPACEBASE, TYPE_STRUCT, TYPE_ARRAY
        tmpoff = (self.multsum + self.nonmultsum) & self.ptrmask
        if self.size == 0 or tmpoff < self.size:
            self.offset = tmpoff
        else:
            stmpoff = sign_extend(tmpoff, self.ptrsize * 8 - 1)
            stmpoff = stmpoff % self.size
            if stmpoff >= 0:
                self.offset = stmpoff
            else:
                if (self.baseType is not None and self.baseType.getMetatype() == TYPE_STRUCT
                        and self.biggestNonMultCoeff != 0 and self.multsum == 0):
                    self.offset = tmpoff
                else:
                    self.offset = stmpoff + self.size
        self.correct = self.nonmultsum
        self.multsum = (tmpoff - self.offset) & self.ptrmask
        if not self.nonmult:
            if self.multsum == 0 and not self.multiple:
                self.valid = False
                return
            self.isSubtype = False
        elif self.baseType is not None and self.baseType.getMetatype() == TYPE_SPACEBASE:
            ws = self.ct.getWordSize() if hasattr(self.ct, 'getWordSize') else 1
            offsetbytes = self.offset * ws if ws > 1 else self.offset
            found, extra = self.hasMatchingSubType(offsetbytes, self.biggestNonMultCoeff)
            if not found:
                self.valid = False
                return
            extra_addr = extra // ws if ws > 1 else extra
            self.offset = (self.offset - extra_addr) & self.ptrmask
            self.correct = (self.correct - extra_addr) & self.ptrmask
            self.isSubtype = True
        elif self.baseType is not None and self.baseType.getMetatype() == TYPE_STRUCT:
            soffset = sign_extend(self.offset, self.ptrsize * 8 - 1)
            ws = self.ct.getWordSize() if hasattr(self.ct, 'getWordSize') else 1
            offsetbytes = soffset * ws if ws > 1 else soffset
            found, extra = self.hasMatchingSubType(offsetbytes, self.biggestNonMultCoeff)
            if not found:
                bsize = self.baseType.getSize()
                if offsetbytes < 0 or offsetbytes >= bsize:
                    self.valid = False
                    return
                extra = 0
            extra_addr = extra // ws if ws > 1 else extra
            self.offset = (self.offset - extra_addr) & self.ptrmask
            self.correct = (self.correct - extra_addr) & self.ptrmask
            if self.pRelType is not None and hasattr(self.pRelType, 'getAddressOffset'):
                if self.offset == self.pRelType.getAddressOffset():
                    if hasattr(self.pRelType, 'evaluateThruParent') and not self.pRelType.evaluateThruParent(0):
                        self.valid = False
                        return
            self.isSubtype = True
        elif self.baseType is not None and self.baseType.getMetatype() == TYPE_ARRAY:
            self.isSubtype = True
            self.correct = (self.correct - self.offset) & self.ptrmask
            self.offset = 0
        else:
            self.valid = False
        if self.pRelType is not None and hasattr(self.pRelType, 'getAddressOffset'):
            ptrOff = self.pRelType.getAddressOffset()
            self.offset = (self.offset - ptrOff) & self.ptrmask
            self.correct = (self.correct - ptrOff) & self.ptrmask

    def assignPropagatedType(self, op) -> None:
        """Assign a data-type propagated through the given PcodeOp.

        C++ ref: AddTreeState::assignPropagatedType
        """
        vn = op.getIn(0)
        inType = vn.getTypeReadFacing(op) if hasattr(vn, 'getTypeReadFacing') else vn.getType()
        if hasattr(op, 'getOpcode') and hasattr(op.getOpcode(), 'propagateType'):
            newType = op.getOpcode().propagateType(inType, op, vn, op.getOut(), 0, -1)
            if newType is not None and hasattr(op.getOut(), 'updateType'):
                op.getOut().updateType(newType)

    def buildMultiples(self):
        """Build part of tree that is multiple of base size.

        C++ ref: AddTreeState::buildMultiples
        """
        from ghidra.core.address import sign_extend
        smultsum = sign_extend(self.multsum, self.ptrsize * 8 - 1)
        constCoeff = 0 if self.size == 0 else (smultsum // self.size) & self.ptrmask
        resNode = None
        if constCoeff != 0:
            resNode = self.data.newConstant(self.ptrsize, constCoeff)
        for i in range(len(self.multiple)):
            finalCoeff = 0 if self.size == 0 else (self.coeff[i] // self.size) & self.ptrmask
            vn = self.multiple[i]
            if finalCoeff != 1:
                op = self.data.newOpBefore(self.baseOp, OpCode.CPUI_INT_MULT, vn,
                                           self.data.newConstant(self.ptrsize, finalCoeff))
                vn = op.getOut()
            if resNode is None:
                resNode = vn
            else:
                op = self.data.newOpBefore(self.baseOp, OpCode.CPUI_INT_ADD, vn, resNode)
                resNode = op.getOut()
        return resNode

    def buildExtra(self):
        """Build part of tree not accounted for by multiples or offset.

        C++ ref: AddTreeState::buildExtra
        """
        from ghidra.core.address import uintb_negate
        resNode = None
        for vn in self.nonmult:
            if vn.isConstant():
                self.correct -= vn.getOffset()
                continue
            if resNode is None:
                resNode = vn
            else:
                op = self.data.newOpBefore(self.baseOp, OpCode.CPUI_INT_ADD, vn, resNode)
                resNode = op.getOut()
        self.correct &= self.ptrmask
        if self.correct != 0:
            vn = self.data.newConstant(self.ptrsize, uintb_negate(self.correct - 1, self.ptrsize))
            if resNode is None:
                resNode = vn
            else:
                op = self.data.newOpBefore(self.baseOp, OpCode.CPUI_INT_ADD, vn, resNode)
                resNode = op.getOut()
        return resNode

    def buildDegenerate(self) -> bool:
        """Transform ADD into degenerate PTRADD (unit-size base type).

        C++ ref: AddTreeState::buildDegenerate
        """
        from ghidra.types.datatype import TYPE_PTR
        if self.baseType is None:
            return False
        ws = self.ct.getWordSize() if hasattr(self.ct, 'getWordSize') else 1
        if self.baseType.getAlignSize() < ws:
            return False
        outType = self.baseOp.getOut().getTypeDefFacing() if hasattr(self.baseOp.getOut(), 'getTypeDefFacing') else None
        if outType is None or outType.getMetatype() != TYPE_PTR:
            return False
        slot = self.baseOp.getSlot(self.ptr) if hasattr(self.baseOp, 'getSlot') else self.baseSlot
        newparams = [self.ptr, self.baseOp.getIn(1 - slot),
                     self.data.newConstant(self.ct.getSize() if self.ct else self.ptrsize, 1)]
        self.data.opSetAllInput(self.baseOp, newparams)
        self.data.opSetOpcode(self.baseOp, OpCode.CPUI_PTRADD)
        return True

    def buildTree(self) -> None:
        """Build the transformed ADD tree.

        C++ ref: AddTreeState::buildTree
        """
        multNode = self.buildMultiples()
        extraNode = self.buildExtra()
        newop = None
        if multNode is not None:
            newop = self.data.newOpBefore(self.baseOp, OpCode.CPUI_PTRADD, self.ptr, multNode,
                                          self.data.newConstant(self.ptrsize, self.size))
            if hasattr(self.ptr, 'getType') and self.ptr.getType() is not None and hasattr(self.ptr.getType(), 'needsResolution'):
                if self.ptr.getType().needsResolution() and hasattr(self.data, 'inheritResolution'):
                    self.data.inheritResolution(self.ptr.getType(), newop, 0, self.baseOp, self.baseSlot)
            if hasattr(self.data, 'isTypeRecoveryExceeded') and self.data.isTypeRecoveryExceeded():
                self.assignPropagatedType(newop)
            multNode = newop.getOut()
        else:
            multNode = self.ptr
        if self.isSubtype:
            newop = self.data.newOpBefore(self.baseOp, OpCode.CPUI_PTRSUB, multNode,
                                          self.data.newConstant(self.ptrsize, self.offset))
            if hasattr(multNode, 'getType') and multNode.getType() is not None and hasattr(multNode.getType(), 'needsResolution'):
                if multNode.getType().needsResolution() and hasattr(self.data, 'inheritResolution'):
                    self.data.inheritResolution(multNode.getType(), newop, 0, self.baseOp, self.baseSlot)
            if hasattr(self.data, 'isTypeRecoveryExceeded') and self.data.isTypeRecoveryExceeded():
                self.assignPropagatedType(newop)
            if self.size != 0 and hasattr(newop, 'setStopTypePropagation'):
                newop.setStopTypePropagation()
            multNode = newop.getOut()
        if extraNode is not None:
            newop = self.data.newOpBefore(self.baseOp, OpCode.CPUI_INT_ADD, multNode, extraNode)
        if newop is None:
            if hasattr(self.data, 'warning'):
                self.data.warning("ptrarith problems", self.baseOp.getAddr())
            return
        self.data.opSetOutput(newop, self.baseOp.getOut())
        self.data.opDestroy(self.baseOp)

    def apply(self) -> bool:
        """Attempt to transform the pointer expression.

        C++ ref: AddTreeState::apply
        """
        if self.isDegenerate:
            return self.buildDegenerate()
        self.spanAddTree(self.baseOp, 1)
        if not self.valid:
            return False
        if self.distributeOp is not None and not self.isDistributeUsed:
            self.clear()
            self.preventDistribution = True
            self.spanAddTree(self.baseOp, 1)
        self.calcSubtype()
        if not self.valid:
            return False
        while self.valid and self.distributeOp is not None:
            if hasattr(self.data, 'distributeIntMultAdd') and not self.data.distributeIntMultAdd(self.distributeOp):
                self.valid = False
                break
            if hasattr(self.data, 'collapseIntMultMult'):
                self.data.collapseIntMultMult(self.distributeOp.getIn(0))
                self.data.collapseIntMultMult(self.distributeOp.getIn(1))
            self.clear()
            self.spanAddTree(self.baseOp, 1)
            if self.distributeOp is not None and not self.isDistributeUsed:
                self.clear()
                self.preventDistribution = True
                self.spanAddTree(self.baseOp, 1)
            self.calcSubtype()
        if not self.valid:
            if hasattr(self.data, 'warningHeader'):
                self.data.warningHeader(f"Problems distributing in pointer arithmetic at {self.baseOp.getAddr()}")
            return True
        self.buildTree()
        return True


class RulePtrArith(Rule):
    """Transform pointer arithmetic: INT_ADD with pointer to PTRADD/PTRSUB.

    C++ ref: ruleaction.cc — RulePtrArith
    """
    def __init__(self, g): super().__init__(g, 0, "ptrarith")
    def clone(self, gl):
        return RulePtrArith(self._basegroup) if gl.contains(self._basegroup) else None
    def getOpList(self): return [OpCode.CPUI_INT_ADD]

    @staticmethod
    def verifyPreferredPointer(op, slot: int) -> bool:
        """Check if slot holds the preferred pointer for the expression.

        C++ ref: RulePtrArith::verifyPreferredPointer
        """
        vn = op.getIn(slot)
        if not vn.isWritten():
            return True
        preOp = vn.getDef()
        if preOp.code() != OpCode.CPUI_INT_ADD:
            return True
        from ghidra.types.datatype import TYPE_PTR
        preslot = 0
        tp0 = preOp.getIn(0).getTypeReadFacing(preOp) if hasattr(preOp.getIn(0), 'getTypeReadFacing') else None
        if tp0 is None or tp0.getMetatype() != TYPE_PTR:
            preslot = 1
            tp1 = preOp.getIn(1).getTypeReadFacing(preOp) if hasattr(preOp.getIn(1), 'getTypeReadFacing') else None
            if tp1 is None or tp1.getMetatype() != TYPE_PTR:
                return True
        return RulePtrArith.evaluatePointerExpression(preOp, preslot) != 1

    @staticmethod
    def evaluatePointerExpression(op, slot: int) -> int:
        """Determine if the expression rooted at given INT_ADD is ready for conversion.

        C++ ref: RulePtrArith::evaluatePointerExpression
        Returns: 0=no action, 1=push needed, 2=convert can proceed.
        """
        from ghidra.types.datatype import TYPE_PTR
        res = 1  # Assume push
        count = 0
        ptrBase = op.getIn(slot)
        if ptrBase.isFree() and not ptrBase.isConstant():
            return 0
        otherTp = op.getIn(1 - slot).getTypeReadFacing(op) if hasattr(op.getIn(1 - slot), 'getTypeReadFacing') else None
        if otherTp is not None and otherTp.getMetatype() == TYPE_PTR:
            res = 2
        outVn = op.getOut()
        for decOp in list(outVn.getDescend()):
            count += 1
            opc = decOp.code()
            if opc == OpCode.CPUI_INT_ADD:
                otherVn = decOp.getIn(1 - decOp.getSlot(outVn))
                if otherVn.isFree() and not otherVn.isConstant():
                    return 0
                oTp = otherVn.getTypeReadFacing(decOp) if hasattr(otherVn, 'getTypeReadFacing') else None
                if oTp is not None and oTp.getMetatype() == TYPE_PTR:
                    res = 2
            elif opc in (OpCode.CPUI_LOAD, OpCode.CPUI_STORE) and decOp.getIn(1) is outVn:
                if (ptrBase.isSpacebase() and (ptrBase.isInput() or ptrBase.isConstant()) and
                        op.getIn(1 - slot).isConstant()):
                    return 0
                res = 2
            else:
                res = 2
        if count == 0:
            return 0
        if count > 1:
            if outVn.isSpacebase():
                return 0
        return res

    def applyOp(self, op, data):
        # Check if one input is a pointer type and the other is a scaled index
        for slot in range(2):
            basevn = op.getIn(slot)
            dt = basevn.getType() if hasattr(basevn, 'getType') and basevn.getType() is not None else None
            if dt is None: continue
            from ghidra.types.datatype import TYPE_PTR
            if dt.getMetatype() != TYPE_PTR: continue
            idxvn = op.getIn(1 - slot)
            if idxvn.isWritten():
                defop = idxvn.getDef()
                if defop.code() == OpCode.CPUI_INT_MULT and defop.getIn(1).isConstant():
                    elemsize = int(defop.getIn(1).getOffset())
                    ptrto = dt.getPtrTo()
                    if ptrto is not None and ptrto.getSize() == elemsize:
                        # Convert to PTRADD
                        data.opSetOpcode(op, OpCode.CPUI_PTRADD)
                        if slot == 1:
                            data.opSwapInput(op, 0, 1)
                        data.opSetInput(op, defop.getIn(0), 1)
                        data.opInsertInput(op, data.newConstant(4, elemsize), 2)
                        return 1
        return 0


class RulePtrFlow(Rule):
    """Mark pointer flow: propagate ptrflow flag through COPY/INT_ADD chains from LOAD/STORE.

    C++ ref: ruleaction.cc — RulePtrFlow
    """
    def __init__(self, g, conf=None):
        super().__init__(g, 0, "ptrflow")
        self.glb = conf
        self.hasTruncations = False
        if conf is not None and hasattr(conf, 'getDefaultDataSpace'):
            spc = conf.getDefaultDataSpace()
            if spc is not None and hasattr(spc, 'isTruncated'):
                self.hasTruncations = spc.isTruncated()
    def clone(self, gl):
        return RulePtrFlow(self._basegroup, self.glb) if gl.contains(self._basegroup) else None
    def getOpList(self):
        return [OpCode.CPUI_STORE, OpCode.CPUI_LOAD, OpCode.CPUI_CALLIND,
                OpCode.CPUI_BRANCHIND, OpCode.CPUI_NEW, OpCode.CPUI_INDIRECT,
                OpCode.CPUI_COPY, OpCode.CPUI_PTRSUB, OpCode.CPUI_PTRADD,
                OpCode.CPUI_MULTIEQUAL, OpCode.CPUI_INT_ADD]

    @staticmethod
    def trialSetPtrFlow(op) -> bool:
        """Set ptrflow property on op if applicable.

        C++ ref: RulePtrFlow::trialSetPtrFlow
        """
        opc = op.code()
        if opc in (OpCode.CPUI_COPY, OpCode.CPUI_MULTIEQUAL, OpCode.CPUI_INT_ADD,
                   OpCode.CPUI_INDIRECT, OpCode.CPUI_PTRSUB, OpCode.CPUI_PTRADD):
            if not op.isPtrFlow():
                op.setPtrFlow()
                return True
        return False

    @staticmethod
    def propagateFlowToDef(vn) -> bool:
        """Propagate ptrflow property to given Varnode and its defining PcodeOp.

        C++ ref: RulePtrFlow::propagateFlowToDef
        """
        madeChange = False
        if not vn.isPtrFlow():
            vn.setPtrFlow()
            madeChange = True
        if not vn.isWritten():
            return madeChange
        op = vn.getDef()
        if RulePtrFlow.trialSetPtrFlow(op):
            madeChange = True
        return madeChange

    @staticmethod
    def propagateFlowToReads(vn) -> bool:
        """Propagate ptrflow property to given Varnode and descendant PcodeOps.

        C++ ref: RulePtrFlow::propagateFlowToReads
        """
        madeChange = False
        if not vn.isPtrFlow():
            vn.setPtrFlow()
            madeChange = True
        for op in list(vn.getDescend()):
            if RulePtrFlow.trialSetPtrFlow(op):
                madeChange = True
        return madeChange

    @staticmethod
    def truncatePointer(spc, op, vn, slot, data):
        """Truncate pointer Varnode being read by given PcodeOp.

        C++ ref: RulePtrFlow::truncatePointer
        """
        from ghidra.core.space import IPTR_INTERNAL
        truncop = data.newOp(2, op.getAddr())
        data.opSetOpcode(truncop, OpCode.CPUI_SUBPIECE)
        data.opSetInput(truncop, data.newConstant(vn.getSize(), 0), 1)
        if vn.getSpace().getType() == IPTR_INTERNAL:
            newvn = data.newUniqueOut(spc.getAddrSize(), truncop)
        else:
            addr = vn.getAddr()
            if hasattr(addr, 'isBigEndian') and addr.isBigEndian():
                addr = addr + (vn.getSize() - spc.getAddrSize())
            if hasattr(addr, 'renormalize'):
                addr.renormalize(spc.getAddrSize())
            newvn = data.newVarnodeOut(spc.getAddrSize(), addr, truncop)
        data.opSetInput(op, newvn, slot)
        data.opSetInput(truncop, vn, 0)
        data.opInsertBefore(truncop, op)
        return newvn

    def applyOp(self, op, data):
        opc = op._opcode_enum
        ins = op._inrefs
        madeChange = 0
        if opc in (OpCode.CPUI_LOAD, OpCode.CPUI_STORE):
            vn = ins[1]
            i0 = ins[0]
            spc = i0.getSpaceFromConst()
            if spc is not None and vn._size > spc.getAddrSize():
                vn = self.truncatePointer(spc, op, vn, 1, data)
                madeChange = 1
            if self.propagateFlowToDef(vn):
                madeChange = 1
        elif opc in (OpCode.CPUI_CALLIND, OpCode.CPUI_BRANCHIND):
            vn = ins[0]
            arch = data.getArch()
            spc = arch.getDefaultCodeSpace() if arch is not None else None
            if spc is not None and vn._size > spc.getAddrSize():
                vn = self.truncatePointer(spc, op, vn, 0, data)
                madeChange = 1
            if self.propagateFlowToDef(vn):
                madeChange = 1
        elif opc == OpCode.CPUI_NEW:
            vn = op._output
            if vn is not None and self.propagateFlowToReads(vn):
                madeChange = 1
        elif opc == OpCode.CPUI_INDIRECT:
            if not op.isPtrFlow():
                return 0
            vn = op._output
            if vn is not None and self.propagateFlowToReads(vn):
                madeChange = 1
            vn = ins[0]
            if self.propagateFlowToDef(vn):
                madeChange = 1
        elif opc in (OpCode.CPUI_COPY, OpCode.CPUI_PTRSUB, OpCode.CPUI_PTRADD):
            if not op.isPtrFlow():
                return 0
            vn = op._output
            if vn is not None and self.propagateFlowToReads(vn):
                madeChange = 1
            vn = ins[0]
            if self.propagateFlowToDef(vn):
                madeChange = 1
        elif opc in (OpCode.CPUI_MULTIEQUAL, OpCode.CPUI_INT_ADD):
            if not op.isPtrFlow():
                return 0
            vn = op._output
            if vn is not None and self.propagateFlowToReads(vn):
                madeChange = 1
            for vn in ins:
                if self.propagateFlowToDef(vn):
                    madeChange = 1
        return madeChange


class RulePtraddUndo(Rule):
    """Undo PTRADD when pointer type no longer matches the element size."""
    def __init__(self, g): super().__init__(g, 0, "ptraddundo")
    def clone(self, gl):
        return RulePtraddUndo(self._basegroup) if gl.contains(self._basegroup) else None
    def getOpList(self): return [OpCode.CPUI_PTRADD]
    def applyOp(self, op, data):
        if not hasattr(data, 'hasTypeRecoveryStarted') or not data.hasTypeRecoveryStarted():
            return 0
        # Check if the PTRADD element size still matches the pointer type
        basevn = op.getIn(0)
        dt = basevn.getType() if hasattr(basevn, 'getType') else None
        if dt is not None:
            from ghidra.types.datatype import TYPE_PTR
            if dt.getMetatype() == TYPE_PTR:
                return 0  # Still a valid pointer - don't undo
        # Undo: convert PTRADD back to INT_ADD + INT_MULT
        if hasattr(data, 'opUndoPtradd'):
            data.opUndoPtradd(op, False)
            return 1
        return 0


class RulePtrsubUndo(Rule):
    """Remove PTRSUB operations with mismatched data-type information.

    C++ ref: ruleaction.cc — RulePtrsubUndo
    """
    DEPTH_LIMIT: int = 8

    def __init__(self, g): super().__init__(g, 0, "ptrsubundo")
    def clone(self, gl):
        return RulePtrsubUndo(self._basegroup) if gl.contains(self._basegroup) else None
    def getOpList(self): return [OpCode.CPUI_PTRSUB]

    @staticmethod
    def getConstOffsetBack(vn, maxLevel: int) -> tuple:
        """Recursively search for additive constants and multiplicative constants.

        C++ ref: RulePtrsubUndo::getConstOffsetBack
        Returns (total_const, biggest_multiplier).
        """
        if vn.isConstant():
            return (int(vn.getOffset()), 0)
        if not vn.isWritten():
            return (0, 0)
        maxLevel -= 1
        if maxLevel < 0:
            return (0, 0)
        op = vn.getDef()
        opc = op.code()
        multiplier = 0
        retval = 0
        if opc == OpCode.CPUI_INT_ADD:
            r0, m0 = RulePtrsubUndo.getConstOffsetBack(op.getIn(0), maxLevel)
            retval += r0
            if m0 > multiplier:
                multiplier = m0
            r1, m1 = RulePtrsubUndo.getConstOffsetBack(op.getIn(1), maxLevel)
            retval += r1
            if m1 > multiplier:
                multiplier = m1
        elif opc == OpCode.CPUI_INT_MULT:
            cvn = op.getIn(1)
            if not cvn.isConstant():
                return (0, 0)
            multiplier = int(cvn.getOffset())
            _, subm = RulePtrsubUndo.getConstOffsetBack(op.getIn(0), maxLevel)
            if subm > 0:
                multiplier *= subm
        return (retval, multiplier)

    @staticmethod
    def getExtraOffset(op) -> tuple:
        """Collect constants and biggest multiplier in PTRSUB expression.

        C++ ref: RulePtrsubUndo::getExtraOffset
        Returns (extra, multiplier).
        """
        extra = 0
        multiplier = 0
        outvn = op.getOut()
        op = outvn.loneDescend()
        while op is not None:
            opc = op.code()
            if opc == OpCode.CPUI_INT_ADD:
                slot = op.getSlot(outvn)
                r, m = RulePtrsubUndo.getConstOffsetBack(op.getIn(1 - slot), RulePtrsubUndo.DEPTH_LIMIT)
                extra += r
                if m > multiplier:
                    multiplier = m
            elif opc == OpCode.CPUI_PTRSUB:
                extra += int(op.getIn(1).getOffset())
            elif opc == OpCode.CPUI_PTRADD:
                if op.getIn(0) is not outvn:
                    break
                ptraddmult = int(op.getIn(2).getOffset())
                invn = op.getIn(1)
                if invn.isConstant():
                    extra += ptraddmult * int(invn.getOffset())
                _, subm = RulePtrsubUndo.getConstOffsetBack(invn, RulePtrsubUndo.DEPTH_LIMIT)
                if subm != 0:
                    ptraddmult *= subm
                if ptraddmult > multiplier:
                    multiplier = ptraddmult
            else:
                break
            outvn = op.getOut()
            op = outvn.loneDescend()
        from ghidra.core.address import sign_extend
        extra = sign_extend(extra & calc_mask(outvn.getSize()), outvn.getSize() * 8 - 1)
        return (extra, multiplier)

    @staticmethod
    def removeLocalAddRecurse(op, slot: int, maxLevel: int, data) -> int:
        """Remove constants in the additive expression rooted at the given PcodeOp.

        C++ ref: RulePtrsubUndo::removeLocalAddRecurse
        """
        vn = op.getIn(slot)
        if not vn.isWritten():
            return 0
        if vn.loneDescend() is not op:
            return 0
        maxLevel -= 1
        if maxLevel < 0:
            return 0
        op = vn.getDef()
        retval = 0
        if op.code() == OpCode.CPUI_INT_ADD:
            if op.getIn(1).isConstant():
                retval += int(op.getIn(1).getOffset())
                data.opRemoveInput(op, 1)
                data.opSetOpcode(op, OpCode.CPUI_COPY)
            else:
                retval += RulePtrsubUndo.removeLocalAddRecurse(op, 0, maxLevel, data)
                retval += RulePtrsubUndo.removeLocalAddRecurse(op, 1, maxLevel, data)
        return retval

    @staticmethod
    def removeLocalAdds(vn, data) -> int:
        """Remove constants in the additive expression involving the given Varnode.

        C++ ref: RulePtrsubUndo::removeLocalAdds
        """
        extra = 0
        op = vn.loneDescend()
        while op is not None:
            opc = op.code()
            if opc == OpCode.CPUI_INT_ADD:
                slot = op.getSlot(vn)
                if slot == 0 and op.getIn(1).isConstant():
                    extra += int(op.getIn(1).getOffset())
                    data.opRemoveInput(op, 1)
                    data.opSetOpcode(op, OpCode.CPUI_COPY)
                else:
                    extra += RulePtrsubUndo.removeLocalAddRecurse(op, 1 - slot, RulePtrsubUndo.DEPTH_LIMIT, data)
            elif opc == OpCode.CPUI_PTRSUB:
                extra += int(op.getIn(1).getOffset())
                if hasattr(op, 'clearStopTypePropagation'):
                    op.clearStopTypePropagation()
                data.opRemoveInput(op, 1)
                data.opSetOpcode(op, OpCode.CPUI_COPY)
            elif opc == OpCode.CPUI_PTRADD:
                if op.getIn(0) is not vn:
                    break
                ptraddmult = int(op.getIn(2).getOffset())
                invn = op.getIn(1)
                if invn.isConstant():
                    extra += ptraddmult * int(invn.getOffset())
                    data.opRemoveInput(op, 2)
                    data.opRemoveInput(op, 1)
                    data.opSetOpcode(op, OpCode.CPUI_COPY)
                else:
                    if hasattr(data, 'opUndoPtradd'):
                        data.opUndoPtradd(op, False)
                    extra += RulePtrsubUndo.removeLocalAddRecurse(op, 1, RulePtrsubUndo.DEPTH_LIMIT, data)
            else:
                break
            vn = op.getOut()
            op = vn.loneDescend()
        return extra

    def applyOp(self, op, data):
        if not hasattr(data, 'hasTypeRecoveryStarted') or not data.hasTypeRecoveryStarted():
            return 0
        basevn = op.getIn(0)
        cvn = op.getIn(1)
        val = int(cvn.getOffset())
        extra, multiplier = self.getExtraOffset(op)
        baseType = basevn.getTypeReadFacing(op) if hasattr(basevn, 'getTypeReadFacing') else None
        if baseType is not None and hasattr(baseType, 'isPtrsubMatching'):
            if baseType.isPtrsubMatching(val, extra, multiplier):
                return 0
        data.opSetOpcode(op, OpCode.CPUI_INT_ADD)
        if hasattr(op, 'clearStopTypePropagation'):
            op.clearStopTypePropagation()
        extra = self.removeLocalAdds(op.getOut(), data)
        if extra != 0:
            val = val + extra
            data.opSetInput(op, data.newConstant(cvn.getSize(), val & calc_mask(cvn.getSize())), 1)
        return 1


class RulePtrsubCharConstant(Rule):
    """Cleanup: Set-up to print string constants.

    C++ ref: ruleaction.cc — RulePtrsubCharConstant
    """
    def __init__(self, g): super().__init__(g, 0, "ptrsubcharconstant")
    def clone(self, gl):
        return RulePtrsubCharConstant(self._basegroup) if gl.contains(self._basegroup) else None
    def getOpList(self): return [OpCode.CPUI_PTRSUB]

    @staticmethod
    def pushConstFurther(data, outtype, op, slot: int, val: int) -> bool:
        """Push constant pointer further through a PTRADD descendant.

        C++ ref: RulePtrsubCharConstant::pushConstFurther
        """
        if op.code() != OpCode.CPUI_PTRADD:
            return False
        if slot != 0:
            return False
        vn = op.getIn(1)
        if not vn.isConstant():
            return False
        addval = int(vn.getOffset())
        addval *= int(op.getIn(2).getOffset())
        val += addval
        newconst = data.newConstant(vn.getSize(), val)
        if hasattr(newconst, 'updateType'):
            newconst.updateType(outtype)
        data.opRemoveInput(op, 2)
        data.opRemoveInput(op, 1)
        data.opSetOpcode(op, OpCode.CPUI_COPY)
        data.opSetInput(op, newconst, 0)
        return True

    def applyOp(self, op, data):
        """C++ ref: RulePtrsubCharConstant::applyOp in ruleaction.cc"""
        from ghidra.types.datatype import TYPE_PTR, TYPE_SPACEBASE
        sb = op.getIn(0)
        sbType = sb.getTypeReadFacing(op) if hasattr(sb, 'getTypeReadFacing') else None
        if sbType is None or sbType.getMetatype() != TYPE_PTR:
            return 0
        dt = sbType.getPtrTo()
        if dt is None or dt.getMetatype() != TYPE_SPACEBASE:
            return 0
        vn1 = op.getIn(1)
        if not vn1.isConstant():
            return 0
        outvn = op.getOut()
        outtype = outvn.getTypeDefFacing() if hasattr(outvn, 'getTypeDefFacing') else None
        if outtype is None or outtype.getMetatype() != TYPE_PTR:
            return 0
        basetype = outtype.getPtrTo()
        if basetype is None or not basetype.isCharPrint():
            return 0
        # Resolve address from spacebase
        sbtype = dt
        symaddr = sbtype.getAddress(vn1.getOffset(), vn1.getSize(), op.getAddr()) if hasattr(sbtype, 'getAddress') else None
        if symaddr is None:
            return 0
        scope = sbtype.getMap() if hasattr(sbtype, 'getMap') else None
        if scope is None or not (hasattr(scope, 'isReadOnly') and scope.isReadOnly(symaddr, 1, op.getAddr())):
            return 0
        # Check if data at address looks like a string
        glb = data.getArch()
        if glb is None:
            return 0
        stringMgr = getattr(glb, 'stringManager', None)
        if stringMgr is None or not stringMgr.isString(symaddr, basetype):
            return 0

        # Convert PTRSUB to pointer constant or propagate further
        removeCopy = False
        if not outvn.isAddrForce():
            removeCopy = True
            for subop in list(outvn.getDescend()):
                slot = subop.getSlot(outvn)
                if not self.pushConstFurther(data, outtype, subop, slot, vn1.getOffset()):
                    removeCopy = False
        if removeCopy:
            data.opDestroy(op)
        else:
            newvn = data.newConstant(outvn.getSize(), vn1.getOffset())
            if hasattr(newvn, 'updateType'):
                newvn.updateType(outtype)
            data.opRemoveInput(op, 1)
            data.opSetInput(op, newvn, 0)
            data.opSetOpcode(op, OpCode.CPUI_COPY)
        return 1


class RuleLoadVarnode(Rule):
    """Convert LOAD from constant/spacebase address to COPY from direct Varnode.

    The pointer can be a constant offset into the LOAD's address space,
    or a spacebase register plus a constant offset.
    C++ ref: ``RuleLoadVarnode`` in ruleaction.cc
    """
    def __init__(self, g): super().__init__(g, 0, "loadvarnode")
    def clone(self, gl):
        return RuleLoadVarnode(self._basegroup) if gl.contains(self._basegroup) else None
    def getOpList(self): return [OpCode.CPUI_LOAD]

    @staticmethod
    def correctSpacebase(glb, vn, spc):
        """Check if *vn* is a spacebase register for *spc*.

        Returns the associated spacebase space, or None.
        C++ ref: ``RuleLoadVarnode::correctSpacebase``
        """
        if not vn.isSpacebase():
            return None
        if vn.isConstant():
            return spc
        if not vn.isInput():
            return None
        if not hasattr(glb, 'getSpaceBySpacebase'):
            return None
        assoc = glb.getSpaceBySpacebase(vn.getAddr(), vn.getSize())
        if assoc is None:
            return None
        contain = assoc.getContain() if hasattr(assoc, 'getContain') else None
        if contain is not spc:
            return None
        return assoc

    @staticmethod
    def vnSpacebase(glb, vn, spc, _depth=0):
        """Check if *vn* is spacebase or spacebase + constant.

        Returns (space, offset) or (None, 0).
        C++ ref: ``RuleLoadVarnode::vnSpacebase``

        Extended from C++: traces through chains of
        ``INT_ADD(spacebase_ssa, constant)`` where ``spacebase_ssa`` is a
        written copy (not input) that itself traces back to the input
        through further INT_ADD ops.  This handles the case after heritage
        SSA-renames the stack pointer.
        """
        retspace = RuleLoadVarnode.correctSpacebase(glb, vn, spc)
        if retspace is not None:
            return retspace, 0
        if not vn.isWritten():
            return None, 0
        defop = vn.getDef()
        if defop.code() != OpCode.CPUI_INT_ADD:
            return None, 0
        vn1 = defop.getIn(0)
        vn2 = defop.getIn(1)
        # Direct: INT_ADD(spacebase_input, constant)
        retspace = RuleLoadVarnode.correctSpacebase(glb, vn1, spc)
        if retspace is not None:
            if vn2.isConstant():
                return retspace, vn2.getOffset()
            return None, 0
        retspace = RuleLoadVarnode.correctSpacebase(glb, vn2, spc)
        if retspace is not None:
            if vn1.isConstant():
                return retspace, vn1.getOffset()
            return None, 0
        # Recurse through spacebase chain (Python extension for SSA handling)
        if _depth < 8:
            mask = (1 << (vn.getSize() * 8)) - 1
            if vn2.isConstant() and vn1.isSpacebase():
                retspace, inner_off = RuleLoadVarnode.vnSpacebase(glb, vn1, spc, _depth + 1)
                if retspace is not None:
                    return retspace, (inner_off + vn2.getOffset()) & mask
            if vn1.isConstant() and vn2.isSpacebase():
                retspace, inner_off = RuleLoadVarnode.vnSpacebase(glb, vn2, spc, _depth + 1)
                if retspace is not None:
                    return retspace, (inner_off + vn1.getOffset()) & mask
        return None, 0

    @staticmethod
    def checkSpacebase(glb, op):
        """Check if STORE/LOAD is off a spacebase + constant.

        Returns (space, offset) or (None, 0).
        C++ ref: ``RuleLoadVarnode::checkSpacebase``
        """
        offvn = op.getIn(1)
        spcvn = op.getIn(0)
        loadspace = spcvn.getSpaceFromConst() if hasattr(spcvn, 'getSpaceFromConst') else None
        if loadspace is None:
            return None, 0
        # Handle SEGMENTOP
        if offvn.isWritten() and offvn.getDef().code() == OpCode.CPUI_SEGMENTOP:
            offvn = offvn.getDef().getIn(2)
            if offvn.isConstant():
                return None, 0
        elif offvn.isConstant():
            return loadspace, offvn.getOffset()
        return RuleLoadVarnode.vnSpacebase(glb, offvn, loadspace)

    def applyOp(self, op, data):
        glb = data.getArch() if hasattr(data, 'getArch') else None
        baseoff, offoff = RuleLoadVarnode.checkSpacebase(glb, op)
        if baseoff is None:
            return 0
        size = op.getOut().getSize()
        wordsize = baseoff.getWordSize() if hasattr(baseoff, 'getWordSize') else 1
        if wordsize > 1:
            offoff = offoff * wordsize  # addressToByte
        from ghidra.core.address import Address
        newvn = data.newVarnode(size, Address(baseoff, offoff))
        data.opSetInput(op, newvn, 0)
        data.opRemoveInput(op, 1)
        data.opSetOpcode(op, OpCode.CPUI_COPY)
        # C++ ref: ruleaction.cc:4294-4303 — resolve spacebase placeholder
        refvn = op.getOut()
        if refvn is not None and refvn.isSpacebasePlaceholder():
            refvn.clearSpacebasePlaceholder()
            placeOp = refvn.loneDescend()
            if placeOp is not None:
                fc = data.getCallSpecs(placeOp) if hasattr(data, 'getCallSpecs') else None
                if fc is not None and hasattr(fc, 'resolveSpacebaseRelative'):
                    fc.resolveSpacebaseRelative(data, refvn)
        return 1


class RuleStoreVarnode(Rule):
    """Convert STORE to constant/spacebase address to COPY to direct Varnode.

    The pointer can be a constant offset or spacebase + constant.
    C++ ref: ``RuleStoreVarnode`` in ruleaction.cc
    """
    def __init__(self, g): super().__init__(g, 0, "storevarnode")
    def clone(self, gl):
        return RuleStoreVarnode(self._basegroup) if gl.contains(self._basegroup) else None
    def getOpList(self): return [OpCode.CPUI_STORE]
    def applyOp(self, op, data):
        glb = data.getArch() if hasattr(data, 'getArch') else None
        baseoff, offoff = RuleLoadVarnode.checkSpacebase(glb, op)
        if baseoff is None:
            return 0
        size = op.getIn(2).getSize()
        wordsize = baseoff.getWordSize() if hasattr(baseoff, 'getWordSize') else 1
        if wordsize > 1:
            offoff = offoff * wordsize  # addressToByte
        from ghidra.core.address import Address
        addr = Address(baseoff, offoff)
        data.newVarnodeOut(size, addr, op)
        outvn = op.getOut()
        if outvn is not None and hasattr(outvn, 'setStackStore'):
            outvn.setStackStore()
        data.opRemoveInput(op, 1)
        data.opRemoveInput(op, 0)
        data.opSetOpcode(op, OpCode.CPUI_COPY)
        return 1


class RuleExpandLoad(Rule):
    """Convert LOAD size to match pointer data-type.

    C++ ref: ruleaction.cc — RuleExpandLoad
    """
    def __init__(self, g): super().__init__(g, 0, "expandload")
    def clone(self, gl):
        return RuleExpandLoad(self._basegroup) if gl.contains(self._basegroup) else None
    def getOpList(self): return [OpCode.CPUI_LOAD]

    @staticmethod
    def checkAndComparison(vn) -> bool:
        """Check if all uses of the given Varnode are of the form (V & C) == D.

        C++ ref: RuleExpandLoad::checkAndComparison
        """
        for op in list(vn.getDescend()):
            if op.code() != OpCode.CPUI_INT_AND:
                return False
            if not op.getIn(1).isConstant():
                return False
            compOp = op.getOut().loneDescend()
            if compOp is None:
                return False
            opc = compOp.code()
            if opc != OpCode.CPUI_INT_EQUAL and opc != OpCode.CPUI_INT_NOTEQUAL:
                return False
            if not compOp.getIn(1).isConstant():
                return False
        return True

    @staticmethod
    def modifyAndComparison(data, oldVn, newVn, dt, offset: int):
        """Expand the constants in (V & C) == D expressions after LOAD expansion.

        C++ ref: RuleExpandLoad::modifyAndComparison
        """
        offset = 8 * offset  # Convert to shift amount
        for andOp in list(oldVn.getDescend()):
            compOp = andOp.getOut().loneDescend()
            newOff = int(andOp.getIn(1).getOffset())
            newOff <<= offset
            vn = data.newConstant(dt.getSize(), newOff)
            if hasattr(vn, 'updateType'):
                vn.updateType(dt)
            data.opSetInput(andOp, newVn, 0)
            data.opSetInput(andOp, vn, 1)
            newOff = int(compOp.getIn(1).getOffset())
            newOff <<= offset
            vn = data.newConstant(dt.getSize(), newOff)
            if hasattr(vn, 'updateType'):
                vn.updateType(dt)
            data.opSetInput(compOp, vn, 1)

    def applyOp(self, op, data):
        """C++ ref: RuleExpandLoad::applyOp in ruleaction.cc"""
        from ghidra.types.datatype import TYPE_PTR, TYPE_INT, TYPE_UINT, TYPE_UNKNOWN, TYPE_BOOL
        outVn = op.getOut()
        outSize = outVn.getSize()
        rootPtr = op.getIn(1)
        addOp = None
        offset = 0
        if rootPtr.isWritten():
            defOp = rootPtr.getDef()
            if defOp.code() == OpCode.CPUI_INT_ADD and defOp.getIn(1).isConstant():
                addOp = defOp
                rootPtr = defOp.getIn(0)
                off = int(defOp.getIn(1).getOffset())
                if off > 16:
                    return 0
                offset = off
                if defOp.getOut().loneDescend() is None:
                    return 0
                elType = rootPtr.getTypeReadFacing(defOp) if hasattr(rootPtr, 'getTypeReadFacing') else None
            else:
                elType = rootPtr.getTypeReadFacing(op) if hasattr(rootPtr, 'getTypeReadFacing') else None
        else:
            elType = rootPtr.getTypeReadFacing(op) if hasattr(rootPtr, 'getTypeReadFacing') else None
        if elType is None or elType.getMetatype() != TYPE_PTR:
            return 0
        elType = elType.getPtrTo()
        if elType.getSize() <= outSize:
            return 0
        if elType.getSize() < outSize + offset:
            return 0

        meta = elType.getMetatype()
        if meta == TYPE_UNKNOWN:
            return 0
        addForm = self.checkAndComparison(outVn)
        spc = op.getIn(0).getSpaceFromConst() if hasattr(op.getIn(0), 'getSpaceFromConst') else None
        lsbCut = 0
        if addForm:
            if spc is not None and spc.isBigEndian():
                lsbCut = elType.getSize() - outSize - offset
            else:
                lsbCut = offset
        else:
            if meta != TYPE_INT and meta != TYPE_UINT:
                return 0
            outMeta = outVn.getTypeDefFacing().getMetatype() if hasattr(outVn, 'getTypeDefFacing') else TYPE_UNKNOWN
            if outMeta not in (TYPE_INT, TYPE_UINT, TYPE_UNKNOWN, TYPE_BOOL):
                return 0
            if spc is not None and spc.isBigEndian():
                if outSize + offset != elType.getSize():
                    return 0
            else:
                if offset != 0:
                    return 0

        # Modify the LOAD
        newOut = data.newUnique(elType.getSize(), elType) if hasattr(data, 'newUnique') else data.newUniqueOut(elType.getSize(), op)
        data.opSetOutput(op, newOut)
        if addOp is not None:
            data.opSetInput(op, rootPtr, 1)
            data.opDestroy(addOp)
        if addForm:
            if meta != TYPE_INT and meta != TYPE_UINT:
                elType = data.getArch().types.getBase(elType.getSize(), TYPE_UINT)
            self.modifyAndComparison(data, outVn, newOut, elType, lsbCut)
        else:
            subOp = data.newOp(2, op.getAddr())
            data.opSetOpcode(subOp, OpCode.CPUI_SUBPIECE)
            data.opSetInput(subOp, newOut, 0)
            data.opSetInput(subOp, data.newConstant(4, 0), 1)
            data.opSetOutput(subOp, outVn)
            data.opInsertAfter(subOp, op)
        return 1
