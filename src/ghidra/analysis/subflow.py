"""
Corresponds to: subflow.hh / subflow.cc

Classes for reducing/splitting Varnodes containing smaller logical values.
SubvariableFlow traces logical sub-variables through containing Varnodes
and replaces operations to work on the smaller values directly.
"""

from __future__ import annotations
from typing import Optional, List, Dict
from ghidra.core.opcodes import OpCode
from ghidra.core.address import calc_mask, leastsigbit_set, mostsigbit_set, sign_extend
from ghidra.transform.transform import TransformManager, LaneDescription


class ReplaceVarnode:
    """Placeholder for a Varnode holding a smaller logical value."""
    __slots__ = ('vn', 'replacement', 'mask', 'val', 'defop')

    def __init__(self, vn=None, mask: int = 0) -> None:
        self.vn = vn
        self.replacement = None
        self.mask: int = mask
        self.val: int = 0
        self.defop = None

    def getVarnode(self): return self.vn
    def getReplacement(self): return self.replacement


class ReplaceOp:
    """Placeholder for a PcodeOp operating on smaller logical values."""
    __slots__ = ('op', 'replacement', 'opc', 'numparams', 'output', 'input')

    def __init__(self, op=None, opc: int = 0, nparams: int = 0) -> None:
        self.op = op
        self.replacement = None
        self.opc: int = opc
        self.numparams: int = nparams
        self.output: Optional[ReplaceVarnode] = None
        self.input: List[ReplaceVarnode] = []

    def getOp(self): return self.op
    def getReplacement(self): return self.replacement
    def getOpcode(self): return self.opc


class PatchRecord:
    """Operation with new logical value as input but unchanged output."""
    copy_patch = 0
    compare_patch = 1
    parameter_patch = 2
    extension_patch = 3
    push_patch = 4
    int2float_patch = 5

    __slots__ = ('type', 'patchOp', 'in1', 'in2', 'slot')

    def __init__(self, tp: int = 0, op=None, inv1=None, inv2=None, sl: int = 0) -> None:
        self.type: int = tp
        self.patchOp = op
        self.in1 = inv1
        self.in2 = inv2
        self.slot: int = sl


class SubvariableFlow:
    """Trace and replace logical sub-variables within larger Varnodes.

    Given a root Varnode and the bit dimensions of a logical variable,
    traces the flow of the logical variable through containing Varnodes,
    creating a subgraph. When doReplacement() is called, the subgraph
    is materialized as new smaller Varnodes and Ops in the syntax tree.

    C++ ref: SubvariableFlow in subflow.cc
    """

    def __init__(self, fd, root, mask: int, aggressive: bool = False,
                 sext: bool = False, big: bool = False) -> None:
        self._fd = fd
        self._returnsTraversed: bool = False
        self._aggressive: bool = aggressive
        self._sextrestrictions: bool = sext
        self._varmap: Dict[int, ReplaceVarnode] = {}
        self._newvarlist: List[ReplaceVarnode] = []
        self._oplist: List[ReplaceOp] = []
        self._patchlist: List[PatchRecord] = []
        self._worklist: List[ReplaceVarnode] = []
        self._pullcount: int = 0
        self._flowsize: int = 0
        self._bitsize: int = 0

        if mask == 0:
            self._fd = None
            return
        low = leastsigbit_set(mask)
        high = mostsigbit_set(mask)
        self._bitsize = (high - low) + 1
        if self._bitsize <= 8:
            self._flowsize = 1
        elif self._bitsize <= 16:
            self._flowsize = 2
        elif self._bitsize <= 24:
            self._flowsize = 3
        elif self._bitsize <= 32:
            self._flowsize = 4
        elif self._bitsize <= 64:
            if not big:
                self._fd = None
                return
            self._flowsize = 8
        else:
            self._fd = None
            return
        self._createLink(None, mask, 0, root)

    # ------------------------------------------------------------------
    # Static helpers
    # ------------------------------------------------------------------

    @staticmethod
    def _doesOrSet(orop, mask: int) -> int:
        """Return slot of constant if INT_OR sets all bits in mask, else -1."""
        idx = 1 if orop.getIn(1).isConstant() else 0
        if not orop.getIn(idx).isConstant():
            return -1
        orval = orop.getIn(idx).getOffset()
        if (mask & (~orval & calc_mask(orop.getIn(idx).getSize()))) == 0:
            return idx
        return -1

    @staticmethod
    def _doesAndClear(andop, mask: int) -> int:
        """Return slot of constant if INT_AND clears all bits in mask, else -1."""
        idx = 1 if andop.getIn(1).isConstant() else 0
        if not andop.getIn(idx).isConstant():
            return -1
        andval = andop.getIn(idx).getOffset()
        if (mask & andval) == 0:
            return idx
        return -1

    # ------------------------------------------------------------------
    # Subgraph construction helpers
    # ------------------------------------------------------------------

    def _setReplacement(self, vn, mask: int):
        """Add vn to subgraph. Returns (ReplaceVarnode, inworklist) or (None, False)."""
        vid = id(vn)
        if vn.isMark():
            res = self._varmap.get(vid)
            if res is None:
                return None, False
            if res.mask != mask:
                return None, False
            return res, False

        if vn.isConstant():
            if self._sextrestrictions:
                cval = vn.getOffset()
                smallval = cval & mask
                sextval = sign_extend(smallval, self._flowsize * 8 - 1)
                sextval &= calc_mask(vn.getSize())
                if sextval != cval:
                    return None, False
            return self._addConstant(None, mask, 0, vn), False

        if vn.isFree():
            return None, False

        if hasattr(vn, 'isAddrForce') and vn.isAddrForce() and vn.getSize() != self._flowsize:
            return None, False

        if self._sextrestrictions:
            if vn.getSize() != self._flowsize:
                if (not self._aggressive) and vn.isInput():
                    return None, False
                if hasattr(vn, 'isPersist') and vn.isPersist():
                    return None, False
            if hasattr(vn, 'isTypeLock') and vn.isTypeLock():
                tp = vn.getType()
                if hasattr(tp, 'getMetatype'):
                    from ghidra.types.datatype import TYPE_PARTIALSTRUCT
                    if tp.getMetatype() != TYPE_PARTIALSTRUCT:
                        if tp.getSize() != self._flowsize:
                            return None, False
        else:
            if self._bitsize >= 8:
                if (not self._aggressive) and ((vn.getConsume() & ~mask) != 0):
                    return None, False
                if hasattr(vn, 'isTypeLock') and vn.isTypeLock():
                    tp = vn.getType()
                    if hasattr(tp, 'getMetatype'):
                        from ghidra.types.datatype import TYPE_PARTIALSTRUCT
                        if tp.getMetatype() != TYPE_PARTIALSTRUCT:
                            if tp.getSize() != self._flowsize:
                                return None, False
            if vn.isInput():
                if self._bitsize < 8:
                    return None, False
                if (mask & 1) == 0:
                    return None, False

        res = ReplaceVarnode(vn, mask)
        self._varmap[vid] = res
        vn.setMark()
        res.defop = None
        inworklist = True
        if vn.getSize() == self._flowsize:
            if mask == calc_mask(self._flowsize):
                inworklist = False
                res.replacement = vn
            elif mask == 1:
                if vn.isWritten() and hasattr(vn.getDef(), 'isBoolOutput') and vn.getDef().isBoolOutput():
                    inworklist = False
                    res.replacement = vn
        return res, inworklist

    def _createOp(self, opc: int, numparam: int, outrvn: ReplaceVarnode) -> ReplaceOp:
        """Create a subgraph op node given its output variable node."""
        if outrvn.defop is not None:
            return outrvn.defop
        rop = ReplaceOp(outrvn.vn.getDef() if outrvn.vn is not None and outrvn.vn.isWritten() else None, opc, numparam)
        rop.output = outrvn
        outrvn.defop = rop
        self._oplist.append(rop)
        return rop

    def _createOpDown(self, opc: int, numparam: int, op, inrvn: ReplaceVarnode, slot: int) -> ReplaceOp:
        """Create a subgraph op node given one of its input variable nodes."""
        rop = ReplaceOp(op, opc, numparam)
        rop.output = None
        while len(rop.input) <= slot:
            rop.input.append(None)
        rop.input[slot] = inrvn
        self._oplist.append(rop)
        return rop

    def _createLink(self, rop, mask: int, slot: int, vn) -> bool:
        """Extend the subgraph by an edge."""
        rep, inworklist = self._setReplacement(vn, mask)
        if rep is None:
            return False
        if rop is not None:
            if slot == -1:
                rop.output = rep
                rep.defop = rop
            else:
                while len(rop.input) <= slot:
                    rop.input.append(None)
                rop.input[slot] = rep
        if inworklist:
            self._worklist.append(rep)
        return True

    def _createCompareBridge(self, op, inrvn: ReplaceVarnode, slot: int, othervn) -> bool:
        """Extend subgraph through a comparison."""
        rep, inworklist = self._setReplacement(othervn, inrvn.mask)
        if rep is None:
            return False
        if slot == 0:
            self._addComparePatch(inrvn, rep, op)
        else:
            self._addComparePatch(rep, inrvn, op)
        if inworklist:
            self._worklist.append(rep)
        return True

    def _addConstant(self, rop, mask: int, slot: int, constvn) -> ReplaceVarnode:
        """Add a constant variable node to the subgraph."""
        res = ReplaceVarnode(constvn, mask)
        sa = leastsigbit_set(mask)
        if sa < 0:
            sa = 0
        res.val = (mask & constvn.getOffset()) >> sa
        res.defop = None
        self._newvarlist.append(res)
        if rop is not None:
            while len(rop.input) <= slot:
                rop.input.append(None)
            rop.input[slot] = res
        return res

    def _addNewConstant(self, rop, slot: int, val: int) -> ReplaceVarnode:
        """Add a new constant not associated with an original Varnode."""
        res = ReplaceVarnode(None, 0)
        res.val = val
        res.defop = None
        self._newvarlist.append(res)
        if rop is not None:
            while len(rop.input) <= slot:
                rop.input.append(None)
            rop.input[slot] = res
        return res

    def _createNewOut(self, rop: ReplaceOp, mask: int) -> None:
        """Create a new non-shadowing subgraph variable as operation output."""
        res = ReplaceVarnode(None, mask)
        rop.output = res
        res.defop = rop
        self._newvarlist.append(res)

    # ------------------------------------------------------------------
    # Patch helpers
    # ------------------------------------------------------------------

    def _addPush(self, pushOp, rvn: ReplaceVarnode) -> None:
        self._patchlist.insert(0, PatchRecord(PatchRecord.push_patch, pushOp, rvn))

    def _addTerminalPatch(self, pullop, rvn: ReplaceVarnode) -> None:
        self._patchlist.append(PatchRecord(PatchRecord.copy_patch, pullop, rvn))
        self._pullcount += 1

    def _addTerminalPatchSameOp(self, pullop, rvn: ReplaceVarnode, slot: int) -> None:
        self._patchlist.append(PatchRecord(PatchRecord.parameter_patch, pullop, rvn, None, slot))
        self._pullcount += 1

    def _addBooleanPatch(self, pullop, rvn: ReplaceVarnode, slot: int) -> None:
        self._patchlist.append(PatchRecord(PatchRecord.parameter_patch, pullop, rvn, None, slot))

    def _addExtensionPatch(self, rvn: ReplaceVarnode, pushop, sa: int) -> None:
        if sa == -1:
            sa = leastsigbit_set(rvn.mask)
            if sa < 0:
                sa = 0
        self._patchlist.append(PatchRecord(PatchRecord.extension_patch, pushop, rvn, None, sa))

    def _addComparePatch(self, in1: ReplaceVarnode, in2: ReplaceVarnode, op) -> None:
        self._patchlist.append(PatchRecord(PatchRecord.compare_patch, op, in1, in2))
        self._pullcount += 1

    # ------------------------------------------------------------------
    # Try* helpers for special ops
    # ------------------------------------------------------------------

    def _tryCallPull(self, op, rvn: ReplaceVarnode, slot: int) -> bool:
        if slot == 0:
            return False
        if not self._aggressive:
            if (rvn.vn.getConsume() & ~rvn.mask) != 0:
                return False
        fc = self._fd.getCallSpecs(op) if hasattr(self._fd, 'getCallSpecs') else None
        if fc is None:
            return False
        if hasattr(fc, 'isInputActive') and fc.isInputActive():
            return False
        if hasattr(fc, 'isInputLocked') and fc.isInputLocked():
            if not (hasattr(fc, 'isDotdotdot') and fc.isDotdotdot()):
                return False
        self._patchlist.append(PatchRecord(PatchRecord.parameter_patch, op, rvn, None, slot))
        self._pullcount += 1
        return True

    def _tryReturnPull(self, op, rvn: ReplaceVarnode, slot: int) -> bool:
        if slot == 0:
            return False
        if hasattr(self._fd, 'getFuncProto') and self._fd.getFuncProto().isOutputLocked():
            return False
        if not self._aggressive:
            if (rvn.vn.getConsume() & ~rvn.mask) != 0:
                return False
        if not self._returnsTraversed:
            if hasattr(self._fd, 'beginOp'):
                for retop in self._fd.beginOp(OpCode.CPUI_RETURN):
                    if hasattr(retop, 'getHaltType') and retop.getHaltType() != 0:
                        continue
                    if slot >= retop.numInput():
                        continue
                    retvn = retop.getIn(slot)
                    rep, inworklist = self._setReplacement(retvn, rvn.mask)
                    if rep is None:
                        return False
                    if inworklist:
                        self._worklist.append(rep)
                    elif retvn.isConstant() and retop is not op:
                        self._patchlist.append(PatchRecord(PatchRecord.parameter_patch, retop, rep, None, slot))
                        self._pullcount += 1
            self._returnsTraversed = True
        self._patchlist.append(PatchRecord(PatchRecord.parameter_patch, op, rvn, None, slot))
        self._pullcount += 1
        return True

    def _tryCallReturnPush(self, op, rvn: ReplaceVarnode) -> bool:
        if not self._aggressive:
            if (rvn.vn.getConsume() & ~rvn.mask) != 0:
                return False
        if (rvn.mask & 1) == 0:
            return False
        if self._bitsize < 8:
            return False
        fc = self._fd.getCallSpecs(op) if hasattr(self._fd, 'getCallSpecs') else None
        if fc is None:
            return False
        if hasattr(fc, 'isOutputLocked') and fc.isOutputLocked():
            return False
        if hasattr(fc, 'isOutputActive') and fc.isOutputActive():
            return False
        self._addPush(op, rvn)
        return True

    def _trySwitchPull(self, op, rvn: ReplaceVarnode) -> bool:
        if (rvn.mask & 1) == 0:
            return False
        if (rvn.vn.getConsume() & ~rvn.mask) != 0:
            return False
        self._patchlist.append(PatchRecord(PatchRecord.parameter_patch, op, rvn, None, 0))
        self._pullcount += 1
        return True

    def _tryInt2FloatPull(self, op, rvn: ReplaceVarnode) -> bool:
        if (rvn.mask & 1) == 0:
            return False
        if (rvn.vn.getNZMask() & ~rvn.mask) != 0:
            return False
        if rvn.vn.getSize() == self._flowsize:
            return False
        pullModification = True
        if rvn.vn.isWritten() and rvn.vn.getDef().code() == OpCode.CPUI_INT_ZEXT:
            lone = rvn.vn.loneDescend()
            if lone is op:
                pullModification = False
        self._patchlist.append(PatchRecord(PatchRecord.int2float_patch, op, rvn))
        if pullModification:
            self._pullcount += 1
        return True

    # ------------------------------------------------------------------
    # traceForward
    # ------------------------------------------------------------------

    def _traceForward(self, rvn: ReplaceVarnode) -> bool:
        """Trace logical value forward through descendants."""
        dcount = 0
        hcount = 0
        callcount = 0
        vn = rvn.vn

        desc_list = list(vn.beginDescend()) if hasattr(vn, 'beginDescend') else []
        desc_iter = iter(desc_list)
        for op in desc_iter:
            outvn = op.getOut()
            if outvn is not None and outvn.isMark() and not (hasattr(op, 'isCall') and op.isCall()):
                continue
            dcount += 1
            slot = op.getSlot(vn)
            opc = op.code()

            if opc in (OpCode.CPUI_COPY, OpCode.CPUI_MULTIEQUAL, OpCode.CPUI_INT_NEGATE, OpCode.CPUI_INT_XOR):
                rop = self._createOpDown(opc, op.numInput(), op, rvn, slot)
                if not self._createLink(rop, rvn.mask, -1, outvn):
                    return False
                hcount += 1

            elif opc == OpCode.CPUI_INT_OR:
                if self._doesOrSet(op, rvn.mask) != -1:
                    pass  # Subvar set to 1s, truncate
                else:
                    rop = self._createOpDown(OpCode.CPUI_INT_OR, 2, op, rvn, slot)
                    if not self._createLink(rop, rvn.mask, -1, outvn):
                        return False
                    hcount += 1

            elif opc == OpCode.CPUI_INT_AND:
                if op.getIn(1).isConstant() and op.getIn(1).getOffset() == rvn.mask:
                    if outvn.getSize() == self._flowsize and (rvn.mask & 1) != 0:
                        self._addTerminalPatch(op, rvn)
                        hcount += 1
                    elif (not self._aggressive) and ((outvn.getConsume() & rvn.mask) != outvn.getConsume()):
                        self._addExtensionPatch(rvn, op, -1)
                        hcount += 1
                    else:
                        if self._doesAndClear(op, rvn.mask) != -1:
                            pass  # Subvar set to zero, truncate
                        else:
                            rop = self._createOpDown(OpCode.CPUI_INT_AND, 2, op, rvn, slot)
                            if not self._createLink(rop, rvn.mask, -1, outvn):
                                return False
                            hcount += 1
                else:
                    if self._doesAndClear(op, rvn.mask) != -1:
                        pass
                    else:
                        rop = self._createOpDown(OpCode.CPUI_INT_AND, 2, op, rvn, slot)
                        if not self._createLink(rop, rvn.mask, -1, outvn):
                            return False
                        hcount += 1

            elif opc in (OpCode.CPUI_INT_ZEXT, OpCode.CPUI_INT_SEXT):
                rop = self._createOpDown(OpCode.CPUI_COPY, 1, op, rvn, 0)
                if not self._createLink(rop, rvn.mask, -1, outvn):
                    return False
                hcount += 1

            elif opc == OpCode.CPUI_INT_MULT:
                if (rvn.mask & 1) == 0:
                    return False
                sa = leastsigbit_set(op.getIn(1 - slot).getNZMask())
                if sa < 0:
                    sa = 0
                sa &= ~7
                if self._bitsize + sa > 8 * vn.getSize():
                    return False
                rop = self._createOpDown(OpCode.CPUI_INT_MULT, 2, op, rvn, slot)
                if not self._createLink(rop, (rvn.mask << sa) & calc_mask(outvn.getSize()), -1, outvn):
                    return False
                hcount += 1

            elif opc in (OpCode.CPUI_INT_DIV, OpCode.CPUI_INT_REM):
                if (rvn.mask & 1) == 0:
                    return False
                if (self._bitsize & 7) != 0:
                    return False
                if not op.getIn(0).isZeroExtended(self._flowsize):
                    return False
                if not op.getIn(1).isZeroExtended(self._flowsize):
                    return False
                rop = self._createOpDown(opc, 2, op, rvn, slot)
                if not self._createLink(rop, rvn.mask, -1, outvn):
                    return False
                hcount += 1

            elif opc == OpCode.CPUI_INT_ADD:
                if (rvn.mask & 1) == 0:
                    return False
                rop = self._createOpDown(OpCode.CPUI_INT_ADD, 2, op, rvn, slot)
                if not self._createLink(rop, rvn.mask, -1, outvn):
                    return False
                hcount += 1

            elif opc == OpCode.CPUI_INT_LEFT:
                if slot == 1:
                    if (rvn.mask & 1) == 0:
                        return False
                    if self._bitsize < 8:
                        return False
                    self._addTerminalPatchSameOp(op, rvn, slot)
                    hcount += 1
                else:
                    if not op.getIn(1).isConstant():
                        return False
                    sa = int(op.getIn(1).getOffset())
                    if sa >= 64:
                        return False
                    newmask = (rvn.mask << sa) & calc_mask(outvn.getSize())
                    if newmask == 0:
                        pass  # Cleared, truncate
                    elif rvn.mask != (newmask >> sa):
                        return False
                    elif ((rvn.mask & 1) != 0) and (sa + self._bitsize == 8 * outvn.getSize()) and \
                            ((outvn.getConsume() & ~newmask) != 0):
                        self._addExtensionPatch(rvn, op, sa)
                        hcount += 1
                    else:
                        rop = self._createOpDown(OpCode.CPUI_COPY, 1, op, rvn, 0)
                        if not self._createLink(rop, newmask, -1, outvn):
                            return False
                        hcount += 1

            elif opc in (OpCode.CPUI_INT_RIGHT, OpCode.CPUI_INT_SRIGHT):
                if slot == 1:
                    if (rvn.mask & 1) == 0:
                        return False
                    if self._bitsize < 8:
                        return False
                    self._addTerminalPatchSameOp(op, rvn, slot)
                    hcount += 1
                else:
                    if not op.getIn(1).isConstant():
                        return False
                    sa = int(op.getIn(1).getOffset())
                    if sa >= 64:
                        newmask = 0
                    else:
                        newmask = rvn.mask >> sa
                    if newmask == 0:
                        if opc == OpCode.CPUI_INT_RIGHT:
                            pass
                        else:
                            return False
                    elif rvn.mask != (newmask << sa):
                        return False
                    elif (outvn.getSize() == self._flowsize) and ((newmask & 1) == 1) and \
                            (op.getIn(0).getNZMask() == rvn.mask):
                        self._addTerminalPatch(op, rvn)
                        hcount += 1
                    elif ((newmask & 1) == 1) and (sa + self._bitsize == 8 * outvn.getSize()) and \
                            ((outvn.getConsume() & ~newmask) != 0):
                        self._addExtensionPatch(rvn, op, 0)
                        hcount += 1
                    else:
                        rop = self._createOpDown(OpCode.CPUI_COPY, 1, op, rvn, 0)
                        if not self._createLink(rop, newmask, -1, outvn):
                            return False
                        hcount += 1

            elif opc == OpCode.CPUI_SUBPIECE:
                sa = int(op.getIn(1).getOffset()) * 8
                if sa >= 64:
                    pass
                else:
                    newmask = (rvn.mask >> sa) & calc_mask(outvn.getSize())
                    if newmask == 0:
                        pass
                    elif rvn.mask != (newmask << sa):
                        if self._flowsize > ((sa // 8) + outvn.getSize()) and (rvn.mask & 1) != 0:
                            self._addTerminalPatchSameOp(op, rvn, 0)
                            hcount += 1
                        else:
                            return False
                    elif ((newmask & 1) != 0) and (outvn.getSize() == self._flowsize):
                        self._addTerminalPatch(op, rvn)
                        hcount += 1
                    else:
                        rop = self._createOpDown(OpCode.CPUI_COPY, 1, op, rvn, 0)
                        if not self._createLink(rop, newmask, -1, outvn):
                            return False
                        hcount += 1

            elif opc == OpCode.CPUI_PIECE:
                if vn is op.getIn(0):
                    newmask = rvn.mask << (8 * op.getIn(1).getSize())
                else:
                    newmask = rvn.mask
                rop = self._createOpDown(OpCode.CPUI_COPY, 1, op, rvn, 0)
                if not self._createLink(rop, newmask, -1, outvn):
                    return False
                hcount += 1

            elif opc in (OpCode.CPUI_INT_LESS, OpCode.CPUI_INT_LESSEQUAL):
                othervn = op.getIn(1 - slot)
                if (not self._aggressive) and ((vn.getNZMask() | rvn.mask) != rvn.mask):
                    return False
                if othervn.isConstant():
                    if (rvn.mask | othervn.getOffset()) != rvn.mask:
                        return False
                else:
                    if (not self._aggressive) and ((rvn.mask | othervn.getNZMask()) != rvn.mask):
                        return False
                if not self._createCompareBridge(op, rvn, slot, othervn):
                    return False
                hcount += 1

            elif opc in (OpCode.CPUI_INT_NOTEQUAL, OpCode.CPUI_INT_EQUAL):
                othervn = op.getIn(1 - slot)
                if self._bitsize != 1:
                    if (not self._aggressive) and ((vn.getNZMask() | rvn.mask) != rvn.mask):
                        return False
                    if othervn.isConstant():
                        if (rvn.mask | othervn.getOffset()) != rvn.mask:
                            return False
                    else:
                        if (not self._aggressive) and ((rvn.mask | othervn.getNZMask()) != rvn.mask):
                            return False
                    if not self._createCompareBridge(op, rvn, slot, othervn):
                        return False
                else:
                    if not othervn.isConstant():
                        return False
                    newmask = vn.getNZMask()
                    if newmask != rvn.mask:
                        return False
                    if op.getIn(1 - slot).getOffset() == 0:
                        booldir = True
                    elif op.getIn(1 - slot).getOffset() == newmask:
                        booldir = False
                    else:
                        return False
                    if opc == OpCode.CPUI_INT_EQUAL:
                        booldir = not booldir
                    if booldir:
                        self._addTerminalPatch(op, rvn)
                    else:
                        brop = self._createOpDown(OpCode.CPUI_BOOL_NEGATE, 1, op, rvn, 0)
                        self._createNewOut(brop, 1)
                        self._addTerminalPatch(op, brop.output)
                hcount += 1

            elif opc in (OpCode.CPUI_CALL, OpCode.CPUI_CALLIND):
                callcount += 1
                if callcount > 1:
                    slot = op.getRepeatSlot(vn, slot, op)
                if not self._tryCallPull(op, rvn, slot):
                    return False
                hcount += 1

            elif opc == OpCode.CPUI_RETURN:
                if not self._tryReturnPull(op, rvn, slot):
                    return False
                hcount += 1

            elif opc == OpCode.CPUI_BRANCHIND:
                if not self._trySwitchPull(op, rvn):
                    return False
                hcount += 1

            elif opc in (OpCode.CPUI_BOOL_NEGATE, OpCode.CPUI_BOOL_AND, OpCode.CPUI_BOOL_OR, OpCode.CPUI_BOOL_XOR):
                if self._bitsize != 1:
                    return False
                if rvn.mask != 1:
                    return False
                self._addBooleanPatch(op, rvn, slot)

            elif opc == OpCode.CPUI_FLOAT_INT2FLOAT:
                if not self._tryInt2FloatPull(op, rvn):
                    return False
                hcount += 1

            elif opc == OpCode.CPUI_CBRANCH:
                if self._bitsize != 1 or slot != 1:
                    return False
                if rvn.mask != 1:
                    return False
                self._addBooleanPatch(op, rvn, 1)
                hcount += 1

            else:
                return False

        if dcount != hcount:
            if vn.isInput():
                return False
        return True

    # ------------------------------------------------------------------
    # traceBackward
    # ------------------------------------------------------------------

    def _traceBackward(self, rvn: ReplaceVarnode) -> bool:
        """Trace logical value backward through its defining op."""
        vn = rvn.vn
        if not vn.isWritten():
            return True  # Input varnode
        op = vn.getDef()
        opc = op.code()

        if opc in (OpCode.CPUI_COPY, OpCode.CPUI_MULTIEQUAL, OpCode.CPUI_INT_NEGATE, OpCode.CPUI_INT_XOR):
            rop = self._createOp(opc, op.numInput(), rvn)
            for i in range(op.numInput()):
                if not self._createLink(rop, rvn.mask, i, op.getIn(i)):
                    return False
            return True

        if opc == OpCode.CPUI_INT_AND:
            sa = self._doesAndClear(op, rvn.mask)
            if sa != -1:
                rop = self._createOp(OpCode.CPUI_COPY, 1, rvn)
                self._addConstant(rop, rvn.mask, 0, op.getIn(sa))
            else:
                rop = self._createOp(OpCode.CPUI_INT_AND, 2, rvn)
                if not self._createLink(rop, rvn.mask, 0, op.getIn(0)):
                    return False
                if not self._createLink(rop, rvn.mask, 1, op.getIn(1)):
                    return False
            return True

        if opc == OpCode.CPUI_INT_OR:
            sa = self._doesOrSet(op, rvn.mask)
            if sa != -1:
                rop = self._createOp(OpCode.CPUI_COPY, 1, rvn)
                self._addConstant(rop, rvn.mask, 0, op.getIn(sa))
            else:
                rop = self._createOp(OpCode.CPUI_INT_OR, 2, rvn)
                if not self._createLink(rop, rvn.mask, 0, op.getIn(0)):
                    return False
                if not self._createLink(rop, rvn.mask, 1, op.getIn(1)):
                    return False
            return True

        if opc in (OpCode.CPUI_INT_ZEXT, OpCode.CPUI_INT_SEXT):
            if (rvn.mask & calc_mask(op.getIn(0).getSize())) != rvn.mask:
                if (rvn.mask & 1) != 0 and self._flowsize > op.getIn(0).getSize():
                    self._addPush(op, rvn)
                    return True
                return False
            rop = self._createOp(OpCode.CPUI_COPY, 1, rvn)
            if not self._createLink(rop, rvn.mask, 0, op.getIn(0)):
                return False
            return True

        if opc == OpCode.CPUI_INT_ADD:
            if (rvn.mask & 1) == 0:
                return False
            if rvn.mask == 1:
                rop = self._createOp(OpCode.CPUI_INT_XOR, 2, rvn)
            else:
                rop = self._createOp(OpCode.CPUI_INT_ADD, 2, rvn)
            if not self._createLink(rop, rvn.mask, 0, op.getIn(0)):
                return False
            if not self._createLink(rop, rvn.mask, 1, op.getIn(1)):
                return False
            return True

        if opc == OpCode.CPUI_INT_LEFT:
            if not op.getIn(1).isConstant():
                return False
            sa = int(op.getIn(1).getOffset())
            newmask = (rvn.mask >> sa) if sa < 64 else 0
            if newmask == 0:
                rop = self._createOp(OpCode.CPUI_COPY, 1, rvn)
                self._addNewConstant(rop, 0, 0)
                return True
            if (newmask << sa) == rvn.mask:
                rop = self._createOp(OpCode.CPUI_COPY, 1, rvn)
                if not self._createLink(rop, newmask, 0, op.getIn(0)):
                    return False
                return True
            if (rvn.mask & 1) == 0:
                return False
            rop = self._createOp(OpCode.CPUI_INT_LEFT, 2, rvn)
            if not self._createLink(rop, rvn.mask, 0, op.getIn(0)):
                return False
            self._addConstant(rop, calc_mask(op.getIn(1).getSize()), 1, op.getIn(1))
            return True

        if opc == OpCode.CPUI_INT_RIGHT:
            if not op.getIn(1).isConstant():
                return False
            sa = int(op.getIn(1).getOffset())
            if sa >= 64:
                return False
            newmask = (rvn.mask << sa) & calc_mask(op.getIn(0).getSize())
            if newmask == 0:
                rop = self._createOp(OpCode.CPUI_COPY, 1, rvn)
                self._addNewConstant(rop, 0, 0)
                return True
            if (newmask >> sa) != rvn.mask:
                return False
            rop = self._createOp(OpCode.CPUI_COPY, 1, rvn)
            if not self._createLink(rop, newmask, 0, op.getIn(0)):
                return False
            return True

        if opc == OpCode.CPUI_INT_SRIGHT:
            if not op.getIn(1).isConstant():
                return False
            sa = int(op.getIn(1).getOffset())
            if sa >= 64:
                return False
            newmask = (rvn.mask << sa) & calc_mask(op.getIn(0).getSize())
            if (newmask >> sa) != rvn.mask:
                return False
            rop = self._createOp(OpCode.CPUI_COPY, 1, rvn)
            if not self._createLink(rop, newmask, 0, op.getIn(0)):
                return False
            return True

        if opc == OpCode.CPUI_INT_MULT:
            sa = leastsigbit_set(rvn.mask)
            if sa is None or sa < 0:
                sa = 0
            if sa != 0:
                sa2 = leastsigbit_set(op.getIn(1).getNZMask())
                if sa2 is None or sa2 < 0:
                    sa2 = 0
                if sa2 < sa:
                    return False
                newmask = rvn.mask >> sa
                rop = self._createOp(OpCode.CPUI_INT_MULT, 2, rvn)
                if not self._createLink(rop, newmask, 0, op.getIn(0)):
                    return False
                if not self._createLink(rop, rvn.mask, 1, op.getIn(1)):
                    return False
            else:
                if rvn.mask == 1:
                    rop = self._createOp(OpCode.CPUI_INT_AND, 2, rvn)
                else:
                    rop = self._createOp(OpCode.CPUI_INT_MULT, 2, rvn)
                if not self._createLink(rop, rvn.mask, 0, op.getIn(0)):
                    return False
                if not self._createLink(rop, rvn.mask, 1, op.getIn(1)):
                    return False
            return True

        if opc in (OpCode.CPUI_INT_DIV, OpCode.CPUI_INT_REM):
            if (rvn.mask & 1) == 0:
                return False
            if (self._bitsize & 7) != 0:
                return False
            if not op.getIn(0).isZeroExtended(self._flowsize):
                return False
            if not op.getIn(1).isZeroExtended(self._flowsize):
                return False
            rop = self._createOp(opc, 2, rvn)
            if not self._createLink(rop, rvn.mask, 0, op.getIn(0)):
                return False
            if not self._createLink(rop, rvn.mask, 1, op.getIn(1)):
                return False
            return True

        if opc == OpCode.CPUI_SUBPIECE:
            sa = int(op.getIn(1).getOffset()) * 8
            newmask = rvn.mask << sa
            rop = self._createOp(OpCode.CPUI_COPY, 1, rvn)
            if not self._createLink(rop, newmask, 0, op.getIn(0)):
                return False
            return True

        if opc == OpCode.CPUI_PIECE:
            lo_mask = calc_mask(op.getIn(1).getSize())
            if (rvn.mask & lo_mask) == rvn.mask:
                rop = self._createOp(OpCode.CPUI_COPY, 1, rvn)
                if not self._createLink(rop, rvn.mask, 0, op.getIn(1)):
                    return False
                return True
            sa = op.getIn(1).getSize() * 8
            newmask = rvn.mask >> sa
            if (newmask << sa) == rvn.mask:
                rop = self._createOp(OpCode.CPUI_COPY, 1, rvn)
                if not self._createLink(rop, newmask, 0, op.getIn(0)):
                    return False
                return True
            return False

        if opc in (OpCode.CPUI_CALL, OpCode.CPUI_CALLIND):
            if self._tryCallReturnPush(op, rvn):
                return True
            return False

        if opc in (OpCode.CPUI_INT_EQUAL, OpCode.CPUI_INT_NOTEQUAL,
                   OpCode.CPUI_INT_SLESS, OpCode.CPUI_INT_SLESSEQUAL,
                   OpCode.CPUI_INT_LESS, OpCode.CPUI_INT_LESSEQUAL,
                   OpCode.CPUI_INT_CARRY, OpCode.CPUI_INT_SCARRY, OpCode.CPUI_INT_SBORROW,
                   OpCode.CPUI_BOOL_NEGATE, OpCode.CPUI_BOOL_XOR,
                   OpCode.CPUI_BOOL_AND, OpCode.CPUI_BOOL_OR,
                   OpCode.CPUI_FLOAT_EQUAL, OpCode.CPUI_FLOAT_NOTEQUAL,
                   OpCode.CPUI_FLOAT_LESSEQUAL, OpCode.CPUI_FLOAT_NAN):
            if (rvn.mask & 1) == 1:
                return False
            rop = self._createOp(OpCode.CPUI_COPY, 1, rvn)
            self._addNewConstant(rop, 0, 0)
            return True

        return False

    # ------------------------------------------------------------------
    # traceForwardSext / traceBackwardSext
    # ------------------------------------------------------------------

    def _traceForwardSext(self, rvn: ReplaceVarnode) -> bool:
        """Trace forward assuming sign-extensions."""
        dcount = 0
        hcount = 0
        callcount = 0
        vn = rvn.vn

        for op in list(vn.beginDescend()) if hasattr(vn, 'beginDescend') else []:
            outvn = op.getOut()
            if outvn is not None and outvn.isMark() and not (hasattr(op, 'isCall') and op.isCall()):
                continue
            dcount += 1
            slot = op.getSlot(vn)
            opc = op.code()

            if opc in (OpCode.CPUI_COPY, OpCode.CPUI_MULTIEQUAL, OpCode.CPUI_INT_NEGATE,
                       OpCode.CPUI_INT_XOR, OpCode.CPUI_INT_OR, OpCode.CPUI_INT_AND):
                rop = self._createOpDown(opc, op.numInput(), op, rvn, slot)
                if not self._createLink(rop, rvn.mask, -1, outvn):
                    return False
                hcount += 1

            elif opc == OpCode.CPUI_INT_SEXT:
                rop = self._createOpDown(OpCode.CPUI_COPY, 1, op, rvn, 0)
                if not self._createLink(rop, rvn.mask, -1, outvn):
                    return False
                hcount += 1

            elif opc == OpCode.CPUI_INT_SRIGHT:
                if not op.getIn(1).isConstant():
                    return False
                rop = self._createOpDown(OpCode.CPUI_INT_SRIGHT, 2, op, rvn, 0)
                if not self._createLink(rop, rvn.mask, -1, outvn):
                    return False
                self._addConstant(rop, calc_mask(op.getIn(1).getSize()), 1, op.getIn(1))
                hcount += 1

            elif opc == OpCode.CPUI_SUBPIECE:
                if op.getIn(1).getOffset() != 0:
                    return False
                if outvn.getSize() > self._flowsize:
                    return False
                if outvn.getSize() == self._flowsize:
                    self._addTerminalPatch(op, rvn)
                else:
                    self._addTerminalPatchSameOp(op, rvn, 0)
                hcount += 1

            elif opc in (OpCode.CPUI_INT_LESS, OpCode.CPUI_INT_LESSEQUAL,
                         OpCode.CPUI_INT_SLESS, OpCode.CPUI_INT_SLESSEQUAL,
                         OpCode.CPUI_INT_EQUAL, OpCode.CPUI_INT_NOTEQUAL):
                othervn = op.getIn(1 - slot)
                if not self._createCompareBridge(op, rvn, slot, othervn):
                    return False
                hcount += 1

            elif opc in (OpCode.CPUI_CALL, OpCode.CPUI_CALLIND):
                callcount += 1
                if callcount > 1:
                    slot = op.getRepeatSlot(vn, slot, op)
                if not self._tryCallPull(op, rvn, slot):
                    return False
                hcount += 1

            elif opc == OpCode.CPUI_RETURN:
                if not self._tryReturnPull(op, rvn, slot):
                    return False
                hcount += 1

            elif opc == OpCode.CPUI_BRANCHIND:
                if not self._trySwitchPull(op, rvn):
                    return False
                hcount += 1

            else:
                return False

        if dcount != hcount:
            if vn.isInput():
                return False
        return True

    def _traceBackwardSext(self, rvn: ReplaceVarnode) -> bool:
        """Trace backward assuming sign-extensions."""
        vn = rvn.vn
        if not vn.isWritten():
            return True
        op = vn.getDef()
        opc = op.code()

        if opc in (OpCode.CPUI_COPY, OpCode.CPUI_MULTIEQUAL, OpCode.CPUI_INT_NEGATE,
                   OpCode.CPUI_INT_XOR, OpCode.CPUI_INT_AND, OpCode.CPUI_INT_OR):
            rop = self._createOp(opc, op.numInput(), rvn)
            for i in range(op.numInput()):
                if not self._createLink(rop, rvn.mask, i, op.getIn(i)):
                    return False
            return True

        if opc == OpCode.CPUI_INT_ZEXT:
            if op.getIn(0).getSize() < self._flowsize:
                self._addPush(op, rvn)
                return True
            return False

        if opc == OpCode.CPUI_INT_SEXT:
            if self._flowsize != op.getIn(0).getSize():
                return False
            rop = self._createOp(OpCode.CPUI_COPY, 1, rvn)
            if not self._createLink(rop, rvn.mask, 0, op.getIn(0)):
                return False
            return True

        if opc == OpCode.CPUI_INT_SRIGHT:
            if not op.getIn(1).isConstant():
                return False
            rop = self._createOp(OpCode.CPUI_INT_SRIGHT, 2, rvn)
            if not self._createLink(rop, rvn.mask, 0, op.getIn(0)):
                return False
            if len(rop.input) == 1:
                self._addConstant(rop, calc_mask(op.getIn(1).getSize()), 1, op.getIn(1))
            return True

        if opc in (OpCode.CPUI_CALL, OpCode.CPUI_CALLIND):
            if self._tryCallReturnPush(op, rvn):
                return True
            return False

        return False

    # ------------------------------------------------------------------
    # processNextWork / doTrace
    # ------------------------------------------------------------------

    def _processNextWork(self) -> bool:
        rvn = self._worklist.pop()
        if self._sextrestrictions:
            if not self._traceBackwardSext(rvn):
                return False
            return self._traceForwardSext(rvn)
        if not self._traceBackward(rvn):
            return False
        return self._traceForward(rvn)

    def doTrace(self) -> bool:
        """Trace logical value through data-flow, constructing transform."""
        self._pullcount = 0
        retval = False
        if self._fd is not None:
            retval = True
            while self._worklist:
                if not self._processNextWork():
                    retval = False
                    break
        # Clear marks
        for vid, rvn in self._varmap.items():
            if rvn.vn is not None and hasattr(rvn.vn, 'clearMark'):
                rvn.vn.clearMark()
        if not retval:
            return False
        if self._pullcount == 0:
            return False
        return True

    # ------------------------------------------------------------------
    # Replacement address / varnode helpers
    # ------------------------------------------------------------------

    def _getReplacementAddress(self, rvn: ReplaceVarnode):
        """Calculate address of replacement Varnode."""
        addr = rvn.vn.getAddr()
        sa = leastsigbit_set(rvn.mask) // 8
        if sa < 0:
            sa = 0
        if hasattr(addr, 'isBigEndian') and addr.isBigEndian():
            addr = addr + (rvn.vn.getSize() - self._flowsize - sa)
        else:
            addr = addr + sa
        if hasattr(addr, 'renormalize'):
            addr.renormalize(self._flowsize)
        return addr

    def _useSameAddress(self, rvn: ReplaceVarnode) -> bool:
        """Decide if we use the same memory range for the replacement."""
        if rvn.vn.isInput():
            return True
        if hasattr(rvn.vn, 'isAddrTied') and rvn.vn.isAddrTied():
            return False
        if (rvn.mask & 1) == 0:
            return False
        if self._bitsize >= 8:
            return True
        if self._aggressive:
            return True
        bitmask = (1 << self._bitsize) - 1
        mask = rvn.vn.getConsume() | bitmask
        if mask == rvn.mask:
            return True
        return False

    def _replaceInput(self, rvn: ReplaceVarnode) -> None:
        """Replace an input Varnode to avoid overlap errors."""
        newvn = self._fd.newUnique(rvn.vn.getSize())
        newvn = self._fd.setInputVarnode(newvn)
        self._fd.totalReplace(rvn.vn, newvn)
        self._fd.deleteVarnode(rvn.vn)
        rvn.vn = newvn

    def _getReplaceVarnode(self, rvn: ReplaceVarnode):
        """Build the replacement Varnode for a subgraph variable."""
        if rvn.replacement is not None:
            return rvn.replacement
        if rvn.vn is None:
            if rvn.defop is None:
                return self._fd.newConstant(self._flowsize, rvn.val)
            rvn.replacement = self._fd.newUnique(self._flowsize)
            return rvn.replacement
        if rvn.vn.isConstant():
            newVn = self._fd.newConstant(self._flowsize, rvn.val)
            if hasattr(newVn, 'copySymbolIfValid'):
                newVn.copySymbolIfValid(rvn.vn)
            return newVn
        isinput = rvn.vn.isInput()
        if self._useSameAddress(rvn):
            addr = self._getReplacementAddress(rvn)
            if isinput:
                self._replaceInput(rvn)
            rvn.replacement = self._fd.newVarnode(self._flowsize, addr)
        else:
            rvn.replacement = self._fd.newUnique(self._flowsize)
        if isinput:
            rvn.replacement = self._fd.setInputVarnode(rvn.replacement)
        return rvn.replacement

    # ------------------------------------------------------------------
    # doReplacement
    # ------------------------------------------------------------------

    def doReplacement(self) -> None:
        """Perform the discovered transform, making logical values explicit."""
        fd = self._fd
        piter_idx = 0

        # Process push_patch records at front
        while piter_idx < len(self._patchlist):
            pr = self._patchlist[piter_idx]
            if pr.type != PatchRecord.push_patch:
                break
            pushOp = pr.patchOp
            newVn = self._getReplaceVarnode(pr.in1)
            oldVn = pushOp.getOut()
            fd.opSetOutput(pushOp, newVn)
            newZext = fd.newOp(1, pushOp.getAddr())
            fd.opSetOpcode(newZext, OpCode.CPUI_INT_ZEXT)
            fd.opSetInput(newZext, newVn, 0)
            fd.opSetOutput(newZext, oldVn)
            fd.opInsertAfter(newZext, pushOp)
            piter_idx += 1

        # Define all outputs first
        for rop in self._oplist:
            newop = fd.newOp(rop.numparams, rop.op.getAddr())
            rop.replacement = newop
            fd.opSetOpcode(newop, rop.opc)
            fd.opSetOutput(newop, self._getReplaceVarnode(rop.output))
            fd.opInsertAfter(newop, rop.op)

        # Set all inputs
        for rop in self._oplist:
            newop = rop.replacement
            for i in range(len(rop.input)):
                fd.opSetInput(newop, self._getReplaceVarnode(rop.input[i]), i)

        # Process remaining patches
        while piter_idx < len(self._patchlist):
            pr = self._patchlist[piter_idx]
            piter_idx += 1
            pullop = pr.patchOp

            if pr.type == PatchRecord.copy_patch:
                while pullop.numInput() > 1:
                    fd.opRemoveInput(pullop, pullop.numInput() - 1)
                fd.opSetInput(pullop, self._getReplaceVarnode(pr.in1), 0)
                fd.opSetOpcode(pullop, OpCode.CPUI_COPY)

            elif pr.type == PatchRecord.compare_patch:
                fd.opSetInput(pullop, self._getReplaceVarnode(pr.in1), 0)
                fd.opSetInput(pullop, self._getReplaceVarnode(pr.in2), 1)

            elif pr.type == PatchRecord.parameter_patch:
                fd.opSetInput(pullop, self._getReplaceVarnode(pr.in1), pr.slot)

            elif pr.type == PatchRecord.extension_patch:
                sa = pr.slot
                inVn = self._getReplaceVarnode(pr.in1)
                outSize = pullop.getOut().getSize()
                if sa == 0:
                    opc = OpCode.CPUI_COPY if inVn.getSize() == outSize else OpCode.CPUI_INT_ZEXT
                    fd.opSetOpcode(pullop, opc)
                    fd.opSetAllInput(pullop, [inVn])
                else:
                    if inVn.getSize() != outSize:
                        zextop = fd.newOp(1, pullop.getAddr())
                        fd.opSetOpcode(zextop, OpCode.CPUI_INT_ZEXT)
                        zextout = fd.newUniqueOut(outSize, zextop)
                        fd.opSetInput(zextop, inVn, 0)
                        fd.opInsertBefore(zextop, pullop)
                        inVn = zextout
                    fd.opSetAllInput(pullop, [inVn, fd.newConstant(4, sa)])
                    fd.opSetOpcode(pullop, OpCode.CPUI_INT_LEFT)

            elif pr.type == PatchRecord.int2float_patch:
                invn = self._getReplaceVarnode(pr.in1)
                zextOp = fd.newOp(1, pullop.getAddr())
                fd.opSetOpcode(zextOp, OpCode.CPUI_INT_ZEXT)
                fd.opSetInput(zextOp, invn, 0)
                sizeout = invn.getSize() * 2 if invn.getSize() <= 4 else 8
                outvn = fd.newUniqueOut(sizeout, zextOp)
                fd.opInsertBefore(zextOp, pullop)
                fd.opSetInput(pullop, outvn, 0)

    # ------------------------------------------------------------------
    # Legacy accessors
    # ------------------------------------------------------------------

    def getReplacementCount(self) -> int:
        return len(self._varmap)

    def getFlowSize(self) -> int:
        return self._flowsize

    def getOpCount(self) -> int:
        return len(self._oplist)


class SplitFlow(TransformManager):
    """Class for splitting up Varnodes that hold 2 logical variables.

    Starting from a root Varnode, looks for data-flow that consistently holds
    2 logical values in a single Varnode. If doTrace() returns True, a consistent
    view has been created and invoking apply() will split all Varnodes and PcodeOps.

    C++ ref: SplitFlow in subflow.cc
    """

    def __init__(self, fd, root, lowSize: int) -> None:
        super().__init__(fd)
        hiSize = root.getSize() - lowSize
        self.laneDescription = LaneDescription(root.getSize(), lowSize, hiSize)
        self.worklist: list = []
        self.setReplacement(root)

    def setReplacement(self, vn):
        """Create placeholders for a Varnode that needs to be split into 2 lanes."""
        if vn.isMark():
            return self.getSplit(vn, self.laneDescription)
        from ghidra.types.datatype import TYPE_PARTIALSTRUCT
        if vn.isTypeLock() and vn.getType().getMetatype() != TYPE_PARTIALSTRUCT:
            return None
        if vn.isInput():
            return None
        if vn.isFree() and not vn.isConstant():
            return None
        res = self.newSplit(vn, self.laneDescription)
        vn.setMark()
        if not vn.isConstant():
            self.worklist.append(res)
        return res

    def addOp(self, op, rvn, slot: int) -> bool:
        """Split given op into its lanes (lo/hi)."""
        if slot == -1:
            outvn = rvn
        else:
            outvn = self.setReplacement(op.getOut())
            if outvn is None:
                return False
        # rvn is a list [lo, hi]; outvn is also [lo, hi]
        if outvn[0].defOp is not None:
            return True  # Already traversed
        loOp = self.newOpReplace(op.numInput(), op.code(), op)
        hiOp = self.newOpReplace(op.numInput(), op.code(), op)
        numParam = op.numInput()
        if op.code() == OpCode.CPUI_INDIRECT:
            self.opSetInput(loOp, self.newIop(op.getIn(1)), 1)
            self.opSetInput(hiOp, self.newIop(op.getIn(1)), 1)
            if hasattr(loOp, 'inheritIndirect'):
                loOp.inheritIndirect(op)
            if hasattr(hiOp, 'inheritIndirect'):
                hiOp.inheritIndirect(op)
            numParam = 1
        for i in range(numParam):
            if i == slot:
                invn = rvn
            else:
                invn = self.setReplacement(op.getIn(i))
                if invn is None:
                    return False
            self.opSetInput(loOp, invn[0], i)  # Low piece with low op
            self.opSetInput(hiOp, invn[1], i)  # High piece with high op
        self.opSetOutput(loOp, outvn[0])
        self.opSetOutput(hiOp, outvn[1])
        return True

    def traceForward(self, rvn) -> bool:
        """Trace the pair of logical values forward through reading ops."""
        origvn = rvn[0].getOriginal()
        for op in list(origvn.beginDescend()):
            outvn = op.getOut()
            if outvn is not None and outvn.isMark():
                continue
            opc = op.code()
            if opc in (OpCode.CPUI_COPY, OpCode.CPUI_MULTIEQUAL, OpCode.CPUI_INDIRECT,
                       OpCode.CPUI_INT_AND, OpCode.CPUI_INT_OR, OpCode.CPUI_INT_XOR):
                if not self.addOp(op, rvn, op.getSlot(origvn)):
                    return False
            elif opc == OpCode.CPUI_SUBPIECE:
                if hasattr(outvn, 'isPrecisLo') and (outvn.isPrecisLo() or outvn.isPrecisHi()):
                    return False
                val = int(op.getIn(1).getOffset())
                loSize = self.laneDescription.getSize(0)
                hiSize = self.laneDescription.getSize(1)
                if val == 0 and outvn.getSize() == loSize:
                    rop = self.newPreexistingOp(1, OpCode.CPUI_COPY, op)
                    self.opSetInput(rop, rvn[0], 0)  # Grabs the low piece
                elif val == loSize and outvn.getSize() == hiSize:
                    rop = self.newPreexistingOp(1, OpCode.CPUI_COPY, op)
                    self.opSetInput(rop, rvn[1], 0)  # Grabs the high piece
                else:
                    return False
            elif opc == OpCode.CPUI_INT_LEFT:
                tmpvn = op.getIn(1)
                if not tmpvn.isConstant():
                    return False
                val = int(tmpvn.getOffset())
                hiSize = self.laneDescription.getSize(1)
                if val < hiSize * 8:
                    return False  # Must obliterate all high bits
                rop = self.newPreexistingOp(2, OpCode.CPUI_INT_LEFT, op)
                zextrop = self.newOp(1, OpCode.CPUI_INT_ZEXT, rop)
                self.opSetInput(zextrop, rvn[0], 0)  # Input is just the low piece
                self.opSetOutput(zextrop, self.newUnique(self.laneDescription.getWholeSize()))
                self.opSetInput(rop, zextrop.getOut(), 0)
                self.opSetInput(rop, self.newConstant(op.getIn(1).getSize(), 0, op.getIn(1).getOffset()), 1)
            elif opc in (OpCode.CPUI_INT_SRIGHT, OpCode.CPUI_INT_RIGHT):
                tmpvn = op.getIn(1)
                if not tmpvn.isConstant():
                    return False
                val = int(tmpvn.getOffset())
                loSize = self.laneDescription.getSize(0)
                if val < loSize * 8:
                    return False
                extOpCode = OpCode.CPUI_INT_ZEXT if opc == OpCode.CPUI_INT_RIGHT else OpCode.CPUI_INT_SEXT
                if val == loSize * 8:
                    rop = self.newPreexistingOp(1, extOpCode, op)
                    self.opSetInput(rop, rvn[1], 0)  # Input is the high piece
                else:
                    remainShift = val - loSize * 8
                    rop = self.newPreexistingOp(2, opc, op)
                    extrop = self.newOp(1, extOpCode, rop)
                    self.opSetInput(extrop, rvn[1], 0)  # Input is the high piece
                    self.opSetOutput(extrop, self.newUnique(self.laneDescription.getWholeSize()))
                    self.opSetInput(rop, extrop.getOut(), 0)
                    self.opSetInput(rop, self.newConstant(op.getIn(1).getSize(), 0, remainShift), 1)
            else:
                return False
        return True

    def traceBackward(self, rvn) -> bool:
        """Trace the pair of logical values backward through the defining op."""
        op = rvn[0].getOriginal().getDef()
        if op is None:
            return True  # vn is input
        opc = op.code()
        if opc in (OpCode.CPUI_COPY, OpCode.CPUI_MULTIEQUAL, OpCode.CPUI_INT_AND,
                   OpCode.CPUI_INT_OR, OpCode.CPUI_INT_XOR, OpCode.CPUI_INDIRECT):
            if not self.addOp(op, rvn, -1):
                return False
        elif opc == OpCode.CPUI_PIECE:
            hiSize = self.laneDescription.getSize(1)
            loSize = self.laneDescription.getSize(0)
            if op.getIn(0).getSize() != hiSize:
                return False
            if op.getIn(1).getSize() != loSize:
                return False
            loOp = self.newOpReplace(1, OpCode.CPUI_COPY, op)
            hiOp = self.newOpReplace(1, OpCode.CPUI_COPY, op)
            self.opSetInput(loOp, self.getPreexistingVarnode(op.getIn(1)), 0)
            self.opSetOutput(loOp, rvn[0])  # Least sig -> low
            self.opSetInput(hiOp, self.getPreexistingVarnode(op.getIn(0)), 0)
            self.opSetOutput(hiOp, rvn[1])  # Most sig -> high
        elif opc == OpCode.CPUI_INT_ZEXT:
            loSize = self.laneDescription.getSize(0)
            hiSize = self.laneDescription.getSize(1)
            if op.getIn(0).getSize() != loSize:
                return False
            if op.getOut().getSize() != self.laneDescription.getWholeSize():
                return False
            loOp = self.newOpReplace(1, OpCode.CPUI_COPY, op)
            hiOp = self.newOpReplace(1, OpCode.CPUI_COPY, op)
            self.opSetInput(loOp, self.getPreexistingVarnode(op.getIn(0)), 0)
            self.opSetOutput(loOp, rvn[0])  # ZEXT input -> low
            self.opSetInput(hiOp, self.newConstant(hiSize, 0, 0), 0)
            self.opSetOutput(hiOp, rvn[1])  # zero -> high
        elif opc == OpCode.CPUI_INT_LEFT:
            cvn = op.getIn(1)
            if not cvn.isConstant():
                return False
            loSize = self.laneDescription.getSize(0)
            hiSize = self.laneDescription.getSize(1)
            if int(cvn.getOffset()) != loSize * 8:
                return False
            invn = op.getIn(0)
            if not invn.isWritten():
                return False
            zextOp = invn.getDef()
            if zextOp.code() != OpCode.CPUI_INT_ZEXT:
                return False
            invn = zextOp.getIn(0)
            if invn.getSize() != hiSize:
                return False
            if invn.isFree():
                return False
            loOp = self.newOpReplace(1, OpCode.CPUI_COPY, op)
            hiOp = self.newOpReplace(1, OpCode.CPUI_COPY, op)
            self.opSetInput(loOp, self.newConstant(loSize, 0, 0), 0)
            self.opSetOutput(loOp, rvn[0])  # zero -> low
            self.opSetInput(hiOp, self.getPreexistingVarnode(invn), 0)
            self.opSetOutput(hiOp, rvn[1])  # invn -> high
        else:
            return False
        return True

    def processNextWork(self) -> bool:
        rvn = self.worklist.pop()
        if not self.traceBackward(rvn):
            return False
        return self.traceForward(rvn)

    def doTrace(self) -> bool:
        """Trace split through data-flow, constructing transform."""
        if not self.worklist:
            return False
        retval = True
        while self.worklist:
            if not self.processNextWork():
                retval = False
                break
        self.clearVarnodeMarks()
        return retval


class SubfloatFlow(TransformManager):
    """Class for tracing changes of precision in floating point variables.

    Follows the flow of a logical lower precision value stored in higher precision
    locations and rewrites the data-flow in terms of the lower precision.

    C++ ref: SubfloatFlow in subflow.cc
    """

    class _State:
        """Helper for maxPrecision iteration."""
        __slots__ = ('op', 'slot', 'maxPrecision')
        def __init__(self, op) -> None:
            self.op = op
            self.slot: int = 0
            self.maxPrecision: int = 0
        def incorporateInputSize(self, sz: int) -> None:
            if sz > self.maxPrecision:
                self.maxPrecision = sz

    def __init__(self, fd, root, prec: int) -> None:
        super().__init__(fd)
        self.precision: int = prec
        self.terminatorCount: int = 0
        self.worklist: list = []
        self.maxPrecisionMap: dict = {}
        arch = fd.getArch() if hasattr(fd, 'getArch') else None
        translate = arch.translate if arch is not None and hasattr(arch, 'translate') else None
        self.format = translate.getFloatFormat(prec) if translate is not None and hasattr(translate, 'getFloatFormat') else None
        if self.format is not None:
            self.setReplacement(root)

    def preserveAddress(self, vn, bitSize: int, lsbOffset: int) -> bool:
        return vn.isInput()

    def maxPrecision(self, vn) -> int:
        """Approximate maximum precision reaching vn."""
        if not vn.isWritten():
            return vn.getSize()
        op = vn.getDef()
        opc = op.code()
        _FLOAT_UNARY = (OpCode.CPUI_MULTIEQUAL, OpCode.CPUI_FLOAT_NEG, OpCode.CPUI_FLOAT_ABS,
                        OpCode.CPUI_FLOAT_SQRT, OpCode.CPUI_FLOAT_CEIL, OpCode.CPUI_FLOAT_FLOOR,
                        OpCode.CPUI_FLOAT_ROUND, OpCode.CPUI_COPY)
        _FLOAT_BINARY = (OpCode.CPUI_FLOAT_ADD, OpCode.CPUI_FLOAT_SUB,
                         OpCode.CPUI_FLOAT_MULT, OpCode.CPUI_FLOAT_DIV)
        if opc in _FLOAT_BINARY:
            return 0
        if opc in (OpCode.CPUI_FLOAT_FLOAT2FLOAT, OpCode.CPUI_FLOAT_INT2FLOAT):
            if op.getIn(0).getSize() > vn.getSize():
                return vn.getSize()
            return op.getIn(0).getSize()
        if opc not in _FLOAT_UNARY:
            return vn.getSize()
        cached = self.maxPrecisionMap.get(id(op))
        if cached is not None:
            return cached
        opStack = [SubfloatFlow._State(op)]
        op.setMark()
        mx = 0
        while opStack:
            state = opStack[-1]
            if state.slot >= state.op.numInput():
                mx = state.maxPrecision
                state.op.clearMark()
                self.maxPrecisionMap[id(state.op)] = state.maxPrecision
                opStack.pop()
                if opStack:
                    opStack[-1].incorporateInputSize(mx)
                continue
            nextVn = state.op.getIn(state.slot)
            state.slot += 1
            if not nextVn.isWritten():
                state.incorporateInputSize(nextVn.getSize())
                continue
            nextOp = nextVn.getDef()
            if nextOp.isMark():
                continue
            nextOpc = nextOp.code()
            if nextOpc in _FLOAT_UNARY:
                c = self.maxPrecisionMap.get(id(nextOp))
                if c is not None:
                    state.incorporateInputSize(c)
                else:
                    nextOp.setMark()
                    opStack.append(SubfloatFlow._State(nextOp))
            elif nextOpc in _FLOAT_BINARY:
                pass  # Delay checking binary ops
            elif nextOpc in (OpCode.CPUI_FLOAT_FLOAT2FLOAT, OpCode.CPUI_FLOAT_INT2FLOAT):
                if nextOp.getIn(0).getSize() > nextVn.getSize():
                    state.incorporateInputSize(nextVn.getSize())
                else:
                    state.incorporateInputSize(nextOp.getIn(0).getSize())
            else:
                state.incorporateInputSize(nextVn.getSize())
        return mx

    def exceedsPrecision(self, op) -> bool:
        """Check if both inputs exceed the established precision."""
        val1 = self.maxPrecision(op.getIn(0))
        val2 = self.maxPrecision(op.getIn(1))
        mn = min(val1, val2)
        return mn > self.precision

    def setReplacement(self, vn):
        """Create and return a placeholder for the given Varnode."""
        if vn.isMark():
            return self.getPiece(vn, self.precision * 8, 0)
        if vn.isConstant():
            form2 = None
            arch = self.getFunction().getArch() if hasattr(self.getFunction(), 'getArch') else None
            translate = arch.translate if arch is not None and hasattr(arch, 'translate') else None
            if translate is not None and hasattr(translate, 'getFloatFormat'):
                form2 = translate.getFloatFormat(vn.getSize())
            if form2 is None:
                return None
            converted = self.format.convertEncoding(vn.getOffset(), form2) if hasattr(self.format, 'convertEncoding') else vn.getOffset()
            return self.newConstant(self.precision, 0, converted)
        if vn.isFree():
            return None
        if vn.isAddrForce() and vn.getSize() != self.precision:
            return None
        from ghidra.types.datatype import TYPE_PARTIALSTRUCT
        if vn.isTypeLock() and vn.getType().getMetatype() != TYPE_PARTIALSTRUCT:
            sz = vn.getType().getSize()
            if sz != self.precision:
                return None
        if vn.isInput():
            if vn.getSize() != self.precision:
                return None
        vn.setMark()
        if vn.getSize() == self.precision:
            res = self.newPreexistingVarnode(vn)
        else:
            res = self.newPiece(vn, self.precision * 8, 0)
            self.worklist.append(res)
        return res

    def traceForward(self, rvn) -> bool:
        """Trace logical value forward through descendant ops."""
        vn = rvn.getOriginal()
        for op in list(vn.beginDescend()):
            outvn = op.getOut()
            if outvn is not None and outvn.isMark():
                continue
            opc = op.code()
            _FLOAT_BINARY = (OpCode.CPUI_FLOAT_ADD, OpCode.CPUI_FLOAT_SUB,
                             OpCode.CPUI_FLOAT_MULT, OpCode.CPUI_FLOAT_DIV)
            _FLOAT_UNARY = (OpCode.CPUI_MULTIEQUAL, OpCode.CPUI_COPY,
                            OpCode.CPUI_FLOAT_CEIL, OpCode.CPUI_FLOAT_FLOOR,
                            OpCode.CPUI_FLOAT_ROUND, OpCode.CPUI_FLOAT_NEG,
                            OpCode.CPUI_FLOAT_ABS, OpCode.CPUI_FLOAT_SQRT)
            if opc in _FLOAT_BINARY:
                if self.exceedsPrecision(op):
                    return False
                # fall through to unary handling
                rop = self.newOpReplace(op.numInput(), opc, op)
                outrvn = self.setReplacement(outvn)
                if outrvn is None:
                    return False
                self.opSetInput(rop, rvn, op.getSlot(vn))
                self.opSetOutput(rop, outrvn)
            elif opc in _FLOAT_UNARY:
                rop = self.newOpReplace(op.numInput(), opc, op)
                outrvn = self.setReplacement(outvn)
                if outrvn is None:
                    return False
                self.opSetInput(rop, rvn, op.getSlot(vn))
                self.opSetOutput(rop, outrvn)
            elif opc == OpCode.CPUI_FLOAT_FLOAT2FLOAT:
                if outvn.getSize() < self.precision:
                    return False
                newOpc = OpCode.CPUI_COPY if outvn.getSize() == self.precision else OpCode.CPUI_FLOAT_FLOAT2FLOAT
                rop = self.newPreexistingOp(1, newOpc, op)
                self.opSetInput(rop, rvn, 0)
                self.terminatorCount += 1
            elif opc in (OpCode.CPUI_FLOAT_EQUAL, OpCode.CPUI_FLOAT_NOTEQUAL,
                         OpCode.CPUI_FLOAT_LESS, OpCode.CPUI_FLOAT_LESSEQUAL):
                if self.exceedsPrecision(op):
                    return False
                slot = op.getSlot(vn)
                rvn2 = self.setReplacement(op.getIn(1 - slot))
                if rvn2 is None:
                    return False
                if rvn is rvn2:
                    slot = op.getRepeatSlot(vn, slot, None) if hasattr(op, 'getRepeatSlot') else slot
                if self.preexistingGuard(slot, rvn2):
                    rop = self.newPreexistingOp(2, opc, op)
                    self.opSetInput(rop, rvn, slot)
                    self.opSetInput(rop, rvn2, 1 - slot)
                    self.terminatorCount += 1
            elif opc in (OpCode.CPUI_FLOAT_TRUNC, OpCode.CPUI_FLOAT_NAN):
                rop = self.newPreexistingOp(1, opc, op)
                self.opSetInput(rop, rvn, 0)
                self.terminatorCount += 1
            else:
                return False
        return True

    def traceBackward(self, rvn) -> bool:
        """Trace logical value backward through defining op."""
        op = rvn.getOriginal().getDef()
        if op is None:
            return True  # vn is input
        opc = op.code()
        _FLOAT_BINARY = (OpCode.CPUI_FLOAT_ADD, OpCode.CPUI_FLOAT_SUB,
                         OpCode.CPUI_FLOAT_MULT, OpCode.CPUI_FLOAT_DIV)
        _FLOAT_UNARY = (OpCode.CPUI_COPY, OpCode.CPUI_FLOAT_CEIL, OpCode.CPUI_FLOAT_FLOOR,
                        OpCode.CPUI_FLOAT_ROUND, OpCode.CPUI_FLOAT_NEG, OpCode.CPUI_FLOAT_ABS,
                        OpCode.CPUI_FLOAT_SQRT, OpCode.CPUI_MULTIEQUAL)
        if opc in _FLOAT_BINARY:
            if self.exceedsPrecision(op):
                return False
            # fall through
        if opc in _FLOAT_BINARY or opc in _FLOAT_UNARY:
            rop = rvn.defOp
            if rop is None:
                rop = self.newOpReplace(op.numInput(), opc, op)
                self.opSetOutput(rop, rvn)
            for i in range(op.numInput()):
                newvar = rop.input[i] if i < len(rop.input) else None
                if newvar is None:
                    newvar = self.setReplacement(op.getIn(i))
                    if newvar is None:
                        return False
                    self.opSetInput(rop, newvar, i)
            return True
        elif opc == OpCode.CPUI_FLOAT_INT2FLOAT:
            invn = op.getIn(0)
            if not invn.isConstant() and invn.isFree():
                return False
            rop = self.newOpReplace(1, OpCode.CPUI_FLOAT_INT2FLOAT, op)
            self.opSetOutput(rop, rvn)
            newvar = self.getPreexistingVarnode(invn)
            self.opSetInput(rop, newvar, 0)
            return True
        elif opc == OpCode.CPUI_FLOAT_FLOAT2FLOAT:
            invn = op.getIn(0)
            if invn.isConstant():
                newOpc = OpCode.CPUI_COPY
                if invn.getSize() == self.precision:
                    newvar = self.newConstant(self.precision, 0, invn.getOffset())
                else:
                    newvar = self.setReplacement(invn)
                    if newvar is None:
                        return False
            else:
                if invn.isFree():
                    return False
                newOpc = OpCode.CPUI_COPY if invn.getSize() == self.precision else OpCode.CPUI_FLOAT_FLOAT2FLOAT
                newvar = self.getPreexistingVarnode(invn)
            rop = self.newOpReplace(1, newOpc, op)
            self.opSetOutput(rop, rvn)
            self.opSetInput(rop, newvar, 0)
            return True
        return False

    def processNextWork(self) -> bool:
        rvn = self.worklist.pop()
        if not self.traceBackward(rvn):
            return False
        return self.traceForward(rvn)

    def doTrace(self) -> bool:
        """Trace logical value as far as possible."""
        if self.format is None:
            return False
        self.terminatorCount = 0
        retval = True
        while self.worklist:
            if not self.processNextWork():
                retval = False
                break
        self.clearVarnodeMarks()
        if not retval:
            return False
        if self.terminatorCount == 0:
            return False
        return True


class SplitDatatype:
    """Split a p-code COPY, LOAD, or STORE op based on underlying composite data-type.

    During cleanup, if a COPY/LOAD/STORE occurs on a partial structure or array,
    try to break it up into multiple operations on logical components.

    C++ ref: SplitDatatype in subflow.cc
    """

    class Component:
        """A pair of matching data-types for the split."""
        __slots__ = ('inType', 'outType', 'offset')

        def __init__(self, inT, outT, off: int) -> None:
            self.inType = inT
            self.outType = outT
            self.offset: int = off

    class RootPointer:
        """Helper describing the pointer being passed to a LOAD or STORE."""
        __slots__ = ('loadStore', 'ptrType', 'firstPointer', 'pointer', 'baseOffset')

        def __init__(self) -> None:
            self.loadStore = None
            self.ptrType = None
            self.firstPointer = None
            self.pointer = None
            self.baseOffset: int = 0

        def backUpPointer(self, impliedBase) -> bool:
            if not self.pointer.isWritten():
                return False
            addOp = self.pointer.getDef()
            opc = addOp.code()
            if opc in (OpCode.CPUI_PTRSUB, OpCode.CPUI_INT_ADD, OpCode.CPUI_PTRADD):
                cvn = addOp.getIn(1)
                if not cvn.isConstant():
                    return False
                off = int(cvn.getOffset())
            elif opc == OpCode.CPUI_COPY:
                off = 0
            else:
                return False
            tmpPointer = addOp.getIn(0)
            ct = tmpPointer.getTypeReadFacing(addOp) if hasattr(tmpPointer, 'getTypeReadFacing') else None
            if ct is None:
                return False
            from ghidra.types.datatype import TYPE_PTR, TYPE_STRUCT, TYPE_ARRAY
            if ct.getMetatype() != TYPE_PTR:
                return False
            parent = ct.getPtrTo() if hasattr(ct, 'getPtrTo') else None
            if parent is None:
                return False
            meta = parent.getMetatype()
            if meta != TYPE_STRUCT and meta != TYPE_ARRAY:
                if (opc != OpCode.CPUI_PTRADD and opc != OpCode.CPUI_COPY) or parent is not impliedBase:
                    return False
            self.ptrType = ct
            if opc == OpCode.CPUI_PTRADD:
                off *= int(addOp.getIn(2).getOffset())
            wordSize = self.ptrType.getWordSize() if hasattr(self.ptrType, 'getWordSize') else 1
            if wordSize > 1:
                off *= wordSize
            self.baseOffset += off
            self.pointer = tmpPointer
            return True

        def find(self, op, valueType) -> bool:
            from ghidra.types.datatype import TYPE_PTR, TYPE_PARTIALSTRUCT, TYPE_ARRAY
            impliedBase = None
            if hasattr(valueType, 'getMetatype') and valueType.getMetatype() == TYPE_PARTIALSTRUCT:
                if hasattr(valueType, 'getParent'):
                    valueType = valueType.getParent()
            if hasattr(valueType, 'getMetatype') and valueType.getMetatype() == TYPE_ARRAY:
                if hasattr(valueType, 'getBase'):
                    valueType = valueType.getBase()
                impliedBase = valueType
            self.loadStore = op
            self.baseOffset = 0
            self.firstPointer = op.getIn(1)
            self.pointer = self.firstPointer
            ct = self.pointer.getTypeReadFacing(op) if hasattr(self.pointer, 'getTypeReadFacing') else None
            if ct is None:
                return False
            if ct.getMetatype() != TYPE_PTR:
                return False
            self.ptrType = ct
            ptrTo = ct.getPtrTo() if hasattr(ct, 'getPtrTo') else None
            if ptrTo is not valueType:
                if impliedBase is not None:
                    return False
                if not self.backUpPointer(impliedBase):
                    return False
                ptrTo2 = self.ptrType.getPtrTo() if hasattr(self.ptrType, 'getPtrTo') else None
                if ptrTo2 is not valueType:
                    return False
            for _ in range(3):
                if self.pointer.isAddrTied() or self.pointer.loneDescend() is None:
                    break
                if not self.backUpPointer(impliedBase):
                    break
            return True

        def duplicateToTemp(self, data, followOp) -> None:
            if hasattr(data, 'buildCopyTemp'):
                newRoot = data.buildCopyTemp(self.pointer, followOp)
                if self.ptrType is not None and hasattr(newRoot, 'updateType'):
                    newRoot.updateType(self.ptrType)
                self.pointer = newRoot

        def freePointerChain(self, data) -> None:
            while (self.firstPointer is not self.pointer and
                   not self.firstPointer.isAddrTied() and
                   self.firstPointer.hasNoDescend()):
                tmpOp = self.firstPointer.getDef()
                self.firstPointer = tmpOp.getIn(0)
                data.opDestroy(tmpOp)

    def __init__(self, fd) -> None:
        self._fd = fd
        arch = fd.getArch() if hasattr(fd, 'getArch') else None
        self._types = arch.types if arch is not None and hasattr(arch, 'types') else None
        self._dataTypePieces: list = []
        splitConfig = getattr(arch, 'split_datatype_config', 3) if arch is not None else 3
        self._splitStructures: bool = (splitConfig & 1) != 0
        self._splitArrays: bool = (splitConfig & 2) != 0
        self._isLoadStore: bool = False

    # -- Helper methods --

    def _getComponent(self, ct, offset: int):
        """Get component data-type at offset, return (datatype, isHole) or (None, False)."""
        if ct is None:
            return None, False
        curType = ct
        curOff = offset
        while True:
            if not hasattr(curType, 'getSubType'):
                return None, False
            result = curType.getSubType(curOff)
            if result is None:
                hole = ct.getHoleSize(offset) if hasattr(ct, 'getHoleSize') else 0
                if hole > 0:
                    if hole > 8:
                        hole = 8
                    from ghidra.types.datatype import TYPE_UNKNOWN
                    return self._types.getBase(hole, TYPE_UNKNOWN) if self._types else None, True
                return None, False
            if isinstance(result, tuple):
                curType, curOff = result
            else:
                curType = result
                curOff = 0
            if curOff == 0:
                from ghidra.types.datatype import TYPE_ARRAY
                if curType.getMetatype() != TYPE_ARRAY:
                    break
        return curType, False

    def _categorizeDatatype(self, ct) -> int:
        """Categorize: -1=not splittable, 0=struct, 1=array, 2=primitive."""
        if ct is None:
            return -1
        from ghidra.types.datatype import (TYPE_ARRAY, TYPE_PARTIALSTRUCT, TYPE_STRUCT,
                                           TYPE_INT, TYPE_UINT, TYPE_UNKNOWN)
        meta = ct.getMetatype()
        if meta == TYPE_ARRAY:
            if not self._splitArrays:
                return -1
            subType = ct.getBase() if hasattr(ct, 'getBase') else None
            if subType is not None and (subType.getMetatype() != TYPE_UNKNOWN or subType.getSize() != 1):
                return 1
            return 2
        elif meta == TYPE_PARTIALSTRUCT:
            parent = ct.getParent() if hasattr(ct, 'getParent') else None
            if parent is not None:
                pmeta = parent.getMetatype()
                if pmeta == TYPE_ARRAY:
                    if not self._splitArrays:
                        return -1
                    subType = parent.getBase() if hasattr(parent, 'getBase') else None
                    if subType is not None and (subType.getMetatype() != TYPE_UNKNOWN or subType.getSize() != 1):
                        return 1
                    return 2
                elif pmeta == TYPE_STRUCT:
                    if not self._splitStructures:
                        return -1
                    return 0
            return -1
        elif meta == TYPE_STRUCT:
            if not self._splitStructures:
                return -1
            if hasattr(ct, 'numDepend') and ct.numDepend() > 1:
                return 0
            return -1
        elif meta in (TYPE_INT, TYPE_UINT, TYPE_UNKNOWN):
            return 2
        return -1

    def _testDatatypeCompatibility(self, inBase, outBase, inConstant: bool) -> bool:
        """Test if in/out data-types can be mutually split into matching components."""
        inCategory = self._categorizeDatatype(inBase)
        if inCategory < 0:
            return False
        outCategory = self._categorizeDatatype(outBase)
        if outCategory < 0:
            return False
        if outCategory == 2 and inCategory == 2:
            return False
        from ghidra.types.datatype import TYPE_STRUCT
        if not inConstant and inBase is outBase and inBase.getMetatype() == TYPE_STRUCT:
            return False
        if self._isLoadStore and outCategory == 2 and inCategory == 1:
            return False
        if self._isLoadStore and inCategory == 2 and not inConstant and outCategory == 1:
            return False
        if self._isLoadStore and inCategory == 1 and outCategory == 1 and not inConstant:
            return False
        from ghidra.types.datatype import TYPE_UNKNOWN
        self._dataTypePieces.clear()
        sizeLeft = inBase.getSize()
        curOff = 0
        if inCategory == 2:  # Input is primitive
            while sizeLeft > 0:
                curOut, outHole = self._getComponent(outBase, curOff)
                if curOut is None:
                    return False
                curIn = curOut if inConstant else (self._types.getBase(curOut.getSize(), TYPE_UNKNOWN) if self._types else None)
                if curIn is None:
                    return False
                self._dataTypePieces.append(SplitDatatype.Component(curIn, curOut, curOff))
                sizeLeft -= curOut.getSize()
                curOff += curOut.getSize()
                if outHole:
                    if len(self._dataTypePieces) == 1:
                        return False
                    if sizeLeft == 0 and len(self._dataTypePieces) == 2:
                        return False
        elif outCategory == 2:  # Output is primitive
            while sizeLeft > 0:
                curIn, inHole = self._getComponent(inBase, curOff)
                if curIn is None:
                    return False
                curOut = self._types.getBase(curIn.getSize(), TYPE_UNKNOWN) if self._types else None
                if curOut is None:
                    return False
                self._dataTypePieces.append(SplitDatatype.Component(curIn, curOut, curOff))
                sizeLeft -= curIn.getSize()
                curOff += curIn.getSize()
                if inHole:
                    if len(self._dataTypePieces) == 1:
                        return False
                    if sizeLeft == 0 and len(self._dataTypePieces) == 2:
                        return False
        else:  # Both have components
            while sizeLeft > 0:
                curIn, inHole = self._getComponent(inBase, curOff)
                if curIn is None:
                    return False
                curOut, outHole = self._getComponent(outBase, curOff)
                if curOut is None:
                    return False
                while curIn.getSize() != curOut.getSize():
                    if curIn.getSize() > curOut.getSize():
                        if inHole:
                            curIn = self._types.getBase(curOut.getSize(), TYPE_UNKNOWN) if self._types else None
                        else:
                            curIn, inHole = self._getComponent(curIn, 0)
                        if curIn is None:
                            return False
                    else:
                        if outHole:
                            curOut = self._types.getBase(curIn.getSize(), TYPE_UNKNOWN) if self._types else None
                        else:
                            curOut, outHole = self._getComponent(curOut, 0)
                        if curOut is None:
                            return False
                self._dataTypePieces.append(SplitDatatype.Component(curIn, curOut, curOff))
                sizeLeft -= curIn.getSize()
                curOff += curIn.getSize()
        return len(self._dataTypePieces) > 1

    @staticmethod
    def _testCopyConstraints(copyOp) -> bool:
        """Check specific constraints for splitting COPY."""
        inVn = copyOp.getIn(0)
        if inVn.isInput():
            return False
        if inVn.isAddrTied():
            outVn = copyOp.getOut()
            if outVn.isAddrTied() and outVn.getAddr() == inVn.getAddr():
                return False
        elif inVn.isWritten() and inVn.getDef().code() == OpCode.CPUI_LOAD:
            if inVn.loneDescend() == copyOp:
                return False
        return True

    @staticmethod
    def _isArithmeticInput(vn) -> bool:
        """Check if any descendant is arithmetic."""
        for op in vn.beginDescend():
            if hasattr(op, 'getOpcode') and hasattr(op.getOpcode(), 'isArithmeticOp'):
                if op.getOpcode().isArithmeticOp():
                    return True
        return False

    @staticmethod
    def _isArithmeticOutput(vn) -> bool:
        """Check if defining op is arithmetic."""
        if not vn.isWritten():
            return False
        defOp = vn.getDef()
        if hasattr(defOp, 'getOpcode') and hasattr(defOp.getOpcode(), 'isArithmeticOp'):
            return defOp.getOpcode().isArithmeticOp()
        return False

    def _generateConstants(self, vn, inVarnodes: list) -> bool:
        """If vn is an extended precision constant (ZEXT(c) or CONCAT(c1,c2)), split into pieces."""
        if vn.loneDescend() is None:
            return False
        if not vn.isWritten():
            return False
        op = vn.getDef()
        opc = op.code()
        if opc == OpCode.CPUI_INT_ZEXT:
            if not op.getIn(0).isConstant():
                return False
        elif opc == OpCode.CPUI_PIECE:
            if not op.getIn(0).isConstant() or not op.getIn(1).isConstant():
                return False
        else:
            return False
        fullsize = vn.getSize()
        isBigEndian = vn.getSpace().isBigEndian() if hasattr(vn.getSpace(), 'isBigEndian') else False
        if opc == OpCode.CPUI_INT_ZEXT:
            hi = 0
            lo = op.getIn(0).getOffset()
            losize = op.getIn(0).getSize()
        else:
            hi = op.getIn(0).getOffset()
            lo = op.getIn(1).getOffset()
            losize = op.getIn(1).getSize()
        for i in range(len(self._dataTypePieces)):
            dt = self._dataTypePieces[i].inType
            if dt.getSize() > 8:
                inVarnodes.clear()
                return False
            if isBigEndian:
                sa = fullsize - (self._dataTypePieces[i].offset + dt.getSize())
            else:
                sa = self._dataTypePieces[i].offset
            if sa >= losize:
                val = hi >> ((sa - losize) * 8)
            else:
                val = lo >> (sa * 8)
                if sa + dt.getSize() > losize:
                    val |= hi << ((losize - sa) * 8)
            val &= calc_mask(dt.getSize())
            outVn = self._fd.newConstant(dt.getSize(), val)
            inVarnodes.append(outVn)
            if hasattr(outVn, 'updateType'):
                outVn.updateType(dt)
        self._fd.opDestroy(op)
        return True

    def _buildInConstants(self, rootVn, inVarnodes: list, bigEndian: bool) -> None:
        """Build constant input Varnodes from root constant."""
        baseVal = rootVn.getOffset()
        for piece in self._dataTypePieces:
            dt = piece.inType
            off = piece.offset
            if bigEndian:
                off = rootVn.getSize() - off - dt.getSize()
            val = (baseVal >> (8 * off)) & calc_mask(dt.getSize())
            outVn = self._fd.newConstant(dt.getSize(), val)
            inVarnodes.append(outVn)
            if hasattr(outVn, 'updateType'):
                outVn.updateType(dt)

    def _buildInSubpieces(self, rootVn, followOp, inVarnodes: list) -> None:
        """Build input Varnodes by extracting SUBPIECEs from the root."""
        if self._generateConstants(rootVn, inVarnodes):
            return
        baseAddr = rootVn.getAddr()
        for piece in self._dataTypePieces:
            dt = piece.inType
            off = piece.offset
            addr = baseAddr + off
            if hasattr(addr, 'renormalize'):
                addr.renormalize(dt.getSize())
            truncOff = off
            if hasattr(addr, 'isBigEndian') and addr.isBigEndian():
                truncOff = rootVn.getSize() - off - dt.getSize()
            subpiece = self._fd.newOp(2, followOp.getAddr())
            self._fd.opSetOpcode(subpiece, OpCode.CPUI_SUBPIECE)
            self._fd.opSetInput(subpiece, rootVn, 0)
            self._fd.opSetInput(subpiece, self._fd.newConstant(4, truncOff), 1)
            outVn = self._fd.newVarnodeOut(dt.getSize(), addr, subpiece)
            inVarnodes.append(outVn)
            if hasattr(outVn, 'updateType'):
                outVn.updateType(dt)
            self._fd.opInsertBefore(subpiece, followOp)

    def _buildOutVarnodes(self, rootVn, outVarnodes: list) -> None:
        """Build output Varnodes with storage based on the given root."""
        baseAddr = rootVn.getAddr()
        for piece in self._dataTypePieces:
            dt = piece.outType
            off = piece.offset
            addr = baseAddr + off
            if hasattr(addr, 'renormalize'):
                addr.renormalize(dt.getSize())
            outVn = self._fd.newVarnode(dt.getSize(), addr, dt)
            outVarnodes.append(outVn)

    def _buildOutConcats(self, rootVn, previousOp, outVarnodes: list) -> None:
        """Concatenate output Varnodes into root Varnode."""
        if rootVn.hasNoDescend():
            return
        baseAddr = rootVn.getAddr()
        addressTied = rootVn.isAddrTied()
        for ov in outVarnodes:
            if not addressTied and hasattr(ov, 'setProtoPartial'):
                ov.setProtoPartial()
        isBigEndian = hasattr(baseAddr, 'isBigEndian') and baseAddr.isBigEndian()
        preOp = previousOp
        concatOp = None
        if isBigEndian:
            vn = outVarnodes[0]
            for i in range(1, len(outVarnodes)):
                concatOp = self._fd.newOp(2, previousOp.getAddr())
                self._fd.opSetOpcode(concatOp, OpCode.CPUI_PIECE)
                self._fd.opSetInput(concatOp, vn, 0)
                self._fd.opSetInput(concatOp, outVarnodes[i], 1)
                self._fd.opInsertAfter(concatOp, preOp)
                if i + 1 >= len(outVarnodes):
                    break
                preOp = concatOp
                sz = vn.getSize() + outVarnodes[i].getSize()
                addr = baseAddr
                if hasattr(addr, 'renormalize'):
                    addr.renormalize(sz)
                vn = self._fd.newVarnodeOut(sz, addr, concatOp)
                if not addressTied and hasattr(vn, 'setProtoPartial'):
                    vn.setProtoPartial()
        else:
            vn = outVarnodes[-1]
            for i in range(len(outVarnodes) - 2, -1, -1):
                concatOp = self._fd.newOp(2, previousOp.getAddr())
                self._fd.opSetOpcode(concatOp, OpCode.CPUI_PIECE)
                self._fd.opSetInput(concatOp, vn, 0)
                self._fd.opSetInput(concatOp, outVarnodes[i], 1)
                self._fd.opInsertAfter(concatOp, preOp)
                if i <= 0:
                    break
                preOp = concatOp
                sz = vn.getSize() + outVarnodes[i].getSize()
                addr = outVarnodes[i].getAddr()
                if hasattr(addr, 'renormalize'):
                    addr.renormalize(sz)
                vn = self._fd.newVarnodeOut(sz, addr, concatOp)
                if not addressTied and hasattr(vn, 'setProtoPartial'):
                    vn.setProtoPartial()
        if concatOp is not None:
            if hasattr(concatOp, 'setPartialRoot'):
                concatOp.setPartialRoot()
            self._fd.opSetOutput(concatOp, rootVn)
            if not addressTied and hasattr(self._fd, 'getMerge'):
                self._fd.getMerge().registerProtoPartialRoot(rootVn)

    def _buildPointers(self, rootVn, ptrType, baseOffset: int, followOp,
                       ptrVarnodes: list, isInput: bool) -> None:
        """Build a series of PTRSUB/PTRADD ops at different offsets."""
        baseType = ptrType.getPtrTo() if hasattr(ptrType, 'getPtrTo') else None
        if baseType is None:
            return
        for piece in self._dataTypePieces:
            matchType = piece.inType if isInput else piece.outType
            curOff = baseOffset + piece.offset
            tmpType = baseType
            inPtr = rootVn
            while tmpType.getSize() > matchType.getSize():
                if curOff < 0 or curOff >= tmpType.getSize():
                    newType = tmpType
                    newOff = curOff % tmpType.getSize()
                    if newOff < 0:
                        newOff += tmpType.getSize()
                else:
                    if hasattr(tmpType, 'getSubType'):
                        result = tmpType.getSubType(curOff)
                        if result is None:
                            newType = matchType
                            newOff = 0
                        elif isinstance(result, tuple):
                            newType, newOff = result
                        else:
                            newType = result
                            newOff = 0
                    else:
                        newType = matchType
                        newOff = 0
                from ghidra.types.datatype import TYPE_ARRAY
                if tmpType is newType or tmpType.getMetatype() == TYPE_ARRAY:
                    finalOffset = curOff - newOff
                    sz = newType.getSize()
                    finalOffset = finalOffset // sz
                    wordSize = ptrType.getWordSize() if hasattr(ptrType, 'getWordSize') else 1
                    if wordSize > 1:
                        sz = sz // wordSize
                    newOp = self._fd.newOp(3, followOp.getAddr())
                    self._fd.opSetOpcode(newOp, OpCode.CPUI_PTRADD)
                    self._fd.opSetInput(newOp, inPtr, 0)
                    indexVn = self._fd.newConstant(inPtr.getSize(), finalOffset)
                    self._fd.opSetInput(newOp, indexVn, 1)
                    self._fd.opSetInput(newOp, self._fd.newConstant(inPtr.getSize(), sz), 2)
                else:
                    wordSize = ptrType.getWordSize() if hasattr(ptrType, 'getWordSize') else 1
                    finalOffset = curOff - newOff
                    if wordSize > 1:
                        finalOffset = finalOffset // wordSize
                    newOp = self._fd.newOp(2, followOp.getAddr())
                    self._fd.opSetOpcode(newOp, OpCode.CPUI_PTRSUB)
                    self._fd.opSetInput(newOp, inPtr, 0)
                    self._fd.opSetInput(newOp, self._fd.newConstant(inPtr.getSize(), finalOffset), 1)
                inPtr = self._fd.newUniqueOut(inPtr.getSize(), newOp)
                if self._types is not None and hasattr(self._types, 'getTypePointerStripArray'):
                    wordSize = ptrType.getWordSize() if hasattr(ptrType, 'getWordSize') else 1
                    tmpPtr = self._types.getTypePointerStripArray(ptrType.getSize(), newType, wordSize)
                    if tmpPtr is not None and hasattr(inPtr, 'updateType'):
                        inPtr.updateType(tmpPtr)
                self._fd.opInsertBefore(newOp, followOp)
                tmpType = newType
                curOff = newOff
            ptrVarnodes.append(inPtr)

    # -- Public methods --

    def splitCopy(self, copyOp, inType, outType) -> bool:
        """Split a COPY operation."""
        if not self._testCopyConstraints(copyOp):
            return False
        inVn = copyOp.getIn(0)
        if not self._testDatatypeCompatibility(inType, outType, inVn.isConstant()):
            return False
        if self._isArithmeticOutput(inVn):
            return False
        outVn = copyOp.getOut()
        if self._isArithmeticInput(outVn):
            return False
        inVarnodes: list = []
        outVarnodes: list = []
        if inVn.isConstant():
            isBigEndian = outVn.getSpace().isBigEndian() if hasattr(outVn.getSpace(), 'isBigEndian') else False
            self._buildInConstants(inVn, inVarnodes, isBigEndian)
        else:
            self._buildInSubpieces(inVn, copyOp, inVarnodes)
        self._buildOutVarnodes(outVn, outVarnodes)
        self._buildOutConcats(outVn, copyOp, outVarnodes)
        for i in range(len(inVarnodes)):
            newCopyOp = self._fd.newOp(1, copyOp.getAddr())
            self._fd.opSetOpcode(newCopyOp, OpCode.CPUI_COPY)
            self._fd.opSetInput(newCopyOp, inVarnodes[i], 0)
            self._fd.opSetOutput(newCopyOp, outVarnodes[i])
            self._fd.opInsertBefore(newCopyOp, copyOp)
        self._fd.opDestroy(copyOp)
        return True

    def splitLoad(self, loadOp, inType) -> bool:
        """Split a LOAD operation."""
        self._isLoadStore = True
        outVn = loadOp.getOut()
        copyOp = None
        if not outVn.isAddrTied():
            copyOp = outVn.loneDescend()
        if copyOp is not None:
            opc = copyOp.code()
            if opc == OpCode.CPUI_STORE:
                return False
            if opc != OpCode.CPUI_COPY:
                copyOp = None
        if copyOp is not None:
            outVn = copyOp.getOut()
        outType = outVn.getTypeDefFacing() if hasattr(outVn, 'getTypeDefFacing') else None
        if outType is None:
            return False
        if not self._testDatatypeCompatibility(inType, outType, False):
            return False
        if self._isArithmeticInput(outVn):
            return False
        root = SplitDatatype.RootPointer()
        if not root.find(loadOp, inType):
            return False
        ptrVarnodes: list = []
        outVarnodes: list = []
        insertPoint = loadOp if copyOp is None else copyOp
        self._buildPointers(root.pointer, root.ptrType, root.baseOffset, loadOp, ptrVarnodes, True)
        self._buildOutVarnodes(outVn, outVarnodes)
        self._buildOutConcats(outVn, insertPoint, outVarnodes)
        spc = loadOp.getIn(0).getSpaceFromConst() if hasattr(loadOp.getIn(0), 'getSpaceFromConst') else None
        for i in range(len(ptrVarnodes)):
            newLoadOp = self._fd.newOp(2, insertPoint.getAddr())
            self._fd.opSetOpcode(newLoadOp, OpCode.CPUI_LOAD)
            if spc is not None and hasattr(self._fd, 'newVarnodeSpace'):
                self._fd.opSetInput(newLoadOp, self._fd.newVarnodeSpace(spc), 0)
            else:
                self._fd.opSetInput(newLoadOp, loadOp.getIn(0), 0)
            self._fd.opSetInput(newLoadOp, ptrVarnodes[i], 1)
            self._fd.opSetOutput(newLoadOp, outVarnodes[i])
            self._fd.opInsertBefore(newLoadOp, insertPoint)
        if copyOp is not None:
            self._fd.opDestroy(copyOp)
        self._fd.opDestroy(loadOp)
        root.freePointerChain(self._fd)
        return True

    def splitStore(self, storeOp, outType) -> bool:
        """Split a STORE operation."""
        self._isLoadStore = True
        inVn = storeOp.getIn(2)
        loadOp = None
        inType = None
        if inVn.isWritten() and inVn.getDef().code() == OpCode.CPUI_LOAD and inVn.loneDescend() == storeOp:
            loadOp = inVn.getDef()
            inType = SplitDatatype.getValueDatatype(loadOp, inVn.getSize(), self._types)
            if inType is None:
                loadOp = None
        if inType is None:
            inType = inVn.getTypeReadFacing(storeOp) if hasattr(inVn, 'getTypeReadFacing') else None
        if inType is None:
            return False
        if not self._testDatatypeCompatibility(inType, outType, inVn.isConstant()):
            if loadOp is not None:
                loadOp = None
                inType = inVn.getTypeReadFacing(storeOp) if hasattr(inVn, 'getTypeReadFacing') else None
                if inType is None:
                    return False
                self._dataTypePieces.clear()
                if not self._testDatatypeCompatibility(inType, outType, inVn.isConstant()):
                    return False
            else:
                return False
        if self._isArithmeticOutput(inVn):
            return False
        storeRoot = SplitDatatype.RootPointer()
        if not storeRoot.find(storeOp, outType):
            return False
        loadRoot = SplitDatatype.RootPointer()
        if loadOp is not None:
            if not loadRoot.find(loadOp, inType):
                return False
        storeSpace = storeOp.getIn(0).getSpaceFromConst() if hasattr(storeOp.getIn(0), 'getSpaceFromConst') else None
        inVarnodes: list = []
        if inVn.isConstant():
            isBigEndian = storeSpace.isBigEndian() if storeSpace is not None and hasattr(storeSpace, 'isBigEndian') else False
            self._buildInConstants(inVn, inVarnodes, isBigEndian)
        elif loadOp is not None:
            loadPtrs: list = []
            self._buildPointers(loadRoot.pointer, loadRoot.ptrType, loadRoot.baseOffset, loadOp, loadPtrs, True)
            loadSpace = loadOp.getIn(0).getSpaceFromConst() if hasattr(loadOp.getIn(0), 'getSpaceFromConst') else None
            for i in range(len(loadPtrs)):
                newLoadOp = self._fd.newOp(2, loadOp.getAddr())
                self._fd.opSetOpcode(newLoadOp, OpCode.CPUI_LOAD)
                if loadSpace is not None and hasattr(self._fd, 'newVarnodeSpace'):
                    self._fd.opSetInput(newLoadOp, self._fd.newVarnodeSpace(loadSpace), 0)
                else:
                    self._fd.opSetInput(newLoadOp, loadOp.getIn(0), 0)
                self._fd.opSetInput(newLoadOp, loadPtrs[i], 1)
                dt = self._dataTypePieces[i].inType
                vnOut = self._fd.newUniqueOut(dt.getSize(), newLoadOp)
                if hasattr(vnOut, 'updateType'):
                    vnOut.updateType(dt)
                inVarnodes.append(vnOut)
                self._fd.opInsertBefore(newLoadOp, loadOp)
        else:
            self._buildInSubpieces(inVn, storeOp, inVarnodes)
        storePtrs: list = []
        if storeRoot.pointer.isAddrTied():
            storeRoot.duplicateToTemp(self._fd, storeOp)
        self._buildPointers(storeRoot.pointer, storeRoot.ptrType, storeRoot.baseOffset, storeOp, storePtrs, False)
        self._fd.opSetInput(storeOp, storePtrs[0], 1)
        self._fd.opSetInput(storeOp, inVarnodes[0], 2)
        lastStore = storeOp
        for i in range(1, len(storePtrs)):
            newStoreOp = self._fd.newOp(3, storeOp.getAddr())
            self._fd.opSetOpcode(newStoreOp, OpCode.CPUI_STORE)
            if storeSpace is not None and hasattr(self._fd, 'newVarnodeSpace'):
                self._fd.opSetInput(newStoreOp, self._fd.newVarnodeSpace(storeSpace), 0)
            else:
                self._fd.opSetInput(newStoreOp, storeOp.getIn(0), 0)
            self._fd.opSetInput(newStoreOp, storePtrs[i], 1)
            self._fd.opSetInput(newStoreOp, inVarnodes[i], 2)
            self._fd.opInsertAfter(newStoreOp, lastStore)
            lastStore = newStoreOp
        if loadOp is not None:
            self._fd.opDestroy(loadOp)
            loadRoot.freePointerChain(self._fd)
        storeRoot.freePointerChain(self._fd)
        return True

    @staticmethod
    def getValueDatatype(loadStore, size: int, tlst):
        """Get the value data-type for a LOAD or STORE."""
        if tlst is None:
            return None
        ptrVn = loadStore.getIn(1)
        ptrType = ptrVn.getTypeReadFacing(loadStore) if hasattr(ptrVn, 'getTypeReadFacing') else None
        if ptrType is None:
            return None
        from ghidra.types.datatype import (TYPE_PTR, TYPE_INT, TYPE_UINT, TYPE_BOOL,
                                           TYPE_FLOAT, TYPE_STRUCT, TYPE_ARRAY)
        if ptrType.getMetatype() != TYPE_PTR:
            return None
        if hasattr(ptrType, 'isPointerRel') and ptrType.isPointerRel():
            resType = ptrType.getParent() if hasattr(ptrType, 'getParent') else None
            baseOffset = ptrType.getByteOffset() if hasattr(ptrType, 'getByteOffset') else 0
        else:
            resType = ptrType.getPtrTo() if hasattr(ptrType, 'getPtrTo') else None
            baseOffset = 0
        if resType is None:
            return None
        metain = resType.getMetatype()
        alignSize = resType.getAlignSize() if hasattr(resType, 'getAlignSize') else resType.getSize()
        if alignSize < size:
            if metain in (TYPE_INT, TYPE_UINT, TYPE_BOOL, TYPE_FLOAT, TYPE_PTR):
                if (size % alignSize) == 0:
                    numEl = size // alignSize
                    if hasattr(tlst, 'getTypeArray'):
                        return tlst.getTypeArray(numEl, resType)
        elif metain in (TYPE_STRUCT, TYPE_ARRAY):
            if hasattr(tlst, 'getExactPiece'):
                return tlst.getExactPiece(resType, baseOffset, size)
        return None


class LaneDivide(TransformManager):
    """Class for splitting data-flow on laned registers.

    From a root Varnode and a description of its lanes, trace data-flow as far as
    possible through the function, propagating each lane. Then using apply(),
    data-flow can be split.
    """

    class _WorkNode:
        __slots__ = ('lanes', 'numLanes', 'skipLanes')
        def __init__(self, lanes, numLanes: int, skipLanes: int):
            self.lanes = lanes
            self.numLanes = numLanes
            self.skipLanes = skipLanes

    def __init__(self, fd, root, desc, allowDowncast: bool = False) -> None:
        super().__init__(fd)
        self._description = desc
        self._allowSubpieceTerminator: bool = allowDowncast
        self._workList: list = []
        self._setReplacement(root, desc.getNumLanes(), 0)

    def _setReplacement(self, vn, numLanes: int, skipLanes: int):
        """Create split placeholders for vn. Returns list of TransformVar or None."""
        if vn.isMark():
            return self.getSplit(vn, self._description, numLanes, skipLanes)
        if vn.isConstant():
            return self.newSplit(vn, self._description, numLanes, skipLanes)
        if vn.isTypeLock():
            tp = vn.getType()
            if hasattr(tp, 'getMetatype'):
                from ghidra.types.datatype import TYPE_ARRAY, TYPE_STRUCT, TYPE_UNION
                meta = tp.getMetatype()
                if meta not in (TYPE_ARRAY,):
                    if meta in (TYPE_STRUCT, TYPE_UNION):
                        return None
                    # meta > TYPE_ARRAY means primitive
                    if meta > TYPE_ARRAY:
                        return None
        vn.setMark()
        res = self.newSplit(vn, self._description, numLanes, skipLanes)
        if not vn.isFree():
            self._workList.append(LaneDivide._WorkNode(res, numLanes, skipLanes))
        return res

    def _buildUnaryOp(self, opc, op, inVars, outVars, numLanes):
        for i in range(numLanes):
            rop = self.newOpReplace(1, opc, op)
            self.opSetOutput(rop, outVars[i])
            self.opSetInput(rop, inVars[i], 0)

    def _buildBinaryOp(self, opc, op, in0Vars, in1Vars, outVars, numLanes):
        for i in range(numLanes):
            rop = self.newOpReplace(2, opc, op)
            self.opSetOutput(rop, outVars[i])
            self.opSetInput(rop, in0Vars[i], 0)
            self.opSetInput(rop, in1Vars[i], 1)

    def _buildPiece(self, op, outVars, numLanes, skipLanes) -> bool:
        highVn = op.getIn(0)
        lowVn = op.getIn(1)
        ok1, highLanes, highSkip = self._description.restriction(numLanes, skipLanes, lowVn.getSize(), highVn.getSize())
        if not ok1:
            return False
        ok2, lowLanes, lowSkip = self._description.restriction(numLanes, skipLanes, 0, lowVn.getSize())
        if not ok2:
            return False
        if highLanes == 1:
            highRvn = self.getPreexistingVarnode(highVn)
            rop = self.newOpReplace(1, OpCode.CPUI_COPY, op)
            self.opSetInput(rop, highRvn, 0)
            self.opSetOutput(rop, outVars[numLanes - 1])
        else:
            highRvn = self._setReplacement(highVn, highLanes, highSkip)
            if highRvn is None:
                return False
            outHighStart = numLanes - highLanes
            for i in range(highLanes):
                rop = self.newOpReplace(1, OpCode.CPUI_COPY, op)
                self.opSetInput(rop, highRvn[i], 0)
                self.opSetOutput(rop, outVars[outHighStart + i])
        if lowLanes == 1:
            lowRvn = self.getPreexistingVarnode(lowVn)
            rop = self.newOpReplace(1, OpCode.CPUI_COPY, op)
            self.opSetInput(rop, lowRvn, 0)
            self.opSetOutput(rop, outVars[0])
        else:
            lowRvn = self._setReplacement(lowVn, lowLanes, lowSkip)
            if lowRvn is None:
                return False
            for i in range(lowLanes):
                rop = self.newOpReplace(1, OpCode.CPUI_COPY, op)
                self.opSetInput(rop, lowRvn[i], 0)
                self.opSetOutput(rop, outVars[i])
        return True

    def _buildMultiequal(self, op, outVars, numLanes, skipLanes) -> bool:
        inVarSets = []
        numInput = op.numInput()
        for i in range(numInput):
            inVn = self._setReplacement(op.getIn(i), numLanes, skipLanes)
            if inVn is None:
                return False
            inVarSets.append(inVn)
        for i in range(numLanes):
            rop = self.newOpReplace(numInput, OpCode.CPUI_MULTIEQUAL, op)
            self.opSetOutput(rop, outVars[i])
            for j in range(numInput):
                self.opSetInput(rop, inVarSets[j][i], j)
        return True

    def _buildIndirect(self, op, outVars, numLanes, skipLanes) -> bool:
        inVn = self._setReplacement(op.getIn(0), numLanes, skipLanes)
        if inVn is None:
            return False
        for i in range(numLanes):
            rop = self.newOpReplace(2, OpCode.CPUI_INDIRECT, op)
            self.opSetOutput(rop, outVars[i])
            self.opSetInput(rop, inVn[i], 0)
            self.opSetInput(rop, self.newIop(op.getIn(1)), 1)
            if hasattr(rop, 'inheritIndirect'):
                rop.inheritIndirect(op)
        return True

    def _buildStore(self, op, numLanes, skipLanes) -> bool:
        inVars = self._setReplacement(op.getIn(2), numLanes, skipLanes)
        if inVars is None:
            return False
        spaceConst = op.getIn(0).getOffset()
        spaceConstSize = op.getIn(0).getSize()
        spc = op.getIn(0).getSpaceFromConst() if hasattr(op.getIn(0), 'getSpaceFromConst') else None
        origPtr = op.getIn(1)
        if origPtr.isFree() and not origPtr.isConstant():
            return False
        basePtr = self.getPreexistingVarnode(origPtr)
        ptrSize = origPtr.getSize()
        isBig = spc.isBigEndian() if spc is not None and hasattr(spc, 'isBigEndian') else False
        bytePos = 0
        for count in range(numLanes):
            i = (numLanes - 1 - count) if isBig else count
            ropStore = self.newOpReplace(3, OpCode.CPUI_STORE, op)
            if bytePos == 0:
                ptrVn = basePtr
            else:
                ptrVn = self.newUnique(ptrSize)
                addOp = self.newOp(2, OpCode.CPUI_INT_ADD, ropStore)
                self.opSetOutput(addOp, ptrVn)
                self.opSetInput(addOp, basePtr, 0)
                self.opSetInput(addOp, self.newConstant(ptrSize, 0, bytePos), 1)
            if spc is not None:
                self.opSetInput(ropStore, self.newSpaceid(spc), 0)
            else:
                self.opSetInput(ropStore, self.newConstant(spaceConstSize, 0, spaceConst), 0)
            self.opSetInput(ropStore, ptrVn, 1)
            self.opSetInput(ropStore, inVars[i], 2)
            bytePos += self._description.getSize(skipLanes + i)
        return True

    def _buildLoad(self, op, outVars, numLanes, skipLanes) -> bool:
        spaceConst = op.getIn(0).getOffset()
        spaceConstSize = op.getIn(0).getSize()
        spc = op.getIn(0).getSpaceFromConst() if hasattr(op.getIn(0), 'getSpaceFromConst') else None
        origPtr = op.getIn(1)
        if origPtr.isFree() and not origPtr.isConstant():
            return False
        basePtr = self.getPreexistingVarnode(origPtr)
        ptrSize = origPtr.getSize()
        isBig = spc.isBigEndian() if spc is not None and hasattr(spc, 'isBigEndian') else False
        bytePos = 0
        for count in range(numLanes):
            ropLoad = self.newOpReplace(2, OpCode.CPUI_LOAD, op)
            i = (numLanes - 1 - count) if isBig else count
            if bytePos == 0:
                ptrVn = basePtr
            else:
                ptrVn = self.newUnique(ptrSize)
                addOp = self.newOp(2, OpCode.CPUI_INT_ADD, ropLoad)
                self.opSetOutput(addOp, ptrVn)
                self.opSetInput(addOp, basePtr, 0)
                self.opSetInput(addOp, self.newConstant(ptrSize, 0, bytePos), 1)
            if spc is not None:
                self.opSetInput(ropLoad, self.newSpaceid(spc), 0)
            else:
                self.opSetInput(ropLoad, self.newConstant(spaceConstSize, 0, spaceConst), 0)
            self.opSetInput(ropLoad, ptrVn, 1)
            self.opSetOutput(ropLoad, outVars[i])
            bytePos += self._description.getSize(skipLanes + i)
        return True

    def _buildRightShift(self, op, outVars, numLanes, skipLanes) -> bool:
        if not op.getIn(1).isConstant():
            return False
        shiftSize = int(op.getIn(1).getOffset())
        if (shiftSize & 7) != 0:
            return False
        shiftSize //= 8
        startPos = shiftSize + self._description.getPosition(skipLanes)
        startLane = self._description.getBoundary(startPos)
        if startLane < 0:
            return False
        srcLane = startLane
        destLane = skipLanes
        while srcLane - skipLanes < numLanes:
            if self._description.getSize(srcLane) != self._description.getSize(destLane):
                return False
            srcLane += 1
            destLane += 1
        inVars = self._setReplacement(op.getIn(0), numLanes, skipLanes)
        if inVars is None:
            return False
        offset = startLane - skipLanes
        self._buildUnaryOp(OpCode.CPUI_COPY, op, inVars[offset:], outVars, numLanes - offset)
        for zeroLane in range(numLanes - offset, numLanes):
            rop = self.newOpReplace(1, OpCode.CPUI_COPY, op)
            self.opSetOutput(rop, outVars[zeroLane])
            self.opSetInput(rop, self.newConstant(self._description.getSize(zeroLane), 0, 0), 0)
        return True

    def _buildLeftShift(self, op, outVars, numLanes, skipLanes) -> bool:
        if not op.getIn(1).isConstant():
            return False
        shiftSize = int(op.getIn(1).getOffset())
        if (shiftSize & 7) != 0:
            return False
        shiftSize //= 8
        startPos = shiftSize + self._description.getPosition(skipLanes)
        startLane = self._description.getBoundary(startPos)
        if startLane < 0:
            return False
        destLane = startLane
        srcLane = skipLanes
        while destLane - skipLanes < numLanes:
            if self._description.getSize(srcLane) != self._description.getSize(destLane):
                return False
            srcLane += 1
            destLane += 1
        inVars = self._setReplacement(op.getIn(0), numLanes, skipLanes)
        if inVars is None:
            return False
        offset = startLane - skipLanes
        for zeroLane in range(offset):
            rop = self.newOpReplace(1, OpCode.CPUI_COPY, op)
            self.opSetOutput(rop, outVars[zeroLane])
            self.opSetInput(rop, self.newConstant(self._description.getSize(zeroLane), 0, 0), 0)
        self._buildUnaryOp(OpCode.CPUI_COPY, op, inVars, outVars[offset:], numLanes - offset)
        return True

    def _buildZext(self, op, outVars, numLanes, skipLanes) -> bool:
        invn = op.getIn(0)
        ok, inLanes, inSkip = self._description.restriction(numLanes, skipLanes, 0, invn.getSize())
        if not ok:
            return False
        if inLanes == 1:
            rop = self.newOpReplace(1, OpCode.CPUI_COPY, op)
            inVar = self.getPreexistingVarnode(invn)
            self.opSetInput(rop, inVar, 0)
            self.opSetOutput(rop, outVars[0])
        else:
            inRvn = self._setReplacement(invn, inLanes, inSkip)
            if inRvn is None:
                return False
            for i in range(inLanes):
                rop = self.newOpReplace(1, OpCode.CPUI_COPY, op)
                self.opSetInput(rop, inRvn[i], 0)
                self.opSetOutput(rop, outVars[i])
        for i in range(numLanes - inLanes):
            rop = self.newOpReplace(1, OpCode.CPUI_COPY, op)
            self.opSetInput(rop, self.newConstant(self._description.getSize(skipLanes + inLanes + i), 0, 0), 0)
            self.opSetOutput(rop, outVars[inLanes + i])
        return True

    def _traceForward(self, rvn, numLanes, skipLanes) -> bool:
        origvn = rvn[0].getOriginal()
        for op in list(origvn.beginDescend()):
            outvn = op.getOut()
            if outvn is not None and outvn.isMark():
                continue
            opc = op.code()
            if opc == OpCode.CPUI_SUBPIECE:
                bytePos = int(op.getIn(1).getOffset())
                ok, outLanes, outSkip = self._description.restriction(numLanes, skipLanes, bytePos, outvn.getSize())
                if not ok:
                    if self._allowSubpieceTerminator:
                        laneIndex = self._description.getBoundary(bytePos)
                        if laneIndex < 0 or laneIndex >= self._description.getNumLanes():
                            return False
                        if self._description.getSize(laneIndex) <= outvn.getSize():
                            return False
                        rop = self.newPreexistingOp(2, OpCode.CPUI_SUBPIECE, op)
                        self.opSetInput(rop, rvn[laneIndex - skipLanes], 0)
                        self.opSetInput(rop, self.newConstant(4, 0, 0), 1)
                    else:
                        return False
                elif outLanes == 1:
                    rop = self.newPreexistingOp(1, OpCode.CPUI_COPY, op)
                    self.opSetInput(rop, rvn[outSkip - skipLanes], 0)
                else:
                    outRvn = self._setReplacement(outvn, outLanes, outSkip)
                    if outRvn is None:
                        return False
            elif opc == OpCode.CPUI_PIECE:
                bytePos = op.getIn(1).getSize() if op.getIn(0) is origvn else 0
                ok, outLanes, outSkip = self._description.extension(numLanes, skipLanes, bytePos, outvn.getSize())
                if not ok:
                    return False
                outRvn = self._setReplacement(outvn, outLanes, outSkip)
                if outRvn is None:
                    return False
            elif opc in (OpCode.CPUI_COPY, OpCode.CPUI_INT_NEGATE, OpCode.CPUI_INT_AND,
                         OpCode.CPUI_INT_OR, OpCode.CPUI_INT_XOR, OpCode.CPUI_MULTIEQUAL,
                         OpCode.CPUI_INDIRECT):
                outRvn = self._setReplacement(outvn, numLanes, skipLanes)
                if outRvn is None:
                    return False
            elif opc == OpCode.CPUI_INT_RIGHT:
                if not op.getIn(1).isConstant():
                    return False
                outRvn = self._setReplacement(outvn, numLanes, skipLanes)
                if outRvn is None:
                    return False
            elif opc == OpCode.CPUI_STORE:
                if op.getIn(2) is not origvn:
                    return False
                if not self._buildStore(op, numLanes, skipLanes):
                    return False
            else:
                return False
        return True

    def _traceBackward(self, rvn, numLanes, skipLanes) -> bool:
        op = rvn[0].getOriginal().getDef()
        if op is None:
            return True
        opc = op.code()
        if opc in (OpCode.CPUI_INT_NEGATE, OpCode.CPUI_COPY):
            inVars = self._setReplacement(op.getIn(0), numLanes, skipLanes)
            if inVars is None:
                return False
            self._buildUnaryOp(opc, op, inVars, rvn, numLanes)
        elif opc in (OpCode.CPUI_INT_AND, OpCode.CPUI_INT_OR, OpCode.CPUI_INT_XOR):
            in0Vars = self._setReplacement(op.getIn(0), numLanes, skipLanes)
            if in0Vars is None:
                return False
            in1Vars = self._setReplacement(op.getIn(1), numLanes, skipLanes)
            if in1Vars is None:
                return False
            self._buildBinaryOp(opc, op, in0Vars, in1Vars, rvn, numLanes)
        elif opc == OpCode.CPUI_MULTIEQUAL:
            if not self._buildMultiequal(op, rvn, numLanes, skipLanes):
                return False
        elif opc == OpCode.CPUI_INDIRECT:
            if not self._buildIndirect(op, rvn, numLanes, skipLanes):
                return False
        elif opc == OpCode.CPUI_SUBPIECE:
            inVn = op.getIn(0)
            bytePos = int(op.getIn(1).getOffset())
            ok, inLanes, inSkip = self._description.extension(numLanes, skipLanes, bytePos, inVn.getSize())
            if not ok:
                return False
            inVars = self._setReplacement(inVn, inLanes, inSkip)
            if inVars is None:
                return False
            self._buildUnaryOp(OpCode.CPUI_COPY, op, inVars[skipLanes - inSkip:], rvn, numLanes)
        elif opc == OpCode.CPUI_PIECE:
            if not self._buildPiece(op, rvn, numLanes, skipLanes):
                return False
        elif opc == OpCode.CPUI_LOAD:
            if not self._buildLoad(op, rvn, numLanes, skipLanes):
                return False
        elif opc == OpCode.CPUI_INT_RIGHT:
            if not self._buildRightShift(op, rvn, numLanes, skipLanes):
                return False
        elif opc == OpCode.CPUI_INT_LEFT:
            if not self._buildLeftShift(op, rvn, numLanes, skipLanes):
                return False
        elif opc == OpCode.CPUI_INT_ZEXT:
            if not self._buildZext(op, rvn, numLanes, skipLanes):
                return False
        else:
            return False
        return True

    def _processNextWork(self) -> bool:
        wn = self._workList.pop()
        if not self._traceBackward(wn.lanes, wn.numLanes, wn.skipLanes):
            return False
        return self._traceForward(wn.lanes, wn.numLanes, wn.skipLanes)

    def doTrace(self) -> bool:
        """Trace lanes as far as possible from the root Varnode."""
        if not self._workList:
            return False
        retval = True
        while self._workList:
            if not self._processNextWork():
                retval = False
                break
        self.clearVarnodeMarks()
        return retval


# =========================================================================
# Rule subclasses for subvariable/split analysis
# =========================================================================

class RuleSubvarAnd:
    """Perform SubVariableFlow analysis triggered by INT_AND."""
    def __init__(self, group: str = ''):
        self._group = group
        self._name = 'subvar_and'

    def getName(self) -> str:
        return self._name

    def getGroup(self) -> str:
        return self._group

    def clone(self, grouplist=None):
        return RuleSubvarAnd(self._group)

    def getOpList(self) -> list:
        return [int(OpCode.CPUI_INT_AND)]

    def applyOp(self, op, data) -> int:
        if not op.getIn(1).isConstant():
            return 0
        vn = op.getIn(0)
        outvn = op.getOut()
        if outvn.getConsume() != op.getIn(1).getOffset():
            return 0
        if (outvn.getConsume() & 1) == 0:
            return 0
        if outvn.getConsume() == 1:
            cmask = 1
        else:
            cmask = calc_mask(vn.getSize())
            cmask >>= 8
            while cmask != 0:
                if cmask == outvn.getConsume():
                    break
                cmask >>= 8
        if cmask == 0:
            return 0
        if op.getOut().hasNoDescend():
            return 0
        subflow = SubvariableFlow(data, vn, cmask, False, False, False)
        if not subflow.doTrace():
            return 0
        subflow.doReplacement()
        return 1


class RuleSubvarSubpiece:
    """Perform SubVariableFlow analysis triggered by SUBPIECE."""
    def __init__(self, group: str = ''):
        self._group = group
        self._name = 'subvar_subpiece'

    def getName(self) -> str:
        return self._name

    def getGroup(self) -> str:
        return self._group

    def clone(self, grouplist=None):
        return RuleSubvarSubpiece(self._group)

    def getOpList(self) -> list:
        return [int(OpCode.CPUI_SUBPIECE)]

    def applyOp(self, op, data) -> int:
        vn = op.getIn(0)
        outvn = op.getOut()
        flowsize = outvn.getSize()
        sa = int(op.getIn(1).getOffset())
        if flowsize + sa > 8:  # Mask must fit in uintb precision
            return 0
        mask = calc_mask(flowsize)
        mask <<= 8 * sa
        aggressive = outvn.isPtrFlow() if hasattr(outvn, 'isPtrFlow') else False
        if not aggressive:
            if (vn.getConsume() & mask) != vn.getConsume():
                return 0
            if op.getOut().hasNoDescend():
                return 0
        big = False
        if flowsize >= 8 and vn.isInput():
            if vn.loneDescend() == op:
                big = True
        subflow = SubvariableFlow(data, vn, mask, aggressive, False, big)
        if not subflow.doTrace():
            return 0
        subflow.doReplacement()
        return 1


class RuleSubvarCompZero:
    """Perform SubvariableFlow analysis triggered by testing of a single bit."""
    def __init__(self, group: str = ''):
        self._group = group
        self._name = 'subvar_compzero'

    def getName(self) -> str:
        return self._name

    def getGroup(self) -> str:
        return self._group

    def clone(self, grouplist=None):
        return RuleSubvarCompZero(self._group)

    def getOpList(self) -> list:
        return [int(OpCode.CPUI_INT_EQUAL), int(OpCode.CPUI_INT_NOTEQUAL)]

    def applyOp(self, op, data) -> int:
        if not op.getIn(1).isConstant():
            return 0
        vn = op.getIn(0)
        mask = vn.getNZMask()
        bitnum = leastsigbit_set(mask)
        if bitnum == -1:
            return 0
        if (mask >> bitnum) != 1:
            return 0  # Only one bit active
        constval = op.getIn(1).getOffset()
        if constval != mask and constval != 0:
            return 0
        if op.getOut().hasNoDescend():
            return 0
        # Basic check that the stream is not fully consumed
        if vn.isWritten():
            andop = vn.getDef()
            if andop.numInput() == 0:
                return 0
            vn0 = andop.getIn(0)
            opc = andop.code()
            if opc in (OpCode.CPUI_INT_AND, OpCode.CPUI_INT_OR, OpCode.CPUI_INT_RIGHT):
                if not vn0.isConstant():
                    mask0 = vn0.getConsume() & vn0.getNZMask()
                    wholemask = calc_mask(vn0.getSize()) & mask0
                    if (wholemask & 0xff) == 0xff:
                        return 0
                    if (wholemask & 0xff00) == 0xff00:
                        return 0
        subflow = SubvariableFlow(data, vn, mask, False, False, False)
        if not subflow.doTrace():
            return 0
        subflow.doReplacement()
        return 1


class RuleSubvarShift:
    """Perform SubvariableFlow analysis triggered by INT_RIGHT."""
    def __init__(self, group: str = ''):
        self._group = group
        self._name = 'subvar_shift'

    def getName(self) -> str:
        return self._name

    def getGroup(self) -> str:
        return self._group

    def clone(self, grouplist=None):
        return RuleSubvarShift(self._group)

    def getOpList(self) -> list:
        return [int(OpCode.CPUI_INT_RIGHT)]

    def applyOp(self, op, data) -> int:
        vn = op.getIn(0)
        if vn.getSize() != 1:
            return 0
        if not op.getIn(1).isConstant():
            return 0
        sa = int(op.getIn(1).getOffset())
        mask = vn.getNZMask()
        if (mask >> sa) != 1:
            return 0  # Pulling out a single bit
        mask = ((mask >> sa) << sa) & calc_mask(vn.getSize())
        if op.getOut().hasNoDescend():
            return 0
        subflow = SubvariableFlow(data, vn, mask, False, False, False)
        if not subflow.doTrace():
            return 0
        subflow.doReplacement()
        return 1


class RuleSubvarZext:
    """Perform SubvariableFlow analysis triggered by INT_ZEXT."""
    def __init__(self, group: str = ''):
        self._group = group
        self._name = 'subvar_zext'

    def getName(self) -> str:
        return self._name

    def getGroup(self) -> str:
        return self._group

    def clone(self, grouplist=None):
        return RuleSubvarZext(self._group)

    def getOpList(self) -> list:
        return [int(OpCode.CPUI_INT_ZEXT)]

    def applyOp(self, op, data) -> int:
        vn = op.getOut()
        invn = op.getIn(0)
        mask = calc_mask(invn.getSize())
        aggressive = invn.isPtrFlow() if hasattr(invn, 'isPtrFlow') else False
        subflow = SubvariableFlow(data, vn, mask, aggressive, False, False)
        if not subflow.doTrace():
            return 0
        subflow.doReplacement()
        return 1


class RuleSubvarSext:
    """Perform SubvariableFlow analysis triggered by INT_SEXT."""
    def __init__(self, group: str = ''):
        self._group = group
        self._name = 'subvar_sext'
        self._isaggressive: bool = False

    def getName(self) -> str:
        return self._name

    def getGroup(self) -> str:
        return self._group

    def clone(self, grouplist=None):
        return RuleSubvarSext(self._group)

    def getOpList(self) -> list:
        return [int(OpCode.CPUI_INT_SEXT)]

    def applyOp(self, op, data) -> int:
        vn = op.getOut()
        invn = op.getIn(0)
        mask = calc_mask(invn.getSize())
        subflow = SubvariableFlow(data, vn, mask, self._isaggressive, True, False)
        if not subflow.doTrace():
            return 0
        subflow.doReplacement()
        return 1

    def reset(self, data) -> None:
        arch = data.getArch() if hasattr(data, 'getArch') else None
        self._isaggressive = getattr(arch, 'aggressive_ext_trim', False) if arch is not None else False


class RuleSplitFlow:
    """Try to detect and split artificially joined Varnodes."""
    def __init__(self, group: str = ''):
        self._group = group
        self._name = 'splitflow'

    def getName(self) -> str:
        return self._name

    def getGroup(self) -> str:
        return self._group

    def clone(self, grouplist=None):
        return RuleSplitFlow(self._group)

    def getOpList(self) -> list:
        return [int(OpCode.CPUI_SUBPIECE)]

    def applyOp(self, op, data) -> int:
        loSize = int(op.getIn(1).getOffset())
        if loSize == 0:  # Must not take least significant part
            return 0
        vn = op.getIn(0)
        if not vn.isWritten():
            return 0
        if hasattr(vn, 'isPrecisLo') and (vn.isPrecisLo() or vn.isPrecisHi()):
            return 0
        if op.getOut().getSize() + loSize != vn.getSize():
            return 0  # Must take most significant part
        concatOp = None
        multiOp = vn.getDef()
        while multiOp.code() == OpCode.CPUI_INDIRECT:
            tmpvn = multiOp.getIn(0)
            if not tmpvn.isWritten():
                return 0
            multiOp = tmpvn.getDef()
        if multiOp.code() == OpCode.CPUI_PIECE:
            if vn.getDef() != multiOp:
                concatOp = multiOp
        elif multiOp.code() == OpCode.CPUI_MULTIEQUAL:
            for i in range(multiOp.numInput()):
                invn = multiOp.getIn(i)
                if not invn.isWritten():
                    continue
                tmpOp = invn.getDef()
                if tmpOp.code() == OpCode.CPUI_PIECE:
                    concatOp = tmpOp
                    break
        if concatOp is None:
            return 0
        if concatOp.getIn(1).getSize() != loSize:
            return 0
        splitflow = SplitFlow(data, vn, loSize)
        if not splitflow.doTrace():
            return 0
        if hasattr(splitflow, 'apply'):
            splitflow.apply()
        return 1


class RuleSplitCopy:
    """Split COPY ops based on TypePartialStruct."""
    def __init__(self, group: str = ''):
        self._group = group
        self._name = 'splitcopy'

    def getName(self) -> str:
        return self._name

    def getGroup(self) -> str:
        return self._group

    def clone(self, grouplist=None):
        return RuleSplitCopy(self._group)

    def getOpList(self) -> list:
        return [int(OpCode.CPUI_COPY)]

    def applyOp(self, op, data) -> int:
        invn = op.getIn(0)
        outvn = op.getOut()
        inType = invn.getTypeReadFacing(op) if hasattr(invn, 'getTypeReadFacing') else None
        outType = outvn.getTypeDefFacing() if hasattr(outvn, 'getTypeDefFacing') else None
        if inType is None or outType is None:
            return 0
        metain = inType.getMetatype() if hasattr(inType, 'getMetatype') else -1
        metaout = outType.getMetatype() if hasattr(outType, 'getMetatype') else -1
        from ghidra.types.datatype import TYPE_PARTIALSTRUCT, TYPE_ARRAY, TYPE_STRUCT
        if (metain not in (TYPE_PARTIALSTRUCT, TYPE_ARRAY, TYPE_STRUCT) and
                metaout not in (TYPE_PARTIALSTRUCT, TYPE_ARRAY, TYPE_STRUCT)):
            return 0
        splitter = SplitDatatype(data)
        if splitter.splitCopy(op, inType, outType):
            return 1
        return 0


class RuleSplitLoad:
    """Split LOAD ops based on TypePartialStruct."""
    def __init__(self, group: str = ''):
        self._group = group
        self._name = 'splitload'

    def getName(self) -> str:
        return self._name

    def getGroup(self) -> str:
        return self._group

    def clone(self, grouplist=None):
        return RuleSplitLoad(self._group)

    def getOpList(self) -> list:
        return [int(OpCode.CPUI_LOAD)]

    def applyOp(self, op, data) -> int:
        arch = data.getArch() if hasattr(data, 'getArch') else None
        types = arch.types if arch is not None else None
        if types is None:
            return 0
        inType = SplitDatatype.getValueDatatype(op, op.getOut().getSize(), types)
        if inType is None:
            return 0
        metain = inType.getMetatype() if hasattr(inType, 'getMetatype') else -1
        from ghidra.types.datatype import TYPE_PARTIALSTRUCT, TYPE_ARRAY, TYPE_STRUCT
        if metain not in (TYPE_STRUCT, TYPE_ARRAY, TYPE_PARTIALSTRUCT):
            return 0
        splitter = SplitDatatype(data)
        if splitter.splitLoad(op, inType):
            return 1
        return 0


class RuleSplitStore:
    """Split STORE ops based on TypePartialStruct."""
    def __init__(self, group: str = ''):
        self._group = group
        self._name = 'splitstore'

    def getName(self) -> str:
        return self._name

    def getGroup(self) -> str:
        return self._group

    def clone(self, grouplist=None):
        return RuleSplitStore(self._group)

    def getOpList(self) -> list:
        return [int(OpCode.CPUI_STORE)]

    def applyOp(self, op, data) -> int:
        arch = data.getArch() if hasattr(data, 'getArch') else None
        types = arch.types if arch is not None else None
        if types is None:
            return 0
        outType = SplitDatatype.getValueDatatype(op, op.getIn(2).getSize(), types)
        if outType is None:
            return 0
        metaout = outType.getMetatype() if hasattr(outType, 'getMetatype') else -1
        from ghidra.types.datatype import TYPE_PARTIALSTRUCT, TYPE_ARRAY, TYPE_STRUCT
        if metaout not in (TYPE_STRUCT, TYPE_ARRAY, TYPE_PARTIALSTRUCT):
            return 0
        splitter = SplitDatatype(data)
        if splitter.splitStore(op, outType):
            return 1
        return 0


class RuleDumptyHumpLate:
    """Simplify join and break apart based on data-types."""
    def __init__(self, group: str = ''):
        self._group = group
        self._name = 'dumptyhumplate'

    def getName(self) -> str:
        return self._name

    def getGroup(self) -> str:
        return self._group

    def clone(self, grouplist=None):
        return RuleDumptyHumpLate(self._group)

    def getOpList(self) -> list:
        return [int(OpCode.CPUI_SUBPIECE)]

    def applyOp(self, op, data) -> int:
        vn = op.getIn(0)
        if not vn.isWritten():
            return 0
        pieceOp = vn.getDef()
        if pieceOp.code() != OpCode.CPUI_PIECE:
            return 0
        out = op.getOut()
        outSize = out.getSize()
        trunc = int(op.getIn(1).getOffset())
        while True:
            trialVn = pieceOp.getIn(1)  # Least significant component
            trialTrunc = trunc
            if trunc >= trialVn.getSize():
                trialTrunc -= trialVn.getSize()
                trialVn = pieceOp.getIn(0)  # Most significant component
            if outSize + trialTrunc > trialVn.getSize():
                break  # vn crosses both components
            vn = trialVn
            trunc = trialTrunc
            if vn.getSize() == outSize:
                break
            if not vn.isWritten():
                break
            pieceOp = vn.getDef()
            if pieceOp.code() != OpCode.CPUI_PIECE:
                break
        if vn is op.getIn(0):
            return 0  # Didn't backtrack thru any PIECE
        if vn.isWritten() and vn.getDef().code() == OpCode.CPUI_COPY:
            vn = vn.getDef().getIn(0)
        if outSize != vn.getSize():
            removeOp = op.getIn(0).getDef()
            if op.getIn(1).getOffset() != trunc:
                data.opSetInput(op, data.newConstant(4, trunc), 1)
            data.opSetInput(op, vn, 0)
        elif hasattr(out, 'isAutoLive') and out.isAutoLive():
            removeOp = op.getIn(0).getDef()
            data.opRemoveInput(op, 1)
            data.opSetOpcode(op, OpCode.CPUI_COPY)
            data.opSetInput(op, vn, 0)
        else:
            removeOp = op
            data.totalReplace(out, vn)
        if removeOp.getOut().hasNoDescend() and not (hasattr(removeOp.getOut(), 'isAutoLive') and removeOp.getOut().isAutoLive()):
            if hasattr(data, 'opDestroyRecursive'):
                data.opDestroyRecursive(removeOp, [])
            else:
                data.opDestroy(removeOp)
        return 1


class RuleSubfloatConvert:
    """Perform SubfloatFlow analysis triggered by FLOAT_FLOAT2FLOAT."""
    def __init__(self, group: str = ''):
        self._group = group
        self._name = 'subfloat_convert'

    def getName(self) -> str:
        return self._name

    def getGroup(self) -> str:
        return self._group

    def clone(self, grouplist=None):
        return RuleSubfloatConvert(self._group)

    def getOpList(self) -> list:
        return [int(OpCode.CPUI_FLOAT_FLOAT2FLOAT)]

    def applyOp(self, op, data) -> int:
        invn = op.getIn(0)
        outvn = op.getOut()
        insize = invn.getSize()
        outsize = outvn.getSize()
        if outsize > insize:
            subflow = SubfloatFlow(data, outvn, insize)
            if not subflow.doTrace():
                return 0
            if hasattr(subflow, 'apply'):
                subflow.apply()
        else:
            subflow = SubfloatFlow(data, invn, outsize)
            if not subflow.doTrace():
                return 0
            if hasattr(subflow, 'apply'):
                subflow.apply()
        return 1
