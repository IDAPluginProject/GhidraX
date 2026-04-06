"""
Remaining rules batch 2a: INDIRECT/MULTIEQUAL collapse rules + misc.
"""
from __future__ import annotations
import os
from ghidra.transform.action import Rule
from ghidra.core.opcodes import OpCode
from ghidra.core.address import calc_mask
from ghidra.core.error import LowlevelError
from ghidra.core.expression import functionalEquality as _functionalEquality
from ghidra.ir.op import PcodeOp
_IPTR_IOP = 5  # SpaceType.IPTR_IOP — inline to avoid import overhead

_CPUI_COPY    = 1   # OpCode.CPUI_COPY
_CPUI_STORE   = 3   # OpCode.CPUI_STORE
_OP_DEAD      = 0x20  # PcodeOp dead flag
_OP_SPACEBASE_PTR = 0x4000000  # PcodeOp.spacebase_ptr
_OP_INDIRECT_CREATION = 0x8000000  # PcodeOp.indirect_creation
_OP_NO_INDIRECT_COLLAPSE = 0x200  # PcodeOp.no_indirect_collapse addlflag
_VN_WRITTEN   = 0x10  # Varnode written flag
_VN_NOLOCALALIAS = 0x400  # Varnode.nolocalalias
_OP_MARKER    = 0x40  # PcodeOp.marker
_OP_RETURNS   = 0x08  # PcodeOp.returns (isAssignment)


def _indirect_debug_enabled(op) -> bool:
    spec = os.getenv("PYGHIDRA_INDIRECT_DEBUG_ADDRS", "").strip()
    if not spec:
        return False
    try:
        off = op.getAddr().getOffset()
    except Exception:
        return False
    if spec == "*":
        return True
    for part in spec.split(","):
        part = part.strip().lower()
        if not part:
            continue
        try:
            if off == int(part, 0):
                return True
        except Exception:
            continue
    return False


def _indirect_debug_log(op, message: str) -> None:
    if not _indirect_debug_enabled(op):
        return
    path = os.getenv(
        "PYGHIDRA_INDIRECT_DEBUG_LOG",
        "D:/BIGAI/pyghidra/temp/python_indirect_debug.log",
    )
    try:
        from ghidra.transform.action import Action
        idx = Action.getActiveTraceSerial()
    except Exception:
        idx = 0
    try:
        addr = f"{op.getAddr().getOffset():#x}"
    except Exception:
        addr = "?"
    try:
        seq = op.getSeqNum().getOrder()
    except Exception:
        seq = "?"
    try:
        with open(path, "a", encoding="utf-8") as fp:
            prefix = "[indirectcollapse]"
            if idx > 0:
                prefix += f" idx={idx}"
            fp.write(f"{prefix} addr={addr} seq={seq} {message}\n")
    except Exception:
        return


def _pushmulti_debug_enabled(op) -> bool:
    spec = os.getenv("PYGHIDRA_PUSHMULTI_DEBUG_ADDRS", "").strip()
    if not spec:
        return False
    try:
        off = op.getAddr().getOffset()
    except Exception:
        return False
    if spec == "*":
        return True
    for part in spec.split(","):
        part = part.strip().lower()
        if not part:
            continue
        try:
            if off == int(part, 0):
                return True
        except Exception:
            continue
    return False


def _pushmulti_debug_log(op, message: str) -> None:
    if not _pushmulti_debug_enabled(op):
        return
    path = os.getenv(
        "PYGHIDRA_PUSHMULTI_DEBUG_LOG",
        "D:/BIGAI/pyghidra/temp/python_pushmulti_debug.log",
    )
    try:
        from ghidra.transform.action import Action
        idx = Action.getActiveTraceSerial()
    except Exception:
        idx = 0
    try:
        addr = f"{op.getAddr().getOffset():#x}"
    except Exception:
        addr = "?"
    try:
        seq = op.getSeqNum().getOrder()
    except Exception:
        seq = "?"
    try:
        with open(path, "a", encoding="utf-8") as fp:
            prefix = "[pushmulti]"
            if idx > 0:
                prefix += f" idx={idx}"
            fp.write(f"{prefix} addr={addr} seq={seq} {message}\n")
    except Exception:
        return


def _pushmulti_var_desc(vn) -> str:
    try:
        if vn is None:
            return "None"
        if vn.isWritten():
            defop = vn.getDef()
            return (
                f"{defop.code().name}@{defop.getAddr().getOffset():#x}"
                f":{defop.getSeqNum().getOrder()}"
            )
        if vn.isConstant():
            return f"const[{vn.getOffset():#x}:{vn.getSize()}]"
        return f"{vn.getAddr()}:{vn.getSize()}"
    except Exception:
        return "<?>"


def _multicollapse_debug_enabled(op) -> bool:
    spec = os.getenv("PYGHIDRA_MULTICOLLAPSE_DEBUG_ADDRS", "").strip()
    if not spec:
        return False
    try:
        off = op.getAddr().getOffset()
    except Exception:
        return False
    if spec == "*":
        return True
    for part in spec.split(","):
        part = part.strip().lower()
        if not part:
            continue
        try:
            if off == int(part, 0):
                return True
        except Exception:
            continue
    return False


def _multicollapse_debug_log(op, message: str) -> None:
    if not _multicollapse_debug_enabled(op):
        return
    path = os.getenv(
        "PYGHIDRA_MULTICOLLAPSE_DEBUG_LOG",
        "D:/BIGAI/pyghidra/temp/python_multicollapse_debug.log",
    )
    try:
        from ghidra.transform.action import Action
        idx = Action.getActiveTraceSerial()
    except Exception:
        idx = 0
    try:
        addr = f"{op.getAddr().getOffset():#x}"
    except Exception:
        addr = "?"
    try:
        seq = op.getSeqNum().getOrder()
    except Exception:
        seq = "?"
    try:
        with open(path, "a", encoding="utf-8") as fp:
            prefix = "[multicollapse]"
            if idx > 0:
                prefix += f" idx={idx}"
            fp.write(f"{prefix} addr={addr} seq={seq} {message}\n")
    except Exception:
        return


class RuleMultiCollapse(Rule):
    """Collapse MULTIEQUAL whose inputs all match the same value (including through chains)."""
    def __init__(self, g): super().__init__(g, 0, "multicollapse")
    def clone(self, gl):
        return RuleMultiCollapse(self._basegroup) if gl.contains(self._basegroup) else None
    def getOpList(self): return [OpCode.CPUI_MULTIEQUAL]
    def applyOp(self, op, data):
        """Collapse MULTIEQUAL whose inputs all match the same value.

        C++ ref: RuleMultiCollapse::applyOp in ruleaction.cc
        """
        inrefs = op._inrefs
        for vn in inrefs:
            if not vn.isHeritageKnown():
                _multicollapse_debug_log(op, "return=0 reason=heritage_unknown")
                return 0

        func_eq = False
        nofunc = False
        defcopyr = None
        matchlist = list(inrefs)
        # Find base branch to match (prefer non-MULTIEQUAL)
        for copyr in matchlist:
            if not copyr.isWritten() or copyr.getDef().code() != OpCode.CPUI_MULTIEQUAL:
                defcopyr = copyr
                break
        if defcopyr is not None:
            try:
                desc = f"{defcopyr.getDef().code().name}@{defcopyr.getDef().getAddr().getOffset():#x}"
            except Exception:
                desc = "unwritten"
            _multicollapse_debug_log(op, f"state defcopyr={desc}")

        skiplist = [op.getOut()]
        op.getOut().setMark()
        j = 0
        success = True
        while j < len(matchlist):
            copyr = matchlist[j]
            j += 1
            if copyr.isMark():
                continue
            if defcopyr is None:
                defcopyr = copyr
                if defcopyr.isWritten():
                    if defcopyr.getDef().code() == OpCode.CPUI_MULTIEQUAL:
                        nofunc = True
                else:
                    nofunc = True
            elif defcopyr is copyr:
                continue
            elif defcopyr is not copyr and not nofunc and _functionalEquality(defcopyr, copyr):
                func_eq = True
                if defcopyr.isWritten():
                    def_desc = f"{defcopyr.getDef().code().name}@{defcopyr.getDef().getAddr().getOffset():#x}"
                else:
                    def_desc = "input"
                if copyr.isWritten():
                    copy_desc = f"{copyr.getDef().code().name}@{copyr.getDef().getAddr().getOffset():#x}"
                else:
                    copy_desc = "input"
                _multicollapse_debug_log(
                    op,
                    f"state functional_match defcopyr={def_desc} copyr={copy_desc}",
                )
                continue
            elif copyr.isWritten() and copyr.getDef().code() == OpCode.CPUI_MULTIEQUAL:
                newop = copyr.getDef()
                skiplist.append(copyr)
                copyr.setMark()
                _multicollapse_debug_log(
                    op,
                    "state expand_multiequal "
                    f"copyr={newop.code().name}@{newop.getAddr().getOffset():#x} "
                    f"inputs={newop.numInput()}",
                )
                for inv in newop._inrefs:
                    matchlist.append(inv)
            else:
                if defcopyr is None:
                    defdesc = "None"
                elif defcopyr.isWritten():
                    defdesc = f"{defcopyr.getDef().code().name}@{defcopyr.getDef().getAddr().getOffset():#x}"
                else:
                    defdesc = "input"
                if copyr.isWritten():
                    copydesc = f"{copyr.getDef().code().name}@{copyr.getDef().getAddr().getOffset():#x}"
                else:
                    copydesc = "input"
                eq = _functionalEquality(defcopyr, copyr) if defcopyr is not None and not nofunc else False
                _multicollapse_debug_log(
                    op,
                    "return=0 reason=nonmatching_branch "
                    f"defcopyr={defdesc} copyr={copydesc} nofunc={int(nofunc)} eq={int(eq)}",
                )
                success = False
                break

        if success and defcopyr is not None:
            for vn in skiplist:
                vn.clearMark()
                curOp = vn.getDef()
                if curOp is None:
                    continue
                if func_eq:
                    # Functional equality: need to copy the defining op
                    newop = defcopyr.getDef() if defcopyr.isWritten() else None
                    if newop is not None:
                        substitute = None
                        earliest = curOp.getParent().earliestUse(curOp.getOut()) if hasattr(curOp.getParent(), 'earliestUse') else None
                        for invn in newop._inrefs:
                            if not invn.isConstant():
                                if hasattr(data, 'cseFindInBlock'):
                                    substitute = data.cseFindInBlock(newop, invn, curOp.getParent(), earliest)
                                break
                        if substitute is not None:
                            data.totalReplace(vn, substitute.getOut())
                            data.opDestroy(curOp)
                        else:
                            needsreinsert = (curOp.code() == OpCode.CPUI_MULTIEQUAL)
                            parms = list(newop._inrefs)
                            data.opSetAllInput(curOp, parms)
                            data.opSetOpcode(curOp, newop.code())
                            if needsreinsert:
                                bl = curOp.getParent()
                                data.opUninsert(curOp)
                                data.opInsertBegin(curOp, bl)
                    else:
                        data.totalReplace(vn, defcopyr)
                        data.opDestroy(curOp)
                else:
                    data.totalReplace(vn, defcopyr)
                    data.opDestroy(curOp)
            _multicollapse_debug_log(op, f"return=1 func_eq={int(func_eq)}")
            return 1
        for vn in skiplist:
            vn.clearMark()
        _multicollapse_debug_log(op, "return=0 reason=failed")
        return 0


class RuleIndirectCollapse(Rule):
    """Remove CPUI_INDIRECT if its blocking PcodeOp is dead.

    C++ ref: ``RuleIndirectCollapse::applyOp`` in ruleaction.cc
    """
    def __init__(self, g): super().__init__(g, 0, "indirectcollapse")
    def clone(self, gl):
        return RuleIndirectCollapse(self._basegroup) if gl.contains(self._basegroup) else None
    def getOpList(self): return [OpCode.CPUI_INDIRECT]
    def applyOp(self, op, data):
        inrefs = op._inrefs
        if len(inrefs) < 2:
            _indirect_debug_log(op, "return=0 reason=missing_input")
            return 0
        iopvn = inrefs[1]
        if iopvn is None:
            _indirect_debug_log(op, "return=0 reason=missing_iop_varnode")
            return 0
        iopvn_spc = iopvn._loc.base
        if iopvn_spc is None or iopvn_spc._type != _IPTR_IOP:
            spc_type = None if iopvn_spc is None else iopvn_spc._type
            _indirect_debug_log(op, f"return=0 reason=bad_iop_space spc_type={spc_type}")
            return 0
        indop = iopvn._iop_ref
        if indop is None:
            _indirect_debug_log(op, "return=0 reason=missing_indop_ref")
            return 0

        outvn = op._output
        if outvn is None:
            _indirect_debug_log(op, "return=0 reason=missing_output")
            return 0
        indopc = indop._opcode_enum
        indop_dead = 1 if (indop._flags & _OP_DEAD) else 0
        out_nolocal = 1 if (outvn._flags & _VN_NOLOCALALIAS) else 0
        op_indirect_creation = 1 if (op._flags & _OP_INDIRECT_CREATION) else 0
        op_no_collapse = 1 if (op._addlflags & _OP_NO_INDIRECT_COLLAPSE) else 0
        indop_spacebase = 1 if (indop._flags & _OP_SPACEBASE_PTR) else 0
        _indirect_debug_log(
            op,
            "state "
            f"out_addr={outvn.getAddr().getOffset():#x}:{outvn.getSize()} "
            f"indop_addr={indop.getAddr().getOffset():#x} "
            f"indop_seq={indop.getSeqNum().getOrder()} "
            f"indopc={indopc} indop_dead={indop_dead} "
            f"out_flags={outvn._flags:#x} out_nolocal={out_nolocal} "
            f"op_flags={op._flags:#x} op_addl={op._addlflags:#x} "
            f"indirect_creation={op_indirect_creation} no_indirect_collapse={op_no_collapse} "
            f"indop_flags={indop._flags:#x} indop_spacebase={indop_spacebase}"
        )
        if not (indop._flags & _OP_DEAD):
            if indopc == _CPUI_COPY:
                # STORE resolved to a COPY — check overlap
                vn1 = indop._output
                if vn1 is None:
                    _indirect_debug_log(op, "return=0 reason=copy_without_output")
                    return 0
                res = vn1.characterizeOverlap(outvn)
                _indirect_debug_log(
                    op,
                    "copy_overlap "
                    f"vn1={vn1.getAddr().getOffset():#x}:{vn1.getSize()} "
                    f"out={outvn.getAddr().getOffset():#x}:{outvn.getSize()} "
                    f"res={res}",
                )
                if res > 0:
                    if res == 2:
                        # Same storage — convert INDIRECT to COPY
                        data.opUninsert(op)
                        data.opSetInput(op, vn1, 0)
                        data.opRemoveInput(op, 1)
                        data.opSetOpcode(op, OpCode.CPUI_COPY)
                        data.opInsertAfter(op, indop)
                        return 1
                    if vn1.contains(outvn) == 0:
                        # INDIRECT output properly contained in COPY output — SUBPIECE
                        vn1_loc = vn1._loc
                        vn2_loc = outvn._loc
                        vn1_spc = vn1_loc.base
                        if vn1_spc is not None and vn1_spc.isBigEndian():
                            trunc = vn1_loc.offset + vn1._size - (vn2_loc.offset + outvn._size)
                        else:
                            trunc = vn2_loc.offset - vn1_loc.offset
                        data.opUninsert(op)
                        data.opSetInput(op, vn1, 0)
                        data.opSetInput(op, data.newConstant(4, trunc), 1)
                        data.opSetOpcode(op, OpCode.CPUI_SUBPIECE)
                        data.opInsertAfter(op, indop)
                        _indirect_debug_log(op, "return=1 action=subpiece_from_copy")
                        return 1
                    _indirect_debug_log(op, "return=0 reason=partial_copy_overlap")
                    return 0  # Partial overlap
            elif outvn._flags & _VN_NOLOCALALIAS:
                # Guard: do NOT collapse indirect_creation or noIndirectCollapse
                if (op._flags & _OP_INDIRECT_CREATION) or (op._addlflags & _OP_NO_INDIRECT_COLLAPSE):
                    _indirect_debug_log(op, "return=0 reason=nolocalalias_guarded")
                    return 0
            elif indop._flags & _OP_SPACEBASE_PTR:
                if indopc == _CPUI_STORE:
                    guard = data.getStoreGuard(indop)
                    if guard is not None:
                        if guard.isGuarded(outvn._loc):
                            _indirect_debug_log(op, "return=0 reason=store_guarded")
                            return 0
                    else:
                        _indirect_debug_log(op, "return=0 reason=store_guard_missing")
                        return 0  # Marked STORE not yet guarded — keep INDIRECT
            else:
                _indirect_debug_log(op, "return=0 reason=live_indop_unhandled")
                return 0  # Blocking op still alive and not handled

        # Blocking op is dead or effect is gone — collapse
        data.totalReplace(outvn, inrefs[0])
        data.opDestroy(op)
        _indirect_debug_log(op, "return=1 action=collapse")
        return 1


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
            if op.code() != OpCode.CPUI_SUBPIECE:
                raise LowlevelError("Could not perform -replaceDescendants-")
            truncAmount = int(op.getIn(1).getOffset())
            outSize = op.getOut().getSize()
            data.opSetInput(op, newVn, 0)
            if newVn.getSize() == outSize:
                if truncAmount != minByte:
                    raise LowlevelError("Could not perform -replaceDescendants-")
                data.opSetOpcode(op, OpCode.CPUI_COPY)
                data.opRemoveInput(op, 1)
            elif newVn.getSize() > outSize:
                newTrunc = truncAmount - minByte
                if newTrunc < 0:
                    raise LowlevelError("Could not perform -replaceDescendants-")
                if newTrunc != truncAmount:
                    data.opSetInput(op, data.newConstant(4, newTrunc), 1)
            else:
                raise LowlevelError("Could not perform -replaceDescendants-")

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
                raise LowlevelError("Undefined pullsub")
            newaddr = basevn.getDef().getAddr()
        smalladdr1 = None
        usetmp = False
        baseaddr = basevn.getAddr()
        if baseaddr.isJoin():
            usetmp = True
            arch = data.getArch()
            joinrec = arch.findJoin(basevn.getOffset()) if arch is not None and hasattr(arch, 'findJoin') else None
            if joinrec is not None and joinrec.numPieces() > 1:
                skipleft = shift
                for i in range(joinrec.numPieces() - 1, -1, -1):
                    piece = joinrec.getPiece(i)
                    if skipleft >= piece.size:
                        skipleft -= piece.size
                        continue
                    if skipleft + outsize > piece.size:
                        break
                    if piece.space.isBigEndian():
                        smalladdr1 = piece.getAddr() + (piece.size - (outsize + skipleft))
                    else:
                        smalladdr1 = piece.getAddr() + skipleft
                    usetmp = False
                    break
        else:
            if not basevn.getSpace().isBigEndian():
                smalladdr1 = baseaddr + shift
            else:
                smalladdr1 = baseaddr + (basevn.getSize() - (shift + outsize))
        new_op = data.newOp(2, newaddr)
        data.opSetOpcode(new_op, OpCode.CPUI_SUBPIECE)
        if usetmp:
            outvn = data.newUniqueOut(outsize, new_op)
        else:
            if smalladdr1 is None:
                raise LowlevelError("Undefined pullsub")
            smalladdr1.renormalize(outsize)
            outvn = data.newVarnodeOut(outsize, smalladdr1, new_op)
        data.opSetInput(new_op, basevn, 0)
        data.opSetInput(new_op, data.newConstant(4, shift), 1)
        if basevn.isInput():
            data.opInsertBegin(new_op, data.getBasicBlocks().getBlock(0))
        else:
            data.opInsertAfter(new_op, basevn.getDef())
        return outvn

    def applyOp(self, op, data):
        invn = op.getIn(0)
        if not invn.isWritten():
            return 0
        defop = invn.getDef()
        if defop.code() != OpCode.CPUI_MULTIEQUAL:
            return 0
        if defop.getParent().hasLoopIn():
            return 0
        maxByte, minByte = RulePullsubMulti.minMaxUse(invn)
        newSize = maxByte - minByte + 1
        if maxByte < minByte or newSize >= invn.getSize():
            return 0
        if not RulePullsubMulti.acceptableSize(newSize):
            return 0
        outvn = op.getOut()
        if outvn.isPrecisLo() or outvn.isPrecisHi():
            return 0

        if minByte > 8:
            return 0
        if minByte < 8:
            consume = calc_mask(newSize) << (8 * minByte)
        else:
            consume = 0
        consume = (~consume) & calc_mask(8)
        branches = defop.numInput()
        for i in range(branches):
            inVn = defop.getIn(i)
            if (consume & inVn.getConsume()) != 0:
                if minByte == 0 and inVn.isWritten():
                    inDef = inVn.getDef()
                    opc = inDef.code()
                    if opc in (OpCode.CPUI_INT_ZEXT, OpCode.CPUI_INT_SEXT):
                        if newSize == inDef.getIn(0).getSize():
                            continue
                return 0

        if not invn.getSpace().isBigEndian():
            smalladdr2 = invn.getAddr() + minByte
        else:
            smalladdr2 = invn.getAddr() + (invn.getSize() - maxByte - 1)

        params = []
        for i in range(branches):
            vn_piece = defop.getIn(i)
            vn_sub = RulePullsubMulti.findSubpiece(vn_piece, newSize, minByte)
            if vn_sub is None:
                vn_sub = RulePullsubMulti.buildSubpiece(vn_piece, newSize, minByte, data)
            params.append(vn_sub)

        new_multi = data.newOp(len(params), defop.getAddr())
        smalladdr2.renormalize(newSize)
        new_vn = data.newVarnodeOut(newSize, smalladdr2, new_multi)
        data.opSetOpcode(new_multi, OpCode.CPUI_MULTIEQUAL)
        data.opSetAllInput(new_multi, params)
        data.opInsertBegin(new_multi, defop.getParent())

        RulePullsubMulti.replaceDescendants(invn, new_vn, maxByte, minByte, data)
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
        if outvn is None:
            return 0
        if hasattr(outvn, 'isPrecisLo') and (outvn.isPrecisLo() or outvn.isPrecisHi()):
            return 0

        consume = calc_mask(newSize) << (8 * minByte)
        consume = (~consume) & calc_mask(invn.getSize())
        indir_in0 = indir.getIn(0)
        indir_consume = indir_in0.getConsume() if hasattr(indir_in0, 'getConsume') else calc_mask(indir_in0.getSize())
        if (consume & indir_consume) != 0:
            return 0

        if not invn.getSpace().isBigEndian():
            smalladdr2 = invn.getAddr() + minByte
        else:
            smalladdr2 = invn.getAddr() + (invn.getSize() - maxByte - 1)

        if hasattr(indir, 'isIndirectCreation') and indir.isIndirectCreation():
            possibleout = not indir.getIn(0).isIndirectZero()
            new_ind = data.newIndirectCreation(targ_op, smalladdr2, newSize, possibleout)
            small2 = new_ind.getOut()
        else:
            basevn = indir.getIn(0)
            small1 = RulePullsubMulti.findSubpiece(basevn, newSize, int(op.getIn(1).getOffset()))
            if small1 is None:
                small1 = RulePullsubMulti.buildSubpiece(basevn, newSize, int(op.getIn(1).getOffset()), data)
            if small1 is None:
                return 0

            new_ind = data.newOp(2, indir.getAddr())
            data.opSetOpcode(new_ind, OpCode.CPUI_INDIRECT)
            small2 = data.newVarnodeOut(newSize, smalladdr2, new_ind)
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
        _pushmulti_debug_log(
            earliest if earliest is not None else (in1.getDef() if in1.isWritten() else in2.getDef()),
            "findSubstitute:start "
            f"in1={_pushmulti_var_desc(in1)} "
            f"in2={_pushmulti_var_desc(in2)} "
            f"earliest={(earliest.getSeqNum().getOrder() if earliest is not None else 'None')}",
        )
        for desc_op in list(in1.getDescendants()):
            _pushmulti_debug_log(
                desc_op,
                "findSubstitute:candidate "
                f"parent_match={int(desc_op.getParent() is bb)} "
                f"opcode={desc_op.code().name} "
                f"in0={_pushmulti_var_desc(desc_op.getIn(0)) if desc_op.numInput() > 0 else 'None'} "
                f"in1={_pushmulti_var_desc(desc_op.getIn(1)) if desc_op.numInput() > 1 else 'None'}",
            )
            if desc_op.getParent() is not bb:
                continue
            if desc_op.code() != OpCode.CPUI_MULTIEQUAL:
                continue
            if desc_op.getIn(0) is not in1:
                continue
            if desc_op.getIn(1) is not in2:
                continue
            _pushmulti_debug_log(desc_op, "findSubstitute=existing_multiequal")
            return desc_op
        if in1 is in2:
            _pushmulti_debug_log(
                in1.getDef() if in1.isWritten() else earliest,
                "findSubstitute:return=None reason=same_input",
            )
            return None
        buf1 = [None, None]
        buf2 = [None, None]
        feq = functionalEqualityLevel(in1, in2, buf1, buf2)
        _pushmulti_debug_log(
            in1.getDef() if in1.isWritten() else earliest,
            "findSubstitute:functional "
            f"res={feq} "
            f"buf1={_pushmulti_var_desc(buf1[0])} "
            f"buf2={_pushmulti_var_desc(buf2[0])}",
        )
        if feq != 0:
            return None
        op1 = in1.getDef()
        op2 = in2.getDef()
        from ghidra.analysis.funcdata import Funcdata
        for i in range(op1.numInput()):
            vn = op1.getIn(i)
            if vn.isConstant():
                continue
            if vn is op2.getIn(i):
                substitute = Funcdata.cseFindInBlock(op1, vn, bb, earliest)
                if substitute is not None:
                    _pushmulti_debug_log(substitute, f"findSubstitute=cse_match via_slot={i}")
                else:
                    _pushmulti_debug_log(
                        op1,
                        "findSubstitute:return=None "
                        f"reason=no_cse via_slot={i} shared={_pushmulti_var_desc(vn)}",
                    )
                return substitute
        _pushmulti_debug_log(op1, "findSubstitute:return=None reason=no_shared_slot")
        return None

    def applyOp(self, op, data):
        from ghidra.core.expression import functionalEqualityLevel
        if op.numInput() != 2:
            _pushmulti_debug_log(op, "return=0 reason=bad_arity")
            return 0
        in1 = op.getIn(0)
        in2 = op.getIn(1)
        if not in1.isWritten():
            _pushmulti_debug_log(op, "return=0 reason=in1_not_written")
            return 0
        if not in2.isWritten():
            _pushmulti_debug_log(op, "return=0 reason=in2_not_written")
            return 0
        if in1.isSpacebase():
            _pushmulti_debug_log(op, "return=0 reason=in1_spacebase")
            return 0
        if in2.isSpacebase():
            _pushmulti_debug_log(op, "return=0 reason=in2_spacebase")
            return 0
        buf1 = [None, None]
        buf2 = [None, None]
        res = functionalEqualityLevel(in1, in2, buf1, buf2)
        _pushmulti_debug_log(
            op,
            "state "
            f"res={res} "
            f"in1_def={in1.getDef().code().name}@{in1.getDef().getAddr().getOffset():#x} "
            f"in2_def={in2.getDef().code().name}@{in2.getDef().getAddr().getOffset():#x}",
        )
        if res < 0:
            _pushmulti_debug_log(op, "return=0 reason=functional_lt0")
            return 0
        if res > 1:
            _pushmulti_debug_log(op, "return=0 reason=functional_gt1")
            return 0
        op1 = in1.getDef()
        if op1.code() == OpCode.CPUI_SUBPIECE:
            _pushmulti_debug_log(op, "return=0 reason=subpiece")
            return 0
        bl = op.getParent()
        earliest = bl.earliestUse(op.getOut()) if hasattr(bl, 'earliestUse') else None
        if op1.code() == OpCode.CPUI_COPY:
            if res == 0:
                _pushmulti_debug_log(op, "return=0 reason=copy_res0")
                return 0
            substitute = RulePushMulti.findSubstitute(buf1[0], buf2[0], bl, earliest)
            if substitute is None:
                _pushmulti_debug_log(op, "return=0 reason=copy_no_substitute")
                return 0
            data.totalReplace(op.getOut(), substitute.getOut())
            data.opDestroy(op)
            _pushmulti_debug_log(op, "return=1 action=copy_replace")
            return 1
        op2 = in2.getDef()
        if in1.loneDescend() is not op:
            _pushmulti_debug_log(op, "return=0 reason=in1_not_lone_descend")
            return 0
        if in2.loneDescend() is not op:
            _pushmulti_debug_log(op, "return=0 reason=in2_not_lone_descend")
            return 0
        outvn = op.getOut()
        data.opSetOutput(op1, outvn)
        data.opUninsert(op1)
        if res == 1:
            slot1 = op1.getSlot(buf1[0])
            substitute = RulePushMulti.findSubstitute(buf1[0], buf2[0], bl, earliest)
            if substitute is None:
                _pushmulti_debug_log(op, f"state create_substitute slot1={slot1}")
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
        _pushmulti_debug_log(op, "return=1 action=push")
        return 1


class RuleSelectCse(Rule):
    """Common subexpression elimination: if two ops in same block have same opcode and inputs, merge."""
    def __init__(self, g): super().__init__(g, 0, "selectcse")
    def clone(self, gl):
        return RuleSelectCse(self._basegroup) if gl.contains(self._basegroup) else None
    def getOpList(self): return [OpCode.CPUI_SUBPIECE, OpCode.CPUI_INT_SRIGHT]
    def applyOp(self, op, data):
        vn = op.getIn(0)
        if vn is None:
            return 0
        opc = op.code()
        hashlist = []
        outlist = []

        for other in vn._descend:
            if other.code() != opc:
                continue
            h = other.getCseHash()
            if h == 0:
                continue
            hashlist.append((h, other))
        if len(hashlist) <= 1:
            return 0

        data.cseEliminateList(hashlist, outlist)
        return 1 if outlist else 0


class RuleCollectTerms(Rule):
    """Collect terms in a sum: V * c + V * d => V * (c + d).

    C++ ref: ruleaction.cc — RuleCollectTerms
    """
    def __init__(self, g): super().__init__(g, 0, "collect_terms")
    def clone(self, gl):
        return RuleCollectTerms(self._basegroup) if gl.contains(self._basegroup) else None
    def getOpList(self): return [OpCode.CPUI_INT_ADD]

    @staticmethod
    def getMultCoeff(vn):
        """Get the multiplicative coefficient of a term.

        C++ ref: RuleCollectTerms::getMultCoeff
        Returns (underlying_vn, coefficient).
        """
        if not vn.isWritten():
            return (vn, 1)
        testop = vn.getDef()
        if testop.code() != OpCode.CPUI_INT_MULT or not testop.getIn(1).isConstant():
            return (vn, 1)
        return (testop.getIn(0), int(testop.getIn(1).getOffset()))

    def applyOp(self, op, data):
        from ghidra.core.expression import TermOrder

        outvn = op.getOut()
        if outvn is None:
            return 0
        nextop = outvn.loneDescend()
        if nextop is not None and nextop.code() == OpCode.CPUI_INT_ADD:
            return 0

        termorder = TermOrder(op)
        termorder.collect()
        termorder.sortTerms()
        order = termorder.getSort()
        if not order:
            return 0

        i = 0
        if not order[0].getVarnode().isConstant():
            for i in range(1, len(order)):
                vn1 = order[i - 1].getVarnode()
                vn2 = order[i].getVarnode()
                if vn2.isConstant():
                    break
                vn1, coef1 = self.getMultCoeff(vn1)
                vn2, coef2 = self.getMultCoeff(vn2)
                if vn1 is vn2:
                    if order[i - 1].getMultiplier() is not None:
                        return 1 if data.distributeIntMultAdd(order[i - 1].getMultiplier()) else 0
                    if order[i].getMultiplier() is not None:
                        return 1 if data.distributeIntMultAdd(order[i].getMultiplier()) else 0
                    coef1 = (coef1 + coef2) & calc_mask(vn1.getSize())
                    newcoeff = data.newConstant(vn1.getSize(), coef1)
                    zerocoeff = data.newConstant(vn1.getSize(), 0)
                    data.opSetInput(order[i - 1].getOp(), zerocoeff, order[i - 1].getSlot())
                    if coef1 == 0:
                        data.opSetInput(order[i].getOp(), newcoeff, order[i].getSlot())
                    else:
                        nextop = data.newOp(2, order[i].getOp().getAddr())
                        vn2 = data.newUniqueOut(vn1.getSize(), nextop)
                        data.opSetOpcode(nextop, OpCode.CPUI_INT_MULT)
                        data.opSetInput(nextop, vn1, 0)
                        data.opSetInput(nextop, newcoeff, 1)
                        data.opInsertBefore(nextop, order[i].getOp())
                        data.opSetInput(order[i].getOp(), vn2, order[i].getSlot())
                    return 1

        coef1 = 0
        nonzerocount = 0
        lastconst = 0
        for j in range(len(order) - 1, i - 1, -1):
            if order[j].getMultiplier() is not None:
                continue
            vn1 = order[j].getVarnode()
            val = vn1.getOffset()
            if val != 0:
                nonzerocount += 1
                coef1 += val
                lastconst = j
        if nonzerocount <= 1:
            return 0
        vn1 = order[lastconst].getVarnode()
        coef1 &= calc_mask(vn1.getSize())
        for j in range(lastconst + 1, len(order)):
            if order[j].getMultiplier() is None:
                data.opSetInput(order[j].getOp(), data.newConstant(vn1.getSize(), 0), order[j].getSlot())
        data.opSetInput(order[lastconst].getOp(), data.newConstant(vn1.getSize(), coef1), order[lastconst].getSlot())
        return 1


class RuleSubCommute(Rule):
    """Commute SUBPIECE with various operations (AND, OR, XOR, ADD, MULT, NEGATE, etc.).

    C++ ref: ruleaction.cc — RuleSubCommute
    """
    def __init__(self, g): super().__init__(g, 0, "subcommute")
    def clone(self, gl):
        return RuleSubCommute(self._basegroup) if gl.contains(self._basegroup) else None
    def getOpList(self): return [OpCode.CPUI_SUBPIECE]

    @staticmethod
    def shortenExtension(extOp, maxSize: int, data):
        """Shorten the output of an extension op to maxSize.

        C++ ref: RuleSubCommute::shortenExtension
        """
        origOut = extOp.getOut()
        addr = origOut.getAddr()
        if hasattr(addr, 'isBigEndian') and addr.isBigEndian():
            addr = addr + (origOut.getSize() - maxSize)
        data.opUnsetOutput(extOp)
        return data.newVarnodeOut(maxSize, addr, extOp)

    @staticmethod
    def cancelExtensions(longform, subOp, ext0In, ext1In, data) -> bool:
        """Eliminate input extensions on given binary PcodeOp.

        C++ ref: RuleSubCommute::cancelExtensions
        """
        outvn = longform.getOut()
        if outvn.loneDescend() is not subOp:
            return False
        if ext0In.getSize() == ext1In.getSize():
            maxSize = ext0In.getSize()
            if ext0In.isFree():
                return False
            if ext1In.isFree():
                return False
        elif ext0In.getSize() < ext1In.getSize():
            maxSize = ext1In.getSize()
            if ext1In.isFree():
                return False
            if longform.getIn(0).loneDescend() is not longform:
                return False
            ext0In = RuleSubCommute.shortenExtension(longform.getIn(0).getDef(), maxSize, data)
        else:
            maxSize = ext0In.getSize()
            if ext0In.isFree():
                return False
            if longform.getIn(1).loneDescend() is not longform:
                return False
            ext1In = RuleSubCommute.shortenExtension(longform.getIn(1).getDef(), maxSize, data)
        data.opUnsetOutput(longform)
        outvn = data.newUniqueOut(maxSize, longform)
        data.opSetInput(longform, ext0In, 0)
        data.opSetInput(longform, ext1In, 1)
        data.opSetInput(subOp, outvn, 0)
        return True

    def applyOp(self, op, data):
        base = op.getIn(0)
        if not base.isWritten(): return 0
        offset = int(op.getIn(1).getOffset())
        outvn = op.getOut()
        if outvn.isPrecisLo() or outvn.isPrecisHi(): return 0
        insize = base.getSize()
        longform = base.getDef()
        opc = longform.code()
        j = -1  # Special index for shift amount param
        if opc == OpCode.CPUI_INT_LEFT:
            j = 1
            if offset != 0: return 0
            if longform.getIn(0).isWritten():
                defOpc = longform.getIn(0).getDef().code()
                if defOpc != OpCode.CPUI_INT_ZEXT and defOpc != OpCode.CPUI_PIECE:
                    return 0
            else:
                return 0
        elif opc in (OpCode.CPUI_INT_REM, OpCode.CPUI_INT_DIV):
            if offset != 0: return 0
            if not longform.getIn(0).isWritten(): return 0
            zext0 = longform.getIn(0).getDef()
            if zext0.code() != OpCode.CPUI_INT_ZEXT: return 0
            zext0In = zext0.getIn(0)
            if longform.getIn(1).isWritten():
                zext1 = longform.getIn(1).getDef()
                if zext1.code() != OpCode.CPUI_INT_ZEXT: return 0
                zext1In = zext1.getIn(0)
                if zext1In.getSize() > outvn.getSize() or zext0In.getSize() > outvn.getSize():
                    if self.cancelExtensions(longform, op, zext0In, zext1In, data):
                        return 1
                    return 0
            elif longform.getIn(1).isConstant() and zext0In.getSize() <= outvn.getSize():
                val = longform.getIn(1).getOffset()
                smallval = val & calc_mask(outvn.getSize())
                if val != smallval:
                    return 0
            else:
                return 0
        elif opc in (OpCode.CPUI_INT_SREM, OpCode.CPUI_INT_SDIV):
            if offset != 0: return 0
            if not longform.getIn(0).isWritten(): return 0
            sext0 = longform.getIn(0).getDef()
            if sext0.code() != OpCode.CPUI_INT_SEXT: return 0
            sext0In = sext0.getIn(0)
            if longform.getIn(1).isWritten():
                sext1 = longform.getIn(1).getDef()
                if sext1.code() != OpCode.CPUI_INT_SEXT: return 0
                sext1In = sext1.getIn(0)
                if sext1In.getSize() > outvn.getSize() or sext0In.getSize() > outvn.getSize():
                    if self.cancelExtensions(longform, op, sext0In, sext1In, data):
                        return 1
                    return 0
            elif longform.getIn(1).isConstant() and sext0In.getSize() <= outvn.getSize():
                from ghidra.core.address import sign_extend
                val = longform.getIn(1).getOffset()
                smallval = val & calc_mask(outvn.getSize())
                smallval = sign_extend(smallval, outvn.getSize() * 8 - 1)
                smallval &= calc_mask(insize)
                if val != smallval:
                    return 0
            else:
                return 0
        elif opc == OpCode.CPUI_INT_ADD:
            if offset != 0: return 0
            if longform.getIn(0).isSpacebase(): return 0
        elif opc == OpCode.CPUI_INT_MULT:
            if offset != 0: return 0
        elif opc in (OpCode.CPUI_INT_NEGATE, OpCode.CPUI_INT_XOR,
                     OpCode.CPUI_INT_AND, OpCode.CPUI_INT_OR):
            pass
        else:
            return 0
        if base.loneDescend() is not op: return 0
        if offset == 0:
            nextop = outvn.loneDescend()
            if nextop is not None and nextop.code() == OpCode.CPUI_INT_ZEXT:
                if nextop.getOut().getSize() == insize:
                    return 0
        outsize = outvn.getSize()
        lastIn = None
        newVn = None
        for i in range(longform.numInput()):
            vn = longform.getIn(i)
            if i != j:
                if lastIn is not vn or newVn is None:
                    newsub = data.newOp(2, op.getAddr())
                    data.opSetOpcode(newsub, OpCode.CPUI_SUBPIECE)
                    newVn = data.newUniqueOut(outsize, newsub)
                    data.opSetInput(longform, newVn, i)
                    data.opSetInput(newsub, vn, 0)
                    data.opSetInput(newsub, data.newConstant(4, offset), 1)
                    data.opInsertBefore(newsub, longform)
                else:
                    data.opSetInput(longform, newVn, i)
            lastIn = vn
        data.opSetOutput(longform, outvn)
        data.opDestroy(op)
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
    """Cleanup integer bitwise ops that are really floating-point sign manipulations.

    C++ ref: ruleaction.cc — RuleFloatSignCleanup
    """
    def __init__(self, g): super().__init__(g, 0, "floatsigncleanup")
    def clone(self, gl):
        return RuleFloatSignCleanup(self._basegroup) if gl.contains(self._basegroup) else None
    def getOpList(self): return [OpCode.CPUI_INT_AND, OpCode.CPUI_INT_XOR]

    @staticmethod
    def floatSignManipulation(op):
        """Determine if an integer bitwise op is a floating-point sign manipulation.

        C++ ref: TypeOp::floatSignManipulation in typeop.cc
        Returns the equivalent float opcode, or None.
        """
        opc = op.code()
        if opc == OpCode.CPUI_INT_AND:
            cvn = op.getIn(1)
            if cvn.isConstant():
                val = calc_mask(cvn.getSize()) >> 1
                if val == cvn.getOffset():
                    return OpCode.CPUI_FLOAT_ABS
        elif opc == OpCode.CPUI_INT_XOR:
            cvn = op.getIn(1)
            if cvn.isConstant():
                full = calc_mask(cvn.getSize())
                val = full ^ (full >> 1)
                if val == cvn.getOffset():
                    return OpCode.CPUI_FLOAT_NEG
        return None

    def applyOp(self, op, data):
        from ghidra.types.datatype import TYPE_FLOAT
        outType = op.getOut().getType() if hasattr(op.getOut(), 'getType') else None
        if outType is None or outType.getMetatype() != TYPE_FLOAT:
            return 0
        opc = self.floatSignManipulation(op)
        if opc is None:
            return 0
        data.opRemoveInput(op, 1)
        data.opSetOpcode(op, opc)
        return 1


class RuleIgnoreNan(Rule):
    """Replace FLOAT_NAN with constant false when NaN-ignore mode is on.

    C++ ref: ruleaction.cc — RuleIgnoreNan
    """
    def __init__(self, g): super().__init__(g, 0, "ignorenan")
    def clone(self, gl):
        return RuleIgnoreNan(self._basegroup) if gl.contains(self._basegroup) else None
    def getOpList(self): return [OpCode.CPUI_FLOAT_NAN]

    @staticmethod
    def checkBackForCompare(floatVar, root) -> bool:
        """Check if a boolean Varnode incorporates a floating-point comparison with floatVar.

        C++ ref: RuleIgnoreNan::checkBackForCompare
        """
        if not root.isWritten():
            return False
        def1 = root.getDef()
        if not def1.isBoolOutput():
            return False
        if def1.code() == OpCode.CPUI_BOOL_NEGATE:
            vn = def1.getIn(0)
            if not vn.isWritten():
                return False
            def1 = vn.getDef()
        if hasattr(def1.getOpcode(), 'isFloatingPointOp') and def1.getOpcode().isFloatingPointOp():
            if def1.numInput() != 2:
                return False
            from ghidra.ir.varnode import functionalEquality
            if functionalEquality(floatVar, def1.getIn(0)):
                return True
            if functionalEquality(floatVar, def1.getIn(1)):
                return True
            return False
        opc = def1.code()
        if opc != OpCode.CPUI_BOOL_AND and opc != OpCode.CPUI_BOOL_OR:
            return False
        from ghidra.ir.varnode import functionalEquality
        for i in range(2):
            vn = def1.getIn(i)
            if not vn.isWritten():
                continue
            def2 = vn.getDef()
            if not def2.isBoolOutput():
                continue
            if not (hasattr(def2.getOpcode(), 'isFloatingPointOp') and def2.getOpcode().isFloatingPointOp()):
                continue
            if def2.numInput() != 2:
                continue
            if functionalEquality(floatVar, def2.getIn(0)):
                return True
            if functionalEquality(floatVar, def2.getIn(1)):
                return True
        return False

    @staticmethod
    def isAnotherNan(vn) -> bool:
        """Test if the given Varnode is produced by a NaN operation.

        C++ ref: RuleIgnoreNan::isAnotherNan
        """
        if not vn.isWritten():
            return False
        op = vn.getDef()
        opc = op.code()
        if opc == OpCode.CPUI_BOOL_NEGATE:
            vn = op.getIn(0)
            if not vn.isWritten():
                return False
            op = vn.getDef()
            opc = op.code()
        return opc == OpCode.CPUI_FLOAT_NAN

    @staticmethod
    def testForComparison(floatVar, op, slot: int, matchCode, count: int, data):
        """Test if a boolean expression incorporates a floating-point comparison and remove NaN.

        C++ ref: RuleIgnoreNan::testForComparison
        Returns (output_vn_or_None, updated_count).
        """
        opc = op.code()
        if opc == matchCode:
            vn = op.getIn(1 - slot)
            if RuleIgnoreNan.checkBackForCompare(floatVar, vn):
                data.opSetOpcode(op, OpCode.CPUI_COPY)
                data.opRemoveInput(op, 1)
                data.opSetInput(op, vn, 0)
                count += 1
            elif RuleIgnoreNan.isAnotherNan(vn):
                return (op.getOut(), count)
        elif opc in (OpCode.CPUI_INT_EQUAL, OpCode.CPUI_INT_NOTEQUAL):
            vn = op.getIn(1 - slot)
            if RuleIgnoreNan.checkBackForCompare(floatVar, vn):
                constVal = 0 if matchCode == OpCode.CPUI_BOOL_OR else 1
                data.opSetInput(op, data.newConstant(1, constVal), slot)
                count += 1
        elif opc == OpCode.CPUI_CBRANCH:
            parent = op.getParent()
            outDir = 0 if matchCode == OpCode.CPUI_BOOL_OR else 1
            if hasattr(op, 'isBooleanFlip') and op.isBooleanFlip():
                outDir = 1 - outDir
            outBranch = parent.getOut(outDir)
            lastOp = outBranch.lastOp() if hasattr(outBranch, 'lastOp') else None
            if lastOp is not None and lastOp.code() == OpCode.CPUI_CBRANCH:
                otherBranch = parent.getOut(1 - outDir)
                if (outBranch.getOut(0) is otherBranch or outBranch.getOut(1) is otherBranch):
                    if RuleIgnoreNan.checkBackForCompare(floatVar, lastOp.getIn(1)):
                        constVal = 0 if matchCode == OpCode.CPUI_BOOL_OR else 1
                        data.opSetInput(op, data.newConstant(1, constVal), 1)
                        count += 1
        return (None, count)

    def applyOp(self, op, data):
        glb = data.getArch()
        if glb is None: return 0
        if getattr(glb, 'nan_ignore_all', False):
            data.opSetOpcode(op, OpCode.CPUI_COPY)
            data.opSetInput(op, data.newConstant(1, 0), 0)
            return 1
        # Non-ignore mode: try to remove NaN when combined with comparison
        floatVar = op.getIn(0)
        outvn = op.getOut()
        matchCode = OpCode.CPUI_BOOL_OR
        count = 0
        for descOp in list(outvn.getDescend()):
            slot = descOp.getSlot(outvn)
            result, count = self.testForComparison(floatVar, descOp, slot, matchCode, count, data)
            while result is not None:
                nextOp = result.loneDescend()
                if nextOp is None:
                    break
                slot = nextOp.getSlot(result)
                result, count = self.testForComparison(floatVar, nextOp, slot, matchCode, count, data)
        if count > 0:
            return 1
        return 0


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
