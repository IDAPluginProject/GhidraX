"""
Corresponds to: merge.hh / merge.cc

Utilities for merging low-level Varnodes into high-level variables.
"""

from __future__ import annotations
import os
from typing import TYPE_CHECKING, Optional, List, Tuple
from bisect import bisect_left

from ghidra.ir.cover import Cover, PcodeOpSet
from ghidra.ir.op import PcodeOp, PieceNode
from ghidra.core.opcodes import OpCode

# Pre-cached Varnode flag constants for hot merge test paths
_VN_INPUT           = 0x08
_VN_TYPELOCK        = 0x100
_VN_NAMELOCK        = 0x200
_VN_PERSIST         = 0x4000
_VN_ADDRTIED        = 0x8000
_VN_INDIRECT_CREATE = 0x400000
_VN_PROTO_PARTIAL   = 0x80000000
_HV_FLAGSDIRTY      = 1
_HV_SYMBOLDIRTY     = 0x10
_HV_TYPEDIRTY       = 4
# Combined mask for speculative exclusions
_SPEC_EXCL = _VN_INPUT | _VN_PERSIST | _VN_ADDRTIED
# isExtraOut = (flags & (indirect_creation | addrtied)) == indirect_creation
_EXTRAOUT_MASK = _VN_INDIRECT_CREATE | _VN_ADDRTIED
_MERGE_DEBUG_ADDRS = {
    int(tok, 0)
    for tok in os.environ.get("PYGHIDRA_MERGE_DEBUG_ADDRS", "").split(",")
    if tok.strip()
}
_MERGE_DEBUG_LOG = os.environ.get(
    "PYGHIDRA_MERGE_DEBUG_LOG",
    "D:/BIGAI/pyghidra/temp/python_merge_debug.log",
).strip()

if TYPE_CHECKING:
    from ghidra.ir.varnode import Varnode
    from ghidra.ir.variable import HighVariable
    from ghidra.ir.op import PcodeOp
    from ghidra.analysis.funcdata import Funcdata
    from ghidra.block.block import FlowBlock, BlockBasic


def _merge_debug_should_log(addr) -> bool:
    if not _MERGE_DEBUG_LOG or not _MERGE_DEBUG_ADDRS:
        return False
    try:
        off = addr.getOffset()
    except Exception:
        return False
    return off in _MERGE_DEBUG_ADDRS


def _merge_debug_log(addr, message: str) -> None:
    if not _merge_debug_should_log(addr):
        return
    try:
        from ghidra.transform.action import Action

        idx = Action.getActiveTraceSerial()
    except Exception:
        idx = 0
    try:
        with open(_MERGE_DEBUG_LOG, "a", encoding="utf-8") as fp:
            prefix = "[merge]"
            if idx > 0:
                prefix += f" idx={idx}"
            fp.write(f"{prefix} addr={addr.getOffset():#x} {message}\n")
    except Exception:
        return


# =========================================================================
# BlockVarnode
# =========================================================================

class BlockVarnode:
    """Helper class associating a Varnode with the block where it is defined.

    If a Varnode does not have a defining PcodeOp it is assigned an index of 0.
    """

    def __init__(self) -> None:
        self._index: int = 0
        self._vn: Optional[Varnode] = None

    def set(self, v: Varnode) -> None:
        """Set this as representing the given Varnode."""
        self._vn = v
        op = v.getDef()
        if op is None:
            self._index = 0
        else:
            self._index = op.getParent().getIndex()

    def __lt__(self, op2: BlockVarnode) -> bool:
        return self._index < op2._index

    def getVarnode(self) -> Optional[Varnode]:
        return self._vn

    def getIndex(self) -> int:
        return self._index

    @staticmethod
    def findFront(blocknum: int, blist: List[BlockVarnode]) -> int:
        """Find the first BlockVarnode in sorted list with the given block index.

        Returns the index in the list, or -1 if not found.
        """
        lo = 0
        hi = len(blist) - 1
        while lo < hi:
            mid = (lo + hi) // 2
            if blist[mid].getIndex() >= blocknum:
                hi = mid
            else:
                lo = mid + 1
        if lo > hi:
            return -1
        if blist[lo].getIndex() != blocknum:
            return -1
        return lo


# =========================================================================
# StackAffectingOps
# =========================================================================

class StackAffectingOps(PcodeOpSet):
    """The set of CALL and STORE ops that might indirectly affect stack variables."""

    def __init__(self, fd: Funcdata) -> None:
        super().__init__()
        self._data: Funcdata = fd

    def populate(self) -> None:
        """Fill the set with CALL ops and guarded STORE ops."""
        for i in range(self._data.numCalls()):
            op = self._data.getCallSpecs(i).getOp()
            self.addOp(op)
        for guard in self._data.getStoreGuards():
            if guard.isValid(OpCode.CPUI_STORE):
                self.addOp(guard.getOp())
        self.finalize()

    def affectsTest(self, op: PcodeOp, vn: Varnode) -> bool:
        """Test whether the given op might affect the given Varnode through aliasing."""
        if op.code() == OpCode.CPUI_STORE:
            loadGuard = self._data.getStoreGuard(op)
            if loadGuard is None:
                return True
            return loadGuard.isGuarded(vn.getAddr())
        return True


# =========================================================================
# HighIntersectTest — use full C++ port from variable.py
# =========================================================================

from ghidra.ir.variable import HighIntersectTest


# =========================================================================
# Merge
# =========================================================================

class Merge:
    """Class for merging low-level Varnodes into high-level HighVariables.

    Handles forced merges (MULTIEQUAL, INDIRECT, address-tied, mapped stack)
    and speculative merges (same data-type, adjacent input/output).
    """

    def __init__(self, fd: Funcdata) -> None:
        self._data: Funcdata = fd
        self._stackAffectingOps = StackAffectingOps(fd)
        self._testCache = HighIntersectTest(self._stackAffectingOps)
        self._copyTrims: List[PcodeOp] = []
        self._protoPartial: List[PcodeOp] = []

    def clear(self) -> None:
        """Clear any cached data from the last merge process."""
        self._testCache.clear()
        self._copyTrims.clear()
        self._protoPartial.clear()
        self._stackAffectingOps.clear()

    # ----- Static test methods -----

    @staticmethod
    def mergeTestRequired(high_out: HighVariable, high_in: HighVariable) -> bool:
        """Required tests to merge HighVariables (not Cover related)."""
        if high_in is high_out:
            return True
        if high_in.isTypeLock() and high_out.isTypeLock():
            if high_in.getType() is not high_out.getType():
                return False
        if high_out.isAddrTied() and high_in.isAddrTied():
            if high_in.getTiedVarnode().getAddr() != high_out.getTiedVarnode().getAddr():
                return False
        if high_in.isInput():
            if high_out.isPersist():
                return False
            if high_out.isAddrTied() and not high_in.isAddrTied():
                return False
        elif high_in.isExtraOut():
            return False
        if high_out.isInput():
            if high_in.isPersist():
                return False
            if high_in.isAddrTied() and not high_out.isAddrTied():
                return False
        elif high_out.isExtraOut():
            return False
        if high_in.isProtoPartial():
            if high_out.isProtoPartial():
                return False
            if high_out.isInput():
                return False
            if high_out.isAddrTied():
                return False
            if high_out.isPersist():
                return False
        if high_out.isProtoPartial():
            if high_in.isInput():
                return False
            if high_in.isAddrTied():
                return False
            if high_in.isPersist():
                return False
        if high_in._piece is not None and high_out._piece is not None:
            group_in = high_in._piece.getGroup()
            group_out = high_out._piece.getGroup()
            if group_in is group_out:
                return False
            if high_in._piece.getSize() != group_in.getSize() and high_out._piece.getSize() != group_out.getSize():
                return False
        s_in = high_in.getSymbol()
        s_out = high_out.getSymbol()
        if s_in is not None and s_out is not None:
            if s_in is not s_out:
                return False
            if high_in.getSymbolOffset() != high_out.getSymbolOffset():
                return False
        return True

    @staticmethod
    def mergeTestAdjacent(high_out: HighVariable, high_in: HighVariable) -> bool:
        """Adjacency tests for merging input/output to same op."""
        if not Merge.mergeTestRequired(high_out, high_in):
            return False
        if high_in.isNameLock() and high_out.isNameLock():
            return False
        if high_out.getType() is not high_in.getType():
            return False
        if high_out.isInput():
            vn = high_out.getInputVarnode()
            if vn.isIllegalInput() and not vn.isIndirectOnly():
                return False
        if high_in.isInput():
            vn = high_in.getInputVarnode()
            if vn.isIllegalInput() and not vn.isIndirectOnly():
                return False
        sym = high_in.getSymbol()
        if sym is not None and sym.isIsolated():
            return False
        sym = high_out.getSymbol()
        if sym is not None and sym.isIsolated():
            return False
        if high_out._piece is not None and high_in._piece is not None:
            return False
        return True

    @staticmethod
    def mergeTestSpeculative(high_out: HighVariable, high_in: HighVariable) -> bool:
        """Speculative tests for merging HighVariables that are not Cover related."""
        if not Merge.mergeTestAdjacent(high_out, high_in):
            return False
        if high_out.isPersist():
            return False
        if high_in.isPersist():
            return False
        if high_out.isInput():
            return False
        if high_in.isInput():
            return False
        if high_out.isAddrTied():
            return False
        if high_in.isAddrTied():
            return False
        return True

    @staticmethod
    def mergeTestMust(vn: Varnode) -> None:
        """Test if vn that must be merged, can be merged. Raise if not."""
        if vn.hasCover() and not vn.isImplied():
            return
        from ghidra.core.error import LowlevelError
        raise LowlevelError("Cannot force merge of range")

    @staticmethod
    def mergeTestBasic(vn: Varnode) -> bool:
        """Test if the given Varnode can ever be merged."""
        if vn is None:
            return False
        if not vn.hasCover():
            return False
        if vn.isImplied():
            return False
        if vn.isProtoPartial():
            return False
        if vn.isSpacebase():
            return False
        return True

    @staticmethod
    def markImplied(vn: Varnode) -> None:
        """Mark the given Varnode as implied."""
        from ghidra.ir.varnode import Varnode as VnCls
        vn.setImplied()
        op = vn.getDef()
        for i in range(op.numInput()):
            defvn = op.getIn(i)
            if not defvn.hasCover():
                continue
            defvn.setFlags(VnCls.coverdirty)

    @staticmethod
    def findSingleCopy(high: HighVariable, singlelist: List[Varnode]) -> None:
        """Find instance Varnodes that are copied from outside the HighVariable."""
        for i in range(high.numInstances()):
            vn = high.getInstance(i)
            if not vn.isWritten():
                continue
            op = vn.getDef()
            if op.code() != OpCode.CPUI_COPY:
                continue
            if op.getIn(0).getHigh() is high:
                continue
            singlelist.append(vn)

    @staticmethod
    def compareHighByBlock(a: HighVariable, b: HighVariable) -> bool:
        """Compare HighVariables by the blocks they cover."""
        result = a.getCover().compareTo(b.getCover())
        if result == 0:
            v1 = a.getInstance(0)
            v2 = b.getInstance(0)
            if v1.getAddr() == v2.getAddr():
                def1 = v1.getDef()
                def2 = v2.getDef()
                if def1 is None:
                    return def2 is not None
                elif def2 is None:
                    return False
                return def1.getAddr() < def2.getAddr()
            return v1.getAddr() < v2.getAddr()
        return result < 0

    @staticmethod
    def compareCopyByInVarnode(op1: PcodeOp, op2: PcodeOp) -> bool:
        """Compare COPY ops by input Varnode, then by block."""
        inVn1 = op1.getIn(0)
        inVn2 = op2.getIn(0)
        if inVn1 is not inVn2:
            return inVn1.getCreateIndex() < inVn2.getCreateIndex()
        idx1 = op1.getParent().getIndex()
        idx2 = op2.getParent().getIndex()
        if idx1 != idx2:
            return idx1 < idx2
        return op1.getSeqNum().getOrder() < op2.getSeqNum().getOrder()

    @staticmethod
    def shadowedVarnode(vn: Varnode) -> bool:
        """Determine if vn is shadowed by another in the same HighVariable."""
        high = vn.getHigh()
        for i in range(high.numInstances()):
            othervn = high.getInstance(i)
            if othervn is vn:
                continue
            if vn.getCover().intersect(othervn.getCover()) == 2:
                return True
        return False

    @staticmethod
    def findAllIntoCopies(high: HighVariable, copyIns: List[PcodeOp], filterTemps: bool) -> None:
        """Find all COPY ops into the given HighVariable from outside."""
        from ghidra.core.space import IPTR_INTERNAL
        for i in range(high.numInstances()):
            vn = high.getInstance(i)
            if not vn.isWritten():
                continue
            op = vn.getDef()
            if op.code() != OpCode.CPUI_COPY:
                continue
            if op.getIn(0).getHigh() is high:
                continue
            if filterTemps and op.getOut().getSpace().getType() != IPTR_INTERNAL:
                continue
            copyIns.append(op)
        copyIns.sort(key=lambda o: (o.getIn(0).getCreateIndex(),
                                     o.getParent().getIndex(),
                                     o.getSeqNum().getOrder()))

    # ----- Instance merge methods -----

    def merge(self, high1: HighVariable, high2: HighVariable, isspeculative: bool) -> bool:
        """Perform low-level merge of two HighVariables if possible.

        Returns False if there is a Cover intersection.
        """
        if high1 is high2:
            return True
        if self._testCache.intersection(high1, high2):
            return False
        high1.merge(high2, self._testCache, isspeculative)
        high1.updateCover()
        return True

    def inflateTest(self, a: Varnode, high: HighVariable) -> bool:
        """Test if inflating Cover of a would cause intersections with high."""
        ahigh = a.getHigh()
        self._testCache.updateHigh(high)
        highCover = high._internalCover
        for i in range(ahigh.numInstances()):
            b = ahigh.getInstance(i)
            if b.copyShadow(a):
                continue
            if b.getCover().intersect(highCover) == 2:
                return True
        piece = ahigh._piece
        if piece is not None:
            piece.updateIntersections()
            for i in range(piece.numIntersection()):
                otherPiece = piece.getIntersection(i)
                otherHigh = otherPiece.getHigh()
                off = otherPiece.getOffset() - piece.getOffset()
                for j in range(otherHigh.numInstances()):
                    b = otherHigh.getInstance(j)
                    if b.partialCopyShadow(a, off):
                        continue
                    if b.getCover().intersect(highCover) == 2:
                        return True
        return False

    def mergeTest(self, high: HighVariable, tmplist: List[HighVariable]) -> bool:
        """Test for intersections between high and a list of others.

        If no intersections, high is added to the list and True returned.
        """
        if not high.hasCover():
            return False
        for a in tmplist:
            if self._testCache.intersection(a, high):
                return False
        tmplist.append(high)
        return True

    def snipReads(self, vn: Varnode, markedop: List[PcodeOp]) -> None:
        """Snip off set of read p-code ops for a given Varnode."""
        if not markedop:
            return
        copyop = None
        afterop = None
        if vn.isInput():
            bl = self._data.getBasicBlocks().getBlock(0)
            pc = bl.getStart()
            afterop = None
        else:
            bl = vn.getDef().getParent()
            pc = vn.getDef().getAddr()
            if vn.getDef().code() == OpCode.CPUI_INDIRECT:
                afterop = PcodeOp.getOpFromConst(vn.getDef().getIn(1).getAddr())
            else:
                afterop = vn.getDef()
        copyop = self.allocateCopyTrim(vn, pc, markedop[0])
        if afterop is None:
            _merge_debug_log(
                copyop.getAddr(),
                f"snipReads insert=begin vn={vn} block={bl.getIndex()}",
            )
            self._data.opInsertBegin(copyop, bl)
        else:
            _merge_debug_log(
                copyop.getAddr(),
                f"snipReads insert=after prev={afterop.getAddr().getOffset():#x}#{afterop.getSeqNum().getOrder()} "
                f"prev_opc={afterop.code()} vn={vn}",
            )
            self._data.opInsertAfter(copyop, afterop)
        for op in markedop:
            slot = op.getSlot(vn)
            self._data.opSetInput(op, copyop.getOut(), slot)

    def allocateCopyTrim(self, inVn: Varnode, addr, trimOp: PcodeOp):
        """Allocate COPY PcodeOp designed to trim an overextended Cover."""
        copyop = self._data.newOp(1, addr)
        self._data.opSetOpcode(copyop, OpCode.CPUI_COPY)
        ct = inVn.getType()
        if ct.needsResolution():
            if inVn.isWritten():
                fieldNum = self._data.inheritResolution(ct, copyop, -1, inVn.getDef(), -1)
                self._data.forceFacingType(ct, fieldNum, copyop, 0)
            else:
                slot = trimOp.getSlot(inVn)
                resUnion = self._data.getUnionField(ct, trimOp, slot)
                fieldNum = -1 if resUnion is None else resUnion.getFieldNum()
                self._data.forceFacingType(ct, fieldNum, copyop, 0)
        outVn = self._data.newUnique(inVn.getSize(), ct)
        self._data.opSetOutput(copyop, outVn)
        self._data.opSetInput(copyop, inVn, 0)
        self._copyTrims.append(copyop)
        return copyop

    def snipOutputInterference(self, indop: PcodeOp) -> bool:
        """Snip instances of the output of an INDIRECT that are also inputs to the underlying PcodeOp.

        Examine the output HighVariable for the given INDIRECT op. Varnode instances
        that are also inputs to the underlying PcodeOp causing the INDIRECT are snipped
        by creating a new COPY op from the Varnode to a new temporary.
        Returns True if specific instances are snipped.
        """
        effect_op = PcodeOp.getOpFromConst(indop.getIn(1).getAddr())
        correctable: list = []
        self.collectInputs(indop.getOut().getHigh(), correctable, effect_op)
        if not correctable:
            return False

        correctable.sort(key=lambda item: id(item[0].getIn(item[1]).getHigh()))
        snipop = None
        curHigh = None
        for insertop, slot in correctable:
            vn = insertop.getIn(slot)
            if vn.getHigh() is not curHigh:
                snipop = self.allocateCopyTrim(vn, insertop.getAddr(), insertop)
                self._data.opInsertBefore(snipop, insertop)
                curHigh = vn.getHigh()
            self._data.opSetInput(insertop, snipop.getOut(), slot)
        return True

    def eliminateIntersect(self, vn: Varnode, blocksort: List[BlockVarnode]) -> None:
        """Eliminate intersections of given Varnode with others in a list."""
        markedop: List[PcodeOp] = []
        for op in vn.beginDescend():
            insertop = False
            single = Cover()
            single.addDefPoint(vn)
            single.addRefPoint(op, vn)
            for blocknum, _ in single.begin():
                slot = BlockVarnode.findFront(blocknum, blocksort)
                if slot == -1:
                    continue
                while slot < len(blocksort):
                    bvn = blocksort[slot]
                    if bvn.getIndex() != blocknum:
                        break
                    vn2 = bvn.getVarnode()
                    slot += 1
                    if vn2 is vn:
                        continue
                    boundtype = single.containVarnodeDef(vn2)
                    if boundtype == 0:
                        continue
                    overlaptype = vn.characterizeOverlap(vn2)
                    if overlaptype == 0:
                        continue
                    if overlaptype == 1:
                        off = int(vn.getOffset() - vn2.getOffset())
                        if vn.partialCopyShadow(vn2, off):
                            continue
                    if boundtype == 2:
                        def2 = vn2.getDef()
                        def1 = vn.getDef()
                        if def2 is None:
                            if def1 is None:
                                if vn < vn2:
                                    continue
                            else:
                                continue
                        elif def1 is not None and def2.getSeqNum().getOrder() < def1.getSeqNum().getOrder():
                            continue
                    elif boundtype == 3:
                        if not vn2.isAddrForce():
                            continue
                        if not vn2.isWritten():
                            continue
                        indop = vn2.getDef()
                        if indop.code() != OpCode.CPUI_INDIRECT:
                            continue
                        if PcodeOp.getOpFromConst(indop.getIn(1).getAddr()) is not op:
                            continue
                        if overlaptype != 1:
                            if vn.copyShadow(indop.getIn(0)):
                                continue
                        else:
                            off = int(vn.getOffset() - vn2.getOffset())
                            if vn.partialCopyShadow(indop.getIn(0), off):
                                continue
                    insertop = True
                    break
                if insertop:
                    break
            if insertop:
                markedop.append(op)
        self.snipReads(vn, markedop)

    def unifyAddress(self, startiter: list, enditer: list) -> None:
        """Make sure all Varnodes with the same storage can be merged."""
        isectlist = []
        stop = enditer[0] if enditer else None
        for vn in startiter:
            if stop is not None and vn is stop:
                break
            if vn.isFree():
                continue
            isectlist.append(vn)
        blocksort = []
        for vn in isectlist:
            bvn = BlockVarnode()
            bvn.set(vn)
            blocksort.append(bvn)
        blocksort.sort()
        for vn in isectlist:
            self.eliminateIntersect(vn, blocksort)

    def trimOpOutput(self, op: PcodeOp) -> None:
        """Trim the output HighVariable of the given PcodeOp so its Cover is tiny.

        C++ ref: ``Merge::trimOpOutput``
        """
        if op.code() == OpCode.CPUI_INDIRECT:
            afterop = PcodeOp.getOpFromConst(op.getIn(1).getAddr())
        else:
            afterop = op
        vn = op.getOut()
        ct = vn.getType()
        copyop = self._data.newOp(1, op.getAddr())
        self._data.opSetOpcode(copyop, OpCode.CPUI_COPY)
        if ct.needsResolution():
            fieldNum = self._data.inheritResolution(ct, copyop, -1, op, -1)
            self._data.forceFacingType(ct, fieldNum, copyop, 0)
            from ghidra.types.datatype import TYPE_PARTIALUNION

            if ct.getMetatype() == TYPE_PARTIALUNION:
                ct = vn.getTypeDefFacing()
        uniq = self._data.newUnique(vn.getSize(), ct)
        self._data.opSetOutput(op, uniq)
        self._data.opSetOutput(copyop, vn)
        self._data.opSetInput(copyop, uniq, 0)
        _merge_debug_log(
            copyop.getAddr(),
            f"trimOpOutput insert=after prev={afterop.getAddr().getOffset():#x}#{afterop.getSeqNum().getOrder()} "
            f"prev_opc={afterop.code()} op={op.getAddr().getOffset():#x}#{op.getSeqNum().getOrder()} "
            f"op_opc={op.code()}",
        )
        self._data.opInsertAfter(copyop, afterop)

    def trimOpInput(self, op: PcodeOp, slot: int) -> None:
        """Trim the input HighVariable of the given PcodeOp so its Cover is tiny."""
        if op.code() == OpCode.CPUI_MULTIEQUAL:
            bb = op.getParent().getIn(slot)
            pc = bb.getStop()
        else:
            pc = op.getAddr()
        vn = op.getIn(slot)
        copyop = self.allocateCopyTrim(vn, pc, op)
        self._data.opSetInput(op, copyop.getOut(), slot)
        if op.code() == OpCode.CPUI_MULTIEQUAL:
            _merge_debug_log(
                copyop.getAddr(),
                f"trimOpInput insert=end op={op.getAddr().getOffset():#x}#{op.getSeqNum().getOrder()} slot={slot}",
            )
            self._data.opInsertEnd(copyop, bb)
        else:
            _merge_debug_log(
                copyop.getAddr(),
                f"trimOpInput insert=before op={op.getAddr().getOffset():#x}#{op.getSeqNum().getOrder()} "
                f"op_opc={op.code()} slot={slot}",
            )
            self._data.opInsertBefore(copyop, op)

    def mergeRangeMust(self, startiter: list, enditer: list) -> None:
        """Force the merge of a range of Varnodes with same size and address."""
        stop = enditer[0] if enditer else None
        vn = startiter[0]
        self.mergeTestMust(vn)
        high = vn.getHigh()
        for vn2 in startiter[1:]:
            if stop is not None and vn2 is stop:
                break
            if vn2.getHigh() is high:
                continue
            self.mergeTestMust(vn2)
            if not self.merge(high, vn2.getHigh(), False):
                from ghidra.core.error import LowlevelError
                raise LowlevelError("Forced merge caused intersection")

    def mergeOp(self, op: PcodeOp) -> None:
        """Force the merge of all input and output Varnodes for the given op."""
        maxslot = 1 if op.code() == OpCode.CPUI_INDIRECT else op.numInput()
        high_out = op.getOut().getHigh()
        # First check non-cover restrictions
        for i in range(maxslot):
            high_in = op.getIn(i).getHigh()
            if not self.mergeTestRequired(high_out, high_in):
                self.trimOpInput(op, i)
                continue
            for j in range(i):
                if not self.mergeTestRequired(op.getIn(j).getHigh(), high_in):
                    self.trimOpInput(op, i)
                    break
        # Check cover restrictions
        testlist: List[HighVariable] = []
        self.mergeTest(high_out, testlist)
        ok = True
        for i in range(maxslot):
            if not self.mergeTest(op.getIn(i).getHigh(), testlist):
                ok = False
                break
        if not ok:
            # Trim until merges work
            for nexttrim in range(maxslot):
                self.trimOpInput(op, nexttrim)
                testlist.clear()
                self.mergeTest(high_out, testlist)
                allgood = True
                for i in range(maxslot):
                    if not self.mergeTest(op.getIn(i).getHigh(), testlist):
                        allgood = False
                        break
                if allgood:
                    break
            else:
                self.trimOpOutput(op)
        # Actually merge
        from ghidra.core.error import LowlevelError

        for i in range(maxslot):
            if not self.mergeTestRequired(op.getOut().getHigh(), op.getIn(i).getHigh()):
                raise LowlevelError("Non-cover related merge restriction violated, despite trims")
            if not self.merge(op.getOut().getHigh(), op.getIn(i).getHigh(), False):
                raise LowlevelError(f"Unable to force merge of op at {op.getSeqNum()}")

    def mergeIndirect(self, indop: PcodeOp) -> None:
        """Force the merge of input and output Varnodes to a given INDIRECT op."""
        outvn = indop.getOut()
        if not outvn.isAddrForce():
            self.mergeOp(indop)
            return
        invn0 = indop.getIn(0)
        if self.mergeTestRequired(outvn.getHigh(), invn0.getHigh()):
            if self.merge(invn0.getHigh(), outvn.getHigh(), False):
                return
        if self.snipOutputInterference(indop):
            if self.mergeTestRequired(outvn.getHigh(), invn0.getHigh()):
                if self.merge(invn0.getHigh(), outvn.getHigh(), False):
                    return
        # Snip the INDIRECT itself
        copyop = self.allocateCopyTrim(invn0, indop.getAddr(), indop)
        entry = outvn.getSymbolEntry()
        if entry is not None and entry.getSymbol().getType().needsResolution():
            self._data.inheritResolution(entry.getSymbol().getType(), copyop, -1, indop, -1)
        self._data.opSetInput(indop, copyop.getOut(), 0)
        _merge_debug_log(
            copyop.getAddr(),
            f"mergeIndirect insert=before indop={indop.getAddr().getOffset():#x}#{indop.getSeqNum().getOrder()}",
        )
        self._data.opInsertBefore(copyop, indop)
        if not self.mergeTestRequired(outvn.getHigh(), indop.getIn(0).getHigh()) or \
           not self.merge(indop.getIn(0).getHigh(), outvn.getHigh(), False):
            from ghidra.core.error import LowlevelError
            raise LowlevelError("Unable to merge address forced indirect")

    def mergeLinear(self, highvec: List[HighVariable]) -> None:
        """Speculatively merge all HighVariables in the given list."""
        if len(highvec) <= 1:
            return
        for h in highvec:
            self._testCache.updateHigh(h)
        from functools import cmp_to_key

        def _compare(a, b):
            if Merge.compareHighByBlock(a, b):
                return -1
            if Merge.compareHighByBlock(b, a):
                return 1
            return 0

        highvec.sort(key=cmp_to_key(_compare))
        highstack: List[HighVariable] = []
        for high in highvec:
            for out in highstack:
                if self.mergeTestSpeculative(out, high):
                    if self.merge(out, high, True):
                        break
            else:
                highstack.append(high)

    # ----- Public merge entry points -----

    def mergeOpcode(self, opc: OpCode) -> None:
        """Try to force input/output merge for all ops of a given type."""
        bblocks = self._data.getBasicBlocks()
        for i in range(bblocks.getSize()):
            bl = bblocks.getBlock(i)
            for op in bl.beginOp():
                if op.code() != opc:
                    continue
                vn1 = op.getOut()
                if not self.mergeTestBasic(vn1):
                    continue
                for j in range(op.numInput()):
                    vn2 = op.getIn(j)
                    if not self.mergeTestBasic(vn2):
                        continue
                    if self.mergeTestRequired(vn1.getHigh(), vn2.getHigh()):
                        self.merge(vn1.getHigh(), vn2.getHigh(), False)

    def mergeByDatatype(self, varnodes: list) -> None:
        """Try to merge all HighVariables with the same data-type."""
        highlist: List[HighVariable] = []
        for vn in varnodes:
            if vn.isFree():
                continue
            high = vn.getHigh()
            if high.isMark():
                continue
            if not self.mergeTestBasic(vn):
                continue
            high.setMark()
            highlist.append(high)
        for high in highlist:
            high.clearMark()

        while highlist:
            highvec: List[HighVariable] = []
            high = highlist.pop(0)
            ct = high.getType()
            highvec.append(high)
            remaining: List[HighVariable] = []
            for other in highlist:
                if ct == other.getType():
                    highvec.append(other)
                else:
                    remaining.append(other)
            highlist = remaining
            self.mergeLinear(highvec)

    def mergeAddrTied(self) -> None:
        """Force the merge of address-tied Varnodes.

        C++ ref: ``Merge::mergeAddrTied``
        Filters by space type (processor/spacebase), collects overlapping
        ranges, unifies addresses, merges ranges, and groups overlapping highs.
        """
        from ghidra.core.space import IPTR_PROCESSOR, IPTR_SPACEBASE

        startiter = list(self._data.beginLoc())
        enditer = list(self._data.endLoc())
        while startiter != enditer:
            spc = startiter[0].getSpace()
            spc_type = spc.getType()
            if spc_type != IPTR_PROCESSOR and spc_type != IPTR_SPACEBASE:
                startiter = self._data.endLoc(spc)
                continue
            finaliter = self._data.endLoc(spc)
            while startiter != finaliter:
                vn = startiter[0]
                if vn.isFree():
                    startiter = self._data.endLoc(vn.getSize(), vn.getAddr(), 0)
                    continue
                bounds = []
                flags = self._data.overlapLoc(startiter, bounds)
                max_idx = len(bounds) - 1
                if (flags & _VN_ADDRTIED) != 0:
                    self.unifyAddress(bounds[0], bounds[max_idx])
                    for i in range(0, max_idx, 2):
                        self.mergeRangeMust(bounds[i], bounds[i + 1])
                    if max_idx > 2:
                        vn1 = bounds[0][0]
                        for i in range(2, max_idx, 2):
                            vn2 = bounds[i][0]
                            off = int(vn2.getOffset() - vn1.getOffset())
                            vn2.getHigh().groupWith(off, vn1.getHigh())
                startiter = bounds[max_idx]

    def mergeMarker(self) -> None:
        """Force the merge of input/output Varnodes to MULTIEQUAL and INDIRECT ops."""
        for op in self._data.beginOpAlive():
            if not op.isMarker() or op.isIndirectCreation():
                continue
            if op.code() == OpCode.CPUI_INDIRECT:
                self.mergeIndirect(op)
            else:
                self.mergeOp(op)

    def mergeMultiEntry(self) -> None:
        """Merge together Varnodes mapped to SymbolEntrys from the same Symbol.

        Symbols that have more than one SymbolEntry may attach to more than one
        Varnode. These Varnodes need to be merged to properly represent a single variable.
        """
        scope = self._data.getScopeLocal()
        for symbol in scope.beginMultiEntry():
            mergeList: List[Varnode] = []
            numEntries = symbol.numEntries()
            mergeCount = 0
            skipCount = 0
            conflictCount = 0
            for i in range(numEntries):
                prevSize = len(mergeList)
                entry = symbol.getMapEntry(i)
                if entry.getSize() != symbol.getType().getSize():
                    continue
                self._data.findLinkedVarnodes(entry, mergeList)
                if len(mergeList) == prevSize:
                    skipCount += 1
            if not mergeList:
                continue
            high = mergeList[0].getHigh()
            self._testCache.updateHigh(high)
            for i in range(len(mergeList)):
                newHigh = mergeList[i].getHigh()
                if newHigh is high:
                    continue
                self._testCache.updateHigh(newHigh)
                if not self.mergeTestRequired(high, newHigh):
                    symbol.setMergeProblems()
                    newHigh.setUnmerged()
                    conflictCount += 1
                    continue
                if not self.merge(high, newHigh, False):
                    symbol.setMergeProblems()
                    newHigh.setUnmerged()
                    conflictCount += 1
                    continue
                mergeCount += 1
            if skipCount != 0 or conflictCount != 0:
                msg = 'Unable to'
                if mergeCount != 0:
                    msg += ' fully'
                msg += f' merge symbol: {symbol.getName()}'
                if skipCount > 0:
                    msg += ' -- Some instance varnodes not found.'
                if conflictCount > 0:
                    msg += ' -- Some merges are forbidden'
                self._data.warningHeader(msg)

    def groupPartials(self) -> None:
        """Run through CONCAT tree roots and group each tree."""
        for op in self._protoPartial:
            if op.isDead():
                continue
            if not op.isPartialRoot():
                continue
            self.groupPartialRoot(op.getOut())

    def groupPartialRoot(self, vn: Varnode) -> None:
        """Group the different nodes of a CONCAT tree into a VariableGroup.

        This formally labels all the Varnodes in the tree as overlapping pieces
        of the same variable. The tree is reconstructed from the root Varnode.
        """
        high = vn.getHigh()
        if high.numInstances() != 1:
            return

        baseOffset = 0
        entry = vn.getSymbolEntry()
        if entry is not None:
            baseOffset = entry.getOffset()

        pieces: list[PieceNode] = []
        PieceNode.gatherPieces(pieces, vn, vn.getDef(), baseOffset, baseOffset)

        throwOut = False
        for piece in pieces:
            nodeVn = piece.getVarnode()
            if not nodeVn.isProtoPartial() or nodeVn.getHigh().numInstances() != 1:
                throwOut = True
                break

        if throwOut:
            for piece in pieces:
                piece.getVarnode().clearProtoPartial()
        else:
            for piece in pieces:
                nodeVn = piece.getVarnode()
                nodeVn.getHigh().groupWith(piece.getTypeOffset() - baseOffset, high)

    def mergeAdjacent(self) -> None:
        """Speculatively merge Varnodes that are input/output to the same p-code op."""
        for op in self._data.beginOpAlive():
            if op.isCall():
                continue
            vn1 = op.getOut()
            if not self.mergeTestBasic(vn1):
                continue
            high_out = vn1.getHigh()
            ct = op.outputTypeLocal()
            for i in range(op.numInput()):
                if ct is not op.inputTypeLocal(i):
                    continue
                vn2 = op.getIn(i)
                if not self.mergeTestBasic(vn2):
                    continue
                if vn1.getSize() != vn2.getSize():
                    continue
                if vn2.getDef() is None and not vn2.isInput():
                    continue
                high_in = vn2.getHigh()
                if not self.mergeTestAdjacent(high_out, high_in):
                    continue
                if not self._testCache.intersection(high_in, high_out):
                    self.merge(high_out, high_in, True)

    def hideShadows(self, high: HighVariable) -> bool:
        """Hide shadow Varnodes by consolidating COPY chains."""
        singlelist: List[Varnode] = []
        self.findSingleCopy(high, singlelist)
        if len(singlelist) <= 1:
            return False
        res = False
        for i in range(len(singlelist) - 1):
            vn1 = singlelist[i]
            if vn1 is None:
                continue
            for j in range(i + 1, len(singlelist)):
                vn2 = singlelist[j]
                if vn2 is None:
                    continue
                if not vn1.copyShadow(vn2):
                    continue
                if vn2.getCover().containVarnodeDef(vn1) == 1:
                    self._data.opSetInput(vn1.getDef(), vn2, 0)
                    res = True
                    break
                if vn1.getCover().containVarnodeDef(vn2) == 1:
                    self._data.opSetInput(vn2.getDef(), vn1, 0)
                    singlelist[j] = None
                    res = True
        return res

    def processCopyTrims(self) -> None:
        """Try to reduce/eliminate COPYs produced by the merge trimming process."""
        multiCopy: List[HighVariable] = []
        for i in range(len(self._copyTrims)):
            high = self._copyTrims[i].getOut().getHigh()
            if not high.hasCopyIn1():
                multiCopy.append(high)
                high.setCopyIn1()
            else:
                high.setCopyIn2()
        self._copyTrims.clear()
        for i in range(len(multiCopy)):
            high = multiCopy[i]
            if high.hasCopyIn2():
                self.processHighDominantCopy(high)
            high.clearCopyIns()

    def markInternalCopies(self) -> None:
        """Mark redundant/internal COPY PcodeOps."""
        multiCopy: List[HighVariable] = []
        for op in self._data.beginOpAlive():
            opc = op.code()
            if opc == OpCode.CPUI_COPY:
                v1 = op.getOut()
                h1 = v1.getHigh()
                if h1 is op.getIn(0).getHigh():
                    self._data.opMarkNonPrinting(op)
                else:
                    if not h1.hasCopyIn1():
                        h1.setCopyIn1()
                        multiCopy.append(h1)
                    else:
                        h1.setCopyIn2()
                    if v1.hasNoDescend() and self.shadowedVarnode(v1):
                        self._data.opMarkNonPrinting(op)
            elif opc == OpCode.CPUI_PIECE:
                v1 = op.getOut()
                v2 = op.getIn(0)
                v3 = op.getIn(1)
                p1 = v1.getHigh()._piece
                p2 = v2.getHigh()._piece
                p3 = v3.getHigh()._piece
                if p1 is None or p2 is None or p3 is None:
                    continue
                if p1.getGroup() != p2.getGroup():
                    continue
                if p1.getGroup() != p3.getGroup():
                    continue
                if v1.getSpace().isBigEndian():
                    if p2.getOffset() != p1.getOffset():
                        continue
                    if p3.getOffset() != p1.getOffset() + v2.getSize():
                        continue
                else:
                    if p3.getOffset() != p1.getOffset():
                        continue
                    if p2.getOffset() != p1.getOffset() + v3.getSize():
                        continue
                self._data.opMarkNonPrinting(op)
                if v2.isImplied():
                    v2.clearImplied()
                    v2.setExplicit()
                if v3.isImplied():
                    v3.clearImplied()
                    v3.setExplicit()
            elif opc == OpCode.CPUI_SUBPIECE:
                v1 = op.getOut()
                v2 = op.getIn(0)
                p1 = v1.getHigh()._piece
                p2 = v2.getHigh()._piece
                if p1 is None or p2 is None:
                    continue
                if p1.getGroup() != p2.getGroup():
                    continue
                val = op.getIn(1).getOffset()
                if v1.getSpace().isBigEndian():
                    if p2.getOffset() + (v2.getSize() - v1.getSize() - val) != p1.getOffset():
                        continue
                else:
                    if p2.getOffset() + val != p1.getOffset():
                        continue
                self._data.opMarkNonPrinting(op)
                if v2.isImplied():
                    v2.clearImplied()
                    v2.setExplicit()
        for high in multiCopy:
            if high.hasCopyIn2():
                self._data.getMerge().processHighRedundantCopy(high)
            high.clearCopyIns()

    def registerProtoPartialRoot(self, vn: Varnode) -> None:
        """Register an unmapped CONCAT stack with the merge process."""
        self._protoPartial.append(vn.getDef())

    def checkCopyPair(self, high: HighVariable, domOp: PcodeOp, subOp: PcodeOp) -> bool:
        """Check if the given COPY ops are redundant."""
        domBlock = domOp.getParent()
        subBlock = subOp.getParent()
        if not domBlock.dominates(subBlock):
            return False
        range_ = Cover()
        range_.addDefPoint(domOp.getOut())
        range_.addRefPoint(subOp, subOp.getIn(0))
        inVn = domOp.getIn(0)
        for i in range(high.numInstances()):
            vn = high.getInstance(i)
            if not vn.isWritten():
                continue
            op = vn.getDef()
            if op.code() == OpCode.CPUI_COPY:
                if op.getIn(0) is inVn:
                    continue
            if range_.contain(op, 1):
                return False
        return True

    def buildDominantCopy(self, high: HighVariable, copy: List[PcodeOp], pos: int, size: int) -> None:
        """Try to replace a set of COPYs from the same Varnode with a single dominant COPY.

        All COPY outputs must be instances of the same HighVariable. Either an existing COPY
        dominates all the others, or a new dominating COPY is constructed. Replacement only
        happens with COPY outputs that are temporary registers.
        """
        from ghidra.block.block import FlowBlock
        blockSet = [copy[pos + i].getParent() for i in range(size)]
        domBl = FlowBlock.findCommonBlock(blockSet)
        domCopy = copy[pos]
        rootVn = domCopy.getIn(0)
        domVn = domCopy.getOut()
        if domBl is domCopy.getParent():
            domCopyIsNew = False
        else:
            domCopyIsNew = True
            oldCopy = domCopy
            domCopy = self._data.newOp(1, domBl.getStop())
            self._data.opSetOpcode(domCopy, OpCode.CPUI_COPY)
            ct = rootVn.getType()
            if ct.needsResolution():
                resUnion = self._data.getUnionField(ct, oldCopy, 0)
                fieldNum = -1 if resUnion is None else resUnion.getFieldNum()
                self._data.forceFacingType(ct, fieldNum, domCopy, 0)
                self._data.forceFacingType(ct, fieldNum, domCopy, -1)
                from ghidra.types.datatype import TYPE_PARTIALUNION

                if ct.getMetatype() == TYPE_PARTIALUNION:
                    ct = rootVn.getTypeReadFacing(oldCopy)
            domVn = self._data.newUnique(rootVn.getSize(), ct)
            self._data.opSetOutput(domCopy, domVn)
            self._data.opSetInput(domCopy, rootVn, 0)
            self._data.opInsertEnd(domCopy, domBl)

        bCover = Cover()
        for i in range(high.numInstances()):
            vn = high.getInstance(i)
            if vn.isWritten():
                op = vn.getDef()
                if op.code() == OpCode.CPUI_COPY:
                    if op.getIn(0).copyShadow(rootVn):
                        continue
            bCover.merge(vn.getCover())

        count = size
        for i in range(size):
            op = copy[pos + i]
            if op is domCopy:
                continue
            outVn = op.getOut()
            aCover = Cover()
            aCover.addDefPoint(domVn)
            for desc_op in outVn.beginDescend():
                aCover.addRefPoint(desc_op, outVn)
            if bCover.intersect(aCover) > 1:
                count -= 1
                op.setMark()

        if count <= 1:
            for i in range(size):
                copy[pos + i].setMark()
            count = 0
            if domCopyIsNew:
                self._data.opDestroy(domCopy)

        for i in range(size):
            op = copy[pos + i]
            if op.isMark():
                op.clearMark()
            else:
                outVn = op.getOut()
                if outVn is not domVn:
                    outVn.getHigh().remove(outVn)
                    self._data.totalReplace(outVn, domVn)
                    self._data.opDestroy(op)
        if count > 0 and domCopyIsNew:
            high.merge(domVn.getHigh(), None, True)

    def markRedundantCopies(self, high: HighVariable, copy: List[PcodeOp], pos: int, size: int) -> None:
        """Mark redundant COPY ops as non-printing."""
        for i in range(size - 1, 0, -1):
            subOp = copy[pos + i]
            if subOp.isDead():
                continue
            for j in range(i - 1, -1, -1):
                domOp = copy[pos + j]
                if domOp.isDead():
                    continue
                if self.checkCopyPair(high, domOp, subOp):
                    self._data.opMarkNonPrinting(subOp)
                    break

    def processHighDominantCopy(self, high: HighVariable) -> None:
        """Try to replace COPYs into the given HighVariable with a single dominant COPY."""
        copyIns: List[PcodeOp] = []
        self.findAllIntoCopies(high, copyIns, True)
        if len(copyIns) < 2:
            return
        pos = 0
        while pos < len(copyIns):
            inVn = copyIns[pos].getIn(0)
            sz = 1
            while pos + sz < len(copyIns) and copyIns[pos + sz].getIn(0) is inVn:
                sz += 1
            if sz > 1:
                self.buildDominantCopy(high, copyIns, pos, sz)
            pos += sz

    def processHighRedundantCopy(self, high: HighVariable) -> None:
        """Mark COPY ops into the given HighVariable that are redundant."""
        copyIns: List[PcodeOp] = []
        self.findAllIntoCopies(high, copyIns, False)
        if len(copyIns) < 2:
            return
        pos = 0
        while pos < len(copyIns):
            inVn = copyIns[pos].getIn(0)
            sz = 1
            while pos + sz < len(copyIns) and copyIns[pos + sz].getIn(0) is inVn:
                sz += 1
            if sz > 1:
                self.markRedundantCopies(high, copyIns, pos, sz)
            pos += sz

    def getTestCount(self) -> int:
        return self._testcount if hasattr(self, '_testcount') else 0

    def getStackAffectingOps(self) -> list:
        return self._stackAffectingOps if hasattr(self, '_stackAffectingOps') else []

    def getNumHighMerges(self) -> int:
        return self._numHighMerges if hasattr(self, '_numHighMerges') else 0

    def verifyHighCovers(self) -> None:
        """Verify that all HighVariable covers are consistent (debug method).

        For each HighVariable, make sure there are no internal intersections
        between its instance Varnodes (unless one is a COPY shadow of the other).

        C++ ref: ``Merge::verifyHighCovers``
        """
        _enditer = self._data.endLoc()
        for vn in self._data.beginLoc():
            if vn.hasCover():
                high = vn.getHigh()
                if not high.hasCopyIn1():
                    high.setCopyIn1()
                    high.verifyCover()

    def collectInputs(self, high: HighVariable, oplist: list, op: PcodeOp) -> None:
        """Collect Varnode instances from a HighVariable that are inputs to a given PcodeOp."""
        group = None
        if high._piece is not None:
            group = high._piece.getGroup()
        while True:
            for i in range(op.numInput()):
                vn = op.getIn(i)
                if vn.isAnnotation():
                    continue
                testHigh = vn.getHigh()
                testPiece = testHigh._piece
                if testHigh is high or (testPiece is not None and testPiece.getGroup() == group):
                    oplist.append((op, i))
            op = op.previousOp()
            if op is None or op.code() != OpCode.CPUI_INDIRECT:
                break
