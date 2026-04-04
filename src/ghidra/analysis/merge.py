"""
Corresponds to: merge.hh / merge.cc

Utilities for merging low-level Varnodes into high-level variables.
"""

from __future__ import annotations
from typing import TYPE_CHECKING, Optional, List, Tuple
from bisect import bisect_left

from ghidra.ir.cover import Cover, PcodeOpSet
from ghidra.ir.op import PcodeOp
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

if TYPE_CHECKING:
    from ghidra.ir.varnode import Varnode
    from ghidra.ir.variable import HighVariable
    from ghidra.ir.op import PcodeOp
    from ghidra.analysis.funcdata import Funcdata
    from ghidra.block.block import FlowBlock, BlockBasic


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
            parent = op.getParent()
            self._index = parent.getIndex() if parent is not None else 0

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
            fc = self._data.getCallSpecs(i)
            if fc is not None:
                self.addOp(fc.getOp())
        # Store guards if available
        if hasattr(self._data, 'getStoreGuards'):
            for guard in self._data.getStoreGuards():
                if hasattr(guard, 'isValid') and guard.isValid(OpCode.CPUI_STORE):
                    self.addOp(guard.getOp())
        self.finalize()

    def affectsTest(self, op: PcodeOp, vn: Varnode) -> bool:
        """Test whether the given op might affect the given Varnode through aliasing."""
        if op.code() == OpCode.CPUI_STORE:
            if hasattr(self._data, 'getStoreGuard'):
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
        self._stackAffectingOps.clear() if hasattr(self._stackAffectingOps, 'clear') else None

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
            t1 = high_out.getTiedVarnode()
            t2 = high_in.getTiedVarnode()
            if t1 is not None and t2 is not None and t1.getAddr() != t2.getAddr():
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
            if vn is not None and vn.isIllegalInput() and not vn.isIndirectOnly():
                return False
        if high_in.isInput():
            vn = high_in.getInputVarnode()
            if vn is not None and vn.isIllegalInput() and not vn.isIndirectOnly():
                return False
        sym = high_in.getSymbol()
        if sym is not None and sym.isIsolated():
            return False
        sym = high_out.getSymbol()
        if sym is not None and sym.isIsolated():
            return False
        return True

    @staticmethod
    def mergeTestSpeculative(hi: HighVariable, ho: HighVariable) -> bool:
        """Speculative tests — inlines required+adjacent+speculative using direct flag bits."""
        if hi is ho:
            return True
        # Ensure flags are up to date (inline dirty check)
        if hi._highflags & _HV_FLAGSDIRTY:
            hi._updateFlags()
        if ho._highflags & _HV_FLAGSDIRTY:
            ho._updateFlags()
        fi = hi._flags
        fo = ho._flags
        # --- speculative: neither can be input, persist, or addr-tied ---
        if fi & _SPEC_EXCL or fo & _SPEC_EXCL:
            return False
        # --- required: typeLock type equality ---
        if fi & _VN_TYPELOCK and fo & _VN_TYPELOCK:
            if hi._highflags & _HV_TYPEDIRTY: hi._updateType()
            if ho._highflags & _HV_TYPEDIRTY: ho._updateType()
            if hi._type is not ho._type:
                return False
        # isAddrTied excluded above → skip tied-varnode check
        # isInput excluded above → isExtraOut branch runs for both
        if (fi & _EXTRAOUT_MASK) == _VN_INDIRECT_CREATE:
            return False
        if (fo & _EXTRAOUT_MASK) == _VN_INDIRECT_CREATE:
            return False
        # proto_partial: if both partial → no merge
        if fi & _VN_PROTO_PARTIAL and fo & _VN_PROTO_PARTIAL:
            return False
        # (proto_partial other subconditions excluded by isInput/isAddrTied/isPersist above)
        # --- symbol check ---
        if hi._highflags & _HV_SYMBOLDIRTY: hi._updateSymbol()
        if ho._highflags & _HV_SYMBOLDIRTY: ho._updateSymbol()
        s_in = hi._symbol
        s_out = ho._symbol
        if s_in is not None and s_out is not None:
            if s_in is not s_out:
                return False
            if hi._symboloffset != ho._symboloffset:
                return False
        # --- adjacent: namelock both ---
        if fi & _VN_NAMELOCK and fo & _VN_NAMELOCK:
            return False
        # --- adjacent: type equality ---
        if hi._highflags & _HV_TYPEDIRTY: hi._updateType()
        if ho._highflags & _HV_TYPEDIRTY: ho._updateType()
        if hi._type is not ho._type:
            return False
        # isInput excluded → skip getInputVarnode illegalInput check
        if s_in is not None and s_in.isIsolated():
            return False
        if s_out is not None and s_out.isIsolated():
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
        if op is None:
            return
        for i in range(op.numInput()):
            defvn = op.getIn(i)
            if defvn is None or not defvn.hasCover():
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
            in0 = op.getIn(0)
            if in0 is None:
                continue
            if in0.getHigh() is high:
                continue
            singlelist.append(vn)

    @staticmethod
    def compareHighByBlock(a: HighVariable, b: HighVariable) -> bool:
        """Compare HighVariables by the blocks they cover."""
        ca = a.getCover() if hasattr(a, 'getCover') else None
        cb = b.getCover() if hasattr(b, 'getCover') else None
        if ca is not None and cb is not None and hasattr(ca, 'compareTo'):
            result = ca.compareTo(cb)
        else:
            result = 0
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
        idx1 = op1.getParent().getIndex() if op1.getParent() else 0
        idx2 = op2.getParent().getIndex() if op2.getParent() else 0
        if idx1 != idx2:
            return idx1 < idx2
        return op1.getSeqNum().getOrder() < op2.getSeqNum().getOrder()

    @staticmethod
    def shadowedVarnode(vn: Varnode) -> bool:
        """Determine if vn is shadowed by another in the same HighVariable."""
        high = vn.getHigh()
        if high is None:
            return False
        for i in range(high.numInstances()):
            othervn = high.getInstance(i)
            if othervn is vn:
                continue
            c1 = vn.getCover()
            c2 = othervn.getCover()
            if c1 is not None and c2 is not None and c1.intersect(c2) == 2:
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
            _in0 = op.getIn(0)
            if _in0 is None:
                continue
            if _in0.getHigh() is high:
                continue
            if filterTemps and op.getOut().getSpace() is not None:
                if op.getOut().getSpace().getType() != IPTR_INTERNAL:
                    continue
            copyIns.append(op)
        copyIns.sort(key=lambda o: (o.getIn(0).getCreateIndex(),
                                     o.getParent().getIndex() if o.getParent() else 0,
                                     o.getSeqNum().getOrder()))

    # ----- Instance merge methods -----

    def merge(self, high1: HighVariable, high2: HighVariable, isspeculative: bool) -> bool:
        """Perform low-level merge of two HighVariables if possible.

        Returns False if there is a Cover intersection.
        """
        if high1 is high2:
            return True
        if isspeculative:
            if high1._highflags & _HV_FLAGSDIRTY:
                high1._updateFlags()
            if high2._highflags & _HV_FLAGSDIRTY:
                high2._updateFlags()
            # Fast path: both highs are "clean" (no exclusion flags, no symbol)
            if high1._spec_ok and high2._spec_ok:
                if high1._highflags & _HV_TYPEDIRTY: high1._updateType()
                if high2._highflags & _HV_TYPEDIRTY: high2._updateType()
                if high1._type is not high2._type:
                    return False
            else:
                # Full speculative test
                fi = high1._flags; fo = high2._flags
                if fi & _SPEC_EXCL or fo & _SPEC_EXCL:
                    return False
                if (fi & _EXTRAOUT_MASK) == _VN_INDIRECT_CREATE:
                    return False
                if (fo & _EXTRAOUT_MASK) == _VN_INDIRECT_CREATE:
                    return False
                if fi & _VN_PROTO_PARTIAL and fo & _VN_PROTO_PARTIAL:
                    return False
                if fi & _VN_TYPELOCK and fo & _VN_TYPELOCK:
                    if high1._highflags & _HV_TYPEDIRTY: high1._updateType()
                    if high2._highflags & _HV_TYPEDIRTY: high2._updateType()
                    if high1._type is not high2._type:
                        return False
                if high1._highflags & _HV_SYMBOLDIRTY: high1._updateSymbol()
                if high2._highflags & _HV_SYMBOLDIRTY: high2._updateSymbol()
                s1 = high1._symbol; s2 = high2._symbol
                if s1 is not None and s2 is not None:
                    if s1 is not s2:
                        return False
                    if high1._symboloffset != high2._symboloffset:
                        return False
                if fi & _VN_NAMELOCK and fo & _VN_NAMELOCK:
                    return False
                if high1._highflags & _HV_TYPEDIRTY: high1._updateType()
                if high2._highflags & _HV_TYPEDIRTY: high2._updateType()
                if high1._type is not high2._type:
                    return False
                if s1 is not None and s1.isIsolated():
                    return False
                if s2 is not None and s2.isIsolated():
                    return False
        if self._testCache.intersection(high1, high2):
            return False
        high1.merge(high2, self._testCache, isspeculative)
        high1.updateCover()
        return True

    def inflateTest(self, a: Varnode, high: HighVariable) -> bool:
        """Test if inflating Cover of a would cause intersections with high."""
        self._testCache.updateHigh(high)
        ahigh = a.getHigh()
        if ahigh is None:
            return False
        for i in range(ahigh.numInstances()):
            b = ahigh.getInstance(i)
            if b.copyShadow(a):
                continue
            bc = b.getCover()
            hc = high.getCover() if hasattr(high, 'getCover') else None
            if bc is not None and hc is not None:
                if bc.intersect(hc) == 2:
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
        # Insert a COPY to isolate reads
        afterop = None
        if vn.isInput():
            bl = self._data.getBasicBlocks().getBlock(0) if hasattr(self._data, 'getBasicBlocks') else None
            pc = bl.getStart() if bl is not None else vn.getAddr()
        else:
            bl = vn.getDef().getParent()
            pc = vn.getDef().getAddr()
            if vn.getDef().code() == OpCode.CPUI_INDIRECT:
                iop_vn = vn.getDef().getIn(1)
                if iop_vn is not None and hasattr(PcodeOp, 'getOpFromConst'):
                    afterop = PcodeOp.getOpFromConst(iop_vn.getAddr())
            if afterop is None:
                afterop = vn.getDef()
        copyop = self._allocateCopyTrim(vn, pc, markedop[0])
        if copyop is None:
            return
        if vn.isInput():
            if hasattr(self._data, 'opInsertBegin') and bl is not None:
                self._data.opInsertBegin(copyop, bl)
        else:
            if hasattr(self._data, 'opInsertAfter'):
                self._data.opInsertAfter(copyop, afterop)
        # Replace reads
        for op in markedop:
            slot = op.getSlot(vn)
            if hasattr(self._data, 'opSetInput'):
                self._data.opSetInput(op, copyop.getOut(), slot)

    def _allocateCopyTrim(self, inVn: Varnode, addr, trimOp: PcodeOp):
        """Allocate COPY PcodeOp designed to trim an overextended Cover."""
        if not hasattr(self._data, 'newOp'):
            return None
        copyop = self._data.newOp(1, addr)
        self._data.opSetOpcode(copyop, OpCode.CPUI_COPY)
        ct = inVn.getType()
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
        if not hasattr(indop, 'getIn') or indop.numInput() < 2:
            return False
        # Get the op causing the indirect effect
        from ghidra.ir.op import PcodeOp as PcodeOpCls
        if hasattr(PcodeOpCls, 'getOpFromConst'):
            effect_op = PcodeOpCls.getOpFromConst(indop.getIn(1).getAddr())
        else:
            return False
        if effect_op is None:
            return False
        # Collect instances of output->high that are inputs to effect_op
        correctable: list = []
        out_high = indop.getOut().getHigh()
        if out_high is None:
            return False
        self.collectInputs(out_high, correctable, effect_op)
        if not correctable:
            return False
        # Sort by high variable
        correctable.sort(key=lambda x: id(x[0].getIn(x[1]).getHigh()) if x[0].getIn(x[1]).getHigh() else 0)
        snipop = None
        curHigh = None
        for insertop, slot in correctable:
            vn = insertop.getIn(slot)
            if vn.getHigh() is not curHigh:
                snipop = self._allocateCopyTrim(vn, insertop.getAddr(), insertop)
                if snipop is not None and hasattr(self._data, 'opInsertBefore'):
                    self._data.opInsertBefore(snipop, insertop)
                curHigh = vn.getHigh()
            if snipop is not None and hasattr(self._data, 'opSetInput'):
                self._data.opSetInput(insertop, snipop.getOut(), slot)
        return True

    def eliminateIntersect(self, vn: Varnode, blocksort: List[BlockVarnode]) -> None:
        """Eliminate intersections of given Varnode with others in a list."""
        markedop: List[PcodeOp] = []
        for op in list(vn.getDescendants()):
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
                                if vn.getCreateIndex() < vn2.getCreateIndex():
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
                        if indop is None or indop.code() != OpCode.CPUI_INDIRECT:
                            continue
                        effect_op = None
                        if hasattr(PcodeOp, 'getOpFromConst'):
                            effect_op = PcodeOp.getOpFromConst(indop.getIn(1).getAddr())
                        if effect_op is not op:
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

    def unifyAddress(self, varnodes: list) -> None:
        """Make sure all Varnodes with the same storage can be merged."""
        isectlist = [vn for vn in varnodes if not vn.isFree()]
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
        if not hasattr(self._data, 'newOp'):
            return
        if op.code() == OpCode.CPUI_INDIRECT:
            # Insert copyop AFTER the source of the indirect
            afterop = None
            if op.numInput() > 1:
                iop_vn = op.getIn(1)
                if hasattr(PcodeOp, 'getOpFromConst') and iop_vn is not None:
                    afterop = PcodeOp.getOpFromConst(iop_vn.getAddr())
            if afterop is None:
                afterop = op
        else:
            afterop = op
        vn = op.getOut()
        ct = vn.getType()
        copyop = self._data.newOp(1, op.getAddr())
        self._data.opSetOpcode(copyop, OpCode.CPUI_COPY)
        if ct is not None and hasattr(ct, 'needsResolution') and ct.needsResolution():
            if hasattr(self._data, 'inheritResolution'):
                fieldNum = self._data.inheritResolution(ct, copyop, -1, op, -1)
                if hasattr(self._data, 'forceFacingType'):
                    self._data.forceFacingType(ct, fieldNum, copyop, 0)
            if hasattr(ct, 'getMetatype'):
                from ghidra.types.datatype import TYPE_PARTIALUNION
                if ct.getMetatype() == TYPE_PARTIALUNION:
                    ct = vn.getTypeDefFacing() if hasattr(vn, 'getTypeDefFacing') else ct
        uniq = self._data.newUnique(vn.getSize(), ct)
        self._data.opSetOutput(op, uniq)
        self._data.opSetOutput(copyop, vn)
        self._data.opSetInput(copyop, uniq, 0)
        if hasattr(self._data, 'opInsertAfter'):
            self._data.opInsertAfter(copyop, afterop)

    def trimOpInput(self, op: PcodeOp, slot: int) -> None:
        """Trim the input HighVariable of the given PcodeOp so its Cover is tiny."""
        if not hasattr(self._data, 'newOp'):
            return
        if op.code() == OpCode.CPUI_MULTIEQUAL:
            inbl = op.getParent().getIn(slot)
            pc = inbl.getStop()
        else:
            inbl = None
            pc = op.getAddr()
        vn = op.getIn(slot)
        copyop = self._allocateCopyTrim(vn, pc, op)
        if copyop is None:
            return
        if hasattr(self._data, 'opSetInput'):
            self._data.opSetInput(op, copyop.getOut(), slot)
        if op.code() == OpCode.CPUI_MULTIEQUAL:
            if hasattr(self._data, 'opInsertEnd') and inbl is not None:
                self._data.opInsertEnd(copyop, inbl)
        elif hasattr(self._data, 'opInsertBefore'):
            self._data.opInsertBefore(copyop, op)

    def mergeRangeMust(self, varnodes: list) -> None:
        """Force the merge of a range of Varnodes with same size and address."""
        if not varnodes:
            return
        vn = varnodes[0]
        self.mergeTestMust(vn)
        high = vn.getHigh()
        for vn2 in varnodes[1:]:
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
        for i in range(maxslot):
            self.merge(op.getOut().getHigh(), op.getIn(i).getHigh(), False)

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
        # Fall back to snipping
        self.snipOutputInterference(indop)
        if self.mergeTestRequired(outvn.getHigh(), invn0.getHigh()):
            if self.merge(invn0.getHigh(), outvn.getHigh(), False):
                return
        # Snip the INDIRECT itself
        copyop = self._allocateCopyTrim(invn0, indop.getAddr(), indop)
        if copyop is not None and hasattr(self._data, 'opSetInput'):
            self._data.opSetInput(indop, copyop.getOut(), 0)
            if hasattr(self._data, 'opInsertBefore'):
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
        def _compareHighByBlock(h):
            """Sort key matching C++ Merge::compareHighByBlock."""
            cover = h.getCover() if hasattr(h, 'getCover') else None
            # Primary: cover compareTo order
            cover_key = cover.compareTo_key() if cover is not None and hasattr(cover, 'compareTo_key') else 0
            # Secondary: first instance address and def address
            v = h.getInstance(0) if hasattr(h, 'getInstance') and h.numInstances() > 0 else None
            addr_key = (v.getAddr().getSpace().getIndex() if v and v.getAddr().getSpace() else 0,
                        v.getAddr().getOffset() if v else 0) if v else (0, 0)
            defop = v.getDef() if v else None
            def_key = (0, defop.getAddr().getSpace().getIndex() if defop and defop.getAddr().getSpace() else 0,
                       defop.getAddr().getOffset() if defop else 0) if defop else (1, 0, 0)
            return (cover_key, addr_key, def_key)
        try:
            highvec.sort(key=_compareHighByBlock)
        except Exception:
            highvec.sort(key=lambda h: id(h))  # Fallback if cover comparison not available
        highstack: List[HighVariable] = []
        for high in highvec:
            merged = False
            for out in highstack:
                if self.merge(out, high, True):
                    merged = True
                    break
            if not merged:
                highstack.append(high)

    # ----- Public merge entry points -----

    def mergeOpcode(self, opc: OpCode) -> None:
        """Try to force input/output merge for all ops of a given type."""
        if not hasattr(self._data, 'getBasicBlocks'):
            return
        bblocks = self._data.getBasicBlocks()
        for i in range(bblocks.getSize()):
            bl = bblocks.getBlock(i)
            if not hasattr(bl, 'beginOp'):
                continue
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
        seen = set()
        for vn in varnodes:
            if vn.isFree():
                continue
            high = vn.getHigh()
            if high is None or id(high) in seen:
                continue
            if not self.mergeTestBasic(vn):
                continue
            seen.add(id(high))
            highlist.append(high)
        # Group by datatype
        groups: dict = {}
        for high in highlist:
            ct = high.getType()
            key = id(ct)
            if key not in groups:
                groups[key] = []
            groups[key].append(high)
        for group in groups.values():
            self.mergeLinear(group)

    def mergeAddrTied(self) -> None:
        """Force the merge of address-tied Varnodes.

        C++ ref: ``Merge::mergeAddrTied``
        Filters by space type (processor/spacebase), collects overlapping
        ranges, unifies addresses, merges ranges, and groups overlapping highs.
        """
        from ghidra.core.space import IPTR_PROCESSOR, IPTR_SPACEBASE
        if not hasattr(self._data, 'beginLoc'):
            return
        # Group by space, then collect overlapping ranges
        space_groups: dict = {}
        for vn in self._data.beginLoc():
            if vn.isFree():
                continue
            spc = vn.getSpace()
            if spc is None:
                continue
            stype = spc.getType() if hasattr(spc, 'getType') else -1
            if stype != IPTR_PROCESSOR and stype != IPTR_SPACEBASE:
                continue
            spc_id = id(spc)
            if spc_id not in space_groups:
                space_groups[spc_id] = []
            space_groups[spc_id].append(vn)
        for vn_list in space_groups.values():
            # Sort by (offset, size) to find overlapping ranges
            vn_list.sort(key=lambda v: (v.getOffset(), v.getSize()))
            i = 0
            while i < len(vn_list):
                vn = vn_list[i]
                if vn.isFree():
                    i += 1
                    continue
                # Collect maximally overlapping range
                maxOff = vn.getOffset() + vn.getSize() - 1
                has_addrtied = vn.isAddrTied()
                group = [vn]
                j = i + 1
                while j < len(vn_list):
                    vn2 = vn_list[j]
                    if vn2.isFree():
                        j += 1
                        continue
                    if vn2.getOffset() > maxOff:
                        break
                    endOff = vn2.getOffset() + vn2.getSize() - 1
                    if endOff > maxOff:
                        maxOff = endOff
                    if vn2.isAddrTied():
                        has_addrtied = True
                    group.append(vn2)
                    j += 1
                if has_addrtied and len(group) > 1:
                    self.unifyAddress(group)
                    self.mergeRangeMust(group)
                    # groupWith for overlapping sub-ranges
                    if len(group) > 2:
                        vn1 = group[0]
                        for k in range(1, len(group)):
                            vn2 = group[k]
                            off = int(vn2.getOffset() - vn1.getOffset())
                            h1 = vn1.getHigh() if hasattr(vn1, 'getHigh') else None
                            h2 = vn2.getHigh() if hasattr(vn2, 'getHigh') else None
                            if h1 is not None and h2 is not None and hasattr(h2, 'groupWith'):
                                try:
                                    h2.groupWith(off, h1)
                                except Exception:
                                    pass
                i = j

    def mergeMarker(self) -> None:
        """Force the merge of input/output Varnodes to MULTIEQUAL and INDIRECT ops."""
        if not hasattr(self._data, 'beginOpAlive'):
            return
        for op in self._data.getAliveOps():
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
        if not hasattr(self._data, 'getScopeLocal'):
            return
        scope = self._data.getScopeLocal()
        if not hasattr(scope, 'beginMultiEntry'):
            return
        for symbol in scope.beginMultiEntry():
            mergeList: List[Varnode] = []
            numEntries = symbol.numEntries() if hasattr(symbol, 'numEntries') else 0
            mergeCount = 0
            skipCount = 0
            conflictCount = 0
            for i in range(numEntries):
                prevSize = len(mergeList)
                entry = symbol.getMapEntry(i) if hasattr(symbol, 'getMapEntry') else None
                if entry is None:
                    continue
                if hasattr(entry, 'getSize') and hasattr(symbol, 'getType'):
                    if entry.getSize() != symbol.getType().getSize():
                        continue
                if hasattr(self._data, 'findLinkedVarnodes'):
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
                    if hasattr(symbol, 'setMergeProblems'):
                        symbol.setMergeProblems()
                    if hasattr(newHigh, 'setUnmerged'):
                        newHigh.setUnmerged()
                    conflictCount += 1
                    continue
                if not self.merge(high, newHigh, False):
                    if hasattr(symbol, 'setMergeProblems'):
                        symbol.setMergeProblems()
                    if hasattr(newHigh, 'setUnmerged'):
                        newHigh.setUnmerged()
                    conflictCount += 1
                    continue
                mergeCount += 1
            if skipCount != 0 or conflictCount != 0:
                msg = 'Unable to'
                if mergeCount != 0:
                    msg += ' fully'
                name = symbol.getName() if hasattr(symbol, 'getName') else '?'
                msg += f' merge symbol: {name}'
                if skipCount > 0:
                    msg += ' -- Some instance varnodes not found.'
                if conflictCount > 0:
                    msg += ' -- Some merges are forbidden'
                if hasattr(self._data, 'warningHeader'):
                    self._data.warningHeader(msg)

    def groupPartials(self) -> None:
        """Run through CONCAT tree roots and group each tree."""
        for op in self._protoPartial:
            if hasattr(op, 'isDead') and op.isDead():
                continue
            if hasattr(op, 'isPartialRoot') and not op.isPartialRoot():
                continue
            self.groupPartialRoot(op.getOut())

    def groupPartialRoot(self, vn: Varnode) -> None:
        """Group the different nodes of a CONCAT tree into a VariableGroup.

        This formally labels all the Varnodes in the tree as overlapping pieces
        of the same variable. The tree is reconstructed from the root Varnode.
        """
        high = vn.getHigh()
        if high is None or high.numInstances() != 1:
            return

        baseOffset = 0
        entry = vn.getSymbolEntry()
        if entry is not None and hasattr(entry, 'getOffset'):
            baseOffset = entry.getOffset()

        # Gather pieces from the CONCAT tree
        pieces: list = []
        if hasattr(vn, 'getDef') and vn.getDef() is not None:
            self._gatherPieceNodes(pieces, vn, vn.getDef(), baseOffset, baseOffset)

        # Check all nodes are still valid
        throwOut = False
        for piece_vn, piece_off in pieces:
            if not piece_vn.isProtoPartial() or piece_vn.getHigh().numInstances() != 1:
                throwOut = True
                break

        if throwOut:
            for piece_vn, _ in pieces:
                piece_vn.clearProtoPartial()
        else:
            for piece_vn, piece_off in pieces:
                if hasattr(piece_vn.getHigh(), 'groupWith'):
                    piece_vn.getHigh().groupWith(piece_off - baseOffset, high)

    def _gatherPieceNodes(self, pieces: list, root, op, baseOff: int, curOff: int) -> None:
        """Recursively gather piece nodes from a CONCAT tree."""
        if op is None:
            return
        if op.code() == OpCode.CPUI_PIECE:
            # High part = input 0, Low part = input 1
            hiVn = op.getIn(0)
            loVn = op.getIn(1)
            loSize = loVn.getSize()
            # Recurse into sub-pieces
            if loVn.isWritten() and loVn.getDef().code() == OpCode.CPUI_PIECE:
                self._gatherPieceNodes(pieces, root, loVn.getDef(), baseOff, curOff)
            else:
                pieces.append((loVn, curOff))
            hiOff = curOff + loSize
            if hiVn.isWritten() and hiVn.getDef().code() == OpCode.CPUI_PIECE:
                self._gatherPieceNodes(pieces, root, hiVn.getDef(), baseOff, hiOff)
            else:
                pieces.append((hiVn, hiOff))

    def mergeAdjacent(self) -> None:
        """Speculatively merge Varnodes that are input/output to the same p-code op."""
        if not hasattr(self._data, 'getAliveOps'):
            return
        for op in self._data.getAliveOps():
            if op.isCall():
                continue
            vn1 = op.getOut()
            if vn1 is None or not self.mergeTestBasic(vn1):
                continue
            high_out = vn1.getHigh()
            for i in range(op.numInput()):
                vn2 = op.getIn(i)
                if not self.mergeTestBasic(vn2):
                    continue
                if vn1.getSize() != vn2.getSize():
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
                c2 = vn2.getCover()
                if c2 is not None and hasattr(c2, 'containVarnodeDef'):
                    if c2.containVarnodeDef(vn1) == 1:
                        if hasattr(self._data, 'opSetInput'):
                            self._data.opSetInput(vn1.getDef(), vn2, 0)
                        res = True
                        break
                c1 = vn1.getCover()
                if c1 is not None and hasattr(c1, 'containVarnodeDef'):
                    if c1.containVarnodeDef(vn2) == 1:
                        if hasattr(self._data, 'opSetInput'):
                            self._data.opSetInput(vn2.getDef(), vn1, 0)
                        singlelist[j] = None
                        res = True
        return res

    def processCopyTrims(self) -> None:
        """Try to reduce/eliminate COPYs produced by the merge trimming process."""
        self._copyTrims.clear()

    def markInternalCopies(self) -> None:
        """Mark redundant/internal COPY PcodeOps."""
        if not hasattr(self._data, 'getAliveOps'):
            return
        for op in self._data.getAliveOps():
            if op.code() == OpCode.CPUI_COPY:
                v1 = op.getOut()
                h1 = v1.getHigh() if v1 is not None else None
                _in0c = op.getIn(0)
                if h1 is not None and _in0c is not None and h1 is _in0c.getHigh():
                    if hasattr(self._data, 'opMarkNonPrinting'):
                        self._data.opMarkNonPrinting(op)

    def registerProtoPartialRoot(self, vn: Varnode) -> None:
        """Register an unmapped CONCAT stack with the merge process."""
        if vn.getDef() is not None:
            self._protoPartial.append(vn.getDef())

    def checkCopyPair(self, high: HighVariable, domOp: PcodeOp, subOp: PcodeOp) -> bool:
        """Check if the given COPY ops are redundant."""
        domBlock = domOp.getParent()
        subBlock = subOp.getParent()
        if domBlock is None or subBlock is None:
            return False
        if hasattr(domBlock, 'dominates') and not domBlock.dominates(subBlock):
            return False
        return True

    def buildDominantCopy(self, high: HighVariable, copy: List[PcodeOp], pos: int, size: int) -> None:
        """Try to replace a set of COPYs from the same Varnode with a single dominant COPY.

        All COPY outputs must be instances of the same HighVariable. Either an existing COPY
        dominates all the others, or a new dominating COPY is constructed. Replacement only
        happens with COPY outputs that are temporary registers.
        """
        if not hasattr(self._data, 'newOp'):
            return
        # Find common dominating block
        from ghidra.block.block import FlowBlock
        blockSet = []
        for i in range(size):
            parent = copy[pos + i].getParent()
            if parent is not None:
                blockSet.append(parent)
        if not blockSet:
            return
        domBl = FlowBlock.findCommonBlock(blockSet) if hasattr(FlowBlock, 'findCommonBlock') else blockSet[0]
        domCopy = copy[pos]
        rootVn = domCopy.getIn(0)
        domVn = domCopy.getOut()
        domCopyIsNew = (domBl is not domCopy.getParent())

        if domCopyIsNew:
            # Create a new dominant COPY
            domCopy = self._data.newOp(1, domBl.getStop() if hasattr(domBl, 'getStop') else domCopy.getAddr())
            self._data.opSetOpcode(domCopy, OpCode.CPUI_COPY)
            ct = rootVn.getType()
            domVn = self._data.newUnique(rootVn.getSize(), ct)
            self._data.opSetOutput(domCopy, domVn)
            self._data.opSetInput(domCopy, rootVn, 0)
            if hasattr(self._data, 'opInsertEnd'):
                self._data.opInsertEnd(domCopy, domBl)

        # Replace non-intersecting COPYs with read of dominant Varnode
        for i in range(size):
            op = copy[pos + i]
            if op is domCopy:
                continue
            outVn = op.getOut()
            if outVn is not domVn:
                if hasattr(self._data, 'totalReplace'):
                    self._data.totalReplace(outVn, domVn)
                if hasattr(self._data, 'opDestroy'):
                    self._data.opDestroy(op)

    def markRedundantCopies(self, high: HighVariable, copy: List[PcodeOp], pos: int, size: int) -> None:
        """Mark redundant COPY ops as non-printing."""
        for i in range(size - 1, 0, -1):
            subOp = copy[pos + i]
            if hasattr(subOp, 'isDead') and subOp.isDead():
                continue
            for j in range(i - 1, -1, -1):
                domOp = copy[pos + j]
                if hasattr(domOp, 'isDead') and domOp.isDead():
                    continue
                if self.checkCopyPair(high, domOp, subOp):
                    if hasattr(self._data, 'opMarkNonPrinting'):
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
        if self._data is None:
            return
        if not hasattr(self._data, 'beginLoc'):
            return
        for vn in self._data.beginLoc():
            if hasattr(vn, 'hasCover') and vn.hasCover():
                high = vn.getHigh() if hasattr(vn, 'getHigh') else None
                if high is None:
                    continue
                if hasattr(high, 'hasCopyIn1') and not high.hasCopyIn1():
                    if hasattr(high, 'setCopyIn1'):
                        high.setCopyIn1()
                    if hasattr(high, 'verifyCover'):
                        high.verifyCover()

    def collectInputs(self, high: HighVariable, oplist: list, op: PcodeOp) -> None:
        """Collect Varnode instances from a HighVariable that are inputs to a given PcodeOp."""
        while True:
            for i in range(op.numInput()):
                vn = op.getIn(i)
                if vn.isAnnotation():
                    continue
                testHigh = vn.getHigh()
                if testHigh is high:
                    oplist.append((op, i))
            prev = op.previousOp() if hasattr(op, 'previousOp') else None
            if prev is None or prev.code() != OpCode.CPUI_INDIRECT:
                break
            op = prev
