"""
Corresponds to: double.hh / double.cc

SplitVarnode and related classes for handling double-precision operations.
When the decompiler encounters operations on values that span two registers
(e.g. 64-bit values in 32-bit architectures), this module helps combine
them into single logical operations.
"""

from __future__ import annotations
from typing import Optional, List
from ghidra.core.address import calc_mask
from ghidra.core.opcodes import OpCode


class SplitVarnode:
    """A logical value split across two Varnodes (hi and lo parts).

    Represents a double-precision value that is stored in two registers
    or memory locations. The 'whole' field, if set, points to a single
    Varnode that represents the combined value.
    """

    def __init__(self) -> None:
        self.lo = None       # Varnode: low part
        self.hi = None       # Varnode: high part
        self.whole = None    # Varnode: combined (if exists)
        self.defpoint = None # PcodeOp defining the pair
        self.defblock = None # BlockBasic where pair is defined
        self.wholesize: int = 0

    def initAll(self, whole_or_lo, lo_or_hi=None, hi=None) -> None:
        """Initialize from whole + lo + hi (3-arg C++ form) or lo + hi (2-arg legacy)."""
        if hi is not None or lo_or_hi is not None:
            # 3-arg form: initAll(whole, lo, hi)
            if lo_or_hi is not None and hi is None:
                # 2-arg legacy: initAll(lo, hi) — treat as lo=whole_or_lo, hi=lo_or_hi
                self.lo = whole_or_lo
                self.hi = lo_or_hi
            else:
                self.whole = whole_or_lo
                self.lo = lo_or_hi
                self.hi = hi
        else:
            self.lo = whole_or_lo
            self.hi = None
        if self.lo is not None and self.hi is not None:
            self.wholesize = self.lo.getSize() + self.hi.getSize()
        elif self.whole is not None:
            self.wholesize = self.whole.getSize()

    def initPartial(self, sz: int, lo_or_vn, hi=None) -> None:
        """Initialize from lo+hi pieces or a single whole Varnode.
        2-arg: initPartial(sz, whole_vn)
        3-arg: initPartial(sz, lo, hi)
        Corresponds to SplitVarnode::initPartial in double.cc."""
        if hi is not None:
            self.lo = lo_or_vn
            self.hi = hi
            self.wholesize = sz
        else:
            self.whole = lo_or_vn
            self.wholesize = sz

    def initPartialConst(self, sz: int, val: int) -> None:
        """Initialize as a constant value.
        Corresponds to SplitVarnode::initPartial(int4,uintb) in double.cc."""
        self._val = val
        self.wholesize = sz
        self.lo = None
        self.hi = None
        self.whole = None

    def getLo(self):
        return self.lo

    def getHi(self):
        return self.hi

    def getWhole(self):
        return self.whole

    def getSize(self) -> int:
        return self.wholesize

    def isConstant(self) -> bool:
        if self.whole is not None:
            return self.whole.isConstant() if hasattr(self.whole, 'isConstant') else False
        if self.lo is not None and self.hi is not None:
            lo_const = self.lo.isConstant() if hasattr(self.lo, 'isConstant') else False
            hi_const = self.hi.isConstant() if hasattr(self.hi, 'isConstant') else False
            return lo_const and hi_const
        return False

    def getConstValue(self) -> int:
        if self.whole is not None:
            return self.whole.getOffset()
        if self.lo is not None and self.hi is not None:
            loval = self.lo.getOffset()
            hival = self.hi.getOffset()
            return (hival << (self.lo.getSize() * 8)) | loval
        return 0

    def hasBothPieces(self) -> bool:
        return self.lo is not None and self.hi is not None

    def isWholeFilled(self) -> bool:
        return self.whole is not None

    def getDefPoint(self):
        return self.defpoint

    def getDefBlock(self):
        return self.defblock

    def getValue(self) -> int:
        return self.getConstValue()

    def inHandHi(self, h) -> bool:
        """Try to initialize given just the most significant piece split from whole.
        Corresponds to SplitVarnode::inHandHi in double.cc."""
        if not hasattr(h, 'isPrecisHi') or not h.isPrecisHi():
            return False
        if h.isWritten():
            op = h.getDef()
            if op.code() == OpCode.CPUI_SUBPIECE:
                w = op.getIn(0)
                if op.getIn(1).getOffset() != (w.getSize() - h.getSize()):
                    return False
                for desc in w.getDescendants():
                    if desc.code() != OpCode.CPUI_SUBPIECE:
                        continue
                    tmplo = desc.getOut()
                    if not hasattr(tmplo, 'isPrecisLo') or not tmplo.isPrecisLo():
                        continue
                    if tmplo.getSize() + h.getSize() != w.getSize():
                        continue
                    if desc.getIn(1).getOffset() != 0:
                        continue
                    self.initAll(w, tmplo, h)
                    return True
        return False

    def inHandLo(self, l) -> bool:
        """Try to initialize given just the least significant piece split from whole.
        Corresponds to SplitVarnode::inHandLo in double.cc."""
        if not hasattr(l, 'isPrecisLo') or not l.isPrecisLo():
            return False
        if l.isWritten():
            op = l.getDef()
            if op.code() == OpCode.CPUI_SUBPIECE:
                w = op.getIn(0)
                if op.getIn(1).getOffset() != 0:
                    return False
                for desc in w.getDescendants():
                    if desc.code() != OpCode.CPUI_SUBPIECE:
                        continue
                    tmphi = desc.getOut()
                    if not hasattr(tmphi, 'isPrecisHi') or not tmphi.isPrecisHi():
                        continue
                    if tmphi.getSize() + l.getSize() != w.getSize():
                        continue
                    if desc.getIn(1).getOffset() != l.getSize():
                        continue
                    self.initAll(w, l, tmphi)
                    return True
        return False

    def inHandLoNoHi(self, l) -> bool:
        """Try to initialize given just the least significant piece (other may be zero).
        Corresponds to SplitVarnode::inHandLoNoHi in double.cc."""
        if not hasattr(l, 'isPrecisLo') or not l.isPrecisLo():
            return False
        if not l.isWritten():
            return False
        op = l.getDef()
        if op.code() != OpCode.CPUI_SUBPIECE:
            return False
        if op.getIn(1).getOffset() != 0:
            return False
        w = op.getIn(0)
        for desc in w.getDescendants():
            if desc.code() != OpCode.CPUI_SUBPIECE:
                continue
            tmphi = desc.getOut()
            if not hasattr(tmphi, 'isPrecisHi') or not tmphi.isPrecisHi():
                continue
            if tmphi.getSize() + l.getSize() != w.getSize():
                continue
            if desc.getIn(1).getOffset() != l.getSize():
                continue
            self.initAll(w, l, tmphi)
            return True
        self.initAll(w, l, None)
        return True

    def inHandHiOut(self, h) -> bool:
        """Try to initialize given just the most significant piece concatenated into whole.
        Corresponds to SplitVarnode::inHandHiOut in double.cc."""
        loTmp = None
        outvn = None
        for desc in h.getDescendants():
            if desc.code() != OpCode.CPUI_PIECE:
                continue
            if desc.getIn(0) is not h:
                continue
            l = desc.getIn(1)
            if not hasattr(l, 'isPrecisLo') or not l.isPrecisLo():
                continue
            if loTmp is not None:
                return False  # Whole is not unique
            loTmp = l
            outvn = desc.getOut()
        if loTmp is not None:
            self.initAll(outvn, loTmp, h)
            return True
        return False

    def inHandLoOut(self, l) -> bool:
        """Try to initialize given just the least significant piece concatenated into whole.
        Corresponds to SplitVarnode::inHandLoOut in double.cc."""
        hiTmp = None
        outvn = None
        for desc in l.getDescendants():
            if desc.code() != OpCode.CPUI_PIECE:
                continue
            if desc.getIn(1) is not l:
                continue
            h = desc.getIn(0)
            if not hasattr(h, 'isPrecisHi') or not h.isPrecisHi():
                continue
            if hiTmp is not None:
                return False  # Whole is not unique
            hiTmp = h
            outvn = desc.getOut()
        if hiTmp is not None:
            self.initAll(outvn, l, hiTmp)
            return True
        return False

    def isWholeFeasible(self, existop) -> bool:
        """Does a whole Varnode already exist or can it be created?
        Corresponds to SplitVarnode::isWholeFeasible in double.cc."""
        if self.isConstant():
            return True
        if self.lo is not None and self.hi is not None:
            lo_const = self.lo.isConstant() if hasattr(self.lo, 'isConstant') else False
            hi_const = self.hi.isConstant() if hasattr(self.hi, 'isConstant') else False
            if lo_const != hi_const:
                return False
        if not self.findWholeSplitToPieces():
            if not self.findWholeBuiltFromPieces():
                if not self.findDefinitionPoint():
                    return False
        if self.defblock is None:
            return True
        curbl = existop.getParent()
        if curbl is self.defblock:
            return self.defpoint.getSeqNum().getOrder() <= existop.getSeqNum().getOrder()
        while curbl is not None:
            curbl = curbl.getImmedDom() if hasattr(curbl, 'getImmedDom') else None
            if curbl is self.defblock:
                return True
        return False

    def isWholePhiFeasible(self, bl) -> bool:
        """Check if whole can be defined before end of the given block.
        Corresponds to SplitVarnode::isWholePhiFeasible in double.cc."""
        if self.isConstant():
            return False
        if not self.findWholeSplitToPieces():
            if not self.findWholeBuiltFromPieces():
                if not self.findDefinitionPoint():
                    return False
        if self.defblock is None:
            return True
        if bl is self.defblock:
            return True
        while bl is not None:
            bl = bl.getImmedDom() if hasattr(bl, 'getImmedDom') else None
            if bl is self.defblock:
                return True
        return False

    def findCreateWhole(self, data) -> None:
        """Create a whole Varnode for this, if it doesn't already exist.
        Corresponds to SplitVarnode::findCreateWhole in double.cc."""
        if self.isConstant():
            val = getattr(self, '_val', self.getConstValue())
            self.whole = data.newConstant(self.wholesize, val)
            return
        if self.lo is not None:
            if hasattr(self.lo, 'setPrecisLo'):
                self.lo.setPrecisLo()
        if self.hi is not None:
            if hasattr(self.hi, 'setPrecisHi'):
                self.hi.setPrecisHi()
        if self.whole is not None:
            return
        if self.defblock is not None:
            addr = self.defpoint.getAddr()
        else:
            topblock = data.getBasicBlocks().getStartBlock()
            addr = topblock.getStart() if topblock is not None else self.lo.getAddr()
        if self.hi is not None:
            concatop = data.newOp(2, addr)
            self.whole = data.newUniqueOut(self.wholesize, concatop)
            data.opSetOpcode(concatop, OpCode.CPUI_PIECE)
            data.opSetOutput(concatop, self.whole)
            data.opSetInput(concatop, self.hi, 0)
            data.opSetInput(concatop, self.lo, 1)
        else:
            concatop = data.newOp(1, addr)
            self.whole = data.newUniqueOut(self.wholesize, concatop)
            data.opSetOpcode(concatop, OpCode.CPUI_INT_ZEXT)
            data.opSetOutput(concatop, self.whole)
            data.opSetInput(concatop, self.lo, 0)
        if self.defblock is not None:
            data.opInsertAfter(concatop, self.defpoint)
        else:
            if topblock is not None:
                data.opInsertBegin(concatop, topblock)
        self.defpoint = concatop
        self.defblock = concatop.getParent()

    def findCreateOutputWhole(self, data) -> None:
        """Create a whole Varnode that will be a PcodeOp output.
        Corresponds to SplitVarnode::findCreateOutputWhole in double.cc."""
        if self.lo is not None and hasattr(self.lo, 'setPrecisLo'):
            self.lo.setPrecisLo()
        if self.hi is not None and hasattr(self.hi, 'setPrecisHi'):
            self.hi.setPrecisHi()
        if self.whole is not None:
            return
        self.whole = data.newUnique(self.wholesize)

    def createJoinedWhole(self, data) -> None:
        """Create a whole Varnode from pieces, respecting piece storage.
        Corresponds to SplitVarnode::createJoinedWhole in double.cc."""
        if self.lo is not None and hasattr(self.lo, 'setPrecisLo'):
            self.lo.setPrecisLo()
        if self.hi is not None and hasattr(self.hi, 'setPrecisHi'):
            self.hi.setPrecisHi()
        if self.whole is not None:
            return
        ok, newaddr = SplitVarnode.isAddrTiedContiguous(self.lo, self.hi)
        if not ok:
            # Use lo addr as fallback (join address not available in pure Python)
            newaddr = self.lo.getAddr()
        self.whole = data.newVarnode(self.wholesize, newaddr)
        if hasattr(self.whole, 'setWriteMask'):
            self.whole.setWriteMask()

    def buildLoFromWhole(self, data) -> None:
        """Rebuild the least significant piece as a SUBPIECE of the whole.
        Corresponds to SplitVarnode::buildLoFromWhole in double.cc."""
        loop = self.lo.getDef() if self.lo is not None and self.lo.isWritten() else None
        if loop is None:
            return
        inlist = [self.whole, data.newConstant(4, 0)]
        if loop.code() == OpCode.CPUI_MULTIEQUAL:
            bl = loop.getParent()
            data.opUninsert(loop)
            data.opSetOpcode(loop, OpCode.CPUI_SUBPIECE)
            data.opSetAllInput(loop, inlist)
            data.opInsertBegin(loop, bl)
        elif loop.code() == OpCode.CPUI_INDIRECT:
            data.opSetOpcode(loop, OpCode.CPUI_SUBPIECE)
            data.opSetAllInput(loop, inlist)
        else:
            data.opSetOpcode(loop, OpCode.CPUI_SUBPIECE)
            data.opSetAllInput(loop, inlist)

    def buildHiFromWhole(self, data) -> None:
        """Rebuild the most significant piece as a SUBPIECE of the whole.
        Corresponds to SplitVarnode::buildHiFromWhole in double.cc."""
        hiop = self.hi.getDef() if self.hi is not None and self.hi.isWritten() else None
        if hiop is None:
            return
        lo_size = self.lo.getSize() if self.lo is not None else 0
        inlist = [self.whole, data.newConstant(4, lo_size)]
        if hiop.code() == OpCode.CPUI_MULTIEQUAL:
            bl = hiop.getParent()
            data.opUninsert(hiop)
            data.opSetOpcode(hiop, OpCode.CPUI_SUBPIECE)
            data.opSetAllInput(hiop, inlist)
            data.opInsertBegin(hiop, bl)
        elif hiop.code() == OpCode.CPUI_INDIRECT:
            data.opSetOpcode(hiop, OpCode.CPUI_SUBPIECE)
            data.opSetAllInput(hiop, inlist)
        else:
            data.opSetOpcode(hiop, OpCode.CPUI_SUBPIECE)
            data.opSetAllInput(hiop, inlist)

    def findEarliestSplitPoint(self):
        """Return the earlier of the two defining PcodeOps for hi and lo, or None.
        Corresponds to SplitVarnode::findEarliestSplitPoint in double.cc."""
        if self.hi is None or self.lo is None:
            return None
        if not self.hi.isWritten() or not self.lo.isWritten():
            return None
        hiop = self.hi.getDef()
        loop = self.lo.getDef()
        if loop.getParent() is not hiop.getParent():
            return None
        if loop.getSeqNum().getOrder() < hiop.getSeqNum().getOrder():
            return loop
        return hiop

    def findOutExist(self):
        """Find the first PcodeOp where the whole needs to exist.
        Corresponds to SplitVarnode::findOutExist in double.cc."""
        if self.findWholeBuiltFromPieces():
            return self.defpoint
        return self.findEarliestSplitPoint()

    def exceedsConstPrecision(self) -> bool:
        return self.wholesize > 8

    def findWholeSplitToPieces(self) -> bool:
        """Look for CPUI_SUBPIECE operations off of a common whole Varnode.
        Corresponds to SplitVarnode::findWholeSplitToPieces in double.cc."""
        if self.whole is None:
            if self.hi is None or self.lo is None:
                return False
            if not self.hi.isWritten():
                return False
            subhi = self.hi.getDef()
            if subhi.code() == OpCode.CPUI_COPY:
                otherhi = subhi.getIn(0)
                if not otherhi.isWritten():
                    return False
                subhi = otherhi.getDef()
            if subhi.code() != OpCode.CPUI_SUBPIECE:
                return False
            if subhi.getIn(1).getOffset() != self.wholesize - self.hi.getSize():
                return False
            putativeWhole = subhi.getIn(0)
            if putativeWhole.getSize() != self.wholesize:
                return False
            if not self.lo.isWritten():
                return False
            sublo = self.lo.getDef()
            if sublo.code() == OpCode.CPUI_COPY:
                otherlo = sublo.getIn(0)
                if not otherlo.isWritten():
                    return False
                sublo = otherlo.getDef()
            if sublo.code() != OpCode.CPUI_SUBPIECE:
                return False
            if putativeWhole is not sublo.getIn(0):
                return False
            if sublo.getIn(1).getOffset() != 0:
                return False
            self.whole = putativeWhole
        if self.whole.isWritten():
            self.defpoint = self.whole.getDef()
            self.defblock = self.defpoint.getParent()
        elif self.whole.isInput():
            self.defpoint = None
            self.defblock = None
        return True

    def findDefinitionPoint(self) -> bool:
        """Set the basic block and PcodeOp where the split value is defined.
        Corresponds to SplitVarnode::findDefinitionPoint in double.cc."""
        if self.hi is not None and hasattr(self.hi, 'isConstant') and self.hi.isConstant():
            return False
        if self.lo is None or (hasattr(self.lo, 'isConstant') and self.lo.isConstant()):
            return False
        if self.hi is None:
            if self.lo.isInput():
                self.defblock = None
                self.defpoint = None
            elif self.lo.isWritten():
                self.defpoint = self.lo.getDef()
                self.defblock = self.defpoint.getParent()
            else:
                return False
        elif self.hi.isWritten():
            if not self.lo.isWritten():
                return False
            lastop = self.hi.getDef()
            self.defblock = lastop.getParent()
            lastop2 = self.lo.getDef()
            otherblock = lastop2.getParent()
            if self.defblock is not otherblock:
                self.defpoint = lastop
                curbl = self.defblock
                while curbl is not None:
                    curbl = curbl.getImmedDom() if hasattr(curbl, 'getImmedDom') else None
                    if curbl is otherblock:
                        return True
                self.defblock = otherblock
                self.defpoint = lastop2
                curbl = self.defblock
                while curbl is not None:
                    curbl = curbl.getImmedDom() if hasattr(curbl, 'getImmedDom') else None
                    if curbl is lastop.getParent():
                        return True
                self.defblock = None
                return False
            if lastop2.getSeqNum().getOrder() > lastop.getSeqNum().getOrder():
                lastop = lastop2
            self.defpoint = lastop
        elif self.hi.isInput():
            if not self.lo.isInput():
                return False
            self.defblock = None
            self.defpoint = None
        return True

    def findWholeBuiltFromPieces(self) -> bool:
        """Scan for concatenations formed out of hi and lo.
        Corresponds to SplitVarnode::findWholeBuiltFromPieces in double.cc."""
        if self.hi is None or self.lo is None:
            return False
        res = None
        if self.lo.isWritten():
            bb = self.lo.getDef().getParent()
        elif self.lo.isInput():
            bb = None
        else:
            return False
        for desc in self.lo.getDescendants():
            if desc.code() != OpCode.CPUI_PIECE:
                continue
            if desc.getIn(0) is not self.hi:
                continue
            if bb is not None:
                if desc.getParent() is not bb:
                    continue
            elif not (hasattr(desc.getParent(), 'isEntryPoint') and desc.getParent().isEntryPoint()):
                continue
            if res is None:
                res = desc
            else:
                if desc.getSeqNum().getOrder() < res.getSeqNum().getOrder():
                    res = desc
        if res is None:
            self.whole = None
        else:
            self.defpoint = res
            self.defblock = self.defpoint.getParent()
            self.whole = res.getOut()
        return self.whole is not None

    @staticmethod
    def adjacentOffsets(vn1, vn2, size1: int) -> bool:
        """Check if two Varnodes are at adjacent offsets.
        Corresponds to SplitVarnode::adjacentOffsets in double.cc."""
        if vn1.isConstant():
            if not vn2.isConstant():
                return False
            return (vn1.getOffset() + size1) == vn2.getOffset()
        if not vn2.isWritten():
            return False
        op2 = vn2.getDef()
        if op2.code() != OpCode.CPUI_INT_ADD:
            return False
        if not op2.getIn(1).isConstant():
            return False
        c2 = op2.getIn(1).getOffset()
        if op2.getIn(0) is vn1:
            return size1 == c2
        if not vn1.isWritten():
            return False
        op1 = vn1.getDef()
        if op1.code() != OpCode.CPUI_INT_ADD:
            return False
        if not op1.getIn(1).isConstant():
            return False
        c1 = op1.getIn(1).getOffset()
        if op1.getIn(0) is not op2.getIn(0):
            return False
        return (c1 + size1) == c2

    @staticmethod
    def wholeList(w, splitvec: list) -> None:
        """Find all SplitVarnodes formed from a given whole.
        Corresponds to SplitVarnode::wholeList in double.cc."""
        basic = SplitVarnode()
        basic.whole = w
        basic.hi = None
        basic.lo = None
        basic.wholesize = w.getSize()
        res = 0
        for subop in w.getDescendants():
            if subop.code() != OpCode.CPUI_SUBPIECE:
                continue
            vn = subop.getOut()
            if hasattr(vn, 'isPrecisHi') and vn.isPrecisHi():
                if subop.getIn(1).getOffset() != basic.wholesize - vn.getSize():
                    continue
                basic.hi = vn
                res |= 2
            elif hasattr(vn, 'isPrecisLo') and vn.isPrecisLo():
                if subop.getIn(1).getOffset() != 0:
                    continue
                basic.lo = vn
                res |= 1
        if res == 0:
            return
        if res == 3 and (basic.lo.getSize() + basic.hi.getSize() != basic.wholesize):
            return
        splitvec.append(basic)
        SplitVarnode.findCopies(basic, splitvec)

    @staticmethod
    def findCopies(inv, splitvec: list) -> None:
        """Find copies of a SplitVarnode.
        Corresponds to SplitVarnode::findCopies in double.cc."""
        if not inv.hasBothPieces():
            return
        for loop in inv.getLo().getDescendants():
            if loop.code() != OpCode.CPUI_COPY:
                continue
            locpy = loop.getOut()
            addr = locpy.getAddr()
            lo_size = locpy.getSize()
            for hiop in inv.getHi().getDescendants():
                if hiop.code() != OpCode.CPUI_COPY:
                    continue
                hicpy = hiop.getOut()
                # Check adjacency: in big-endian, hi comes before lo; in little-endian, lo before hi
                hi_addr = hicpy.getAddr()
                if hiop.getParent() is not loop.getParent():
                    continue
                # Simple adjacency check
                if hi_addr.getSpace() is addr.getSpace():
                    if addr.getOffset() + lo_size == hi_addr.getOffset() or \
                       hi_addr.getOffset() + hicpy.getSize() == addr.getOffset():
                        newsplit = SplitVarnode()
                        newsplit.initAll(inv.getWhole(), locpy, hicpy)
                        splitvec.append(newsplit)

    @staticmethod
    def getTrueFalse(boolop, flip: bool):
        """Get the true and false output blocks of a CBRANCH.
        Corresponds to SplitVarnode::getTrueFalse in double.cc."""
        parent = boolop.getParent()
        trueblock = parent.getTrueOut()
        falseblock = parent.getFalseOut()
        is_flipped = boolop.isBooleanFlip() if hasattr(boolop, 'isBooleanFlip') else False
        if is_flipped != flip:
            return (falseblock, trueblock)
        return (trueblock, falseblock)

    @staticmethod
    def otherwiseEmpty(branchop) -> bool:
        """Return True if the block containing branchop performs no other operation.
        Corresponds to SplitVarnode::otherwiseEmpty in double.cc."""
        bl = branchop.getParent()
        if bl.sizeIn() != 1:
            return False
        otherop = None
        vn = branchop.getIn(1) if branchop.numInput() > 1 else None
        if vn is not None and vn.isWritten():
            otherop = vn.getDef()
        for op in bl.getOpList():
            if op is otherop:
                continue
            if op is branchop:
                continue
            return False
        return True

    @staticmethod
    def verifyMultNegOne(op) -> bool:
        """Verify that op is a CPUI_INT_MULT by -1.
        Corresponds to SplitVarnode::verifyMultNegOne in double.cc."""
        if op.code() != OpCode.CPUI_INT_MULT:
            return False
        in1 = op.getIn(1)
        if not in1.isConstant():
            return False
        mask = (1 << (in1.getSize() * 8)) - 1
        return in1.getOffset() == mask

    @staticmethod
    def prepareBinaryOp(out, in1, in2):
        """Check that a binary double-precision operation can be created.
        Corresponds to SplitVarnode::prepareBinaryOp in double.cc."""
        existop = out.findOutExist()
        if existop is None:
            return None
        if not in1.isWholeFeasible(existop):
            return None
        if not in2.isWholeFeasible(existop):
            return None
        return existop

    @staticmethod
    def createBinaryOp(data, out, in1, in2, existop, opc) -> None:
        """Rewrite a double precision binary operation.
        Corresponds to SplitVarnode::createBinaryOp in double.cc."""
        out.findCreateOutputWhole(data)
        in1.findCreateWhole(data)
        in2.findCreateWhole(data)
        if existop.code() != OpCode.CPUI_PIECE:
            newop = data.newOp(2, existop.getAddr())
            data.opSetOpcode(newop, opc)
            data.opSetOutput(newop, out.getWhole())
            data.opSetInput(newop, in1.getWhole(), 0)
            data.opSetInput(newop, in2.getWhole(), 1)
            data.opInsertBefore(newop, existop)
            out.buildLoFromWhole(data)
            out.buildHiFromWhole(data)
        else:
            data.opSetOpcode(existop, opc)
            data.opSetInput(existop, in1.getWhole(), 0)
            data.opSetInput(existop, in2.getWhole(), 1)

    @staticmethod
    def prepareShiftOp(out, inv):
        """Check that a shift double-precision operation can be created.
        Corresponds to SplitVarnode::prepareShiftOp in double.cc."""
        existop = out.findOutExist()
        if existop is None:
            return None
        if not inv.isWholeFeasible(existop):
            return None
        return existop

    @staticmethod
    def createShiftOp(data, out, inv, sa, existop, opc) -> None:
        """Rewrite a double precision shift operation.
        Corresponds to SplitVarnode::createShiftOp in double.cc."""
        out.findCreateOutputWhole(data)
        inv.findCreateWhole(data)
        if sa.isConstant():
            sa = data.newConstant(sa.getSize(), sa.getOffset())
        if existop.code() != OpCode.CPUI_PIECE:
            newop = data.newOp(2, existop.getAddr())
            data.opSetOpcode(newop, opc)
            data.opSetOutput(newop, out.getWhole())
            data.opSetInput(newop, inv.getWhole(), 0)
            data.opSetInput(newop, sa, 1)
            data.opInsertBefore(newop, existop)
            out.buildLoFromWhole(data)
            out.buildHiFromWhole(data)
        else:
            data.opSetOpcode(existop, opc)
            data.opSetInput(existop, inv.getWhole(), 0)
            data.opSetInput(existop, sa, 1)

    @staticmethod
    def replaceBoolOp(data, boolop, in1, in2, opc) -> None:
        """Rewrite a double precision boolean operation.
        Corresponds to SplitVarnode::replaceBoolOp in double.cc."""
        in1.findCreateWhole(data)
        in2.findCreateWhole(data)
        data.opSetOpcode(boolop, opc)
        data.opSetInput(boolop, in1.getWhole(), 0)
        data.opSetInput(boolop, in2.getWhole(), 1)

    @staticmethod
    def prepareBoolOp(in1, in2, testop) -> bool:
        """Check that input operands of a double precision compare are compatible.
        Corresponds to SplitVarnode::prepareBoolOp in double.cc."""
        if not in1.isWholeFeasible(testop):
            return False
        if not in2.isWholeFeasible(testop):
            return False
        return True

    @staticmethod
    def createBoolOp(data, cbranch, in1, in2, opc) -> None:
        """Create a new compare PcodeOp for a CBRANCH.
        Corresponds to SplitVarnode::createBoolOp in double.cc."""
        addrop = cbranch
        boolvn = cbranch.getIn(1) if cbranch.numInput() > 1 else None
        if boolvn is not None and boolvn.isWritten():
            addrop = boolvn.getDef()
        in1.findCreateWhole(data)
        in2.findCreateWhole(data)
        newop = data.newOp(2, addrop.getAddr())
        data.opSetOpcode(newop, opc)
        newbool = data.newUniqueOut(1, newop)
        data.opSetInput(newop, in1.getWhole(), 0)
        data.opSetInput(newop, in2.getWhole(), 1)
        data.opInsertBefore(newop, cbranch)
        data.opSetInput(cbranch, newbool, 1)

    @staticmethod
    def preparePhiOp(out, inlist):
        """Check that a MULTIEQUAL double-precision operation can be created.
        Corresponds to SplitVarnode::preparePhiOp in double.cc."""
        existop = out.findEarliestSplitPoint()
        if existop is None:
            return None
        if existop.code() != OpCode.CPUI_MULTIEQUAL:
            return None
        bl = existop.getParent()
        for i, inv in enumerate(inlist):
            inbl = bl.getIn(i) if hasattr(bl, 'getIn') else None
            if inbl is None:
                return None
            if not inv.isWholePhiFeasible(inbl):
                return None
        return existop

    @staticmethod
    def createPhiOp(data, out, inlist, existop) -> None:
        """Rewrite a double precision MULTIEQUAL operation.
        Corresponds to SplitVarnode::createPhiOp in double.cc."""
        out.findCreateOutputWhole(data)
        for inv in inlist:
            inv.findCreateWhole(data)
        newop = data.newOp(len(inlist), existop.getAddr())
        data.opSetOpcode(newop, OpCode.CPUI_MULTIEQUAL)
        data.opSetOutput(newop, out.getWhole())
        for i, inv in enumerate(inlist):
            data.opSetInput(newop, inv.getWhole(), i)
        data.opInsertBefore(newop, existop)
        out.buildLoFromWhole(data)
        out.buildHiFromWhole(data)

    @staticmethod
    def prepareIndirectOp(inv, affector) -> bool:
        """Check that a INDIRECT double-precision operation can be created.
        Corresponds to SplitVarnode::prepareIndirectOp in double.cc."""
        if not inv.isWholeFeasible(affector):
            return False
        return True

    @staticmethod
    def replaceIndirectOp(data, out, inv, affector) -> None:
        """Rewrite a double precision INDIRECT operation.
        Corresponds to SplitVarnode::replaceIndirectOp in double.cc."""
        out.createJoinedWhole(data)
        inv.findCreateWhole(data)
        newop = data.newOp(2, affector.getAddr())
        data.opSetOpcode(newop, OpCode.CPUI_INDIRECT)
        data.opSetOutput(newop, out.getWhole())
        data.opSetInput(newop, inv.getWhole(), 0)
        iop_vn = data.newVarnodeIop(affector) if hasattr(data, 'newVarnodeIop') else data.newConstant(4, 0)
        data.opSetInput(newop, iop_vn, 1)
        data.opInsertBefore(newop, affector)
        out.buildLoFromWhole(data)
        out.buildHiFromWhole(data)

    @staticmethod
    def replaceCopyForce(data, addr, inv, copylo, copyhi) -> None:
        """Rewrite the double precision version of a COPY to an address forced Varnode.
        Corresponds to SplitVarnode::replaceCopyForce in double.cc."""
        inVn = inv.getWhole()
        wholeCopy = data.newOp(1, copyhi.getAddr())
        data.opSetOpcode(wholeCopy, OpCode.CPUI_COPY)
        outVn = data.newVarnodeOut(inv.getSize(), addr, wholeCopy)
        if hasattr(outVn, 'setAddrForce'):
            outVn.setAddrForce()
        data.opSetInput(wholeCopy, inVn, 0)
        data.opInsertBefore(wholeCopy, copyhi)
        data.opDestroy(copyhi)
        data.opDestroy(copylo)

    @staticmethod
    def testContiguousPointers(most, least):
        """Verify that the pointers into the given LOAD/STORE PcodeOps address contiguous memory.
        Corresponds to SplitVarnode::testContiguousPointers in double.cc."""
        spc = least.getIn(0).getSpaceFromConst() if hasattr(least.getIn(0), 'getSpaceFromConst') else None
        if spc is None:
            return (False, None, None, None)
        most_spc = most.getIn(0).getSpaceFromConst() if hasattr(most.getIn(0), 'getSpaceFromConst') else None
        if most_spc is not spc:
            return (False, None, None, None)
        if hasattr(spc, 'isBigEndian') and spc.isBigEndian():
            first = most
            second = least
        else:
            first = least
            second = most
        firstptr = first.getIn(1)
        if hasattr(firstptr, 'isFree') and firstptr.isFree():
            return (False, None, None, None)
        if first.code() == OpCode.CPUI_LOAD:
            sizeres = first.getOut().getSize()
        else:
            sizeres = first.getIn(2).getSize()
        if SplitVarnode.adjacentOffsets(first.getIn(1), second.getIn(1), sizeres):
            return (True, first, second, spc)
        return (False, None, None, None)

    @staticmethod
    def isAddrTiedContiguous(lo, hi):
        """Return True if lo and hi are address-tied and form a contiguous range.
        Corresponds to SplitVarnode::isAddrTiedContiguous in double.cc."""
        if not hasattr(lo, 'isAddrTied') or not lo.isAddrTied():
            return (False, None)
        if not hasattr(hi, 'isAddrTied') or not hi.isAddrTied():
            return (False, None)
        entryLo = lo.getSymbolEntry() if hasattr(lo, 'getSymbolEntry') else None
        entryHi = hi.getSymbolEntry() if hasattr(hi, 'getSymbolEntry') else None
        if entryLo is not None or entryHi is not None:
            if entryLo is None or entryHi is None:
                return (False, None)
            if entryLo.getSymbol() is not entryHi.getSymbol():
                return (False, None)
        lo_spc = lo.getSpace()
        hi_spc = hi.getSpace()
        if lo_spc is not hi_spc:
            return (False, None)
        looffset = lo.getOffset()
        hioffset = hi.getOffset()
        if hasattr(lo_spc, 'isBigEndian') and lo_spc.isBigEndian():
            if hioffset >= looffset:
                return (False, None)
            if hioffset + hi.getSize() != looffset:
                return (False, None)
            return (True, hi.getAddr())
        else:
            if looffset >= hioffset:
                return (False, None)
            if looffset + lo.getSize() != hioffset:
                return (False, None)
            return (True, lo.getAddr())

    @staticmethod
    def applyRuleIn(inv, data) -> int:
        """Try to perform one transform on a logical double precision operation.
        Corresponds to SplitVarnode::applyRuleIn in double.cc."""
        for i in range(2):
            vn = inv.getHi() if i == 0 else inv.getLo()
            if vn is None:
                continue
            workishi = (i == 0)
            for workop in list(vn.getDescendants()):
                opc = workop.code()
                if opc == OpCode.CPUI_INT_ADD:
                    af = AddForm()
                    if af.applyRule(inv, workop, workishi, data):
                        return 1
                    sf = SubForm()
                    if sf.applyRule(inv, workop, workishi, data):
                        return 1
                elif opc == OpCode.CPUI_INT_AND:
                    ef = Equal3Form()
                    if ef.applyRule(inv, workop, workishi, data):
                        return 1
                    lf = LogicalForm()
                    if lf.applyRule(inv, workop, workishi, data):
                        return 1
                elif opc in (OpCode.CPUI_INT_OR, OpCode.CPUI_INT_XOR):
                    lf = LogicalForm()
                    if lf.applyRule(inv, workop, workishi, data):
                        return 1
                elif opc in (OpCode.CPUI_INT_EQUAL, OpCode.CPUI_INT_NOTEQUAL):
                    lt = LessThreeWay()
                    if lt.applyRule(inv, workop, workishi, data):
                        return 1
                    e1 = Equal1Form()
                    if e1.applyRule(inv, workop, workishi, data):
                        return 1
                    e2 = Equal2Form()
                    if e2.applyRule(inv, workop, workishi, data):
                        return 1
                elif opc in (OpCode.CPUI_INT_LESS, OpCode.CPUI_INT_LESSEQUAL):
                    lt = LessThreeWay()
                    if lt.applyRule(inv, workop, workishi, data):
                        return 1
                    lc = LessConstForm()
                    if lc.applyRule(inv, workop, workishi, data):
                        return 1
                elif opc in (OpCode.CPUI_INT_SLESS, OpCode.CPUI_INT_SLESSEQUAL):
                    lc = LessConstForm()
                    if lc.applyRule(inv, workop, workishi, data):
                        return 1
                elif opc == OpCode.CPUI_INT_LEFT:
                    shf = ShiftForm()
                    if hasattr(shf, 'applyRuleLeft') and shf.applyRuleLeft(inv, workop, workishi, data):
                        return 1
                elif opc in (OpCode.CPUI_INT_RIGHT, OpCode.CPUI_INT_SRIGHT):
                    shf = ShiftForm()
                    if hasattr(shf, 'applyRuleRight') and shf.applyRuleRight(inv, workop, workishi, data):
                        return 1
                elif opc == OpCode.CPUI_INT_MULT:
                    mf = MultForm()
                    if mf.applyRule(inv, workop, workishi, data):
                        return 1
                elif opc == OpCode.CPUI_MULTIEQUAL:
                    pf = PhiForm()
                    if pf.applyRule(inv, workop, workishi, data):
                        return 1
                elif opc == OpCode.CPUI_INDIRECT:
                    idf = IndirectForm()
                    if idf.applyRule(inv, workop, workishi, data):
                        return 1
                elif opc == OpCode.CPUI_COPY:
                    outvn = workop.getOut()
                    if outvn is not None and hasattr(outvn, 'isAddrForce') and outvn.isAddrForce():
                        cf = CopyForceForm()
                        if cf.applyRule(inv, workop, workishi, data):
                            return 1
        return 0


class AddForm:
    """Verify and collect the components of a double-precision add.
    Corresponds to AddForm in double.cc."""

    def __init__(self) -> None:
        self.inv = SplitVarnode()
        self.indoub = SplitVarnode()
        self.outdoub = SplitVarnode()
        self.lo1 = None
        self.lo2 = None
        self.hi1 = None
        self.hi2 = None
        self.reshi = None
        self.reslo = None
        self.negconst: int = 0
        self.slot1: int = 0
        self.existop = None

    def checkForCarry(self, op) -> bool:
        """Check if op matches a CARRY construction based on lo1."""
        if op.code() != OpCode.CPUI_INT_ZEXT:
            return False
        if not op.getIn(0).isWritten():
            return False
        carryop = op.getIn(0).getDef()
        if carryop.code() == OpCode.CPUI_INT_CARRY:
            if carryop.getIn(0) is self.lo1:
                self.lo2 = carryop.getIn(1)
            elif carryop.getIn(1) is self.lo1:
                self.lo2 = carryop.getIn(0)
            else:
                return False
            if self.lo2.isConstant():
                return False
            return True
        if carryop.code() == OpCode.CPUI_INT_LESS:
            tmpvn = carryop.getIn(0)
            if tmpvn.isConstant():
                if carryop.getIn(1) is not self.lo1:
                    return False
                self.negconst = tmpvn.getOffset()
                mask = (1 << (self.lo1.getSize() * 8)) - 1
                self.negconst = (~self.negconst) & mask
                self.lo2 = None
                return True
            elif tmpvn.isWritten():
                loadd_op = tmpvn.getDef()
                if loadd_op.code() != OpCode.CPUI_INT_ADD:
                    return False
                if loadd_op.getIn(0) is self.lo1:
                    othervn = loadd_op.getIn(1)
                elif loadd_op.getIn(1) is self.lo1:
                    othervn = loadd_op.getIn(0)
                else:
                    return False
                if othervn.isConstant():
                    self.negconst = othervn.getOffset()
                    self.lo2 = None
                    relvn = carryop.getIn(1)
                    if relvn is self.lo1:
                        return True
                    if not relvn.isConstant():
                        return False
                    if relvn.getOffset() != self.negconst:
                        return False
                    return True
                else:
                    self.lo2 = othervn
                    compvn = carryop.getIn(1)
                    if compvn is self.lo2 or compvn is self.lo1:
                        return True
            return False
        if carryop.code() == OpCode.CPUI_INT_NOTEQUAL:
            if not carryop.getIn(1).isConstant():
                return False
            if carryop.getIn(0) is not self.lo1:
                return False
            if carryop.getIn(1).getOffset() != 0:
                return False
            mask = (1 << (self.lo1.getSize() * 8)) - 1
            self.negconst = mask
            self.lo2 = None
            return True
        return False

    def verify(self, h, l, op) -> bool:
        """Verify the double-precision add form.
        Corresponds to AddForm::verify in double.cc."""
        self.hi1 = h
        self.lo1 = l
        self.slot1 = op.getSlot(self.hi1)
        for i in range(3):
            if i == 0:
                add2 = op.getOut().loneDescend() if hasattr(op.getOut(), 'loneDescend') else None
                if add2 is None:
                    continue
                if add2.code() != OpCode.CPUI_INT_ADD:
                    continue
                self.reshi = add2.getOut()
                hizext1 = op.getIn(1 - self.slot1)
                hizext2 = add2.getIn(1 - add2.getSlot(op.getOut()))
            elif i == 1:
                tmpvn = op.getIn(1 - self.slot1)
                if not tmpvn.isWritten():
                    continue
                add2 = tmpvn.getDef()
                if add2.code() != OpCode.CPUI_INT_ADD:
                    continue
                self.reshi = op.getOut()
                hizext1 = add2.getIn(0)
                hizext2 = add2.getIn(1)
            else:
                self.reshi = op.getOut()
                hizext1 = op.getIn(1 - self.slot1)
                hizext2 = None

            for j in range(2):
                if i == 2:
                    if not hizext1.isWritten():
                        continue
                    zextop = hizext1.getDef()
                    self.hi2 = None
                elif j == 0:
                    if not hizext1.isWritten():
                        continue
                    zextop = hizext1.getDef()
                    self.hi2 = hizext2
                else:
                    if hizext2 is None or not hizext2.isWritten():
                        continue
                    zextop = hizext2.getDef()
                    self.hi2 = hizext1
                if not self.checkForCarry(zextop):
                    continue
                for loadd in list(self.lo1.getDescendants()):
                    if loadd.code() != OpCode.CPUI_INT_ADD:
                        continue
                    tmpvn2 = loadd.getIn(1 - loadd.getSlot(self.lo1))
                    if self.lo2 is None:
                        if not tmpvn2.isConstant():
                            continue
                        if tmpvn2.getOffset() != self.negconst:
                            continue
                        self.lo2 = tmpvn2
                    elif self.lo2.isConstant():
                        if not tmpvn2.isConstant():
                            continue
                        if self.lo2.getOffset() != tmpvn2.getOffset():
                            continue
                    elif loadd.getIn(1 - loadd.getSlot(self.lo1)) is not self.lo2:
                        continue
                    self.reslo = loadd.getOut()
                    return True
        return False

    def applyRule(self, i, op, workishi: bool, data) -> bool:
        """Apply the add form rule.
        Corresponds to AddForm::applyRule in double.cc."""
        if not workishi:
            return False
        if not i.hasBothPieces():
            return False
        self.inv = i
        if not self.verify(self.inv.getHi(), self.inv.getLo(), op):
            return False
        self.indoub.initPartial(self.inv.getSize(), self.lo2, self.hi2)
        if self.indoub.exceedsConstPrecision():
            return False
        self.outdoub.initPartial(self.inv.getSize(), self.reslo, self.reshi)
        self.existop = SplitVarnode.prepareBinaryOp(self.outdoub, self.inv, self.indoub)
        if self.existop is None:
            return False
        SplitVarnode.createBinaryOp(data, self.outdoub, self.inv, self.indoub, self.existop, OpCode.CPUI_INT_ADD)
        return True


class SubForm:
    """Verify and collect the components of a double-precision subtract.
    Corresponds to SubForm in double.cc."""

    def __init__(self) -> None:
        self.inv = SplitVarnode()
        self.indoub = SplitVarnode()
        self.outdoub = SplitVarnode()
        self.lo1 = None
        self.lo2 = None
        self.hi1 = None
        self.hi2 = None
        self.reshi = None
        self.reslo = None
        self.existop = None

    def verify(self, h, l, op) -> bool:
        """Verify the double-precision subtract form.
        Corresponds to SubForm::verify in double.cc."""
        self.hi1 = h
        self.lo1 = l
        slot1 = op.getSlot(self.hi1)
        for i in range(2):
            if i == 0:
                add2 = op.getOut().loneDescend() if hasattr(op.getOut(), 'loneDescend') else None
                if add2 is None:
                    continue
                if add2.code() != OpCode.CPUI_INT_ADD:
                    continue
                self.reshi = add2.getOut()
                hineg1 = op.getIn(1 - slot1)
                hineg2 = add2.getIn(1 - add2.getSlot(op.getOut()))
            else:
                tmpvn = op.getIn(1 - slot1)
                if not tmpvn.isWritten():
                    continue
                add2 = tmpvn.getDef()
                if add2.code() != OpCode.CPUI_INT_ADD:
                    continue
                self.reshi = op.getOut()
                hineg1 = add2.getIn(0)
                hineg2 = add2.getIn(1)
            if not hineg1.isWritten() or not hineg2.isWritten():
                continue
            if not SplitVarnode.verifyMultNegOne(hineg1.getDef()):
                continue
            if not SplitVarnode.verifyMultNegOne(hineg2.getDef()):
                continue
            hizext1 = hineg1.getDef().getIn(0)
            hizext2 = hineg2.getDef().getIn(0)
            for j in range(2):
                if j == 0:
                    if not hizext1.isWritten():
                        continue
                    zextop = hizext1.getDef()
                    self.hi2 = hizext2
                else:
                    if not hizext2.isWritten():
                        continue
                    zextop = hizext2.getDef()
                    self.hi2 = hizext1
                if zextop.code() != OpCode.CPUI_INT_ZEXT:
                    continue
                if not zextop.getIn(0).isWritten():
                    continue
                lessop = zextop.getIn(0).getDef()
                if lessop.code() != OpCode.CPUI_INT_LESS:
                    continue
                if lessop.getIn(0) is not self.lo1:
                    continue
                self.lo2 = lessop.getIn(1)
                for loadd in list(self.lo1.getDescendants()):
                    if loadd.code() != OpCode.CPUI_INT_ADD:
                        continue
                    tmpvn2 = loadd.getIn(1 - loadd.getSlot(self.lo1))
                    if not tmpvn2.isWritten():
                        continue
                    negop = tmpvn2.getDef()
                    if not SplitVarnode.verifyMultNegOne(negop):
                        continue
                    if negop.getIn(0) is not self.lo2:
                        continue
                    self.reslo = loadd.getOut()
                    return True
        return False

    def applyRule(self, i, op, workishi: bool, data) -> bool:
        """Apply the sub form rule.
        Corresponds to SubForm::applyRule in double.cc."""
        if not workishi:
            return False
        if not i.hasBothPieces():
            return False
        self.inv = i
        if not self.verify(self.inv.getHi(), self.inv.getLo(), op):
            return False
        self.indoub.initPartial(self.inv.getSize(), self.lo2, self.hi2)
        if self.indoub.exceedsConstPrecision():
            return False
        self.outdoub.initPartial(self.inv.getSize(), self.reslo, self.reshi)
        self.existop = SplitVarnode.prepareBinaryOp(self.outdoub, self.inv, self.indoub)
        if self.existop is None:
            return False
        SplitVarnode.createBinaryOp(data, self.outdoub, self.inv, self.indoub, self.existop, OpCode.CPUI_INT_SUB)
        return True


class LogicalForm:
    """Verify double-precision logical operations (AND, OR, XOR).
    Corresponds to LogicalForm in double.cc."""

    def __init__(self) -> None:
        self.inv = SplitVarnode()
        self.indoub = SplitVarnode()
        self.outdoub = SplitVarnode()
        self.hi1 = None
        self.lo1 = None
        self.hi2 = None
        self.lo2 = None
        self.hiop = None
        self.loop = None
        self.existop = None

    def findHiMatch(self) -> int:
        """Look for the matching hi-precision operation.
        Corresponds to LogicalForm::findHiMatch in double.cc."""
        lo1Tmp = self.inv.getLo()
        vn2 = self.loop.getIn(1 - self.loop.getSlot(lo1Tmp))
        out = SplitVarnode()
        if out.inHandLoOut(lo1Tmp):
            hi = out.getHi()
            if hi is not None and hi.isWritten():
                maybeop = hi.getDef()
                if maybeop.code() == self.loop.code():
                    if maybeop.getIn(0) is self.hi1:
                        if maybeop.getIn(1).isConstant() == vn2.isConstant():
                            self.hiop = maybeop
                            return 0
                    elif maybeop.getIn(1) is self.hi1:
                        if maybeop.getIn(0).isConstant() == vn2.isConstant():
                            self.hiop = maybeop
                            return 0
        if not vn2.isConstant():
            in2 = SplitVarnode()
            if in2.inHandLo(vn2):
                for maybeop in in2.getHi().getDescendants():
                    if maybeop.code() == self.loop.code():
                        if maybeop.getIn(0) is self.hi1 or maybeop.getIn(1) is self.hi1:
                            self.hiop = maybeop
                            return 0
            return -1
        else:
            count = 0
            lastop = None
            for maybeop in self.hi1.getDescendants():
                if maybeop.code() == self.loop.code():
                    if maybeop.getIn(1).isConstant():
                        count += 1
                        if count > 1:
                            break
                        lastop = maybeop
            if count == 1:
                self.hiop = lastop
                return 0
            if count > 1:
                return -1
        return -2

    def verify(self, h, l, lop) -> bool:
        """Verify the double-precision logical form.
        Corresponds to LogicalForm::verify in double.cc."""
        self.loop = lop
        self.lo1 = l
        self.hi1 = h
        res = self.findHiMatch()
        if res == 0:
            self.lo2 = self.loop.getIn(1 - self.loop.getSlot(self.lo1))
            self.hi2 = self.hiop.getIn(1 - self.hiop.getSlot(self.hi1))
            if self.lo2 is self.lo1 or self.lo2 is self.hi1 or self.hi2 is self.hi1 or self.hi2 is self.lo1:
                return False
            if self.lo2 is self.hi2:
                return False
            return True
        return False

    def applyRule(self, i, lop, workishi: bool, data) -> bool:
        """Apply the logical form rule.
        Corresponds to LogicalForm::applyRule in double.cc."""
        if workishi:
            return False
        if not i.hasBothPieces():
            return False
        self.inv = i
        if not self.verify(self.inv.getHi(), self.inv.getLo(), lop):
            return False
        self.outdoub.initPartial(self.inv.getSize(), self.loop.getOut(), self.hiop.getOut())
        self.indoub.initPartial(self.inv.getSize(), self.lo2, self.hi2)
        if self.indoub.exceedsConstPrecision():
            return False
        self.existop = SplitVarnode.prepareBinaryOp(self.outdoub, self.inv, self.indoub)
        if self.existop is None:
            return False
        SplitVarnode.createBinaryOp(data, self.outdoub, self.inv, self.indoub, self.existop, self.loop.code())
        return True


class Equal1Form:
    """Verify double-precision equality comparison (branching form).
    Corresponds to Equal1Form in double.cc."""

    def __init__(self) -> None:
        self.in1 = SplitVarnode()
        self.in2 = SplitVarnode()

    def applyRule(self, i, hop, workishi: bool, data) -> bool:
        """Apply the equal1 form rule.
        Corresponds to Equal1Form::applyRule in double.cc."""
        if not workishi:
            return False
        if not i.hasBothPieces():
            return False
        self.in1 = i
        hi1 = self.in1.getHi()
        lo1 = self.in1.getLo()
        hi1slot = hop.getSlot(hi1)
        hi2 = hop.getIn(1 - hi1slot)
        notequalformhi = (hop.code() == OpCode.CPUI_INT_NOTEQUAL)
        for loop in list(lo1.getDescendants()):
            if loop.code() == OpCode.CPUI_INT_EQUAL:
                notequalformlo = False
            elif loop.code() == OpCode.CPUI_INT_NOTEQUAL:
                notequalformlo = True
            else:
                continue
            lo2 = loop.getIn(1 - loop.getSlot(lo1))
            for hibool in list(hop.getOut().getDescendants()):
                for lobool in list(loop.getOut().getDescendants()):
                    self.in2 = SplitVarnode()
                    self.in2.initPartial(self.in1.getSize(), lo2, hi2)
                    if self.in2.exceedsConstPrecision():
                        continue
                    if hibool.code() == OpCode.CPUI_CBRANCH and lobool.code() == OpCode.CPUI_CBRANCH:
                        hibooltrue, hiboolfalse = SplitVarnode.getTrueFalse(hibool, notequalformhi)
                        lobooltrue, loboolfalse = SplitVarnode.getTrueFalse(lobool, notequalformlo)
                        if (hibooltrue is lobool.getParent() and
                                hiboolfalse is loboolfalse and
                                SplitVarnode.otherwiseEmpty(lobool)):
                            if SplitVarnode.prepareBoolOp(self.in1, self.in2, hibool):
                                opc = OpCode.CPUI_INT_NOTEQUAL if notequalformhi else OpCode.CPUI_INT_EQUAL
                                SplitVarnode.createBoolOp(data, hibool, self.in1, self.in2, opc)
                                cval = 0 if notequalformlo else 1
                                data.opSetInput(lobool, data.newConstant(1, cval), 1)
                                return True
                        elif (lobooltrue is hibool.getParent() and
                                hiboolfalse is loboolfalse and
                                SplitVarnode.otherwiseEmpty(hibool)):
                            if SplitVarnode.prepareBoolOp(self.in1, self.in2, lobool):
                                opc = OpCode.CPUI_INT_NOTEQUAL if notequalformlo else OpCode.CPUI_INT_EQUAL
                                SplitVarnode.createBoolOp(data, lobool, self.in1, self.in2, opc)
                                cval = 0 if notequalformhi else 1
                                data.opSetInput(hibool, data.newConstant(1, cval), 1)
                                return True
        return False


class LessConstForm:
    """Verify double-precision less-than with a constant.
    Corresponds to LessConstForm in double.cc."""

    def __init__(self) -> None:
        self.inv = SplitVarnode()
        self.val: int = 0

    def applyRule(self, i, op, workishi: bool, data) -> bool:
        """Apply the less-constant form rule.
        Corresponds to LessConstForm::applyRule in double.cc."""
        if not workishi:
            return False
        if i.getHi() is None:
            return False
        self.inv = i
        vn = self.inv.getHi()
        inslot = op.getSlot(vn)
        cvn = op.getIn(1 - inslot)
        losize = self.inv.getSize() - vn.getSize()
        if not cvn.isConstant():
            return False
        signcompare = op.code() in (OpCode.CPUI_INT_SLESSEQUAL, OpCode.CPUI_INT_SLESS)
        hilessequalform = op.code() in (OpCode.CPUI_INT_SLESSEQUAL, OpCode.CPUI_INT_LESSEQUAL)
        val = cvn.getOffset() << (8 * losize)
        if hilessequalform != (inslot == 1):
            val |= (1 << (8 * losize)) - 1
        desc = op.getOut().loneDescend() if hasattr(op.getOut(), 'loneDescend') else None
        if desc is None:
            return False
        if desc.code() != OpCode.CPUI_CBRANCH:
            return False
        constin = SplitVarnode()
        constin.initPartialConst(self.inv.getSize(), val)
        if constin.exceedsConstPrecision():
            return False
        if inslot == 0:
            if SplitVarnode.prepareBoolOp(self.inv, constin, op):
                SplitVarnode.replaceBoolOp(data, op, self.inv, constin, op.code())
                return True
        else:
            if SplitVarnode.prepareBoolOp(constin, self.inv, op):
                SplitVarnode.replaceBoolOp(data, op, constin, self.inv, op.code())
                return True
        return False


class ShiftForm:
    """Verify double-precision shift operations.
    Corresponds to ShiftForm in double.cc."""

    def __init__(self) -> None:
        self.inv = SplitVarnode()
        self.out = SplitVarnode()
        self.lo = None
        self.hi = None
        self.reslo = None
        self.reshi = None
        self.midlo = None
        self.midhi = None
        self.salo = None
        self.sahi = None
        self.samid = None
        self.loshift = None
        self.midshift = None
        self.hishift = None
        self.orop = None
        self.opc = None
        self.existop = None

    def mapLeft(self) -> bool:
        """Assume reshi, reslo are filled in, fill in other ops and varnodes for left shift."""
        if not self.reslo.isWritten():
            return False
        if not self.reshi.isWritten():
            return False
        self.loshift = self.reslo.getDef()
        self.opc = self.loshift.code()
        if self.opc != OpCode.CPUI_INT_LEFT:
            return False
        self.orop = self.reshi.getDef()
        if self.orop.code() not in (OpCode.CPUI_INT_OR, OpCode.CPUI_INT_XOR, OpCode.CPUI_INT_ADD):
            return False
        self.midlo = self.orop.getIn(0)
        self.midhi = self.orop.getIn(1)
        if not self.midlo.isWritten():
            return False
        if not self.midhi.isWritten():
            return False
        if self.midhi.getDef().code() != OpCode.CPUI_INT_LEFT:
            self.midhi, self.midlo = self.midlo, self.midhi
        self.midshift = self.midlo.getDef()
        if self.midshift.code() != OpCode.CPUI_INT_RIGHT:
            return False
        self.hishift = self.midhi.getDef()
        if self.hishift.code() != OpCode.CPUI_INT_LEFT:
            return False
        if self.lo is not self.loshift.getIn(0):
            return False
        if self.hi is not self.hishift.getIn(0):
            return False
        if self.lo is not self.midshift.getIn(0):
            return False
        self.salo = self.loshift.getIn(1)
        self.sahi = self.hishift.getIn(1)
        self.samid = self.midshift.getIn(1)
        return True

    def mapRight(self) -> bool:
        """Assume reshi, reslo are filled in, fill in other ops and varnodes for right shift."""
        if not self.reslo.isWritten():
            return False
        if not self.reshi.isWritten():
            return False
        self.hishift = self.reshi.getDef()
        self.opc = self.hishift.code()
        if self.opc not in (OpCode.CPUI_INT_RIGHT, OpCode.CPUI_INT_SRIGHT):
            return False
        self.orop = self.reslo.getDef()
        if self.orop.code() not in (OpCode.CPUI_INT_OR, OpCode.CPUI_INT_XOR, OpCode.CPUI_INT_ADD):
            return False
        self.midlo = self.orop.getIn(0)
        self.midhi = self.orop.getIn(1)
        if not self.midlo.isWritten():
            return False
        if not self.midhi.isWritten():
            return False
        if self.midlo.getDef().code() != OpCode.CPUI_INT_RIGHT:
            self.midhi, self.midlo = self.midlo, self.midhi
        self.midshift = self.midhi.getDef()
        if self.midshift.code() != OpCode.CPUI_INT_LEFT:
            return False
        self.loshift = self.midlo.getDef()
        if self.loshift.code() != OpCode.CPUI_INT_RIGHT:
            return False
        if self.lo is not self.loshift.getIn(0):
            return False
        if self.hi is not self.hishift.getIn(0):
            return False
        if self.hi is not self.midshift.getIn(0):
            return False
        self.salo = self.loshift.getIn(1)
        self.sahi = self.hishift.getIn(1)
        self.samid = self.midshift.getIn(1)
        return True

    def verifyShiftAmount(self) -> bool:
        """Make sure all the shift amount varnodes are consistent."""
        if not self.salo.isConstant():
            return False
        if not self.samid.isConstant():
            return False
        if not self.sahi.isConstant():
            return False
        val = self.salo.getOffset()
        if val != self.sahi.getOffset():
            return False
        if val >= 8 * self.lo.getSize():
            return False
        complement = 8 * self.lo.getSize() - val
        if self.samid.getOffset() != complement:
            return False
        return True

    def verifyLeft(self, h, l, loop) -> bool:
        """Verify the left shift pattern starting from the lo shift op."""
        self.hi = h
        self.lo = l
        self.loshift = loop
        self.reslo = self.loshift.getOut()
        for hishift in list(h.getDescendants()):
            if hishift.code() != OpCode.CPUI_INT_LEFT:
                continue
            outvn = hishift.getOut()
            for midshift in list(outvn.getDescendants()):
                tmpvn = midshift.getOut()
                if tmpvn is None:
                    continue
                self.reshi = tmpvn
                if not self.mapLeft():
                    continue
                if not self.verifyShiftAmount():
                    continue
                return True
        return False

    def verifyRight(self, h, l, hiop) -> bool:
        """Verify the right shift pattern starting from the hi shift op."""
        self.hi = h
        self.lo = l
        self.hishift = hiop
        self.reshi = hiop.getOut()
        for loshift in list(l.getDescendants()):
            if loshift.code() != OpCode.CPUI_INT_RIGHT:
                continue
            outvn = loshift.getOut()
            for midshift in list(outvn.getDescendants()):
                tmpvn = midshift.getOut()
                if tmpvn is None:
                    continue
                self.reslo = tmpvn
                if not self.mapRight():
                    continue
                if not self.verifyShiftAmount():
                    continue
                return True
        return False

    def applyRuleLeft(self, i, op, workishi: bool, data) -> bool:
        """Apply the left shift form rule.
        Corresponds to ShiftForm::applyRuleLeft in double.cc."""
        if workishi:
            return False
        if not i.hasBothPieces():
            return False
        self.inv = i
        if not self.verifyLeft(self.inv.getHi(), self.inv.getLo(), op):
            return False
        self.out.initPartial(self.inv.getSize(), self.reslo, self.reshi)
        self.existop = SplitVarnode.prepareShiftOp(self.out, self.inv)
        if self.existop is None:
            return False
        SplitVarnode.createShiftOp(data, self.out, self.inv, self.salo, self.existop, self.opc)
        return True

    def applyRuleRight(self, i, op, workishi: bool, data) -> bool:
        """Apply the right shift form rule.
        Corresponds to ShiftForm::applyRuleRight in double.cc."""
        if not workishi:
            return False
        if not i.hasBothPieces():
            return False
        self.inv = i
        if not self.verifyRight(self.inv.getHi(), self.inv.getLo(), op):
            return False
        self.out.initPartial(self.inv.getSize(), self.reslo, self.reshi)
        self.existop = SplitVarnode.prepareShiftOp(self.out, self.inv)
        if self.existop is None:
            return False
        SplitVarnode.createShiftOp(data, self.out, self.inv, self.salo, self.existop, self.opc)
        return True


class MultForm:
    """Verify double-precision multiply.
    Corresponds to MultForm in double.cc."""

    def __init__(self) -> None:
        self.inv = SplitVarnode()
        self.in2 = SplitVarnode()
        self.outdoub = SplitVarnode()
        self.lo1 = None
        self.hi1 = None
        self.lo2 = None
        self.hi2 = None
        self.reslo = None
        self.reshi = None
        self.midtmp = None
        self.lo1zext = None
        self.lo2zext = None
        self.add1 = None
        self.add2 = None
        self.subhi = None
        self.multhi1 = None
        self.multhi2 = None
        self.multlo = None
        self.existop = None

    @staticmethod
    def zextOf(big, small) -> bool:
        """Verify that big is (some form of) a zero extension of small."""
        if small.isConstant():
            if not big.isConstant():
                return False
            return big.getOffset() == small.getOffset()
        if not big.isWritten():
            return False
        op = big.getDef()
        if op.code() == OpCode.CPUI_INT_ZEXT:
            return op.getIn(0) is small
        if op.code() == OpCode.CPUI_INT_AND:
            if not op.getIn(1).isConstant():
                return False
            if op.getIn(1).getOffset() != calc_mask(small.getSize()):
                return False
            whole = op.getIn(0)
            if not small.isWritten():
                return False
            sub = small.getDef()
            if sub.code() != OpCode.CPUI_SUBPIECE:
                return False
            return sub.getIn(0) is whole
        return False

    def mapResHiSmallConst(self, rhi) -> bool:
        """Find reshi = hi1*lo2 + (tmp>>32) for small constant case."""
        self.reshi = rhi
        if not self.reshi.isWritten():
            return False
        self.add1 = self.reshi.getDef()
        if self.add1.code() != OpCode.CPUI_INT_ADD:
            return False
        ad1 = self.add1.getIn(0)
        ad2 = self.add1.getIn(1)
        if not ad1.isWritten():
            return False
        if not ad2.isWritten():
            return False
        self.multhi1 = ad1.getDef()
        if self.multhi1.code() != OpCode.CPUI_INT_MULT:
            self.subhi = self.multhi1
            self.multhi1 = ad2.getDef()
        else:
            self.subhi = ad2.getDef()
        if self.multhi1.code() != OpCode.CPUI_INT_MULT:
            return False
        if self.subhi.code() != OpCode.CPUI_SUBPIECE:
            return False
        self.midtmp = self.subhi.getIn(0)
        if not self.midtmp.isWritten():
            return False
        self.multlo = self.midtmp.getDef()
        if self.multlo.code() != OpCode.CPUI_INT_MULT:
            return False
        self.lo1zext = self.multlo.getIn(0)
        self.lo2zext = self.multlo.getIn(1)
        return True

    def mapResHi(self, rhi) -> bool:
        """Find reshi = hi1*lo2 + hi2*lo1 + (tmp>>32)."""
        self.reshi = rhi
        if not self.reshi.isWritten():
            return False
        self.add1 = self.reshi.getDef()
        if self.add1.code() != OpCode.CPUI_INT_ADD:
            return False
        ad1 = self.add1.getIn(0)
        ad2 = self.add1.getIn(1)
        if not ad1.isWritten():
            return False
        if not ad2.isWritten():
            return False
        self.add2 = ad1.getDef()
        if self.add2.code() == OpCode.CPUI_INT_ADD:
            ad1 = self.add2.getIn(0)
            ad3 = self.add2.getIn(1)
        else:
            self.add2 = ad2.getDef()
            if self.add2.code() != OpCode.CPUI_INT_ADD:
                return False
            ad2 = self.add2.getIn(0)
            ad3 = self.add2.getIn(1)
        if not ad1.isWritten():
            return False
        if not ad2.isWritten():
            return False
        if not ad3.isWritten():
            return False
        self.subhi = ad1.getDef()
        if self.subhi.code() == OpCode.CPUI_SUBPIECE:
            self.multhi1 = ad2.getDef()
            self.multhi2 = ad3.getDef()
        else:
            self.subhi = ad2.getDef()
            if self.subhi.code() == OpCode.CPUI_SUBPIECE:
                self.multhi1 = ad1.getDef()
                self.multhi2 = ad3.getDef()
            else:
                self.subhi = ad3.getDef()
                if self.subhi.code() == OpCode.CPUI_SUBPIECE:
                    self.multhi1 = ad1.getDef()
                    self.multhi2 = ad2.getDef()
                else:
                    return False
        if self.multhi1.code() != OpCode.CPUI_INT_MULT:
            return False
        if self.multhi2.code() != OpCode.CPUI_INT_MULT:
            return False
        self.midtmp = self.subhi.getIn(0)
        if not self.midtmp.isWritten():
            return False
        self.multlo = self.midtmp.getDef()
        if self.multlo.code() != OpCode.CPUI_INT_MULT:
            return False
        self.lo1zext = self.multlo.getIn(0)
        self.lo2zext = self.multlo.getIn(1)
        return True

    def findLoFromInSmallConst(self) -> bool:
        """Label lo2 from multhi1, assuming small constant model."""
        vn1 = self.multhi1.getIn(0)
        vn2 = self.multhi1.getIn(1)
        if vn1 is self.hi1:
            self.lo2 = vn2
        elif vn2 is self.hi1:
            self.lo2 = vn1
        else:
            return False
        if not self.lo2.isConstant():
            return False
        self.hi2 = None
        return True

    def findLoFromIn(self) -> bool:
        """Label lo2/hi2 pair from multhi1 and multhi2."""
        vn1 = self.multhi1.getIn(0)
        vn2 = self.multhi1.getIn(1)
        if vn1 is not self.lo1 and vn2 is not self.lo1:
            self.multhi1, self.multhi2 = self.multhi2, self.multhi1
            vn1 = self.multhi1.getIn(0)
            vn2 = self.multhi1.getIn(1)
        if vn1 is self.lo1:
            self.hi2 = vn2
        elif vn2 is self.lo1:
            self.hi2 = vn1
        else:
            return False
        vn1 = self.multhi2.getIn(0)
        vn2 = self.multhi2.getIn(1)
        if vn1 is self.hi1:
            self.lo2 = vn2
        elif vn2 is self.hi1:
            self.lo2 = vn1
        else:
            return False
        return True

    def verifyLo(self) -> bool:
        """Verify midtmp is formed properly from lo1 and lo2."""
        if int(self.subhi.getIn(1).getOffset()) != self.lo1.getSize():
            return False
        if MultForm.zextOf(self.lo1zext, self.lo1):
            if MultForm.zextOf(self.lo2zext, self.lo2):
                return True
        elif MultForm.zextOf(self.lo1zext, self.lo2):
            if MultForm.zextOf(self.lo2zext, self.lo1):
                return True
        return False

    def findResLo(self) -> bool:
        """Find potential reslo from midtmp descendants."""
        for op in list(self.midtmp.getDescendants()):
            if op.code() != OpCode.CPUI_SUBPIECE:
                continue
            if int(op.getIn(1).getOffset()) != 0:
                continue
            self.reslo = op.getOut()
            if self.reslo.getSize() != self.lo1.getSize():
                continue
            return True
        for op in list(self.lo1.getDescendants()):
            if op.code() != OpCode.CPUI_INT_MULT:
                continue
            vn1 = op.getIn(0)
            vn2 = op.getIn(1)
            if self.lo2.isConstant():
                if (not vn1.isConstant() or vn1.getOffset() != self.lo2.getOffset()) and \
                   (not vn2.isConstant() or vn2.getOffset() != self.lo2.getOffset()):
                    continue
            else:
                if op.getIn(0) is not self.lo2 and op.getIn(1) is not self.lo2:
                    continue
            self.reslo = op.getOut()
            return True
        return False

    def mapFromInSmallConst(self, rhi) -> bool:
        if not self.mapResHiSmallConst(rhi):
            return False
        if not self.findLoFromInSmallConst():
            return False
        if not self.verifyLo():
            return False
        if not self.findResLo():
            return False
        return True

    def mapFromIn(self, rhi) -> bool:
        if not self.mapResHi(rhi):
            return False
        if not self.findLoFromIn():
            return False
        if not self.verifyLo():
            return False
        if not self.findResLo():
            return False
        return True

    def replace(self, data) -> bool:
        """Transform matched multiply to logical variables."""
        self.outdoub.initPartial(self.inv.getSize(), self.reslo, self.reshi)
        if self.hi2 is None:
            losize = self.lo1.getSize()
            val = self.lo2.getOffset() & calc_mask(losize)
            self.in2.initPartialConst(self.inv.getSize(), val)
        else:
            self.in2.initPartial(self.inv.getSize(), self.lo2, self.hi2)
        if self.in2.exceedsConstPrecision():
            return False
        self.existop = SplitVarnode.prepareBinaryOp(self.outdoub, self.inv, self.in2)
        if self.existop is None:
            return False
        SplitVarnode.createBinaryOp(data, self.outdoub, self.inv, self.in2, self.existop, OpCode.CPUI_INT_MULT)
        return True

    def verify(self, h, l, hop) -> bool:
        """Verify the full multiply pattern."""
        self.hi1 = h
        self.lo1 = l
        for add1 in list(hop.getOut().getDescendants()):
            if add1.code() != OpCode.CPUI_INT_ADD:
                continue
            self.add1 = add1
            for add2 in list(add1.getOut().getDescendants()):
                if add2.code() != OpCode.CPUI_INT_ADD:
                    continue
                self.add2 = add2
                if self.mapFromIn(add2.getOut()):
                    return True
            if self.mapFromIn(add1.getOut()):
                return True
            if self.mapFromInSmallConst(add1.getOut()):
                return True
        return False

    def applyRule(self, i, op, workishi: bool, data) -> bool:
        """Apply the mult form rule.
        Corresponds to MultForm::applyRule in double.cc."""
        if not workishi:
            return False
        if not i.hasBothPieces():
            return False
        self.inv = i
        if not self.verify(self.inv.getHi(), self.inv.getLo(), op):
            return False
        return self.replace(data)


class Equal2Form:
    """Verify double-precision equality comparison (form 2: AND/OR of comparisons).
    Corresponds to Equal2Form in double.cc."""
    def __init__(self) -> None:
        self.inv = SplitVarnode()
        self.param2 = SplitVarnode()
        self.hi1 = None
        self.lo1 = None
        self.hi2 = None
        self.lo2 = None
        self.boolAndOr = None

    def replace(self, data) -> bool:
        """Prepare the boolean replacement."""
        if self.hi2.isConstant() and self.lo2.isConstant():
            val = self.hi2.getOffset()
            val <<= 8 * self.lo1.getSize()
            val |= self.lo2.getOffset()
            self.param2.initPartialConst(self.inv.getSize(), val)
            return SplitVarnode.prepareBoolOp(self.inv, self.param2, self.boolAndOr)
        if self.hi2.isConstant() or self.lo2.isConstant():
            return False
        self.param2.initPartial(self.inv.getSize(), self.lo2, self.hi2)
        return SplitVarnode.prepareBoolOp(self.inv, self.param2, self.boolAndOr)

    def applyRule(self, i, op, workishi: bool, data) -> bool:
        """Apply the equal2 form rule.
        Corresponds to Equal2Form::applyRule in double.cc."""
        if not workishi:
            return False
        if not i.hasBothPieces():
            return False
        self.inv = i
        self.hi1 = self.inv.getHi()
        self.lo1 = self.inv.getLo()
        eqCode = op.code()
        hi1slot = op.getSlot(self.hi1)
        self.hi2 = op.getIn(1 - hi1slot)
        outvn = op.getOut()
        for boolAndOr in list(outvn.getDescendants()):
            if eqCode == OpCode.CPUI_INT_EQUAL and boolAndOr.code() != OpCode.CPUI_BOOL_AND:
                continue
            if eqCode == OpCode.CPUI_INT_NOTEQUAL and boolAndOr.code() != OpCode.CPUI_BOOL_OR:
                continue
            self.boolAndOr = boolAndOr
            slot = boolAndOr.getSlot(outvn)
            othervn = boolAndOr.getIn(1 - slot)
            if not othervn.isWritten():
                continue
            equalLo = othervn.getDef()
            if equalLo.code() != eqCode:
                continue
            if equalLo.getIn(0) is self.lo1:
                self.lo2 = equalLo.getIn(1)
            elif equalLo.getIn(1) is self.lo1:
                self.lo2 = equalLo.getIn(0)
            else:
                continue
            if not self.replace(data):
                continue
            if self.param2.exceedsConstPrecision():
                continue
            SplitVarnode.replaceBoolOp(data, boolAndOr, self.inv, self.param2, eqCode)
            return True
        return False


class Equal3Form:
    """Verify double-precision equality comparison (form 3: hi & lo == -1).
    Corresponds to Equal3Form in double.cc."""
    def __init__(self) -> None:
        self.inv = SplitVarnode()
        self.hi = None
        self.lo = None
        self.andop = None
        self.compareop = None
        self.smallc = None

    def verify(self, h, l, aop) -> bool:
        """Verify the AND+compare form.
        Corresponds to Equal3Form::verify in double.cc."""
        if aop.code() != OpCode.CPUI_INT_AND:
            return False
        self.hi = h
        self.lo = l
        self.andop = aop
        hislot = self.andop.getSlot(self.hi)
        if self.andop.getIn(1 - hislot) is not self.lo:
            return False
        self.compareop = self.andop.getOut().loneDescend() if hasattr(self.andop.getOut(), 'loneDescend') else None
        if self.compareop is None:
            return False
        if self.compareop.code() not in (OpCode.CPUI_INT_EQUAL, OpCode.CPUI_INT_NOTEQUAL):
            return False
        mask = (1 << (self.lo.getSize() * 8)) - 1
        self.smallc = self.compareop.getIn(1)
        if not self.smallc.isConstant():
            return False
        if self.smallc.getOffset() != mask:
            return False
        return True

    def applyRule(self, i, op, workishi: bool, data) -> bool:
        """Apply the equal3 form rule.
        Corresponds to Equal3Form::applyRule in double.cc."""
        if not workishi:
            return False
        if not i.hasBothPieces():
            return False
        self.inv = i
        if not self.verify(self.inv.getHi(), self.inv.getLo(), op):
            return False
        mask = (1 << (self.inv.getSize() * 8)) - 1
        in2 = SplitVarnode()
        in2.initPartialConst(self.inv.getSize(), mask)
        if in2.exceedsConstPrecision():
            return False
        if not SplitVarnode.prepareBoolOp(self.inv, in2, self.compareop):
            return False
        SplitVarnode.replaceBoolOp(data, self.compareop, self.inv, in2, self.compareop.code())
        return True


class LessThreeWay:
    """Verify double-precision less-than using three-way comparison.
    Corresponds to LessThreeWay in double.cc."""
    def __init__(self) -> None:
        self.inv = SplitVarnode()
        self.in2 = SplitVarnode()
        self.hilessbl = None
        self.lolessbl = None
        self.hieqbl = None
        self.hilesstrue = None
        self.hilessfalse = None
        self.hieqtrue = None
        self.hieqfalse = None
        self.lolesstrue = None
        self.lolessfalse = None
        self.hilessbool = None
        self.lolessbool = None
        self.hieqbool = None
        self.hiless = None
        self.hiequal = None
        self.loless = None
        self.vnhil1 = None
        self.vnhil2 = None
        self.vnhie1 = None
        self.vnhie2 = None
        self.vnlo1 = None
        self.vnlo2 = None
        self.hi = None
        self.lo = None
        self.hi2 = None
        self.lo2 = None
        self.hislot: int = 0
        self.hiflip: bool = False
        self.equalflip: bool = False
        self.loflip: bool = False
        self.lolessiszerocomp: bool = False
        self.lolessequalform: bool = False
        self.hilessequalform: bool = False
        self.signcompare: bool = False
        self.midlessform: bool = False
        self.midlessequal: bool = False
        self.midsigncompare: bool = False
        self.hiconstform: bool = False
        self.midconstform: bool = False
        self.loconstform: bool = False
        self.hival: int = 0
        self.midval: int = 0
        self.loval: int = 0
        self.finalopc = OpCode.CPUI_INT_LESS

    def mapBlocksFromLow(self, lobl) -> bool:
        """Map out blocks from the low-precision comparison block.

        C++ ref: LessThreeWay::mapBlocksFromLow
        """
        self.lolessbl = lobl
        if self.lolessbl.sizeIn() != 1:
            return False
        if self.lolessbl.sizeOut() != 2:
            return False
        self.hieqbl = self.lolessbl.getIn(0)
        if self.hieqbl.sizeIn() != 1:
            return False
        if self.hieqbl.sizeOut() != 2:
            return False
        self.hilessbl = self.hieqbl.getIn(0)
        if self.hilessbl.sizeOut() != 2:
            return False
        return True

    def mapOpsFromBlocks(self) -> bool:
        """Map CBRANCH ops and comparison ops from the three blocks.

        C++ ref: LessThreeWay::mapOpsFromBlocks
        """
        self.lolessbool = self.lolessbl.lastOp()
        if self.lolessbool is None:
            return False
        if self.lolessbool.code() != OpCode.CPUI_CBRANCH:
            return False
        self.hieqbool = self.hieqbl.lastOp()
        if self.hieqbool is None:
            return False
        if self.hieqbool.code() != OpCode.CPUI_CBRANCH:
            return False
        self.hilessbool = self.hilessbl.lastOp()
        if self.hilessbool is None:
            return False
        if self.hilessbool.code() != OpCode.CPUI_CBRANCH:
            return False

        self.hiflip = False
        self.equalflip = False
        self.loflip = False
        self.midlessform = False
        self.lolessiszerocomp = False

        vn = self.hieqbool.getIn(1)
        if not vn.isWritten():
            return False
        self.hiequal = vn.getDef()
        opc = self.hiequal.code()
        if opc == OpCode.CPUI_INT_EQUAL:
            self.midlessform = False
        elif opc == OpCode.CPUI_INT_NOTEQUAL:
            self.midlessform = False
        elif opc == OpCode.CPUI_INT_LESS:
            self.midlessequal = False
            self.midsigncompare = False
            self.midlessform = True
        elif opc == OpCode.CPUI_INT_LESSEQUAL:
            self.midlessequal = True
            self.midsigncompare = False
            self.midlessform = True
        elif opc == OpCode.CPUI_INT_SLESS:
            self.midlessequal = False
            self.midsigncompare = True
            self.midlessform = True
        elif opc == OpCode.CPUI_INT_SLESSEQUAL:
            self.midlessequal = True
            self.midsigncompare = True
            self.midlessform = True
        else:
            return False

        vn = self.lolessbool.getIn(1)
        if not vn.isWritten():
            return False
        self.loless = vn.getDef()
        opc = self.loless.code()
        if opc == OpCode.CPUI_INT_LESS:
            self.lolessequalform = False
        elif opc == OpCode.CPUI_INT_LESSEQUAL:
            self.lolessequalform = True
        elif opc == OpCode.CPUI_INT_EQUAL:
            if not self.loless.getIn(1).isConstant():
                return False
            if self.loless.getIn(1).getOffset() != 0:
                return False
            self.lolessiszerocomp = True
            self.lolessequalform = True
        elif opc == OpCode.CPUI_INT_NOTEQUAL:
            if not self.loless.getIn(1).isConstant():
                return False
            if self.loless.getIn(1).getOffset() != 0:
                return False
            self.lolessiszerocomp = True
            self.lolessequalform = False
        else:
            return False

        vn = self.hilessbool.getIn(1)
        if not vn.isWritten():
            return False
        self.hiless = vn.getDef()
        opc = self.hiless.code()
        if opc == OpCode.CPUI_INT_LESS:
            self.hilessequalform = False
            self.signcompare = False
        elif opc == OpCode.CPUI_INT_LESSEQUAL:
            self.hilessequalform = True
            self.signcompare = False
        elif opc == OpCode.CPUI_INT_SLESS:
            self.hilessequalform = False
            self.signcompare = True
        elif opc == OpCode.CPUI_INT_SLESSEQUAL:
            self.hilessequalform = True
            self.signcompare = True
        else:
            return False
        return True

    def checkSignedness(self) -> bool:
        """Verify signedness consistency between hi and mid comparisons.

        C++ ref: LessThreeWay::checkSignedness
        """
        if self.midlessform:
            if self.midsigncompare != self.signcompare:
                return False
        return True

    def normalizeHi(self) -> bool:
        """Normalize the hi comparison so constant is on right and form is strict less.

        C++ ref: LessThreeWay::normalizeHi
        """
        self.vnhil1 = self.hiless.getIn(0)
        self.vnhil2 = self.hiless.getIn(1)
        if self.vnhil1.isConstant():
            self.hiflip = not self.hiflip
            self.hilessequalform = not self.hilessequalform
            self.vnhil1, self.vnhil2 = self.vnhil2, self.vnhil1
        self.hiconstform = False
        if self.vnhil2.isConstant():
            if self.inv.getSize() > 8:
                return False
            self.hiconstform = True
            self.hival = self.vnhil2.getOffset()
            self.hilesstrue, self.hilessfalse = SplitVarnode.getTrueFalse(self.hilessbool, self.hiflip)
            inc = 1
            if self.hilessfalse is not self.hieqbl:
                self.hiflip = not self.hiflip
                self.hilessequalform = not self.hilessequalform
                self.vnhil1, self.vnhil2 = self.vnhil2, self.vnhil1
                inc = -1
            if self.hilessequalform:
                self.hival += inc
                self.hival &= calc_mask(self.inv.getSize())
                self.hilessequalform = False
            lo_vn = self.inv.getLo()
            if lo_vn is not None:
                self.hival >>= lo_vn.getSize() * 8
        else:
            if self.hilessequalform:
                self.hilessequalform = False
                self.hiflip = not self.hiflip
                self.vnhil1, self.vnhil2 = self.vnhil2, self.vnhil1
        return True

    def normalizeMid(self) -> bool:
        """Normalize the mid (equality) comparison.

        C++ ref: LessThreeWay::normalizeMid
        """
        self.vnhie1 = self.hiequal.getIn(0)
        self.vnhie2 = self.hiequal.getIn(1)
        if self.vnhie1.isConstant():
            self.vnhie1, self.vnhie2 = self.vnhie2, self.vnhie1
            if self.midlessform:
                self.equalflip = not self.equalflip
                self.midlessequal = not self.midlessequal
        self.midconstform = False
        if self.vnhie2.isConstant():
            if not self.hiconstform:
                return False
            self.midconstform = True
            self.midval = self.vnhie2.getOffset()
            if self.vnhie2.getSize() == self.inv.getSize():
                lo_vn = self.inv.getLo()
                losize = lo_vn.getSize() if lo_vn else 0
                lopart = self.midval & calc_mask(losize)
                self.midval >>= losize * 8
                if self.midlessform:
                    if self.midlessequal:
                        if lopart != calc_mask(losize):
                            return False
                    else:
                        if lopart != 0:
                            return False
                else:
                    return False
            if self.midval != self.hival:
                if not self.midlessform:
                    return False
                self.midval += 1 if self.midlessequal else -1
                lo_vn = self.inv.getLo()
                losize = lo_vn.getSize() if lo_vn else 0
                self.midval &= calc_mask(losize)
                self.midlessequal = not self.midlessequal
                if self.midval != self.hival:
                    return False
        if self.midlessform:
            if not self.midlessequal:
                self.equalflip = not self.equalflip
        else:
            if self.hiequal.code() == OpCode.CPUI_INT_NOTEQUAL:
                self.equalflip = not self.equalflip
        return True

    def normalizeLo(self) -> bool:
        """Normalize the lo comparison.

        C++ ref: LessThreeWay::normalizeLo
        """
        self.vnlo1 = self.loless.getIn(0)
        self.vnlo2 = self.loless.getIn(1)
        if self.lolessiszerocomp:
            self.loconstform = True
            if self.lolessequalform:
                self.loval = 1
                self.lolessequalform = False
            else:
                self.loflip = not self.loflip
                self.loval = 1
            return True
        if self.vnlo1.isConstant():
            self.loflip = not self.loflip
            self.lolessequalform = not self.lolessequalform
            self.vnlo1, self.vnlo2 = self.vnlo2, self.vnlo1
        self.loconstform = False
        if self.vnlo2.isConstant():
            self.loconstform = True
            self.loval = self.vnlo2.getOffset()
            if self.lolessequalform:
                self.loval += 1
                self.loval &= calc_mask(self.vnlo2.getSize())
                self.lolessequalform = False
        else:
            if self.lolessequalform:
                self.lolessequalform = False
                self.loflip = not self.loflip
                self.vnlo1, self.vnlo2 = self.vnlo2, self.vnlo1
        return True

    def checkBlockForm(self) -> bool:
        """Check that block edges match the expected three-way pattern.

        C++ ref: LessThreeWay::checkBlockForm
        """
        self.hilesstrue, self.hilessfalse = SplitVarnode.getTrueFalse(self.hilessbool, self.hiflip)
        self.lolesstrue, self.lolessfalse = SplitVarnode.getTrueFalse(self.lolessbool, self.loflip)
        self.hieqtrue, self.hieqfalse = SplitVarnode.getTrueFalse(self.hieqbool, self.equalflip)
        if (self.hilesstrue is self.lolesstrue and
                self.hieqfalse is self.lolessfalse and
                self.hilessfalse is self.hieqbl and
                self.hieqtrue is self.lolessbl):
            if SplitVarnode.otherwiseEmpty(self.hieqbool) and SplitVarnode.otherwiseEmpty(self.lolessbool):
                return True
        return False

    def checkOpForm(self) -> bool:
        """Verify that the comparisons use matching hi/lo pieces.

        C++ ref: LessThreeWay::checkOpForm
        """
        self.lo = self.inv.getLo()
        self.hi = self.inv.getHi()

        if self.midconstform:
            if not self.hiconstform:
                return False
            if self.vnhie2.getSize() == self.inv.getSize():
                if self.vnhie1 is not self.vnhil1 and self.vnhie1 is not self.vnhil2:
                    return False
            else:
                if self.vnhie1 is not self.inv.getHi():
                    return False
        else:
            if (self.vnhil1 is not self.vnhie1 and self.vnhil1 is not self.vnhie2):
                return False
            if (self.vnhil2 is not self.vnhie1 and self.vnhil2 is not self.vnhie2):
                return False

        if self.hi is not None and self.hi is self.vnhil1:
            if self.hiconstform:
                return False
            self.hislot = 0
            self.hi2 = self.vnhil2
            if self.vnlo1 is not self.lo:
                self.vnlo1, self.vnlo2 = self.vnlo2, self.vnlo1
                if self.vnlo1 is not self.lo:
                    return False
                self.loflip = not self.loflip
                self.lolessequalform = not self.lolessequalform
            self.lo2 = self.vnlo2
        elif self.hi is not None and self.hi is self.vnhil2:
            if self.hiconstform:
                return False
            self.hislot = 1
            self.hi2 = self.vnhil1
            if self.vnlo2 is not self.lo:
                self.vnlo1, self.vnlo2 = self.vnlo2, self.vnlo1
                if self.vnlo2 is not self.lo:
                    return False
                self.loflip = not self.loflip
                self.lolessequalform = not self.lolessequalform
            self.lo2 = self.vnlo1
        elif self.inv.getWhole() is not None and self.inv.getWhole() is self.vnhil1:
            if not self.hiconstform:
                return False
            if not self.loconstform:
                return False
            if self.vnlo1 is not self.lo:
                return False
            self.hislot = 0
        elif self.inv.getWhole() is not None and self.inv.getWhole() is self.vnhil2:
            if not self.hiconstform:
                return False
            if not self.loconstform:
                return False
            if self.vnlo2 is not self.lo:
                self.loflip = not self.loflip
                self.loval -= 1
                if self.lo is not None:
                    self.loval &= calc_mask(self.lo.getSize())
                if self.vnlo1 is not self.lo:
                    return False
            self.hislot = 1
        else:
            return False
        return True

    def setOpCode(self) -> None:
        """Decide on the opcode of the final double precision compare.

        C++ ref: LessThreeWay::setOpCode
        """
        if self.lolessequalform != self.hiflip:
            self.finalopc = OpCode.CPUI_INT_SLESSEQUAL if self.signcompare else OpCode.CPUI_INT_LESSEQUAL
        else:
            self.finalopc = OpCode.CPUI_INT_SLESS if self.signcompare else OpCode.CPUI_INT_LESS
        if self.hiflip:
            self.hislot = 1 - self.hislot
            self.hiflip = False

    def setBoolOp(self) -> bool:
        """Prepare the final boolean operation.

        C++ ref: LessThreeWay::setBoolOp
        """
        if self.hislot == 0:
            return SplitVarnode.prepareBoolOp(self.inv, self.in2, self.hilessbool)
        else:
            return SplitVarnode.prepareBoolOp(self.in2, self.inv, self.hilessbool)

    def mapFromLow(self, op) -> bool:
        """Map the three-way form starting from the low comparison op.

        C++ ref: LessThreeWay::mapFromLow
        """
        loop = op.getOut().loneDescend()
        if loop is None:
            return False
        if not self.mapBlocksFromLow(loop.getParent()):
            return False
        if not self.mapOpsFromBlocks():
            return False
        if not self.checkSignedness():
            return False
        if not self.normalizeHi():
            return False
        if not self.normalizeMid():
            return False
        if not self.normalizeLo():
            return False
        if not self.checkOpForm():
            return False
        if not self.checkBlockForm():
            return False
        return True

    def testReplace(self) -> bool:
        """Test if the replacement can be made.

        C++ ref: LessThreeWay::testReplace
        """
        self.setOpCode()
        if self.hiconstform:
            lo_vn = self.inv.getLo()
            losize = lo_vn.getSize() if lo_vn else 0
            self.in2.initPartial(self.inv.getSize(), (self.hival << (8 * losize)) | self.loval)
            if not self.setBoolOp():
                return False
        else:
            self.in2.initPartial(self.inv.getSize(), self.lo2, self.hi2)
            if not self.setBoolOp():
                return False
        return True

    def applyRule(self, i, loop, workishi: bool, data) -> bool:
        """Apply the less-three-way rule.

        C++ ref: LessThreeWay::applyRule
        """
        if workishi:
            return False
        if i.getLo() is None:
            return False
        self.inv = i
        if not self.mapFromLow(loop):
            return False
        res = self.testReplace()
        if res:
            if self.in2.exceedsConstPrecision():
                return False
            if self.hislot == 0:
                SplitVarnode.createBoolOp(data, self.hilessbool, self.inv, self.in2, self.finalopc)
            else:
                SplitVarnode.createBoolOp(data, self.hilessbool, self.in2, self.inv, self.finalopc)
            data.opSetInput(self.hieqbool, data.newConstant(1, 1 if self.equalflip else 0), 1)
        return res


class PhiForm:
    """Verify double-precision phi (MULTIEQUAL) operation.
    Corresponds to PhiForm in double.cc."""
    def __init__(self) -> None:
        self.inv = SplitVarnode()
        self.outvn = SplitVarnode()
        self.inlist = []

    def applyRule(self, i, hphi, workishi: bool, data) -> bool:
        """Apply the phi form rule.
        Corresponds to PhiForm::applyRule in double.cc."""
        if not workishi:
            return False
        if not i.hasBothPieces():
            return False
        if hphi.code() != OpCode.CPUI_MULTIEQUAL:
            return False
        self.inv = i
        hibase = self.inv.getHi()
        lobase = self.inv.getLo()
        hiphi = hphi
        inslot = hiphi.getSlot(hibase)
        outvn = hiphi.getOut()
        if outvn is None or outvn.hasNoDescend():
            return False
        blbase = hiphi.getParent()
        lophi = None
        for desc in list(lobase.getDescendants()):
            if desc.code() != OpCode.CPUI_MULTIEQUAL:
                continue
            if desc.getParent() is not blbase:
                continue
            if desc.getIn(inslot) is not lobase:
                continue
            lophi = desc
            break
        if lophi is None:
            return False
        numin = hiphi.numInput()
        self.inlist = []
        for j in range(numin):
            sv = SplitVarnode()
            vhi = hiphi.getIn(j)
            vlo = lophi.getIn(j)
            sv.initPartial(self.inv.getSize(), vlo, vhi)
            self.inlist.append(sv)
        self.outvn = SplitVarnode()
        self.outvn.initPartial(self.inv.getSize(), lophi.getOut(), hiphi.getOut())
        existop = SplitVarnode.preparePhiOp(self.outvn, self.inlist)
        if existop is None:
            return False
        SplitVarnode.createPhiOp(data, self.outvn, self.inlist, existop)
        return True


class IndirectForm:
    """Verify double-precision INDIRECT operation.
    Corresponds to IndirectForm in double.cc."""
    def __init__(self) -> None:
        self.inv = SplitVarnode()
        self.outvn = SplitVarnode()

    def applyRule(self, i, ind, workishi: bool, data) -> bool:
        """Apply the indirect form rule.
        Corresponds to IndirectForm::applyRule in double.cc."""
        if not workishi:
            return False
        if not i.hasBothPieces():
            return False
        self.inv = i
        hi = self.inv.getHi()
        lo = self.inv.getLo()
        if ind.code() != OpCode.CPUI_INDIRECT:
            return False
        if ind.getOut() is not hi:
            return False
        # Find matching lo INDIRECT
        loind = None
        if lo.isWritten():
            lodef = lo.getDef()
            if lodef.code() == OpCode.CPUI_INDIRECT:
                loind = lodef
        if loind is None:
            return False
        # Both must be affected by the same op
        # Get affector from the INDIRECT
        affector_hi = ind.getIn(1) if ind.numInput() > 1 else None
        affector_lo = loind.getIn(1) if loind.numInput() > 1 else None
        if affector_hi is None or affector_lo is None:
            return False
        # Input pieces
        in_hi = ind.getIn(0)
        in_lo = loind.getIn(0)
        inv2 = SplitVarnode()
        inv2.initPartial(self.inv.getSize(), in_lo, in_hi)
        self.outvn = SplitVarnode()
        self.outvn.initPartial(self.inv.getSize(), lo, hi)
        # Use hi affector for the indirect affect point
        if not SplitVarnode.prepareIndirectOp(inv2, ind):
            return False
        SplitVarnode.replaceIndirectOp(data, self.outvn, inv2, ind)
        return True


class CopyForceForm:
    """Collapse two COPYs into contiguous address forced Varnodes.
    Corresponds to CopyForceForm in double.cc."""
    def __init__(self) -> None:
        self.inv = SplitVarnode()

    def applyRule(self, i, cpy, workishi: bool, data) -> bool:
        """Apply the copy-force form rule.
        Corresponds to CopyForceForm::applyRule in double.cc."""
        if not i.hasBothPieces():
            return False
        self.inv = i
        # The copy output must be address forced
        outvn = cpy.getOut()
        if outvn is None:
            return False
        if not hasattr(outvn, 'isAddrForce') or not outvn.isAddrForce():
            return False
        # Find the matching copy for the other piece
        if workishi:
            lo = self.inv.getLo()
            hi_piece = cpy
            # Find lo copy
            lo_copy = None
            for desc in lo.getDescendants():
                if desc.code() == OpCode.CPUI_COPY:
                    lo_out = desc.getOut()
                    if lo_out is not None and hasattr(lo_out, 'isAddrForce') and lo_out.isAddrForce():
                        lo_copy = desc
                        break
            if lo_copy is None:
                return False
            copyhi = hi_piece
            copylo = lo_copy
        else:
            hi = self.inv.getHi()
            lo_piece = cpy
            # Find hi copy
            hi_copy = None
            for desc in hi.getDescendants():
                if desc.code() == OpCode.CPUI_COPY:
                    hi_out = desc.getOut()
                    if hi_out is not None and hasattr(hi_out, 'isAddrForce') and hi_out.isAddrForce():
                        hi_copy = desc
                        break
            if hi_copy is None:
                return False
            copyhi = hi_copy
            copylo = lo_piece
        # Check contiguity
        ok, addr = SplitVarnode.isAddrTiedContiguous(copylo.getOut(), copyhi.getOut())
        if not ok:
            return False
        # Need the whole input
        if not self.inv.isWholeFeasible(copyhi):
            return False
        self.inv.findCreateWhole(data)
        SplitVarnode.replaceCopyForce(data, addr, self.inv, copylo, copyhi)
        return True


# =========================================================================
# Rule subclasses for double precision
# =========================================================================

class RuleDoubleIn:
    """Simplify a double precision operation, pushing down one level, starting from marked input."""
    def __init__(self, group: str = ''):
        self._group = group
        self._name = 'doublein'

    def getName(self) -> str:
        return self._name

    def getGroup(self) -> str:
        return self._group

    def clone(self, grouplist=None):
        return RuleDoubleIn(self._group)

    def getOpList(self) -> list:
        return [int(OpCode.CPUI_SUBPIECE)]

    def applyOp(self, op, data) -> int:
        """Try to simplify a double-precision operation starting from a SUBPIECE.
        Corresponds to RuleDoubleIn::applyOp in double.cc."""
        outvn = op.getOut()
        if outvn is None:
            return 0
        if not hasattr(outvn, 'isPrecisHi') or not hasattr(outvn, 'isPrecisLo'):
            return 0
        if not outvn.isPrecisHi() and not outvn.isPrecisLo():
            return 0
        inv = SplitVarnode()
        if outvn.isPrecisHi():
            if not inv.inHandHi(outvn):
                return 0
        else:
            if not inv.inHandLo(outvn):
                if not inv.inHandLoNoHi(outvn):
                    return 0
        return SplitVarnode.applyRuleIn(inv, data)

    def reset(self, data) -> None:
        """C++ ref: ``RuleDoubleIn::reset``"""
        if hasattr(data, 'setDoublePrecisRecovery'):
            data.setDoublePrecisRecovery(True)


class RuleDoubleOut:
    """Simplify a double precision operation, pulling back one level, starting from PIECE."""
    def __init__(self, group: str = ''):
        self._group = group
        self._name = 'doubleout'

    def getName(self) -> str:
        return self._name

    def getGroup(self) -> str:
        return self._group

    def clone(self, grouplist=None):
        return RuleDoubleOut(self._group)

    def getOpList(self) -> list:
        return [int(OpCode.CPUI_PIECE)]

    def applyOp(self, op, data) -> int:
        """Try to simplify a double-precision operation starting from a PIECE.
        Corresponds to RuleDoubleOut::applyOp in double.cc."""
        outvn = op.getOut()
        if outvn is None:
            return 0
        splitvec = []
        SplitVarnode.wholeList(outvn, splitvec)
        if len(splitvec) == 0:
            return 0
        for sv in splitvec:
            ret = SplitVarnode.applyRuleIn(sv, data)
            if ret != 0:
                return ret
        return 0


class RuleDoubleLoad:
    """Collapse contiguous loads into a single wider load."""
    def __init__(self, group: str = ''):
        self._group = group
        self._name = 'doubleload'

    def getName(self) -> str:
        return self._name

    def getGroup(self) -> str:
        return self._group

    def clone(self, grouplist=None):
        return RuleDoubleLoad(self._group)

    def getOpList(self) -> list:
        return [int(OpCode.CPUI_PIECE)]

    def applyOp(self, op, data) -> int:
        piece0 = op.getIn(0)
        piece1 = op.getIn(1)
        if not piece0.isWritten():
            return 0
        if not piece1.isWritten():
            return 0
        load1 = piece1.getDef()
        if load1.code() != OpCode.CPUI_LOAD:
            return 0
        load0 = piece0.getDef()
        opc = load0.code()
        offset = 0
        if opc == OpCode.CPUI_SUBPIECE:
            if load0.getIn(1).getOffset() != 0:
                return 0
            vn0 = load0.getIn(0)
            if not vn0.isWritten():
                return 0
            offset = vn0.getSize() - piece0.getSize()
            load0 = vn0.getDef()
            opc = load0.code()
        if opc != OpCode.CPUI_LOAD:
            return 0
        ok, loadlo, loadhi, spc = SplitVarnode.testContiguousPointers(load0, load1)
        if not ok:
            return 0
        size = piece0.getSize() + piece1.getSize()
        latest = RuleDoubleLoad.noWriteConflict(loadlo, loadhi, spc)
        if latest is None:
            return 0
        newload = data.newOp(2, latest.getAddr())
        vnout = data.newUniqueOut(size, newload)
        spcvn = data.newVarnodeSpace(spc) if hasattr(data, 'newVarnodeSpace') else data.newConstant(loadlo.getIn(0).getSize(), loadlo.getIn(0).getOffset())
        data.opSetOpcode(newload, OpCode.CPUI_LOAD)
        data.opSetInput(newload, spcvn, 0)
        addrvn = loadlo.getIn(1)
        if hasattr(spc, 'isBigEndian') and spc.isBigEndian() and offset != 0:
            newadd = data.newOp(2, latest.getAddr())
            addout = data.newUniqueOut(addrvn.getSize(), newadd)
            data.opSetOpcode(newadd, OpCode.CPUI_INT_ADD)
            data.opSetInput(newadd, addrvn, 0)
            data.opSetInput(newadd, data.newConstant(addrvn.getSize(), offset), 1)
            data.opInsertAfter(newadd, latest)
            addrvn = addout
            latest = newadd
        data.opSetInput(newload, addrvn, 1)
        data.opInsertAfter(newload, latest)
        data.opRemoveInput(op, 1)
        data.opSetOpcode(op, OpCode.CPUI_COPY)
        data.opSetInput(op, vnout, 0)
        return 1

    @staticmethod
    def noWriteConflict(op1, op2, spc, indirects=None):
        """Check that there is no write conflict between two LOADs or STOREs in the same block."""
        bb = op1.getParent()
        if bb is not op2.getParent():
            return None
        if hasattr(op2, 'getSeqNum') and hasattr(op1, 'getSeqNum'):
            if op2.getSeqNum().getOrder() < op1.getSeqNum().getOrder():
                op1, op2 = op2, op1
        else:
            return op2
        startop = op1
        if op1.code() == OpCode.CPUI_STORE:
            tmpOp = startop.previousOp() if hasattr(startop, 'previousOp') else None
            while tmpOp is not None and tmpOp.code() == OpCode.CPUI_INDIRECT:
                startop = tmpOp
                tmpOp = tmpOp.previousOp() if hasattr(tmpOp, 'previousOp') else None
        if hasattr(startop, 'getBasicIter') and hasattr(op2, 'getBasicIter'):
            it = startop.getBasicIter()
            endit = op2.getBasicIter()
            curop = next(it, None)
            while curop is not None and curop is not op2:
                if curop is op1:
                    curop = next(it, None)
                    continue
                opc = curop.code()
                if opc == OpCode.CPUI_STORE:
                    cspc = curop.getIn(0).getSpaceFromConst() if hasattr(curop.getIn(0), 'getSpaceFromConst') else None
                    if cspc is spc:
                        return None
                elif opc == OpCode.CPUI_INDIRECT:
                    from ghidra.ir.op import PcodeOp
                    affector = PcodeOp.getOpFromConst(curop.getIn(1).getAddr()) if hasattr(PcodeOp, 'getOpFromConst') else None
                    if affector is op1 or affector is op2:
                        if indirects is not None:
                            indirects.append(curop)
                    else:
                        outvn = curop.getOut()
                        if outvn is not None and outvn.getSpace() is spc:
                            return None
                elif opc in (OpCode.CPUI_CALL, OpCode.CPUI_CALLIND, OpCode.CPUI_CALLOTHER,
                             OpCode.CPUI_RETURN, OpCode.CPUI_BRANCH, OpCode.CPUI_CBRANCH,
                             OpCode.CPUI_BRANCHIND):
                    return None
                else:
                    outvn = curop.getOut()
                    if outvn is not None and outvn.getSpace() is spc:
                        return None
                curop = next(it, None)
        return op2


class RuleDoubleStore:
    """Collapse contiguous stores into a single wider store."""
    def __init__(self, group: str = ''):
        self._group = group
        self._name = 'doublestore'

    def getName(self) -> str:
        return self._name

    def getGroup(self) -> str:
        return self._group

    def clone(self, grouplist=None):
        return RuleDoubleStore(self._group)

    def getOpList(self) -> list:
        return [int(OpCode.CPUI_STORE)]

    def applyOp(self, op, data) -> int:
        vnlo = op.getIn(2)
        if not hasattr(vnlo, 'isPrecisLo') or not vnlo.isPrecisLo():
            return 0
        if not vnlo.isWritten():
            return 0
        subpieceOpLo = vnlo.getDef()
        if subpieceOpLo.code() != OpCode.CPUI_SUBPIECE:
            return 0
        if subpieceOpLo.getIn(1).getOffset() != 0:
            return 0
        whole = subpieceOpLo.getIn(0)
        if whole.isFree():
            return 0
        for subpieceOpHi in list(whole.beginDescend()):
            if subpieceOpHi.code() != OpCode.CPUI_SUBPIECE:
                continue
            if subpieceOpHi is subpieceOpLo:
                continue
            hi_offset = int(subpieceOpHi.getIn(1).getOffset())
            if hi_offset != vnlo.getSize():
                continue
            vnhi = subpieceOpHi.getOut()
            if not hasattr(vnhi, 'isPrecisHi') or not vnhi.isPrecisHi():
                continue
            if vnhi.getSize() != whole.getSize() - hi_offset:
                continue
            for storeOp2 in list(vnhi.beginDescend()):
                if storeOp2.code() != OpCode.CPUI_STORE:
                    continue
                if storeOp2.getIn(2) is not vnhi:
                    continue
                ok, storelo, storehi, spc = SplitVarnode.testContiguousPointers(storeOp2, op)
                if not ok:
                    continue
                indirects = []
                latest = RuleDoubleLoad.noWriteConflict(storelo, storehi, spc, indirects)
                if latest is None:
                    continue
                if not RuleDoubleStore.testIndirectUse(storelo, storehi, indirects):
                    continue
                newstore = data.newOp(3, latest.getAddr())
                spcvn = data.newVarnodeSpace(spc) if hasattr(data, 'newVarnodeSpace') else data.newConstant(storelo.getIn(0).getSize(), storelo.getIn(0).getOffset())
                data.opSetOpcode(newstore, OpCode.CPUI_STORE)
                data.opSetInput(newstore, spcvn, 0)
                addrvn = storelo.getIn(1)
                if addrvn.isConstant():
                    addrvn = data.newConstant(addrvn.getSize(), addrvn.getOffset())
                data.opSetInput(newstore, addrvn, 1)
                data.opSetInput(newstore, whole, 2)
                data.opInsertAfter(newstore, latest)
                data.opDestroy(op)
                data.opDestroy(storeOp2)
                RuleDoubleStore.reassignIndirects(data, newstore, indirects)
                return 1
        return 0

    @staticmethod
    def testIndirectUse(op1, op2, indirects) -> bool:
        """Test if output Varnodes from INDIRECTs are used within the range of op1..op2."""
        if hasattr(op2, 'getSeqNum') and hasattr(op1, 'getSeqNum'):
            if op2.getSeqNum().getOrder() < op1.getSeqNum().getOrder():
                op1, op2 = op2, op1
        for ind in indirects:
            outvn = ind.getOut()
            usecount = 0
            usebyop2 = 0
            for useop in outvn.beginDescend():
                usecount += 1
                if useop.getParent() is not op1.getParent():
                    continue
                if hasattr(useop, 'getSeqNum'):
                    order = useop.getSeqNum().getOrder()
                    if order < op1.getSeqNum().getOrder():
                        continue
                    if order > op2.getSeqNum().getOrder():
                        continue
                if useop.code() == OpCode.CPUI_INDIRECT:
                    from ghidra.ir.op import PcodeOp
                    affector = PcodeOp.getOpFromConst(useop.getIn(1).getAddr()) if hasattr(PcodeOp, 'getOpFromConst') else None
                    if affector is op2:
                        usebyop2 += 1
                        continue
                return False
            if usebyop2 > 0 and usecount != usebyop2:
                return False
            if usebyop2 > 1:
                return False
        return True

    @staticmethod
    def reassignIndirects(data, newStore, indirects) -> None:
        """Reassign INDIRECT ops to point at a new combined STORE.

        Search for INDIRECT pairs.  The earlier is deleted.  The later gains the
        earlier's input.  Then move all surviving INDIRECTs before the new STORE.

        C++ ref: ``RuleDoubleStore::reassignIndirects``
        """
        # Phase 1: mark and merge pairs
        for op in indirects:
            op.setMark()
            vn = op.getIn(0)
            if vn is None or not vn.isWritten():
                continue
            earlyop = vn.getDef()
            if earlyop is not None and earlyop.isMark():
                data.opSetInput(op, earlyop.getIn(0), 0)
                data.opDestroy(earlyop)
        # Phase 2: clear marks and move before newStore
        for op in indirects:
            op.clearMark()
            if op.isDead():
                continue
            data.opUninsert(op)
            data.opInsertBefore(op, newStore)
            data.opSetInput(op, data.newVarnodeIop(newStore), 1)
