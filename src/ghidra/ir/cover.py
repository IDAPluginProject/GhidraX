"""
Corresponds to: cover.hh / cover.cc

Classes describing the topological scope of variables within a function.
"""

from __future__ import annotations

from abc import ABC, abstractmethod
from typing import TYPE_CHECKING, Optional, Dict, List

from ghidra.core.opcodes import OpCode

if TYPE_CHECKING:
    from ghidra.ir.op import PcodeOp
    from ghidra.ir.varnode import Varnode
    from ghidra.block.block import FlowBlock


class PcodeOpSet(ABC):
    """A set of PcodeOps that can be tested for Cover intersections.

    Lazily constructed via populate() at first intersection test time.
    """

    def __init__(self) -> None:
        self._opList: List[PcodeOp] = []
        self._blockStart: List[int] = []
        self._is_pop: bool = False

    def isPopulated(self) -> bool:
        return self._is_pop

    def addOp(self, op: PcodeOp) -> None:
        self._opList.append(op)

    def finalize(self) -> None:
        """Sort ops in the set into blocks."""
        self._opList.sort(key=lambda op: (op.getParent().getIndex() if op.getParent() else -1, op.getSeqNum().getOrder()))
        self._blockStart.clear()
        last_block = -1
        for i, op in enumerate(self._opList):
            parent = op.getParent()
            blk = parent.getIndex() if parent else -1
            while len(self._blockStart) <= blk:
                self._blockStart.append(-1)
            if blk != last_block:
                self._blockStart[blk] = i
                last_block = blk
        self._is_pop = True

    @abstractmethod
    def populate(self) -> None:
        """Call-back to lazily add PcodeOps to this set."""
        ...

    @abstractmethod
    def affectsTest(self, op: PcodeOp, vn: Varnode) -> bool:
        """Secondary test: does the given PcodeOp affect the Varnode?"""
        ...

    @staticmethod
    def compareByBlock(a: PcodeOp, b: PcodeOp) -> bool:
        """Compare two PcodeOps first by block index, then by SeqNum order.

        C++ ref: PcodeOpSet::compareByBlock
        """
        if a.getParent() != b.getParent():
            return a.getParent().getIndex() < b.getParent().getIndex()
        return a.getSeqNum().getOrder() < b.getSeqNum().getOrder()

    def clear(self) -> None:
        self._is_pop = False
        self._opList.clear()
        self._blockStart.clear()


class CoverBlock:
    """The topological scope of a variable within a basic block.

    A contiguous range of p-code operations described with a start and stop.
    Special encodings:
      - start=None, stop=None  =>  empty/uncovered
      - start=None, stop=sentinel  =>  from beginning of block
      - start=sentinel, stop=sentinel  =>  whole block covered
    """

    # Sentinel value representing "whole block" endpoint  (C++ (PcodeOp*)1)
    _WHOLE_BLOCK_SENTINEL = object()
    # Sentinel: "begin-only, not yet extended"  (C++ (PcodeOp*)2)
    _BEGIN_ONLY_SENTINEL = object()

    __slots__ = ('start', 'stop', 'ustart', 'ustop')

    def __init__(self) -> None:
        self.start: object = None  # PcodeOp or None or sentinel
        self.stop: object = None   # PcodeOp or None or sentinel
        self.ustart: int = 0       # cached getUIndex(start)
        self.ustop: int = 0        # cached getUIndex(stop)

    @staticmethod
    def getUIndex(op) -> int:
        """Get the comparison index for a PcodeOp.

        C++ ref: CoverBlock::getUIndex
        Sentinel mapping:
          None                  -> 0           (C++ (PcodeOp*)0)
          _WHOLE_BLOCK_SENTINEL -> 0xFFFFFFFF   (C++ (PcodeOp*)1)
          _BEGIN_ONLY_SENTINEL  -> 0xFFFFFFFE   (C++ (PcodeOp*)2)
        """
        if op is None:
            return 0
        if op is CoverBlock._WHOLE_BLOCK_SENTINEL:
            return 0xFFFFFFFF
        if op is CoverBlock._BEGIN_ONLY_SENTINEL:
            return 0xFFFFFFFE
        return op.getSeqNum().getOrder()

    def getStart(self):
        return self.start

    def getStop(self):
        return self.stop

    def clear(self) -> None:
        self.start = None; self.stop = None
        self.ustart = 0; self.ustop = 0

    def setAll(self) -> None:
        """Mark whole block as covered."""
        self.start = None; self.stop = CoverBlock._WHOLE_BLOCK_SENTINEL
        self.ustart = 0; self.ustop = 0xFFFFFFFF

    def setBegin(self, begin) -> None:
        """Reset start of range.

        C++ ref: CoverBlock::setBegin
        If stop was previously None, set it to _BEGIN_ONLY_SENTINEL
        (C++ (PcodeOp*)2) meaning 'defined but not yet extended'.
        """
        self.start = begin
        self.ustart = CoverBlock.getUIndex(begin)
        if self.stop is None:
            self.stop = CoverBlock._BEGIN_ONLY_SENTINEL
            self.ustop = 0xFFFFFFFE

    def setEnd(self, end) -> None:
        """Reset end of range."""
        self.stop = end
        self.ustop = CoverBlock.getUIndex(end)

    def empty(self) -> bool:
        """Return True if this is empty/uncovered."""
        return self.start is None and self.stop is None

    def contain(self, point) -> bool:
        """Check containment of given point."""
        if self.empty():
            return False
        if self.stop is CoverBlock._WHOLE_BLOCK_SENTINEL and self.start is None:
            return True  # Whole block
        uind = CoverBlock.getUIndex(point)
        start_ind = CoverBlock.getUIndex(self.start) if self.start is not None else 0
        stop_ind = CoverBlock.getUIndex(self.stop) if self.stop is not CoverBlock._WHOLE_BLOCK_SENTINEL else 0xFFFFFFFF
        if self.stop is None:
            stop_ind = 0
        return start_ind <= uind <= stop_ind

    def boundary(self, point) -> int:
        """Characterize given point as boundary.

        Returns:
          0 = not on boundary
          1 = on start boundary
          2 = on stop boundary
          3 = on both (single-point cover)
        """
        if self.empty():
            return -1
        result = 0
        if self.start is not None and self.start is not CoverBlock._WHOLE_BLOCK_SENTINEL:
            if CoverBlock.getUIndex(point) == CoverBlock.getUIndex(self.start):
                result |= 1
        if self.stop is not None and self.stop is not CoverBlock._WHOLE_BLOCK_SENTINEL:
            if CoverBlock.getUIndex(point) == CoverBlock.getUIndex(self.stop):
                result |= 2
        return result

    def intersect(self, op2: CoverBlock) -> int:
        """Compute intersection with another CoverBlock.

        Returns:
          0 = no intersection
          1 = boundary intersection only
          2 = interval intersection
        """
        if self.start is None and self.stop is None: return 0
        if op2.start is None and op2.stop is None: return 0
        # Use cached integer values — no getUIndex() calls needed
        ustart = self.ustart
        ustop = self.ustop
        u2start = op2.ustart
        u2stop = op2.ustop
        if ustart <= ustop:
            if u2start <= u2stop:
                if ustop <= u2start or u2stop <= ustart:
                    if ustart == u2stop or ustop == u2start:
                        return 1
                    return 0
            else:
                if ustart >= u2stop and ustop <= u2start:
                    if ustart == u2stop or ustop == u2start:
                        return 1
                    return 0
        else:
            if u2start <= u2stop:
                if u2start >= ustop and u2stop <= ustart:
                    if u2start == ustop or u2stop == ustart:
                        return 1
                    return 0
        return 2

    def merge(self, op2: CoverBlock) -> None:
        """Merge another CoverBlock into this."""
        if op2.start is None and op2.stop is None:
            return
        if self.start is None and self.stop is None:
            self.start = op2.start; self.stop = op2.stop
            self.ustart = op2.ustart; self.ustop = op2.ustop
            return
        # Take the union — use cached values
        s1 = self.ustart if self.start is not None else 0
        e1 = self.ustop if (self.stop is not None and self.stop is not CoverBlock._WHOLE_BLOCK_SENTINEL) else 0xFFFFFFFF
        s2 = op2.ustart if op2.start is not None else 0
        e2 = op2.ustop if (op2.stop is not None and op2.stop is not CoverBlock._WHOLE_BLOCK_SENTINEL) else 0xFFFFFFFF
        if self.stop is None:
            e1 = s1
        if op2.stop is None:
            e2 = s2
        if s2 < s1:
            self.start = op2.start; self.ustart = op2.ustart
        if e2 > e1:
            self.stop = op2.stop; self.ustop = op2.ustop

    def print(self, s) -> None:
        """Print a description of the covered range.

        C++ ref: CoverBlock::print
        """
        if self.empty():
            s.write("empty")
            return
        ustart = CoverBlock.getUIndex(self.start)
        ustop = CoverBlock.getUIndex(self.stop)
        if ustart == 0:
            s.write("begin")
        elif ustart >= 0xFFFFFFFE:
            s.write("end")
        else:
            s.write(str(self.start.getSeqNum()))
        s.write('-')
        if ustop == 0:
            s.write("begin")
        elif ustop >= 0xFFFFFFFE:
            s.write("end")
        else:
            s.write(str(self.stop.getSeqNum()))

    def __repr__(self) -> str:
        if self.empty():
            return "CoverBlock(empty)"
        return f"CoverBlock(start={self.start}, stop={self.stop})"


class Cover:
    """A description of the topological scope of a single variable object.

    Internally implemented as a map from basic block index to non-empty CoverBlock.
    """

    _emptyBlock: CoverBlock = CoverBlock()

    __slots__ = ('_cover',)

    def __init__(self) -> None:
        self._cover: Dict[int, CoverBlock] = {}

    def clear(self) -> None:
        self._cover.clear()

    def compareTo(self, op2: Cover) -> int:
        """Give ordering of this and another Cover."""
        keys1 = sorted(self._cover.keys())
        keys2 = sorted(op2._cover.keys())
        for k1, k2 in zip(keys1, keys2):
            if k1 != k2:
                return -1 if k1 < k2 else 1
        if len(keys1) != len(keys2):
            return -1 if len(keys1) < len(keys2) else 1
        return 0

    def getCoverBlock(self, i: int) -> CoverBlock:
        """Get the CoverBlock corresponding to the i-th block."""
        return self._cover.get(i, Cover._emptyBlock)

    def intersect(self, op2: Cover) -> int:
        """Characterize the intersection between this and another Cover.

        Returns:
          0 = no intersection
          1 = boundary/point intersection only
          2 = interval intersection (immediate return)
        """
        result = 0
        for blk in sorted(self._cover.keys()):
            cb1 = self._cover[blk]
            cb2 = op2._cover.get(blk)
            if cb2 is None:
                continue
            val = cb1.intersect(cb2)
            if val == 2:
                return 2
            if val == 1:
                result = 1
        return result

    def intersectByBlock(self, blk: int, op2: Cover) -> int:
        """Characterize the intersection on a specific block."""
        cb1 = self._cover.get(blk)
        cb2 = op2._cover.get(blk)
        if cb1 is None or cb2 is None:
            return 0
        return cb1.intersect(cb2)

    def contain(self, op, max_: int) -> bool:
        """Check if a PcodeOp is contained in the cover."""
        parent = op.getParent()
        if parent is None:
            return False
        blk = parent.getIndex()
        cb = self._cover.get(blk)
        if cb is None:
            return False
        return cb.contain(op)

    def merge(self, op2: Cover) -> None:
        """Merge this with another Cover block by block."""
        for blk, cb2 in op2._cover.items():
            if blk in self._cover:
                self._cover[blk].merge(cb2)
            else:
                new_cb = CoverBlock()
                new_cb.merge(cb2)
                self._cover[blk] = new_cb

    def rebuild(self, vn) -> None:
        """Reset this based on def-use of a single Varnode."""
        self.clear()
        self.addDefPoint(vn)
        for op in vn.getDescendants():
            self.addRefPoint(op, vn)

    def addDefPoint(self, vn) -> None:
        """Reset to the single point where the given Varnode is defined."""
        defop = vn.getDef()
        if defop is None:
            return
        parent = defop.getParent()
        if parent is None:
            return
        blk = parent.getIndex()
        if blk not in self._cover:
            self._cover[blk] = CoverBlock()
        self._cover[blk].setBegin(defop)

    def addRefRecurse(self, bl) -> None:
        """Add cover recursively backward from block bottom.

        C++ ref: Cover::addRefRecurse
        """
        blk_idx = bl.getIndex()
        if blk_idx not in self._cover:
            self._cover[blk_idx] = CoverBlock()
        block = self._cover[blk_idx]

        if block.empty():
            block.setAll()
            for j in range(bl.sizeIn()):
                self.addRefRecurse(bl.getIn(j))
        else:
            op = block.getStop()
            ustart = CoverBlock.getUIndex(block.getStart())
            ustop = CoverBlock.getUIndex(op)
            if ustop != 0xFFFFFFFF and ustop >= ustart:
                block.setEnd(CoverBlock._WHOLE_BLOCK_SENTINEL)

            if ustop == 0 and block.getStart() is None:
                if (op is not None and
                        op is not CoverBlock._BEGIN_ONLY_SENTINEL and
                        op is not CoverBlock._WHOLE_BLOCK_SENTINEL and
                        op.code() == OpCode.CPUI_MULTIEQUAL):
                    for j in range(bl.sizeIn()):
                        self.addRefRecurse(bl.getIn(j))

    def addRefPoint(self, ref, vn) -> None:
        """Add a variable read and recursively fill backward.

        C++ ref: Cover::addRefPoint
        """
        bl = ref.getParent()
        if bl is None:
            return
        blk_idx = bl.getIndex()
        if blk_idx not in self._cover:
            self._cover[blk_idx] = CoverBlock()
        block = self._cover[blk_idx]

        if block.empty():
            block.setEnd(ref)
        else:
            if block.contain(ref):
                if ref.code() != OpCode.CPUI_MULTIEQUAL:
                    return
                # Even if MULTIEQUAL ref is contained, we may be adding
                # new cover because we are looking at a different branch
            else:
                op = block.getStop()
                startop = block.getStart()
                block.setEnd(ref)
                ustop = CoverBlock.getUIndex(block.getStop())
                if ustop >= CoverBlock.getUIndex(startop):
                    if (op is not None and
                            op is not CoverBlock._BEGIN_ONLY_SENTINEL and
                            op is not CoverBlock._WHOLE_BLOCK_SENTINEL and
                            hasattr(op, 'code') and
                            op.code() == OpCode.CPUI_MULTIEQUAL and
                            startop is None):
                        for j in range(bl.sizeIn()):
                            self.addRefRecurse(bl.getIn(j))
                    return

        if ref.code() == OpCode.CPUI_MULTIEQUAL:
            for j in range(ref.numInput()):
                if ref.getIn(j) == vn:
                    self.addRefRecurse(bl.getIn(j))
        else:
            for j in range(bl.sizeIn()):
                self.addRefRecurse(bl.getIn(j))

    def containVarnodeDef(self, vn) -> int:
        """Check the definition of a Varnode for containment.

        Returns:
          0 = cover does not contain varnode definition
          1 = contained in interior
          2 = defining points intersect
          3 = Cover's tail is the varnode definition
        """
        op = vn.getDef()
        if op is None:
            blk = 0
        else:
            parent = op.getParent()
            if parent is None:
                return 0
            blk = parent.getIndex()
        cb = self._cover.get(blk)
        if cb is None:
            return 0
        if op is None:
            # Input varnode — check if block 0 is covered from beginning
            if not cb.empty():
                return 1
            return 0
        if cb.contain(op):
            boundtype = cb.boundary(op)
            if boundtype == 0:
                return 1
            if boundtype == 2:
                return 2
            return 3
        return 0

    def intersectList(self, op2: Cover, level: int) -> List[int]:
        """Get list of block indices where intersection exceeds a level.

        Args:
            op2: the other Cover
            level: characterization threshold which must be exceeded
        Returns:
            list of intersecting block indices
        """
        listout: List[int] = []
        c2 = op2._cover
        for blk, cb1 in self._cover.items():
            cb2 = c2.get(blk)
            if cb2 is not None and cb1.intersect(cb2) >= level:
                listout.append(blk)
        return listout

    def print(self, s) -> None:
        """Dump a description of this cover to stream."""
        for blk in sorted(self._cover.keys()):
            cb = self._cover[blk]
            s.write(f"{blk}: ")
            if cb.empty():
                s.write("empty")
            else:
                start_idx = CoverBlock.getUIndex(cb.start)
                stop_idx = CoverBlock.getUIndex(cb.stop)
                if start_idx == 0:
                    s.write("begin")
                elif start_idx == 0xFFFFFFFF:
                    s.write("end")
                else:
                    s.write(str(cb.start.getSeqNum()))
                s.write('-')
                if stop_idx == 0:
                    s.write("begin")
                elif stop_idx == 0xFFFFFFFF:
                    s.write("end")
                else:
                    s.write(str(cb.stop.getSeqNum()))
            s.write('\n')

    def begin(self):
        """Get beginning iterator of CoverBlocks (sorted by block index)."""
        return iter(sorted(self._cover.items()))

    def end(self):
        """Get end sentinel (for compatibility; use begin() as iterator)."""
        return None

    def getNumBlocks(self) -> int:
        return len(self._cover)

    def containsBlock(self, blk: int) -> bool:
        return blk in self._cover

    def __iter__(self):
        return iter(self._cover.items())

    def __repr__(self) -> str:
        blocks = [f"blk{k}" for k in sorted(self._cover.keys())]
        return f"Cover({', '.join(blocks)})"
