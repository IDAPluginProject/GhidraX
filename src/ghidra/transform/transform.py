"""
Corresponds to: transform.hh / transform.cc

Classes for building large-scale transforms of function data-flow.
Used by lane-splitting rules to replace wide Varnodes/PcodeOps with
narrower lane-level equivalents.

Five classes:
- **LanedRegister** — describes a register that may be split into lanes
  (bitmask-based, matching C++ exactly).
- **LaneDescription** — describes disjoint byte-lanes within a region.
- **TransformVar** — placeholder for a Varnode that will exist after transform.
- **TransformOp** — placeholder for a PcodeOp that will exist after transform.
- **TransformManager** — orchestrates building and applying the transform.
"""
from __future__ import annotations

from typing import TYPE_CHECKING, Dict, List, Optional

from ghidra.core.address import Address, calc_mask
from ghidra.core.error import LowlevelError
from ghidra.core.opcodes import OpCode
from ghidra.core.space import IPTR_INTERNAL

if TYPE_CHECKING:
    from ghidra.analysis.funcdata import Funcdata
    from ghidra.ir.varnode import Varnode
    from ghidra.ir.op import PcodeOp


# =========================================================================
# LanedRegister  (transform.hh / transform.cc)
# =========================================================================

class LanedIterator:
    """Iterator over valid lane sizes in a LanedRegister bitmask."""

    def __init__(self, mask: int = 0) -> None:
        self._size: int = 0
        self._mask: int = mask
        self._normalize()

    def _normalize(self) -> None:
        flag = 1 << self._size
        while flag <= self._mask:
            if flag & self._mask:
                return
            self._size += 1
            flag <<= 1
        self._size = -1  # end sentinel

    def __iter__(self):
        return self

    def __next__(self) -> int:
        if self._size < 0:
            raise StopIteration
        val = self._size
        self._size += 1
        self._normalize()
        return val

    def __eq__(self, other):
        if isinstance(other, LanedIterator):
            return self._size == other._size
        return NotImplemented

    def __ne__(self, other):
        if isinstance(other, LanedIterator):
            return self._size != other._size
        return NotImplemented


class LanedRegister:
    """Describes a (register) storage location and the ways it might be
    split into lanes.  Uses a bitmask where bit *n* means lane-size *n*
    bytes is allowed.

    This is the C++-faithful version (bitmask based).
    """

    def __init__(self, sz: int = 0, mask: int = 0) -> None:
        self.wholeSize: int = sz
        self.sizeBitMask: int = mask

    def parseSizes(self, registerSize: int, laneSizes: str) -> None:
        """Parse a comma-separated list of lane sizes."""
        self.wholeSize = registerSize
        self.sizeBitMask = 0
        for part in laneSizes.split(','):
            part = part.strip()
            if not part:
                continue
            sz = int(part, 0)
            if sz < 0 or sz > 16:
                raise LowlevelError("Bad lane size: " + part)
            self.addLaneSize(sz)

    def getWholeSize(self) -> int:
        return self.wholeSize

    def getSizeBitMask(self) -> int:
        return self.sizeBitMask

    def addLaneSize(self, size: int) -> None:
        self.sizeBitMask |= (1 << size)

    def allowedLane(self, size: int) -> bool:
        return ((self.sizeBitMask >> size) & 1) != 0

    def __iter__(self):
        return LanedIterator(self.sizeBitMask)


# =========================================================================
# LaneDescription  (transform.hh / transform.cc)
# =========================================================================

class LaneDescription:
    """Description of logical lanes within a big Varnode.

    A lane is a byte-offset and size within a Varnode.  Lanes are disjoint.
    """

    def __init__(self, origSize: int, sz_or_lo: int, hi: Optional[int] = None) -> None:
        if hi is not None:
            # Two-lane constructor: LaneDescription(origSize, lo, hi)
            self.wholeSize: int = origSize
            self.laneSize: List[int] = [sz_or_lo, hi]
            self.lanePosition: List[int] = [0, sz_or_lo]
        else:
            # Uniform lane constructor: LaneDescription(origSize, sz)
            sz = sz_or_lo
            self.wholeSize = origSize
            numLanes = origSize // sz
            self.laneSize = [sz] * numLanes
            self.lanePosition = [i * sz for i in range(numLanes)]

    @classmethod
    def fromCopy(cls, other: LaneDescription) -> LaneDescription:
        """Copy constructor."""
        obj = cls.__new__(cls)
        obj.wholeSize = other.wholeSize
        obj.laneSize = list(other.laneSize)
        obj.lanePosition = list(other.lanePosition)
        return obj

    def getNumLanes(self) -> int:
        return len(self.laneSize)

    def getWholeSize(self) -> int:
        return self.wholeSize

    def getSize(self, i: int) -> int:
        return self.laneSize[i]

    def getPosition(self, i: int) -> int:
        return self.lanePosition[i]

    def getBoundary(self, bytePos: int) -> int:
        """Get index of lane starting at *bytePos*, or -1 if none."""
        if bytePos < 0 or bytePos > self.wholeSize:
            return -1
        if bytePos == self.wholeSize:
            return len(self.lanePosition)
        lo, hi = 0, len(self.lanePosition) - 1
        while lo <= hi:
            mid = (lo + hi) // 2
            pos = self.lanePosition[mid]
            if pos == bytePos:
                return mid
            if pos < bytePos:
                lo = mid + 1
            else:
                hi = mid - 1
        return -1

    def subset(self, lsbOffset: int, size: int) -> bool:
        """Trim to a sub-range.  Returns False if boundaries don't align."""
        if lsbOffset == 0 and size == self.wholeSize:
            return True
        firstLane = self.getBoundary(lsbOffset)
        if firstLane < 0:
            return False
        lastLane = self.getBoundary(lsbOffset + size)
        if lastLane < 0:
            return False
        newLaneSize: List[int] = []
        newLanePos: List[int] = []
        newPos = 0
        for i in range(firstLane, lastLane):
            sz = self.laneSize[i]
            newLanePos.append(newPos)
            newLaneSize.append(sz)
            newPos += sz
        self.wholeSize = size
        self.laneSize = newLaneSize
        self.lanePosition = newLanePos
        return True

    def restriction(self, numLanes: int, skipLanes: int,
                    bytePos: int, size: int) -> tuple:
        """Check if a truncation is natural.

        Returns ``(True, resNumLanes, resSkipLanes)`` on success,
        ``(False, 0, 0)`` on failure.
        """
        resSkipLanes = self.getBoundary(self.lanePosition[skipLanes] + bytePos)
        if resSkipLanes < 0:
            return (False, 0, 0)
        finalIndex = self.getBoundary(self.lanePosition[skipLanes] + bytePos + size)
        if finalIndex < 0:
            return (False, 0, 0)
        resNumLanes = finalIndex - resSkipLanes
        if resNumLanes == 0:
            return (False, 0, 0)
        return (True, resNumLanes, resSkipLanes)

    def extension(self, numLanes: int, skipLanes: int,
                  bytePos: int, size: int) -> tuple:
        """Check if an extension is natural.

        Returns ``(True, resNumLanes, resSkipLanes)`` on success,
        ``(False, 0, 0)`` on failure.
        """
        resSkipLanes = self.getBoundary(self.lanePosition[skipLanes] - bytePos)
        if resSkipLanes < 0:
            return (False, 0, 0)
        finalIndex = self.getBoundary(self.lanePosition[skipLanes] - bytePos + size)
        if finalIndex < 0:
            return (False, 0, 0)
        resNumLanes = finalIndex - resSkipLanes
        if resNumLanes == 0:
            return (False, 0, 0)
        return (True, resNumLanes, resSkipLanes)


# =========================================================================
# TransformVar  (transform.hh / transform.cc)
# =========================================================================

class TransformVar:
    """Placeholder node for a Varnode that will exist after a transform."""

    # Types of replacement Varnodes
    piece = 1
    preexisting = 2
    normal_temp = 3
    piece_temp = 4
    constant = 5
    constant_iop = 6

    # Flags
    split_terminator = 1
    input_duplicate = 2

    def __init__(self) -> None:
        self.vn: Optional[Varnode] = None
        self.replacement: Optional[Varnode] = None
        self.type: int = 0
        self.flags: int = 0
        self.byteSize: int = 0
        self.bitSize: int = 0
        self.val: int = 0
        self.defOp: Optional[TransformOp] = None

    def initialize(self, tp: int, vn: Optional[Varnode],
                   bits: int, byteSz: int, value: int) -> None:
        self.type = tp
        self.vn = vn
        self.val = value
        self.bitSize = bits
        self.byteSize = byteSz
        self.flags = 0
        self.defOp = None
        self.replacement = None

    def getOriginal(self) -> Optional[Varnode]:
        return self.vn

    def getDef(self) -> Optional[TransformOp]:
        return self.defOp

    def createReplacement(self, fd: Funcdata) -> None:
        """Create the actual Varnode this placeholder represents."""
        if self.replacement is not None:
            return
        if self.type == TransformVar.preexisting:
            self.replacement = self.vn
        elif self.type == TransformVar.constant:
            self.replacement = fd.newConstant(self.byteSize, self.val)
        elif self.type in (TransformVar.normal_temp, TransformVar.piece_temp):
            if self.defOp is None:
                self.replacement = fd.newUnique(self.byteSize)
            else:
                self.replacement = fd.newUniqueOut(self.byteSize, self.defOp.replacement)
        elif self.type == TransformVar.piece:
            bytePos = int(self.val)
            if (bytePos & 7) != 0:
                raise LowlevelError("Varnode piece is not byte aligned")
            bytePos >>= 3
            if self.vn.getSpace().isBigEndian():
                bytePos = self.vn.getSize() - bytePos - self.byteSize
            addr = self.vn.getAddr() + bytePos
            addr.renormalize(self.byteSize)
            if self.defOp is None:
                self.replacement = fd.newVarnode(self.byteSize, addr)
            else:
                self.replacement = fd.newVarnodeOut(self.byteSize, addr, self.defOp.replacement)
            fd.transferVarnodeProperties(self.vn, self.replacement, bytePos)
        elif self.type == TransformVar.constant_iop:
            iop_space = fd.getArch().getIopSpace()
            indeffect = fd.getOpFromConst(Address(iop_space, self.val))
            self.replacement = fd.newVarnodeIop(indeffect)
        else:
            raise LowlevelError("Bad TransformVar type")


# =========================================================================
# TransformOp  (transform.hh / transform.cc)
# =========================================================================

class TransformOp:
    """Placeholder node for a PcodeOp that will exist after a transform."""

    # Special annotations
    op_replacement = 1
    op_preexisting = 2
    indirect_creation = 4
    indirect_creation_possible_out = 8

    def __init__(self) -> None:
        self.op: Optional[PcodeOp] = None
        self.replacement: Optional[PcodeOp] = None
        self.opc: int = OpCode.CPUI_COPY
        self.special: int = 0
        self.output: Optional[TransformVar] = None
        self.input: List[Optional[TransformVar]] = []
        self.follow: Optional[TransformOp] = None

    def getOut(self) -> Optional[TransformVar]:
        return self.output

    def getIn(self, i: int) -> Optional[TransformVar]:
        return self.input[i]

    def inheritIndirect(self, indOp: PcodeOp) -> None:
        """Set indirect creation flags based on given INDIRECT op."""
        if indOp.isIndirectCreation():
            if indOp.getIn(0).isIndirectZero():
                self.special |= TransformOp.indirect_creation
            else:
                self.special |= TransformOp.indirect_creation_possible_out

    def createReplacement(self, fd: Funcdata) -> None:
        """Create the actual PcodeOp this placeholder represents."""
        if (self.special & TransformOp.op_preexisting) != 0:
            self.replacement = self.op
            fd.opSetOpcode(self.op, self.opc)
            while len(self.input) < self.op.numInput():
                fd.opRemoveInput(self.op, self.op.numInput() - 1)
            for i in range(self.op.numInput()):
                fd.opUnsetInput(self.op, i)
            while self.op.numInput() < len(self.input):
                fd.opInsertInput(self.op, None, self.op.numInput() - 1)
        else:
            self.replacement = fd.newOp(len(self.input), self.op.getAddr())
            fd.opSetOpcode(self.replacement, self.opc)
            if self.output is not None:
                self.output.createReplacement(fd)
            if self.follow is None:
                if self.opc == OpCode.CPUI_MULTIEQUAL:
                    fd.opInsertBegin(self.replacement, self.op.getParent())
                else:
                    fd.opInsertBefore(self.replacement, self.op)

    def attemptInsertion(self, fd: Funcdata) -> bool:
        """Try to insert this op into its basic block.

        Returns True if inserted or already inserted.
        """
        if self.follow is not None:
            if self.follow.follow is None:
                if self.opc == OpCode.CPUI_MULTIEQUAL:
                    fd.opInsertBegin(self.replacement, self.follow.replacement.getParent())
                else:
                    fd.opInsertBefore(self.replacement, self.follow.replacement)
                self.follow = None
                return True
            return False
        return True


# =========================================================================
# TransformManager  (transform.hh / transform.cc)
# =========================================================================

class TransformManager:
    """Orchestrates building and applying a large-scale data-flow transform.

    Subclasses (e.g. lane-splitting) populate placeholder TransformVar /
    TransformOp nodes.  Calling :meth:`apply` realises them in the Funcdata.
    """

    def __init__(self, fd: Funcdata) -> None:
        self.fd: Funcdata = fd
        self.pieceMap: Dict[int, List[TransformVar]] = {}
        self.newVarnodes: List[TransformVar] = []
        self.newOps: List[TransformOp] = []

    def getFunction(self) -> Funcdata:
        return self.fd

    # -- virtual --

    def preserveAddress(self, vn: Varnode, bitSize: int, lsbOffset: int) -> bool:
        """Should overlapping storage be used for a piece?"""
        if (lsbOffset & 7) != 0:
            return False
        if vn.getSpace().getType() == IPTR_INTERNAL:
            return False
        return True

    # -- varnode marks --

    def clearVarnodeMarks(self) -> None:
        for arr in self.pieceMap.values():
            vn = arr[0].vn if arr else None
            if vn is not None:
                vn.clearMark()

    # -- new placeholder factories (Varnodes) --

    def newPreexistingVarnode(self, vn: Varnode) -> TransformVar:
        res = TransformVar()
        res.initialize(TransformVar.preexisting, vn,
                       vn.getSize() * 8, vn.getSize(), 0)
        res.flags = TransformVar.split_terminator
        self.pieceMap[vn.getCreateIndex()] = [res]
        return res

    def newUnique(self, size: int) -> TransformVar:
        res = TransformVar()
        res.initialize(TransformVar.normal_temp, None, size * 8, size, 0)
        self.newVarnodes.append(res)
        return res

    def newConstant(self, size: int, lsbOffset: int, val: int) -> TransformVar:
        res = TransformVar()
        res.initialize(TransformVar.constant, None, size * 8, size,
                       (val >> lsbOffset) & calc_mask(size))
        self.newVarnodes.append(res)
        return res

    def newIop(self, vn: Varnode) -> TransformVar:
        res = TransformVar()
        res.initialize(TransformVar.constant_iop, None,
                       vn.getSize() * 8, vn.getSize(), vn.getOffset())
        self.newVarnodes.append(res)
        return res

    def newPiece(self, vn: Varnode, bitSize: int, lsbOffset: int) -> TransformVar:
        byteSize = (bitSize + 7) // 8
        tp = TransformVar.piece if self.preserveAddress(vn, bitSize, lsbOffset) else TransformVar.piece_temp
        res = TransformVar()
        res.initialize(tp, vn, bitSize, byteSize, lsbOffset)
        res.flags = TransformVar.split_terminator
        self.pieceMap[vn.getCreateIndex()] = [res]
        return res

    def newSplit(self, vn: Varnode, description: LaneDescription,
                 numLanes: Optional[int] = None,
                 startLane: int = 0) -> List[TransformVar]:
        """Create placeholder nodes splitting *vn* into lanes.

        Returns a list of TransformVar from least to most significant.
        """
        if numLanes is None:
            numLanes = description.getNumLanes()
            startLane = 0
            baseBitPos = 0
        else:
            baseBitPos = description.getPosition(startLane) * 8

        result: List[TransformVar] = []
        for i in range(numLanes):
            bitpos = description.getPosition(startLane + i) * 8 - baseBitPos
            byteSize = description.getSize(startLane + i)
            nv = TransformVar()
            if vn.isConstant():
                if bitpos < 64:
                    val = (vn.getOffset() >> bitpos) & calc_mask(byteSize)
                else:
                    val = 0
                nv.initialize(TransformVar.constant, vn, byteSize * 8, byteSize, val)
            else:
                tp = TransformVar.piece if self.preserveAddress(vn, byteSize * 8, bitpos) else TransformVar.piece_temp
                nv.initialize(tp, vn, byteSize * 8, byteSize, bitpos)
            result.append(nv)
        result[-1].flags = TransformVar.split_terminator
        self.pieceMap[vn.getCreateIndex()] = result
        return result

    # -- new placeholder factories (Ops) --

    def newOpReplace(self, numParams: int, opc: int, replace: PcodeOp) -> TransformOp:
        rop = TransformOp()
        rop.op = replace
        rop.opc = opc
        rop.special = TransformOp.op_replacement
        rop.input = [None] * numParams
        self.newOps.append(rop)
        return rop

    def newOp(self, numParams: int, opc: int, follow: TransformOp) -> TransformOp:
        rop = TransformOp()
        rop.op = follow.op
        rop.opc = opc
        rop.follow = follow
        rop.input = [None] * numParams
        self.newOps.append(rop)
        return rop

    def newPreexistingOp(self, numParams: int, opc: int, originalOp: PcodeOp) -> TransformOp:
        rop = TransformOp()
        rop.op = originalOp
        rop.opc = opc
        rop.special = TransformOp.op_preexisting
        rop.input = [None] * numParams
        self.newOps.append(rop)
        return rop

    # -- get-or-create --

    def getPreexistingVarnode(self, vn: Varnode) -> TransformVar:
        if vn.isConstant():
            return self.newConstant(vn.getSize(), 0, vn.getOffset())
        arr = self.pieceMap.get(vn.getCreateIndex())
        if arr is not None:
            return arr[0]
        return self.newPreexistingVarnode(vn)

    def getPiece(self, vn: Varnode, bitSize: int, lsbOffset: int) -> TransformVar:
        arr = self.pieceMap.get(vn.getCreateIndex())
        if arr is not None:
            res = arr[0]
            if res.bitSize != bitSize or res.val != lsbOffset:
                raise LowlevelError(
                    "Cannot create multiple pieces for one Varnode through getPiece")
            return res
        return self.newPiece(vn, bitSize, lsbOffset)

    def getSplit(self, vn: Varnode, description: LaneDescription,
                 numLanes: Optional[int] = None,
                 startLane: int = 0) -> List[TransformVar]:
        arr = self.pieceMap.get(vn.getCreateIndex())
        if arr is not None:
            return arr
        if numLanes is None:
            return self.newSplit(vn, description)
        return self.newSplit(vn, description, numLanes, startLane)

    # -- wiring helpers --

    @staticmethod
    def opSetInput(rop: TransformOp, rvn: TransformVar, slot: int) -> None:
        rop.input[slot] = rvn

    @staticmethod
    def opSetOutput(rop: TransformOp, rvn: TransformVar) -> None:
        rop.output = rvn
        rvn.defOp = rop

    @staticmethod
    def preexistingGuard(slot: int, rvn: TransformVar) -> bool:
        """Should newPreexistingOp be called for this visit?"""
        if slot == 0:
            return True
        if rvn.type in (TransformVar.piece, TransformVar.piece_temp):
            return False
        return True

    # -- apply --

    def apply(self) -> None:
        """Realise the entire transform into the Funcdata."""
        inputList: List[TransformVar] = []
        self._createOps()
        self._createVarnodes(inputList)
        self._removeOld()
        self._transformInputVarnodes(inputList)
        self._placeInputs()

    # -- internal helpers --

    def _specialHandling(self, rop: TransformOp) -> None:
        if (rop.special & TransformOp.indirect_creation) != 0:
            self.fd.markIndirectCreation(rop.replacement, False)
        elif (rop.special & TransformOp.indirect_creation_possible_out) != 0:
            self.fd.markIndirectCreation(rop.replacement, True)

    def _createOps(self) -> None:
        for rop in self.newOps:
            rop.createReplacement(self.fd)
        # Ensure all ops with follow-chains get inserted
        while True:
            followCount = 0
            for rop in self.newOps:
                if not rop.attemptInsertion(self.fd):
                    followCount += 1
            if followCount == 0:
                break

    def _createVarnodes(self, inputList: List[TransformVar]) -> None:
        for arr in self.pieceMap.values():
            for rvn in arr:
                if rvn.type == TransformVar.piece:
                    vn = rvn.vn
                    if vn is not None and vn.isInput():
                        inputList.append(rvn)
                        if vn.isMark():
                            rvn.flags |= TransformVar.input_duplicate
                        else:
                            vn.setMark()
                rvn.createReplacement(self.fd)
                if (rvn.flags & TransformVar.split_terminator) != 0:
                    break
        for rvn in self.newVarnodes:
            rvn.createReplacement(self.fd)

    def _removeOld(self) -> None:
        for rop in self.newOps:
            if (rop.special & TransformOp.op_replacement) != 0:
                if not rop.op.isDead():
                    self.fd.opDestroy(rop.op)

    def _transformInputVarnodes(self, inputList: List[TransformVar]) -> None:
        for rvn in inputList:
            if (rvn.flags & TransformVar.input_duplicate) == 0:
                self.fd.deleteVarnode(rvn.vn)
            rvn.replacement = self.fd.setInputVarnode(rvn.replacement)

    def _placeInputs(self) -> None:
        for rop in self.newOps:
            op = rop.replacement
            for i, rvn in enumerate(rop.input):
                if rvn is None:
                    continue
                if rvn.replacement is None:
                    rvn.createReplacement(self.fd)
                if rvn.replacement is not None:
                    self.fd.opSetInput(op, rvn.replacement, i)
            self._specialHandling(rop)
