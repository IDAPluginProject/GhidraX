"""
Corresponds to: prefersplit.hh / prefersplit.cc

PreferSplitRecord for tracking preferred split points in laned registers.
When a register can be logically split into smaller lanes (e.g. XMM into
4x float), this tracks the preferred split configuration.
"""

from __future__ import annotations
from bisect import bisect_left
from typing import List, Optional, TYPE_CHECKING
from ghidra.core.address import Address
from ghidra.core.opcodes import OpCode

if TYPE_CHECKING:
    from ghidra.analysis.funcdata import Funcdata


def _calc_mask(size: int) -> int:
    """Calculate bit mask for given byte size."""
    if size >= 8:
        return 0xFFFFFFFFFFFFFFFF
    return (1 << (size * 8)) - 1


class LanedRegister:
    """A register that can be split into logical lanes."""

    def __init__(self, sz: int = 0) -> None:
        self.wholeSize: int = sz
        self._lanes: List[int] = []

    def addLaneSize(self, laneSize: int) -> None:
        self._lanes.append(laneSize)

    def getWholeSize(self) -> int:
        return self.wholeSize

    def getNumLanes(self, laneSize: int) -> int:
        if laneSize == 0:
            return 0
        return self.wholeSize // laneSize

    def getLaneSizes(self) -> List[int]:
        return self._lanes

    def supportsSplit(self, laneSize: int) -> bool:
        return laneSize in self._lanes


class PreferSplitRecord:
    """Record of a preferred split for a storage location.

    Associates a specific storage location with a preferred way
    to split it into lanes of a given size.
    """

    def __init__(self) -> None:
        self.storage: Address = Address()
        self.splitSize: int = 0
        self.totalSize: int = 0

    def init(self, addr: Address, splitSz: int, totalSz: int) -> None:
        self.storage = addr
        self.splitSize = splitSz
        self.totalSize = totalSz

    def getAddress(self) -> Address:
        return self.storage

    def getSplitSize(self) -> int:
        return self.splitSize

    def getTotalSize(self) -> int:
        return self.totalSize

    def getNumLanes(self) -> int:
        if self.splitSize == 0:
            return 0
        return self.totalSize // self.splitSize

    def encode(self, encoder) -> None:
        """Encode this record's storage as a VarnodeData element.

        C++ ref: Architecture stores PreferSplitRecords via VarnodeData encoding.
        """
        self.storage.encode(encoder)

    def decode(self, decoder) -> None:
        """Decode this record's storage from a VarnodeData element.

        C++ ref: ``Architecture::decodePreferSplit`` — decodes storage then
        sets splitoffset = storage.size / 2.
        """
        self.storage = Address.decode(decoder)
        self.splitSize = self.totalSize // 2 if self.totalSize > 0 else 0

    def __lt__(self, other) -> bool:
        if not isinstance(other, PreferSplitRecord):
            return NotImplemented
        if self.storage.getSpace() != other.storage.getSpace():
            return self.storage.getSpace().getIndex() < other.storage.getSpace().getIndex()
        if self.totalSize != other.totalSize:
            return self.totalSize > other.totalSize
        return self.storage.getOffset() < other.storage.getOffset()


class PreferSplitManager:
    """Manages a collection of PreferSplitRecords for an architecture.

    Handles splitting Varnodes at preferred points during heritage.
    C++ ref: PreferSplitManager in prefersplit.hh/cc
    """

    IPTR_INTERNAL = 4  # AddrSpace type constant for unique/temp space

    class SplitInstance:
        """Tracks a Varnode being split into hi/lo pieces."""
        def __init__(self, vn=None, off: int = 0):
            self.splitoffset: int = off
            self.vn = vn
            self.hi = None
            self.lo = None

    def __init__(self) -> None:
        self._records: List[PreferSplitRecord] = []
        self._data: Optional[Funcdata] = None
        self._tempsplits: list = []

    def init(self, fd: Funcdata, records) -> None:
        """Initialize with a Funcdata and list of PreferSplitRecords."""
        self._data = fd
        self._records = records

    def addRecord(self, rec: PreferSplitRecord) -> None:
        self._records.append(rec)
        self._records.sort()

    def findRecord(self, addr_or_vn, sz: int = None) -> Optional[PreferSplitRecord]:
        """Find a record by address+size or by Varnode.

        C++ ref: PreferSplitManager::findRecord uses binary search (lower_bound).
        """
        if sz is not None:
            templ = PreferSplitRecord()
            templ.storage = addr_or_vn
            templ.totalSize = sz
        else:
            vn = addr_or_vn
            templ = PreferSplitRecord()
            templ.storage = vn.getAddr()
            templ.totalSize = vn.getSize()
        index = bisect_left(self._records, templ)
        if index == len(self._records):
            return None
        rec = self._records[index]
        if templ < rec:
            return None
        return rec

    def hasSplit(self, addr: Address, sz: int) -> bool:
        return self.findRecord(addr, sz) is not None

    def numRecords(self) -> int:
        return len(self._records)

    def getRecords(self) -> list:
        return self._records

    def decode(self, decoder) -> None:
        """Decode a <prefersplit> element containing multiple records."""
        from ghidra.core.marshal import ELEM_PREFERSPLIT, ATTRIB_STYLE
        elemId = decoder.openElement(ELEM_PREFERSPLIT)
        style = decoder.readString(ATTRIB_STYLE)
        if style != "inhalf":
            raise Exception("Unknown prefersplit style: " + style)
        while decoder.peekElement() != 0:
            rec = PreferSplitRecord()
            rec.storage = Address.decode(decoder)
            rec.totalSize = rec.storage.getAddrSize() if hasattr(rec.storage, 'getAddrSize') else 0
            rec.splitSize = rec.totalSize // 2 if rec.totalSize > 0 else 0
            self._records.append(rec)
        decoder.closeElement(elemId)
        self._records.sort()

    def encode(self, encoder) -> None:
        """Encode all records as a <prefersplit> element."""
        from ghidra.core.marshal import ELEM_PREFERSPLIT, ATTRIB_STYLE
        if not self._records:
            return
        encoder.openElement(ELEM_PREFERSPLIT)
        encoder.writeString(ATTRIB_STYLE, "inhalf")
        for rec in self._records:
            rec.encode(encoder)
        encoder.closeElement(ELEM_PREFERSPLIT)

    def fillinAddress(self, fd) -> None:
        """Fill in register addresses from the translate object."""
        pass  # Requires full translate infrastructure

    def clear(self) -> None:
        self._records.clear()
        self._tempsplits.clear()

    # ------------------------------------------------------------------
    # Core split logic matching C++ prefersplit.cc
    # ------------------------------------------------------------------

    def _fillinInstance(self, inst: 'PreferSplitManager.SplitInstance',
                        bigendian: bool, sethi: bool, setlo: bool) -> None:
        """Define the varnode pieces of *inst*.

        C++ ref: PreferSplitManager::fillinInstance (lines 33-67)
        """
        vn = inst.vn
        if bigendian:
            losize = vn.getSize() - inst.splitoffset
        else:
            losize = inst.splitoffset
        hisize = vn.getSize() - losize

        if vn.isConstant():
            origval = vn.getOffset()
            loval = origval & _calc_mask(losize)
            hival = (origval >> (8 * losize)) & _calc_mask(hisize)
            if setlo and inst.lo is None:
                inst.lo = self._data.newConstant(losize, loval)
            if sethi and inst.hi is None:
                inst.hi = self._data.newConstant(hisize, hival)
        else:
            if bigendian:
                if setlo and inst.lo is None:
                    inst.lo = self._data.newVarnode(losize, vn.getAddr() + inst.splitoffset)
                if sethi and inst.hi is None:
                    inst.hi = self._data.newVarnode(hisize, vn.getAddr())
            else:
                if setlo and inst.lo is None:
                    inst.lo = self._data.newVarnode(losize, vn.getAddr())
                if sethi and inst.hi is None:
                    inst.hi = self._data.newVarnode(hisize, vn.getAddr() + inst.splitoffset)

    def _createCopyOps(self, ininst: 'PreferSplitManager.SplitInstance',
                        outinst: 'PreferSplitManager.SplitInstance',
                        op, istemp: bool) -> None:
        """Create COPY ops based on ininst and outinst to replace op.

        C++ ref: PreferSplitManager::createCopyOps (lines 69-87)
        """
        hiop = self._data.newOp(1, op.getAddr())
        loop = self._data.newOp(1, op.getAddr())
        self._data.opSetOpcode(hiop, int(OpCode.CPUI_COPY))
        self._data.opSetOpcode(loop, int(OpCode.CPUI_COPY))

        self._data.opInsertAfter(loop, op)
        self._data.opInsertAfter(hiop, op)
        self._data.opUnsetInput(op, 0)

        self._data.opSetOutput(hiop, outinst.hi)
        self._data.opSetOutput(loop, outinst.lo)
        self._data.opSetInput(hiop, ininst.hi, 0)
        self._data.opSetInput(loop, ininst.lo, 0)
        self._tempsplits.append(hiop)
        self._tempsplits.append(loop)

    def _testDefiningCopy(self, inst: 'PreferSplitManager.SplitInstance', defop) -> tuple:
        """Check that inst defined by defop is really splittable.

        C++ ref: PreferSplitManager::testDefiningCopy (lines 89-105)
        Returns (ok, istemp).
        """
        invn = defop.getIn(0)
        istemp = False
        if not invn.isConstant():
            if invn.getSpace().getType() != self.IPTR_INTERNAL:
                inrec = self.findRecord(invn)
                if inrec is None:
                    return (False, istemp)
                if inrec.splitSize != inst.splitoffset:
                    return (False, istemp)
                if not invn.isFree():
                    return (False, istemp)
            else:
                istemp = True
        return (True, istemp)

    def _splitDefiningCopy(self, inst: 'PreferSplitManager.SplitInstance', defop, istemp: bool) -> None:
        """Do split of preferred split varnode defined by a COPY.

        C++ ref: PreferSplitManager::splitDefiningCopy (lines 107-116)
        """
        invn = defop.getIn(0)
        ininst = PreferSplitManager.SplitInstance(invn, inst.splitoffset)
        bigendian = inst.vn.getSpace().isBigEndian()
        self._fillinInstance(inst, bigendian, True, True)
        self._fillinInstance(ininst, bigendian, True, True)
        self._createCopyOps(ininst, inst, defop, istemp)

    def _testReadingCopy(self, inst: 'PreferSplitManager.SplitInstance', readop) -> tuple:
        """Check that inst read by readop is really splittable.

        C++ ref: PreferSplitManager::testReadingCopy (lines 118-131)
        Returns (ok, istemp).
        """
        outvn = readop.getOut()
        istemp = False
        if outvn.getSpace().getType() != self.IPTR_INTERNAL:
            outrec = self.findRecord(outvn)
            if outrec is None:
                return (False, istemp)
            if outrec.splitSize != inst.splitoffset:
                return (False, istemp)
        else:
            istemp = True
        return (True, istemp)

    def _splitReadingCopy(self, inst: 'PreferSplitManager.SplitInstance', readop, istemp: bool) -> None:
        """Do split of varnode that is read by a COPY.

        C++ ref: PreferSplitManager::splitReadingCopy (lines 133-142)
        """
        outvn = readop.getOut()
        outinst = PreferSplitManager.SplitInstance(outvn, inst.splitoffset)
        bigendian = inst.vn.getSpace().isBigEndian()
        self._fillinInstance(inst, bigendian, True, True)
        self._fillinInstance(outinst, bigendian, True, True)
        self._createCopyOps(inst, outinst, readop, istemp)

    def _testZext(self, inst: 'PreferSplitManager.SplitInstance', op) -> bool:
        """Check that inst defined by ZEXT is really splittable.

        C++ ref: PreferSplitManager::testZext (lines 144-158)
        """
        invn = op.getIn(0)
        if invn.isConstant():
            return True
        bigendian = inst.vn.getSpace().isBigEndian()
        if bigendian:
            losize = inst.vn.getSize() - inst.splitoffset
        else:
            losize = inst.splitoffset
        if invn.getSize() != losize:
            return False
        return True

    def _splitZext(self, inst: 'PreferSplitManager.SplitInstance', op) -> None:
        """Split ZEXT-defined varnode.

        C++ ref: PreferSplitManager::splitZext (lines 160-188)
        """
        ininst = PreferSplitManager.SplitInstance(op.getIn(0), inst.splitoffset)
        bigendian = inst.vn.getSpace().isBigEndian()
        if bigendian:
            hisize = inst.splitoffset
            losize = inst.vn.getSize() - inst.splitoffset
        else:
            losize = inst.splitoffset
            hisize = inst.vn.getSize() - inst.splitoffset
        if ininst.vn.isConstant():
            origval = ininst.vn.getOffset()
            loval = origval & _calc_mask(losize)
            hival = (origval >> (8 * losize)) & _calc_mask(hisize)
            ininst.lo = self._data.newConstant(losize, loval)
            ininst.hi = self._data.newConstant(hisize, hival)
        else:
            ininst.lo = ininst.vn
            ininst.hi = self._data.newConstant(hisize, 0)
        self._fillinInstance(inst, bigendian, True, True)
        self._createCopyOps(ininst, inst, op, False)

    def _testPiece(self, inst: 'PreferSplitManager.SplitInstance', op) -> bool:
        """Check that inst defined by PIECE is really splittable.

        C++ ref: PreferSplitManager::testPiece (lines 190-200)
        """
        bigendian = inst.vn.getSpace().isBigEndian()
        if bigendian:
            if op.getIn(0).getSize() != inst.splitoffset:
                return False
        else:
            if op.getIn(1).getSize() != inst.splitoffset:
                return False
        return True

    def _splitPiece(self, inst: 'PreferSplitManager.SplitInstance', op) -> None:
        """Split PIECE-defined varnode.

        C++ ref: PreferSplitManager::splitPiece (lines 202-227)
        """
        loin = op.getIn(1)
        hiin = op.getIn(0)
        bigendian = inst.vn.getSpace().isBigEndian()
        self._fillinInstance(inst, bigendian, True, True)
        hiop = self._data.newOp(1, op.getAddr())
        loop = self._data.newOp(1, op.getAddr())
        self._data.opSetOpcode(hiop, int(OpCode.CPUI_COPY))
        self._data.opSetOpcode(loop, int(OpCode.CPUI_COPY))
        self._data.opSetOutput(hiop, inst.hi)
        self._data.opSetOutput(loop, inst.lo)
        self._data.opInsertAfter(loop, op)
        self._data.opInsertAfter(hiop, op)
        self._data.opUnsetInput(op, 0)
        self._data.opUnsetInput(op, 1)
        if hiin.isConstant():
            hiin = self._data.newConstant(hiin.getSize(), hiin.getOffset())
        self._data.opSetInput(hiop, hiin, 0)
        if loin.isConstant():
            loin = self._data.newConstant(loin.getSize(), loin.getOffset())
        self._data.opSetInput(loop, loin, 0)

    def _testSubpiece(self, inst: 'PreferSplitManager.SplitInstance', op) -> bool:
        """Check that inst read by SUBPIECE is really splittable.

        C++ ref: PreferSplitManager::testSubpiece (lines 229-246)
        """
        vn = inst.vn
        outvn = op.getOut()
        suboff = int(op.getIn(1).getOffset())
        if suboff == 0:
            if vn.getSize() - inst.splitoffset != outvn.getSize():
                return False
        else:
            if vn.getSize() - suboff != inst.splitoffset:
                return False
            if outvn.getSize() != inst.splitoffset:
                return False
        return True

    def _splitSubpiece(self, inst: 'PreferSplitManager.SplitInstance', op) -> None:
        """Rewrite SUBPIECE to a COPY extracting a logical piece.

        C++ ref: PreferSplitManager::splitSubpiece (lines 248-263)
        """
        suboff = int(op.getIn(1).getOffset())
        grabbinglo = (suboff == 0)
        bigendian = inst.vn.getSpace().isBigEndian()
        self._fillinInstance(inst, bigendian, not grabbinglo, grabbinglo)
        self._data.opSetOpcode(op, int(OpCode.CPUI_COPY))
        self._data.opRemoveInput(op, 1)
        invn = inst.lo if grabbinglo else inst.hi
        self._data.opSetInput(op, invn, 0)

    def _testLoad(self, inst: 'PreferSplitManager.SplitInstance', op) -> bool:
        """C++ ref: PreferSplitManager::testLoad — always returns True."""
        return True

    def _splitLoad(self, inst: 'PreferSplitManager.SplitInstance', op) -> None:
        """Split a LOAD that defines inst into two LOADs.

        C++ ref: PreferSplitManager::splitLoad (lines 271-314)
        """
        bigendian = inst.vn.getSpace().isBigEndian()
        self._fillinInstance(inst, bigendian, True, True)
        hiop = self._data.newOp(2, op.getAddr())
        loop = self._data.newOp(2, op.getAddr())
        addop = self._data.newOp(2, op.getAddr())
        ptrvn = op.getIn(1)
        self._data.opSetOpcode(hiop, int(OpCode.CPUI_LOAD))
        self._data.opSetOpcode(loop, int(OpCode.CPUI_LOAD))
        self._data.opSetOpcode(addop, int(OpCode.CPUI_INT_ADD))
        self._data.opInsertAfter(loop, op)
        self._data.opInsertAfter(hiop, op)
        self._data.opInsertAfter(addop, op)
        self._data.opUnsetInput(op, 1)
        addvn = self._data.newUniqueOut(ptrvn.getSize(), addop)
        self._data.opSetInput(addop, ptrvn, 0)
        self._data.opSetInput(addop, self._data.newConstant(ptrvn.getSize(), inst.splitoffset), 1)
        self._data.opSetOutput(hiop, inst.hi)
        self._data.opSetOutput(loop, inst.lo)
        spaceid = op.getIn(0)
        spc = spaceid.getSpaceFromConst()
        spaceid2 = self._data.newConstant(spaceid.getSize(), spaceid.getOffset())
        self._data.opSetInput(hiop, spaceid2, 0)
        spaceid3 = self._data.newConstant(spaceid.getSize(), spaceid.getOffset())
        self._data.opSetInput(loop, spaceid3, 0)
        if ptrvn.isFree():
            ptrvn = self._data.newVarnode(ptrvn.getSize(), ptrvn.getSpace(), ptrvn.getOffset())
        if spc.isBigEndian():
            self._data.opSetInput(hiop, ptrvn, 1)
            self._data.opSetInput(loop, addvn, 1)
        else:
            self._data.opSetInput(hiop, addvn, 1)
            self._data.opSetInput(loop, ptrvn, 1)

    def _testStore(self, inst: 'PreferSplitManager.SplitInstance', op) -> bool:
        """C++ ref: PreferSplitManager::testStore — always returns True."""
        return True

    def _splitStore(self, inst: 'PreferSplitManager.SplitInstance', op) -> None:
        """Split a STORE of inst into two STOREs.

        C++ ref: PreferSplitManager::splitStore (lines 322-365)
        """
        bigendian = inst.vn.getSpace().isBigEndian()
        self._fillinInstance(inst, bigendian, True, True)
        hiop = self._data.newOp(3, op.getAddr())
        loop = self._data.newOp(3, op.getAddr())
        addop = self._data.newOp(2, op.getAddr())
        ptrvn = op.getIn(1)
        self._data.opSetOpcode(hiop, int(OpCode.CPUI_STORE))
        self._data.opSetOpcode(loop, int(OpCode.CPUI_STORE))
        self._data.opSetOpcode(addop, int(OpCode.CPUI_INT_ADD))
        self._data.opInsertAfter(loop, op)
        self._data.opInsertAfter(hiop, op)
        self._data.opInsertAfter(addop, op)
        self._data.opUnsetInput(op, 1)
        self._data.opUnsetInput(op, 2)
        addvn = self._data.newUniqueOut(ptrvn.getSize(), addop)
        self._data.opSetInput(addop, ptrvn, 0)
        self._data.opSetInput(addop, self._data.newConstant(ptrvn.getSize(), inst.splitoffset), 1)
        self._data.opSetInput(hiop, inst.hi, 2)
        self._data.opSetInput(loop, inst.lo, 2)
        spaceid = op.getIn(0)
        spc = spaceid.getSpaceFromConst()
        spaceid2 = self._data.newConstant(spaceid.getSize(), spaceid.getOffset())
        self._data.opSetInput(hiop, spaceid2, 0)
        spaceid3 = self._data.newConstant(spaceid.getSize(), spaceid.getOffset())
        self._data.opSetInput(loop, spaceid3, 0)
        if ptrvn.isFree():
            ptrvn = self._data.newVarnode(ptrvn.getSize(), ptrvn.getSpace(), ptrvn.getOffset())
        if spc.isBigEndian():
            self._data.opSetInput(hiop, ptrvn, 1)
            self._data.opSetInput(loop, addvn, 1)
        else:
            self._data.opSetInput(hiop, addvn, 1)
            self._data.opSetInput(loop, ptrvn, 1)

    def _splitVarnode(self, inst: 'PreferSplitManager.SplitInstance') -> bool:
        """Test if vn can be readily split, if so, do the split.

        C++ ref: PreferSplitManager::splitVarnode (lines 367-428)
        """
        vn = inst.vn
        if vn.isWritten():
            if not vn.hasNoDescend():
                return False
            op = vn.getDef()
            opc = op.code()
            if opc == OpCode.CPUI_COPY:
                ok, istemp = self._testDefiningCopy(inst, op)
                if not ok:
                    return False
                self._splitDefiningCopy(inst, op, istemp)
            elif opc == OpCode.CPUI_PIECE:
                if not self._testPiece(inst, op):
                    return False
                self._splitPiece(inst, op)
            elif opc == OpCode.CPUI_LOAD:
                if not self._testLoad(inst, op):
                    return False
                self._splitLoad(inst, op)
            elif opc == OpCode.CPUI_INT_ZEXT:
                if not self._testZext(inst, op):
                    return False
                self._splitZext(inst, op)
            else:
                return False
            self._data.opDestroy(op)
        else:
            if not vn.isFree():
                return False
            op = vn.loneDescend()
            if op is None:
                return False
            opc = op.code()
            if opc == OpCode.CPUI_COPY:
                ok, istemp = self._testReadingCopy(inst, op)
                if not ok:
                    return False
                self._splitReadingCopy(inst, op, istemp)
            elif opc == OpCode.CPUI_SUBPIECE:
                if not self._testSubpiece(inst, op):
                    return False
                self._splitSubpiece(inst, op)
                return True  # Do not destroy op, it has been transformed
            elif opc == OpCode.CPUI_STORE:
                if not self._testStore(inst, op):
                    return False
                self._splitStore(inst, op)
            else:
                return False
            self._data.opDestroy(op)
        return True

    def _splitRecord(self, rec: PreferSplitRecord) -> None:
        """Split all Varnodes matching the given record.

        C++ ref: PreferSplitManager::splitRecord (lines 430-449)
        """
        addr = rec.storage
        inst = PreferSplitManager.SplitInstance(None, rec.splitSize)
        while True:
            self._data.endLoc(rec.totalSize, addr)
            found = False
            for vn in list(self._data.beginLoc(rec.totalSize, addr)):
                inst.vn = vn
                inst.lo = None
                inst.hi = None
                if self._splitVarnode(inst):
                    found = True
                    break
            if not found:
                break

    def _testTemporary(self, inst: 'PreferSplitManager.SplitInstance') -> bool:
        """Test if a temporary can be split.

        C++ ref: PreferSplitManager::testTemporary (lines 451-491)
        """
        op = inst.vn.getDef()
        opc = op.code()
        if opc == OpCode.CPUI_PIECE:
            if not self._testPiece(inst, op):
                return False
        elif opc == OpCode.CPUI_LOAD:
            if not self._testLoad(inst, op):
                return False
        elif opc == OpCode.CPUI_INT_ZEXT:
            if not self._testZext(inst, op):
                return False
        else:
            return False
        for readop in list(inst.vn.getDescend()):
            ropc = readop.code()
            if ropc == OpCode.CPUI_SUBPIECE:
                if not self._testSubpiece(inst, readop):
                    return False
            elif ropc == OpCode.CPUI_STORE:
                if not self._testStore(inst, readop):
                    return False
            else:
                return False
        return True

    def _splitTemporary(self, inst: 'PreferSplitManager.SplitInstance') -> None:
        """Split a temporary varnode.

        C++ ref: PreferSplitManager::splitTemporary (lines 493-527)
        """
        vn = inst.vn
        op = vn.getDef()
        opc = op.code()
        if opc == OpCode.CPUI_PIECE:
            self._splitPiece(inst, op)
        elif opc == OpCode.CPUI_LOAD:
            self._splitLoad(inst, op)
        elif opc == OpCode.CPUI_INT_ZEXT:
            self._splitZext(inst, op)

        while True:
            descend = list(vn.getDescend())
            if not descend:
                break
            readop = descend[0]
            ropc = readop.code()
            if ropc == OpCode.CPUI_SUBPIECE:
                self._splitSubpiece(inst, readop)
            elif ropc == OpCode.CPUI_STORE:
                self._splitStore(inst, readop)
                self._data.opDestroy(readop)
            else:
                break
        self._data.opDestroy(op)

    def split(self) -> None:
        """Perform initial splitting of Varnodes based on records.

        C++ ref: PreferSplitManager::split (lines 558-563)
        """
        for rec in self._records:
            self._splitRecord(rec)

    def splitAdditional(self) -> None:
        """Split any additional temporaries discovered during initial split.

        C++ ref: PreferSplitManager::splitAdditional (lines 565-629)
        """
        defops: list = []
        for tmpop in self._tempsplits:
            if tmpop.isDead():
                continue
            vn = tmpop.getIn(0)
            if vn.isWritten():
                defop = vn.getDef()
                if defop.code() == OpCode.CPUI_SUBPIECE:
                    invn = defop.getIn(0)
                    if invn.getSpace().getType() == self.IPTR_INTERNAL:
                        defops.append(defop)
            outvn = tmpop.getOut()
            for descop in list(outvn.getDescend()):
                if descop.code() == OpCode.CPUI_PIECE:
                    poutvn = descop.getOut()
                    if poutvn.getSpace().getType() == self.IPTR_INTERNAL:
                        defops.append(descop)
        for defop in defops:
            if defop.isDead():
                continue
            opc = defop.code()
            if opc == OpCode.CPUI_PIECE:
                vn = defop.getOut()
                bigendian = vn.getSpace().isBigEndian()
                if bigendian:
                    splitoff = defop.getIn(0).getSize()
                else:
                    splitoff = defop.getIn(1).getSize()
                inst = PreferSplitManager.SplitInstance(vn, splitoff)
                if self._testTemporary(inst):
                    self._splitTemporary(inst)
            elif opc == OpCode.CPUI_SUBPIECE:
                vn = defop.getIn(0)
                suboff = defop.getIn(1).getOffset()
                bigendian = vn.getSpace().isBigEndian()
                if bigendian:
                    if suboff == 0:
                        splitoff = vn.getSize() - defop.getOut().getSize()
                    else:
                        splitoff = vn.getSize() - int(suboff)
                else:
                    if suboff == 0:
                        splitoff = defop.getOut().getSize()
                    else:
                        splitoff = int(suboff)
                inst = PreferSplitManager.SplitInstance(vn, splitoff)
                if self._testTemporary(inst):
                    self._splitTemporary(inst)

    @staticmethod
    def initialize(records: list) -> None:
        """Initialize/sort the records list."""
        records.sort()
