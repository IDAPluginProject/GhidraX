"""
Corresponds to: varmap.hh / varmap.cc

Classes for tracking local variables and reconstructing stack layout.
"""

from __future__ import annotations
import bisect
from typing import List
from ghidra.core.address import Address, AddrSpace, calc_mask, sign_extend
from ghidra.core.opcodes import OpCode
from ghidra.core.marshal import AttributeId, ElementId
from ghidra.database.database import ScopeInternal

ATTRIB_LOCK = AttributeId("lock", 133)
ATTRIB_MAIN = AttributeId("main", 134)

ELEM_LOCALDB = ElementId("localdb", 228)


# =========================================================================
# NameRecommend
# =========================================================================

class NameRecommend:
    """A symbol name recommendation with its associated storage location."""

    def __init__(self, addr: Address, useaddr: Address, sz: int, nm: str, symbolId: int) -> None:
        self._addr: Address = addr
        self._useaddr: Address = useaddr
        self._size: int = sz
        self._name: str = nm
        self._symbolId: int = symbolId

    def getAddr(self) -> Address:
        return self._addr

    def getUseAddr(self) -> Address:
        return self._useaddr

    def getSize(self) -> int:
        return self._size

    def getName(self) -> str:
        return self._name

    def getSymbolId(self) -> int:
        return self._symbolId


# =========================================================================
# DynamicRecommend
# =========================================================================

class DynamicRecommend:
    """A name recommendation for a particular dynamic storage location."""

    def __init__(self, addr: Address, h: int, nm: str, symbolId: int) -> None:
        self._usePoint: Address = addr
        self._hash: int = h
        self._name: str = nm
        self._symbolId: int = symbolId

    def getAddress(self) -> Address:
        return self._usePoint

    def getHash(self) -> int:
        return self._hash

    def getName(self) -> str:
        return self._name

    def getSymbolId(self) -> int:
        return self._symbolId


# =========================================================================
# TypeRecommend
# =========================================================================

class TypeRecommend:
    """Data-type for a storage location when there is no Symbol (yet)."""

    def __init__(self, addr: Address, dt) -> None:
        self._addr: Address = addr
        self._dataType = dt

    def getAddress(self) -> Address:
        return self._addr

    def getType(self):
        return self._dataType


class RangeHint:
    """Partial data-type information mapped to a specific range of bytes."""

    # RangeType enum
    fixed = 0
    open = 1
    endpoint = 2

    # Boolean properties
    typelock = 1
    copy_constant = 2

    def __init__(self, st: int = 0, sz: int = 0, sst: int = 0,
                 ct=None, fl: int = 0, rt: int = 0, hi: int = 0) -> None:
        self.start: int = st
        self.size: int = sz
        self.sstart: int = sst
        self.type = ct
        self.flags: int = fl
        self.rangeType: int = rt
        self.highind: int = hi

    def isTypeLock(self) -> bool:
        return (self.flags & RangeHint.typelock) != 0

    def isConstAbsorbable(self, b: RangeHint) -> bool:
        if (b.flags & RangeHint.copy_constant) == 0:
            return False
        if b.isTypeLock():
            return False
        if b.size < self.size:
            return False
        meta = self.type.getMetatype()
        if meta not in ('int', 'uint', 'bool', 'float'):
            return False
        bMeta = b.type.getMetatype()
        if bMeta not in ('unknown', 'int', 'uint'):
            return False
        end = self.sstart
        if self.highind > 0:
            end += self.highind * self.type.getAlignSize()
        else:
            end += self.size
        if b.sstart > end:
            return False
        return True

    def reconcile(self, b: RangeHint) -> bool:
        a = self
        if a.type.getAlignSize() < b.type.getAlignSize():
            a, b = b, a
        mod = (b.sstart - a.sstart) % a.type.getAlignSize()
        if mod < 0:
            mod += a.type.getAlignSize()
        sub = a.type
        while sub is not None and sub.getAlignSize() > b.type.getAlignSize():
            sub = sub.getSubType(mod)
            if sub is not None:
                mod = mod  # getSubType may update mod in C++, simplified here
        if sub is not None:
            if sub.getAlignSize() == b.type.getAlignSize():
                return True
        if b.rangeType == RangeHint.open and b.isConstAbsorbable(a):
            return True
        if b.isTypeLock():
            return False
        meta = a.type.getMetatype()
        if meta not in ('struct', 'union'):
            if meta != 'array':
                return False
            if hasattr(a.type, 'getBase') and a.type.getBase().getMetatype() != 'unknown':
                return False
        bMeta = b.type.getMetatype()
        if bMeta in ('unknown', 'int', 'uint'):
            return True
        return False

    def contain(self, b: RangeHint) -> bool:
        if self.sstart == b.sstart:
            return True
        if b.sstart + b.size - 1 <= self.sstart + self.size - 1:
            return True
        return False

    def preferred(self, b: RangeHint, didReconcile: bool) -> bool:
        if self.start != b.start:
            return True
        if b.isTypeLock():
            if not self.isTypeLock():
                return False
        elif self.isTypeLock():
            return True
        if self.rangeType == RangeHint.open and b.rangeType != RangeHint.open:
            if not didReconcile:
                return False
            if self.isConstAbsorbable(b):
                return True
        elif b.rangeType == RangeHint.open and self.rangeType != RangeHint.open:
            if not didReconcile:
                return True
            if b.isConstAbsorbable(self):
                return False
        elif self.rangeType == RangeHint.fixed and b.rangeType == RangeHint.fixed:
            if self.size != b.size and not didReconcile:
                return self.size > b.size
        return 0 > self.type.typeOrder(b.type)

    def attemptJoin(self, b: RangeHint) -> bool:
        if self.rangeType != RangeHint.open:
            return False
        if b.rangeType == RangeHint.endpoint:
            return False
        if self.isConstAbsorbable(b):
            self.absorb(b)
            return True
        if self.highind < 0:
            return False
        settype = self.type
        if settype.getAlignSize() != b.type.getAlignSize():
            return False
        if settype != b.type:
            aTestType = self.type
            bTestType = b.type
            while aTestType.getMetatype() == 'ptr':
                if bTestType.getMetatype() != 'ptr':
                    break
                aTestType = aTestType.getPtrTo()
                bTestType = bTestType.getPtrTo()
            if aTestType.getMetatype() == 'unknown':
                settype = b.type
            elif bTestType.getMetatype() == 'unknown':
                pass
            elif aTestType.getMetatype() == 'int' and bTestType.getMetatype() == 'uint':
                pass
            elif aTestType.getMetatype() == 'uint' and bTestType.getMetatype() == 'int':
                pass
            elif aTestType != bTestType:
                return False
        if self.isTypeLock():
            return False
        if b.isTypeLock():
            return False
        diffsz = b.sstart - self.sstart
        if (diffsz % settype.getAlignSize()) != 0:
            return False
        diffsz //= settype.getAlignSize()
        if diffsz > self.highind:
            return False
        self.type = settype
        self.absorb(b)
        return True

    def absorb(self, b: RangeHint) -> None:
        if b.rangeType == RangeHint.open:
            if self.type.getAlignSize() == b.type.getAlignSize():
                self.rangeType = RangeHint.open
                if 0 <= b.highind:
                    diffsz = b.sstart - self.sstart
                    diffsz //= self.type.getAlignSize()
                    trialhi = b.highind + diffsz
                    if self.highind < trialhi:
                        self.highind = trialhi
            elif self.start == b.start:
                meta = self.type.getMetatype()
                if meta not in ('struct', 'union'):
                    self.rangeType = RangeHint.open
        elif (b.flags & RangeHint.copy_constant) != 0 and self.rangeType == RangeHint.open:
            diffsz = b.sstart - self.sstart + b.size
            if diffsz > self.size:
                trialhi = diffsz // self.type.getAlignSize()
                if self.highind < trialhi:
                    self.highind = trialhi
        if (self.flags & RangeHint.copy_constant) != 0 and (b.flags & RangeHint.copy_constant) == 0:
            self.flags ^= RangeHint.copy_constant

    def merge(self, b: RangeHint, space, typeFactory) -> bool:
        if self.contain(b):
            didReconcile = self.reconcile(b)
            if not didReconcile and self.start != b.start:
                resType = 2
            else:
                resType = 0 if self.preferred(b, didReconcile) else 1
        else:
            didReconcile = False
            resType = 0 if self.isTypeLock() else 2
        if not didReconcile:
            if self.isTypeLock():
                if b.isTypeLock():
                    raise RuntimeError("Overlapping forced variable types : " +
                                       self.type.getName() + "   " + b.type.getName())
                if self.start != b.start:
                    return False
        if resType == 0:
            self.absorb(b)
        elif resType == 1:
            copyType = self.type
            copyFlags = self.flags
            copyRangeType = self.rangeType
            copyHighind = self.highind
            copySize = self.size
            copySstart = self.sstart
            copyStart = self.start
            self.type = b.type
            self.flags = b.flags
            self.rangeType = b.rangeType
            self.highind = b.highind
            self.size = b.size
            tmpHint = RangeHint(copyStart, copySize, copySstart, copyType, copyFlags, copyRangeType, copyHighind)
            self.absorb(tmpHint)
        elif resType == 2:
            self.flags = 0
            self.rangeType = RangeHint.fixed
            diff = b.sstart - self.sstart
            if diff + b.size > self.size:
                self.size = diff + b.size
            if self.size not in (1, 2, 4, 8):
                self.size = 1
                self.rangeType = RangeHint.open
            self.type = typeFactory.getBase(self.size, 'unknown')
            self.flags = 0
            self.highind = -1
            return False
        return False

    def compare(self, op2: RangeHint) -> int:
        if self.sstart != op2.sstart:
            return -1 if self.sstart < op2.sstart else 1
        if self.size != op2.size:
            return -1 if self.size < op2.size else 1
        if self.rangeType != op2.rangeType:
            return -1 if self.rangeType < op2.rangeType else 1
        if self.flags != op2.flags:
            return -1 if self.flags < op2.flags else 1
        if self.highind != op2.highind:
            return -1 if self.highind < op2.highind else 1
        return 0

    @staticmethod
    def compareRanges(a: RangeHint, b: RangeHint) -> bool:
        return a.compare(b) < 0


# =========================================================================
# AliasChecker
# =========================================================================

class AliasChecker:
    """A light-weight class for analyzing pointers and aliasing on the stack."""

    class AddBase:
        """A helper class holding a Varnode pointer reference and a possible index."""

        def __init__(self, base, index=None) -> None:
            self.base = base
            self.index = index

    def __init__(self) -> None:
        self._fd = None
        self._space = None
        self._addBase: List[AliasChecker.AddBase] = []
        self._alias: List[int] = []
        self._calculated: bool = False
        self._localExtreme: int = 0
        self._localBoundary: int = 0
        self._aliasBoundary: int = 0
        self._direction: int = 1

    def _deriveBoundaries(self, proto) -> None:
        self._localExtreme = 0xFFFFFFFFFFFFFFFF
        self._localBoundary = 0x1000000
        if self._direction == -1:
            self._localExtreme = self._localBoundary
        if proto.hasModel():
            localrange = proto.getLocalRange()
            paramrange = proto.getParamRange()
            local = localrange.getFirstRange()
            param = paramrange.getLastRange()
            if local is not None and param is not None:
                self._localBoundary = param.getLast()
                if self._direction == -1:
                    self._localBoundary = paramrange.getFirstRange().getFirst()
                    self._localExtreme = self._localBoundary

    def _gatherInternal(self) -> None:
        self._calculated = True
        self._aliasBoundary = self._localExtreme
        spacebase = self._fd.findSpacebaseInput(self._space)
        if spacebase is None:
            return
        AliasChecker.gatherAdditiveBase(spacebase, self._addBase)
        for ab in self._addBase:
            offset = AliasChecker.gatherOffset(ab.base)
            offset = AddrSpace.addressToByte(offset, self._space.getWordSize())
            self._alias.append(offset)
            if self._direction == 1:
                if offset < self._localBoundary:
                    continue
            else:
                if offset > self._localBoundary:
                    continue
            if offset < self._aliasBoundary:
                self._aliasBoundary = offset

    def gather(self, f, spc, defer: bool) -> None:
        self._fd = f
        self._space = spc
        self._calculated = False
        self._addBase.clear()
        self._alias.clear()
        self._direction = 1 if spc.stackGrowsNegative() else -1
        self._deriveBoundaries(f.getFuncProto())
        if not defer:
            self._gatherInternal()

    def hasLocalAlias(self, vn) -> bool:
        if vn is None:
            return False
        if not self._calculated:
            self._gatherInternal()
        if vn.getSpace() != self._space:
            return False
        if self._direction == -1:
            return False
        return vn.getOffset() >= self._aliasBoundary

    def sortAlias(self) -> None:
        self._alias.sort()

    def getAddBase(self) -> List[AliasChecker.AddBase]:
        return self._addBase

    def getAlias(self) -> List[int]:
        return self._alias

    @staticmethod
    def gatherAdditiveBase(startvn, addbase: list) -> None:
        vnqueue: List[AliasChecker.AddBase] = []
        vn = startvn
        vn.setMark()
        vnqueue.append(AliasChecker.AddBase(vn, None))
        i = 0
        while i < len(vnqueue):
            vn = vnqueue[i].base
            indexvn = vnqueue[i].index
            i += 1
            nonadduse = False
            for op in vn.getDescendants():
                opc = op.code()
                if opc == OpCode.CPUI_COPY:
                    nonadduse = True
                    subvn = op.getOut()
                    if not subvn.isMark():
                        subvn.setMark()
                        vnqueue.append(AliasChecker.AddBase(subvn, indexvn))
                elif opc == OpCode.CPUI_INT_SUB:
                    if vn == op.getIn(1):
                        nonadduse = True
                        continue
                    othervn = op.getIn(1)
                    if not othervn.isConstant():
                        indexvn = othervn
                    subvn = op.getOut()
                    if not subvn.isMark():
                        subvn.setMark()
                        vnqueue.append(AliasChecker.AddBase(subvn, indexvn))
                elif opc in (OpCode.CPUI_INT_ADD, OpCode.CPUI_PTRADD):
                    othervn = op.getIn(1)
                    if othervn == vn:
                        othervn = op.getIn(0)
                    if not othervn.isConstant():
                        indexvn = othervn
                    subvn = op.getOut()
                    if not subvn.isMark():
                        subvn.setMark()
                        vnqueue.append(AliasChecker.AddBase(subvn, indexvn))
                elif opc in (OpCode.CPUI_PTRSUB, OpCode.CPUI_SEGMENTOP):
                    subvn = op.getOut()
                    if not subvn.isMark():
                        subvn.setMark()
                        vnqueue.append(AliasChecker.AddBase(subvn, indexvn))
                else:
                    nonadduse = True
            if nonadduse:
                addbase.append(AliasChecker.AddBase(vn, indexvn))
        for j in range(len(vnqueue)):
            vnqueue[j].base.clearMark()

    @staticmethod
    def gatherOffset(vn) -> int:
        if vn.isConstant():
            return vn.getOffset()
        defop = vn.getDef()
        if defop is None:
            return 0
        opc = defop.code()
        if opc == OpCode.CPUI_COPY:
            retval = AliasChecker.gatherOffset(defop.getIn(0))
        elif opc in (OpCode.CPUI_PTRSUB, OpCode.CPUI_INT_ADD):
            retval = AliasChecker.gatherOffset(defop.getIn(0))
            retval += AliasChecker.gatherOffset(defop.getIn(1))
        elif opc == OpCode.CPUI_INT_SUB:
            retval = AliasChecker.gatherOffset(defop.getIn(0))
            retval -= AliasChecker.gatherOffset(defop.getIn(1))
        elif opc == OpCode.CPUI_PTRADD:
            othervn = defop.getIn(2)
            retval = AliasChecker.gatherOffset(defop.getIn(0))
            if defop.getIn(1).isConstant():
                retval = retval + defop.getIn(1).getOffset() * othervn.getOffset()
            elif othervn.getOffset() == 1:
                retval = retval + AliasChecker.gatherOffset(defop.getIn(1))
        elif opc == OpCode.CPUI_SEGMENTOP:
            retval = AliasChecker.gatherOffset(defop.getIn(2))
        else:
            retval = 0
        return retval & calc_mask(vn.getSize())


# =========================================================================
# MapState
# =========================================================================

class MapState:
    """A container for hints about the data-type layout of an address space."""

    def __init__(self, spc, rn, pm, dt) -> None:
        self._spaceid = spc
        self._range = rn
        self._maplist: List[RangeHint] = []
        self._iter: int = 0
        self._defaultType = dt
        self._checker: AliasChecker = AliasChecker()
        # Remove parameter ranges from the analysis range
        if pm is not None:
            for r in pm:
                pmSpc = r.getSpace()
                first = r.getFirst()
                last = r.getLast()
                self._range.removeRange(pmSpc, first, last)

    def _addGuard(self, guard, opc, typeFactory) -> None:
        if not guard.isValid(opc):
            return
        step = guard.getStep()
        if step == 0:
            return
        ct = guard.getOp().getIn(1).getTypeReadFacing(guard.getOp())
        if ct.getMetatype() == 'ptr':
            ct = ct.getPtrTo()
            while ct.getMetatype() == 'array':
                ct = ct.getBase()
        if opc == OpCode.CPUI_STORE:
            outSize = guard.getOp().getIn(2).getSize()
        else:
            outSize = guard.getOp().getOut().getSize()
        if outSize != step:
            if outSize > step or (step % outSize) != 0:
                return
            step = outSize
        if ct.getAlignSize() != step:
            if step > 8:
                return
            ct = typeFactory.getBase(step, 'unknown')
        if guard.isRangeLocked():
            minItems = ((guard.getMaximum() - guard.getMinimum()) + 1) // step
            self.addRange(guard.getMinimum(), ct, 0, RangeHint.open, minItems - 1)
        else:
            self.addRange(guard.getMinimum(), ct, 0, RangeHint.open, 3)

    def addRange(self, st: int, ct, fl: int, rt: int, hi: int) -> None:
        if ct is None or ct.getSize() == 0:
            ct = self._defaultType
        sz = ct.getSize()
        if not self._range.inRange(Address(self._spaceid, st), sz):
            return
        sst = AddrSpace.byteToAddress(st, self._spaceid.getWordSize())
        sst = sign_extend(sst, self._spaceid.getAddrSize() * 8 - 1)
        sst = AddrSpace.addressToByte(sst, self._spaceid.getWordSize())
        newRange = RangeHint(st, sz, sst, ct, fl, rt, hi)
        self._maplist.append(newRange)

    def _addFixedType(self, start: int, ct, flags: int, types) -> None:
        if ct is None:
            return
        if ct.getMetatype() == 'partialstruct':
            parent = ct.getParent()
            if parent.getMetatype() == 'struct' and ct.getOffset() == 0:
                self.addRange(start, parent, 0, RangeHint.open, -1)
            elif parent.getMetatype() == 'array':
                base = parent.getBase()
                if base.getMetatype() != 'unknown':
                    self.addRange(start, base, 0, RangeHint.open, -1)
            if flags != 0:
                unkType = types.getBase(ct.getSize(), 'unknown')
                self.addRange(start, unkType, flags, RangeHint.fixed, -1)
        elif ct.getMetatype() == 'partialunion':
            if ct.getOffset() == 0:
                self.addRange(start, ct.getParentUnion(), 0, RangeHint.open, -1)
        else:
            self.addRange(start, ct, flags, RangeHint.fixed, -1)

    def _reconcileDatatypes(self) -> None:
        newList: List[RangeHint] = []
        startPos = 0
        startHint = self._maplist[0]
        startDatatype = startHint.type
        newList.append(startHint)
        curPos = 1
        while curPos < len(self._maplist):
            curHint = self._maplist[curPos]
            curPos += 1
            if (curHint.start == startHint.start and curHint.size == startHint.size
                    and curHint.flags == startHint.flags):
                curDatatype = curHint.type
                if curDatatype.typeOrder(startDatatype) < 0:
                    startDatatype = curDatatype
                if curHint.compare(newList[-1]) != 0:
                    newList.append(curHint)
            else:
                while startPos < len(newList):
                    newList[startPos].type = startDatatype
                    startPos += 1
                startHint = curHint
                startDatatype = startHint.type
                newList.append(startHint)
        while startPos < len(newList):
            newList[startPos].type = startDatatype
            startPos += 1
        self._maplist = newList

    def initialize(self) -> bool:
        lastrange = self._range.getLastSignedRange(self._spaceid)
        if lastrange is None:
            return False
        if not self._maplist:
            return False
        high = self._spaceid.wrapOffset(lastrange.getLast() + 1)
        sst = AddrSpace.byteToAddress(high, self._spaceid.getWordSize())
        sst = sign_extend(sst, self._spaceid.getAddrSize() * 8 - 1)
        sst = AddrSpace.addressToByte(sst, self._spaceid.getWordSize())
        termRange = RangeHint(high, 1, sst, self._defaultType, 0, RangeHint.endpoint, -2)
        self._maplist.append(termRange)
        self._maplist.sort(key=lambda a: (a.sstart, a.size, a.rangeType, a.flags, a.highind))
        self._reconcileDatatypes()
        self._iter = 0
        return True

    def sortAlias(self) -> None:
        self._checker.sortAlias()

    def getAlias(self) -> List[int]:
        return self._checker.getAlias()

    def gatherSymbols(self, rangemap) -> None:
        if rangemap is None:
            return
        for entry in rangemap:
            sym = entry.getSymbol()
            if sym is None:
                continue
            start = entry.getAddr().getOffset()
            ct = sym.getType()
            fl = RangeHint.typelock if sym.isTypeLocked() else 0
            self.addRange(start, ct, fl, RangeHint.fixed, -1)

    def gatherVarnodes(self, fd) -> None:
        types = fd.getArch().types
        for vn in fd.iterLocVarnodes(self._spaceid):
            if vn.isFree():
                continue
            if not vn.isWritten():
                if MapState._isReadActive(vn):
                    self._addFixedType(vn.getOffset(), vn.getType(), 0, types)
                continue
            op = vn.getDef()
            opc = op.code()
            if opc == OpCode.CPUI_INDIRECT:
                invn = op.getIn(0)
                if vn.getAddr() != invn.getAddr() or MapState._isReadActive(vn):
                    self._addFixedType(vn.getOffset(), vn.getType(), 0, types)
            elif opc == OpCode.CPUI_MULTIEQUAL:
                found = False
                for i in range(op.numInput()):
                    invn = op.getIn(i)
                    if vn.getAddr() != invn.getAddr():
                        found = True
                        break
                if found or MapState._isReadActive(vn):
                    self._addFixedType(vn.getOffset(), vn.getType(), 0, types)
            elif opc == OpCode.CPUI_PIECE:
                addr = vn.getAddr()
                slot = 0 if addr.isBigEndian() else 1
                inFirst = op.getIn(slot)
                if inFirst.getAddr() != addr:
                    self._addFixedType(addr.getOffset(), inFirst.getType(), 0, types)
                addr2 = addr + inFirst.getSize()
                inSecond = op.getIn(1 - slot)
                if inSecond.getAddr() != addr2:
                    self._addFixedType(addr2.getOffset(), inSecond.getType(), 0, types)
                if MapState._isReadActive(vn):
                    self._addFixedType(vn.getOffset(), vn.getType(), 0, types)
            elif opc == OpCode.CPUI_SUBPIECE:
                addr = op.getIn(0).getAddr()
                if addr.isBigEndian():
                    trunc = op.getIn(0).getSize() - vn.getSize() - op.getIn(1).getOffset()
                else:
                    trunc = op.getIn(1).getOffset()
                addr2 = addr + trunc
                if addr2 != vn.getAddr() or MapState._isReadActive(vn):
                    self._addFixedType(vn.getOffset(), vn.getType(), 0, types)
            elif opc == OpCode.CPUI_COPY:
                fl = RangeHint.copy_constant if op.getIn(0).isConstant() else 0
                self._addFixedType(vn.getOffset(), vn.getType(), fl, types)
            else:
                self._addFixedType(vn.getOffset(), vn.getType(), 0, types)

    def gatherOpen(self, fd) -> None:
        self._checker.gather(fd, self._spaceid, False)
        addbase = self._checker.getAddBase()
        alias = self._checker.getAlias()
        for i in range(len(addbase)):
            offset = alias[i]
            ct = addbase[i].base.getType()
            if ct is not None and ct.getMetatype() == 'ptr':
                ct = ct.getPtrTo()
                while ct.getMetatype() == 'array':
                    ct = ct.getBase()
            else:
                ct = None
            if addbase[i].index is not None:
                minItems = 3
            else:
                minItems = -1
            self.addRange(offset, ct, 0, RangeHint.open, minItems)
        typeFactory = fd.getArch().types
        for guard in fd.getLoadGuards():
            self._addGuard(guard, OpCode.CPUI_LOAD, typeFactory)
        for guard in fd.getStoreGuards():
            self._addGuard(guard, OpCode.CPUI_STORE, typeFactory)

    def next(self) -> RangeHint:
        return self._maplist[self._iter]

    def getNext(self) -> bool:
        self._iter += 1
        return self._iter < len(self._maplist)

    @staticmethod
    def _isReadActive(vn) -> bool:
        for op in vn.getDescendants():
            if op.isMarker():
                if vn.getAddr() != op.getOut().getAddr():
                    return True
            else:
                opc = op.code()
                if opc == OpCode.CPUI_PIECE:
                    addr = op.getOut().getAddr()
                    slot = 0 if addr.isBigEndian() else 1
                    if op.getIn(slot) != vn:
                        addr = addr + op.getIn(slot).getSize()
                    if vn.getAddr() != addr:
                        return True
                elif opc == OpCode.CPUI_SUBPIECE:
                    pass
                else:
                    return True
        return False


# =========================================================================
# ScopeLocal
# =========================================================================

class ScopeLocal(ScopeInternal):
    """A Symbol scope for local variables of a particular function.

    This acts like any other variable Scope, but is associated with a specific
    function and the address space where the function maps its local variables
    and parameters, typically the stack space.
    """

    def __init__(self, idval: int, spc, fd, g) -> None:
        nm = fd.getName() if fd is not None else "local"
        super().__init__(idval, nm, g)
        self._space = spc
        self._fd = fd
        self._nameRecommend: List[NameRecommend] = []
        self._dynRecommend: List[DynamicRecommend] = []
        self._typeRecommend: List[TypeRecommend] = []
        self._minParamOffset: int = 0xFFFFFFFFFFFFFFFF
        self._maxParamOffset: int = 0
        self._stackGrowsNegative: bool = True
        self._rangeLocked: bool = False
        self._overlapProblems: bool = False
        self.restrictScope(fd)

    def getSpaceId(self):
        return self._space

    def hasOverlapProbems(self) -> bool:
        return self._overlapProblems

    def isUnaffectedStorage(self, vn) -> bool:
        return vn.getSpace() == self._space

    def isUnmappedUnaliased(self, vn) -> bool:
        if vn.getSpace() != self._space:
            return False
        if self._maxParamOffset < self._minParamOffset:
            return True
        if vn.getOffset() < self._minParamOffset or vn.getOffset() > self._maxParamOffset:
            return True
        return False

    def markNotMapped(self, spc, first: int, sz: int, parameter: bool) -> None:
        if self._space != spc:
            return
        last = first + sz - 1
        if last < first:
            last = spc.getHighest()
        elif last > spc.getHighest():
            last = spc.getHighest()
        if parameter:
            if first < self._minParamOffset:
                self._minParamOffset = first
            if last > self._maxParamOffset:
                self._maxParamOffset = last
        addr = Address(self._space, first)
        overlap = self.findOverlap(addr, sz)
        while overlap is not None:
            sym = overlap.getSymbol()
            if sym.isTypeLocked():
                if not parameter or sym.getCategory() != sym.function_parameter:
                    self._fd.warningHeader("Variable defined which should be unmapped: " + sym.getName())
                return
            elif sym.getCategory() == sym.fake_input:
                return
            self.removeSymbol(sym)
            overlap = self.findOverlap(addr, sz)
        self.glb.symboltab.removeRange(self, self._space, first, last)

    def encode(self, encoder) -> None:
        encoder.openElement(ELEM_LOCALDB)
        encoder.writeSpace(ATTRIB_MAIN, self._space)
        encoder.writeBool(ATTRIB_LOCK, self._rangeLocked)
        super().encode(encoder)
        encoder.closeElement(ELEM_LOCALDB)

    def decode(self, decoder) -> None:
        super().decode(decoder)
        self._collectNameRecs()

    def decodeWrappingAttributes(self, decoder) -> None:
        self._rangeLocked = False
        if decoder.readBool(ATTRIB_LOCK):
            self._rangeLocked = True
        self._space = decoder.readSpace(ATTRIB_MAIN)

    def buildVariableName(self, addr, pc, ct, index: int, flags: int) -> str:
        from ghidra.ir.varnode import Varnode as VN
        if ((flags & (VN.addrtied | VN.persist)) == VN.addrtied
                and addr.getSpace() == self._space):
            if self._fd.getFuncProto().getLocalRange().inRange(addr, 1):
                start = AddrSpace.byteToAddress(addr.getOffset(), self._space.getWordSize())
                start = sign_extend(start, addr.getAddrSize() * 8 - 1)
                if self._stackGrowsNegative:
                    start = -start
                buf = []
                if ct is not None and hasattr(ct, 'printNameBase'):
                    ct.printNameBase(buf)
                s = "".join(buf)
                spacename = addr.getSpace().getName()
                spacename = spacename[0].upper() + spacename[1:]
                s += spacename
                if start <= 0:
                    s += 'X'
                    start = -start
                else:
                    if (self._minParamOffset < self._maxParamOffset and
                            (self._stackGrowsNegative and addr.getOffset() < self._minParamOffset or
                             not self._stackGrowsNegative and addr.getOffset() > self._maxParamOffset)):
                        s += 'Y'
                s += '_' + format(start, 'x')
                return self.makeNameUnique(s)
        return super().buildVariableName(addr, pc, ct, index, flags)

    def resetLocalWindow(self) -> None:
        self._stackGrowsNegative = self._fd.getFuncProto().isStackGrowsNegative()
        self._minParamOffset = 0xFFFFFFFFFFFFFFFF
        self._maxParamOffset = 0
        if self._rangeLocked:
            return
        localRange = self._fd.getFuncProto().getLocalRange()
        paramrange = self._fd.getFuncProto().getParamRange()
        from ghidra.core.address import RangeList
        newrange = RangeList()
        for r in localRange:
            newrange.insertRange(r.getSpace(), r.getFirst(), r.getLast())
        for r in paramrange:
            newrange.insertRange(r.getSpace(), r.getFirst(), r.getLast())
        symboltab = getattr(self.glb, 'symboltab', None)
        if symboltab is not None and hasattr(symboltab, 'setRange'):
            symboltab.setRange(self, newrange)

    def restructureVarnode(self, aliasyes: bool) -> None:
        self.clearUnlockedCategory(-1)
        state = MapState(self._space, self.getRangeTree(),
                         self._fd.getFuncProto().getParamRange(),
                         self.glb.types.getBase(1, 'unknown'))
        state.gatherVarnodes(self._fd)
        state.gatherOpen(self._fd)
        state.gatherSymbols(self._getMapTable(self._space))
        self._overlapProblems = self._restructure(state)
        self.clearUnlockedCategory(0)  # Symbol.function_parameter = 0
        self.clearCategory(-2)  # Symbol.fake_input
        self._fakeInputSymbols()
        state.sortAlias()
        if aliasyes:
            self._markUnaliased(state.getAlias())
            self._checkUnaliasedReturn(state.getAlias())
        if state.getAlias() and state.getAlias()[0] == 0:
            self._annotateRawStackPtr()

    def _restructure(self, state: MapState) -> bool:
        overlapProblems = False
        if not state.initialize():
            return overlapProblems
        cur = RangeHint()
        cur.__dict__.update(state.next().__dict__)
        while state.getNext():
            nxt = state.next()
            if nxt.sstart < cur.sstart + cur.size:
                if cur.merge(nxt, self._space, self.glb.types):
                    overlapProblems = True
            else:
                if not cur.attemptJoin(nxt):
                    if cur.rangeType == RangeHint.open:
                        cur.size = nxt.sstart - cur.sstart
                    if self._adjustFit(cur):
                        self._createEntry(cur)
                    cur = RangeHint()
                    cur.__dict__.update(nxt.__dict__)
        return overlapProblems

    def _adjustFit(self, a: RangeHint) -> bool:
        if a.size == 0:
            return False
        if a.isTypeLock():
            return False
        addr = Address(self._space, a.start)
        maxsize = self.getRangeTree().longestFit(addr, a.size)
        if maxsize == 0:
            return False
        if maxsize < a.size:
            if maxsize < a.type.getSize():
                return False
            a.size = maxsize
        entry = self.findOverlap(addr, a.size)
        if entry is None:
            return True
        if entry.getAddr() <= addr:
            return False
        maxsize = entry.getAddr().getOffset() - a.start
        if maxsize < a.type.getSize():
            return False
        a.size = maxsize
        return True

    def _createEntry(self, a: RangeHint) -> None:
        addr = Address(self._space, a.start)
        usepoint = Address()
        ct = self.glb.types.concretize(a.type)
        num = a.size // ct.getAlignSize()
        if num > 1:
            ct = self.glb.types.getTypeArray(num, ct)
        self.addSymbol("", ct, addr, usepoint)

    def _collectNameRecs(self) -> None:
        self._nameRecommend.clear()
        self._dynRecommend.clear()
        for sym in list(self.iterSymbols()):
            if sym.isNameLocked() and not sym.isTypeLocked():
                if sym.isThisPointer():
                    dt = sym.getType()
                    if dt.getMetatype() == 'ptr':
                        if dt.getPtrTo().getMetatype() == 'struct':
                            entry = sym.getFirstWholeMap()
                            self.addTypeRecommendation(entry.getAddr(), dt)
                self._addRecommendName(sym)

    def _addRecommendName(self, sym) -> None:
        entry = sym.getFirstWholeMap()
        if entry is None:
            return
        if entry.isDynamic():
            self._dynRecommend.append(
                DynamicRecommend(entry.getFirstUseAddress(), entry.getHash(), sym.getName(), sym.getId()))
        else:
            usepoint = Address()
            if not entry.getUseLimit().empty():
                r = entry.getUseLimit().getFirstRange()
                usepoint = Address(r.getSpace(), r.getFirst())
            self._nameRecommend.append(
                NameRecommend(entry.getAddr(), usepoint, entry.getSize(), sym.getName(), sym.getId()))
        if sym.getCategory() < 0:
            self.removeSymbol(sym)

    def _annotateRawStackPtr(self) -> None:
        if not self._fd.hasTypeRecoveryStarted():
            return
        spVn = self._fd.findSpacebaseInput(self._space)
        if spVn is None:
            return
        refOps = []
        for op in spVn.getDescendants():
            if op.getEvalType() == 0 and not op.isCall():  # PcodeOp.special
                continue
            opc = op.code()
            if opc in (OpCode.CPUI_INT_ADD, OpCode.CPUI_PTRSUB, OpCode.CPUI_PTRADD):
                continue
            refOps.append(op)
        for op in refOps:
            slot = op.getSlot(spVn)
            ptrsub = self._fd.newOpBefore(op, OpCode.CPUI_PTRSUB, spVn,
                                          self._fd.newConstant(spVn.getSize(), 0))
            self._fd.opSetInput(op, ptrsub.getOut(), slot)

    def _checkUnaliasedReturn(self, alias: List[int]) -> None:
        retOp = self._fd.getFirstReturnOp()
        if retOp is None or retOp.numInput() < 2:
            return
        vn = retOp.getIn(1)
        if vn.getSpace() != self._space:
            return
        idx = bisect.bisect_left(alias, vn.getOffset())
        if idx < len(alias):
            if alias[idx] <= vn.getOffset() + vn.getSize() - 1:
                return
        self.markNotMapped(self._space, vn.getOffset(), vn.getSize(), False)

    def _markUnaliased(self, alias: List[int]) -> None:
        from ghidra.ir.varnode import Varnode
        from ghidra.types.datatype import TYPE_ARRAY, TYPE_STRUCT

        rangemap = self._getMapTable(self._space)
        if rangemap is None:
            return
        ranges = []
        try:
            ranges = list(self.getRangeTree())
        except Exception:
            ranges = []
        range_index = 0
        alias_block_level = self.glb.alias_block_level
        aliason = False
        curalias = 0
        i = 0
        for entry in rangemap:
            curoff = entry.getAddr().getOffset() + entry.getSize() - 1
            while i < len(alias) and alias[i] <= curoff:
                aliason = True
                curalias = alias[i]
                i += 1
            # Aliases should not propagate across unmapped local ranges.
            while range_index < len(ranges):
                rng = ranges[range_index]
                if rng.getSpace() == self._space:
                    if rng.getFirst() > curalias and curoff >= rng.getFirst():
                        aliason = False
                    if rng.getLast() >= curoff:
                        break
                    if rng.getLast() > curalias:
                        aliason = False
                range_index += 1
            symbol = entry.getSymbol()
            if aliason and (curoff - curalias > 0xffff):
                aliason = False
            if not aliason:
                symbol.getScope().setAttribute(symbol, Varnode.nolocalalias)
            if symbol.isTypeLocked() and alias_block_level != 0:
                if alias_block_level == 3:
                    aliason = False
                else:
                    symbol_type = symbol.getType()
                    meta = symbol_type.getMetatype() if symbol_type is not None else None
                    if meta == TYPE_STRUCT:
                        aliason = False
                    elif meta == TYPE_ARRAY and alias_block_level > 1:
                        aliason = False

    def _fakeInputSymbols(self) -> None:
        lockedinputs = self.getCategorySize(0)  # Symbol.function_parameter
        for vn in self._fd.iterDefVarnodes(0x1):  # Varnode.input
            locked = vn.isTypeLock()
            addr = vn.getAddr()
            if addr.getSpace() != self._space:
                continue
            if not self._fd.getFuncProto().getParamRange().inRange(addr, 1):
                continue
            endpoint = addr.getOffset() + vn.getSize() - 1
            if not locked:
                usepoint = Address()
                if lockedinputs != 0:
                    vflags = [0]
                    entry = self.queryProperties(vn.getAddr(), vn.getSize(), usepoint, vflags)
                    if entry is not None:
                        if entry.getSymbol().getCategory() == 0:  # function_parameter
                            continue
                size = endpoint - addr.getOffset() + 1
                ct = self._fd.getArch().types.getBase(size, 'unknown')
                try:
                    sym = self.addSymbol("", ct, addr, usepoint).getSymbol()
                    self.setCategory(sym, -2, -1)  # Symbol.fake_input
                except RuntimeError as err:
                    self._fd.warningHeader(str(err))

    def remapSymbol(self, sym, addr, usepoint):
        entry = sym.getFirstWholeMap()
        size = entry.getSize()
        if not entry.isDynamic():
            if entry.getAddr() == addr:
                if usepoint.isInvalid() and entry.getFirstUseAddress().isInvalid():
                    return entry
                if entry.getFirstUseAddress() == usepoint:
                    return entry
        self.removeSymbolMappings(sym)
        from ghidra.core.address import RangeList
        rnglist = RangeList()
        if not usepoint.isInvalid():
            rnglist.insertRange(usepoint.getSpace(), usepoint.getOffset(), usepoint.getOffset())
        return self.addMapInternal(sym, 0x8, addr, 0, size, rnglist)  # Varnode.mapped

    def remapSymbolDynamic(self, sym, hashval: int, usepoint):
        entry = sym.getFirstWholeMap()
        size = entry.getSize()
        if entry.isDynamic():
            if entry.getHash() == hashval and entry.getFirstUseAddress() == usepoint:
                return entry
        self.removeSymbolMappings(sym)
        from ghidra.core.address import RangeList
        rnglist = RangeList()
        if not usepoint.isInvalid():
            rnglist.insertRange(usepoint.getSpace(), usepoint.getOffset(), usepoint.getOffset())
        return self.addDynamicMapInternal(sym, 0x8, hashval, 0, size, rnglist)  # Varnode.mapped

    def recoverNameRecommendationsForSymbols(self) -> None:
        param_usepoint = self._fd.getAddress() - 1
        for rec in self._nameRecommend:
            addr = rec.getAddr()
            usepoint = rec.getUseAddr()
            size = rec.getSize()
            vn = None
            if usepoint.isInvalid():
                entry = self.findOverlap(addr, size)
                if entry is None:
                    continue
                if entry.getAddr() != addr:
                    continue
                sym = entry.getSymbol()
                if not sym.isAddrTied():
                    continue
                vn = self._fd.findLinkedVarnode(entry)
            else:
                if usepoint == param_usepoint:
                    vn = self._fd.findVarnodeInput(size, addr)
                else:
                    vn = self._fd.findVarnodeWritten(size, addr, usepoint)
                if vn is None:
                    continue
                sym = vn.getHigh().getSymbol()
                if sym is None:
                    continue
                if sym.isAddrTied():
                    continue
                entry = sym.getFirstWholeMap()
                if entry.getSize() != size:
                    continue
            if not sym.isNameUndefined():
                continue
            self.renameSymbol(sym, self.makeNameUnique(rec.getName()))
            self.setSymbolId(sym, rec.getSymbolId())
            self.setAttribute(sym, 0x80)  # Varnode.namelock
            if vn is not None:
                self._fd.remapVarnode(vn, sym, usepoint)
        if not self._dynRecommend:
            return
        for dynEntry in self._dynRecommend:
            vn = self._fd.findDynamicVarnode(dynEntry.getAddress(), dynEntry.getHash())
            if vn is None:
                continue
            if vn.isAnnotation():
                continue
            sym = vn.getHigh().getSymbol()
            if sym is None:
                continue
            if sym.getScope() != self:
                continue
            if not sym.isNameUndefined():
                continue
            self.renameSymbol(sym, self.makeNameUnique(dynEntry.getName()))
            self.setAttribute(sym, 0x80)  # Varnode.namelock
            self.setSymbolId(sym, dynEntry.getSymbolId())
            self._fd.remapDynamicVarnode(vn, sym, dynEntry.getAddress(), dynEntry.getHash())

    def applyTypeRecommendations(self) -> None:
        for rec in self._typeRecommend:
            dt = rec.getType()
            vn = self._fd.findVarnodeInput(dt.getSize(), rec.getAddress())
            if vn is not None:
                vn.updateType(dt, True, False)

    def hasTypeRecommendations(self) -> bool:
        return len(self._typeRecommend) > 0

    def addTypeRecommendation(self, addr, dt) -> None:
        self._typeRecommend.append(TypeRecommend(addr, dt))

    def _getMapTable(self, spc):
        """Get the map table for the given space (helper)."""
        if hasattr(self, 'maptable') and spc is not None:
            idx = spc.getIndex()
            if idx < len(self.maptable):
                return self.maptable[idx]
        return None
