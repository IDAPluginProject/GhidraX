"""
Corresponds to: constseq.hh / constseq.cc

Constant sequence detection — identifies sequences of STORE operations
that write constant values to consecutive memory locations, which can
be combined into string or array initializations.
"""

from __future__ import annotations
from typing import List
from ghidra.core.opcodes import OpCode
from ghidra.core.address import Address


class WriteNode:
    """Helper class holding a data-flow edge and optionally a memory offset being COPYed."""
    def __init__(self, offset: int = 0, op=None, slot: int = 0):
        self.offset: int = offset
        self.op = op
        self.slot: int = slot

    def __lt__(self, other):
        if self.op is None or other.op is None:
            return False
        return self.op.getSeqNum().getOrder() < other.op.getSeqNum().getOrder()


class ArraySequence:
    """A sequence of PcodeOps that move data in-to/out-of an array data-type.

    Given a starting address and set of COPY/STORE ops, collects a maximal set
    that can be replaced with a single memcpy style user-op.
    """
    MINIMUM_SEQUENCE_LENGTH = 4
    MAXIMUM_SEQUENCE_LENGTH = 0x20000

    def __init__(self, fd=None, ct=None, root=None) -> None:
        self._fd = fd
        self.rootOp = root
        self.charType = ct
        self.block = None
        self.numElements: int = 0
        self.moveOps: List[WriteNode] = []
        self.byteArray: List[int] = []

    def isValid(self) -> bool:
        return self.numElements != 0

    def getSize(self) -> int:
        return self.numElements

    def getCharType(self):
        return self.charType

    def getRootOp(self):
        return self.rootOp

    def getBlock(self):
        return self.block

    def setBlock(self, bl) -> None:
        self.block = bl

    def getMoveOps(self) -> List[WriteNode]:
        return self.moveOps

    @staticmethod
    def interfereBetween(startOp, endOp) -> bool:
        """Check for interfering ops between two given ops.

        Only LOADs, STOREs, and CALLs can really interfere. INDIRECT, CALLOTHER,
        SEGMENTOP, CPOOLREF, and NEW are considered non-interfering special ops.
        Returns True if there is NO interference, False if there IS interference.
        """
        cur = startOp.nextOp() if hasattr(startOp, 'nextOp') else None
        while cur is not None and cur != endOp:
            evaltype = cur.getEvalType() if hasattr(cur, 'getEvalType') else 0
            # PcodeOp::special == 2 in C++
            if evaltype == 2:
                opc = cur.code()
                if (opc != OpCode.CPUI_INDIRECT and opc != OpCode.CPUI_CALLOTHER and
                        opc != OpCode.CPUI_SEGMENTOP and opc != OpCode.CPUI_CPOOLREF and
                        opc != OpCode.CPUI_NEW):
                    return False
            cur = cur.nextOp() if hasattr(cur, 'nextOp') else None
        return True

    def checkInterference(self) -> bool:
        """Find maximal set of ops containing the root with no interfering ops in between.

        Sort ops by block order. Walk backward from root until interference, then
        walk forward. Truncate to the maximal contiguous non-interfering subset.
        """
        self.moveOps.sort()
        pos = -1
        for i in range(len(self.moveOps)):
            if self.moveOps[i].op == self.rootOp:
                pos = i
                break
        if pos < 0:
            return False
        curOp = self.moveOps[pos].op
        startingPos = pos - 1
        while startingPos >= 0:
            prevOp = self.moveOps[startingPos].op
            if not self.interfereBetween(prevOp, curOp):
                break
            curOp = prevOp
            startingPos -= 1
        startingPos += 1
        curOp = self.moveOps[pos].op
        endingPos = pos + 1
        while endingPos < len(self.moveOps):
            nextOp = self.moveOps[endingPos].op
            if not self.interfereBetween(curOp, nextOp):
                break
            curOp = nextOp
            endingPos += 1
        if endingPos - startingPos < self.MINIMUM_SEQUENCE_LENGTH:
            return False
        if startingPos > 0:
            for i in range(startingPos, endingPos):
                self.moveOps[i - startingPos] = self.moveOps[i]
        self.moveOps = self.moveOps[:endingPos - startingPos]
        return True

    def formByteArray(self, sz: int, slot: int, rootOff: int, bigEndian: bool) -> int:
        """Put constant values from COPYs into a single byte array.

        Creates an array of bytes being written. Runs through the ops and places their
        constant input (at given slot) based on offset relative to rootOff.
        If there are gaps, removes ops that don't write to the contiguous region
        in front of the root. Returns 0 if contiguous region is too small.
        """
        self.byteArray = [0] * sz
        used = [0] * sz
        elSize = self.charType.getSize() if hasattr(self.charType, 'getSize') else 1
        for node in self.moveOps:
            bytePos = int(node.offset - rootOff)
            if bytePos < 0 or bytePos + elSize > sz:
                continue
            val = node.op.getIn(slot).getOffset()
            used[bytePos] = 2 if val == 0 else 1
            if bigEndian:
                for j in range(elSize):
                    self.byteArray[bytePos + j] = (val >> ((elSize - 1 - j) * 8)) & 0xFF
            else:
                for j in range(elSize):
                    self.byteArray[bytePos + j] = val & 0xFF
                    val >>= 8
        bigElSize = self.charType.getAlignSize() if hasattr(self.charType, 'getAlignSize') else elSize
        maxEl = len(used) // bigElSize if bigElSize > 0 else 0
        count = 0
        while count < maxEl:
            val = used[count * bigElSize]
            if val != 1:
                if val == 2:
                    count += 1
                break
            count += 1
        if count < self.MINIMUM_SEQUENCE_LENGTH:
            return 0
        if count != len(self.moveOps):
            maxOff = rootOff + count * bigElSize
            finalOps = [node for node in self.moveOps if node.offset < maxOff]
            self.moveOps = finalOps
        return count

    def selectStringCopyFunction(self) -> tuple:
        """Pick either strncpy, wcsncpy, or memcpy function.

        Returns (builtInId, index) where index is either numElements or numElements*alignSize.
        C++ ref: ArraySequence::selectStringCopyFunction
        """
        BUILTIN_STRNCPY = 1
        BUILTIN_WCSNCPY = 2
        BUILTIN_MEMCPY = 3
        types = self._fd.getArch().types if self._fd is not None and hasattr(self._fd, 'getArch') else None
        if types is not None and hasattr(types, 'getTypeChar') and hasattr(types, 'getSizeOfChar'):
            charType1 = types.getTypeChar(types.getSizeOfChar())
            if self.charType == charType1:
                return (BUILTIN_STRNCPY, self.numElements)
            if hasattr(types, 'getSizeOfWChar'):
                wcharType = types.getTypeChar(types.getSizeOfWChar())
                if self.charType == wcharType:
                    return (BUILTIN_WCSNCPY, self.numElements)
        alignSize = self.charType.getAlignSize() if hasattr(self.charType, 'getAlignSize') else 1
        return (BUILTIN_MEMCPY, self.numElements * alignSize)

    def clear(self) -> None:
        self.rootOp = None
        self.numElements = 0
        self.moveOps.clear()
        self.byteArray.clear()


class StringSequence(ArraySequence):
    """A sequence of COPY ops writing characters to the same string.

    Given a starting Address and a Symbol with a character array as a component,
    collects a maximal set of COPY ops that can be treated as writing a single string.
    C++ ref: StringSequence in constseq.hh/cc
    """

    TYPE_ARRAY = 9  # Ghidra TYPE_ARRAY metatype constant

    def __init__(self, fd=None, ct=None, entry=None, root=None, addr=None) -> None:
        super().__init__(fd, ct, root)
        self.rootAddr: Address = addr if addr is not None else Address()
        self.startAddr: Address = Address()
        self.entry = entry
        if fd is not None and root is not None and entry is not None and addr is not None:
            self._initSequence()

    def _initSequence(self) -> None:
        """Full constructor logic matching C++ StringSequence::StringSequence."""
        if self.entry.getAddr().getSpace() != self.rootAddr.getSpace():
            return
        off = self.rootAddr.getOffset() - self.entry.getFirst()
        if off >= self.entry.getSize():
            return
        if self.rootOp.getIn(0).getOffset() == 0:
            return
        parentType = self.entry.getSymbol().getType()
        arrayType = None
        lastOff = 0
        while parentType is not None:
            if parentType == self.charType:
                break
            arrayType = parentType
            lastOff = off
            newOff = [off]
            parentType = parentType.getSubType(off, newOff) if hasattr(parentType, 'getSubType') else None
            if parentType is not None:
                off = newOff[0] if isinstance(newOff, list) else newOff
        if parentType != self.charType or arrayType is None:
            return
        if not hasattr(arrayType, 'getMetatype') or arrayType.getMetatype() != self.TYPE_ARRAY:
            return
        self.startAddr = Address(self.rootAddr.getSpace(), self.rootAddr.getOffset() - lastOff)
        if not self.collectCopyOps(arrayType.getSize()):
            return
        if not self.checkInterference():
            return
        arrSize = arrayType.getSize() - int(self.rootAddr.getOffset() - self.startAddr.getOffset())
        isBigEndian = self.rootAddr.getSpace().isBigEndian() if hasattr(self.rootAddr.getSpace(), 'isBigEndian') else False
        self.numElements = self.formByteArray(arrSize, 0, self.rootAddr.getOffset(), isBigEndian)

    def getRootAddr(self) -> Address:
        return self.rootAddr

    def getEntry(self):
        return self.entry

    def collectCopyOps(self, size: int) -> bool:
        """Collect ops COPYing constants into the memory region.

        C++ ref: StringSequence::collectCopyOps (lines 227-264)
        """
        endAddr = Address(self.startAddr.getSpace(), self.startAddr.getOffset() + size - 1)
        beginAddr = self.startAddr
        if self.startAddr != self.rootAddr:
            alignSize = self.charType.getAlignSize() if hasattr(self.charType, 'getAlignSize') else 1
            beginAddr = Address(self.rootAddr.getSpace(), self.rootAddr.getOffset() - alignSize)

        diff = self.rootAddr.getOffset() - self.startAddr.getOffset()
        charSize = self.charType.getSize() if hasattr(self.charType, 'getSize') else 1
        alignSize = self.charType.getAlignSize() if hasattr(self.charType, 'getAlignSize') else charSize

        if hasattr(self._fd, 'beginLoc') and hasattr(self._fd, 'endLoc'):
            for vn in self._fd.iterLoc(beginAddr, endAddr):
                if not vn.isWritten():
                    continue
                op = vn.getDef()
                if op.code() != OpCode.CPUI_COPY:
                    continue
                if op.getParent() != self.block:
                    continue
                if not op.getIn(0).isConstant():
                    continue
                if vn.getSize() != charSize:
                    return False
                tmpDiff = vn.getOffset() - self.startAddr.getOffset()
                if tmpDiff < diff:
                    if tmpDiff + alignSize == diff:
                        return False
                    continue
                elif tmpDiff > diff:
                    if tmpDiff - diff < alignSize:
                        continue
                    if tmpDiff - diff > alignSize:
                        break
                    diff = tmpDiff
                self.moveOps.append(WriteNode(vn.getOffset(), op, -1))
        return len(self.moveOps) >= self.MINIMUM_SEQUENCE_LENGTH

    def constructTypedPointer(self, insertPoint):
        """Construct a typed pointer Varnode to the root Address.

        C++ ref: StringSequence::constructTypedPointer (lines 273-339)
        Builds PTRSUB/PTRADD chain from base register to array memory region.
        """
        spc = self.rootAddr.getSpace()
        types = self._fd.getArch().types
        if hasattr(spc, 'getType') and spc.getType() == 1:  # IPTR_SPACEBASE
            spacePtr = self._fd.constructSpacebaseInput(spc)
        else:
            spacePtr = self._fd.constructConstSpacebase(spc)
        baseType = self.entry.getSymbol().getType()
        ptrsub = self._fd.newOp(2, insertPoint.getAddr())
        self._fd.opSetOpcode(ptrsub, int(OpCode.CPUI_PTRSUB))
        self._fd.opSetInput(ptrsub, spacePtr, 0)
        wordSize = spc.getWordSize() if hasattr(spc, 'getWordSize') else 1
        baseOff = self.entry.getFirst() // wordSize if wordSize > 1 else self.entry.getFirst()
        self._fd.opSetInput(ptrsub, self._fd.newConstant(spacePtr.getSize(), baseOff), 1)
        spacePtr = self._fd.newUniqueOut(spacePtr.getSize(), ptrsub)
        self._fd.opInsertBefore(ptrsub, insertPoint)
        curOff = self.rootAddr.getOffset() - self.entry.getFirst()
        while baseType != self.charType:
            elSize = -1
            if hasattr(baseType, 'getMetatype') and baseType.getMetatype() == self.TYPE_ARRAY:
                if hasattr(baseType, 'getBase'):
                    elSize = baseType.getBase().getAlignSize()
            newOff = [curOff]
            baseType = baseType.getSubType(curOff, newOff) if hasattr(baseType, 'getSubType') else None
            if baseType is None:
                break
            curOff -= newOff[0] if isinstance(newOff, list) else newOff
            subOff = curOff // wordSize if wordSize > 1 else curOff
            if elSize >= 0:
                if curOff == 0:
                    continue
                ptrsub = self._fd.newOp(3, insertPoint.getAddr())
                self._fd.opSetOpcode(ptrsub, int(OpCode.CPUI_PTRADD))
                numEl = curOff // elSize
                self._fd.opSetInput(ptrsub, self._fd.newConstant(4, numEl), 1)
                self._fd.opSetInput(ptrsub, self._fd.newConstant(4, elSize), 2)
            else:
                ptrsub = self._fd.newOp(2, insertPoint.getAddr())
                self._fd.opSetOpcode(ptrsub, int(OpCode.CPUI_PTRSUB))
                self._fd.opSetInput(ptrsub, self._fd.newConstant(spacePtr.getSize(), subOff), 1)
            self._fd.opSetInput(ptrsub, spacePtr, 0)
            spacePtr = self._fd.newUniqueOut(spacePtr.getSize(), ptrsub)
            self._fd.opInsertBefore(ptrsub, insertPoint)
            curOff = newOff[0] if isinstance(newOff, list) else newOff
        if curOff != 0:
            addOp = self._fd.newOp(2, insertPoint.getAddr())
            self._fd.opSetOpcode(addOp, int(OpCode.CPUI_INT_ADD))
            self._fd.opSetInput(addOp, spacePtr, 0)
            subOff = curOff // wordSize if wordSize > 1 else curOff
            self._fd.opSetInput(addOp, self._fd.newConstant(spacePtr.getSize(), subOff), 1)
            spacePtr = self._fd.newUniqueOut(spacePtr.getSize(), addOp)
            self._fd.opInsertBefore(addOp, insertPoint)
        return spacePtr

    def buildStringCopy(self):
        """Build the strncpy/wcsncpy/memcpy function with string as input.

        C++ ref: StringSequence::buildStringCopy (lines 347-372)
        """
        if not self.moveOps:
            return None
        insertPoint = self.moveOps[0].op
        charSize = self.charType.getSize() if hasattr(self.charType, 'getSize') else 1
        numBytes = len(self.moveOps) * charSize
        glb = self._fd.getArch()
        types = glb.types
        wordSize = self.rootAddr.getSpace().getWordSize() if hasattr(self.rootAddr.getSpace(), 'getWordSize') else 1
        ptrSize = types.getSizeOfPointer() if hasattr(types, 'getSizeOfPointer') else 4
        charPtrType = types.getTypePointer(ptrSize, self.charType, wordSize) if hasattr(types, 'getTypePointer') else None
        srcPtr = self._fd.getInternalString(bytes(self.byteArray[:numBytes]), numBytes, charPtrType, insertPoint) if hasattr(self._fd, 'getInternalString') else None
        if srcPtr is None:
            return None
        builtInId, index = self.selectStringCopyFunction()
        if hasattr(glb, 'userops') and hasattr(glb.userops, 'registerBuiltin'):
            glb.userops.registerBuiltin(builtInId)
        copyOp = self._fd.newOp(4, insertPoint.getAddr())
        self._fd.opSetOpcode(copyOp, int(OpCode.CPUI_CALLOTHER))
        self._fd.opSetInput(copyOp, self._fd.newConstant(4, builtInId), 0)
        destPtr = self.constructTypedPointer(insertPoint)
        self._fd.opSetInput(copyOp, destPtr, 1)
        self._fd.opSetInput(copyOp, srcPtr, 2)
        lenVn = self._fd.newConstant(4, index)
        self._fd.opSetInput(copyOp, lenVn, 3)
        self._fd.opInsertBefore(copyOp, insertPoint)
        return copyOp

    @staticmethod
    def removeForward(curNode, xref: dict, points: list, deadOps: list) -> None:
        """Analyze output descendants of the given PcodeOp being removed.

        C++ ref: StringSequence::removeForward (lines 383-409)
        """
        vn = curNode.op.getOut()
        if vn is None:
            return
        for op in list(vn.getDescend()) if hasattr(vn, 'getDescend') else []:
            opid = id(op)
            if opid in xref:
                idx = xref[opid]
                off = points[idx].offset
                if curNode.offset < off:
                    off = curNode.offset
                points[idx] = None
                del xref[opid]
                deadOps.append(WriteNode(off, op, -1))
            else:
                slot = op.getSlot(vn) if hasattr(op, 'getSlot') else 0
                points.append(WriteNode(curNode.offset, op, slot))
                if op.code() == OpCode.CPUI_PIECE:
                    xref[opid] = len(points) - 1

    def removeCopyOps(self, replaceOp) -> None:
        """Remove all the COPY ops from the basic block.

        C++ ref: StringSequence::removeCopyOps (lines 415-447)
        """
        if self._fd is None:
            return
        concatSet: dict = {}
        points: list = []
        deadOps: list = []
        for node in self.moveOps:
            self.removeForward(node, concatSet, points, deadOps)
        pos = 0
        while pos < len(deadOps):
            self.removeForward(deadOps[pos], concatSet, points, deadOps)
            pos += 1
        for pt in points:
            if pt is None:
                continue
            op = pt.op
            vn = op.getIn(pt.slot)
            if vn.isWritten() and vn.getDef().code() == OpCode.CPUI_INDIRECT:
                continue
            newIn = self._fd.newConstant(vn.getSize(), 0)
            indOp = self._fd.newOp(2, replaceOp.getAddr())
            self._fd.opSetOpcode(indOp, int(OpCode.CPUI_INDIRECT))
            self._fd.opSetInput(indOp, newIn, 0)
            self._fd.opSetInput(indOp, self._fd.newVarnodeIop(replaceOp), 1)
            self._fd.opSetOutput(indOp, vn)
            if hasattr(self._fd, 'markIndirectCreation'):
                self._fd.markIndirectCreation(indOp, False)
            self._fd.opInsertBefore(indOp, replaceOp)
        for node in self.moveOps:
            if hasattr(self._fd, 'opDestroy'):
                self._fd.opDestroy(node.op)
        for node in deadOps:
            if hasattr(self._fd, 'opDestroy'):
                self._fd.opDestroy(node.op)

    def transform(self) -> bool:
        """Transform COPYs into a single memcpy user-op.

        C++ ref: StringSequence::transform (lines 453-461)
        """
        memCpyOp = self.buildStringCopy()
        if memCpyOp is None:
            return False
        self.removeCopyOps(memCpyOp)
        return True


class IndirectPair:
    """Helper class containing Varnode pairs that flow across a sequence of INDIRECTs.

    C++ ref: HeapSequence::IndirectPair
    """
    def __init__(self, inVn, outVn):
        self.inVn = inVn
        self.outVn = outVn

    def markDuplicate(self) -> None:
        self.inVn = None

    def isDuplicate(self) -> bool:
        return self.inVn is None

    @staticmethod
    def compareOutput(a: 'IndirectPair', b: 'IndirectPair') -> bool:
        vn1 = a.outVn
        vn2 = b.outVn
        if vn1.getSpace() != vn2.getSpace():
            idx1 = vn1.getSpace().getIndex() if hasattr(vn1.getSpace(), 'getIndex') else 0
            idx2 = vn2.getSpace().getIndex() if hasattr(vn2.getSpace(), 'getIndex') else 0
            return idx1 < idx2
        if vn1.getOffset() != vn2.getOffset():
            return vn1.getOffset() < vn2.getOffset()
        if vn1.getSize() != vn2.getSize():
            return vn1.getSize() < vn2.getSize()
        return False


def _calc_mask(size: int) -> int:
    """Calculate bit mask for given byte size."""
    if size >= 8:
        return 0xFFFFFFFFFFFFFFFF
    return (1 << (size * 8)) - 1


class HeapSequence(ArraySequence):
    """A sequence of STORE operations writing characters through the same string pointer.

    Given an initial STORE, collects a maximal set of STORE ops that can be treated as
    writing a single string into memory.
    C++ ref: HeapSequence in constseq.hh/cc
    """

    def __init__(self, fd=None, ct=None, root=None) -> None:
        super().__init__(fd, ct, root)
        self.basePointer = None
        self.baseOffset: int = 0
        self.storeSpace = None
        self.ptrAddMult: int = 0
        self.nonConstAdds: List = []
        if fd is not None and ct is not None and root is not None:
            self._initSequence()

    def _initSequence(self) -> None:
        """Full constructor logic matching C++ HeapSequence::HeapSequence."""
        self.baseOffset = 0
        spaceVn = self.rootOp.getIn(0)
        self.storeSpace = spaceVn.getSpaceFromConst() if hasattr(spaceVn, 'getSpaceFromConst') else None
        if self.storeSpace is None:
            return
        alignSize = self.charType.getAlignSize() if hasattr(self.charType, 'getAlignSize') else 1
        wordSize = self.storeSpace.getWordSize() if hasattr(self.storeSpace, 'getWordSize') else 1
        self.ptrAddMult = alignSize // wordSize if wordSize > 0 else alignSize
        self.findBasePointer(self.rootOp.getIn(1))
        if not self.collectStoreOps():
            return
        if not self.checkInterference():
            return
        arrSize = len(self.moveOps) * alignSize
        bigEndian = self.storeSpace.isBigEndian() if hasattr(self.storeSpace, 'isBigEndian') else False
        self.numElements = self.formByteArray(arrSize, 2, 0, bigEndian)

    def findBasePointer(self, initPtr) -> None:
        """Find the base pointer for the sequence by backtracking through PTRADDs and COPYs.

        C++ ref: HeapSequence::findBasePointer (lines 465-480)
        """
        self.basePointer = initPtr
        while self.basePointer is not None and self.basePointer.isWritten():
            op = self.basePointer.getDef()
            opc = op.code()
            if opc == OpCode.CPUI_PTRADD:
                sz = op.getIn(2).getOffset()
                if sz != self.ptrAddMult:
                    break
            elif opc != OpCode.CPUI_COPY:
                break
            self.basePointer = op.getIn(0)

    def findDuplicateBases(self, duplist: list) -> None:
        """Find duplicates of basePointer by backtracking then forward-tracing.

        C++ ref: HeapSequence::findDuplicateBases (lines 486-539)
        """
        if not self.basePointer.isWritten():
            duplist.append(self.basePointer)
            return
        op = self.basePointer.getDef()
        opc = op.code()
        if ((opc != OpCode.CPUI_PTRSUB and opc != OpCode.CPUI_INT_ADD and opc != OpCode.CPUI_PTRADD)
                or not op.getIn(1).isConstant()):
            duplist.append(self.basePointer)
            return
        copyRoot = self.basePointer
        offsets: List[int] = []
        while True:
            off = op.getIn(1).getOffset()
            if opc == OpCode.CPUI_PTRADD:
                off *= op.getIn(2).getOffset()
            offsets.append(off)
            copyRoot = op.getIn(0)
            if not copyRoot.isWritten():
                break
            op = copyRoot.getDef()
            opc = op.code()
            if opc != OpCode.CPUI_PTRSUB and opc != OpCode.CPUI_INT_ADD and opc != OpCode.CPUI_PTRADD:
                break
            if not op.getIn(1).isConstant():
                break
        duplist.append(copyRoot)
        midlist: list = []
        for i in range(len(offsets) - 1, -1, -1):
            midlist = list(duplist)
            duplist.clear()
            for vn in midlist:
                for descOp in (list(vn.getDescend()) if hasattr(vn, 'getDescend') else []):
                    descOpc = descOp.code()
                    if (descOpc != OpCode.CPUI_PTRSUB and descOpc != OpCode.CPUI_INT_ADD
                            and descOpc != OpCode.CPUI_PTRADD):
                        continue
                    if descOp.getIn(0) != vn or not descOp.getIn(1).isConstant():
                        continue
                    descOff = descOp.getIn(1).getOffset()
                    if descOpc == OpCode.CPUI_PTRADD:
                        descOff *= descOp.getIn(2).getOffset()
                    if descOff != offsets[i]:
                        continue
                    duplist.append(descOp.getOut())

    def findInitialStores(self, stores: list) -> None:
        """Find STOREs with pointers derived from basePointer in the same block.

        C++ ref: HeapSequence::findInitialStores (lines 544-573)
        """
        ptradds: list = []
        self.findDuplicateBases(ptradds)
        pos = 0
        while pos < len(ptradds):
            vn = ptradds[pos]
            pos += 1
            for op in (list(vn.getDescend()) if hasattr(vn, 'getDescend') else []):
                opc = op.code()
                if opc == OpCode.CPUI_PTRADD:
                    if op.getIn(0) != vn:
                        continue
                    if op.getIn(2).getOffset() != self.ptrAddMult:
                        continue
                    ptradds.append(op.getOut())
                elif opc == OpCode.CPUI_COPY:
                    ptradds.append(op.getOut())
                elif opc == OpCode.CPUI_STORE and op.getParent() == self.block and op != self.rootOp:
                    if op.getIn(1) != vn:
                        continue
                    stores.append(op)

    @staticmethod
    def calcAddElements(vn, nonConst: list, maxDepth: int) -> int:
        """Recursively walk an ADD tree, collecting offsets and non-constant elements.

        C++ ref: HeapSequence::calcAddElements (lines 583-595)
        """
        if vn.isConstant():
            return vn.getOffset()
        if not vn.isWritten() or vn.getDef().code() != OpCode.CPUI_INT_ADD or maxDepth == 0:
            nonConst.append(vn)
            return 0
        res = HeapSequence.calcAddElements(vn.getDef().getIn(0), nonConst, maxDepth - 1)
        res += HeapSequence.calcAddElements(vn.getDef().getIn(1), nonConst, maxDepth - 1)
        return res

    def calcPtraddOffset(self, vn, nonConst: list) -> int:
        """Calculate byte offset between given Varnode and basePointer.

        C++ ref: HeapSequence::calcPtraddOffset (lines 604-627)
        """
        res = 0
        while vn is not None and vn.isWritten():
            op = vn.getDef()
            opc = op.code()
            if opc == OpCode.CPUI_PTRADD:
                mult = op.getIn(2).getOffset()
                if mult != self.ptrAddMult:
                    break
                off = self.calcAddElements(op.getIn(1), nonConst, 3)
                off *= mult
                res += off
                vn = op.getIn(0)
            elif opc == OpCode.CPUI_COPY:
                vn = op.getIn(0)
            else:
                break
        wordSize = self.storeSpace.getWordSize() if hasattr(self.storeSpace, 'getWordSize') else 1
        return res * wordSize if wordSize > 1 else res

    @staticmethod
    def setsEqual(op1: list, op2: list) -> bool:
        """Determine if two sets of Varnodes are equal.

        C++ ref: HeapSequence::setsEqual (lines 636-644)
        """
        if len(op1) != len(op2):
            return False
        for i in range(len(op1)):
            if op1[i] is not op2[i]:
                return False
        return True

    def testValue(self, op) -> bool:
        """Test if a STORE value has the matching form for the sequence.

        C++ ref: HeapSequence::testValue (lines 648-657)
        """
        vn = op.getIn(2)
        if not vn.isConstant():
            return False
        charSize = self.charType.getSize() if hasattr(self.charType, 'getSize') else 1
        if vn.getSize() != charSize:
            return False
        return True

    def collectStoreOps(self) -> bool:
        """Collect ops STOREing into a memory region from the same root pointer.

        C++ ref: HeapSequence::collectStoreOps (lines 663-690)
        """
        initStores: list = []
        self.findInitialStores(initStores)
        if len(initStores) + 1 < self.MINIMUM_SEQUENCE_LENGTH:
            return False
        alignSize = self.charType.getAlignSize() if hasattr(self.charType, 'getAlignSize') else 1
        maxSize = self.MAXIMUM_SEQUENCE_LENGTH * alignSize
        addrSize = self.storeSpace.getAddrSize() if hasattr(self.storeSpace, 'getAddrSize') else 4
        wrapMask = _calc_mask(addrSize)
        self.baseOffset = self.calcPtraddOffset(self.rootOp.getIn(1), self.nonConstAdds)
        nonConstComp: list = []
        for op in initStores:
            nonConstComp.clear()
            curOffset = self.calcPtraddOffset(op.getIn(1), nonConstComp)
            diff = (curOffset - self.baseOffset) & wrapMask
            if self.setsEqual(self.nonConstAdds, nonConstComp):
                if diff >= maxSize:
                    return False
                if not self.testValue(op):
                    return False
                self.moveOps.append(WriteNode(diff, op, -1))
        self.moveOps.append(WriteNode(0, self.rootOp, -1))
        return True

    def buildStringCopy(self):
        """Build the strncpy/wcsncpy/memcpy function with string as input.

        C++ ref: HeapSequence::buildStringCopy (lines 698-762)
        """
        if not self.moveOps:
            return None
        insertPoint = self.moveOps[0].op
        charPtrType = self.rootOp.getIn(1).getTypeReadFacing(self.rootOp) if hasattr(self.rootOp.getIn(1), 'getTypeReadFacing') else None
        charSize = self.charType.getSize() if hasattr(self.charType, 'getSize') else 1
        numBytes = self.numElements * charSize
        glb = self._fd.getArch()
        srcPtr = self._fd.getInternalString(bytes(self.byteArray[:numBytes]), numBytes, charPtrType, insertPoint) if hasattr(self._fd, 'getInternalString') else None
        if srcPtr is None:
            return None
        destPtr = self.basePointer
        if self.baseOffset != 0 or self.nonConstAdds:
            indexVn = None
            intType = glb.types.getBase(self.basePointer.getSize(), 8) if hasattr(glb.types, 'getBase') else None  # TYPE_INT=8
            if self.nonConstAdds:
                indexVn = self.nonConstAdds[0]
                for i in range(1, len(self.nonConstAdds)):
                    addOp = self._fd.newOp(2, insertPoint.getAddr())
                    self._fd.opSetOpcode(addOp, int(OpCode.CPUI_INT_ADD))
                    self._fd.opSetInput(addOp, indexVn, 0)
                    self._fd.opSetInput(addOp, self.nonConstAdds[i], 1)
                    indexVn = self._fd.newUniqueOut(indexVn.getSize(), addOp)
                    if intType is not None and hasattr(indexVn, 'updateType'):
                        indexVn.updateType(intType)
                    self._fd.opInsertBefore(addOp, insertPoint)
            if self.baseOffset != 0:
                alignSize = self.charType.getAlignSize() if hasattr(self.charType, 'getAlignSize') else 1
                numEl = self.baseOffset // alignSize if alignSize > 0 else self.baseOffset
                cvn = self._fd.newConstant(self.basePointer.getSize(), numEl)
                if intType is not None and hasattr(cvn, 'updateType'):
                    cvn.updateType(intType)
                if indexVn is None:
                    indexVn = cvn
                else:
                    addOp = self._fd.newOp(2, insertPoint.getAddr())
                    self._fd.opSetOpcode(addOp, int(OpCode.CPUI_INT_ADD))
                    self._fd.opSetInput(addOp, indexVn, 0)
                    self._fd.opSetInput(addOp, cvn, 1)
                    indexVn = self._fd.newUniqueOut(indexVn.getSize(), addOp)
                    if intType is not None and hasattr(indexVn, 'updateType'):
                        indexVn.updateType(intType)
                    self._fd.opInsertBefore(addOp, insertPoint)
            alignSize = self.charType.getAlignSize() if hasattr(self.charType, 'getAlignSize') else 1
            ptrAdd = self._fd.newOp(3, insertPoint.getAddr())
            self._fd.opSetOpcode(ptrAdd, int(OpCode.CPUI_PTRADD))
            destPtr = self._fd.newUniqueOut(self.basePointer.getSize(), ptrAdd)
            self._fd.opSetInput(ptrAdd, self.basePointer, 0)
            self._fd.opSetInput(ptrAdd, indexVn, 1)
            self._fd.opSetInput(ptrAdd, self._fd.newConstant(self.basePointer.getSize(), alignSize), 2)
            if charPtrType is not None and hasattr(destPtr, 'updateType'):
                destPtr.updateType(charPtrType)
            self._fd.opInsertBefore(ptrAdd, insertPoint)
        builtInId, index = self.selectStringCopyFunction()
        if hasattr(glb, 'userops') and hasattr(glb.userops, 'registerBuiltin'):
            glb.userops.registerBuiltin(builtInId)
        copyOp = self._fd.newOp(4, insertPoint.getAddr())
        self._fd.opSetOpcode(copyOp, int(OpCode.CPUI_CALLOTHER))
        self._fd.opSetInput(copyOp, self._fd.newConstant(4, builtInId), 0)
        self._fd.opSetInput(copyOp, destPtr, 1)
        self._fd.opSetInput(copyOp, srcPtr, 2)
        lenVn = self._fd.newConstant(4, index)
        self._fd.opSetInput(copyOp, lenVn, 3)
        self._fd.opInsertBefore(copyOp, insertPoint)
        return copyOp

    def gatherIndirectPairs(self, indirects: list, pairs: list) -> None:
        """Gather INDIRECT ops attached to the final sequence STOREs and their input/output pairs.

        C++ ref: HeapSequence::gatherIndirectPairs (lines 770-806)
        """
        for node in self.moveOps:
            op = node.op.previousOp() if hasattr(node.op, 'previousOp') else None
            while op is not None:
                if op.code() != OpCode.CPUI_INDIRECT:
                    break
                if hasattr(op, 'setMark'):
                    op.setMark()
                indirects.append(op)
                op = op.previousOp() if hasattr(op, 'previousOp') else None
        for op in indirects:
            outvn = op.getOut()
            hasUse = False
            for useOp in (list(outvn.getDescend()) if hasattr(outvn, 'getDescend') else []):
                if not (hasattr(useOp, 'isMark') and useOp.isMark()):
                    hasUse = True
                    break
            if hasUse:
                invn = op.getIn(0)
                while invn.isWritten():
                    defOp = invn.getDef()
                    if not (hasattr(defOp, 'isMark') and defOp.isMark()):
                        break
                    invn = defOp.getIn(0)
                pairs.append(IndirectPair(invn, outvn))
        for op in indirects:
            if hasattr(op, 'clearMark'):
                op.clearMark()

    def deduplicatePairs(self, pairs: list) -> bool:
        """Find and eliminate duplicate INDIRECT pairs.

        C++ ref: HeapSequence::deduplicatePairs (lines 827-864)
        """
        if not pairs:
            return True
        from functools import cmp_to_key
        def cmp_pairs(a, b):
            if IndirectPair.compareOutput(a, b):
                return -1
            if IndirectPair.compareOutput(b, a):
                return 1
            return 0
        copy = sorted(pairs, key=cmp_to_key(cmp_pairs))
        head = copy[0]
        dupCount = 0
        for i in range(1, len(copy)):
            vn = copy[i].outVn
            overlap = head.outVn.characterizeOverlap(vn) if hasattr(head.outVn, 'characterizeOverlap') else 0
            if overlap == 1:
                return False
            if overlap == 2:
                if copy[i].inVn is not head.inVn:
                    return False
                copy[i].markDuplicate()
                dupCount += 1
            else:
                head = copy[i]
        if dupCount > 0:
            head = copy[0]
            for i in range(1, len(copy)):
                if copy[i].isDuplicate():
                    if hasattr(self._fd, 'totalReplace'):
                        self._fd.totalReplace(copy[i].outVn, head.outVn)
                else:
                    head = copy[i]
        return True

    def removeStoreOps(self, indirects: list, indirectPairs: list, replaceOp) -> None:
        """Remove all STORE ops from the basic block.

        C++ ref: HeapSequence::removeStoreOps (lines 871-894)
        """
        if self._fd is None:
            return
        for pair in indirectPairs:
            if hasattr(self._fd, 'opUnsetOutput') and pair.outVn.isWritten():
                self._fd.opUnsetOutput(pair.outVn.getDef())
        scratch: list = []
        for node in self.moveOps:
            if hasattr(self._fd, 'opDestroyRecursive'):
                self._fd.opDestroyRecursive(node.op, scratch)
            elif hasattr(self._fd, 'opDestroy'):
                self._fd.opDestroy(node.op)
        for op in indirects:
            if hasattr(self._fd, 'opDestroy'):
                self._fd.opDestroy(op)
        for pair in indirectPairs:
            if pair.isDuplicate():
                continue
            newInd = self._fd.newOp(2, replaceOp.getAddr())
            self._fd.opSetOpcode(newInd, int(OpCode.CPUI_INDIRECT))
            self._fd.opSetOutput(newInd, pair.outVn)
            self._fd.opSetInput(newInd, pair.inVn, 0)
            self._fd.opSetInput(newInd, self._fd.newVarnodeIop(replaceOp), 1)
            self._fd.opInsertBefore(newInd, replaceOp)

    def transform(self) -> bool:
        """Transform STOREs into a single memcpy user-op.

        C++ ref: HeapSequence::transform (lines 927-940)
        """
        indirects: list = []
        indirectPairs: list = []
        self.gatherIndirectPairs(indirects, indirectPairs)
        if not self.deduplicatePairs(indirectPairs):
            return False
        memCpyOp = self.buildStringCopy()
        if memCpyOp is None:
            return False
        self.removeStoreOps(indirects, indirectPairs, memCpyOp)
        return True


class ConstSequence:
    """Detect and collect constant store sequences in a basic block.

    Scans a basic block for consecutive STORE operations that write
    constant values to adjacent memory locations. These can be
    collapsed into a single string or array initialization.
    """

    def __init__(self, fd=None) -> None:
        self._fd = fd
        self._strings: List[StringSequence] = []
        self._arrays: List[ArraySequence] = []

    def clear(self) -> None:
        self._strings.clear()
        self._arrays.clear()

    def getStrings(self) -> List[StringSequence]:
        return self._strings

    def getArrays(self) -> List[ArraySequence]:
        return self._arrays

    def analyzeBlock(self, bb) -> bool:
        """Analyze a basic block for constant sequences.

        Returns True if any sequences were found.
        This is a Python-only utility for simple constant-store detection.
        """
        if bb is None:
            return False
        ops = bb.getOpList() if hasattr(bb, 'getOpList') else []
        stores = []
        for op in ops:
            if op.code() == OpCode.CPUI_STORE:
                val_vn = op.getIn(2)
                addr_vn = op.getIn(1)
                if val_vn is not None and val_vn.isConstant():
                    if addr_vn is not None and addr_vn.isConstant():
                        stores.append((addr_vn.getOffset(), val_vn.getOffset(),
                                       val_vn.getSize(), op))
        if len(stores) < 2:
            return False
        stores.sort(key=lambda x: x[0])
        i = 0
        found = False
        while i < len(stores) - 1:
            seq = ArraySequence()
            addr, val, sz, op = stores[i]
            seq.byteArray.append(val & 0xFF)
            seq.moveOps.append(WriteNode(addr, op, 2))
            seq.rootOp = op
            j = i + 1
            while j < len(stores):
                next_addr, next_val, next_sz, next_op = stores[j]
                if next_addr == addr + sz and next_sz == sz:
                    seq.byteArray.append(next_val & 0xFF)
                    seq.moveOps.append(WriteNode(next_addr, next_op, 2))
                    addr = next_addr
                    j += 1
                else:
                    break
            if len(seq.byteArray) >= 2:
                seq.numElements = len(seq.byteArray)
                self._arrays.append(seq)
                found = True
            i = j
        return found

    def getNumStrings(self) -> int:
        return len(self._strings)

    def analyzeFunction(self, fd) -> bool:
        """Analyze all basic blocks in a function for constant sequences."""
        if fd is None:
            return False
        found = False
        bblocks = fd.getBasicBlocks() if hasattr(fd, 'getBasicBlocks') else None
        if bblocks is None:
            return False
        if hasattr(bblocks, 'getSize'):
            for i in range(bblocks.getSize()):
                bl = bblocks.getBlock(i)
                if self.analyzeBlock(bl):
                    found = True
        return found
