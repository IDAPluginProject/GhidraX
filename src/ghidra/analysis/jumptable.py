"""
Corresponds to: jumptable.hh / jumptable.cc

Classes to support jump-tables and their recovery.
JumpTable, JumpModel, JumpBasic, LoadTable, PathMeld, GuardRecord.
"""

from __future__ import annotations
from bisect import bisect_left
from typing import Optional, List, Dict, Set
from ghidra.core.address import Address
from ghidra.core.error import LowlevelError


class IndexPair:
    """A pair (blockPosition, addressIndex) for mapping address table entries to block out-edges.

    C++ ref: ``IndexPair``
    """
    __slots__ = ('blockPosition', 'addressIndex')

    def __init__(self, blockPos: int = 0, addrIdx: int = 0) -> None:
        self.blockPosition: int = blockPos
        self.addressIndex: int = addrIdx

    def __lt__(self, other):
        if self.blockPosition != other.blockPosition:
            return self.blockPosition < other.blockPosition
        return self.addressIndex < other.addressIndex

    @staticmethod
    def compareByPosition(op1, op2):
        return op1.blockPosition < op2.blockPosition

    def __eq__(self, other):
        return self.blockPosition == other.blockPosition and self.addressIndex == other.addressIndex

    def __repr__(self):
        return f"IndexPair(block={self.blockPosition}, addr={self.addressIndex})"


class LoadTable:
    """A description of where and how data was loaded from memory."""

    def __init__(self, addr: Optional[Address] = None, sz: int = 0, nm: Optional[int] = None) -> None:
        self.addr: Address = addr if addr is not None else Address()
        self.size: int = sz
        if nm is None:
            self.num = 0 if addr is None and sz == 0 else 1
        else:
            self.num = nm

    def __lt__(self, other):
        return self.addr < other.addr

    def encode(self, encoder) -> None:
        """Encode this LoadTable as a <loadtable> element.

        C++ ref: ``LoadTable::encode``
        """
        from ghidra.core.marshal import ELEM_LOADTABLE, ATTRIB_SIZE, ATTRIB_NUM
        encoder.openElement(ELEM_LOADTABLE)
        encoder.writeSignedInteger(ATTRIB_SIZE, self.size)
        encoder.writeSignedInteger(ATTRIB_NUM, self.num)
        self.addr.encode(encoder)
        encoder.closeElement(ELEM_LOADTABLE)

    def decode(self, decoder) -> None:
        """Decode this LoadTable from a <loadtable> element.

        C++ ref: ``LoadTable::decode``
        """
        from ghidra.core.marshal import ELEM_LOADTABLE, ATTRIB_SIZE, ATTRIB_NUM
        elemId = decoder.openElement(ELEM_LOADTABLE)
        self.size = decoder.readSignedInteger(ATTRIB_SIZE)
        self.num = decoder.readSignedInteger(ATTRIB_NUM)
        self.addr = Address.decode(decoder)
        decoder.closeElement(elemId)

    @staticmethod
    def collapseTable(table: list) -> None:
        """Collapse adjacent table entries."""
        if not table:
            return

        issorted = True
        iter_idx = 0
        total_num = table[iter_idx].num
        size = table[iter_idx].size
        nextaddr = table[iter_idx].addr + size
        iter_idx += 1

        while iter_idx < len(table):
            cur = table[iter_idx]
            if cur.addr == nextaddr and cur.size == size:
                total_num += cur.num
                nextaddr = cur.addr + cur.size
            else:
                issorted = False
                break
            iter_idx += 1

        if issorted:
            table[:] = [table[0]]
            table[0].num = total_num
            return

        table.sort()

        count = 1
        last_idx = 0
        iter_idx = 1
        nextaddr = table[last_idx].addr + table[last_idx].size * table[last_idx].num
        while iter_idx < len(table):
            cur = table[iter_idx]
            last = table[last_idx]
            if cur.addr == nextaddr and cur.size == last.size:
                last.num += cur.num
                nextaddr = cur.addr + cur.size * cur.num
            elif nextaddr < cur.addr or cur.size != last.size:
                last_idx += 1
                table[last_idx] = cur
                nextaddr = cur.addr + cur.size * cur.num
                count += 1
            iter_idx += 1

        table[:] = table[:count]


class RootedOp:
    """A PcodeOp paired with the index of the earliest common Varnode it uses as input.

    C++ ref: RootedOp in jumptable.hh
    """
    __slots__ = ('op', 'rootVn')

    def __init__(self, op=None, rootVn: int = 0) -> None:
        self.op = op
        self.rootVn = rootVn


class PathMeld:
    """All paths from a switch variable to the BRANCHIND.

    C++ ref: PathMeld in jumptable.hh / jumptable.cc
    """

    def __init__(self) -> None:
        self.commonVn: list = []
        self.opMeld: List[RootedOp] = []

    def clear(self) -> None:
        self.commonVn.clear()
        self.opMeld.clear()

    def empty(self) -> bool:
        return len(self.commonVn) == 0

    def numCommonVarnode(self) -> int:
        return len(self.commonVn)

    def numOps(self) -> int:
        return len(self.opMeld)

    def getVarnode(self, i: int):
        return self.commonVn[i]

    def getOp(self, i: int):
        return self.opMeld[i].op

    def getOpParent(self, i: int):
        rootIdx = self.opMeld[i].rootVn
        return self.commonVn[rootIdx]

    def getEarliestOp(self, pos: int):
        """Find the earliest PcodeOp using the Varnode at the given index.

        C++ ref: PathMeld::getEarliestOp in jumptable.cc
        """
        for i in range(len(self.opMeld) - 1, -1, -1):
            if self.opMeld[i].rootVn == pos:
                return self.opMeld[i].op
        return None

    def set(self, op_or_path, vn=None):
        """Initialize this container from a single op+vn, a PathMeld, or a PcodeOpNode path.

        C++ ref: PathMeld::set (3 overloads) in jumptable.cc
        """
        if vn is not None:
            # set(PcodeOp*, Varnode*)
            self.commonVn.append(vn)
            self.opMeld.append(RootedOp(op_or_path, 0))
        elif isinstance(op_or_path, PathMeld):
            # set(const PathMeld&)
            self.commonVn = list(op_or_path.commonVn)
            self.opMeld = [RootedOp(entry.op, entry.rootVn) for entry in op_or_path.opMeld]
        elif isinstance(op_or_path, list):
            # set(const vector<PcodeOpNode>&)
            for i, node in enumerate(op_or_path):
                vn_item = node.op.getIn(node.slot)
                self.opMeld.append(RootedOp(node.op, i))
                self.commonVn.append(vn_item)

    def append(self, op2: 'PathMeld') -> None:
        """Append paths from another PathMeld to the beginning.

        C++ ref: PathMeld::append in jumptable.cc
        """
        shift = len(op2.commonVn)
        self.commonVn = op2.commonVn + self.commonVn
        self.opMeld = [RootedOp(entry.op, entry.rootVn) for entry in op2.opMeld] + self.opMeld
        for i in range(len(op2.opMeld), len(self.opMeld)):
            self.opMeld[i].rootVn += shift

    def internalIntersect(self, parentMap: list) -> None:
        """Calculate intersection of a new path with the old path.

        C++ ref: PathMeld::internalIntersect in jumptable.cc
        """
        newVn = []
        for vn in self.commonVn:
            if vn.isMark():
                parentMap.append(len(newVn))
                newVn.append(vn)
                vn.clearMark()
            else:
                parentMap.append(-1)
        self.commonVn = newVn
        lastIntersect = -1
        for i in range(len(parentMap) - 1, -1, -1):
            val = parentMap[i]
            if val == -1:
                parentMap[i] = lastIntersect
            else:
                lastIntersect = val

    def meldOps(self, path: list, cutOff: int, parentMap: list) -> int:
        """Meld in PcodeOps from a new path.

        C++ ref: PathMeld::meldOps in jumptable.cc
        """
        for entry in self.opMeld:
            pos = parentMap[entry.rootVn]
            if pos == -1:
                entry.op = None
            else:
                entry.rootVn = pos

        newMeld: List[RootedOp] = []
        curRoot = -1
        meldPos = 0
        lastBlock = None
        for i in range(cutOff):
            op = path[i].op
            curOp = None
            while meldPos < len(self.opMeld):
                trialOp = self.opMeld[meldPos].op
                if trialOp is None:
                    meldPos += 1
                    continue
                if trialOp.getParent() is not op.getParent():
                    if op.getParent() is lastBlock:
                        curOp = None
                        break
                    elif trialOp.getParent() is not lastBlock:
                        res = self.opMeld[meldPos].rootVn
                        self.opMeld = newMeld
                        return res
                elif trialOp.getSeqNum().getOrder() <= op.getSeqNum().getOrder():
                    curOp = trialOp
                    break
                lastBlock = trialOp.getParent()
                newMeld.append(self.opMeld[meldPos])
                curRoot = self.opMeld[meldPos].rootVn
                meldPos += 1
            if curOp is op:
                newMeld.append(self.opMeld[meldPos])
                curRoot = self.opMeld[meldPos].rootVn
                meldPos += 1
            else:
                newMeld.append(RootedOp(op, curRoot))
            lastBlock = op.getParent()
        self.opMeld = newMeld
        return -1

    def truncatePaths(self, cutPoint: int) -> None:
        """Truncate all paths at the given cut point.

        C++ ref: PathMeld::truncatePaths in jumptable.cc
        """
        while len(self.opMeld) > 1:
            if self.opMeld[-1].rootVn < cutPoint:
                break
            self.opMeld.pop()
        del self.commonVn[cutPoint:]

    def meld(self, path: list) -> None:
        """Add a new path, recalculating common Varnodes.

        C++ ref: PathMeld::meld in jumptable.cc
        """
        parentMap: list = []

        for node in path:
            vn = node.op.getIn(node.slot)
            vn.setMark()
        self.internalIntersect(parentMap)
        cutOff = -1

        for i, node in enumerate(path):
            vn = node.op.getIn(node.slot)
            if not vn.isMark():
                cutOff = i + 1
            else:
                vn.clearMark()
        newCutoff = self.meldOps(path, cutOff, parentMap)
        if newCutoff >= 0:
            self.truncatePaths(newCutoff)
        del path[cutOff:]

    def markPaths(self, val: bool, startVarnode: int) -> None:
        """Mark or unmark all PcodeOps up to the given Varnode index.

        C++ ref: PathMeld::markPaths in jumptable.cc
        """
        startOp = -1
        for i in range(len(self.opMeld) - 1, -1, -1):
            if self.opMeld[i].rootVn == startVarnode:
                startOp = i
                break
        if startOp < 0:
            return
        if val:
            for i in range(startOp + 1):
                self.opMeld[i].op.setMark()
        else:
            for i in range(startOp + 1):
                self.opMeld[i].op.clearMark()


class GuardRecord:
    """A switch variable Varnode and a constraint from a CBRANCH."""

    def __init__(self, cbranch=None, readOp=None, path: int = 0,
                 rng=None, vn=None, unrolled: bool = False) -> None:
        self.cbranch = cbranch
        self.readOp = readOp
        self.vn = vn
        self.indpath: int = path
        self.range = rng._makeCopy()
        bits_preserved_out: list = []
        self.baseVn = self.quasiCopy(vn, bits_preserved_out)
        self.bitsPreserved: int = bits_preserved_out[0]
        self.unrolled: bool = unrolled

    def isUnrolled(self) -> bool:
        return self.unrolled

    def getBranch(self):
        return self.cbranch

    def getReadOp(self):
        return self.readOp

    def getPath(self) -> int:
        return self.indpath

    def getRange(self):
        return self.range

    def clear(self) -> None:
        self.cbranch = None

    @staticmethod
    def oneOffMatch(op1, op2) -> int:
        """Check if two PcodeOps produce the same value via simple duplicate calculation.

        C++ ref: GuardRecord::oneOffMatch in jumptable.cc
        """
        if op1.code() != op2.code():
            return 0
        opc = op1.code()
        from ghidra.core.opcodes import OpCode
        if opc in (OpCode.CPUI_INT_AND, OpCode.CPUI_INT_ADD, OpCode.CPUI_INT_XOR,
                   OpCode.CPUI_INT_OR, OpCode.CPUI_INT_LEFT, OpCode.CPUI_INT_RIGHT,
                   OpCode.CPUI_INT_SRIGHT, OpCode.CPUI_INT_MULT, OpCode.CPUI_SUBPIECE):
            if op2.getIn(0) is not op1.getIn(0):
                return 0
            vn1 = op1.getIn(1)
            vn2 = op2.getIn(1)
            if vn1.isConstant() and vn2.isConstant() and vn1.getOffset() == vn2.getOffset():
                return 1
        return 0

    @staticmethod
    def quasiCopy(vn, bitsPreserved_out: list) -> 'Varnode':
        """Compute the source of a quasi-COPY chain for the given Varnode.

        C++ ref: GuardRecord::quasiCopy in jumptable.cc
        Returns (baseVn, bitsPreserved) as a tuple when called with a list,
        or just baseVn when bitsPreserved_out is provided as a mutable list.
        """
        from ghidra.core.address import mostsigbit_set
        from ghidra.core.opcodes import OpCode
        nzmask = vn.getNZMask()
        bitsPreserved = mostsigbit_set(nzmask) + 1
        if bitsPreserved == 0:
            if isinstance(bitsPreserved_out, list):
                bitsPreserved_out.clear()
                bitsPreserved_out.append(0)
            return vn
        mask = (1 << bitsPreserved) - 1
        op = vn.getDef()
        while op is not None:
            opc = op.code()
            if opc == OpCode.CPUI_COPY:
                vn = op.getIn(0)
                op = vn.getDef()
            elif opc == OpCode.CPUI_INT_AND:
                constVn = op.getIn(1)
                if constVn.isConstant() and constVn.getOffset() == mask:
                    vn = op.getIn(0)
                    op = vn.getDef()
                else:
                    op = None
            elif opc == OpCode.CPUI_INT_OR:
                constVn = op.getIn(1)
                if constVn.isConstant() and ((constVn.getOffset() | mask) == (constVn.getOffset() ^ mask)):
                    vn = op.getIn(0)
                    op = vn.getDef()
                else:
                    op = None
            elif opc in (OpCode.CPUI_INT_SEXT, OpCode.CPUI_INT_ZEXT):
                if op.getIn(0).getSize() * 8 >= bitsPreserved:
                    vn = op.getIn(0)
                    op = vn.getDef()
                else:
                    op = None
            elif opc == OpCode.CPUI_PIECE:
                if op.getIn(1).getSize() * 8 >= bitsPreserved:
                    vn = op.getIn(1)
                    op = vn.getDef()
                else:
                    op = None
            elif opc == OpCode.CPUI_SUBPIECE:
                constVn = op.getIn(1)
                if constVn.isConstant() and constVn.getOffset() == 0:
                    vn = op.getIn(0)
                    op = vn.getDef()
                else:
                    op = None
            else:
                op = None
        if isinstance(bitsPreserved_out, list):
            bitsPreserved_out.clear()
            bitsPreserved_out.append(bitsPreserved)
        return vn

    def valueMatch(self, vn2, baseVn2, bitsPreserved2: int) -> int:
        """Determine if this guard applies to the given Varnode.

        C++ ref: GuardRecord::valueMatch in jumptable.cc
        Returns: 0=no match, 1=same value, 2=same value pending no writes
        """
        from ghidra.core.opcodes import OpCode
        if self.vn is vn2:
            return 1
        if self.bitsPreserved == bitsPreserved2:
            if self.baseVn is baseVn2:
                return 1
            loadOp = self.baseVn.getDef()
            loadOp2 = baseVn2.getDef()
        else:
            loadOp = self.vn.getDef()
            loadOp2 = vn2.getDef()
        if loadOp is None or loadOp2 is None:
            return 0
        if GuardRecord.oneOffMatch(loadOp, loadOp2) == 1:
            return 1
        if loadOp.code() != OpCode.CPUI_LOAD or loadOp2.code() != OpCode.CPUI_LOAD:
            return 0
        if loadOp.getIn(0).getOffset() != loadOp2.getIn(0).getOffset():
            return 0
        ptr = loadOp.getIn(1)
        ptr2 = loadOp2.getIn(1)
        if ptr is ptr2:
            return 2
        if not ptr.isWritten() or not ptr2.isWritten():
            return 0
        addop = ptr.getDef()
        if addop.code() != OpCode.CPUI_INT_ADD:
            return 0
        constvn = addop.getIn(1)
        if not constvn.isConstant():
            return 0
        addop2 = ptr2.getDef()
        if addop2.code() != OpCode.CPUI_INT_ADD:
            return 0
        constvn2 = addop2.getIn(1)
        if not constvn2.isConstant():
            return 0
        if constvn.getOffset() != constvn2.getOffset():
            return 0
        if addop.getIn(0) is addop2.getIn(0):
            return 2
        return 0


class JumpModel:
    """Base class for jump-table execution models."""

    def __init__(self, jt) -> None:
        self.jumptable = jt

    def isOverride(self) -> bool:
        raise NotImplementedError("JumpModel.isOverride must be implemented by subclasses")

    def getTableSize(self) -> int:
        raise NotImplementedError("JumpModel.getTableSize must be implemented by subclasses")

    def recoverModel(self, fd, indop, matchsize: int, maxtablesize: int) -> bool:
        raise NotImplementedError("JumpModel.recoverModel must be implemented by subclasses")

    def buildAddresses(self, fd, indop, addresstable: list,
                       loadpoints=None, loadcounts=None) -> None:
        raise NotImplementedError("JumpModel.buildAddresses must be implemented by subclasses")

    def findUnnormalized(self, maxaddsub: int, maxleftright: int, maxext: int) -> None:
        raise NotImplementedError("JumpModel.findUnnormalized must be implemented by subclasses")

    def buildLabels(self, fd, addresstable: list, label: list, orig=None) -> None:
        raise NotImplementedError("JumpModel.buildLabels must be implemented by subclasses")

    def foldInNormalization(self, fd, indop):
        raise NotImplementedError("JumpModel.foldInNormalization must be implemented by subclasses")

    def foldInGuards(self, fd, jump) -> bool:
        raise NotImplementedError("JumpModel.foldInGuards must be implemented by subclasses")

    def sanityCheck(self, fd, indop, addresstable: list,
                    loadpoints: list = None, loadcounts=None) -> bool:
        raise NotImplementedError("JumpModel.sanityCheck must be implemented by subclasses")

    def clone(self, jt):
        raise NotImplementedError("JumpModel.clone must be implemented by subclasses")

    def clear(self) -> None:
        pass

    def encode(self, encoder) -> None:
        pass

    def decode(self, decoder) -> None:
        pass


class JumpModelTrivial(JumpModel):
    """Trivial model where the BRANCHIND input is the switch variable."""

    def __init__(self, jt) -> None:
        super().__init__(jt)
        self._size: int = 0

    def isOverride(self) -> bool:
        return False

    def getTableSize(self) -> int:
        return self._size

    def recoverModel(self, fd, indop, matchsize: int, maxtablesize: int) -> bool:
        self._size = indop.getParent().sizeOut()
        return self._size != 0 and self._size <= matchsize

    def buildAddresses(self, fd, indop, addresstable, loadpoints=None, loadcounts=None):
        addresstable.clear()
        bl = indop.getParent()
        for i in range(bl.sizeOut()):
            outbl = bl.getOut(i)
            addresstable.append(outbl.getStart())

    def buildLabels(self, fd, addresstable, label, orig):
        for addr in addresstable:
            label.append(addr.getOffset())

    def findUnnormalized(self, maxaddsub: int = 0, maxleftright: int = 0, maxext: int = 0) -> None:
        pass

    def foldInNormalization(self, fd, indop):
        return None

    def foldInGuards(self, fd, jump) -> bool:
        return False

    def sanityCheck(self, fd, indop, addresstable: list,
                    loadpoints: list = None, loadcounts=None) -> bool:
        return True

    def clone(self, jt):
        m = JumpModelTrivial(jt)
        m._size = self._size
        return m


class JumpAssisted(JumpModel):
    """A jump-table model assisted by a jumpassist user-op."""

    def __init__(self, jt) -> None:
        super().__init__(jt)
        self.assistOp = None
        self.userop = None
        self.sizeIndices: int = 0
        self.switchvn = None

    def isOverride(self) -> bool:
        return False

    def getTableSize(self) -> int:
        return self.sizeIndices + 1

    def recoverModel(self, fd, indop, matchsize: int, maxtablesize: int) -> bool:
        from ghidra.arch.userop import UserPcodeOp
        from ghidra.core.opcodes import OpCode

        addrVn = indop.getIn(0)
        if not addrVn.isWritten():
            return False
        self.assistOp = addrVn.getDef()
        if self.assistOp is None:
            return False
        if self.assistOp.code() != OpCode.CPUI_CALLOTHER:
            return False
        if self.assistOp.numInput() < 3:
            return False
        index = self.assistOp.getIn(0).getOffset()
        tmpOp = fd.getArch().userops.getOp(index)
        if tmpOp.getType() != UserPcodeOp.jumpassist:
            return False
        self.userop = tmpOp

        self.switchvn = self.assistOp.getIn(1)
        for i in range(2, self.assistOp.numInput()):
            if not self.assistOp.getIn(i).isConstant():
                return False
        if self.userop.getCalcSize() == -1:
            self.sizeIndices = self.assistOp.getIn(2).getOffset()
        else:
            pcodeScript = fd.getArch().pcodeinjectlib.getPayload(self.userop.getCalcSize())
            inputs = []
            numInputs = self.assistOp.numInput() - 1
            if pcodeScript.sizeInput() != numInputs:
                raise LowlevelError(f"{self.userop.getName()}: <size_pcode> has wrong number of parameters")
            for i in range(numInputs):
                inputs.append(self.assistOp.getIn(i + 1).getOffset())
            self.sizeIndices = pcodeScript.evaluate(inputs)
        if matchsize != 0 and matchsize - 1 != self.sizeIndices:
            return False
        if self.sizeIndices > maxtablesize:
            return False
        return True

    def buildAddresses(self, fd, indop, addresstable, loadpoints, loadcounts) -> None:
        if self.userop.getIndex2Addr() == -1:
            raise LowlevelError("Final index2addr calculation outside of jumpassist")
        pcodeScript = fd.getArch().pcodeinjectlib.getPayload(self.userop.getIndex2Addr())
        addresstable.clear()

        spc = indop.getAddr().getSpace()
        inputs = []
        numInputs = self.assistOp.numInput() - 1
        if pcodeScript.sizeInput() != numInputs:
            raise LowlevelError(f"{self.userop.getName()}: <addr_pcode> has wrong number of parameters")
        for i in range(numInputs):
            inputs.append(self.assistOp.getIn(i + 1).getOffset())

        mask = ~0
        bit = fd.getArch().funcptr_align
        if bit != 0:
            mask = (mask >> bit) << bit
        for index in range(self.sizeIndices):
            inputs[0] = index
            output = pcodeScript.evaluate(inputs)
            output &= mask
            addresstable.append(Address(spc, output))

        defaultScript = fd.getArch().pcodeinjectlib.getPayload(self.userop.getDefaultAddr())
        if defaultScript.sizeInput() != numInputs:
            raise LowlevelError(f"{self.userop.getName()}: <default_pcode> has wrong number of parameters")
        inputs[0] = 0
        defaultAddress = defaultScript.evaluate(inputs)
        addresstable.append(Address(spc, defaultAddress))

    def findUnnormalized(self, maxaddsub: int, maxleftright: int, maxext: int) -> None:
        pass

    def buildLabels(self, fd, addresstable, label, orig) -> None:
        if orig.sizeIndices != self.sizeIndices:
            raise LowlevelError("JumpAssisted table size changed during recovery")
        if self.userop.getIndex2Case() == -1:
            for i in range(self.sizeIndices):
                label.append(i)
        else:
            pcodeScript = fd.getArch().pcodeinjectlib.getPayload(self.userop.getIndex2Case())
            inputs = []
            numInputs = self.assistOp.numInput() - 1
            if numInputs != pcodeScript.sizeInput():
                raise LowlevelError(f"{self.userop.getName()}: <case_pcode> has wrong number of parameters")
            for i in range(numInputs):
                inputs.append(self.assistOp.getIn(i + 1).getOffset())

            for index in range(self.sizeIndices):
                inputs[0] = index
                output = pcodeScript.evaluate(inputs)
                label.append(output)
        label.append(JumpValues.NO_LABEL)

    def foldInNormalization(self, fd, indop):
        outvn = self.assistOp.getOut()
        for op in list(outvn.beginDescend()):
            fd.opSetInput(op, self.switchvn, 0)
        fd.opDestroy(self.assistOp)
        return self.switchvn

    def foldInGuards(self, fd, jump) -> bool:
        origVal = jump.getDefaultBlock()
        jump.setLastAsDefault()
        return origVal != jump.getDefaultBlock()

    def sanityCheck(self, fd, indop, addresstable, loadpoints, loadcounts) -> bool:
        return True

    def clone(self, jt):
        clone = JumpAssisted(jt)
        clone.userop = self.userop
        clone.sizeIndices = self.sizeIndices
        return clone

    def clear(self) -> None:
        self.assistOp = None
        self.switchvn = None


class JumpTable:
    """A map from switch variable values to control-flow targets.

    Attached to a CPUI_BRANCHIND, encapsulates all info to model
    the indirect jump as a switch statement.
    """

    # Recovery status
    success = 0
    fail_normal = 1
    fail_thunk = 2
    fail_return = 3
    fail_callother = 4

    def __init__(self, glb=None, addr: Optional[Address] = None) -> None:
        if isinstance(glb, JumpTable) and addr is None:
            op2 = glb
            self.glb = op2.glb
            self.opaddress = op2.opaddress
            self.indirect = None
            self.jmodel = None
            self.origmodel = None
            self.addresstable = list(op2.addresstable)
            self.label = []
            self.loadpoints = list(op2.loadpoints)
            self.defaultBlock = -1
            self.lastBlock = op2.lastBlock
            self.switchVarConsume = 0xFFFFFFFFFFFFFFFF
            self.maxaddsub = op2.maxaddsub
            self.maxleftright = op2.maxleftright
            self.maxext = op2.maxext
            self.partialTable = op2.partialTable
            self.collectloads = op2.collectloads
            self.defaultIsFolded = False
            self.block2addr = []
            if op2.jmodel is not None:
                self.jmodel = op2.jmodel.clone(self)
            return
        self.glb = glb
        self.opaddress: Address = addr if addr is not None else Address()
        self.indirect = None  # PcodeOp
        self.jmodel: Optional[JumpModel] = None
        self.origmodel: Optional[JumpModel] = None
        self.addresstable: List[Address] = []
        self.label: List[int] = []
        self.loadpoints: List[LoadTable] = []
        self.defaultBlock: int = -1
        self.lastBlock: int = -1
        self.switchVarConsume: int = 0xFFFFFFFFFFFFFFFF
        self.maxaddsub: int = 1
        self.maxleftright: int = 1
        self.maxext: int = 1
        self.partialTable: bool = False
        self.collectloads: bool = False
        self.defaultIsFolded: bool = False
        self.block2addr: List[IndexPair] = []

    def __del__(self) -> None:
        self.jmodel = None
        self.origmodel = None

    def isRecovered(self) -> bool:
        return len(self.addresstable) > 0

    def isLabelled(self) -> bool:
        return len(self.label) > 0

    def isOverride(self) -> bool:
        return self.jmodel is not None and self.jmodel.isOverride()

    def isPartial(self) -> bool:
        return self.partialTable

    def markComplete(self) -> None:
        self.partialTable = False

    def numEntries(self) -> int:
        return len(self.addresstable)

    def getSwitchVarConsume(self) -> int:
        return self.switchVarConsume

    def getDefaultBlock(self) -> int:
        return self.defaultBlock

    def getOpAddress(self) -> Address:
        return self.opaddress

    def getIndirectOp(self):
        return self.indirect

    def setIndirectOp(self, ind) -> None:
        self.opaddress = ind.getAddr()
        self.indirect = ind

    def setNormMax(self, maddsub: int, mleftright: int, mext: int) -> None:
        self.maxaddsub = maddsub
        self.maxleftright = mleftright
        self.maxext = mext

    def setLastAsDefault(self) -> None:
        self.defaultBlock = self.lastBlock

    def setDefaultBlock(self, bl: int) -> None:
        self.defaultBlock = bl

    def setLoadCollect(self, val: bool) -> None:
        self.collectloads = val

    def setFoldedDefault(self) -> None:
        self.defaultIsFolded = True

    def hasFoldedDefault(self) -> bool:
        return self.defaultIsFolded

    def getAddressByIndex(self, i: int) -> Address:
        return self.addresstable[i]

    def getLabelByIndex(self, i: int) -> int:
        return self.label[i]

    def block2Position(self, bl) -> int:
        """Get the out-edge position of the given block relative to the switch parent.

        C++ ref: ``JumpTable::block2Position``
        """
        parent = self.indirect.getParent()
        for position in range(bl.sizeIn()):
            if bl.getIn(position) is parent:
                return bl.getInRevIndex(position)
        raise LowlevelError("Requested block, not in jumptable")

    @staticmethod
    def isReachable(op) -> bool:
        """Check if the given op is still reachable after collapsed guards.

        C++ ref: ``JumpTable::isReachable``
        """
        from ghidra.core.opcodes import OpCode

        parent = op.getParent()
        for _ in range(2):
            if parent.sizeIn() != 1:
                return True
            bl = parent.getIn(0)
            if bl.sizeOut() != 2:
                continue
            cbranch = bl.lastOp()
            if cbranch is None or cbranch.code() != OpCode.CPUI_CBRANCH:
                continue
            vn = cbranch.getIn(1)
            if not vn.isConstant():
                continue
            trueslot = 0 if cbranch.isBooleanFlip() else 1
            if vn.getOffset() == 0:
                trueslot = 1 - trueslot
            if bl.getOut(trueslot) is not parent:
                return False
            parent = bl
        return True

    def numIndicesByBlock(self, bl) -> int:
        """Count the number of address table entries targeting the given block.

        C++ ref: ``JumpTable::numIndicesByBlock``
        """
        pos = self.block2Position(bl)
        left = bisect_left(self.block2addr, IndexPair(pos, -1))
        right = bisect_left(self.block2addr, IndexPair(pos + 1, -1))
        return right - left

    def getIndexByBlock(self, bl, i: int) -> int:
        """Get the i-th address table index for the given block.

        C++ ref: ``JumpTable::getIndexByBlock``
        """
        pos = self.block2Position(bl)
        idx = bisect_left(self.block2addr, IndexPair(pos, 0))
        count = 0
        while idx < len(self.block2addr):
            ip = self.block2addr[idx]
            if ip.blockPosition != pos:
                break
            if count == i:
                return ip.addressIndex
            count += 1
            idx += 1
        raise LowlevelError("Could not get jumptable index for block")

    def recoverAddresses(self, fd) -> None:
        """Recover the raw jump-table addresses."""
        from ghidra.core.error import LowlevelError

        self.recoverModel(fd)
        if self.jmodel is None:
            raise LowlevelError(f"Could not recover jumptable at {self.opaddress}. Too many branches")
        if self.jmodel.getTableSize() == 0:
            raise LowlevelError(f"Jumptable with 0 entries at {self.opaddress}")
        if self.collectloads:
            loadcounts: list[int] = []
            self.jmodel.buildAddresses(fd, self.indirect, self.addresstable, self.loadpoints, loadcounts)
            self.sanityCheck(fd, loadcounts)
            LoadTable.collapseTable(self.loadpoints)
        else:
            self.jmodel.buildAddresses(fd, self.indirect, self.addresstable, None, None)
            self.sanityCheck(fd, None)

    def recoverLabels(self, fd) -> None:
        """Recover case labels for this jump-table."""
        if self.jmodel is not None:
            if self.origmodel is None or self.origmodel.getTableSize() == 0:
                self.jmodel.findUnnormalized(self.maxaddsub, self.maxleftright, self.maxext)
                self.jmodel.buildLabels(fd, self.addresstable, self.label, self.jmodel)
            else:
                self.jmodel.findUnnormalized(self.maxaddsub, self.maxleftright, self.maxext)
                self.jmodel.buildLabels(fd, self.addresstable, self.label, self.origmodel)
        else:
            self.jmodel = JumpModelTrivial(self)
            self.jmodel.recoverModel(fd, self.indirect, len(self.addresstable), self.glb.max_jumptable_size)
            self.jmodel.buildAddresses(fd, self.indirect, self.addresstable, None, None)
            self.trivialSwitchOver()
            self.jmodel.buildLabels(fd, self.addresstable, self.label, self.origmodel)
        self.clearSavedModel()

    def foldInNormalization(self, fd) -> None:
        """Hide the normalization code."""
        from ghidra.core.address import calc_mask, minimalmask
        from ghidra.core.opcodes import OpCode

        switchvn = self.jmodel.foldInNormalization(fd, self.indirect)
        if switchvn is None:
            return

        self.switchVarConsume = minimalmask(switchvn.getNZMask())
        if self.switchVarConsume >= calc_mask(switchvn.getSize()):
            if switchvn.isWritten():
                op = switchvn.getDef()
                if op.code() == OpCode.CPUI_INT_SEXT:
                    self.switchVarConsume = calc_mask(op.getIn(0).getSize())

    def foldInGuards(self, fd) -> bool:
        return self.jmodel.foldInGuards(fd, self)

    def getLastBlock(self) -> int:
        return self.lastBlock

    def getModel(self):
        return self.jmodel

    def setModel(self, model) -> None:
        self.jmodel = model

    def getLoadTable(self) -> list:
        return self.loadpoints

    def isBadJumpTable(self) -> bool:
        return getattr(self, '_badJumpTable', False)

    def setBadJumpTable(self, val: bool) -> None:
        self._badJumpTable = val

    def checkForMultistage(self, fd) -> bool:
        """Check if this jump-table needs multistage recovery."""
        if len(self.addresstable) != 1:
            return False
        if self.partialTable:
            return False
        if self.indirect is None:
            return False

        if fd.getOverride().queryMultistageJumptable(self.indirect.getAddr()):
            self.partialTable = True
            return True
        return False

    def switchOver(self, flow) -> None:
        """Convert jump-table addresses to basic block indices.

        The address table entries are converted to out-edge indices of the
        parent block of the BRANCHIND. The most common target becomes the
        default block.

        C++ ref: ``JumpTable::switchOver``
        """
        self.block2addr.clear()
        parent = self.indirect.getParent()

        for i, addr in enumerate(self.addresstable):
            op = flow.target(addr)
            tmpbl = op.getParent()
            for pos in range(parent.sizeOut()):
                if parent.getOut(pos) is tmpbl:
                    break
            else:
                raise LowlevelError("Jumptable destination not linked")
            self.block2addr.append(IndexPair(pos, i))

        self.lastBlock = self.block2addr[-1].blockPosition
        self.block2addr.sort()

        # Find the most common block position -> default block
        self.defaultBlock = -1
        maxcount = 1  # Only set default if count >= 2
        idx = 0
        while idx < len(self.block2addr):
            curPos = self.block2addr[idx].blockPosition
            count = 0
            while idx < len(self.block2addr) and self.block2addr[idx].blockPosition == curPos:
                count += 1
                idx += 1
            if count > maxcount:
                maxcount = count
                self.defaultBlock = curPos

    def recoverModel(self, fd) -> None:
        """Recover the model for this jump-table."""
        from ghidra.core.opcodes import OpCode

        max_jumptable_size = self.glb.max_jumptable_size
        matchsize = len(self.addresstable)

        if self.jmodel is not None:
            if self.jmodel.isOverride():
                self.jmodel.recoverModel(fd, self.indirect, 0, max_jumptable_size)
                return
            self.jmodel = None

        vn = self.indirect.getIn(0)
        if vn.isWritten():
            op = vn.getDef()
            if op.code() == OpCode.CPUI_CALLOTHER:
                self.jmodel = JumpAssisted(self)
                if self.jmodel.recoverModel(fd, self.indirect, matchsize, max_jumptable_size):
                    return

        jbasic = JumpBasic(self)
        self.jmodel = jbasic
        if self.jmodel.recoverModel(fd, self.indirect, matchsize, max_jumptable_size):
            return

        jbasic2 = JumpBasic2(self)
        jbasic2.initializeStart(jbasic.getPathMeld())
        self.jmodel = jbasic2
        if self.jmodel.recoverModel(fd, self.indirect, matchsize, max_jumptable_size):
            return

        self.jmodel = None

    def sanityCheck(self, fd, loadcounts=None) -> None:
        """Verify the recovered jump-table."""
        if self.jmodel.isOverride():
            return

        sz = len(self.addresstable)
        if not JumpTable.isReachable(self.indirect):
            self.partialTable = True

        if len(self.addresstable) == 1:
            isthunk = False
            addr = self.addresstable[0]
            if addr.getOffset() == 0:
                isthunk = True
            else:
                addr2 = self.indirect.getAddr()
                diff = abs(addr.getOffset() - addr2.getOffset())
                if diff > 0xFFFF:
                    isthunk = True
            if isthunk:
                raise JumptableThunkError("Likely thunk")

        if not self.jmodel.sanityCheck(fd, self.indirect, self.addresstable, self.loadpoints, loadcounts):
            raise LowlevelError(f"Jumptable at {self.opaddress} did not pass sanity check.")
        if sz != len(self.addresstable):
            fd.warning("Sanity check requires truncation of jumptable", self.opaddress)

    def trivialSwitchOver(self) -> None:
        """Simple switch-over when table is already complete.

        Make exactly one case for each output edge of the switch block.

        C++ ref: ``JumpTable::trivialSwitchOver``
        """
        from ghidra.core.error import LowlevelError

        self.block2addr.clear()
        parent = self.indirect.getParent()
        numOut = parent.sizeOut()
        if numOut != len(self.addresstable):
            raise LowlevelError("Trivial addresstable and switch block size do not match")
        for i in range(numOut):
            self.block2addr.append(IndexPair(i, i))
        self.lastBlock = numOut - 1
        self.defaultBlock = -1

    def recoverMultistage(self, fd) -> None:
        """Attempt multistage recovery."""
        self.saveModel()

        oldaddresstable = list(self.addresstable)
        self.addresstable.clear()
        self.loadpoints.clear()
        try:
            self.recoverAddresses(fd)
        except (JumptableThunkError, LowlevelError):
            self.restoreSavedModel()
            self.addresstable = oldaddresstable
            fd.warning("Second-stage recovery error", self.indirect.getAddr())
        self.partialTable = False
        self.clearSavedModel()

    def encode(self, encoder) -> None:
        """Encode this jump-table as a <jumptable> element.

        C++ ref: ``JumpTable::encode``
        """
        from ghidra.core.marshal import (
            ELEM_JUMPTABLE, ELEM_DEST, ATTRIB_LABEL,
        )
        if not self.isRecovered():
            raise LowlevelError("Trying to save unrecovered jumptable")
        encoder.openElement(ELEM_JUMPTABLE)
        self.opaddress.encode(encoder)
        for i, addr in enumerate(self.addresstable):
            encoder.openElement(ELEM_DEST)
            spc = addr.getSpace()
            off = addr.getOffset()
            if spc is not None:
                spc.encodeAttributes(encoder, off)
            if i < len(self.label):
                if self.label[i] != JumpValues.NO_LABEL:
                    encoder.writeUnsignedInteger(ATTRIB_LABEL, self.label[i])
            encoder.closeElement(ELEM_DEST)
        for lp in self.loadpoints:
            lp.encode(encoder)
        if self.jmodel is not None and self.jmodel.isOverride():
            self.jmodel.encode(encoder)
        encoder.closeElement(ELEM_JUMPTABLE)

    def decode(self, decoder) -> None:
        """Decode this jump-table from a <jumptable> element.

        C++ ref: ``JumpTable::decode``
        """
        from ghidra.core.marshal import (
            ELEM_JUMPTABLE, ELEM_DEST, ELEM_LOADTABLE,
            ELEM_BASICOVERRIDE, ATTRIB_LABEL,
        )
        elemId = decoder.openElement(ELEM_JUMPTABLE)
        self.opaddress = Address.decode(decoder)
        missedlabel = False
        while True:
            subId = decoder.peekElement()
            if subId == 0:
                break
            if subId == ELEM_DEST.id:
                decoder.openElement()
                foundlabel = False
                while True:
                    attribId = decoder.getNextAttributeId()
                    if attribId == 0:
                        break
                    if attribId == ATTRIB_LABEL.id:
                        if missedlabel:
                            raise LowlevelError("Jumptable entries are missing labels")
                        lab = decoder.readUnsignedInteger()
                        self.label.append(lab)
                        foundlabel = True
                        break
                if not foundlabel:
                    missedlabel = True
                addr = Address.decode(decoder)
                self.addresstable.append(addr)
            elif subId == ELEM_LOADTABLE.id:
                lp = LoadTable()
                lp.decode(decoder)
                self.loadpoints.append(lp)
            elif subId == ELEM_BASICOVERRIDE.id:
                if self.jmodel is not None:
                    raise LowlevelError("Duplicate jumptable override specs")
                self.jmodel = JumpBasicOverride(self)
                self.jmodel.decode(decoder)
        decoder.closeElement(elemId)
        if self.label:
            while len(self.label) < len(self.addresstable):
                self.label.append(JumpValues.NO_LABEL)

    def setOverride(self, addrtable: list, naddr, h: int, sv: int) -> None:
        """Force a manual override of the jump-table addresses."""
        override = JumpBasicOverride(self)
        self.jmodel = override
        override.setAddresses(addrtable)
        override.setNorm(naddr, h)
        override.setStartingValue(sv)

    def addBlockToSwitch(self, bl, lab: int) -> None:
        """Force a given basic-block to be a switch destination."""
        self.addresstable.append(bl.getStart())
        self.lastBlock = self.indirect.getParent().sizeOut()
        self.block2addr.append(IndexPair(self.lastBlock, len(self.addresstable) - 1))
        self.label.append(lab)

    def saveModel(self) -> None:
        if self.origmodel is not None:
            self.origmodel = None
        self.origmodel = self.jmodel
        self.jmodel = None

    def restoreSavedModel(self) -> None:
        self.jmodel = self.origmodel
        self.origmodel = None

    def clearSavedModel(self) -> None:
        self.origmodel = None

    def matchModel(self, fd) -> None:
        """Try to match JumpTable model to the existing function."""
        from ghidra.core.error import LowlevelError

        if not self.isRecovered():
            raise LowlevelError("Trying to recover jumptable labels without addresses")

        if self.jmodel is not None:
            if not self.jmodel.isOverride():
                self.saveModel()
            else:
                self.clearSavedModel()
                fd.warning("Switch is manually overridden", self.opaddress)

        self.recoverModel(fd)
        if self.jmodel is not None and self.jmodel.getTableSize() != len(self.addresstable):
            if len(self.addresstable) == 1 and self.jmodel.getTableSize() > 1:
                fd.getOverride().insertMultistageJump(self.opaddress)
                fd.setRestartPending(True)
                return
            fd.warning("Could not find normalized switch variable to match jumptable", self.opaddress)

    def clear(self) -> None:
        self.clearSavedModel()
        if self.jmodel.isOverride():
            self.jmodel.clear()
        else:
            self.jmodel = None
        self.addresstable.clear()
        self.block2addr.clear()
        self.lastBlock = -1
        self.label.clear()
        self.loadpoints.clear()
        self.indirect = None
        self.switchVarConsume = 0xFFFFFFFFFFFFFFFF
        self.defaultBlock = -1
        self.partialTable = False


# RecoveryMode as class-level enum on JumpTable
JumpTable.RecoveryMode = type('RecoveryMode', (), {
    'success': 0,
    'fail_normal': 1,
    'fail_thunk': 2,
    'fail_return': 3,
    'fail_callother': 4,
})


class JumptableThunkError(LowlevelError):
    """Exception thrown for a thunk mechanism that looks like a jump-table."""


class JumpValues:
    """An iterator over values a switch variable can take."""
    NO_LABEL = 0xBAD1ABE1BAD1ABE1

    def truncate(self, nm: int) -> None:
        raise NotImplementedError("JumpValues.truncate must be implemented by subclasses")

    def getSize(self) -> int:
        raise NotImplementedError("JumpValues.getSize must be implemented by subclasses")

    def contains(self, val: int) -> bool:
        raise NotImplementedError("JumpValues.contains must be implemented by subclasses")

    def initializeForReading(self) -> bool:
        raise NotImplementedError("JumpValues.initializeForReading must be implemented by subclasses")

    def next(self) -> bool:
        raise NotImplementedError("JumpValues.next must be implemented by subclasses")

    def getValue(self) -> int:
        raise NotImplementedError("JumpValues.getValue must be implemented by subclasses")

    def getStartVarnode(self):
        raise NotImplementedError("JumpValues.getStartVarnode must be implemented by subclasses")

    def getStartOp(self):
        raise NotImplementedError("JumpValues.getStartOp must be implemented by subclasses")

    def isReversible(self) -> bool:
        raise NotImplementedError("JumpValues.isReversible must be implemented by subclasses")

    def clone(self):
        raise NotImplementedError("JumpValues.clone must be implemented by subclasses")


class JumpValuesRange(JumpValues):
    """Single entry switch variable that can take a range of values."""

    def __init__(self) -> None:
        from ghidra.analysis.rangeutil import CircleRange
        self.range = CircleRange()
        self.normqvn = None
        self.startop = None
        self._curval: int = 0

    def setRange(self, rng) -> None:
        self.range = rng._makeCopy()

    def setStartVn(self, vn) -> None:
        self.normqvn = vn

    def setStartOp(self, op) -> None:
        self.startop = op

    def truncate(self, nm: int) -> None:
        from ghidra.core.address import count_leading_zeros

        range_size = 64 - count_leading_zeros(self.range.getMask())
        range_size >>= 3
        left = self.range.getMin()
        step = self.range.getStep()
        right = (left + step * nm) & self.range.getMask()
        self.range.setRange(left, right, range_size, step)

    def getSize(self) -> int:
        return self.range.getSize()

    def contains(self, val: int) -> bool:
        return self.range.contains(val)

    def initializeForReading(self) -> bool:
        if self.range.getSize() == 0:
            return False
        self._curval = self.range.getMin()
        return True

    def next(self) -> bool:
        self._curval, still_in = self.range.getNext(self._curval)
        return still_in

    def getValue(self) -> int:
        return self._curval

    def getStartVarnode(self):
        return self.normqvn

    def getStartOp(self):
        return self.startop

    def isReversible(self) -> bool:
        return True

    def clone(self):
        r = JumpValuesRange()
        r.range = self.range._makeCopy()
        r.normqvn = self.normqvn
        r.startop = self.startop
        return r


class JumpValuesRangeDefault(JumpValuesRange):
    """A jump-table starting range with two possible execution paths."""

    def __init__(self) -> None:
        super().__init__()
        self._extravalue: int = 0
        self._extravn = None
        self._extraop = None
        self._lastvalue: bool = False

    def setExtraValue(self, val: int) -> None:
        self._extravalue = val

    def setDefaultVn(self, vn) -> None:
        self._extravn = vn

    def setDefaultOp(self, op) -> None:
        self._extraop = op

    def getSize(self) -> int:
        return super().getSize() + 1

    def contains(self, val: int) -> bool:
        if val == self._extravalue:
            return True
        return super().contains(val)

    def initializeForReading(self) -> bool:
        if self.range.getSize() == 0:
            self._curval = self._extravalue
            self._lastvalue = True
        else:
            self._curval = self.range.getMin()
            self._lastvalue = False
        return True

    def next(self) -> bool:
        if self._lastvalue:
            return False
        result = super().next()
        if not result:
            self._lastvalue = True
            self._curval = self._extravalue
            return True
        return True

    def getStartVarnode(self):
        if self._lastvalue:
            return self._extravn
        return self.normqvn

    def getStartOp(self):
        if self._lastvalue:
            return self._extraop
        return self.startop

    def isReversible(self) -> bool:
        return not self._lastvalue

    def clone(self):
        r = JumpValuesRangeDefault()
        r.range = self.range._makeCopy()
        r.normqvn = self.normqvn
        r.startop = self.startop
        r._extravalue = self._extravalue
        r._extravn = self._extravn
        r._extraop = self._extraop
        return r


class EmulateFunction:
    """A light-weight emulator to calculate switch targets from switch variables."""

    def __init__(self, fd=None) -> None:
        from ghidra.emulate.emulateutil import EmulatePcodeOp

        class _JumpTableEmulator(EmulatePcodeOp):
            def __init__(self, outer, fd):
                super().__init__(fd.getArch())
                self._outer = outer

            def getVarnodeValue(self, vn) -> int:
                return self._outer.getVarnodeValue(vn)

            def setVarnodeValue(self, vn, val: int) -> None:
                self._outer.setVarnodeValue(vn, val)

            def fallthruOp(self) -> None:
                self.lastOp = self.currentOp
                self._outer._lastOp = self.currentOp

            def executeBranch(self) -> None:
                from ghidra.core.error import LowlevelError

                raise LowlevelError("Branch encountered emulating jumptable calculation")

            def executeBranchind(self) -> None:
                from ghidra.core.error import LowlevelError

                raise LowlevelError("Indirect branch encountered emulating jumptable calculation")

            def executeCall(self) -> None:
                self.fallthruOp()

            def executeCallind(self) -> None:
                self.fallthruOp()

            def executeCallother(self) -> None:
                self.fallthruOp()

            def executeLoad(self) -> None:
                from ghidra.core.address import Address

                if self._outer._loadpoints is not None:
                    off = self.getVarnodeValue(self.currentOp.getIn(1))
                    spc = self.currentOp.getIn(0).getSpaceFromConst()
                    from ghidra.core.space import AddrSpace as _AddrSpace
                    off = _AddrSpace.addressToByte(off, spc.getWordSize())
                    sz = self.currentOp.getOut().getSize()
                    self._outer._loadpoints.append(LoadTable(Address(spc, off), sz))
                super().executeLoad()

        self._fd = fd
        self._varnodeMap: dict = {}
        self._loadpoints = None
        self._lastOp = None
        self._emu = _JumpTableEmulator(self, fd) if fd is not None else None

    def setLoadCollect(self, val) -> None:
        self._loadpoints = val

    def getVarnodeValue(self, vn) -> int:
        if vn.isConstant():
            return vn.getOffset()
        if vn in self._varnodeMap:
            return self._varnodeMap[vn]
        return self._emu.getLoadImageValue(vn.getSpace(), vn.getOffset(), vn.getSize())

    def setVarnodeValue(self, vn, val: int) -> None:
        self._varnodeMap[vn] = val

    def setExecuteAddress(self, addr: Address) -> None:
        from ghidra.core.error import LowlevelError

        if not addr.getSpace().hasPhysical():
            raise LowlevelError("Bad execute address")
        current_op = self._fd.target(addr)
        if current_op is None:
            raise LowlevelError("Could not set execute address")
        self._emu.setCurrentOp(current_op)

    def emulatePath(self, val: int, pathMeld, startop, startvn) -> int:
        """Emulate a path through the function, returning the destination address offset."""
        from ghidra.arch.loadimage import DataUnavailError
        from ghidra.core.error import LowlevelError
        from ghidra.core.opcodes import OpCode

        i = 0
        while i < pathMeld.numOps():
            if pathMeld.getOp(i) is startop:
                break
            i += 1
        if startop.code() == OpCode.CPUI_MULTIEQUAL:
            j = 0
            while j < startop.numInput():
                if startop.getIn(j) is startvn:
                    break
                j += 1
            if j == startop.numInput() or i == 0:
                raise LowlevelError("Cannot start jumptable emulation with unresolved MULTIEQUAL")
            startvn = startop.getOut()
            i -= 1
            startop = pathMeld.getOp(i)
        if i == pathMeld.numOps():
            raise LowlevelError("Bad jumptable emulation")
        if not startvn.isConstant():
            self.setVarnodeValue(startvn, val)
        self._emu.lastOp = self._lastOp
        while i > 0:
            curop = pathMeld.getOp(i)
            i -= 1
            self._emu.setCurrentOp(curop)
            try:
                self._emu.executeCurrentOp()
            except DataUnavailError:
                raise LowlevelError(f"Could not emulate address calculation at {curop.getAddr()}")
        self._lastOp = self._emu.lastOp
        invn = pathMeld.getOp(0).getIn(0)
        return self.getVarnodeValue(invn)


class JumpBasic(JumpModel):
    """The basic jump-table model: a normalized switch variable with a linear map to addresses.

    C++ ref: JumpBasic in jumptable.hh / jumptable.cc
    """

    def __init__(self, jt) -> None:
        super().__init__(jt)
        self.pathMeld = PathMeld()
        self.jrange: Optional[JumpValuesRange] = None
        self.selectguards: List[GuardRecord] = []
        self.varnodeIndex: int = 0
        self.normalvn = None  # Varnode: the normalized switch variable
        self.switchvn = None  # Varnode: the unnormalized switch variable

    def getPathMeld(self):
        return self.pathMeld

    def getValueRange(self):
        return self.jrange

    def __del__(self) -> None:
        self.jrange = None

    def isOverride(self) -> bool:
        return False

    def getTableSize(self) -> int:
        return self.jrange.getSize()

    # ------------------------------------------------------------------
    # Static helpers
    # ------------------------------------------------------------------
    @staticmethod
    def isprune(vn) -> bool:
        """Test if the search should be pruned at this Varnode.

        C++ ref: JumpBasic::isprune in jumptable.cc
        """
        if not vn.isWritten():
            return True
        op = vn.getDef()
        if op.isCall() or op.isMarker():
            return True
        if op.numInput() == 0:
            return True
        return False

    @staticmethod
    def ispoint(vn) -> bool:
        """Test if Varnode could possibly be the switch variable.

        C++ ref: JumpBasic::ispoint in jumptable.cc
        """
        if vn.isConstant():
            return False
        if vn.isAnnotation():
            return False
        if vn.isReadOnly():
            return False
        return True

    @staticmethod
    def getStride(vn) -> int:
        """Calculate stride from known-zero least-significant bits.

        C++ ref: JumpBasic::getStride in jumptable.cc
        """
        mask = vn.getNZMask()
        if (mask & 0x3f) == 0:
            return 32
        stride = 1
        while (mask & 1) == 0:
            mask >>= 1
            stride <<= 1
        return stride

    @staticmethod
    def getMaxValue(vn) -> int:
        """Get maximum value from INT_AND masking, or 0 if unrestricted.

        C++ ref: JumpBasic::getMaxValue in jumptable.cc
        """
        from ghidra.core.opcodes import OpCode
        from ghidra.core.address import coveringmask, calc_mask
        maxValue = 0
        if not vn.isWritten():
            return maxValue
        op = vn.getDef()
        if op.code() == OpCode.CPUI_INT_AND:
            constvn = op.getIn(1)
            if constvn.isConstant():
                maxValue = coveringmask(constvn.getOffset())
                maxValue = (maxValue + 1) & calc_mask(vn.getSize())
        elif op.code() == OpCode.CPUI_MULTIEQUAL:
            i = 0
            for i in range(op.numInput()):
                subvn = op.getIn(i)
                if not subvn.isWritten():
                    break
                andOp = subvn.getDef()
                if andOp.code() != OpCode.CPUI_INT_AND:
                    break
                cv = andOp.getIn(1)
                if not cv.isConstant():
                    break
                if maxValue < cv.getOffset():
                    maxValue = cv.getOffset()
            else:
                i = op.numInput()  # All inputs matched
            if i == op.numInput():
                maxValue = coveringmask(maxValue)
                maxValue = (maxValue + 1) & calc_mask(vn.getSize())
            else:
                maxValue = 0
        return maxValue

    @staticmethod
    def backup2Switch(fd, output: int, outvn, invn) -> int:
        """Back up a constant value from output Varnode to input Varnode.

        C++ ref: JumpBasic::backup2Switch in jumptable.cc
        """
        from ghidra.emulate.memstate import MemoryImage
        from ghidra.ir.op import PcodeOp

        curvn = outvn
        while curvn is not invn:
            op = curvn.getDef()
            top = op.getOpcode()
            # Find first non-constant input
            slot = 0
            for slot in range(op.numInput()):
                if not op.getIn(slot).isConstant():
                    break
            evalType = op.getEvalType()
            if evalType == PcodeOp.binary:
                otherslot = 1 - slot
                otherAddr = op.getIn(otherslot).getAddr()
                if not otherAddr.isConstant():
                    mem = MemoryImage(otherAddr.getSpace(), 4, 1024, fd.getArch().loader)
                    otherval = mem.getValue(otherAddr.getOffset(), op.getIn(otherslot).getSize())
                else:
                    otherval = otherAddr.getOffset()
                output = top.recoverInputBinary(
                    slot,
                    op.getOut().getSize(),
                    output,
                    op.getIn(slot).getSize(),
                    otherval,
                )
                curvn = op.getIn(slot)
            elif evalType == PcodeOp.unary:
                output = top.recoverInputUnary(
                    op.getOut().getSize(),
                    output,
                    op.getIn(slot).getSize(),
                )
                curvn = op.getIn(slot)
            else:
                raise LowlevelError("Bad switch normalization op")
        return output

    @staticmethod
    def duplicateVarnodes(arr: list) -> bool:
        """Check if all Varnodes in array are identical.

        C++ ref: JumpBasic::duplicateVarnodes in jumptable.cc
        """
        if not arr:
            return True
        vn = arr[0]
        for i in range(1, len(arr)):
            if arr[i] is not vn:
                return False
        return True

    # ------------------------------------------------------------------
    # Path / guard analysis
    # ------------------------------------------------------------------
    def findDeterminingVarnodes(self, op, slot: int) -> None:
        """Calculate the initial set of Varnodes that might be switch variables.

        C++ ref: JumpBasic::findDeterminingVarnodes in jumptable.cc
        """
        from ghidra.core.expression import PcodeOpNode
        path = [PcodeOpNode(op, slot)]
        firstpoint = False

        while True:
            node = path[-1]
            curvn = node.op.getIn(node.slot)
            if JumpBasic.isprune(curvn):
                if JumpBasic.ispoint(curvn):
                    if not firstpoint:
                        self.pathMeld.set(path)
                        firstpoint = True
                    else:
                        self.pathMeld.meld(path)
                path[-1].slot += 1
                while path[-1].slot >= path[-1].op.numInput():
                    path.pop()
                    if not path:
                        break
                    path[-1].slot += 1
            else:
                path.append(PcodeOpNode(curvn.getDef(), 0))
            if len(path) <= 1:
                break

        if self.pathMeld.empty():
            self.pathMeld.set(op, op.getIn(slot))

    def analyzeGuards(self, bl, pathout: int) -> None:
        """Analyze CBRANCH guards leading to the switch block.

        C++ ref: JumpBasic::analyzeGuards in jumptable.cc
        """
        from ghidra.core.opcodes import OpCode
        from ghidra.analysis.rangeutil import CircleRange
        maxbranch = 2
        maxpullback = 2
        usenzmask = not self.jumptable.isPartial()

        self.selectguards.clear()

        for i in range(maxbranch):
            if pathout >= 0 and bl.sizeOut() == 2:
                prevbl = bl
                bl = prevbl.getOut(pathout)
                indpath = pathout
                pathout = -1
            else:
                pathout = -1
                while True:
                    if bl.sizeIn() != 1:
                        if bl.sizeIn() > 1:
                            self.checkUnrolledGuard(bl, maxpullback, usenzmask)
                        return
                    prevbl = bl.getIn(0)
                    if prevbl.sizeOut() != 1:
                        break
                    bl = prevbl
                indpath = bl.getInRevIndex(0)

            cbranch = prevbl.lastOp()
            if cbranch is None or cbranch.code() != OpCode.CPUI_CBRANCH:
                break
            if i != 0:
                otherbl = prevbl.getOut(1 - indpath)
                otherop = otherbl.lastOp()
                if otherop is not None and otherop.code() == OpCode.CPUI_BRANCHIND:
                    if otherop is not self.jumptable.getIndirectOp():
                        break

            toswitchval = (indpath == 1)
            if cbranch.isBooleanFlip():
                toswitchval = not toswitchval
            bl = prevbl
            vn = cbranch.getIn(1)
            rng = CircleRange.fromBool(toswitchval)

            indpathstore = (1 - indpath) if prevbl.getFlipPath() else indpath
            self.selectguards.append(GuardRecord(cbranch, cbranch, indpathstore, rng, vn))
            for j in range(maxpullback):
                if not vn.isWritten():
                    break
                readOp = vn.getDef()
                result = rng.pullBack(readOp, usenzmask)
                if result[0] is None:
                    break
                vn = result[0]
                if rng.isEmpty():
                    break
                self.selectguards.append(GuardRecord(cbranch, readOp, indpathstore, rng, vn))

    def calcRange(self, vn, rng_out) -> None:
        """Calculate the range of values for the given Varnode reaching the switch.

        C++ ref: JumpBasic::calcRange in jumptable.cc
        rng_out is a mutable list [CircleRange] that will be replaced with result.
        """
        from ghidra.analysis.rangeutil import CircleRange
        stride = 1
        if vn.isConstant():
            rng = CircleRange.fromSingle(vn.getOffset(), vn.getSize())
        elif vn.isWritten() and vn.getDef().isBoolOutput():
            rng = CircleRange(0, 2, 1, 1)
        else:
            maxValue = JumpBasic.getMaxValue(vn)
            stride = JumpBasic.getStride(vn)
            rng = CircleRange(0, maxValue, vn.getSize(), stride)

        bitsPreserved_out = []
        baseVn = GuardRecord.quasiCopy(vn, bitsPreserved_out)
        bitsPreserved = bitsPreserved_out[0]
        for guard in self.selectguards:
            matchval = guard.valueMatch(vn, baseVn, bitsPreserved)
            if matchval == 0:
                continue
            rng.intersect(guard.getRange())

        if rng.getSize() > 0x10000:
            positive = CircleRange(0, (rng.getMask() >> 1) + 1, vn.getSize(), stride)
            positive.intersect(rng)
            if not positive.isEmpty():
                rng = positive

        rng_out.clear()
        rng_out.append(rng)

    def findSmallestNormal(self, matchsize: int) -> None:
        """Find the Varnode with smallest range as the normalized switch variable.

        C++ ref: JumpBasic::findSmallestNormal in jumptable.cc
        """
        rng_out = [None]
        self.varnodeIndex = 0
        self.calcRange(self.pathMeld.getVarnode(0), rng_out)
        rng = rng_out[0]
        self.jrange.setRange(rng)
        self.jrange.setStartVn(self.pathMeld.getVarnode(0))
        self.jrange.setStartOp(self.pathMeld.getOp(0))
        maxsize = rng.getSize()
        for i in range(1, self.pathMeld.numCommonVarnode()):
            if maxsize == matchsize:
                return
            self.calcRange(self.pathMeld.getVarnode(i), rng_out)
            rng = rng_out[0]
            sz = rng.getSize()
            if sz < maxsize:
                if sz != 256 or self.pathMeld.getVarnode(i).getSize() != 1:
                    self.varnodeIndex = i
                    maxsize = sz
                    self.jrange.setRange(rng)
                    self.jrange.setStartVn(self.pathMeld.getVarnode(i))
                    self.jrange.setStartOp(self.pathMeld.getEarliestOp(i))

    def findNormalized(self, fd, rootbl, pathout: int, matchsize: int, maxtablesize: int) -> None:
        """Do all work to recover the normalized switch variable.

        C++ ref: JumpBasic::findNormalized in jumptable.cc
        """
        self.analyzeGuards(rootbl, pathout)
        self.findSmallestNormal(matchsize)
        sz = self.jrange.getSize()
        if sz > maxtablesize and self.pathMeld.numCommonVarnode() == 1:
            vn = self.pathMeld.getVarnode(0)
            if vn.isReadOnly():
                from ghidra.analysis.rangeutil import CircleRange
                from ghidra.emulate.memstate import MemoryImage

                glb = fd.getArch()
                mem = MemoryImage(vn.getSpace(), 4, 16, glb.loader)
                val = mem.getValue(vn.getOffset(), vn.getSize())
                self.varnodeIndex = 0
                self.jrange.setRange(CircleRange.fromSingle(val, vn.getSize()))
                self.jrange.setStartVn(vn)
                self.jrange.setStartOp(self.pathMeld.getOp(0))

    def markFoldableGuards(self) -> None:
        """Mark the guard CBRANCHs that are truly part of the model.

        C++ ref: JumpBasic::markFoldableGuards in jumptable.cc
        """
        vn = self.pathMeld.getVarnode(self.varnodeIndex)
        bitsPreserved_out = []
        baseVn = GuardRecord.quasiCopy(vn, bitsPreserved_out)
        bitsPreserved = bitsPreserved_out[0]
        for guardRecord in self.selectguards:
            if guardRecord.valueMatch(vn, baseVn, bitsPreserved) == 0 or guardRecord.isUnrolled():
                guardRecord.clear()

    def markModel(self, val: bool) -> None:
        """Set or clear marks on model PcodeOps.

        C++ ref: JumpBasic::markModel in jumptable.cc
        """
        self.pathMeld.markPaths(val, self.varnodeIndex)
        for guard in self.selectguards:
            op = guard.getBranch()
            if op is None:
                continue
            readOp = guard.getReadOp()
            if val:
                readOp.setMark()
            else:
                readOp.clearMark()

    def flowsOnlyToModel(self, vn, trailOp) -> bool:
        """Check if vn only flows into the model (marked ops).

        C++ ref: JumpBasic::flowsOnlyToModel in jumptable.cc
        """
        for op in vn.getDescend():
            if op is trailOp:
                continue
            if not op.isMark():
                return False
        return True

    def checkUnrolledGuard(self, bl, maxpullback: int, usenzmask: bool) -> None:
        """Check for a guard unrolled across multiple blocks.

        C++ ref: JumpBasic::checkUnrolledGuard in jumptable.cc
        """
        from ghidra.analysis.rangeutil import CircleRange
        varArray = []
        if not self.checkCommonCbranch(varArray, bl):
            return
        indpath = bl.getInRevIndex(0)
        toswitchval = indpath == 1
        pred_block = bl.getIn(0)
        cbranch = pred_block.lastOp()
        if cbranch.isBooleanFlip():
            toswitchval = not toswitchval
        rng = CircleRange.fromBool(toswitchval)
        indpathstore = 1 - indpath if pred_block.getFlipPath() else indpath
        readOp = cbranch
        for _ in range(maxpullback):
            if JumpBasic.duplicateVarnodes(varArray):
                self.selectguards.append(GuardRecord(cbranch, readOp, indpathstore, rng, varArray[0], True))
            else:
                multiOp = bl.findMultiequal(varArray)
                if multiOp is not None:
                    self.selectguards.append(GuardRecord(cbranch, readOp, indpathstore, rng, multiOp.getOut(), True))
            vn = varArray[0]
            if not vn.isWritten():
                break
            next_read_op = vn.getDef()
            vn, _markup = rng.pullBack(next_read_op, usenzmask)
            if vn is None:
                break
            if rng.isEmpty():
                break
            if not bl.liftVerifyUnroll(varArray, next_read_op.getSlot(vn)):
                break

    def checkCommonCbranch(self, varArray: list, bl) -> bool:
        """Check for common CBRANCH flow across incoming blocks.

        C++ ref: JumpBasic::checkCommonCbranch in jumptable.cc
        """
        from ghidra.core.opcodes import OpCode
        curBlock = bl.getIn(0)
        op = curBlock.lastOp()
        if op is None or op.code() != OpCode.CPUI_CBRANCH:
            return False
        outslot = bl.getInRevIndex(0)
        isOpFlip = op.isBooleanFlip()
        varArray.append(op.getIn(1))
        for i in range(1, bl.sizeIn()):
            curBlock = bl.getIn(i)
            op = curBlock.lastOp()
            if op is None or op.code() != OpCode.CPUI_CBRANCH:
                return False
            if op.isBooleanFlip() != isOpFlip:
                return False
            if outslot != bl.getInRevIndex(i):
                return False
            varArray.append(op.getIn(1))
        return True

    # ------------------------------------------------------------------
    # Core model methods
    # ------------------------------------------------------------------
    def recoverModel(self, fd, indop, matchsize: int, maxtablesize: int) -> bool:
        """Recover the jump-table model.

        C++ ref: JumpBasic::recoverModel in jumptable.cc
        """
        self.jrange = JumpValuesRange()
        self.findDeterminingVarnodes(indop, 0)
        self.findNormalized(fd, indop.getParent(), -1, matchsize, maxtablesize)
        if self.jrange.getSize() > maxtablesize:
            return False
        self.markFoldableGuards()
        return True

    def buildAddresses(self, fd, indop, addresstable: list,
                       loadpoints, loadcounts) -> None:
        """Build the address table by emulating the switch paths.

        C++ ref: JumpBasic::buildAddresses in jumptable.cc
        """
        addresstable.clear()
        emul = EmulateFunction(fd)
        emul.setLoadCollect(loadpoints)

        from ghidra.core.space import AddrSpace
        mask = 0xFFFFFFFFFFFFFFFF
        bit = fd.getArch().funcptr_align
        if bit != 0:
            mask = (mask >> bit) << bit
        spc = indop.getAddr().getSpace()
        notdone = self.jrange.initializeForReading()
        while notdone:
            val = self.jrange.getValue()
            addr_offset = emul.emulatePath(val, self.pathMeld,
                                           self.jrange.getStartOp(),
                                           self.jrange.getStartVarnode())
            addr_offset = AddrSpace.addressToByte(addr_offset, spc.getWordSize())
            addr_offset &= mask
            addresstable.append(Address(spc, addr_offset))
            if loadcounts is not None:
                loadcounts.append(len(loadpoints))
            notdone = self.jrange.next()

    def findUnnormalized(self, maxaddsub: int, maxleftright: int, maxext: int) -> None:
        """Find the unnormalized switch variable by walking back through normalization ops.

        C++ ref: JumpBasic::findUnnormalized in jumptable.cc
        """
        from ghidra.core.opcodes import OpCode
        i = self.varnodeIndex
        self.normalvn = self.pathMeld.getVarnode(i)
        i += 1
        self.switchvn = self.normalvn
        self.markModel(True)

        countaddsub = 0
        countext = 0
        normop = None
        while i < self.pathMeld.numCommonVarnode():
            if not self.flowsOnlyToModel(self.switchvn, normop):
                break
            testvn = self.pathMeld.getVarnode(i)
            if not self.switchvn.isWritten():
                break
            normop = self.switchvn.getDef()
            found_j = -1
            for j in range(normop.numInput()):
                if normop.getIn(j) is testvn:
                    found_j = j
                    break
            if found_j == -1:
                break
            opc = normop.code()
            accepted = False
            if opc in (OpCode.CPUI_INT_ADD, OpCode.CPUI_INT_SUB):
                countaddsub += 1
                if countaddsub <= maxaddsub:
                    if normop.getIn(1 - found_j).isConstant():
                        self.switchvn = testvn
                        accepted = True
            elif opc in (OpCode.CPUI_INT_ZEXT, OpCode.CPUI_INT_SEXT):
                countext += 1
                if countext <= maxext:
                    self.switchvn = testvn
                    accepted = True
            if not accepted:
                break
            i += 1
        self.markModel(False)

    def buildLabels(self, fd, addresstable: list, label: list, orig) -> None:
        """Build case labels for the address table.

        C++ ref: JumpBasic::buildLabels in jumptable.cc
        """
        from ghidra.core.opbehavior import EvaluationError
        origrange = orig.getValueRange()

        notdone = origrange.initializeForReading()
        while notdone:
            val = origrange.getValue()
            needswarning = 0
            if origrange.isReversible():
                if not self.jrange.contains(val):
                    needswarning = 1
                try:
                    switchval = JumpBasic.backup2Switch(fd, val, self.normalvn, self.switchvn)
                except EvaluationError:
                    switchval = JumpValues.NO_LABEL
                    needswarning = 2
            else:
                switchval = JumpValues.NO_LABEL
            if needswarning == 1:
                fd.warning("This code block may not be properly labeled as switch case", addresstable[len(label)])
            elif needswarning == 2:
                fd.warning("Calculation of case label failed", addresstable[len(label)])
            label.append(switchval)
            if len(label) >= len(addresstable):
                break
            notdone = origrange.next()

        while len(label) < len(addresstable):
            fd.warning("Bad switch case", addresstable[len(label)])
            label.append(JumpValues.NO_LABEL)

    def foldInNormalization(self, fd, indop):
        """Set the BRANCHIND input to the unnormalized switch variable.

        C++ ref: JumpBasic::foldInNormalization in jumptable.cc
        """
        fd.opSetInput(indop, self.switchvn, 0)
        return self.switchvn

    def foldInOneGuard(self, fd, guard, jump) -> bool:
        """Fold in a single guard CBRANCH.

        C++ ref: JumpBasic::foldInOneGuard in jumptable.cc
        """
        cbranch = guard.getBranch()
        cbranchblock = cbranch.getParent()
        if cbranchblock.sizeOut() != 2:
            return False
        indpath = guard.getPath()
        if cbranchblock.getFlipPath():
            indpath = 1 - indpath
        switchbl = jump.getIndirectOp().getParent()
        if cbranchblock.getOut(indpath) is not switchbl:
            return False
        guardtarget = cbranchblock.getOut(1 - indpath)

        pos = -1
        for p in range(switchbl.sizeOut()):
            if switchbl.getOut(p) is guardtarget:
                pos = p
                break
        if pos == -1:
            pos = switchbl.sizeOut()

        if jump.hasFoldedDefault() and jump.getDefaultBlock() != pos:
            return False

        if not switchbl.noInterveningStatement():
            return False

        if pos == switchbl.sizeOut():
            jump.addBlockToSwitch(guardtarget, JumpValues.NO_LABEL)
            jump.setLastAsDefault()
            fd.pushBranch(cbranchblock, 1 - indpath, switchbl)
        else:
            val = 0 if ((indpath == 0) != cbranch.isBooleanFlip()) else 1
            fd.opSetInput(cbranch, fd.newConstant(cbranch.getIn(0).getSize(), val), 1)
            jump.setDefaultBlock(pos)
        jump.setFoldedDefault()
        guard.clear()
        return True

    def foldInGuards(self, fd, jump) -> bool:
        """Fold in all guard CBRANCHs.

        C++ ref: JumpBasic::foldInGuards in jumptable.cc
        """
        change = False
        for guard in self.selectguards:
            cbranch = guard.getBranch()
            if cbranch is None:
                continue
            if cbranch.isDead():
                guard.clear()
                continue
            if self.foldInOneGuard(fd, guard, jump):
                change = True
        return change

    def sanityCheck(self, fd, indop, addresstable: list,
                    loadpoints: list, loadcounts=None) -> bool:
        """Validate the address table, truncating at first unreasonable entry.

        C++ ref: JumpBasic::sanityCheck in jumptable.cc
        """
        from ghidra.arch.loadimage import DataUnavailError
        if not addresstable:
            return True
        addr = addresstable[0]
        i = 0
        if addr.getOffset() != 0:
            for i in range(1, len(addresstable)):
                if addresstable[i].getOffset() == 0:
                    break
                diff = abs(addr.getOffset() - addresstable[i].getOffset())
                if diff > 0xffff:
                    dataavail = True
                    try:
                        fd.getArch().loader.loadFill(bytearray(4), 4, addresstable[i])
                    except DataUnavailError:
                        dataavail = False
                    if not dataavail:
                        break
            else:
                i = len(addresstable)
        if i == 0:
            return False
        if i != len(addresstable):
            del addresstable[i:]
            self.jrange.truncate(i)
            if loadcounts is not None:
                del loadpoints[loadcounts[i - 1]:]
        return True

    def clone(self, jt):
        """Clone this model for a new JumpTable.

        C++ ref: JumpBasic::clone in jumptable.cc
        """
        res = JumpBasic(jt)
        res.jrange = self.jrange.clone()
        return res

    def clear(self):
        """Clear all model state.

        C++ ref: JumpBasic::clear in jumptable.cc
        """
        self.jrange = None
        self.pathMeld.clear()
        self.selectguards.clear()
        self.normalvn = None
        self.switchvn = None


class JumpBasic2(JumpBasic):
    """A two-path jump-table model with a default constant path.

    C++ ref: JumpBasic2 in jumptable.hh / jumptable.cc
    """

    def __init__(self, jt) -> None:
        super().__init__(jt)
        self.extravn = None  # Varnode at the join point
        self.origPathMeld = PathMeld()

    def initializeStart(self, pMeld: PathMeld) -> None:
        """Initialize at the point where JumpBasic model failed.

        C++ ref: JumpBasic2::initializeStart in jumptable.cc
        """
        if pMeld.empty():
            self.extravn = None
            return
        self.extravn = pMeld.getVarnode(pMeld.numCommonVarnode() - 1)
        self.origPathMeld.set(pMeld)

    def recoverModel(self, fd, indop, matchsize: int, maxtablesize: int) -> bool:
        """Try to recover a two-path jump-table model.

        C++ ref: JumpBasic2::recoverModel in jumptable.cc
        """
        from ghidra.core.opcodes import OpCode
        joinvn = self.extravn
        if joinvn is None:
            return False
        if not joinvn.isWritten():
            return False
        multiop = joinvn.getDef()
        if multiop.code() != OpCode.CPUI_MULTIEQUAL:
            return False
        if multiop.numInput() != 2:
            return False
        path = -1
        extravalue = 0
        for p in range(2):
            vn = multiop.getIn(p)
            if not vn.isWritten():
                continue
            cop = vn.getDef()
            if cop.code() != OpCode.CPUI_COPY:
                continue
            othervn = cop.getIn(0)
            if othervn.isConstant():
                extravalue = othervn.getOffset()
                path = p
                break
        if path == -1:
            return False
        rootbl = multiop.getParent().getIn(1 - path)
        pathout = multiop.getParent().getInRevIndex(1 - path)
        jdef = JumpValuesRangeDefault()
        self.jrange = jdef
        jdef.setExtraValue(extravalue)
        jdef.setDefaultVn(joinvn)
        jdef.setDefaultOp(self.origPathMeld.getOp(self.origPathMeld.numOps() - 1))

        self.findDeterminingVarnodes(multiop, 1 - path)
        self.findNormalized(fd, rootbl, pathout, matchsize, maxtablesize)
        if self.jrange.getSize() > maxtablesize:
            return False

        self.pathMeld.append(self.origPathMeld)
        self.varnodeIndex += self.origPathMeld.numCommonVarnode()
        return True

    def checkNormalDominance(self) -> bool:
        """Check if the normalized switch variable's defining block dominates the switch block.

        C++ ref: JumpBasic2::checkNormalDominance in jumptable.cc
        """
        if self.normalvn.isInput():
            return True
        defblock = self.normalvn.getDef().getParent()
        switchblock = self.pathMeld.getOp(0).getParent()
        while switchblock is not None:
            if switchblock is defblock:
                return True
            switchblock = switchblock.getImmedDom()
        return False

    def findUnnormalized(self, maxaddsub: int, maxleftright: int, maxext: int) -> None:
        """Find the unnormalized switch variable, handling backward normalization.

        C++ ref: JumpBasic2::findUnnormalized in jumptable.cc
        """
        from ghidra.core.error import LowlevelError
        self.normalvn = self.pathMeld.getVarnode(self.varnodeIndex)
        if self.checkNormalDominance():
            super().findUnnormalized(maxaddsub, maxleftright, maxext)
            return
        self.switchvn = self.extravn
        multiop = self.extravn.getDef()
        if multiop.getIn(0) is self.normalvn or multiop.getIn(1) is self.normalvn:
            self.normalvn = self.switchvn
        else:
            raise LowlevelError("Backward normalization not implemented")

    def foldInOneGuard(self, fd, guard, jump) -> bool:
        """Fold in a guard for the two-path model.

        C++ ref: JumpBasic2::foldInOneGuard in jumptable.cc
        """
        jump.setLastAsDefault()
        guard.clear()
        return True

    def clone(self, jt):
        """Clone this model.

        C++ ref: JumpBasic2::clone in jumptable.cc
        """
        res = JumpBasic2(jt)
        res.jrange = self.jrange.clone()
        return res

    def clear(self):
        """Clear all state.

        C++ ref: JumpBasic2::clear in jumptable.cc
        """
        self.extravn = None
        self.origPathMeld.clear()
        super().clear()


class JumpBasicOverride(JumpBasic):
    """A jump-table model where destination addresses are provided explicitly."""

    def __init__(self, jt) -> None:
        super().__init__(jt)
        self.adset: Set[Address] = set()
        self.values: List[int] = []
        self.addrtable: List[Address] = []
        self.startingvalue: int = 0
        self.normaddress = Address()
        self.hash: int = 0
        self.istrivial: bool = False

    def setAddresses(self, adtable) -> None:
        for addr in adtable:
            self.adset.add(Address(addr.getSpace(), addr.getOffset()))

    def findStartOp(self, vn) -> int:
        descendants = list(vn.beginDescend())
        for op in descendants:
            op.setMark()
        res = -1
        for i in range(self.pathMeld.numOps()):
            if self.pathMeld.getOp(i).isMark():
                res = i
                break
        for op in descendants:
            op.clearMark()
        return res

    def trialNorm(self, fd, trialvn, tolerance: int) -> int:
        from ghidra.core.space import AddrSpace

        opi = self.findStartOp(trialvn)
        if opi < 0:
            return -1
        startop = self.pathMeld.getOp(opi)
        if self.values:
            return opi

        emul = EmulateFunction(fd)
        spc = startop.getAddr().getSpace()
        val = self.startingvalue
        total = 0
        miss = 0
        alreadyseen: Set[Address] = set()
        while total < len(self.adset):
            try:
                addr = emul.emulatePath(val, self.pathMeld, startop, trialvn)
            except LowlevelError:
                addr = 0
                miss = tolerance
            addr = AddrSpace.addressToByte(addr, spc.getWordSize())
            newaddr = Address(spc, addr)
            if newaddr in self.adset:
                if newaddr not in alreadyseen:
                    alreadyseen.add(newaddr)
                    total += 1
                self.values.append(val)
                self.addrtable.append(newaddr)
                if len(self.values) > len(self.adset) + 100:
                    break
                miss = 0
            else:
                miss += 1
                if miss >= tolerance:
                    break
            val += 1

        if total == len(self.adset):
            return opi
        self.values.clear()
        self.addrtable.clear()
        return -1

    def setupTrivial(self) -> None:
        if not self.addrtable:
            for addr in sorted(self.adset):
                self.addrtable.append(Address(addr.getSpace(), addr.getOffset()))
        self.values.clear()
        for addr in self.addrtable:
            self.values.append(addr.getOffset())
        self.varnodeIndex = 0
        self.normalvn = self.pathMeld.getVarnode(0)
        self.istrivial = True

    def findLikelyNorm(self):
        from ghidra.core.opcodes import OpCode

        res = None
        i = 0
        while i < self.pathMeld.numOps():
            op = self.pathMeld.getOp(i)
            if op.code() == OpCode.CPUI_LOAD:
                res = self.pathMeld.getOpParent(i)
                break
            i += 1
        if res is None:
            return res
        i += 1
        while i < self.pathMeld.numOps():
            op = self.pathMeld.getOp(i)
            if op.code() == OpCode.CPUI_INT_ADD:
                res = self.pathMeld.getOpParent(i)
                break
            i += 1
        i += 1
        while i < self.pathMeld.numOps():
            op = self.pathMeld.getOp(i)
            if op.code() == OpCode.CPUI_INT_MULT:
                res = self.pathMeld.getOpParent(i)
                break
            i += 1
        return res

    def clearCopySpecific(self) -> None:
        self.selectguards.clear()
        self.pathMeld.clear()
        self.normalvn = None
        self.switchvn = None

    def setNorm(self, addr: Address, h: int) -> None:
        self.normaddress = Address(addr.getSpace(), addr.getOffset())
        self.hash = h

    def setStartingValue(self, val: int) -> None:
        self.startingvalue = val

    def isOverride(self) -> bool:
        return True

    def getTableSize(self) -> int:
        return len(self.addrtable)

    def recoverModel(self, fd, indop, matchsize, maxtablesize) -> bool:
        self.clearCopySpecific()
        self.findDeterminingVarnodes(indop, 0)
        if not self.istrivial:
            trialvn = None
            if self.hash != 0:
                from ghidra.analysis.dynamic import DynamicHash

                dyn = DynamicHash()
                trialvn = dyn.findVarnode(fd, self.normaddress, self.hash)
            if trialvn is None and (not self.values or self.hash == 0):
                trialvn = self.findLikelyNorm()
            if trialvn is not None:
                opi = self.trialNorm(fd, trialvn, 10)
                if opi >= 0:
                    self.varnodeIndex = opi
                    self.normalvn = trialvn
                    return True
        self.setupTrivial()
        return True

    def buildAddresses(self, fd, indop, addresstable, loadpoints, loadcounts) -> None:
        addresstable.clear()
        for addr in self.addrtable:
            addresstable.append(Address(addr.getSpace(), addr.getOffset()))

    def buildLabels(self, fd, addresstable, label, orig) -> None:
        from ghidra.core.opbehavior import EvaluationError

        for val in self.values:
            try:
                addr = JumpBasic.backup2Switch(fd, val, self.normalvn, self.switchvn)
            except EvaluationError:
                addr = JumpValues.NO_LABEL
            label.append(addr)
            if len(label) >= len(addresstable):
                break

        while len(label) < len(addresstable):
            fd.warning("Bad switch case", addresstable[len(label)])
            label.append(JumpValues.NO_LABEL)

    def foldInGuards(self, fd, jump) -> bool:
        return False

    def sanityCheck(self, fd, indop, addresstable, loadpoints, loadcounts) -> bool:
        return True

    def clone(self, jt):
        res = JumpBasicOverride(jt)
        res.adset = {Address(addr.getSpace(), addr.getOffset()) for addr in self.adset}
        res.values = list(self.values)
        res.addrtable = [Address(addr.getSpace(), addr.getOffset()) for addr in self.addrtable]
        res.startingvalue = self.startingvalue
        res.normaddress = Address(self.normaddress.getSpace(), self.normaddress.getOffset())
        res.hash = self.hash
        return res

    def clear(self) -> None:
        self.clearCopySpecific()
        self.values.clear()
        self.addrtable.clear()
        self.istrivial = False

    def encode(self, encoder) -> None:
        """Encode this override as a <basicoverride> element.

        C++ ref: ``JumpBasicOverride::encode``
        """
        from ghidra.core.marshal import (
            ATTRIB_CONTENT,
            ELEM_BASICOVERRIDE,
            ELEM_DEST,
            ELEM_NORMADDR,
            ELEM_NORMHASH,
            ELEM_STARTVAL,
        )

        encoder.openElement(ELEM_BASICOVERRIDE)
        for addr in sorted(self.adset):
            encoder.openElement(ELEM_DEST)
            spc = addr.getSpace()
            off = addr.getOffset()
            spc.encodeAttributes(encoder, off)
            encoder.closeElement(ELEM_DEST)
        if self.hash != 0:
            encoder.openElement(ELEM_NORMADDR)
            self.normaddress.getSpace().encodeAttributes(encoder, self.normaddress.getOffset())
            encoder.closeElement(ELEM_NORMADDR)
            encoder.openElement(ELEM_NORMHASH)
            encoder.writeUnsignedInteger(ATTRIB_CONTENT, self.hash)
            encoder.closeElement(ELEM_NORMHASH)
        if self.startingvalue != 0:
            encoder.openElement(ELEM_STARTVAL)
            encoder.writeUnsignedInteger(ATTRIB_CONTENT, self.startingvalue)
            encoder.closeElement(ELEM_STARTVAL)
        encoder.closeElement(ELEM_BASICOVERRIDE)

    def decode(self, decoder) -> None:
        """Decode this override from a <basicoverride> element.

        C++ ref: ``JumpBasicOverride::decode``
        """
        from ghidra.core.marshal import (
            ATTRIB_CONTENT,
            ELEM_BASICOVERRIDE,
            ELEM_DEST,
            ELEM_NORMADDR,
            ELEM_NORMHASH,
            ELEM_STARTVAL,
        )
        from ghidra.core.pcoderaw import VarnodeData

        elemId = decoder.openElement(ELEM_BASICOVERRIDE)
        while True:
            subId = decoder.openElement()
            if subId == 0:
                break
            if subId == ELEM_DEST.id:
                vData = VarnodeData()
                vData.decodeFromAttributes(decoder)
                self.adset.add(vData.getAddr())
            elif subId == ELEM_NORMADDR.id:
                vData = VarnodeData()
                vData.decodeFromAttributes(decoder)
                self.normaddress = vData.getAddr()
            elif subId == ELEM_NORMHASH.id:
                self.hash = decoder.readUnsignedInteger(ATTRIB_CONTENT)
            elif subId == ELEM_STARTVAL.id:
                self.startingvalue = decoder.readUnsignedInteger(ATTRIB_CONTENT)
            decoder.closeElement(subId)
        decoder.closeElement(elemId)
        if not self.adset:
            raise LowlevelError("Empty jumptable override")
