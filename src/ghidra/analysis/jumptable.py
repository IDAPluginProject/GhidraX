"""
Corresponds to: jumptable.hh / jumptable.cc

Classes to support jump-tables and their recovery.
JumpTable, JumpModel, JumpBasic, LoadTable, PathMeld, GuardRecord.
"""

from __future__ import annotations
from typing import Optional, List, Dict, Set
from ghidra.core.address import Address


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

    def __eq__(self, other):
        return self.blockPosition == other.blockPosition and self.addressIndex == other.addressIndex

    def __repr__(self):
        return f"IndexPair(block={self.blockPosition}, addr={self.addressIndex})"


class LoadTable:
    """A description of where and how data was loaded from memory."""

    def __init__(self, addr: Optional[Address] = None, sz: int = 0, nm: int = 1) -> None:
        self.addr: Address = addr if addr is not None else Address()
        self.size: int = sz
        self.num: int = nm

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
        if len(table) <= 1:
            return
        table.sort()
        i = 0
        while i < len(table) - 1:
            cur = table[i]
            nxt = table[i + 1]
            endaddr = cur.addr + cur.size * cur.num
            if endaddr == nxt.addr and cur.size == nxt.size:
                cur.num += nxt.num
                table.pop(i + 1)
            else:
                i += 1


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
        self.clear()
        if vn is not None:
            # set(PcodeOp*, Varnode*)
            self.commonVn.append(vn)
            self.opMeld.append(RootedOp(op_or_path, 0))
        elif isinstance(op_or_path, PathMeld):
            # set(const PathMeld&)
            self.commonVn = list(op_or_path.commonVn)
            self.opMeld = list(op_or_path.opMeld)
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
        self.opMeld = list(op2.opMeld) + self.opMeld
        for i in range(len(op2.opMeld), len(self.opMeld)):
            self.opMeld[i].rootVn += shift

    def internalIntersect(self, parentMap: list) -> None:
        """Calculate intersection of a new path with the old path.

        C++ ref: PathMeld::internalIntersect in jumptable.cc
        """
        newVn = []
        for vn in self.commonVn:
            if hasattr(vn, 'isMark') and vn.isMark():
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
            pos = parentMap[entry.rootVn] if entry.rootVn < len(parentMap) else -1
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
            if hasattr(vn, 'setMark'):
                vn.setMark()
        self.internalIntersect(parentMap)
        cutOff = -1

        for i, node in enumerate(path):
            vn = node.op.getIn(node.slot)
            if not (hasattr(vn, 'isMark') and vn.isMark()):
                cutOff = i + 1
            elif hasattr(vn, 'clearMark'):
                vn.clearMark()
        newCutoff = self.meldOps(path, cutOff, parentMap)
        if newCutoff >= 0:
            self.truncatePaths(newCutoff)
        del path[cutOff:]

    def markPaths(self, val: bool, startVarnode: int = 0) -> None:
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
                if hasattr(self.opMeld[i].op, 'setMark'):
                    self.opMeld[i].op.setMark()
        else:
            for i in range(startOp + 1):
                if hasattr(self.opMeld[i].op, 'clearMark'):
                    self.opMeld[i].op.clearMark()


class GuardRecord:
    """A switch variable Varnode and a constraint from a CBRANCH."""

    def __init__(self, cbranch=None, readOp=None, path: int = 0,
                 rng=None, vn=None, unrolled: bool = False) -> None:
        self.cbranch = cbranch
        self.readOp = readOp
        self.vn = vn
        self.baseVn = vn
        self.indpath: int = path
        self.bitsPreserved: int = 0
        self.range = rng
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
        nzmask = vn.getNZMask() if hasattr(vn, 'getNZMask') else 0
        bitsPreserved = mostsigbit_set(nzmask) + 1
        if bitsPreserved == 0:
            if isinstance(bitsPreserved_out, list):
                bitsPreserved_out.clear()
                bitsPreserved_out.append(0)
            return vn
        mask = (1 << bitsPreserved) - 1
        op = vn.getDef() if vn.isWritten() else None
        while op is not None:
            opc = op.code()
            if opc == OpCode.CPUI_COPY:
                vn = op.getIn(0)
                op = vn.getDef() if vn.isWritten() else None
            elif opc == OpCode.CPUI_INT_AND:
                constVn = op.getIn(1)
                if constVn.isConstant() and constVn.getOffset() == mask:
                    vn = op.getIn(0)
                    op = vn.getDef() if vn.isWritten() else None
                else:
                    op = None
            elif opc == OpCode.CPUI_INT_OR:
                constVn = op.getIn(1)
                if constVn.isConstant() and ((constVn.getOffset() | mask) == (constVn.getOffset() ^ mask)):
                    vn = op.getIn(0)
                    op = vn.getDef() if vn.isWritten() else None
                else:
                    op = None
            elif opc in (OpCode.CPUI_INT_SEXT, OpCode.CPUI_INT_ZEXT):
                if op.getIn(0).getSize() * 8 >= bitsPreserved:
                    vn = op.getIn(0)
                    op = vn.getDef() if vn.isWritten() else None
                else:
                    op = None
            elif opc == OpCode.CPUI_PIECE:
                if op.getIn(1).getSize() * 8 >= bitsPreserved:
                    vn = op.getIn(1)
                    op = vn.getDef() if vn.isWritten() else None
                else:
                    op = None
            elif opc == OpCode.CPUI_SUBPIECE:
                constVn = op.getIn(1)
                if constVn.isConstant() and constVn.getOffset() == 0:
                    vn = op.getIn(0)
                    op = vn.getDef() if vn.isWritten() else None
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
            loadOp = self.baseVn.getDef() if self.baseVn.isWritten() else None
            loadOp2 = baseVn2.getDef() if baseVn2.isWritten() else None
        else:
            loadOp = self.vn.getDef() if self.vn.isWritten() else None
            loadOp2 = vn2.getDef() if vn2.isWritten() else None
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

    def __init__(self, jt=None) -> None:
        self.jumptable = jt

    def isOverride(self) -> bool:
        return False

    def getTableSize(self) -> int:
        return 0

    def recoverModel(self, fd, indop, matchsize: int = 0, maxtablesize: int = 1024) -> bool:
        return False

    def buildAddresses(self, fd, indop, addresstable: list,
                       loadpoints=None, loadcounts=None) -> None:
        pass

    def findUnnormalized(self, maxaddsub: int = 0, maxleftright: int = 0, maxext: int = 0) -> None:
        pass

    def buildLabels(self, fd, addresstable: list, label: list, orig=None) -> None:
        pass

    def foldInNormalization(self, fd, indop):
        return None

    def foldInGuards(self, fd, jump) -> bool:
        return False

    def sanityCheck(self, fd, indop, addresstable: list,
                    loadpoints: list = None, loadcounts=None) -> bool:
        return True

    def clone(self, jt):
        return JumpModel(jt)

    def clear(self) -> None:
        pass


class JumpModelTrivial(JumpModel):
    """Trivial model where the BRANCHIND input is the switch variable."""

    def __init__(self, jt=None) -> None:
        super().__init__(jt)
        self._size: int = 0

    def getTableSize(self) -> int:
        return self._size

    def recoverModel(self, fd, indop, matchsize=0, maxtablesize=1024) -> bool:
        if indop is None:
            return False
        parent = indop.getParent() if hasattr(indop, 'getParent') else None
        if parent is None:
            return False
        self._size = parent.sizeOut()
        return self._size > 0

    def buildAddresses(self, fd, indop, addresstable, loadpoints=None, loadcounts=None):
        if indop is None:
            return
        parent = indop.getParent() if hasattr(indop, 'getParent') else None
        if parent is None:
            return
        for i in range(parent.sizeOut()):
            bl = parent.getOut(i)
            if bl is not None:
                addresstable.append(bl.getStart() if hasattr(bl, 'getStart') else Address())

    def buildLabels(self, fd, addresstable, label, orig=None):
        for i in range(len(addresstable)):
            label.append(i)

    def clone(self, jt):
        m = JumpModelTrivial(jt)
        m._size = self._size
        return m


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
        self.opaddress = ind.getAddr() if hasattr(ind, 'getAddr') else Address()
        self.indirect = ind

    def setNormMax(self, maddsub: int, mleftright: int, mext: int) -> None:
        self.maxaddsub = maddsub
        self.maxleftright = mleftright
        self.maxext = mext

    def setLastAsDefault(self) -> None:
        if self.addresstable:
            self.lastBlock = len(self.addresstable) - 1

    def setDefaultBlock(self, bl: int) -> None:
        self.defaultBlock = bl

    def setLoadCollect(self, val: bool) -> None:
        self.collectloads = val

    def setFoldedDefault(self) -> None:
        self.defaultIsFolded = True

    def hasFoldedDefault(self) -> bool:
        return self.defaultIsFolded

    def getAddressByIndex(self, i: int) -> Address:
        return self.addresstable[i] if i < len(self.addresstable) else Address()

    def getLabelByIndex(self, i: int) -> int:
        return self.label[i] if i < len(self.label) else 0

    def block2Position(self, bl) -> int:
        """Get the out-edge position of the given block relative to the switch parent.

        C++ ref: ``JumpTable::block2Position``
        """
        parent = self.indirect.getParent() if self.indirect is not None else None
        if parent is None:
            raise Exception("Requested block, not in jumptable")
        for position in range(bl.sizeIn()):
            if bl.getIn(position) is parent:
                if hasattr(bl, 'getInRevIndex'):
                    return bl.getInRevIndex(position)
                return position
        raise Exception("Requested block, not in jumptable")

    def numIndicesByBlock(self, bl) -> int:
        """Count the number of address table entries targeting the given block.

        C++ ref: ``JumpTable::numIndicesByBlock``
        """
        if not self.block2addr:
            # Fallback for pre-switchOver state
            blstart = bl.getStart() if hasattr(bl, 'getStart') else None
            if blstart is None:
                return 0
            return sum(1 for addr in self.addresstable if addr == blstart)
        try:
            pos = self.block2Position(bl)
        except Exception:
            return 0
        return sum(1 for ip in self.block2addr if ip.blockPosition == pos)

    def getIndexByBlock(self, bl, i: int = 0) -> int:
        """Get the i-th address table index for the given block.

        C++ ref: ``JumpTable::getIndexByBlock``
        """
        pos = self.block2Position(bl)
        count = 0
        for ip in self.block2addr:
            if ip.blockPosition == pos:
                if count == i:
                    return ip.addressIndex
                count += 1
        raise Exception("Could not get jumptable index for block")

    def recoverAddresses(self, fd) -> None:
        """Recover the raw jump-table addresses."""
        if self.jmodel is None:
            self.jmodel = JumpModelTrivial(self)
        if not self.jmodel.recoverModel(fd, self.indirect, 0, 1024):
            return
        self.addresstable.clear()
        self.jmodel.buildAddresses(fd, self.indirect, self.addresstable,
                                   self.loadpoints if self.collectloads else None)

    def recoverLabels(self, fd) -> None:
        """Recover case labels for this jump-table."""
        if self.jmodel is None:
            return
        self.label.clear()
        self.jmodel.buildLabels(fd, self.addresstable, self.label, self.jmodel)

    def foldInNormalization(self, fd) -> None:
        """Hide the normalization code."""
        if self.jmodel is not None:
            self.jmodel.foldInNormalization(fd, self.indirect)

    def foldInGuards(self, fd) -> bool:
        if self.jmodel is not None:
            return self.jmodel.foldInGuards(fd, self)
        return False

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
        return False

    def switchOver(self, flow) -> None:
        """Convert jump-table addresses to basic block indices.

        The address table entries are converted to out-edge indices of the
        parent block of the BRANCHIND. The most common target becomes the
        default block.

        C++ ref: ``JumpTable::switchOver``
        """
        self.block2addr.clear()
        parent = self.indirect.getParent() if self.indirect is not None else None
        if parent is None:
            return

        for i, addr in enumerate(self.addresstable):
            op = flow.target(addr) if hasattr(flow, 'target') else None
            if op is None:
                continue
            tmpbl = op.getParent()
            pos = -1
            for j in range(parent.sizeOut()):
                if parent.getOut(j) is tmpbl:
                    pos = j
                    break
            if pos == -1:
                raise Exception("Jumptable destination not linked")
            self.block2addr.append(IndexPair(pos, i))

        if self.block2addr:
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

    def recoverModel(self, fd) -> bool:
        """Recover the model for this jump-table."""
        if self.jmodel is None:
            self.jmodel = JumpModelTrivial(self)
        return self.jmodel.recoverModel(fd, self.indirect, 0, 1024)

    def sanityCheck(self, fd) -> bool:
        """Verify the recovered jump-table."""
        if self.jmodel is None:
            return False
        return self.jmodel.sanityCheck(fd, self.indirect, self.addresstable)

    def trivialSwitchOver(self) -> None:
        """Simple switch-over when table is already complete.

        Make exactly one case for each output edge of the switch block.

        C++ ref: ``JumpTable::trivialSwitchOver``
        """
        self.block2addr.clear()
        parent = self.indirect.getParent() if self.indirect is not None else None
        if parent is None:
            return
        numOut = parent.sizeOut()
        if numOut != len(self.addresstable):
            raise Exception("Trivial addresstable and switch block size do not match")
        for i in range(numOut):
            self.block2addr.append(IndexPair(i, i))
        self.lastBlock = numOut - 1
        self.defaultBlock = -1

    def recoverMultistage(self, fd) -> bool:
        """Attempt multistage recovery."""
        return False

    def encode(self, encoder) -> None:
        """Encode this jump-table as a <jumptable> element.

        C++ ref: ``JumpTable::encode``
        """
        from ghidra.core.marshal import (
            ELEM_JUMPTABLE, ELEM_DEST, ATTRIB_LABEL,
        )
        if not self.isRecovered():
            return
        encoder.openElement(ELEM_JUMPTABLE)
        self.opaddress.encode(encoder)
        for i, addr in enumerate(self.addresstable):
            encoder.openElement(ELEM_DEST)
            if not addr.isInvalid():
                spc = addr.getSpace()
                if spc is not None and hasattr(spc, 'encodeAttributes'):
                    spc.encodeAttributes(encoder, addr.getOffset())
            if i < len(self.label):
                if self.label[i] != JumpValues.NO_LABEL:
                    encoder.writeUnsignedInteger(ATTRIB_LABEL, self.label[i])
            encoder.closeElement(ELEM_DEST)
        for lp in self.loadpoints:
            if hasattr(lp, 'encode'):
                lp.encode(encoder)
        if self.jmodel is not None and self.jmodel.isOverride():
            if hasattr(self.jmodel, 'encode'):
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
                            raise Exception("Jumptable entries are missing labels")
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
                self.jmodel = JumpBasicOverride(self)
                self.jmodel.decode(decoder)
            else:
                decoder.openElement()
                decoder.closeElement(subId)
        decoder.closeElement(elemId)
        if self.label:
            while len(self.label) < len(self.addresstable):
                self.label.append(JumpValues.NO_LABEL)

    def setOverride(self, addrtable: list, naddr, h: int, sv: int) -> None:
        """Force a manual override of the jump-table addresses."""
        self.addresstable = list(addrtable)
        self.switchVarConsume = sv
        self.jmodel = JumpModelTrivial(self)

    def addBlockToSwitch(self, bl, lab: int) -> None:
        """Force a given basic-block to be a switch destination."""
        addr = bl.getStart() if hasattr(bl, 'getStart') else Address()
        self.addresstable.append(addr)
        self.label.append(lab)

    def matchModel(self, fd) -> None:
        """Try to match JumpTable model to the existing function."""
        if self.jmodel is None:
            self.jmodel = JumpModelTrivial(self)

    def clear(self) -> None:
        self.addresstable.clear()
        self.label.clear()
        self.loadpoints.clear()
        self.defaultBlock = -1
        self.lastBlock = -1
        if self.jmodel is not None:
            self.jmodel.clear()


# RecoveryMode as class-level enum on JumpTable
JumpTable.RecoveryMode = type('RecoveryMode', (), {
    'success': 0,
    'fail_normal': 1,
    'fail_thunk': 2,
    'fail_return': 3,
    'fail_callother': 4,
})


class JumptableThunkError(Exception):
    """Exception thrown for a thunk mechanism that looks like a jump-table."""
    pass


class JumpValues:
    """An iterator over values a switch variable can take."""
    NO_LABEL = 0xFFFFFFFFFFFFFFFF

    def truncate(self, nm: int) -> None:
        pass

    def getSize(self) -> int:
        return 0

    def contains(self, val: int) -> bool:
        return False

    def initializeForReading(self) -> bool:
        return False

    def next(self) -> bool:
        return False

    def getValue(self) -> int:
        return 0

    def getStartVarnode(self):
        return None

    def getStartOp(self):
        return None

    def isReversible(self) -> bool:
        return False

    def clone(self):
        return JumpValues()


class JumpValuesRange(JumpValues):
    """Single entry switch variable that can take a range of values."""

    def __init__(self) -> None:
        from ghidra.analysis.rangeutil import CircleRange
        self.range = CircleRange()
        self.normqvn = None
        self.startop = None
        self._curval: int = 0

    def setRange(self, rng) -> None:
        self.range = rng

    def setStartVn(self, vn) -> None:
        self.normqvn = vn

    def setStartOp(self, op) -> None:
        self.startop = op

    def getSize(self) -> int:
        return self.range.getSize()

    def contains(self, val: int) -> bool:
        return self.range.contains(val)

    def initializeForReading(self) -> bool:
        if self.range.isEmpty():
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
        r.range = self.range
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
        self._lastvalue = False
        return super().initializeForReading()

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
        r.range = self.range
        r.normqvn = self.normqvn
        r.startop = self.startop
        r._extravalue = self._extravalue
        r._extravn = self._extravn
        r._extraop = self._extraop
        return r


class EmulateFunction:
    """A light-weight emulator to calculate switch targets from switch variables."""

    def __init__(self, fd=None) -> None:
        self._fd = fd
        self._varnodeMap: dict = {}
        self._loadpoints = None

    def setLoadCollect(self, val) -> None:
        self._loadpoints = val

    def getVarnodeValue(self, vn) -> int:
        return self._varnodeMap.get(id(vn), 0)

    def setVarnodeValue(self, vn, val: int) -> None:
        self._varnodeMap[id(vn)] = val

    def emulatePath(self, val: int, pathMeld, startop, startvn) -> int:
        """Emulate a path through the function, returning the destination address offset."""
        if startvn is not None:
            self.setVarnodeValue(startvn, val)
        # Would execute ops along the path here
        return val


class JumpBasic(JumpModel):
    """The basic jump-table model: a normalized switch variable with a linear map to addresses.

    C++ ref: JumpBasic in jumptable.hh / jumptable.cc
    """

    def __init__(self, jt=None) -> None:
        super().__init__(jt)
        self.pathMeld = PathMeld()
        self.jrange: Optional[JumpValuesRange] = None
        self.selectguards: List[GuardRecord] = []
        self.varnodeIndex: int = 0
        self.normalvn = None  # Varnode: the normalized switch variable
        self.switchvn = None  # Varnode: the unnormalized switch variable

    def getValueRange(self):
        return self.jrange

    def isOverride(self) -> bool:
        return False

    def getTableSize(self) -> int:
        if self.jrange is not None:
            return self.jrange.getSize()
        return 0

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
        if hasattr(vn, 'isAnnotation') and vn.isAnnotation():
            return False
        if hasattr(vn, 'isReadOnly') and vn.isReadOnly():
            return False
        return True

    @staticmethod
    def getStride(vn) -> int:
        """Calculate stride from known-zero least-significant bits.

        C++ ref: JumpBasic::getStride in jumptable.cc
        """
        mask = vn.getNZMask() if hasattr(vn, 'getNZMask') else 0xFFFFFFFFFFFFFFFF
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
        from ghidra.core.error import LowlevelError
        curvn = outvn
        while curvn is not invn:
            op = curvn.getDef()
            top = op.getOpcode()
            # Find first non-constant input
            slot = 0
            for slot in range(op.numInput()):
                if not op.getIn(slot).isConstant():
                    break
            evalType = op.getEvalType() if hasattr(op, 'getEvalType') else -1
            if evalType == 2:  # PcodeOp::binary
                otherslot = 1 - slot
                otherAddr = op.getIn(otherslot).getAddr()
                if not otherAddr.isConstant():
                    otherval = 0  # Would need MemoryImage for readonly
                else:
                    otherval = otherAddr.getOffset()
                if hasattr(top, 'recoverInputBinary'):
                    output = top.recoverInputBinary(slot, op.getOut().getSize(), output,
                                                    op.getIn(slot).getSize(), otherval)
                curvn = op.getIn(slot)
            elif evalType == 1:  # PcodeOp::unary
                if hasattr(top, 'recoverInputUnary'):
                    output = top.recoverInputUnary(op.getOut().getSize(), output,
                                                   op.getIn(slot).getSize())
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
        usenzmask = not self.jumptable.isPartial() if self.jumptable is not None else True

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
                indpath = bl.getInRevIndex(0) if hasattr(bl, 'getInRevIndex') else 0

            cbranch = prevbl.lastOp() if hasattr(prevbl, 'lastOp') else None
            if cbranch is None or cbranch.code() != OpCode.CPUI_CBRANCH:
                break
            if i != 0:
                otherbl = prevbl.getOut(1 - indpath)
                otherop = otherbl.lastOp() if hasattr(otherbl, 'lastOp') else None
                if otherop is not None and otherop.code() == OpCode.CPUI_BRANCHIND:
                    if self.jumptable is not None and otherop is not self.jumptable.getIndirectOp():
                        break

            toswitchval = (indpath == 1)
            if cbranch.isBooleanFlip():
                toswitchval = not toswitchval
            bl = prevbl
            vn = cbranch.getIn(1)
            rng = CircleRange(1 if toswitchval else 0, 1)

            indpathstore = (1 - indpath) if (hasattr(prevbl, 'getFlipPath') and prevbl.getFlipPath()) else indpath
            self.selectguards.append(GuardRecord(cbranch, cbranch, indpathstore, rng, vn))
            for j in range(maxpullback):
                if not vn.isWritten():
                    break
                readOp = vn.getDef()
                result = rng.pullBack(readOp, usenzmask)
                if result is None or result[0] is None:
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
            rng = CircleRange(vn.getOffset(), vn.getSize())
        elif vn.isWritten() and hasattr(vn.getDef(), 'isBoolOutput') and vn.getDef().isBoolOutput():
            rng = CircleRange(0, 2, 1, 1)
        else:
            maxValue = JumpBasic.getMaxValue(vn)
            stride = JumpBasic.getStride(vn)
            rng = CircleRange(0, maxValue, vn.getSize(), stride)

        bitsPreserved_out = []
        baseVn = GuardRecord.quasiCopy(vn, bitsPreserved_out)
        bitsPreserved = bitsPreserved_out[0] if bitsPreserved_out else 0
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
                    earlyOp = self.pathMeld.getEarliestOp(i) if hasattr(self.pathMeld, 'getEarliestOp') else self.pathMeld.getOp(i)
                    self.jrange.setStartOp(earlyOp)

    def findNormalized(self, fd, rootbl, pathout: int, matchsize: int, maxtablesize: int) -> None:
        """Do all work to recover the normalized switch variable.

        C++ ref: JumpBasic::findNormalized in jumptable.cc
        """
        self.analyzeGuards(rootbl, pathout)
        self.findSmallestNormal(matchsize)
        sz = self.jrange.getSize()
        if sz > maxtablesize and self.pathMeld.numCommonVarnode() == 1:
            vn = self.pathMeld.getVarnode(0)
            if hasattr(vn, 'isReadOnly') and vn.isReadOnly():
                from ghidra.analysis.rangeutil import CircleRange
                # Would need MemoryImage to read value — simplified
                self.varnodeIndex = 0

    def markFoldableGuards(self) -> None:
        """Mark the guard CBRANCHs that are truly part of the model.

        C++ ref: JumpBasic::markFoldableGuards in jumptable.cc
        """
        vn = self.pathMeld.getVarnode(self.varnodeIndex)
        bitsPreserved_out = []
        baseVn = GuardRecord.quasiCopy(vn, bitsPreserved_out)
        bitsPreserved = bitsPreserved_out[0] if bitsPreserved_out else 0
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
            if readOp is not None:
                if val:
                    if hasattr(readOp, 'setMark'):
                        readOp.setMark()
                else:
                    if hasattr(readOp, 'clearMark'):
                        readOp.clearMark()

    def flowsOnlyToModel(self, vn, trailOp) -> bool:
        """Check if vn only flows into the model (marked ops).

        C++ ref: JumpBasic::flowsOnlyToModel in jumptable.cc
        """
        for op in vn.getDescend():
            if op is trailOp:
                continue
            if not (hasattr(op, 'isMark') and op.isMark()):
                return False
        return True

    def checkUnrolledGuard(self, bl, maxpullback: int, usenzmask: bool) -> None:
        """Check for a guard unrolled across multiple blocks.

        C++ ref: JumpBasic::checkUnrolledGuard in jumptable.cc
        """
        from ghidra.core.opcodes import OpCode
        from ghidra.analysis.rangeutil import CircleRange
        varArray = []
        if not self.checkCommonCbranch(varArray, bl):
            return
        if JumpBasic.duplicateVarnodes(varArray):
            vn = varArray[0]
            rng = CircleRange(True)
            indpathstore = bl.getInRevIndex(0) if hasattr(bl, 'getInRevIndex') else 0
            cbranch = bl.getIn(0).lastOp() if hasattr(bl.getIn(0), 'lastOp') else None
            if cbranch is not None:
                self.selectguards.append(GuardRecord(cbranch, cbranch, indpathstore, rng, vn, True))
                for j in range(maxpullback):
                    if not vn.isWritten():
                        break
                    readOp = vn.getDef()
                    result = rng.pullBack(readOp, usenzmask)
                    if result is None or result[0] is None:
                        break
                    vn = result[0]
                    if rng.isEmpty():
                        break
                    self.selectguards.append(GuardRecord(cbranch, readOp, indpathstore, rng, vn, True))

    def checkCommonCbranch(self, varArray: list, bl) -> bool:
        """Check for common CBRANCH flow across incoming blocks.

        C++ ref: JumpBasic::checkCommonCbranch in jumptable.cc
        """
        from ghidra.core.opcodes import OpCode
        curBlock = bl.getIn(0)
        op = curBlock.lastOp() if hasattr(curBlock, 'lastOp') else None
        if op is None or op.code() != OpCode.CPUI_CBRANCH:
            return False
        outslot = bl.getInRevIndex(0) if hasattr(bl, 'getInRevIndex') else 0
        isOpFlip = op.isBooleanFlip()
        varArray.append(op.getIn(1))
        for i in range(1, bl.sizeIn()):
            curBlock = bl.getIn(i)
            op = curBlock.lastOp() if hasattr(curBlock, 'lastOp') else None
            if op is None or op.code() != OpCode.CPUI_CBRANCH:
                return False
            if op.isBooleanFlip() != isOpFlip:
                return False
            revIdx = bl.getInRevIndex(i) if hasattr(bl, 'getInRevIndex') else i
            if outslot != revIdx:
                return False
            varArray.append(op.getIn(1))
        return True

    # ------------------------------------------------------------------
    # Core model methods
    # ------------------------------------------------------------------
    def recoverModel(self, fd, indop, matchsize: int = 0, maxtablesize: int = 1024) -> bool:
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
                       loadpoints=None, loadcounts=None) -> None:
        """Build the address table by emulating the switch paths.

        C++ ref: JumpBasic::buildAddresses in jumptable.cc
        """
        addresstable.clear()
        emul = EmulateFunction(fd)
        emul.setLoadCollect(loadpoints)

        mask = 0xFFFFFFFFFFFFFFFF
        glb = fd.getArch() if hasattr(fd, 'getArch') else None
        bit = glb.funcptr_align if glb is not None and hasattr(glb, 'funcptr_align') else 0
        if bit != 0:
            mask = (mask >> bit) << bit
        spc = indop.getAddr().getSpace()
        notdone = self.jrange.initializeForReading()
        while notdone:
            val = self.jrange.getValue()
            addr_offset = emul.emulatePath(val, self.pathMeld,
                                           self.jrange.getStartOp(),
                                           self.jrange.getStartVarnode())
            wordsize = spc.getWordSize() if spc is not None and hasattr(spc, 'getWordSize') else 1
            if wordsize > 1:
                addr_offset = addr_offset * wordsize
            addr_offset &= mask
            addresstable.append(Address(spc, addr_offset))
            if loadcounts is not None and loadpoints is not None:
                loadcounts.append(len(loadpoints))
            notdone = self.jrange.next()

    def findUnnormalized(self, maxaddsub: int = 0, maxleftright: int = 0, maxext: int = 0) -> None:
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

    def buildLabels(self, fd, addresstable: list, label: list, orig=None) -> None:
        """Build case labels for the address table.

        C++ ref: JumpBasic::buildLabels in jumptable.cc
        """
        origrange = orig.getValueRange() if orig is not None and hasattr(orig, 'getValueRange') else self.jrange
        if origrange is None:
            for i in range(len(addresstable)):
                label.append(i)
            return

        notdone = origrange.initializeForReading()
        while notdone:
            val = origrange.getValue()
            needswarning = 0
            if origrange.isReversible():
                if self.jrange is not None and not self.jrange.contains(val):
                    needswarning = 1
                try:
                    switchval = JumpBasic.backup2Switch(fd, val, self.normalvn, self.switchvn)
                except Exception:
                    switchval = JumpValues.NO_LABEL
                    needswarning = 2
            else:
                switchval = JumpValues.NO_LABEL
            if needswarning == 1 and hasattr(fd, 'warning') and len(label) < len(addresstable):
                fd.warning("This code block may not be properly labeled as switch case", addresstable[len(label)])
            elif needswarning == 2 and hasattr(fd, 'warning') and len(label) < len(addresstable):
                fd.warning("Calculation of case label failed", addresstable[len(label)])
            label.append(switchval)
            if len(label) >= len(addresstable):
                break
            notdone = origrange.next()

        while len(label) < len(addresstable):
            if hasattr(fd, 'warning'):
                fd.warning("Bad switch case", addresstable[len(label)])
            label.append(JumpValues.NO_LABEL)

    def foldInNormalization(self, fd, indop):
        """Set the BRANCHIND input to the unnormalized switch variable.

        C++ ref: JumpBasic::foldInNormalization in jumptable.cc
        """
        if self.switchvn is not None and hasattr(fd, 'opSetInput'):
            fd.opSetInput(indop, self.switchvn, 0)
        return self.switchvn

    def foldInOneGuard(self, fd, guard, jump) -> bool:
        """Fold in a single guard CBRANCH.

        C++ ref: JumpBasic::foldInOneGuard in jumptable.cc
        """
        from ghidra.core.opcodes import OpCode
        cbranch = guard.getBranch()
        cbranchblock = cbranch.getParent()
        if cbranchblock.sizeOut() != 2:
            return False
        indpath = guard.getPath()
        if hasattr(cbranchblock, 'getFlipPath') and cbranchblock.getFlipPath():
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

        if hasattr(switchbl, 'noInterveningStatement') and not switchbl.noInterveningStatement():
            return False

        if pos == switchbl.sizeOut():
            if hasattr(jump, 'addBlockToSwitch'):
                jump.addBlockToSwitch(guardtarget, JumpValues.NO_LABEL)
            jump.setLastAsDefault()
            if hasattr(fd, 'pushBranch'):
                fd.pushBranch(cbranchblock, 1 - indpath, switchbl)
        else:
            val = 0 if ((indpath == 0) != cbranch.isBooleanFlip()) else 1
            if hasattr(fd, 'opSetInput') and hasattr(fd, 'newConstant'):
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
            if hasattr(cbranch, 'isDead') and cbranch.isDead():
                guard.clear()
                continue
            if self.foldInOneGuard(fd, guard, jump):
                change = True
        return change

    def sanityCheck(self, fd, indop, addresstable: list,
                    loadpoints=None, loadcounts=None) -> bool:
        """Validate the address table, truncating at first unreasonable entry.

        C++ ref: JumpBasic::sanityCheck in jumptable.cc
        """
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
                    glb = fd.getArch() if hasattr(fd, 'getArch') else None
                    loader = glb.loader if glb is not None and hasattr(glb, 'loader') else None
                    dataavail = True
                    if loader is not None and hasattr(loader, 'loadFill'):
                        try:
                            loader.loadFill(bytearray(4), 4, addresstable[i])
                        except Exception:
                            dataavail = False
                    else:
                        dataavail = False
                    if not dataavail:
                        break
            else:
                i = len(addresstable)
        if i == 0:
            return False
        if i != len(addresstable):
            del addresstable[i:]
            if self.jrange is not None:
                self.jrange.truncate(i)
            if loadcounts is not None and loadpoints is not None:
                del loadpoints[loadcounts[i - 1]:]
        return True

    def clone(self, jt):
        """Clone this model for a new JumpTable.

        C++ ref: JumpBasic::clone in jumptable.cc
        """
        res = JumpBasic(jt)
        if self.jrange is not None:
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

    def __init__(self, jt=None) -> None:
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

    def recoverModel(self, fd, indop, matchsize: int = 0, maxtablesize: int = 1024) -> bool:
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
        # Search for a constant along one of the paths
        path = -1
        copyop = None
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
                copyop = cop
                path = p
                break
        if path == -1:
            return False
        rootbl = multiop.getParent().getIn(1 - path)
        pathout = multiop.getParent().getInRevIndex(1 - path) if hasattr(multiop.getParent(), 'getInRevIndex') else 0
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
        if hasattr(self.normalvn, 'isInput') and self.normalvn.isInput():
            return True
        if not self.normalvn.isWritten():
            return True
        defblock = self.normalvn.getDef().getParent()
        switchblock = self.pathMeld.getOp(0).getParent()
        while switchblock is not None:
            if switchblock is defblock:
                return True
            switchblock = switchblock.getImmedDom() if hasattr(switchblock, 'getImmedDom') else None
        return False

    def findUnnormalized(self, maxaddsub: int = 0, maxleftright: int = 0, maxext: int = 0) -> None:
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
        if self.jrange is not None:
            res.jrange = self.jrange.clone()
        return res

    def clear(self):
        """Clear all state.

        C++ ref: JumpBasic2::clear in jumptable.cc
        """
        self.extravn = None
        self.origPathMeld.clear()
        super().clear()


class JumpBasicOverride(JumpModel):
    """A jump-table model where addresses are explicitly provided by an override."""

    def __init__(self, jt=None) -> None:
        super().__init__(jt)
        self._addrOverride: list = []

    def isOverride(self) -> bool:
        return True

    def getTableSize(self) -> int:
        return len(self._addrOverride)

    def recoverModel(self, fd, indop, matchsize=0, maxtablesize=1024) -> bool:
        return len(self._addrOverride) > 0

    def buildAddresses(self, fd, indop, addresstable, loadpoints=None, loadcounts=None):
        addresstable.extend(self._addrOverride)

    def findUnnormalized(self, maxaddsub=0, maxleftright=0, maxext=0):
        pass

    def buildLabels(self, fd, addresstable, label, orig=None):
        for i in range(len(addresstable)):
            label.append(i)

    def foldInNormalization(self, fd, indop):
        return None

    def foldInGuards(self, fd, jump) -> bool:
        return False

    def sanityCheck(self, fd, indop, addresstable, loadpoints=None, loadcounts=None) -> bool:
        return True

    def clone(self, jt):
        m = JumpBasicOverride(jt)
        m._addrOverride = list(self._addrOverride)
        return m

    def clear(self):
        self._addrOverride.clear()

    def getNumOverrides(self) -> int:
        return len(self._addrOverride)

    def addOverride(self, addr) -> None:
        self._addrOverride.append(addr)

    def getOverride(self, i: int):
        return self._addrOverride[i]

    def encode(self, encoder) -> None:
        """Encode this override as a <basicoverride> element.

        C++ ref: ``JumpBasicOverride::encode``
        """
        from ghidra.core.marshal import (
            ELEM_BASICOVERRIDE, ELEM_DEST,
            ELEM_NORMADDR, ELEM_NORMHASH, ELEM_STARTVAL,
            ATTRIB_CONTENT,
        )
        encoder.openElement(ELEM_BASICOVERRIDE)
        for addr in self._addrOverride:
            encoder.openElement(ELEM_DEST)
            spc = addr.getSpace()
            if spc is not None and hasattr(spc, 'encodeAttributes'):
                spc.encodeAttributes(encoder, addr.getOffset())
            encoder.closeElement(ELEM_DEST)
        encoder.closeElement(ELEM_BASICOVERRIDE)

    def decode(self, decoder) -> None:
        """Decode this override from a <basicoverride> element.

        C++ ref: ``JumpBasicOverride::decode``
        """
        from ghidra.core.marshal import (
            ELEM_BASICOVERRIDE, ELEM_DEST,
            ELEM_NORMADDR, ELEM_NORMHASH, ELEM_STARTVAL,
            ATTRIB_CONTENT,
        )
        elemId = decoder.openElement(ELEM_BASICOVERRIDE)
        while True:
            subId = decoder.openElement()
            if subId == 0:
                break
            if subId == ELEM_DEST.id:
                addr = Address.decode(decoder)
                self._addrOverride.append(addr)
            decoder.closeElement(subId)
        decoder.closeElement(elemId)
