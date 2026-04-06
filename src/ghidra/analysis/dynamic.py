"""
DynamicHash: Hash-based Varnode identification for dynamic symbols.
Corresponds to dynamic.hh / dynamic.cc.
"""
from __future__ import annotations
from typing import Optional, List, TYPE_CHECKING
from ghidra.core.address import Address
from ghidra.core.crc32 import crc_update

if TYPE_CHECKING:
    from ghidra.ir.varnode import Varnode
    from ghidra.ir.op import PcodeOp
    from ghidra.analysis.funcdata import Funcdata


class ToOpEdge:
    """An edge between a Varnode and a PcodeOp in a data-flow sub-graph.

    C++ ref: ToOpEdge
    """

    def __init__(self, op=None, slot: int = -1) -> None:
        self._op = op
        self._slot: int = slot

    def getOp(self):
        return self._op

    def getSlot(self) -> int:
        return self._slot

    def __lt__(self, op2: ToOpEdge) -> bool:
        """C++ ref: ToOpEdge::operator<"""
        addr1 = self._op.getSeqNum().getAddr()
        addr2 = op2._op.getSeqNum().getAddr()
        if addr1 != addr2:
            return addr1 < addr2
        ord1 = self._op.getSeqNum().getOrder()
        ord2 = op2._op.getSeqNum().getOrder()
        if ord1 != ord2:
            return ord1 < ord2
        return self._slot < op2._slot

    def hash(self, reg: int) -> int:
        """Hash this edge into an accumulator.

        C++ ref: ToOpEdge::hash
        """
        reg = crc_update(reg, self._slot & 0xFFFFFFFF)
        reg = crc_update(reg, DynamicHash.transtable[self._op.code()])
        val = self._op.getSeqNum().getAddr().getOffset()
        sz = self._op.getSeqNum().getAddr().getAddrSize()
        for _ in range(sz):
            reg = crc_update(reg, val & 0xFF)
            val >>= 8
        return reg


class DynamicHash:
    """Uniquely identify a Varnode via a hash of its local data-flow neighborhood.

    Calculates a hash and an address of the PcodeOp most closely associated
    with the Varnode.  There are four Varnode hash methods (0-3) and three
    PcodeOp hash methods (4-6).

    C++ ref: DynamicHash
    """

    # fmt: off
    # Translation table: opcode index -> hash value.  Some opcodes map to
    # the same hash so the hash is invariant under common op-code variants.
    # C++ ref: DynamicHash::transtable
    transtable: List[int] = [
        0,      # 0  unused
        1,      # 1  COPY
        2,      # 2  LOAD
        3,      # 3  STORE
        4,      # 4  BRANCH
        5,      # 5  CBRANCH
        6,      # 6  BRANCHIND
        7,      # 7  CALL
        8,      # 8  CALLIND
        9,      # 9  CALLOTHER
        10,     # 10 RETURN
        11,     # 11 INT_EQUAL
        11,     # 12 INT_NOTEQUAL -> INT_EQUAL
        13,     # 13 INT_SLESS
        13,     # 14 INT_SLESSEQUAL -> INT_SLESS
        15,     # 15 INT_LESS
        15,     # 16 INT_LESSEQUAL -> INT_LESS
        17,     # 17 INT_ZEXT
        18,     # 18 INT_SEXT
        19,     # 19 INT_ADD
        19,     # 20 INT_SUB -> INT_ADD
        21,     # 21 INT_CARRY
        22,     # 22 INT_SCARRY
        23,     # 23 INT_SBORROW
        24,     # 24 INT_2COMP
        25,     # 25 INT_NEGATE
        26,     # 26 INT_XOR
        27,     # 27 INT_AND
        28,     # 28 INT_OR
        32,     # 29 INT_LEFT -> INT_MULT
        30,     # 30 INT_RIGHT
        31,     # 31 INT_SRIGHT
        32,     # 32 INT_MULT
        33,     # 33 INT_DIV
        34,     # 34 INT_SDIV
        35,     # 35 INT_REM
        36,     # 36 INT_SREM
        37,     # 37 BOOL_NEGATE
        38,     # 38 BOOL_XOR
        39,     # 39 BOOL_AND
        40,     # 40 BOOL_OR
        41,     # 41 FLOAT_EQUAL
        41,     # 42 FLOAT_NOTEQUAL -> FLOAT_EQUAL
        43,     # 43 FLOAT_LESS
        43,     # 44 FLOAT_LESSEQUAL -> FLOAT_LESS
        0,      # 45 unused slot
        46,     # 46 FLOAT_NAN
        47,     # 47 FLOAT_ADD
        48,     # 48 FLOAT_DIV
        49,     # 49 FLOAT_MULT
        47,     # 50 FLOAT_SUB -> FLOAT_ADD
        51,     # 51 FLOAT_NEG
        52,     # 52 FLOAT_ABS
        53,     # 53 FLOAT_SQRT
        54,     # 54 FLOAT_INT2FLOAT
        55,     # 55 FLOAT_FLOAT2FLOAT
        56,     # 56 FLOAT_TRUNC
        57,     # 57 FLOAT_CEIL
        58,     # 58 FLOAT_FLOOR
        59,     # 59 FLOAT_ROUND
        60,     # 60 MULTIEQUAL
        61,     # 61 INDIRECT
        62,     # 62 PIECE
        63,     # 63 SUBPIECE
        0,      # 64 CAST (skipped)
        19,     # 65 PTRADD -> INT_ADD
        19,     # 66 PTRSUB -> INT_ADD
        67,     # 67 SEGMENTOP
        68,     # 68 CPOOLREF
        69,     # 69 NEW
        70,     # 70 INSERT
        71,     # 71 EXTRACT
        72,     # 72 POPCOUNT
        73,     # 73 LZCOUNT
    ]
    # fmt: on

    def __init__(self) -> None:
        self.hash: int = 0
        self.addrresult: Address = Address()
        self.markop: list = []
        self.markvn: list = []
        self.vnedge: list = []
        self.opedge: List[ToOpEdge] = []
        self.vnproc: int = 0
        self.opproc: int = 0
        self.opedgeproc: int = 0

    def clear(self) -> None:
        """C++ ref: DynamicHash::clear"""
        self.markop.clear()
        self.markvn.clear()
        self.vnedge.clear()
        self.opedge.clear()

    def getHash(self) -> int:
        return self.hash

    def setHash(self, h: int) -> None:
        self.hash = h

    def setAddress(self, addr: Address) -> None:
        self.addrresult = addr

    def getAddress(self) -> Address:
        return self.addrresult

    # ----------------------------------------------------------------
    # Sub-graph building methods (C++ ref: DynamicHash::build*)
    # ----------------------------------------------------------------

    def buildVnUp(self, vn) -> None:
        """Build edge from Varnode upward to its defining op, skipping CAST-like ops.

        C++ ref: DynamicHash::buildVnUp
        """
        while True:
            if not vn.isWritten():
                return
            op = vn.getDef()
            if self.transtable[op.code()] != 0:
                break
            vn = op.getIn(0)
        self.opedge.append(ToOpEdge(op, -1))

    def buildVnDown(self, vn) -> None:
        """Build edges from Varnode downward to consuming ops, skipping CAST-like ops.

        C++ ref: DynamicHash::buildVnDown
        """
        insize = len(self.opedge)
        for op in vn.getDescendants():
            tmpvn = vn
            while self.transtable[op.code()] == 0:
                tmpvn = op.getOut()
                if tmpvn is None:
                    op = None
                    break
                op = tmpvn.loneDescend()
                if op is None:
                    break
            if op is None:
                continue
            slot = op.getSlot(tmpvn)
            self.opedge.append(ToOpEdge(op, slot))
        if len(self.opedge) - insize > 1:
            self.opedge[insize:] = sorted(self.opedge[insize:])

    def buildOpUp(self, op) -> None:
        """Add all input Varnodes of op to vnedge.

        C++ ref: DynamicHash::buildOpUp
        """
        for i in range(op.numInput()):
            self.vnedge.append(op.getIn(i))

    def buildOpDown(self, op) -> None:
        """Add output Varnode of op to vnedge.

        C++ ref: DynamicHash::buildOpDown
        """
        vn = op.getOut()
        if vn is not None:
            self.vnedge.append(vn)

    def gatherUnmarkedVn(self) -> None:
        """Move unmarked Varnodes from vnedge into markvn.

        C++ ref: DynamicHash::gatherUnmarkedVn
        """
        for vn in self.vnedge:
            if vn is None:
                continue
            if vn.isMark():
                continue
            self.markvn.append(vn)
            vn.setMark()
        self.vnedge.clear()

    def gatherUnmarkedOp(self) -> None:
        """Move unmarked PcodeOps from opedge into markop.

        C++ ref: DynamicHash::gatherUnmarkedOp
        """
        while self.opedgeproc < len(self.opedge):
            op = self.opedge[self.opedgeproc].getOp()
            self.opedgeproc += 1
            if op.isMark():
                continue
            self.markop.append(op)
            op.setMark()

    # ----------------------------------------------------------------
    # Hash calculation (C++ ref: DynamicHash::calcHash)
    # ----------------------------------------------------------------

    def calcHash(self, root, method: int = 0) -> None:
        """Calculate hash for a given Varnode based on its local data-flow.

        C++ ref: DynamicHash::calcHash (Varnode version)
        """
        self.vnproc = 0
        self.opproc = 0
        self.opedgeproc = 0

        self.vnedge.append(root)
        self.gatherUnmarkedVn()
        for i in range(self.vnproc, len(self.markvn)):
            self.buildVnUp(self.markvn[i])
        while self.vnproc < len(self.markvn):
            self.buildVnDown(self.markvn[self.vnproc])
            self.vnproc += 1

        if method == 0:
            pass
        elif method == 1:
            self.gatherUnmarkedOp()
            while self.opproc < len(self.markop):
                self.buildOpUp(self.markop[self.opproc])
                self.opproc += 1
            self.gatherUnmarkedVn()
            while self.vnproc < len(self.markvn):
                self.buildVnUp(self.markvn[self.vnproc])
                self.vnproc += 1
        elif method == 2:
            self.gatherUnmarkedOp()
            while self.opproc < len(self.markop):
                self.buildOpDown(self.markop[self.opproc])
                self.opproc += 1
            self.gatherUnmarkedVn()
            while self.vnproc < len(self.markvn):
                self.buildVnDown(self.markvn[self.vnproc])
                self.vnproc += 1
        elif method == 3:
            self.gatherUnmarkedOp()
            while self.opproc < len(self.markop):
                self.buildOpUp(self.markop[self.opproc])
                self.opproc += 1
            self.gatherUnmarkedVn()
            while self.vnproc < len(self.markvn):
                self.buildVnDown(self.markvn[self.vnproc])
                self.vnproc += 1

        self.pieceTogetherHash(root, method)

    def calcHashOp(self, op, slot: int, method: int = 4) -> None:
        """Calculate hash for a given PcodeOp and slot.

        C++ ref: DynamicHash::calcHash (PcodeOp version)
        """
        if slot < 0:
            root = op.getOut()
            if root is None:
                self.hash = 0
                self.addrresult = Address()
                return
        else:
            if slot >= op.numInput():
                self.hash = 0
                self.addrresult = Address()
                return
            root = op.getIn(slot)

        self.vnproc = 0
        self.opproc = 0
        self.opedgeproc = 0

        self.opedge.append(ToOpEdge(op, slot))
        if method == 4:
            pass
        elif method == 5:
            self.gatherUnmarkedOp()
            while self.opproc < len(self.markop):
                self.buildOpUp(self.markop[self.opproc])
                self.opproc += 1
            self.gatherUnmarkedVn()
            while self.vnproc < len(self.markvn):
                self.buildVnUp(self.markvn[self.vnproc])
                self.vnproc += 1
        elif method == 6:
            self.gatherUnmarkedOp()
            while self.opproc < len(self.markop):
                self.buildOpDown(self.markop[self.opproc])
                self.opproc += 1
            self.gatherUnmarkedVn()
            while self.vnproc < len(self.markvn):
                self.buildVnDown(self.markvn[self.vnproc])
                self.vnproc += 1

        self.pieceTogetherHash(root, method)

    def pieceTogetherHash(self, root, method: int) -> None:
        """Assemble the final 64-bit hash from accumulated edges.

        C++ ref: DynamicHash::pieceTogetherHash
        """
        for vn in self.markvn:
            vn.clearMark()
        for op in self.markop:
            op.clearMark()

        if len(self.opedge) == 0:
            self.hash = 0
            self.addrresult = Address()
            return

        reg = 0x3BA0FE06
        reg = crc_update(reg, root.getSize() & 0xFF)
        if root.isConstant():
            val = root.getOffset()
            for _ in range(root.getSize()):
                reg = crc_update(reg, val & 0xFF)
                val >>= 8

        for edge in self.opedge:
            reg = edge.hash(reg)

        # Find op directly attached to root
        attached_op = None
        attached_slot = 0
        attachedop = True
        for ct, edge in enumerate(self.opedge):
            op = edge.getOp()
            sl = edge.getSlot()
            if sl < 0 and op.getOut() is root:
                attached_op = op
                attached_slot = sl
                break
            if sl >= 0 and op.getIn(sl) is root:
                attached_op = op
                attached_slot = sl
                break
        else:
            attached_op = self.opedge[0].getOp()
            attached_slot = self.opedge[0].getSlot()
            attachedop = False

        # Build the 64-bit hash:
        # 15 bits unused | 1 bit attached | 4 bits method | 7 bits opcode | 5 bits slot | 32 bits reg
        h = 0 if attachedop else 1
        h <<= 4
        h |= (method & 0xF)
        h <<= 7
        h |= (self.transtable[attached_op.code()] & 0x7F)
        h <<= 5
        h |= (attached_slot & 0x1F)
        h <<= 32
        h |= (reg & 0xFFFFFFFF)
        self.hash = h
        self.addrresult = attached_op.getSeqNum().getAddr()

    @staticmethod
    def moveOffSkip(op_slot: list) -> None:
        """Move off skipped opcodes (CAST etc.) following data-flow.

        op_slot is a two-element list: [op, slot].  Modified in place.
        C++ ref: DynamicHash::moveOffSkip
        """
        op, slot = op_slot[0], op_slot[1]
        while DynamicHash.transtable[op.code()] == 0:
            if slot >= 0:
                vn = op.getOut()
                op = vn.loneDescend() if vn is not None else None
                if op is None:
                    op_slot[0] = None
                    return
                slot = op.getSlot(vn)
            else:
                vn = op.getIn(0)
                if not vn.isWritten():
                    op_slot[0] = None
                    return
                op = vn.getDef()
        op_slot[0] = op
        op_slot[1] = slot

    # ----------------------------------------------------------------
    # Unique hash and lookup (C++ ref: DynamicHash::uniqueHash / find*)
    # ----------------------------------------------------------------

    def uniqueHash(self, root_or_op, fd_or_slot=None, fd2=None) -> None:
        """Select a unique hash for the given Varnode or PcodeOp+slot.

        C++ ref: DynamicHash::uniqueHash
        """
        if fd2 is not None:
            # uniqueHash(op, slot, fd)
            op = root_or_op
            slot = fd_or_slot
            fd = fd2
            os_ref = [op, slot]
            self.moveOffSkip(os_ref)
            op, slot = os_ref[0], os_ref[1]
            if op is None:
                self.hash = 0
                self.addrresult = Address()
                return
            oplist: list = []
            self.gatherOpsAtAddress(oplist, fd, op.getAddr())
            champion: list = []
            tmphash = 0
            tmpaddr = Address()
            maxdup = 8
            for method in range(4, 7):
                self.clear()
                self.calcHashOp(op, slot, method)
                if self.hash == 0:
                    return
                tmphash = self.hash
                tmpaddr = self.addrresult
                oplist2: list = []
                for tmpop in oplist:
                    if slot >= tmpop.numInput():
                        continue
                    self.clear()
                    self.calcHashOp(tmpop, slot, method)
                    if self.getComparable(self.hash) == self.getComparable(tmphash):
                        oplist2.append(tmpop)
                        if len(oplist2) > maxdup:
                            break
                if len(oplist2) <= maxdup:
                    if len(champion) == 0 or len(oplist2) < len(champion):
                        champion = oplist2
                        if len(champion) == 1:
                            break
            if not champion:
                self.hash = 0
                self.addrresult = Address()
                return
            total = len(champion) - 1
            pos = 0
            for pos in range(len(champion)):
                if champion[pos] is op:
                    break
            else:
                self.hash = 0
                self.addrresult = Address()
                return
            self.hash = tmphash | (pos << 49) | (total << 52)
            self.addrresult = tmpaddr
        else:
            # uniqueHash(vn, fd)
            root = root_or_op
            fd = fd_or_slot
            champion = []
            tmphash = 0
            tmpaddr = Address()
            maxdup = 8
            for method in range(4):
                self.clear()
                self.calcHash(root, method)
                if self.hash == 0:
                    return
                tmphash = self.hash
                tmpaddr = self.addrresult
                vnlist: list = []
                vnlist2: list = []
                self.gatherFirstLevelVars(vnlist, fd, tmpaddr, tmphash)
                for tmpvn in vnlist:
                    self.clear()
                    self.calcHash(tmpvn, method)
                    if self.getComparable(self.hash) == self.getComparable(tmphash):
                        vnlist2.append(tmpvn)
                        if len(vnlist2) > maxdup:
                            break
                if len(vnlist2) <= maxdup:
                    if len(champion) == 0 or len(vnlist2) < len(champion):
                        champion = vnlist2
                        if len(champion) == 1:
                            break
            if not champion:
                self.hash = 0
                self.addrresult = Address()
                return
            total = len(champion) - 1
            pos = 0
            for pos in range(len(champion)):
                if champion[pos] is root:
                    break
            else:
                self.hash = 0
                self.addrresult = Address()
                return
            self.hash = tmphash | (pos << 49) | (total << 52)
            self.addrresult = tmpaddr

    def findVarnode(self, fd, addr: Address, h: int) -> Optional[Varnode]:
        """Find a Varnode matching the given address and hash.

        C++ ref: DynamicHash::findVarnode
        """
        method = self.getMethodFromHash(h)
        total = self.getTotalFromHash(h)
        pos = self.getPositionFromHash(h)
        h = self.clearTotalPosition(h)
        vnlist: list = []
        vnlist2: list = []
        self.gatherFirstLevelVars(vnlist, fd, addr, h)
        for tmpvn in vnlist:
            self.clear()
            self.calcHash(tmpvn, method)
            if self.getComparable(self.hash) == self.getComparable(h):
                vnlist2.append(tmpvn)
        if total != len(vnlist2):
            return None
        return vnlist2[pos]

    def findOp(self, fd, addr: Address, h: int):
        """Find a PcodeOp matching the given address and hash.

        C++ ref: DynamicHash::findOp
        """
        method = self.getMethodFromHash(h)
        slot = self.getSlotFromHash(h)
        total = self.getTotalFromHash(h)
        pos = self.getPositionFromHash(h)
        h = self.clearTotalPosition(h)
        oplist: list = []
        oplist2: list = []
        self.gatherOpsAtAddress(oplist, fd, addr)
        for tmpop in oplist:
            if slot >= tmpop.numInput():
                continue
            self.clear()
            self.calcHashOp(tmpop, slot, method)
            if self.getComparable(self.hash) == self.getComparable(h):
                oplist2.append(tmpop)
        if total != len(oplist2):
            return None
        return oplist2[pos]

    # ----------------------------------------------------------------
    # Static hash field accessors (C++ ref: DynamicHash::get*FromHash)
    # ----------------------------------------------------------------
    # 64-bit hash layout (from LSB):
    #   bits  0-31 : 32-bit neighborhood CRC
    #   bits 32-36 : slot (5 bits)
    #   bits 37-43 : opcode (7 bits)
    #   bits 44-47 : method (4 bits)
    #   bit  48    : isNotAttached
    #   bits 49-51 : position (3 bits)
    #   bits 52-54 : total (3 bits)

    @staticmethod
    def getSlotFromHash(h: int) -> int:
        """C++ ref: DynamicHash::getSlotFromHash"""
        res = (h >> 32) & 0x1F
        if res == 31:
            res = -1
        return res

    @staticmethod
    def getMethodFromHash(h: int) -> int:
        """C++ ref: DynamicHash::getMethodFromHash"""
        return (h >> 44) & 0xF

    @staticmethod
    def getOpCodeFromHash(h: int) -> int:
        """C++ ref: DynamicHash::getOpCodeFromHash"""
        return (h >> 37) & 0x7F

    @staticmethod
    def getPositionFromHash(h: int) -> int:
        """C++ ref: DynamicHash::getPositionFromHash"""
        return (h >> 49) & 7

    @staticmethod
    def getTotalFromHash(h: int) -> int:
        """C++ ref: DynamicHash::getTotalFromHash"""
        return ((h >> 52) & 7) + 1

    @staticmethod
    def getIsNotAttached(h: int) -> bool:
        """C++ ref: DynamicHash::getIsNotAttached"""
        return ((h >> 48) & 1) != 0

    @staticmethod
    def clearTotalPosition(h: int) -> int:
        """Clear position and total fields from hash.

        C++ ref: DynamicHash::clearTotalPosition
        """
        mask = 0x3F << 49
        return h & ~mask

    @staticmethod
    def getComparable(h: int) -> int:
        """Get the low 32-bit formal hash used for collision comparison."""
        return h & 0xFFFFFFFF

    # ----------------------------------------------------------------
    # Gather helpers (C++ ref: DynamicHash::gather*)
    # ----------------------------------------------------------------

    @staticmethod
    def gatherFirstLevelVars(varlist: list, fd, addr: Address, h: int) -> None:
        """Gather first-level Varnodes at the given address.

        C++ ref: DynamicHash::gatherFirstLevelVars
        """
        opcVal = DynamicHash.getOpCodeFromHash(h)
        slot = DynamicHash.getSlotFromHash(h)
        isnotattached = DynamicHash.getIsNotAttached(h)
        if not hasattr(fd, 'beginOp'):
            return
        for op in fd.beginOp(addr):
            if op.isDead():
                continue
            if DynamicHash.transtable[op.code()] != opcVal:
                continue
            if slot < 0:
                vn = op.getOut()
                if vn is not None:
                    if isnotattached:
                        desc_op = vn.loneDescend()
                        if desc_op is not None:
                            if DynamicHash.transtable[desc_op.code()] == 0:
                                vn = desc_op.getOut()
                                if vn is None:
                                    continue
                    varlist.append(vn)
            elif slot < op.numInput():
                vn = op.getIn(slot)
                if isnotattached:
                    def_op = vn.getDef() if vn.isWritten() else None
                    if def_op is not None and DynamicHash.transtable[def_op.code()] == 0:
                        vn = def_op.getIn(0)
                varlist.append(vn)
        DynamicHash.dedupVarnodes(varlist)

    @staticmethod
    def gatherOpsAtAddress(opList: list, fd, addr: Address) -> None:
        """Gather all live PcodeOps at the given address.

        C++ ref: DynamicHash::gatherOpsAtAddress
        """
        if not hasattr(fd, 'beginOp'):
            return
        for op in fd.beginOp(addr):
            if not op.isDead():
                opList.append(op)

    @staticmethod
    def dedupVarnodes(varlist: list) -> None:
        """Remove duplicate Varnodes, preserving order.

        C++ ref: DynamicHash::dedupVarnodes
        """
        if len(varlist) < 2:
            return
        res: list = []
        for vn in varlist:
            if not vn.isMark():
                vn.setMark()
                res.append(vn)
        for vn in res:
            vn.clearMark()
        varlist.clear()
        varlist.extend(res)

    # ----------------------------------------------------------------
    # Convenience accessors
    # ----------------------------------------------------------------

    def getVnEdges(self) -> list:
        return self.vnedge

    def getOpEdges(self) -> list:
        return self.opedge

    def getMarkOps(self) -> list:
        return self.markop

    def __repr__(self) -> str:
        return f"DynamicHash(hash=0x{self.hash:x})"
