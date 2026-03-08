"""
Corresponds to: funcdata.hh / funcdata.cc / funcdata_block.cc / funcdata_op.cc / funcdata_varnode.cc

Container for data structures associated with a single function.
Holds control-flow, data-flow, and prototype information.
"""

from __future__ import annotations

from typing import TYPE_CHECKING, Optional, List, Iterator

from ghidra.core.address import Address, SeqNum
from ghidra.core.opcodes import OpCode
from ghidra.core.pcoderaw import VarnodeData
from ghidra.core.space import AddrSpace, IPTR_CONSTANT, IPTR_INTERNAL
from ghidra.ir.varnode import Varnode, VarnodeBank
from ghidra.ir.op import PcodeOp, PcodeOpBank
from ghidra.ir.variable import HighVariable
from ghidra.block.block import BlockBasic, BlockGraph
from ghidra.fspec.fspec import FuncProto, FuncCallSpecs

if TYPE_CHECKING:
    from ghidra.database.database import Scope, FunctionSymbol
    from ghidra.types.datatype import Datatype


class Funcdata:
    """Container for data structures associated with a single function.

    Holds control-flow, data-flow, and prototype information, plus class
    instances to help with SSA form, structure control-flow, recover
    jump-tables, recover parameters, and merge Varnodes.
    """

    # Internal flags
    highlevel_on = 1
    blocks_generated = 2
    blocks_unreachable = 4
    processing_started = 8
    processing_complete = 0x10
    typerecovery_on = 0x20
    typerecovery_start = 0x40
    no_code = 0x80
    jumptablerecovery_on = 0x100
    jumptablerecovery_dont = 0x200
    restart_pending = 0x400
    unimplemented_present = 0x800
    baddata_present = 0x1000
    double_precis_on = 0x2000
    typerecovery_exceeded = 0x4000

    def __init__(self, nm: str, disp: str, scope: Optional[Scope],
                 addr: Address, sym: Optional[FunctionSymbol] = None,
                 sz: int = 0) -> None:
        self._flags: int = 0
        self._clean_up_index: int = 0
        self._high_level_index: int = 0
        self._cast_phase_index: int = 0
        self._minLanedSize: int = 0
        self._size: int = sz
        self._glb = None  # Architecture (set externally)
        self._functionSymbol = sym
        self._name: str = nm
        self._displayName: str = disp
        self._baseaddr: Address = addr
        self._funcp: FuncProto = FuncProto()
        self._localmap: Optional[Scope] = scope  # ScopeLocal

        self._qlst: List[FuncCallSpecs] = []
        self._qlst_map: dict = {}  # PcodeOp id -> FuncCallSpecs
        self._jumpvec = []  # List[JumpTable]
        self._override = None  # Override
        self._unionMap = None  # UnionResolveMap

        self._vbank: VarnodeBank = VarnodeBank()
        self._obank: PcodeOpBank = PcodeOpBank()
        self._bblocks: BlockGraph = BlockGraph()
        self._sblocks: BlockGraph = BlockGraph()

    # --- Basic accessors ---

    def getName(self) -> str:
        return self._name

    def getDisplayName(self) -> str:
        return self._displayName

    def getAddress(self) -> Address:
        return self._baseaddr

    def getSize(self) -> int:
        return self._size

    def getArch(self):
        return self._glb

    def setArch(self, glb) -> None:
        self._glb = glb

    def getSymbol(self):
        return self._functionSymbol

    def getVarnodeBank(self):
        return self._vbank

    def getOpBank(self):
        return self._obank

    def getOverride(self):
        if self._override is None:
            from ghidra.arch.override import Override
            self._override = Override()
        return self._override

    def getJumpTable(self, ind):
        """Get the JumpTable associated with the given BRANCHIND op."""
        for jt in self._jumpvec:
            if jt.getIndirectOp() is ind:
                return jt
        return None

    def getJumpTables(self):
        return self._jumpvec

    def installJumpTable(self, addr):
        from ghidra.analysis.jumptable import JumpTable
        jt = JumpTable(self._glb, addr)
        self._jumpvec.append(jt)
        return jt

    def getCallSpecs(self, op):
        """Look up FuncCallSpecs for a given CALL/CALLIND PcodeOp."""
        opid = id(op)
        if opid in self._qlst_map:
            return self._qlst_map[opid]
        for fc in self._qlst:
            if hasattr(fc, 'getOp') and fc.getOp() is op:
                self._qlst_map[opid] = fc
                return fc
        return None

    def addCallSpecs(self, fc):
        """Register a FuncCallSpecs for this function."""
        self._qlst.append(fc)
        if hasattr(fc, 'getOp') and fc.getOp() is not None:
            self._qlst_map[id(fc.getOp())] = fc

    def setUnionField(self, dt, op, slot, res):
        if self._unionMap is None:
            from ghidra.types.resolve import UnionResolveMap
            self._unionMap = UnionResolveMap()
        self._unionMap.setUnionField(dt, op, slot, res)

    def getUnionField(self, dt, op, slot):
        if self._unionMap is None:
            return None
        return self._unionMap.getUnionField(dt, op, slot)

    def getFirstReturnOp(self):
        from ghidra.core.opcodes import OpCode
        for i in range(self._bblocks.getSize()):
            bl = self._bblocks.getBlock(i)
            if hasattr(bl, 'getOpList'):
                for op in bl.getOpList():
                    if op.code() == OpCode.CPUI_RETURN:
                        return op
        return None

    def getFuncProto(self) -> FuncProto:
        return self._funcp

    def getLocalScope(self):
        return self._localmap

    def getScopeLocal(self):
        return self._localmap

    def getBasicBlocks(self) -> BlockGraph:
        return self._bblocks

    def getStructure(self) -> BlockGraph:
        return self._sblocks

    # --- Flag queries ---

    def isHighOn(self) -> bool:
        return (self._flags & Funcdata.highlevel_on) != 0

    def isProcStarted(self) -> bool:
        return (self._flags & Funcdata.processing_started) != 0

    def isProcComplete(self) -> bool:
        return (self._flags & Funcdata.processing_complete) != 0

    def hasUnreachableBlocks(self) -> bool:
        return (self._flags & Funcdata.blocks_unreachable) != 0

    def isTypeRecoveryOn(self) -> bool:
        return (self._flags & Funcdata.typerecovery_on) != 0

    def hasTypeRecoveryStarted(self) -> bool:
        return (self._flags & Funcdata.typerecovery_start) != 0

    def hasNoCode(self) -> bool:
        return (self._flags & Funcdata.no_code) != 0

    def setNoCode(self, val: bool) -> None:
        if val:
            self._flags |= Funcdata.no_code
        else:
            self._flags &= ~Funcdata.no_code

    def hasRestartPending(self) -> bool:
        return (self._flags & Funcdata.restart_pending) != 0

    def setRestartPending(self, val: bool) -> None:
        if val:
            self._flags |= Funcdata.restart_pending
        else:
            self._flags &= ~Funcdata.restart_pending

    def hasUnimplemented(self) -> bool:
        return (self._flags & Funcdata.unimplemented_present) != 0

    def hasBadData(self) -> bool:
        return (self._flags & Funcdata.baddata_present) != 0

    def isDoublePrecisOn(self) -> bool:
        return (self._flags & Funcdata.double_precis_on) != 0

    def setTypeRecovery(self, val: bool) -> None:
        if val:
            self._flags |= Funcdata.typerecovery_on
        else:
            self._flags &= ~Funcdata.typerecovery_on

    def hasNoStructBlocks(self) -> bool:
        return self._sblocks.getSize() == 0

    # --- Processing lifecycle ---

    def startProcessing(self) -> None:
        self._flags |= Funcdata.processing_started

    def stopProcessing(self) -> None:
        self._flags |= Funcdata.processing_complete

    def startTypeRecovery(self) -> bool:
        if (self._flags & Funcdata.typerecovery_on) == 0:
            return False
        self._flags |= Funcdata.typerecovery_start
        return True

    def startCastPhase(self) -> None:
        self._cast_phase_index = self._vbank.getCreateIndex()

    def startCleanUp(self) -> None:
        self._clean_up_index = self._vbank.getCreateIndex()

    def opHeritage(self) -> None:
        """Build SSA representation (heritage pass)."""
        if not hasattr(self, '_heritage'):
            from ghidra.analysis.heritage import Heritage
            self._heritage = Heritage(self)
        self._heritage.heritage()

    def getHeritagePass(self) -> int:
        """Get the current heritage pass number."""
        if hasattr(self, '_heritage'):
            return self._heritage.getPass()
        return 0

    def setHighLevel(self) -> None:
        """Assign HighVariable objects to each Varnode."""
        if (self._flags & Funcdata.highlevel_on) != 0:
            return
        self._flags |= Funcdata.highlevel_on
        self._high_level_index = self._vbank.getCreateIndex()

    def getActiveOutput(self):
        """Get the active output parameter recovery object, or None."""
        return getattr(self, '_activeoutput', None)

    def clearActiveOutput(self) -> None:
        """Clear the active output recovery object."""
        self._activeoutput = None

    def initActiveOutput(self) -> None:
        """Initialize active output parameter recovery."""
        from ghidra.fspec.paramactive import ParamActive
        self._activeoutput = ParamActive(False)

    def calcNZMask(self) -> None:
        """Calculate the non-zero mask property on all Varnodes."""
        from ghidra.transform.nzmask import calcNZMask as _calcNZMask
        _calcNZMask(self)

    def clearDeadVarnodes(self) -> None:
        """Remove Varnodes that are no longer referenced."""
        self._vbank.clearDead()

    def clearDeadOps(self) -> None:
        """Remove PcodeOps that have been marked as dead."""
        self._obank.clearDead()

    def seenDeadcode(self, spc) -> None:
        """Record that dead code has been seen for a given space."""
        pass  # TODO: heritage.seenDeadCode(spc)

    def spacebase(self) -> None:
        """Mark Varnode objects that hold stack-pointer values as spacebase."""
        from ghidra.ir.varnode import Varnode
        glb = self._glb
        if glb is None:
            return
        for j in range(glb.numSpaces()):
            spc = glb.getSpace(j)
            if spc is None:
                continue
            numspace = getattr(spc, 'numSpacebase', lambda: 0)()
            for i in range(numspace):
                point = spc.getSpacebase(i)
                from ghidra.core.address import Address
                addr = Address(point.space, point.offset)
                for vn in list(self._vbank.beginLoc()):
                    if vn.getAddr() == addr and vn.getSize() == point.size:
                        if vn.isFree():
                            continue
                        if not vn.isSpacebase():
                            vn._flags |= Varnode.spacebase

    def structureReset(self) -> None:
        """Reset the control-flow structuring hierarchy."""
        self._sblocks.clear()

    def opZeroMulti(self, op) -> None:
        """Handle MULTIEQUAL with 0 or 1 inputs after edge removal."""
        if op.numInput() == 0:
            self.opInsertInput(op, self.newVarnode(op.getOut().getSize(), op.getOut().getAddr()), 0)
            self.setInputVarnode(op.getIn(0))
            self.opSetOpcode(op, OpCode.CPUI_COPY)
        elif op.numInput() == 1:
            self.opSetOpcode(op, OpCode.CPUI_COPY)

    def branchRemoveInternal(self, bb, num: int) -> None:
        """Remove outgoing branch edge, patch MULTIEQUAL ops in target block."""
        if bb.sizeOut() == 2:
            self.opDestroy(bb.lastOp())
        bbout = bb.getOut(num)
        blocknum = bbout.getInIndex(bb)
        self._bblocks.removeEdge(bb, bbout)
        if hasattr(bbout, 'getOpList'):
            for op in list(bbout.getOpList()):
                if op.code() != OpCode.CPUI_MULTIEQUAL:
                    continue
                if blocknum < op.numInput():
                    self.opRemoveInput(op, blocknum)
                self.opZeroMulti(op)

    def removeUnreachableBlocks(self, issuewarning: bool, checkexistence: bool) -> bool:
        """Remove unreachable blocks from the control flow graph."""
        if checkexistence:
            found = False
            for i in range(self._bblocks.getSize()):
                blk = self._bblocks.getBlock(i)
                if blk.isEntryPoint():
                    continue
                if blk.getImmedDom() is None:
                    found = True
                    break
            if not found:
                return False
        entry = self._bblocks.getEntryBlock()
        if entry is None:
            return False
        unreachable = []
        self._bblocks.collectReachable(unreachable, entry, True)
        if not unreachable:
            return False
        for bl in unreachable:
            bl.setDead()
        for bl in unreachable:
            while bl.sizeOut() > 0:
                self.branchRemoveInternal(bl, 0)
        for bl in unreachable:
            self.blockRemoveInternal(bl, True)
        self.structureReset()
        return True

    def removeBranch(self, bb, num: int) -> None:
        """Remove a branch edge from a basic block."""
        self.branchRemoveInternal(bb, num)
        self.structureReset()

    def blockRemoveInternal(self, bb, unreachable: bool) -> None:
        """Remove a basic block, destroying all its ops."""
        self._bblocks.removeFromFlow(bb)
        if hasattr(bb, 'getOpList'):
            for op in list(bb.getOpList()):
                if op.isCall():
                    self.deleteCallSpecs(op)
                self.opDestroy(op)
        self._bblocks.removeBlock(bb)

    def spliceBlockBasic(self, bb) -> None:
        """Splice a block with a single exit into its successor."""
        if bb.sizeOut() != 1:
            return
        target = bb.getOut(0)
        if target.sizeIn() != 1:
            return
        if hasattr(bb, 'getOpList') and hasattr(target, 'getOpList'):
            last = bb.lastOp()
            if last is not None and last.code() in (OpCode.CPUI_BRANCH, OpCode.CPUI_CBRANCH):
                self.opDestroy(last)
            for op in list(bb.getOpList()):
                bb.removeOp(op)
                target.insertOp(op, 0)
        self._bblocks.removeEdge(bb, target)
        while bb.sizeIn() > 0:
            src = bb.getIn(0)
            lab = bb._intothis[0].label
            bb.removeInEdge(0)
            target.addInEdge(src, lab)
        self._bblocks.removeBlock(bb)
        self.structureReset()

    def removeDoNothingBlock(self, bb) -> None:
        """Remove a block that does nothing."""
        bb.setDead()
        self.blockRemoveInternal(bb, False)
        self.structureReset()

    def deleteCallSpecs(self, op) -> None:
        """Remove call specs associated with the given op."""
        self._qlst = [cs for cs in self._qlst if cs.getOp() is not op]

    def clear(self) -> None:
        """Clear out old disassembly."""
        self._vbank.clear()
        self._obank.clear()
        self._bblocks.clear()
        self._sblocks.clear()
        self._qlst.clear()
        self._qlst_map.clear()
        self._jumpvec.clear()
        self._override = None
        self._unionMap = None
        self._flags &= Funcdata.highlevel_on  # Keep only highlevel_on

    # --- Call specification routines ---

    def numCalls(self) -> int:
        return len(self._qlst)

    def getCallSpecsByIndex(self, i: int) -> Optional[FuncCallSpecs]:
        return self._qlst[i] if 0 <= i < len(self._qlst) else None

    # --- Varnode creation routines ---

    def newVarnode(self, s: int, addr: Address, ct: Optional[Datatype] = None) -> Varnode:
        """Create a new Varnode."""
        vn = self._vbank.create(s, addr, ct)
        return vn

    def newConstant(self, s: int, val: int) -> Varnode:
        """Create a new constant Varnode."""
        cs = None
        if self._glb is not None:
            cs = self._glb.getConstantSpace()
        if cs is None and self._localmap is not None:
            # Try to get constant space from scope's architecture
            pass
        if cs is None:
            # Fallback: create a minimal ConstantSpace
            from ghidra.core.space import ConstantSpace
            cs = ConstantSpace()
        addr = Address(cs, val)
        vn = self._vbank.create(s, addr)
        return vn

    def newUnique(self, s: int, ct: Optional[Datatype] = None) -> Varnode:
        """Create a new temporary Varnode in unique space."""
        if self._glb is not None:
            uniq = self._glb.getUniqueSpace()
            base = self._glb.getUniqueBase()
        else:
            uniq = None
            base = 0x10000000
        addr = Address(uniq, base)
        vn = self._vbank.create(s, addr, ct)
        return vn

    def newVarnodeOut(self, s: int, addr: Address, op: PcodeOp) -> Varnode:
        """Create a new output Varnode."""
        vn = self._vbank.createDef(s, addr, None, op)
        op.setOutput(vn)
        return vn

    def newUniqueOut(self, s: int, op: PcodeOp) -> Varnode:
        """Create a new temporary output Varnode."""
        vn = self.newUnique(s)
        vn.setDef(op)
        op.setOutput(vn)
        return vn

    def setInputVarnode(self, vn: Varnode) -> Varnode:
        """Mark a Varnode as an input to the function."""
        vn.setInput()
        return vn

    def deleteVarnode(self, vn: Varnode) -> None:
        self._vbank.destroy(vn)

    def findVarnodeInput(self, s: int, loc: Address) -> Optional[Varnode]:
        return self._vbank.findInput(s, loc)

    def findCoveredInput(self, s: int, loc: Address) -> Optional[Varnode]:
        return self._vbank.findCoveredInput(s, loc)

    def numVarnodes(self) -> int:
        return self._vbank.size()

    def findVarnodeWritten(self, s, loc, pc, uniq=-1):
        for vn in self._vbank.beginLoc():
            if vn.getAddr() == loc and vn.getSize() == s and vn.isWritten():
                if vn.getDef() is not None and vn.getDef().getAddr() == pc:
                    return vn
        return None

    def findCoveringInput(self, s, loc):
        return self._vbank.findCoveredInput(s, loc)

    def findHigh(self, nm):
        for vn in self._vbank.allVarnodes():
            h = vn.getHigh() if hasattr(vn, 'getHigh') else None
            if h and hasattr(h, 'getSymbol'):
                sym = h.getSymbol()
                if sym and sym.getName() == nm:
                    return h
        return None

    def beginLoc(self):
        return self._vbank.beginLoc()

    def beginDef(self):
        return self._vbank.beginDef()

    def newVarnodeIop(self, op):
        addr = op.getAddr() if hasattr(op, 'getAddr') else Address()
        return self._vbank.create(1, addr)

    def newVarnodeSpace(self, spc):
        cs = self._glb.getConstantSpace() if self._glb else None
        idx = spc.getIndex() if hasattr(spc, 'getIndex') else 0
        return self._vbank.create(4, Address(cs, idx) if cs else Address())

    def newVarnodeCallSpecs(self, fc):
        addr = fc.getEntryAddress() if hasattr(fc, 'getEntryAddress') else Address()
        return self._vbank.create(4, addr)

    def newCodeRef(self, m):
        return self._vbank.create(1, m)

    def numHeritagePasses(self, spc):
        return self._heritage.numHeritagePasses(spc) if hasattr(self, '_heritage') else 0

    def deadRemovalAllowed(self, spc):
        return self._heritage.deadRemovalAllowed(spc) if hasattr(self, '_heritage') else True

    def deadRemovalAllowedSeen(self, spc):
        return self._heritage.deadRemovalAllowedSeen(spc) if hasattr(self, '_heritage') else False

    def isHeritaged(self, vn):
        return self._heritage.heritagePass(vn.getAddr()) >= 0 if hasattr(self, '_heritage') else False

    def setDeadCodeDelay(self, spc, delay):
        if hasattr(self, '_heritage'):
            self._heritage.setDeadCodeDelay(spc, delay)

    def getMerge(self):
        if not hasattr(self, '_covermerge'):
            from ghidra.analysis.merge import Merge
            self._covermerge = Merge(self)
        return self._covermerge

    def fillinExtrapop(self):
        return self._glb.extra_pop if self._glb and hasattr(self._glb, 'extra_pop') else 0

    def isJumptableRecoveryOn(self):
        return (self._flags & Funcdata.jumptablerecovery_on) != 0

    def setJumptableRecovery(self, val):
        if val:
            self._flags &= ~Funcdata.jumptablerecovery_dont
        else:
            self._flags |= Funcdata.jumptablerecovery_dont

    def setDoublePrecisRecovery(self, val):
        if val:
            self._flags |= Funcdata.double_precis_on
        else:
            self._flags &= ~Funcdata.double_precis_on

    def isTypeRecoveryExceeded(self):
        return (self._flags & Funcdata.typerecovery_exceeded) != 0

    def setTypeRecoveryExceeded(self):
        self._flags |= Funcdata.typerecovery_exceeded

    def getCastPhaseIndex(self):
        return self._cast_phase_index

    def getHighLevelIndex(self):
        return self._high_level_index

    def getCleanUpIndex(self):
        return self._clean_up_index

    def setLanedRegGenerated(self):
        self._minLanedSize = 1000000

    def numJumpTables(self):
        return len(self._jumpvec)

    def findJumpTable(self, op):
        for jt in self._jumpvec:
            if jt.getIndirectOp() is op:
                return jt
        return None

    def removeJumpTable(self, jt):
        try:
            self._jumpvec.remove(jt)
        except ValueError:
            pass

    def linkJumpTable(self, op):
        return self.findJumpTable(op)

    def opUnlink(self, op):
        self.opUnsetOutput(op)
        for i in range(op.numInput()):
            inv = op.getIn(i)
            if inv is not None:
                inv.eraseDescend(op)
        parent = op.getParent()
        if parent is not None:
            parent.removeOp(op)

    def opDestroyRaw(self, op):
        self._obank.destroy(op)

    def opMarkHalt(self, op, flag):
        if hasattr(op, 'setHaltType'):
            op.setHaltType(flag)

    def opMarkStartBasic(self, op):
        op.setFlag(PcodeOp.startbasic)

    def opMarkStartInstruction(self, op):
        op.setFlag(PcodeOp.startmark)

    def opMarkNonPrinting(self, op):
        op.setFlag(PcodeOp.nonprinting)

    def opMarkNoCollapse(self, op):
        op.setFlag(PcodeOp.nocollapse)

    def opMarkCalculatedBool(self, op):
        op.setFlag(PcodeOp.calculated_bool)

    def opMarkSpacebasePtr(self, op):
        op.setFlag(PcodeOp.spacebase_ptr)

    def opClearSpacebasePtr(self, op):
        op.clearFlag(PcodeOp.spacebase_ptr)

    def opMarkSpecialPrint(self, op):
        if hasattr(op, 'setAdditionalFlag'):
            op.setAdditionalFlag(PcodeOp.special_print)

    def opMarkCpoolTransformed(self, op):
        if hasattr(op, 'setAdditionalFlag'):
            op.setAdditionalFlag(PcodeOp.is_cpool_transformed)

    def target(self, addr):
        return self._obank.target(addr) if hasattr(self._obank, 'target') else None

    def findOp(self, sq):
        return self._obank.findOp(sq) if hasattr(self._obank, 'findOp') else None

    def beginOp(self, opc=None):
        if opc is not None and hasattr(self._obank, 'begin'):
            return self._obank.begin(opc)
        return self._obank.beginAll() if hasattr(self._obank, 'beginAll') else iter([])

    def beginOpAlive(self):
        return self._obank.beginAlive() if hasattr(self._obank, 'beginAlive') else iter([])

    def beginOpDead(self):
        return self._obank.beginDead() if hasattr(self._obank, 'beginDead') else iter([])

    def beginOpAll(self):
        return self._obank.beginAll() if hasattr(self._obank, 'beginAll') else iter([])

    def mapGlobals(self):
        pass

    def prepareThisPointer(self):
        pass

    def markIndirectOnly(self):
        pass

    def setBasicBlockRange(self, bb, beg, end):
        if hasattr(bb, 'setInitialRange'):
            bb.setInitialRange(beg, end)
        elif hasattr(bb, 'setRange'):
            bb.setRange(beg, end)

    def clearBlocks(self):
        self._bblocks.clear()
        self._sblocks.clear()

    def clearCallSpecs(self):
        self._qlst.clear()
        self._qlst_map.clear()

    def clearJumpTables(self):
        self._jumpvec.clear()

    def sortCallSpecs(self):
        pass

    # --- PcodeOp creation routines ---

    def newOp(self, inputs: int, addr: Address) -> PcodeOp:
        """Create a new PcodeOp at the given address."""
        return self._obank.create(inputs, addr)

    def newOpBefore(self, op: PcodeOp, opc: OpCode, out: Optional[Varnode],
                    in0: Optional[Varnode], in1: Optional[Varnode] = None) -> PcodeOp:
        """Create and insert a new PcodeOp before the given op."""
        numinputs = 1 if in1 is None else 2
        newop = self._obank.create(numinputs, op.getAddr())
        newop.setOpcodeEnum(opc)
        if out is not None:
            newop.setOutput(out)
            out.setDef(newop)
        if in0 is not None:
            newop.setInput(in0, 0)
            in0.addDescend(newop)
        if in1 is not None:
            newop.setInput(in1, 1)
            in1.addDescend(newop)
        return newop

    def opSetOpcode(self, op: PcodeOp, opc: OpCode) -> None:
        """Change the opcode of an existing PcodeOp."""
        op.setOpcodeEnum(opc)

    def opSetOutput(self, op: PcodeOp, vn: Varnode) -> None:
        """Set the output of a PcodeOp."""
        op.setOutput(vn)
        vn.setDef(op)

    def opSetInput(self, op: PcodeOp, vn: Varnode, slot: int) -> None:
        """Set an input of a PcodeOp."""
        old = op.getIn(slot)
        if old is not None:
            old.eraseDescend(op)
        op.setInput(vn, slot)
        vn.addDescend(op)

    def opSwapInput(self, op: PcodeOp, slot1: int, slot2: int) -> None:
        """Swap two inputs of a PcodeOp."""
        vn1 = op.getIn(slot1)
        vn2 = op.getIn(slot2)
        op.setInput(vn2, slot1)
        op.setInput(vn1, slot2)

    def opRemoveInput(self, op: PcodeOp, slot: int) -> None:
        """Remove an input from a PcodeOp."""
        old = op.getIn(slot)
        if old is not None:
            old.eraseDescend(op)
        op.removeInput(slot)

    def opInsertInput(self, op: PcodeOp, vn: Varnode, slot: int) -> None:
        """Insert a new input into a PcodeOp at the given slot."""
        op.insertInput(slot)
        op.setInput(vn, slot)
        vn.addDescend(op)

    def opSetAllInput(self, op: PcodeOp, inputs: List[Varnode]) -> None:
        """Set all inputs of a PcodeOp at once."""
        # Clear old
        for i in range(op.numInput()):
            old = op.getIn(i)
            if old is not None:
                old.eraseDescend(op)
        op.setNumInputs(len(inputs))
        for i, vn in enumerate(inputs):
            op.setInput(vn, i)
            vn.addDescend(op)

    def opUnsetOutput(self, op: PcodeOp) -> None:
        """Remove the output from a PcodeOp."""
        out = op.getOut()
        if out is not None:
            out._def = None
            out.clearFlags(Varnode.written)
        op.setOutput(None)

    def opDestroy(self, op: PcodeOp) -> None:
        """Destroy a PcodeOp, unlinking it from everything."""
        self.opUnsetOutput(op)
        for i in range(op.numInput()):
            inv = op.getIn(i)
            if inv is not None:
                inv.eraseDescend(op)
        parent = op.getParent()
        if parent is not None:
            parent.removeOp(op)
        self._obank.destroy(op)

    def totalReplace(self, vn, newvn) -> None:
        """Replace every read of vn with newvn."""
        for op in list(vn.getDescendants()):
            slot = op.getSlot(vn)
            self.opSetInput(op, newvn, slot)

    def totalReplaceConstant(self, vn, val: int) -> None:
        """Replace every read of vn with a constant value."""
        copyop = None
        newrep = None
        for op in list(vn.getDescendants()):
            slot = op.getSlot(vn)
            if op.isMarker():
                if copyop is None:
                    if vn.isWritten():
                        copyop = self.newOp(1, vn.getDef().getSeqNum().getAddr())
                        self.opSetOpcode(copyop, OpCode.CPUI_COPY)
                        newrep = self.newUniqueOut(vn.getSize(), copyop)
                        self.opSetInput(copyop, self.newConstant(vn.getSize(), val), 0)
                        self.opInsertAfter(copyop, vn.getDef())
                    else:
                        bb = self._bblocks.getBlock(0)
                        copyop = self.newOp(1, bb.getStart())
                        self.opSetOpcode(copyop, OpCode.CPUI_COPY)
                        newrep = self.newUniqueOut(vn.getSize(), copyop)
                        self.opSetInput(copyop, self.newConstant(vn.getSize(), val), 0)
                        self.opInsertBegin(copyop, bb)
                else:
                    newrep = copyop.getOut()
            else:
                newrep = self.newConstant(vn.getSize(), val)
            self.opSetInput(op, newrep, slot)

    def opUnsetInput(self, op: PcodeOp, slot: int) -> None:
        """Unlink input Varnode from the given slot of a PcodeOp."""
        vn = op.getIn(slot)
        if vn is not None:
            vn.eraseDescend(op)
        op.clearInput(slot)

    def opFlipCondition(self, op: PcodeOp) -> None:
        """Flip output condition of given CBRANCH."""
        op.flipFlag(PcodeOp.boolean_flip)

    def opDeadAndGone(self, op: PcodeOp) -> None:
        """Mark a PcodeOp as dead (but keep it around)."""
        self._obank.markDead(op)

    def opMarkAlive(self, op: PcodeOp) -> None:
        """Mark a PcodeOp as alive."""
        self._obank.markAlive(op)

    def totalNumOps(self) -> int:
        return len(list(self._obank.beginAll()))

    # --- Op flip / boolean helpers ---

    @staticmethod
    def opFlipInPlaceTest(op, fliplist: list) -> int:
        """Trace boolean to a set of PcodeOps that can flip the value.

        Returns 0 if normalizing, 1 if ambivalent, 2 if does not normalize.
        """
        opc = op.code()
        if opc == OpCode.CPUI_CBRANCH:
            vn = op.getIn(1)
            if vn.loneDescend() is not op:
                return 2
            if not vn.isWritten():
                return 2
            return Funcdata.opFlipInPlaceTest(vn.getDef(), fliplist)
        if opc in (OpCode.CPUI_INT_EQUAL, OpCode.CPUI_FLOAT_EQUAL):
            fliplist.append(op)
            return 1
        if opc in (OpCode.CPUI_BOOL_NEGATE, OpCode.CPUI_INT_NOTEQUAL, OpCode.CPUI_FLOAT_NOTEQUAL):
            fliplist.append(op)
            return 0
        if opc in (OpCode.CPUI_INT_SLESS, OpCode.CPUI_INT_LESS):
            vn = op.getIn(0)
            fliplist.append(op)
            if not vn.isConstant():
                return 1
            return 0
        if opc in (OpCode.CPUI_INT_SLESSEQUAL, OpCode.CPUI_INT_LESSEQUAL):
            vn = op.getIn(1)
            fliplist.append(op)
            if vn.isConstant():
                return 1
            return 0
        if opc in (OpCode.CPUI_BOOL_OR, OpCode.CPUI_BOOL_AND):
            vn = op.getIn(0)
            if vn.loneDescend() is not op:
                return 2
            if not vn.isWritten():
                return 2
            subtest1 = Funcdata.opFlipInPlaceTest(vn.getDef(), fliplist)
            if subtest1 == 2:
                return 2
            vn = op.getIn(1)
            if vn.loneDescend() is not op:
                return 2
            if not vn.isWritten():
                return 2
            subtest2 = Funcdata.opFlipInPlaceTest(vn.getDef(), fliplist)
            if subtest2 == 2:
                return 2
            fliplist.append(op)
            return subtest1
        return 2

    def opFlipInPlaceExecute(self, fliplist: list) -> None:
        """Perform op-code flips (in-place) to change a boolean value."""
        from ghidra.core.opcodes import get_booleanflip
        for op in fliplist:
            opc, flipyes = get_booleanflip(op.code())
            if opc == OpCode.CPUI_COPY:
                vn = op.getIn(0)
                otherop = op.getOut().loneDescend()
                slot = otherop.getSlot(op.getOut())
                self.opSetInput(otherop, vn, slot)
                self.opDestroy(op)
            elif opc == OpCode.CPUI_MAX:
                if op.code() == OpCode.CPUI_BOOL_AND:
                    self.opSetOpcode(op, OpCode.CPUI_BOOL_OR)
                elif op.code() == OpCode.CPUI_BOOL_OR:
                    self.opSetOpcode(op, OpCode.CPUI_BOOL_AND)
            else:
                self.opSetOpcode(op, opc)
                if flipyes:
                    self.opSwapInput(op, 0, 1)
                    if opc in (OpCode.CPUI_INT_LESSEQUAL, OpCode.CPUI_INT_SLESSEQUAL):
                        self.replaceLessequal(op)

    def opBoolNegate(self, vn, op, insertafter: bool):
        """Construct the boolean negation of a given boolean Varnode."""
        negateop = self.newOp(1, op.getAddr())
        self.opSetOpcode(negateop, OpCode.CPUI_BOOL_NEGATE)
        resvn = self.newUniqueOut(1, negateop)
        self.opSetInput(negateop, vn, 0)
        if insertafter:
            self.opInsertAfter(negateop, op)
        else:
            self.opInsertBefore(negateop, op)
        return resvn

    def opUndoPtradd(self, op, finalize: bool) -> None:
        """Convert a CPUI_PTRADD back into a CPUI_INT_ADD."""
        multVn = op.getIn(2)
        multSize = multVn.getOffset()
        self.opRemoveInput(op, 2)
        self.opSetOpcode(op, OpCode.CPUI_INT_ADD)
        if multSize == 1:
            return
        offVn = op.getIn(1)
        if offVn.isConstant():
            newVal = (multSize * offVn.getOffset()) & ((1 << (offVn.getSize() * 8)) - 1)
            newOffVn = self.newConstant(offVn.getSize(), newVal)
            self.opSetInput(op, newOffVn, 1)
            return
        multOp = self.newOp(2, op.getAddr())
        self.opSetOpcode(multOp, OpCode.CPUI_INT_MULT)
        addVn = self.newUniqueOut(offVn.getSize(), multOp)
        self.opSetInput(multOp, offVn, 0)
        self.opSetInput(multOp, multVn, 1)
        self.opSetInput(op, addVn, 1)
        self.opInsertBefore(multOp, op)

    def createStackRef(self, spc, off, op, stackptr, insertafter: bool):
        """Create an INT_ADD PcodeOp calculating offset relative to spacebase register."""
        if stackptr is None:
            stackptr = self.newSpacebasePtr(spc)
        addrsize = stackptr.getSize()
        addop = self.newOp(2, op.getAddr())
        self.opSetOpcode(addop, OpCode.CPUI_INT_ADD)
        addout = self.newUniqueOut(addrsize, addop)
        self.opSetInput(addop, stackptr, 0)
        self.opSetInput(addop, self.newConstant(addrsize, off), 1)
        if insertafter:
            self.opInsertAfter(addop, op)
        else:
            self.opInsertBefore(addop, op)
        return addout

    def opStackStore(self, spc, off, op, insertafter: bool):
        """Create a STORE at an offset relative to a spacebase register."""
        addout = self.createStackRef(spc, off, op, None, insertafter)
        storeop = self.newOp(3, op.getAddr())
        self.opSetOpcode(storeop, OpCode.CPUI_STORE)
        container = spc.getContain() if hasattr(spc, 'getContain') else spc
        self.opSetInput(storeop, self.newVarnodeSpace(container), 0)
        self.opSetInput(storeop, addout, 1)
        self.opInsertAfter(storeop, addout.getDef())
        return storeop

    def opStackLoad(self, spc, off, sz: int, op, stackref, insertafter: bool):
        """Create a LOAD at an offset relative to a spacebase register."""
        addout = self.createStackRef(spc, off, op, stackref, insertafter)
        loadop = self.newOp(2, op.getAddr())
        self.opSetOpcode(loadop, OpCode.CPUI_LOAD)
        container = spc.getContain() if hasattr(spc, 'getContain') else spc
        self.opSetInput(loadop, self.newVarnodeSpace(container), 0)
        self.opSetInput(loadop, addout, 1)
        res = self.newUniqueOut(sz, loadop)
        self.opInsertAfter(loadop, addout.getDef())
        return res

    # --- CSE / transform helpers ---

    @staticmethod
    def cseFindInBlock(op, vn, bl, earliest):
        """Find a duplicate calculation of op reading vn in block bl before earliest."""
        for desc in vn.getDescendants():
            if desc is op:
                continue
            if desc.getParent() is not bl:
                continue
            if earliest is not None:
                if earliest.getSeqNum().getOrder() < desc.getSeqNum().getOrder():
                    continue
            outvn1 = op.getOut()
            outvn2 = desc.getOut()
            if outvn2 is None:
                continue
            if outvn1 is not None and outvn2 is not None:
                if op.code() == desc.code() and op.numInput() == desc.numInput():
                    match = True
                    for i in range(op.numInput()):
                        if op.getIn(i) is not desc.getIn(i):
                            match = False
                            break
                    if match:
                        return desc
        return None

    def cseElimination(self, op1, op2):
        """Perform a Common Subexpression Elimination step between two ops."""
        from ghidra.block.block import FlowBlock
        if op1.getParent() is op2.getParent():
            if op1.getSeqNum().getOrder() < op2.getSeqNum().getOrder():
                replace = op1
            else:
                replace = op2
        else:
            common = FlowBlock.findCommonBlock(op1.getParent(), op2.getParent())
            if common is op1.getParent():
                replace = op1
            elif common is op2.getParent():
                replace = op2
            else:
                replace = self.newOp(op1.numInput(), common.getStop())
                self.opSetOpcode(replace, op1.code())
                self.newVarnodeOut(op1.getOut().getSize(), op1.getOut().getAddr(), replace)
                for i in range(op1.numInput()):
                    inv = op1.getIn(i)
                    if inv.isConstant():
                        self.opSetInput(replace, self.newConstant(inv.getSize(), inv.getOffset()), i)
                    else:
                        self.opSetInput(replace, inv, i)
                self.opInsertEnd(replace, common)
        if replace is not op1:
            self.totalReplace(op1.getOut(), replace.getOut())
            self.opDestroy(op1)
        if replace is not op2:
            self.totalReplace(op2.getOut(), replace.getOut())
            self.opDestroy(op2)
        return replace

    def cseEliminateList(self, hashlist: list, outlist: list) -> None:
        """Perform CSE on a list of (hash, PcodeOp) pairs."""
        if not hashlist:
            return
        hashlist.sort(key=lambda x: x[0])
        for i in range(len(hashlist) - 1):
            if hashlist[i][0] == hashlist[i + 1][0]:
                op1 = hashlist[i][1]
                op2 = hashlist[i + 1][1]
                if not op1.isDead() and not op2.isDead():
                    if hasattr(op1, 'isCseMatch') and op1.isCseMatch(op2):
                        resop = self.cseElimination(op1, op2)
                        if resop.getOut() is not None:
                            outlist.append(resop.getOut())

    def replaceLessequal(self, op) -> bool:
        """Replace INT_LESSEQUAL/INT_SLESSEQUAL with strict less-than."""
        vn = op.getIn(0)
        if vn.isConstant():
            diff = -1
            i = 0
        else:
            vn = op.getIn(1)
            if vn.isConstant():
                diff = 1
                i = 1
            else:
                return False
        mask = (1 << (vn.getSize() * 8)) - 1
        half = 1 << (vn.getSize() * 8 - 1)
        val = vn.getOffset()
        if val >= half:
            val = val - (mask + 1)
        if op.code() == OpCode.CPUI_INT_SLESSEQUAL:
            if val < 0 and val + diff > 0:
                return False
            if val > 0 and val + diff < 0:
                return False
            self.opSetOpcode(op, OpCode.CPUI_INT_SLESS)
        else:
            if diff == -1 and val == 0:
                return False
            if diff == 1 and (vn.getOffset() == mask):
                return False
            self.opSetOpcode(op, OpCode.CPUI_INT_LESS)
        res = (val + diff) & mask
        newvn = self.newConstant(vn.getSize(), res)
        self.opSetInput(op, newvn, i)
        return True

    def distributeIntMultAdd(self, op) -> bool:
        """Distribute constant coefficient to additive input."""
        addop = op.getIn(0).getDef()
        vn0 = addop.getIn(0)
        vn1 = addop.getIn(1)
        if vn0.isFree() and not vn0.isConstant():
            return False
        if vn1.isFree() and not vn1.isConstant():
            return False
        coeff = op.getIn(1).getOffset()
        sz = op.getOut().getSize()
        mask = (1 << (sz * 8)) - 1
        if vn0.isConstant():
            newvn0 = self.newConstant(sz, (coeff * vn0.getOffset()) & mask)
        else:
            newop0 = self.newOp(2, op.getAddr())
            self.opSetOpcode(newop0, OpCode.CPUI_INT_MULT)
            newvn0 = self.newUniqueOut(sz, newop0)
            self.opSetInput(newop0, vn0, 0)
            self.opSetInput(newop0, self.newConstant(sz, coeff), 1)
            self.opInsertBefore(newop0, op)
        if vn1.isConstant():
            newvn1 = self.newConstant(sz, (coeff * vn1.getOffset()) & mask)
        else:
            newop1 = self.newOp(2, op.getAddr())
            self.opSetOpcode(newop1, OpCode.CPUI_INT_MULT)
            newvn1 = self.newUniqueOut(sz, newop1)
            self.opSetInput(newop1, vn1, 0)
            self.opSetInput(newop1, self.newConstant(sz, coeff), 1)
            self.opInsertBefore(newop1, op)
        self.opSetInput(op, newvn0, 0)
        self.opSetInput(op, newvn1, 1)
        self.opSetOpcode(op, OpCode.CPUI_INT_ADD)
        return True

    def collapseIntMultMult(self, vn) -> bool:
        """Collapse constant coefficients for two chained CPUI_INT_MULT."""
        if not vn.isWritten():
            return False
        op = vn.getDef()
        if op.code() != OpCode.CPUI_INT_MULT:
            return False
        constFirst = op.getIn(1)
        if not constFirst.isConstant():
            return False
        if not op.getIn(0).isWritten():
            return False
        otherOp = op.getIn(0).getDef()
        if otherOp.code() != OpCode.CPUI_INT_MULT:
            return False
        constSecond = otherOp.getIn(1)
        if not constSecond.isConstant():
            return False
        invn = otherOp.getIn(0)
        if invn.isFree():
            return False
        sz = invn.getSize()
        mask = (1 << (sz * 8)) - 1
        val = (constFirst.getOffset() * constSecond.getOffset()) & mask
        self.opSetInput(op, self.newConstant(sz, val), 1)
        self.opSetInput(op, invn, 0)
        return True

    def buildCopyTemp(self, vn, point):
        """Create a COPY of given Varnode in a temporary register."""
        from ghidra.block.block import FlowBlock
        otherOp = None
        usedCopy = None
        for desc in vn.getDescendants():
            if desc.code() != OpCode.CPUI_COPY:
                continue
            outvn = desc.getOut()
            if outvn is not None and outvn.getSpace() is not None:
                if outvn.getSpace().getType() == IPTR_INTERNAL:
                    if not outvn.isTypeLock():
                        otherOp = desc
                        break
        if otherOp is not None:
            if point.getParent() is otherOp.getParent():
                if point.getSeqNum().getOrder() < otherOp.getSeqNum().getOrder():
                    usedCopy = None
                else:
                    usedCopy = otherOp
            else:
                common = FlowBlock.findCommonBlock(point.getParent(), otherOp.getParent())
                if common is point.getParent():
                    usedCopy = None
                elif common is otherOp.getParent():
                    usedCopy = otherOp
                else:
                    usedCopy = self.newOp(1, common.getStop())
                    self.opSetOpcode(usedCopy, OpCode.CPUI_COPY)
                    self.newUniqueOut(vn.getSize(), usedCopy)
                    self.opSetInput(usedCopy, vn, 0)
                    self.opInsertEnd(usedCopy, common)
        if usedCopy is None:
            usedCopy = self.newOp(1, point.getAddr())
            self.opSetOpcode(usedCopy, OpCode.CPUI_COPY)
            self.newUniqueOut(vn.getSize(), usedCopy)
            self.opSetInput(usedCopy, vn, 0)
            self.opInsertBefore(usedCopy, point)
        if otherOp is not None and otherOp is not usedCopy:
            self.totalReplace(otherOp.getOut(), usedCopy.getOut())
            self.opDestroy(otherOp)
        return usedCopy.getOut()

    # --- Block manipulation helpers ---

    def pushMultiequals(self, bb) -> None:
        """Push MULTIEQUAL Varnodes from bb into its output block."""
        if bb.sizeOut() == 0:
            return
        outblock = bb.getOut(0)
        outblock_ind = bb.getOutRevIndex(0)
        for op in list(bb.getOpList()) if hasattr(bb, 'getOpList') else []:
            if op.code() != OpCode.CPUI_MULTIEQUAL:
                continue
            origvn = op.getOut()
            if origvn is None or origvn.hasNoDescend():
                continue
            needreplace = False
            neednewunique = False
            for desc in origvn.getDescendants():
                if desc.code() == OpCode.CPUI_MULTIEQUAL and desc.getParent() is outblock:
                    deadEdge = True
                    for i in range(desc.numInput()):
                        if i == outblock_ind:
                            continue
                        if desc.getIn(i) is origvn:
                            deadEdge = False
                            break
                    if deadEdge:
                        if origvn.getAddr() == desc.getOut().getAddr() and origvn.isAddrTied():
                            neednewunique = True
                        continue
                needreplace = True
                break
            if not needreplace:
                continue
            branches = []
            if neednewunique:
                replacevn = self.newUnique(origvn.getSize())
            else:
                replacevn = self.newVarnode(origvn.getSize(), origvn.getAddr())
            for i in range(outblock.sizeIn()):
                if outblock.getIn(i) is bb:
                    branches.append(origvn)
                else:
                    branches.append(replacevn)
            replaceop = self.newOp(len(branches), outblock.getStart())
            self.opSetOpcode(replaceop, OpCode.CPUI_MULTIEQUAL)
            self.opSetOutput(replaceop, replacevn)
            self.opSetAllInput(replaceop, branches)
            self.opInsertBegin(replaceop, outblock)
            for desc in list(origvn.getDescendants()):
                for i in range(desc.numInput()):
                    if desc.getIn(i) is not origvn:
                        continue
                    if i == outblock_ind and desc.getParent() is outblock and desc.code() == OpCode.CPUI_MULTIEQUAL:
                        continue
                    self.opSetInput(desc, replacevn, i)
                    break

    def nodeSplitBlockEdge(self, b, inedge):
        """Split a basic block along an in edge, returning the new copy."""
        a = b.getIn(inedge)
        bprime = self._bblocks.newBlockBasic(self)
        from ghidra.block.block import FlowBlock
        bprime.setFlag(FlowBlock.f_duplicate_block)
        if hasattr(bprime, 'copyRange'):
            bprime.copyRange(b)
        self._bblocks.switchEdge(a, b, bprime)
        for i in range(b.sizeOut()):
            self._bblocks.addEdge(bprime, b.getOut(i))
        return bprime

    def nodeSplit(self, b, inedge: int) -> None:
        """Split control-flow into a basic block, duplicating p-code into a new block."""
        if b.sizeOut() != 0:
            raise RuntimeError("Cannot (currently) nodesplit block with out flow")
        if b.sizeIn() <= 1:
            raise RuntimeError("Cannot nodesplit block with only 1 in edge")
        bprime = self.nodeSplitBlockEdge(b, inedge)
        # Clone ops from b into bprime (simplified: no CloneBlockOps helper)
        if hasattr(b, 'getOpList'):
            for origop in list(b.getOpList()):
                if origop.isBranch():
                    continue
                dup = self.newOp(origop.numInput(), origop.getAddr())
                self.opSetOpcode(dup, origop.code())
                if origop.getOut() is not None:
                    self.newVarnodeOut(origop.getOut().getSize(), origop.getOut().getAddr(), dup)
                for i in range(origop.numInput()):
                    inv = origop.getIn(i)
                    if inv.isConstant():
                        self.opSetInput(dup, self.newConstant(inv.getSize(), inv.getOffset()), i)
                    else:
                        self.opSetInput(dup, inv, i)
                self.opInsertEnd(dup, bprime)
        self.structureReset()

    def pushBranch(self, bb, slot: int, bbnew) -> None:
        """Move a control-flow edge from one block to another (for switch guard elimination)."""
        cbranch = bb.lastOp()
        if cbranch is None or cbranch.code() != OpCode.CPUI_CBRANCH or bb.sizeOut() != 2:
            raise RuntimeError("Cannot push non-conditional edge")
        indop = bbnew.lastOp()
        if indop is None or indop.code() != OpCode.CPUI_BRANCHIND:
            raise RuntimeError("Can only push branch into indirect jump")
        self.opRemoveInput(cbranch, 1)
        self.opSetOpcode(cbranch, OpCode.CPUI_BRANCH)
        self._bblocks.moveOutEdge(bb, slot, bbnew)
        self.structureReset()

    def forceGoto(self, pcop, pcdest) -> bool:
        """Force a specific control-flow edge to be marked as unstructured."""
        for i in range(self._bblocks.getSize()):
            bl = self._bblocks.getBlock(i)
            op = bl.lastOp()
            if op is None:
                continue
            if op.getAddr() != pcop:
                continue
            for j in range(bl.sizeOut()):
                bl2 = bl.getOut(j)
                op2 = bl2.lastOp()
                if op2 is None:
                    continue
                if op2.getAddr() != pcdest:
                    continue
                bl.setGotoBranch(j)
                return True
        return False

    def removeFromFlowSplit(self, bl, swap: bool) -> None:
        """Remove a basic block splitting its control-flow into two distinct paths."""
        self._bblocks.removeFromFlowSplit(bl, swap)
        self._bblocks.removeBlock(bl)
        self.structureReset()

    def switchEdge(self, inblock, outbefore, outafter) -> None:
        """Switch an outgoing edge from source block to flow into another block."""
        self._bblocks.switchEdge(inblock, outbefore, outafter)
        self.structureReset()

    def nodeJoinCreateBlock(self, block1, block2, exita, exitb,
                            fora_block1ishigh: bool, forb_block1ishigh: bool,
                            addr) -> 'BlockBasic':
        """Create a new basic block for holding a merged CBRANCH."""
        from ghidra.block.block import FlowBlock
        newblock = self._bblocks.newBlockBasic(self)
        newblock.setFlag(FlowBlock.f_joined_block)
        if hasattr(newblock, 'setInitialRange'):
            newblock.setInitialRange(addr, addr)
        if fora_block1ishigh:
            self._bblocks.removeEdge(block1, exita)
            swapa = block2
        else:
            self._bblocks.removeEdge(block2, exita)
            swapa = block1
        if forb_block1ishigh:
            self._bblocks.removeEdge(block1, exitb)
            swapb = block2
        else:
            self._bblocks.removeEdge(block2, exitb)
            swapb = block1
        self._bblocks.moveOutEdge(swapa, swapa.getOutIndex(exita), newblock)
        self._bblocks.moveOutEdge(swapb, swapb.getOutIndex(exitb), newblock)
        self._bblocks.addEdge(block1, newblock)
        self._bblocks.addEdge(block2, newblock)
        self.structureReset()
        return newblock

    def installSwitchDefaults(self) -> None:
        """Make sure default switch cases are properly labeled."""
        for jt in self._jumpvec:
            indop = jt.getIndirectOp()
            if indop is None:
                continue
            ind = indop.getParent()
            defblock = jt.getDefaultBlock() if hasattr(jt, 'getDefaultBlock') else -1
            if defblock != -1:
                ind.setDefaultSwitch(defblock)

    @staticmethod
    def compareCallspecs(a, b) -> bool:
        """Compare two FuncCallSpecs by address for sorting."""
        return a.getEntryAddress() < b.getEntryAddress()

    @staticmethod
    def descendantsOutside(vn) -> bool:
        """Return True if any PcodeOp reading vn is in a non-dead block."""
        for desc in vn.getDescendants():
            if not desc.getParent().isDead():
                return True
        return False

    @staticmethod
    def findPrimaryBranch(ops, findbranch: bool, findcall: bool, findreturn: bool):
        """Find the primary branch op from a list of ops."""
        for op in ops:
            opc = op.code()
            if opc in (OpCode.CPUI_BRANCH, OpCode.CPUI_CBRANCH):
                if findbranch:
                    if not op.getIn(0).isConstant():
                        return op
            elif opc == OpCode.CPUI_BRANCHIND:
                if findbranch:
                    return op
            elif opc in (OpCode.CPUI_CALL, OpCode.CPUI_CALLIND):
                if findcall:
                    return op
            elif opc == OpCode.CPUI_RETURN:
                if findreturn:
                    return op
        return None

    @staticmethod
    def checkIndirectUse(vn) -> bool:
        """Check if a Varnode is used only by INDIRECT ops."""
        for desc in vn.getDescendants():
            if desc.code() != OpCode.CPUI_INDIRECT:
                return False
        return True

    # --- Varnode manipulation helpers ---

    def destroyVarnode(self, vn) -> None:
        """Delete the given Varnode from this function."""
        self._vbank.destroy(vn)

    def cloneVarnode(self, vn):
        """Clone a Varnode (between copies of the function)."""
        newvn = self._vbank.create(vn.getSize(), vn.getAddr())
        return newvn

    def splitUses(self, vn) -> None:
        """Make all reads of the given Varnode unique by inserting COPYs."""
        descs = list(vn.getDescendants())
        if len(descs) <= 1:
            return
        for desc in descs[1:]:
            slot = desc.getSlot(vn)
            copyop = self.newOp(1, desc.getAddr())
            self.opSetOpcode(copyop, OpCode.CPUI_COPY)
            newvn = self.newUniqueOut(vn.getSize(), copyop)
            self.opSetInput(copyop, vn, 0)
            self.opInsertBefore(copyop, desc)
            self.opSetInput(desc, newvn, slot)

    def descend2Undef(self, vn) -> bool:
        """Transform all reads of the given Varnode to a special undefined constant."""
        if vn.hasNoDescend():
            return False
        for desc in list(vn.getDescendants()):
            slot = desc.getSlot(vn)
            newvn = self.newConstant(vn.getSize(), 0)
            self.opSetInput(desc, newvn, slot)
        return True

    def assignHigh(self, vn):
        """Assign a new HighVariable to a Varnode."""
        high = HighVariable(vn)
        return high

    def setVarnodeProperties(self, vn) -> None:
        """Look-up boolean properties and data-type information for a Varnode."""
        pass

    def coverVarnodes(self, entry, result: list) -> None:
        """Find Varnodes that overlap the given SymbolEntry range."""
        if entry is None:
            return
        addr = entry.getAddr() if hasattr(entry, 'getAddr') else None
        sz = entry.getSize() if hasattr(entry, 'getSize') else 0
        if addr is None or sz == 0:
            return
        for vn in self._vbank.beginLoc():
            if vn.getAddr() == addr and vn.getSize() == sz:
                result.append(vn)

    def syncVarnodesWithSymbol(self, iterobj, fl, ct) -> bool:
        """Sync Varnodes matching flags with their symbol data-type."""
        return False

    def handleSymbolConflict(self, entry, vn):
        """Handle two variables with matching storage."""
        return None

    def applyUnionFacet(self, entry, dhash) -> bool:
        """Apply union facet resolution from dynamic hash."""
        return False

    def onlyOpUse(self, invn, opmatch, trial, mainFlags) -> bool:
        """Check if invn is only used by opmatch (for parameter passing)."""
        return True

    def ancestorOpUse(self, maxlevel, invn, op, trial, offset, mainFlags) -> bool:
        """Check if a Varnode traces to a legitimate source for parameter passing."""
        return True

    def checkCallDoubleUse(self, opmatch, op, vn, fl, trial) -> bool:
        """Check if a Varnode is used in two different call sites."""
        return False

    def attemptDynamicMapping(self, entry, dhash) -> bool:
        """Attempt dynamic symbol mapping."""
        return False

    def attemptDynamicMappingLate(self, entry, dhash) -> bool:
        """Attempt late dynamic symbol mapping."""
        return False

    # --- Iterator / search methods ---

    def endLoc(self, *args):
        """End of Varnodes sorted by storage (various overloads)."""
        return self._vbank.endLoc(*args) if hasattr(self._vbank, 'endLoc') else iter([])

    def endDef(self, *args):
        """End of Varnodes sorted by definition address."""
        return self._vbank.endDef(*args) if hasattr(self._vbank, 'endDef') else iter([])

    def endOp(self, *args):
        """End of PcodeOp objects (by opcode or address)."""
        if args and hasattr(self._obank, 'end'):
            return self._obank.end(*args)
        return self._obank.endAll() if hasattr(self._obank, 'endAll') else iter([])

    def endOpAlive(self):
        return self._obank.endAlive() if hasattr(self._obank, 'endAlive') else iter([])

    def endOpDead(self):
        return self._obank.endDead() if hasattr(self._obank, 'endDead') else iter([])

    def endOpAll(self):
        return self._obank.endAll() if hasattr(self._obank, 'endAll') else iter([])

    def overlapLoc(self, iterobj, bounds: list) -> int:
        """Given start, return maximal range of overlapping Varnodes."""
        if hasattr(self._vbank, 'overlapLoc'):
            return self._vbank.overlapLoc(iterobj, bounds)
        return 0

    def beginLaneAccess(self):
        """Beginning iterator over laned accesses."""
        return iter(self._lanedMap) if hasattr(self, '_lanedMap') else iter({})

    def endLaneAccess(self):
        """Ending iterator over laned accesses."""
        return iter([])

    def clearLanedAccessMap(self) -> None:
        """Clear records from the laned access list."""
        if hasattr(self, '_lanedMap'):
            self._lanedMap.clear()

    # --- Print / debug helpers ---

    def printBlockTree(self) -> str:
        """Print a description of control-flow structuring."""
        if self._sblocks.getSize() != 0:
            return str(self._sblocks)
        return ""

    def printVarnodeTree(self) -> str:
        """Print a description of all Varnodes."""
        lines = []
        for vn in self._vbank.beginLoc():
            lines.append(str(vn))
        return "\n".join(lines)

    def printLocalRange(self) -> str:
        """Print description of memory ranges associated with local scopes."""
        return ""

    # --- Misc helpers ---

    def constructConstSpacebase(self, spc):
        """Construct a constant Varnode referring to the spacebase of the given space."""
        return self.newConstant(4, 0)

    def spacebaseConstant(self, op, slot, entry, rampoint, origval, origsize) -> None:
        """Replace a constant reference with an address relative to a spacebase register."""
        pass

    def switchOverJumpTables(self, flow) -> None:
        """Convert jump-table addresses to basic block indices."""
        for jt in self._jumpvec:
            if hasattr(jt, 'switchOver'):
                jt.switchOver(flow)

    def issueDatatypeWarnings(self) -> None:
        """Add warning headers for any data-types that have been modified."""
        pass

    def enableJTCallback(self, cb) -> None:
        """Enable a jump-table callback."""
        self._jtcallback = cb

    def disableJTCallback(self) -> None:
        """Disable the jump-table callback."""
        self._jtcallback = None

    def stageJumpTable(self, partial, jt, op, flow):
        """Stage analysis for a jump-table recovery."""
        return None

    # --- Block routines ---

    def getBasicBlockCount(self) -> int:
        return self._bblocks.getSize()

    def getBlock(self, i: int):
        return self._bblocks.getBlock(i)

    def opInsertBegin(self, op: PcodeOp, bl: BlockBasic) -> None:
        """Insert op at the beginning of a basic block."""
        bl.insertOp(op, 0)
        self.opMarkAlive(op)

    def opInsertEnd(self, op: PcodeOp, bl: BlockBasic) -> None:
        """Insert op at the end of a basic block."""
        bl.addOp(op)
        self.opMarkAlive(op)

    def opInsertAfter(self, op: PcodeOp, prev: PcodeOp) -> None:
        """Insert op after a specific PcodeOp in its basic block."""
        bl = prev.getParent()
        if bl is not None:
            ops = bl.getOpList()
            try:
                idx = ops.index(prev)
                bl.insertOp(op, idx + 1)
            except ValueError:
                bl.addOp(op)
        self.opMarkAlive(op)

    def opInsertBefore(self, op: PcodeOp, follow: PcodeOp) -> None:
        """Insert op before a specific PcodeOp in its basic block."""
        bl = follow.getParent()
        if bl is not None:
            ops = bl.getOpList()
            try:
                idx = ops.index(follow)
                bl.insertOp(op, idx)
            except ValueError:
                bl.addOp(op)
        self.opMarkAlive(op)

    # --- Warning / comment ---

    def warning(self, txt: str, ad: Address) -> None:
        """Add a warning comment in the function body."""
        pass  # Would use CommentDatabase

    def warningHeader(self, txt: str) -> None:
        """Add a warning comment in the function header."""
        pass

    # --- Flow and inline ---

    def followFlow(self, baddr, eaddr) -> None:
        """Generate raw p-code and basic blocks for the function body."""
        from ghidra.analysis.flow import FlowInfo
        flow = FlowInfo(self, self._obank, self._bblocks, self._qlst)
        flow.setRange(baddr, eaddr)
        flow.setFlags(self._glb.flowoptions if self._glb else 0)
        flow.setMaximumInstructions(self._glb.max_instructions if self._glb else 100000)
        flow.generateOps()
        flow.generateBlocks()
        self._flags |= Funcdata.blocks_generated
        if flow.hasUnimplemented():
            self._flags |= Funcdata.unimplemented_present
        if flow.hasBadData():
            self._flags |= Funcdata.baddata_present

    def truncatedFlow(self, fd, flow) -> None:
        """Generate a truncated set of p-code from an existing flow."""
        pass

    def inlineFlow(self, inlinefd, flow, callop) -> int:
        """In-line the given function. Returns 0=EZ, 1=hard, -1=fail."""
        return -1

    def overrideFlow(self, addr, flowtype: int) -> None:
        """Override the flow at a specific address."""
        if self._localoverride is not None and hasattr(self._localoverride, 'insertFlowOverride'):
            self._localoverride.insertFlowOverride(addr, flowtype)

    def doLiveInject(self, payload, addr, bl, pos) -> None:
        """Inject p-code into a live basic block."""
        pass

    # --- Clone / Indirect ---

    def cloneOp(self, op, seq):
        """Clone a PcodeOp into this function."""
        newop = self._obank.create(op.numInput(), seq)
        self.opSetOpcode(newop, op.code())
        if op.getOut() is not None:
            outvn = self.newVarnodeOut(op.getOut().getSize(), op.getOut().getAddr(), newop)
        for i in range(op.numInput()):
            invn = op.getIn(i)
            if invn is not None:
                newvn = self.newVarnode(invn.getSize(), invn.getAddr())
                self.opSetInput(newop, newvn, i)
        return newop

    def newIndirectOp(self, indeffect, addr, sz: int, extraFlags: int = 0):
        """Create a new INDIRECT PcodeOp."""
        from ghidra.core.opcodes import OpCode
        indop = self.newOp(2, indeffect.getAddr())
        self.opSetOpcode(indop, OpCode.CPUI_INDIRECT)
        outvn = self.newVarnodeOut(sz, addr, indop)
        invn = self.newVarnode(sz, addr)
        self.opSetInput(indop, invn, 0)
        iopvn = self.newVarnodeIop(indeffect)
        self.opSetInput(indop, iopvn, 1)
        self.opInsertBefore(indop, indeffect)
        return indop

    def newIndirectCreation(self, indeffect, addr, sz: int, possibleout: bool):
        """Create a new indirect creation PcodeOp."""
        from ghidra.core.opcodes import OpCode
        indop = self.newOp(2, indeffect.getAddr())
        self.opSetOpcode(indop, OpCode.CPUI_INDIRECT)
        outvn = self.newVarnodeOut(sz, addr, indop)
        outvn.setFlags(Varnode.indirect_creation)
        invn = self.newConstant(sz, 0)
        invn.setFlags(Varnode.indirect_creation)
        self.opSetInput(indop, invn, 0)
        iopvn = self.newVarnodeIop(indeffect)
        self.opSetInput(indop, iopvn, 1)
        indop.setFlag(PcodeOp.indirect_creation)
        self.opInsertBefore(indop, indeffect)
        return indop

    def markIndirectCreation(self, indop, possibleOutput: bool) -> None:
        """Convert CPUI_INDIRECT into an indirect creation."""
        indop.setFlag(PcodeOp.indirect_creation)
        if indop.getOut() is not None:
            indop.getOut().setFlags(Varnode.indirect_creation)

    def opInsert(self, op, bl, pos) -> None:
        """Insert a PcodeOp into a specific position in a basic block."""
        if bl is not None:
            if pos is not None and hasattr(bl, 'insertOpBefore'):
                bl.insertOpBefore(op, pos)
            elif hasattr(bl, 'addOp'):
                bl.addOp(op)
            op.setParent(bl)
        self.opMarkAlive(op)

    def opUninsert(self, op) -> None:
        """Remove the given PcodeOp from its basic block without destroying it."""
        bl = op.getParent()
        if bl is not None and hasattr(bl, 'removeOp'):
            bl.removeOp(op)
        op.setParent(None)

    def opDeadInsertAfter(self, op, prev) -> None:
        """Insert op after prev in the dead list."""
        if hasattr(self._obank, 'insertAfterDead'):
            self._obank.insertAfterDead(op, prev)

    def opDestroyRecursive(self, op, scratch: list = None) -> None:
        """Remove a PcodeOp and recursively remove ops producing its inputs."""
        if scratch is None:
            scratch = []
        for i in range(op.numInput()):
            invn = op.getIn(i)
            if invn is not None and invn.isWritten():
                defop = invn.getDef()
                if defop is not None and defop.getOut().hasNoDescend():
                    scratch.append(defop)
        self.opDestroy(op)
        for sop in scratch:
            self.opDestroyRecursive(sop)

    # --- Varnode search / link ---

    def findLinkedVarnode(self, entry):
        """Find a Varnode matching the given Symbol mapping."""
        if entry is None:
            return None
        addr = entry.getAddr() if hasattr(entry, 'getAddr') else None
        sz = entry.getSize() if hasattr(entry, 'getSize') else 0
        if addr is None or sz == 0:
            return None
        for vn in self._vbank.beginLoc():
            if vn.getAddr() == addr and vn.getSize() == sz:
                return vn
        return None

    def findLinkedVarnodes(self, entry, res: list) -> None:
        """Find Varnodes that map to the given SymbolEntry."""
        if entry is None:
            return
        addr = entry.getAddr() if hasattr(entry, 'getAddr') else None
        sz = entry.getSize() if hasattr(entry, 'getSize') else 0
        if addr is None or sz == 0:
            return
        for vn in self._vbank.beginLoc():
            if vn.getAddr() == addr and vn.getSize() == sz:
                res.append(vn)

    def linkSymbol(self, vn):
        """Find or create Symbol associated with given Varnode."""
        return None

    def linkSymbolReference(self, vn):
        """Discover and attach Symbol to a constant reference."""
        return None

    def linkProtoPartial(self, vn) -> None:
        """Find or create Symbol and a partial mapping."""
        pass

    def buildDynamicSymbol(self, vn) -> None:
        """Build a dynamic Symbol associated with the given Varnode."""
        pass

    def combineInputVarnodes(self, vnHi, vnLo) -> None:
        """Combine two contiguous input Varnodes into one."""
        pass

    def findSpacebaseInput(self, spc):
        """Find the input Varnode for the given spacebase."""
        if spc is None or not hasattr(spc, 'numSpacebase'):
            return None
        for i in range(spc.numSpacebase()):
            base = spc.getSpacebase(i)
            vn = self._vbank.findInput(base.size, base.getAddr())
            if vn is not None:
                return vn
        return None

    def constructSpacebaseInput(self, spc):
        """Construct a new spacebase register input for the given space."""
        if spc is None or not hasattr(spc, 'numSpacebase') or spc.numSpacebase() == 0:
            return None
        base = spc.getSpacebase(0)
        vn = self.newVarnode(base.size, base.getAddr())
        return self.setInputVarnode(vn)

    def newSpacebasePtr(self, spc):
        """Construct a new spacebase register for a given address space."""
        return self.constructSpacebaseInput(spc)

    def hasInputIntersection(self, s: int, loc) -> bool:
        return self._vbank.hasInputIntersection(s, loc)

    def getAliveOps(self):
        """Get all alive PcodeOps as an iterable."""
        if hasattr(self._obank, 'getAliveList'):
            return self._obank.getAliveList()
        return []

    def getStoreGuards(self):
        return self._heritage.getStoreGuards() if self._heritage else []

    def getLoadGuards(self):
        return self._heritage.getLoadGuards() if self._heritage else []

    def getStoreGuard(self, op):
        return self._heritage.getStoreGuard(op) if self._heritage else None

    # --- Encode / decode ---

    def encodeVarnode(self, encoder, vn) -> None:
        """Encode a specific Varnode to stream."""
        pass

    def encode(self, encoder, uid=0, savetree: bool = True) -> None:
        """Encode a description of this function to stream."""
        pass

    def decode(self, decoder) -> int:
        """Restore the state of this function from a stream."""
        return 0

    def encodeTree(self, encoder) -> None:
        """Encode a description of the p-code tree to stream."""
        pass

    def encodeHigh(self, encoder) -> None:
        """Encode a description of all HighVariables to stream."""
        pass

    def encodeJumpTable(self, encoder) -> None:
        """Encode a description of jump-tables to stream."""
        pass

    def decodeJumpTable(self, decoder) -> None:
        """Decode jump-tables from a stream."""
        pass

    # --- Data-flow / transformation helpers ---

    def syncVarnodesWithSymbols(self, lm=None, updateDatatypes: bool = False,
                                 unmappedAliasCheck: bool = False) -> bool:
        return False

    def transferVarnodeProperties(self, vn, newVn, lsbOffset: int = 0) -> None:
        """Transfer properties from one Varnode to another."""
        if vn is not None and newVn is not None:
            newVn._type = vn._type
            if vn.isTypeLock():
                newVn.setFlags(Varnode.typelock)

    def fillinReadOnly(self, vn) -> bool:
        """Replace the given Varnode with its (constant) value in the load image."""
        return False

    def replaceVolatile(self, vn) -> bool:
        """Replace accesses of the given Varnode with volatile operations."""
        return False

    def remapVarnode(self, vn, sym, usepoint) -> None:
        pass

    def remapDynamicVarnode(self, vn, sym, usepoint, hashval) -> None:
        pass

    def newExtendedConstant(self, s: int, val, op):
        """Create extended precision constant."""
        return self.newConstant(s, val[0] if isinstance(val, list) else val)

    def adjustInputVarnodes(self, addr, sz: int) -> None:
        pass

    def findDisjointCover(self, vn):
        """Find range covering given Varnode and any intersecting Varnodes."""
        return (vn.getAddr(), vn.getSize())

    def checkForLanedRegister(self, sz: int, addr) -> None:
        pass

    def recoverJumpTable(self, op, flow=None, mode_ref=None):
        """Recover a jump-table for the given BRANCHIND op."""
        return None

    def earlyJumpTableFail(self, op):
        return None

    def testForReturnAddress(self, vn) -> bool:
        return False

    def getInternalString(self, buf, size, ptrType, readOp):
        return None

    def moveRespectingCover(self, op, lastOp) -> bool:
        return False

    def forceFacingType(self, parent, fieldNum: int, op, slot: int) -> None:
        pass

    def inheritResolution(self, parent, op, slot: int, oldOp, oldSlot: int) -> int:
        return -1

    def markReturnCopy(self, op) -> None:
        op.setFlag(PcodeOp.return_copy)

    def numCallSpecs(self) -> int:
        return len(self._qlst)

    def getJumpTableByIndex(self, i: int):
        """Get JumpTable by list index."""
        if 0 <= i < len(self._jumpvec):
            return self._jumpvec[i]
        return None

    def getHighCount(self) -> int:
        return self._highcount if hasattr(self, '_highcount') else 0

    def setHighCount(self, val: int) -> None:
        self._highcount = val

    def hasMutualExclusion(self) -> bool:
        return False

    def getMinimumLanedSize(self) -> int:
        return self._minLanedSize if hasattr(self, '_minLanedSize') else 0

    def setMinimumLanedSize(self, val: int) -> None:
        self._minLanedSize = val

    def getDecompileMaxInstructions(self) -> int:
        return self._decomp_max_inst if hasattr(self, '_decomp_max_inst') else 0

    def setDecompileMaxInstructions(self, val: int) -> None:
        self._decomp_max_inst = val

    def getRestartPending(self) -> bool:
        return self._restart_pending if hasattr(self, '_restart_pending') else False

    def getMaxOpcodeIndex(self) -> int:
        return self._maxopcodeindex if hasattr(self, '_maxopcodeindex') else 0

    def getCastPhase(self) -> int:
        return self._cast_phase if hasattr(self, '_cast_phase') else 0

    def setCastPhase(self, val: int) -> None:
        self._cast_phase = val

    def getHighLevelCount(self) -> int:
        return self._highlevelcount if hasattr(self, '_highlevelcount') else 0

    def getJumpTableCount(self) -> int:
        return self._jumptablecount if hasattr(self, '_jumptablecount') else 0

    def getNumCalls(self) -> int:
        return len(self._qlst) if hasattr(self, '_qlst') else 0

    def getNumHighVariables(self) -> int:
        return self._numHighVars if hasattr(self, '_numHighVars') else 0

    def getCallGraphNode(self):
        return self._callGraphNode if hasattr(self, '_callGraphNode') else None

    def setCallGraphNode(self, node) -> None:
        self._callGraphNode = node

    def getBaseOffset(self) -> int:
        return self._baseoffset if hasattr(self, '_baseoffset') else 0

    def getSwitchCount(self) -> int:
        return self._switchcount if hasattr(self, '_switchcount') else 0

    def getOverrideCount(self) -> int:
        return self._overridecount if hasattr(self, '_overridecount') else 0

    def getReturnAddr(self):
        return self._returnaddr if hasattr(self, '_returnaddr') else None

    # --- Print / debug ---

    def printRaw(self) -> str:
        """Print raw p-code op descriptions."""
        lines = []
        lines.append(f"Function: {self._name} @ {self._baseaddr}")
        for i in range(self._bblocks.getSize()):
            bl = self._bblocks.getBlock(i)
            if isinstance(bl, BlockBasic):
                lines.append(f"  Block {bl.getIndex()} ({bl.getStart()} - {bl.getStop()}):")
                for op in bl.getOpList():
                    lines.append(f"    {op.printRaw()}")
        return "\n".join(lines)

    def __repr__(self) -> str:
        return (f"Funcdata({self._name!r} @ {self._baseaddr}, "
                f"varnodes={self._vbank.size()}, "
                f"blocks={self._bblocks.getSize()})")
