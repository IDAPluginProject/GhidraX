"""
Corresponds to: funcdata.hh / funcdata.cc / funcdata_block.cc / funcdata_op.cc / funcdata_varnode.cc

Container for data structures associated with a single function.
Holds control-flow, data-flow, and prototype information.
"""

from __future__ import annotations

import struct as _struct
from typing import TYPE_CHECKING, Optional, List, Iterator

_PTR_SIZE: int = _struct.calcsize('P')  # sizeof(void*): 8 on 64-bit, 4 on 32-bit

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

    def getCallSpecs(self, op_or_index):
        """Look up FuncCallSpecs by PcodeOp or by integer index.

        C++ has two overloads:
          FuncCallSpecs *getCallSpecs(const PcodeOp *op)
          FuncCallSpecs *getCallSpecs(int4 i)
        """
        if isinstance(op_or_index, int):
            return self._qlst[op_or_index] if 0 <= op_or_index < len(self._qlst) else None
        op = op_or_index
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
        """Associate a union field with the given edge.

        If there was a previous locked association, returns False.
        For MULTIEQUAL ops, copies resolution to other input slots
        holding the same Varnode.

        C++ ref: ``Funcdata::setUnionField``
        """
        if self._unionMap is None:
            from ghidra.types.resolve import UnionResolveMap
            self._unionMap = UnionResolveMap()
        # Check for locked previous association
        existing = self._unionMap.getUnionField(dt, op, slot)
        if existing is not None and hasattr(existing, 'isLocked') and existing.isLocked():
            return False
        self._unionMap.setUnionField(dt, op, slot, res)
        # MULTIEQUAL: copy resolution to other slots holding same Varnode
        if op is not None and hasattr(op, 'code') and op.code() == OpCode.CPUI_MULTIEQUAL and slot >= 0:
            vn = op.getIn(slot)
            for i in range(op.numInput()):
                if i == slot:
                    continue
                if op.getIn(i) is not vn:
                    continue
                dup_existing = self._unionMap.getUnionField(dt, op, i)
                if dup_existing is not None and hasattr(dup_existing, 'isLocked') and dup_existing.isLocked():
                    continue
                self._unionMap.setUnionField(dt, op, i, res)
        return True

    def getUnionField(self, dt, op, slot):
        if self._unionMap is None:
            return None
        return self._unionMap.getUnionField(dt, op, slot)

    def getFirstReturnOp(self):
        """Return the first non-dead, non-halt RETURN op, or None.

        C++ ref: ``Funcdata::getFirstReturnOp``
        """
        from ghidra.core.opcodes import OpCode
        for op in self._obank.beginOp(OpCode.CPUI_RETURN):
            if op.isDead():
                continue
            if hasattr(op, 'getHaltType') and op.getHaltType() != 0:
                continue
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
            self._flags &= ~Funcdata.typerecovery_start
            self._flags &= ~Funcdata.typerecovery_exceeded
        else:
            self._flags &= ~Funcdata.typerecovery_on
            self._flags &= ~Funcdata.typerecovery_start
            self._flags &= ~Funcdata.typerecovery_exceeded

    def hasNoStructBlocks(self) -> bool:
        return self._sblocks.getSize() == 0

    # --- Processing lifecycle ---

    def startProcessing(self) -> None:
        """Start processing: generate raw p-code, build blocks, call specs.

        C++ ref: ``Funcdata::startProcessing``
        """
        if (self._flags & Funcdata.processing_started) != 0:
            raise Exception("Function processing already started")
        self._flags |= Funcdata.processing_started

        if hasattr(self, '_funcp') and self._funcp is not None and hasattr(self._funcp, 'isInline') and self._funcp.isInline():
            self.warningHeader("This is an inlined function")
        if self._localmap is not None and hasattr(self._localmap, 'clearUnlocked'):
            self._localmap.clearUnlocked()
        if hasattr(self, '_funcp') and self._funcp is not None and hasattr(self._funcp, 'clearUnlockedOutput'):
            self._funcp.clearUnlockedOutput()
        # followFlow + structureReset only if blocks haven't been built externally
        if self._bblocks.getSize() == 0 and hasattr(self, 'followFlow'):
            from ghidra.core.address import Address as Addr
            baddr = Addr(self._baseaddr.getSpace(), 0)
            eaddr = Addr(self._baseaddr.getSpace(), 0xFFFFFFFFFFFFFFFF)
            self.followFlow(baddr, eaddr)
        self.structureReset()
        self.sortCallSpecs()
        if hasattr(self, '_heritage') and self._heritage is not None and hasattr(self._heritage, 'buildInfoList'):
            self._heritage.buildInfoList()
        if hasattr(self, '_localoverride') and self._localoverride is not None and hasattr(self._localoverride, 'applyDeadCodeDelay'):
            self._localoverride.applyDeadCodeDelay(self)

    def stopProcessing(self) -> None:
        """Mark processing as complete, clean up dead ops, issue warnings.

        C++ ref: ``Funcdata::stopProcessing``
        """
        self._flags |= Funcdata.processing_complete
        if hasattr(self._obank, 'destroyDead'):
            self._obank.destroyDead()
        if not self.isJumptableRecoveryOn():
            self.issueDatatypeWarnings()

    def startTypeRecovery(self) -> bool:
        if (self._flags & Funcdata.typerecovery_on) == 0:
            return False
        if (self._flags & Funcdata.typerecovery_start) != 0:
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
        if not self._heritage._infolist:
            self._heritage.buildInfoList()
        self._heritage.heritage()

    def getHeritagePass(self) -> int:
        """Get the current heritage pass number."""
        if hasattr(self, '_heritage'):
            return self._heritage.getPass()
        return 0

    def setHighLevel(self) -> None:
        """Turn on HighVariable objects for all existing Varnodes.

        C++ ref: ``Funcdata::setHighLevel``
        """
        if (self._flags & Funcdata.highlevel_on) != 0:
            return
        self._flags |= Funcdata.highlevel_on
        self._high_level_index = self._vbank.getCreateIndex()
        for vn in list(self._vbank.beginLoc()):
            self.assignHigh(vn)

    def getActiveOutput(self):
        """Get the active output parameter recovery object, or None."""
        return getattr(self, '_activeoutput', None)

    def clearActiveOutput(self) -> None:
        """Clear the active output recovery object."""
        self._activeoutput = None

    def initActiveOutput(self) -> None:
        """Initialize active output parameter recovery.

        C++ ref: ``Funcdata::initActiveOutput``
        """
        from ghidra.fspec.paramactive import ParamActive
        self._activeoutput = ParamActive(False)
        maxdelay = self._funcp.getMaxOutputDelay() if hasattr(self._funcp, 'getMaxOutputDelay') else 0
        if maxdelay > 0:
            maxdelay = 3
        if hasattr(self._activeoutput, 'setMaxPass'):
            self._activeoutput.setMaxPass(maxdelay)

    def calcNZMask(self) -> None:
        """Calculate the non-zero mask property on all Varnodes."""
        from ghidra.transform.nzmask import calcNZMask as _calcNZMask
        _calcNZMask(self)

    def clearDeadVarnodes(self) -> None:
        """Free any Varnodes not attached to anything.

        Input Varnodes that have no descendants and are not locked are
        demoted to free, then all free Varnodes with no descendants are
        destroyed.

        C++ ref: ``Funcdata::clearDeadVarnodes``
        """
        for vn in list(self._vbank.beginLoc()):
            if vn.hasNoDescend():
                if vn.isInput() and not (hasattr(vn, 'isLockedInput') and vn.isLockedInput()):
                    if hasattr(self._vbank, 'makeFree'):
                        self._vbank.makeFree(vn)
                    if hasattr(vn, 'clearCover'):
                        vn.clearCover()
                if vn.isFree():
                    self._vbank.destroy(vn)

    def clearDeadOps(self) -> None:
        """Remove PcodeOps that have been marked as dead."""
        self._obank.clearDead()

    def seenDeadcode(self, spc) -> None:
        """Record that dead code has been seen for a given space."""
        if hasattr(self, '_heritage') and self._heritage is not None:
            self._heritage.seenDeadCode(spc)

    def spacebase(self) -> None:
        """Mark Varnode objects that hold stack-pointer values as spacebase.

        For each address space that has a base register, find all Varnodes at
        the register's location/size.  Already-marked spacebases with an
        INT_ADD def get their uses split.  Unmarked ones are flagged as
        spacebase, and input varnodes additionally get the TypeSpacebase
        pointer type.

        C++ ref: ``Funcdata::spacebase``
        """
        from ghidra.ir.varnode import Varnode
        from ghidra.core.address import Address
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
                addr = Address(point.space, point.offset)
                # Build pointer-to-spacebase type
                ptr = None
                if hasattr(glb, 'types') and glb.types is not None:
                    ct = glb.types.getTypeSpacebase(spc, self.getAddress()) if hasattr(glb.types, 'getTypeSpacebase') else None
                    if ct is not None and hasattr(glb.types, 'getTypePointer'):
                        wordSize = spc.getWordSize() if hasattr(spc, 'getWordSize') else 1
                        ptr = glb.types.getTypePointer(point.size, ct, wordSize)
                # Iterate over varnodes at this location
                for vn in list(self._vbank.beginLoc()):
                    if vn.getAddr() != addr or vn.getSize() != point.size:
                        continue
                    if vn.isFree():
                        continue
                    if vn.isSpacebase():
                        # Already marked -- split uses if def is INT_ADD
                        defop = vn.getDef() if vn.isWritten() else None
                        if defop is not None and defop.code() == OpCode.CPUI_INT_ADD:
                            self.splitUses(vn)
                    else:
                        vn.setFlags(Varnode.spacebase)
                        if vn.isInput() and ptr is not None:
                            vn.updateType(ptr, True, True)

    def structureReset(self) -> None:
        """Recalculate loop structure and dominance for the current CFG.

        The structured hierarchy is also reset. This can be called
        multiple times as changes are made to control-flow.

        C++ ref: ``Funcdata::structureReset``
        """
        self._flags &= ~Funcdata.blocks_unreachable
        rootlist = []
        if hasattr(self._bblocks, 'structureLoops'):
            self._bblocks.structureLoops(rootlist)
        if hasattr(self._bblocks, 'calcForwardDominator'):
            self._bblocks.calcForwardDominator(rootlist)
        if len(rootlist) > 1:
            self._flags |= Funcdata.blocks_unreachable
        # Check for dead jumptables
        alivejumps = []
        for jt in self._jumpvec:
            indop = jt.getIndirectOp() if hasattr(jt, 'getIndirectOp') else None
            if indop is not None and indop.isDead():
                self.warningHeader("Recovered jumptable eliminated as dead code")
                continue
            alivejumps.append(jt)
        self._jumpvec = alivejumps
        self._sblocks.clear()
        if hasattr(self, '_heritage') and hasattr(self._heritage, 'forceRestructure'):
            self._heritage.forceRestructure()

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
        """Remove an active basic block from the function.

        PcodeOps in the block are deleted.  Data-flow and control-flow
        are patched up.  MULTIEQUAL ops in successor blocks are adjusted.

        C++ ref: ``Funcdata::blockRemoveInternal``
        """
        # Check for BRANCHIND and associated jump table
        lastop = bb.lastOp() if hasattr(bb, 'lastOp') else None
        if lastop is not None and lastop.code() == OpCode.CPUI_BRANCHIND:
            jt = self.findJumpTable(lastop)
            if jt is not None:
                self.removeJumpTable(jt)

        if not unreachable:
            self.pushMultiequals(bb)
            # Patch MULTIEQUALs in successor blocks
            for i in range(bb.sizeOut()):
                bbout = bb.getOut(i)
                if hasattr(bbout, 'isDead') and bbout.isDead():
                    continue
                blocknum = bbout.getInIndex(bb)
                if hasattr(bbout, 'getOpList'):
                    for op in list(bbout.getOpList()):
                        if op.code() != OpCode.CPUI_MULTIEQUAL:
                            continue
                        if blocknum >= op.numInput():
                            continue
                        deadvn = op.getIn(blocknum)
                        self.opRemoveInput(op, blocknum)
                        deadop = deadvn.getDef() if deadvn is not None and deadvn.isWritten() else None
                        if (deadop is not None and deadop.code() == OpCode.CPUI_MULTIEQUAL
                                and deadop.getParent() == bb):
                            for j in range(bb.sizeIn()):
                                self.opInsertInput(op, deadop.getIn(j), op.numInput())
                        else:
                            for j in range(bb.sizeIn()):
                                self.opInsertInput(op, deadvn, op.numInput())
                        self.opZeroMulti(op)

        self._bblocks.removeFromFlow(bb)

        desc_warning = False
        if hasattr(bb, 'getOpList'):
            for op in list(bb.getOpList()):
                if op.isAssignment():
                    deadvn = op.getOut()
                    if deadvn is not None:
                        if unreachable:
                            undef = self.descend2Undef(deadvn)
                            if undef and not desc_warning:
                                self.warningHeader("Creating undefined varnodes in (possibly) reachable block")
                                desc_warning = True
                        if self.descendantsOutside(deadvn):
                            raise Exception("Deleting op with descendants")
                if op.isCall():
                    self.deleteCallSpecs(op)
                self.opDestroy(op)
        self._bblocks.removeBlock(bb)

    def spliceBlockBasic(self, bl) -> None:
        """Splice a block with its single successor, concatenating p-code.

        The given block must have a single output block with a single
        input. The output block's ops are appended to bl, and bl
        inherits the output block's out edges.

        C++ ref: ``Funcdata::spliceBlockBasic``
        """
        outbl = None
        if bl.sizeOut() == 1:
            outbl = bl.getOut(0)
            if outbl.sizeIn() != 1:
                outbl = None
        if outbl is None:
            raise Exception("Cannot splice basic blocks")
        # Remove any jump op at the end of bl
        if hasattr(bl, 'getOpList') and bl.getOpList():
            jumpop = bl.lastOp()
            if jumpop is not None and jumpop.isBranch():
                self.opDestroy(jumpop)
        if hasattr(outbl, 'getOpList') and outbl.getOpList():
            # Convert any leading MULTIEQUALs to COPYs (outbl has sizeIn==1)
            for mop in list(outbl.getOpList()):
                if mop.code() != OpCode.CPUI_MULTIEQUAL:
                    break
                # MULTIEQUAL with 1 input → COPY
                while mop.numInput() > 1:
                    self.opRemoveInput(mop, mop.numInput() - 1)
                self.opSetOpcode(mop, OpCode.CPUI_COPY)
            firstop = outbl.getOpList()[0]
            firstop.clearFlag(PcodeOp.startbasic)
            # Reparent all ops from outbl to bl
            for op in list(outbl.getOpList()):
                op.setParent(bl)
            # Move all ops from outbl to end of bl
            bl_ops = bl.getOpList()
            out_ops = outbl.getOpList()
            bl_ops.extend(out_ops)
            out_ops.clear()
        if hasattr(bl, 'mergeRange'):
            bl.mergeRange(outbl)
        if hasattr(self._bblocks, 'spliceBlock'):
            self._bblocks.spliceBlock(bl)
        else:
            # Fallback manual splice
            self._bblocks.removeEdge(bl, outbl)
            while outbl.sizeOut() > 0:
                target = outbl.getOut(0)
                self._bblocks.removeEdge(outbl, target)
                self._bblocks.addEdge(bl, target)
            self._bblocks.removeBlock(outbl)
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
        """Clear everything associated with decompilation (analysis).

        C++ ref: ``Funcdata::clear``
        """
        self._flags &= ~(Funcdata.highlevel_on | Funcdata.blocks_generated |
                         Funcdata.processing_started | Funcdata.typerecovery_start |
                         Funcdata.typerecovery_on | Funcdata.double_precis_on |
                         Funcdata.restart_pending)
        self._clean_up_index = 0
        self._high_level_index = 0
        self._cast_phase_index = 0
        if self._glb is not None and hasattr(self._glb, 'getMinimumLanedRegisterSize'):
            self._minLanedSize = self._glb.getMinimumLanedRegisterSize()

        if self._localmap is not None and hasattr(self._localmap, 'clearUnlocked'):
            self._localmap.clearUnlocked()
        if self._localmap is not None and hasattr(self._localmap, 'resetLocalWindow'):
            self._localmap.resetLocalWindow()

        self.clearActiveOutput()
        if hasattr(self, '_funcp') and self._funcp is not None and hasattr(self._funcp, 'clearUnlockedOutput'):
            self._funcp.clearUnlockedOutput()
        self._unionMap = None
        self._bblocks.clear()
        self._sblocks.clear()
        self._obank.clear()
        self._vbank.clear()
        self._qlst.clear()
        self._qlst_map.clear()
        self._jumpvec.clear()
        # Do not clear overrides
        if hasattr(self, '_heritage') and self._heritage is not None:
            self._heritage.clear()
        if hasattr(self, '_covermerge') and self._covermerge is not None and hasattr(self._covermerge, 'clear'):
            self._covermerge.clear()

    # --- Call specification routines ---

    def numCalls(self) -> int:
        return len(self._qlst)

    def getCallSpecsByIndex(self, i: int) -> Optional[FuncCallSpecs]:
        return self._qlst[i] if 0 <= i < len(self._qlst) else None

    # --- Varnode creation routines ---

    def newVarnode(self, s: int, addr: Address, ct: Optional[Datatype] = None) -> Varnode:
        """Create a new unattached Varnode.

        C++ ref: ``Funcdata::newVarnode``
        """
        vn = self._vbank.create(s, addr, ct)
        self.assignHigh(vn)
        if s >= self._minLanedSize:
            self.checkForLanedRegister(s, addr)
        if self._localmap is not None and hasattr(self._localmap, 'queryProperties'):
            vflags = 0
            entry = self._localmap.queryProperties(vn.getAddr(), vn.getSize(), Address(), vflags)
            if entry is not None and hasattr(vn, 'setSymbolProperties'):
                vn.setSymbolProperties(entry)
            elif vflags != 0:
                vn.setFlags(vflags & ~Varnode.typelock)
        return vn

    def newConstant(self, s: int, val: int) -> Varnode:
        """Create a new constant Varnode.

        C++ ref: ``Funcdata::newConstant``
        """
        cs = None
        if self._glb is not None:
            cs = self._glb.getConstantSpace()
        if cs is None:
            from ghidra.core.space import ConstantSpace
            cs = ConstantSpace()
        addr = Address(cs, val)
        vn = self._vbank.create(s, addr)
        self.assignHigh(vn)
        return vn

    def newUnique(self, s: int, ct: Optional[Datatype] = None) -> Varnode:
        """Create a new temporary Varnode in unique space.

        C++ ref: ``Funcdata::newUnique``
        """
        if self._glb is not None:
            uniq = self._glb.getUniqueSpace()
            base = self._glb.getUniqueBase()
        else:
            uniq = None
            base = 0x10000000
        addr = Address(uniq, base)
        if self._glb is not None and hasattr(self._glb, 'setUniqueBase'):
            self._glb.setUniqueBase(base + s)
        vn = self._vbank.create(s, addr, ct)
        self.assignHigh(vn)
        if s >= self._minLanedSize:
            self.checkForLanedRegister(s, vn.getAddr())
        return vn

    def newVarnodeOut(self, s: int, addr: Address, op: PcodeOp) -> Varnode:
        """Create a new Varnode defined as output of a given PcodeOp.

        C++ ref: ``Funcdata::newVarnodeOut``
        """
        vn = self._vbank.createDef(s, addr, None, op)
        op.setOutput(vn)
        self.assignHigh(vn)
        if s >= self._minLanedSize:
            self.checkForLanedRegister(s, addr)
        if self._localmap is not None and hasattr(self._localmap, 'queryProperties'):
            vflags = 0
            entry = self._localmap.queryProperties(addr, s, op.getAddr(), vflags)
            if entry is not None and hasattr(vn, 'setSymbolProperties'):
                vn.setSymbolProperties(entry)
            elif vflags != 0:
                vn.setFlags(vflags & ~Varnode.typelock)
        return vn

    def newUniqueOut(self, s: int, op: PcodeOp) -> Varnode:
        """Create a new temporary output Varnode.

        C++ ref: ``Funcdata::newUniqueOut``
        """
        if self._glb is not None:
            uniq = self._glb.getUniqueSpace()
            base = self._glb.getUniqueBase()
        else:
            uniq = None
            base = 0x10000000
        addr = Address(uniq, base)
        if self._glb is not None and hasattr(self._glb, 'setUniqueBase'):
            self._glb.setUniqueBase(base + s)
        vn = self._vbank.createDef(s, addr, None, op)
        op.setOutput(vn)
        self.assignHigh(vn)
        if s >= self._minLanedSize:
            self.checkForLanedRegister(s, vn.getAddr())
        return vn

    def setInputVarnode(self, vn: Varnode) -> Varnode:
        """Mark a Varnode as an input to the function.

        If the Varnode is already an input, return it. Check for overlapping
        input Varnodes — if one exists with the same size and address, return
        it instead. Then set varnode properties and mark unaffected/return_address
        effects.

        C++ ref: ``Funcdata::setInputVarnode``
        """
        if vn.isInput():
            return vn
        # Check for overlapping existing inputs
        existing = self._vbank.findInput(vn.getSize(), vn.getAddr())
        if existing is not None and existing.isInput():
            return existing
        vn.setInput()
        self.setVarnodeProperties(vn)
        # Check for unaffected/return_address effects
        if hasattr(self._funcp, 'hasEffect'):
            effecttype = self._funcp.hasEffect(vn.getAddr(), vn.getSize())
            UNAFFECTED = 1  # EffectRecord::unaffected
            RETURN_ADDRESS = 2  # EffectRecord::return_address
            if effecttype == UNAFFECTED:
                if hasattr(vn, 'setUnaffected'):
                    vn.setUnaffected()
            elif effecttype == RETURN_ADDRESS:
                if hasattr(vn, 'setUnaffected'):
                    vn.setUnaffected()
                if hasattr(vn, 'setReturnAddress'):
                    vn.setReturnAddress()
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
        """Look up a Symbol by name and return its associated HighVariable.

        C++ ref: ``Funcdata::findHigh``
        """
        if self._localmap is not None and hasattr(self._localmap, 'queryByName'):
            symList = []
            self._localmap.queryByName(nm, symList)
            if symList:
                sym = symList[0]
                entry = sym.getFirstWholeMap() if hasattr(sym, 'getFirstWholeMap') else None
                if entry is not None:
                    vn = self.findLinkedVarnode(entry)
                    if vn is not None and hasattr(vn, 'getHigh'):
                        return vn.getHigh()
            return None
        # Fallback: brute-force scan
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
        """Create an annotation Varnode encoding a reference to a PcodeOp.

        C++ ref: ``Funcdata::newVarnodeIop``
        """
        iopSpc = None
        if self._glb is not None and hasattr(self._glb, 'getIopSpace'):
            iopSpc = self._glb.getIopSpace()
        opaddr = op.getAddr() if hasattr(op, 'getAddr') else Address()
        addr = Address(iopSpc, id(op)) if iopSpc is not None else opaddr
        vn = self._vbank.create(_PTR_SIZE, addr)
        self.assignHigh(vn)
        return vn

    def newVarnodeSpace(self, spc):
        """Create a constant varnode encoding an address space identifier.

        C++ encodes the AddrSpace* pointer as a sizeof(void*)-byte constant.
        We use 8 bytes to match the C++ 64-bit build output.

        C++ ref: ``Funcdata::newVarnodeSpace``
        """
        cs = self._glb.getConstantSpace() if self._glb else None
        idx = spc.getIndex() if hasattr(spc, 'getIndex') else 0
        return self._vbank.create(8, Address(cs, idx) if cs else Address())

    def newVarnodeCallSpecs(self, fc):
        """Create an annotation Varnode encoding a reference to a FuncCallSpecs.

        C++ ref: ``Funcdata::newVarnodeCallSpecs`` — uses FSPEC space with
        the object id as the offset.
        """
        fspecSpc = None
        if self._glb is not None and hasattr(self._glb, '_spc_mgr'):
            fspecSpc = getattr(self._glb._spc_mgr, '_fspecSpace', None)
        elif self._glb is not None and hasattr(self._glb, 'getFspecSpace'):
            fspecSpc = self._glb.getFspecSpace()
        if fspecSpc is not None:
            addr = Address(fspecSpc, id(fc))
        else:
            addr = fc.getEntryAddress() if hasattr(fc, 'getEntryAddress') else Address()
        vn = self._vbank.create(8 if fspecSpc is not None else 4, addr)
        self.assignHigh(vn)
        return vn

    def newCodeRef(self, m):
        """Create an annotation Varnode holding a code reference address.

        C++ ref: ``Funcdata::newCodeRef``
        """
        vn = self._vbank.create(1, m)
        vn.setFlags(Varnode.annotation)
        self.assignHigh(vn)
        return vn

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

    def fillinExtrapop(self) -> int:
        """Recover extrapop from function body if unknown.

        If there is no function body or extrapop is already known, return
        the current value.  Otherwise examine the first RETURN op to
        determine the value (assumes x86 ret/ret-imm).

        C++ ref: ``Funcdata::fillinExtrapop``
        """
        EXTRAPOP_UNKNOWN = 0x7FFFFFFF  # ProtoModel::extrapop_unknown
        if self.hasNoCode():
            if hasattr(self, '_funcp') and self._funcp is not None and hasattr(self._funcp, 'getExtraPop'):
                return self._funcp.getExtraPop()
            return self._glb.extra_pop if self._glb and hasattr(self._glb, 'extra_pop') else 0

        if hasattr(self, '_funcp') and self._funcp is not None and hasattr(self._funcp, 'getExtraPop'):
            ep = self._funcp.getExtraPop()
            if ep != EXTRAPOP_UNKNOWN:
                return ep

        # Find first RETURN op
        retop = None
        for op in self._obank.getAliveList() if hasattr(self._obank, 'getAliveList') else []:
            if op.code() == OpCode.CPUI_RETURN:
                retop = op
                break
        if retop is None:
            return 0

        # Try to read bytes at return address (x86 specific)
        extrapop = 4  # default
        if self._glb is not None and hasattr(self._glb, 'loader') and self._glb.loader is not None:
            try:
                buf = self._glb.loader.loadFill(4, retop.getAddr())
                if buf is not None and len(buf) >= 3:
                    if buf[0] == 0xc2:  # ret imm16
                        extrapop = (buf[2] << 8) + buf[1] + 4
            except Exception:
                pass

        if hasattr(self, '_funcp') and self._funcp is not None and hasattr(self._funcp, 'setExtraPop'):
            self._funcp.setExtraPop(extrapop)
        return extrapop

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
        """Unlink op from all varnodes and remove from its basic block.

        C++ ref: ``Funcdata::opUnlink``
        """
        self.opUnsetOutput(op)
        for i in range(op.numInput()):
            inv = op.getIn(i)
            if inv is not None:
                inv.eraseDescend(op)
        parent = op.getParent()
        if parent is not None:
            parent.removeOp(op)

    def opDestroyRaw(self, op):
        """Destroy a raw (dead) PcodeOp and all its unlinked varnodes.

        C++ ref: ``Funcdata::opDestroyRaw``

        Note: C++ expects inputs/outputs to be unlinked from anything else.
        We safely check before destroying each varnode.
        """
        for i in range(op.numInput()):
            inv = op.getIn(i)
            if inv is not None and inv.hasNoDescend():
                self.destroyVarnode(inv)
        outvn = op.getOut()
        if outvn is not None:
            self.destroyVarnode(outvn)
        self._obank.destroy(op)

    def opMarkHalt(self, op, flag):
        """Mark a RETURN op as a halt with the given flags.

        C++ ref: ``Funcdata::opMarkHalt``
        """
        if op.code() != OpCode.CPUI_RETURN:
            raise Exception("Only RETURN pcode ops can be marked as halt")
        valid = (PcodeOp.halt | PcodeOp.badinstruction |
                 PcodeOp.unimplemented | PcodeOp.noreturn |
                 PcodeOp.missing) if hasattr(PcodeOp, 'halt') else 0xFFFFFFFF
        flag &= valid
        if flag == 0:
            raise Exception("Bad halt flag")
        op.setFlag(flag)

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
        if opc is not None and hasattr(self._obank, 'beginByOpcode'):
            return iter(self._obank.beginByOpcode(opc))
        return self._obank.beginAll() if hasattr(self._obank, 'beginAll') else iter([])

    def beginOpAlive(self):
        return self._obank.beginAlive() if hasattr(self._obank, 'beginAlive') else iter([])

    def beginOpDead(self):
        return self._obank.beginDead() if hasattr(self._obank, 'beginDead') else iter([])

    def beginOpAll(self):
        return self._obank.beginAll() if hasattr(self._obank, 'beginAll') else iter([])

    def mapGlobals(self) -> None:
        """Search for addrtied Varnodes in global scope and create Symbols.

        C++ ref: ``Funcdata::mapGlobals``
        """
        if self._localmap is None:
            return
        inconsistentuse = False
        for vn in list(self._vbank.beginLoc()):
            if vn.isFree():
                continue
            if not vn.isPersist():
                continue
            if hasattr(vn, 'getSymbolEntry') and vn.getSymbolEntry() is not None:
                continue
            addr = vn.getAddr()
            sz = vn.getSize()
            # Query existing symbol properties
            fl = 0
            usepoint = Address()
            entry = None
            if hasattr(self._localmap, 'queryProperties'):
                entry = self._localmap.queryProperties(addr, 1, usepoint, fl)
            if entry is None:
                # Try to discover scope and add symbol
                discover = None
                if hasattr(self._localmap, 'discoverScope'):
                    ct = vn.getType() if hasattr(vn, 'getType') and vn.getType() is not None else None
                    if ct is None and self._glb is not None and hasattr(self._glb, 'types'):
                        ct = self._glb.types.getBase(sz, 1)  # TYPE_UNKNOWN
                    discover = self._localmap.discoverScope(addr, sz, usepoint)
                if discover is not None and hasattr(discover, 'addSymbol'):
                    index = 0
                    nm = discover.buildVariableName(addr, usepoint, ct, index,
                                                    Varnode.addrtied | Varnode.persist) \
                        if hasattr(discover, 'buildVariableName') else f"DAT_{addr.getOffset():x}"
                    discover.addSymbol(nm, ct, addr, usepoint)
            else:
                # Check for inconsistent use (symbol too small for varnode)
                eaddr = entry.getAddr() if hasattr(entry, 'getAddr') else addr
                esz = entry.getSize() if hasattr(entry, 'getSize') else sz
                if addr.getOffset() + sz - 1 > eaddr.getOffset() + esz - 1:
                    inconsistentuse = True
        if inconsistentuse:
            self.warningHeader("Globals starting with '_' overlap smaller symbols at the same address")

    def prepareThisPointer(self) -> None:
        """Ensure 'this' pointer Varnode is treated as pointer data-type.

        C++ ref: ``Funcdata::prepareThisPointer``
        """
        numInputs = self._funcp.numParams()
        for i in range(numInputs):
            param = self._funcp.getParam(i)
            if param is not None and hasattr(param, 'isThisPointer'):
                if param.isThisPointer() and param.isTypeLocked():
                    return
        # Check if type recommendations already exist
        if self._localmap is not None and hasattr(self._localmap, 'hasTypeRecommendations'):
            if self._localmap.hasTypeRecommendations():
                return
        # Build a void* type recommendation
        if self._glb is None or not hasattr(self._glb, 'types'):
            return
        dt = self._glb.types.getTypeVoid() if hasattr(self._glb.types, 'getTypeVoid') else None
        if dt is None:
            return
        spc = self._glb.getDefaultDataSpace() if hasattr(self._glb, 'getDefaultDataSpace') else None
        if spc is None:
            return
        addrSize = spc.getAddrSize() if hasattr(spc, 'getAddrSize') else 4
        wordSize = spc.getWordSize() if hasattr(spc, 'getWordSize') else 1
        dt = self._glb.types.getTypePointer(addrSize, dt, wordSize) \
            if hasattr(self._glb.types, 'getTypePointer') else dt
        addr = self._funcp.getThisPointerStorage(dt) \
            if hasattr(self._funcp, 'getThisPointerStorage') else None
        if addr is not None and self._localmap is not None and hasattr(self._localmap, 'addTypeRecommendation'):
            self._localmap.addTypeRecommendation(addr, dt)

    def markIndirectOnly(self) -> None:
        """Mark illegal input Varnodes that are only used by INDIRECT ops.

        C++ ref: ``Funcdata::markIndirectOnly``
        """
        for vn in list(self._vbank.beginLoc()):
            if not vn.isInput():
                continue
            if not hasattr(vn, 'isIllegalInput') or not vn.isIllegalInput():
                continue
            if Funcdata.checkIndirectUse(vn):
                vn.setFlags(Varnode.indirectonly)

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

    @staticmethod
    def compareCallspecs(a, b) -> bool:
        """Compare call specs by block index then op order.

        C++ ref: ``Funcdata::compareCallspecs``
        """
        opa = a.getOp() if hasattr(a, 'getOp') else None
        opb = b.getOp() if hasattr(b, 'getOp') else None
        if opa is None or opb is None:
            return False
        pa = opa.getParent() if hasattr(opa, 'getParent') else None
        pb = opb.getParent() if hasattr(opb, 'getParent') else None
        ind1 = pa.getIndex() if pa is not None and hasattr(pa, 'getIndex') else 0
        ind2 = pb.getIndex() if pb is not None and hasattr(pb, 'getIndex') else 0
        if ind1 != ind2:
            return ind1 < ind2
        return opa.getSeqNum().getOrder() < opb.getSeqNum().getOrder()

    def sortCallSpecs(self) -> None:
        """Sort call specs in dominance order.

        Calls are put in dominance order so that earlier calls get
        evaluated first.  Order affects parameter analysis.

        C++ ref: ``Funcdata::sortCallSpecs``
        """
        import functools
        def _cmp(a, b):
            if Funcdata.compareCallspecs(a, b):
                return -1
            if Funcdata.compareCallspecs(b, a):
                return 1
            return 0
        self._qlst.sort(key=functools.cmp_to_key(_cmp))

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
        """Change the opcode of an existing PcodeOp.

        C++ ref: ``Funcdata::opSetOpcode``
        """
        if hasattr(self._obank, 'changeOpcode') and self._glb is not None and hasattr(self._glb, 'inst'):
            self._obank.changeOpcode(op, self._glb.inst[opc])
        else:
            op.setOpcodeEnum(opc)

    def opSetOutput(self, op: PcodeOp, vn: Varnode) -> None:
        """Set the output of a PcodeOp.

        C++ ref: ``Funcdata::opSetOutput``
        """
        if vn is op.getOut():
            return
        op.setOutput(vn)
        vn.setDef(op)

    def opSetInput(self, op: PcodeOp, vn: Varnode, slot: int) -> None:
        """Set an input of a PcodeOp.

        If *vn* is a free varnode that already has a descendant, clone it
        first so the "free varnode has one descendant" invariant is preserved.
        This matches C++ Ghidra behaviour (op.cc: PcodeOp::setInput).
        """
        old = op.getIn(slot)
        if old is not None:
            old.eraseDescend(op)
        # Clone free varnodes that already have a descendant
        if vn.isFree() and not vn.isSpacebase() and len(vn._descend) > 0:
            from ghidra.core.address import Address
            addr = vn.getAddr()
            clone = self.newVarnode(vn.getSize(), addr)
            clone._flags = vn._flags  # Preserve flags (input, constant, etc.)
            vn = clone
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
        """Remove the output from a PcodeOp, making it free.

        C++ ref: ``Funcdata::opUnsetOutput``
        """
        out = op.getOut()
        if out is not None:
            out._def = None
            out.clearFlags(Varnode.written)
        op.setOutput(None)

    def opDestroy(self, op: PcodeOp) -> None:
        """Destroy a PcodeOp, unlinking it from everything.

        C++ ref: ``Funcdata::opDestroy``
        """
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
        # Clone ops from b into bprime (C++ ref: CloneBlockOps::cloneBlock + patchInputs)
        origToClone = {}  # map original op -> cloned op
        cloneList = []    # list of (cloneOp, origOp) pairs
        if hasattr(b, 'getOpList'):
            # Phase 1: build skeleton clones with outputs
            for origop in list(b.getOpList()):
                if origop.isBranch():
                    if origop.code() != OpCode.CPUI_BRANCH:
                        raise RuntimeError("Cannot duplicate 2-way or n-way branch in nodesplit")
                    continue
                dup = self.newOp(origop.numInput(), origop.getAddr())
                self.opSetOpcode(dup, origop.code())
                # Clone output varnode
                if origop.getOut() is not None:
                    opvn = origop.getOut()
                    self.newVarnodeOut(opvn.getSize(), opvn.getAddr(), dup)
                origToClone[id(origop)] = dup
                cloneList.append((dup, origop))
                self.opInsertEnd(dup, bprime)
            # Phase 2: patch inputs (C++ ref: CloneBlockOps::patchInputs)
            for dup, origop in cloneList:
                if origop.code() == OpCode.CPUI_MULTIEQUAL:
                    # Convert clone to COPY taking the inedge input
                    self.opSetOpcode(dup, OpCode.CPUI_COPY)
                    if hasattr(dup, 'setNumInputs'):
                        dup.setNumInputs(1)
                    self.opSetInput(dup, origop.getIn(inedge), 0)
                    # Remove inedge from original MULTIEQUAL
                    self.opRemoveInput(origop, inedge)
                    if origop.numInput() == 1:
                        self.opSetOpcode(origop, OpCode.CPUI_COPY)
                else:
                    for i in range(origop.numInput()):
                        inv = origop.getIn(i)
                        if inv.isConstant():
                            cloneVn = inv  # Constants can be shared
                        elif hasattr(inv, 'isAnnotation') and inv.isAnnotation():
                            cloneVn = self.newCodeRef(inv.getAddr())
                        elif inv.isWritten():
                            defOp = inv.getDef()
                            mapped = origToClone.get(id(defOp))
                            if mapped is not None and mapped.getOut() is not None:
                                cloneVn = mapped.getOut()
                            else:
                                cloneVn = inv
                        else:
                            cloneVn = inv
                        self.opSetInput(dup, cloneVn, i)
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
        """Check if the given Varnode only flows into call-based INDIRECT ops.

        Flow is followed through MULTIEQUAL ops and INDIRECT store ops.

        C++ ref: ``Funcdata::checkIndirectUse``
        """
        vlist = [vn]
        marked = {id(vn)}
        result = True
        i = 0
        while i < len(vlist) and result:
            cur = vlist[i]
            i += 1
            for op in cur.getDescendants():
                opc = op.code()
                if opc == OpCode.CPUI_INDIRECT:
                    if hasattr(op, 'isIndirectStore') and op.isIndirectStore():
                        outvn = op.getOut()
                        if outvn is not None and id(outvn) not in marked:
                            vlist.append(outvn)
                            marked.add(id(outvn))
                elif opc == OpCode.CPUI_MULTIEQUAL:
                    outvn = op.getOut()
                    if outvn is not None and id(outvn) not in marked:
                        vlist.append(outvn)
                        marked.add(id(outvn))
                else:
                    result = False
                    break
        return result

    # --- Varnode manipulation helpers ---

    def destroyVarnode(self, vn) -> None:
        """Delete the given Varnode, clearing all references first.

        All PcodeOps reading the Varnode have their input slot cleared.
        If the Varnode is defined by a PcodeOp, that op's output is cleared.

        C++ ref: ``Funcdata::destroyVarnode``
        """
        for op in list(vn.getDescendants()):
            slot = op.getSlot(vn)
            op.clearInput(slot)
        defop = vn.getDef() if vn.isWritten() else None
        if defop is not None:
            defop.setOutput(None)
            vn._def = None
            vn.clearFlags(Varnode.written)
        if hasattr(vn, 'destroyDescend'):
            vn.destroyDescend()
        self._vbank.destroy(vn)

    def cloneVarnode(self, vn):
        """Clone a Varnode, preserving allowed flags.

        C++ ref: ``Funcdata::cloneVarnode``
        """
        ct = vn.getType() if hasattr(vn, 'getType') else None
        newvn = self._vbank.create(vn.getSize(), vn.getAddr(), ct)
        # Clone only the allowed flags
        allowed = (Varnode.annotation | Varnode.externref |
                   Varnode.readonly | Varnode.persist |
                   Varnode.addrtied | Varnode.addrforce |
                   Varnode.indirect_creation | Varnode.incidental_copy |
                   Varnode.volatil | Varnode.mapped)
        vflags = vn.getFlags() & allowed
        newvn.setFlags(vflags)
        return newvn

    def splitUses(self, vn) -> None:
        """Duplicate the defining PcodeOp at each read so each becomes a new unique.

        For each descendant except the last, clone the defining op and
        create a new output Varnode, then redirect the descendant's input
        to the new clone output. Dead-code actions should remove the
        original op if it becomes unused.

        C++ ref: ``Funcdata::splitUses``
        """
        op = vn.getDef()
        if op is None:
            return
        descs = list(vn.getDescendants())
        if len(descs) <= 1:
            return
        # Process all descendants except the last one (which keeps the original)
        for useop in descs[:-1]:
            slot = useop.getSlot(vn)
            newop = self.newOp(op.numInput(), op.getAddr())
            newvn = self.newVarnode(vn.getSize(), vn.getAddr(), vn.getType() if hasattr(vn, 'getType') else None)
            self.opSetOutput(newop, newvn)
            self.opSetOpcode(newop, op.code())
            for i in range(op.numInput()):
                self.opSetInput(newop, op.getIn(i), i)
            self.opSetInput(useop, newvn, slot)
            self.opInsertBefore(newop, op)

    def descend2Undef(self, vn) -> bool:
        """Replace reads of the given Varnode with a special 0xBADDEF constant.

        For MULTIEQUAL and INDIRECT ops, a COPY is inserted since constants
        cannot be placed directly as inputs. Blocks with no predecessors
        (unreachable) are skipped.

        C++ ref: ``Funcdata::descend2Undef``
        """
        res = False
        sz = vn.getSize()
        for op in list(vn.getDescendants()):
            bl = op.getParent()
            if bl is not None and hasattr(bl, 'isDead') and bl.isDead():
                continue
            if bl is not None and bl.sizeIn() != 0:
                res = True
            i = op.getSlot(vn)
            badconst = self.newConstant(sz, 0xBADDEF)
            opc = op.code()
            if opc == OpCode.CPUI_MULTIEQUAL:
                # Cannot put constant directly into MULTIEQUAL
                inbl = bl.getIn(i) if bl is not None else None
                if inbl is not None:
                    copyop = self.newOp(1, inbl.getStart())
                    inputvn = self.newUniqueOut(sz, copyop)
                    self.opSetOpcode(copyop, OpCode.CPUI_COPY)
                    self.opSetInput(copyop, badconst, 0)
                    self.opInsertEnd(copyop, inbl)
                    self.opSetInput(op, inputvn, i)
                else:
                    self.opSetInput(op, badconst, i)
            elif opc == OpCode.CPUI_INDIRECT:
                # Cannot put constant directly into INDIRECT
                copyop = self.newOp(1, op.getAddr())
                inputvn = self.newUniqueOut(sz, copyop)
                self.opSetOpcode(copyop, OpCode.CPUI_COPY)
                self.opSetInput(copyop, badconst, 0)
                self.opInsertBefore(copyop, op)
                self.opSetInput(op, inputvn, i)
            else:
                self.opSetInput(op, badconst, i)
        return res

    def assignHigh(self, vn):
        """Assign a HighVariable to a Varnode if high-level analysis is on.

        Only assigns if highlevel_on flag is set. Calculates cover if the
        Varnode already has one, and skips annotation Varnodes.

        C++ ref: ``Funcdata::assignHigh``
        """
        if (self._flags & Funcdata.highlevel_on) != 0:
            if hasattr(vn, 'hasCover') and vn.hasCover():
                if hasattr(vn, 'calcCover'):
                    vn.calcCover()
            if not (hasattr(vn, 'isAnnotation') and vn.isAnnotation()):
                return HighVariable(vn)
        return None

    def setVarnodeProperties(self, vn) -> None:
        """Look-up boolean properties and data-type information for a Varnode.

        C++ ref: ``Funcdata::setVarnodeProperties``
        """
        if not vn.isMapped():
            vflags = 0
            usepoint = vn.getUsePoint(self) if hasattr(vn, 'getUsePoint') else Address()
            entry = None
            if self._localmap is not None and hasattr(self._localmap, 'queryProperties'):
                entry = self._localmap.queryProperties(vn.getAddr(), vn.getSize(), usepoint, vflags)
            if entry is not None and hasattr(vn, 'setSymbolProperties'):
                vn.setSymbolProperties(entry)
            elif vflags != 0:
                vn.setFlags(vflags & ~Varnode.typelock)
        if self.isHighOn() and hasattr(vn, 'calcCover'):
            vn.calcCover()

    def coverVarnodes(self, entry, vnlist: list) -> None:
        """Make sure every Varnode in the given list has a Symbol it will link to.

        This is used when Varnodes overlap a locked Symbol but extend beyond it.
        An existing Symbol is passed in with a list of possibly overextending
        Varnodes. The list is in Address order. We check that each Varnode has
        a Symbol that overlaps its first byte (to guarantee a link). If one
        doesn't exist it is created.

        C++ ref: ``Funcdata::coverVarnodes``
        """
        if entry is None or not vnlist:
            return
        sym = entry.getSymbol() if hasattr(entry, 'getSymbol') else None
        if sym is None:
            return
        scope = sym.getScope() if hasattr(sym, 'getScope') else None
        if scope is None:
            return
        for i, vn in enumerate(vnlist):
            # We only need to check once for all Varnodes at the same Address
            # Of these, pick the biggest Varnode (last one in the list at same addr)
            if i + 1 < len(vnlist) and vnlist[i + 1].getAddr() == vn.getAddr():
                continue
            usepoint = vn.getUsePoint(self) if hasattr(vn, 'getUsePoint') else Address()
            overlapEntry = scope.findContainer(vn.getAddr(), vn.getSize(), usepoint) if hasattr(scope, 'findContainer') else None
            if overlapEntry is None:
                diff = vn.getOffset() - entry.getAddr().getOffset()
                name = f"{sym.getName()}_{diff}"
                if vn.isAddrTied() if hasattr(vn, 'isAddrTied') else False:
                    usepoint = Address()
                if hasattr(scope, 'addSymbol'):
                    tp = vn.getHigh().getType() if hasattr(vn, 'getHigh') and vn.getHigh() is not None else None
                    scope.addSymbol(name, tp, vn.getAddr(), usepoint)

    def syncVarnodesWithSymbol(self, iterobj, fl: int, ct) -> bool:
        """Update boolean properties and data-type on a set of Varnodes.

        The iterator provides a sequence of Varnodes at the same location.
        We update their flags and optionally their data-type to match what
        is dictated by the Symbol mapping.

        C++ ref: ``Funcdata::syncVarnodesWithSymbol``
        """
        from ghidra.ir.varnode import Varnode as VnCls
        updateoccurred = False
        mask = VnCls.mapped
        if (fl & VnCls.addrtied) == 0:
            mask |= VnCls.addrtied | VnCls.addrforce
        if (fl & VnCls.nolocalalias) != 0:
            mask |= VnCls.nolocalalias | VnCls.addrforce
        fl &= mask

        vnlist = list(iterobj) if not isinstance(iterobj, list) else iterobj
        for vn in vnlist:
            if vn.isFree():
                continue
            vnflags = vn.getFlags()
            if hasattr(vn, 'mapentry') and vn.mapentry is not None:
                localMask = mask & ~VnCls.mapped
                localFlags = fl & localMask
                if (vnflags & localMask) != localFlags:
                    updateoccurred = True
                    vn.setFlags(localFlags)
                    vn.clearFlags((~localFlags) & localMask)
            elif (vnflags & mask) != fl:
                updateoccurred = True
                vn.setFlags(fl)
                vn.clearFlags((~fl) & mask)
            if ct is not None and hasattr(vn, 'updateType'):
                if vn.updateType(ct):
                    updateoccurred = True
        return updateoccurred

    def handleSymbolConflict(self, entry, vn):
        """Handle a Varnode that overlaps the given SymbolEntry.

        Make sure the Varnode is part of the variable underlying the Symbol.
        If not, remap things so that the Varnode maps to a distinct Symbol.
        In either case, attach the appropriate Symbol to the Varnode.

        C++ ref: ``Funcdata::handleSymbolConflict``
        """
        if entry is None:
            return None
        # Simple cases: input, addrtied, persist, constant, or dynamic entry
        if vn.isInput() or (hasattr(vn, 'isAddrTied') and vn.isAddrTied()) or \
           vn.isPersist() or vn.isConstant() or \
           (hasattr(entry, 'isDynamic') and entry.isDynamic()):
            if hasattr(vn, 'setSymbolEntry'):
                vn.setSymbolEntry(entry)
            return entry.getSymbol() if hasattr(entry, 'getSymbol') else None

        high = vn.getHigh() if hasattr(vn, 'getHigh') else None
        otherHigh = None
        # Look for a conflicting HighVariable at same size/addr
        if hasattr(self, 'beginLoc') and hasattr(entry, 'getSize') and hasattr(entry, 'getAddr'):
            for othervn in self.beginLoc(entry.getSize(), entry.getAddr()):
                if othervn.getSize() != entry.getSize():
                    break
                if othervn.getAddr() != entry.getAddr():
                    break
                tmpHigh = othervn.getHigh() if hasattr(othervn, 'getHigh') else None
                if tmpHigh is not None and tmpHigh is not high:
                    otherHigh = tmpHigh
                    break

        if otherHigh is None:
            if hasattr(vn, 'setSymbolEntry'):
                vn.setSymbolEntry(entry)
            return entry.getSymbol() if hasattr(entry, 'getSymbol') else None

        # Conflicting variable - build a dynamic symbol
        if hasattr(self, 'buildDynamicSymbol'):
            self.buildDynamicSymbol(vn)
        se = vn.getSymbolEntry() if hasattr(vn, 'getSymbolEntry') else None
        return se.getSymbol() if se is not None and hasattr(se, 'getSymbol') else None

    def applyUnionFacet(self, entry, dhash) -> bool:
        """Apply union facet resolution from a dynamic hash.

        The SymbolEntry encodes a UnionFacetSymbol which selects a specific
        field of a union data-type to apply at a particular PcodeOp edge.

        C++ ref: ``Funcdata::applyUnionFacet``
        """
        if entry is None:
            return False
        sym = entry.getSymbol() if hasattr(entry, 'getSymbol') else None
        if sym is None:
            return False
        if not hasattr(dhash, 'findOp'):
            return False
        op = dhash.findOp(self, entry.getFirstUseAddress(), entry.getHash())
        if op is None:
            return False
        slot = dhash.getSlotFromHash(entry.getHash()) if hasattr(dhash, 'getSlotFromHash') else 0
        fldNum = sym.getFieldNumber() if hasattr(sym, 'getFieldNumber') else -1
        if fldNum < 0:
            return False
        try:
            from ghidra.types.type_base import ResolvedUnion
            resolve = ResolvedUnion(sym.getType(), fldNum, self._glb.types)
            resolve.setLock(True)
            if hasattr(self, 'setUnionField'):
                return self.setUnionField(sym.getType(), op, slot, resolve)
        except (ImportError, Exception):
            pass
        return False

    def onlyOpUse(self, invn, opmatch, trial, mainFlags) -> bool:
        """Check if a Varnode is only used as a parameter to a given op.

        Walk all descendants of invn. If every path leads to opmatch
        (at the correct slot) or to an INDIRECT / MULTIEQUAL / extension,
        return True. Any other real use means the Varnode is not exclusively
        used for parameter passing.

        C++ ref: ``Funcdata::onlyOpUse``
        """
        TraverseIndirectAlt = 0x1
        TraverseActionAlt = 0x2
        TraverseConcatHigh = 0x4
        TraverseLsbTruncated = 0x8

        varlist = [(invn, mainFlags)]
        marked = {id(invn)}
        res = True
        i = 0
        while i < len(varlist) and res:
            vn, baseFlags = varlist[i]
            i += 1
            for op in vn.getDescendants():
                if op is opmatch:
                    trialSlot = trial.getSlot() if hasattr(trial, 'getSlot') else 0
                    if op.getIn(trialSlot) is vn:
                        continue
                curFlags = baseFlags
                opc = op.code()
                if opc in (OpCode.CPUI_BRANCH, OpCode.CPUI_CBRANCH,
                           OpCode.CPUI_BRANCHIND, OpCode.CPUI_LOAD, OpCode.CPUI_STORE):
                    res = False
                    break
                elif opc in (OpCode.CPUI_CALL, OpCode.CPUI_CALLIND):
                    if self.checkCallDoubleUse(opmatch, op, vn, curFlags, trial):
                        continue
                    res = False
                    break
                elif opc == OpCode.CPUI_INDIRECT:
                    curFlags |= TraverseIndirectAlt
                elif opc == OpCode.CPUI_COPY:
                    outvn = op.getOut()
                    if outvn is not None and hasattr(outvn, 'getSpace'):
                        if outvn.getSpace().getType() != IPTR_INTERNAL:
                            if not (hasattr(op, 'isIncidentalCopy') and op.isIncidentalCopy()):
                                if not (hasattr(vn, 'isIncidentalCopy') and vn.isIncidentalCopy()):
                                    curFlags |= TraverseActionAlt
                elif opc == OpCode.CPUI_RETURN:
                    if opmatch.code() == OpCode.CPUI_RETURN:
                        trialSlot = trial.getSlot() if hasattr(trial, 'getSlot') else 0
                        if op.getIn(trialSlot) is vn:
                            continue
                    res = False
                    break
                elif opc in (OpCode.CPUI_MULTIEQUAL, OpCode.CPUI_INT_SEXT,
                             OpCode.CPUI_INT_ZEXT, OpCode.CPUI_CAST):
                    pass  # Follow through
                elif opc == OpCode.CPUI_PIECE:
                    if op.getIn(0) is vn:
                        if (curFlags & TraverseLsbTruncated) != 0:
                            continue
                        curFlags |= TraverseConcatHigh
                elif opc == OpCode.CPUI_SUBPIECE:
                    if op.getIn(1).getOffset() != 0:
                        if (curFlags & TraverseConcatHigh) == 0:
                            curFlags |= TraverseLsbTruncated
                else:
                    curFlags |= TraverseActionAlt
                subvn = op.getOut()
                if subvn is not None:
                    if hasattr(subvn, 'isPersist') and subvn.isPersist():
                        res = False
                        break
                    if id(subvn) not in marked:
                        varlist.append((subvn, curFlags))
                        marked.add(id(subvn))
        return res

    def ancestorOpUse(self, maxlevel: int, invn, op, trial, offset: int, mainFlags: int) -> bool:
        """Test if the given trial Varnode is likely only used for parameter passing.

        Flow is followed from the Varnode and from ancestors it was copied
        from to see if it hits anything other than the given CALL or RETURN.

        C++ ref: ``Funcdata::ancestorOpUse``
        """
        if maxlevel == 0:
            return False
        if not invn.isWritten():
            if not invn.isInput():
                return False
            if not invn.isTypeLock():
                return False
            return self.onlyOpUse(invn, op, trial, mainFlags)

        defop = invn.getDef()
        opc = defop.code()
        if opc == OpCode.CPUI_INDIRECT:
            if hasattr(defop, 'isIndirectCreation') and defop.isIndirectCreation():
                return False
            return self.ancestorOpUse(maxlevel - 1, defop.getIn(0), op, trial, offset, mainFlags | 0x10)
        elif opc == OpCode.CPUI_MULTIEQUAL:
            if hasattr(defop, 'isMark') and defop.isMark():
                return False
            if hasattr(defop, 'setMark'):
                defop.setMark()
            for j in range(defop.numInput()):
                if self.ancestorOpUse(maxlevel - 1, defop.getIn(j), op, trial, offset, mainFlags):
                    if hasattr(defop, 'clearMark'):
                        defop.clearMark()
                    return True
            if hasattr(defop, 'clearMark'):
                defop.clearMark()
            return False
        elif opc == OpCode.CPUI_COPY:
            inSpace = invn.getSpace().getType() if hasattr(invn, 'getSpace') and invn.getSpace() is not None else IPTR_INTERNAL
            isIncidental = (hasattr(defop, 'isIncidentalCopy') and defop.isIncidentalCopy()) or \
                           (hasattr(defop.getIn(0), 'isIncidentalCopy') and defop.getIn(0).isIncidentalCopy())
            if inSpace == IPTR_INTERNAL or isIncidental:
                return self.ancestorOpUse(maxlevel - 1, defop.getIn(0), op, trial, offset, mainFlags)
        elif opc == OpCode.CPUI_PIECE:
            if offset == 0:
                return self.ancestorOpUse(maxlevel - 1, defop.getIn(1), op, trial, 0, mainFlags)
            if offset == defop.getIn(1).getSize():
                return self.ancestorOpUse(maxlevel - 1, defop.getIn(0), op, trial, 0, mainFlags)
            return False
        elif opc == OpCode.CPUI_SUBPIECE:
            newOff = defop.getIn(1).getOffset()
            if newOff == 0:
                srcvn = defop.getIn(0)
                if srcvn.isWritten():
                    remop = srcvn.getDef()
                    if remop.code() in (OpCode.CPUI_INT_REM, OpCode.CPUI_INT_SREM):
                        if hasattr(trial, 'setRemFormed'):
                            trial.setRemFormed()
            inSpace = invn.getSpace().getType() if hasattr(invn, 'getSpace') and invn.getSpace() is not None else IPTR_INTERNAL
            isIncidental = (hasattr(defop, 'isIncidentalCopy') and defop.isIncidentalCopy()) or \
                           (hasattr(defop.getIn(0), 'isIncidentalCopy') and defop.getIn(0).isIncidentalCopy())
            if inSpace == IPTR_INTERNAL or isIncidental:
                return self.ancestorOpUse(maxlevel - 1, defop.getIn(0), op, trial, offset + newOff, mainFlags)
        elif opc in (OpCode.CPUI_CALL, OpCode.CPUI_CALLIND):
            return False
        return self.onlyOpUse(invn, op, trial, mainFlags)

    def checkCallDoubleUse(self, opmatch, op, vn, fl, trial) -> bool:
        """Check if a Varnode is legitimately used in two different call sites.

        If vn flows into a CALL/CALLIND op that is different from opmatch,
        determine if this constitutes a legitimate double-use (same function,
        same parameter slot) or if it should be considered a real alternate use.

        C++ ref: ``Funcdata::checkCallDoubleUse``
        """
        j = op.getSlot(vn) if hasattr(op, 'getSlot') else -1
        if j <= 0:
            return False  # Flow traces to indirect call variable, not a param
        fc = self.getCallSpecs(op) if hasattr(self, 'getCallSpecs') else None
        matchfc = self.getCallSpecs(opmatch) if hasattr(self, 'getCallSpecs') else None
        if fc is not None and matchfc is not None and op.code() == opmatch.code():
            isdirect = (opmatch.code() == OpCode.CPUI_CALL)
            sameFunc = False
            if isdirect and hasattr(matchfc, 'getEntryAddress') and hasattr(fc, 'getEntryAddress'):
                sameFunc = (matchfc.getEntryAddress() == fc.getEntryAddress())
            elif not isdirect:
                sameFunc = (op.getIn(0) is opmatch.getIn(0))
            if sameFunc:
                if hasattr(fc, 'getActiveInput') and fc.getActiveInput() is not None:
                    active = fc.getActiveInput()
                    if hasattr(active, 'getTrialForInputVarnode'):
                        curtrial = active.getTrialForInputVarnode(j)
                        if curtrial is not None and hasattr(curtrial, 'getAddress') and hasattr(trial, 'getAddress'):
                            if curtrial.getAddress() == trial.getAddress():
                                if op.getParent() == opmatch.getParent():
                                    if opmatch.getSeqNum().getOrder() < op.getSeqNum().getOrder():
                                        return True
                                else:
                                    return True

        if fc is not None and hasattr(fc, 'isInputActive') and fc.isInputActive():
            if hasattr(fc, 'getActiveInput') and fc.getActiveInput() is not None:
                active = fc.getActiveInput()
                if hasattr(active, 'getTrialForInputVarnode'):
                    curtrial = active.getTrialForInputVarnode(j)
                    if curtrial is not None and hasattr(curtrial, 'isChecked') and curtrial.isChecked():
                        if hasattr(curtrial, 'isActive') and curtrial.isActive():
                            return False
                    else:
                        return False
            return True
        return False

    def attemptDynamicMapping(self, entry, dhash) -> bool:
        """Map properties of a dynamic symbol to a Varnode.

        Given a dynamic mapping, try to find the mapped Varnode, then adjust
        type and flags to reflect this mapping.

        C++ ref: ``Funcdata::attemptDynamicMapping``
        """
        if entry is None:
            return False
        sym = entry.getSymbol() if hasattr(entry, 'getSymbol') else None
        if sym is None:
            return False
        if hasattr(dhash, 'clear'):
            dhash.clear()
        category = sym.getCategory() if hasattr(sym, 'getCategory') else -1
        UNION_FACET = 3  # Symbol::union_facet
        EQUATE = 1  # Symbol::equate
        if category == UNION_FACET:
            if hasattr(self, 'applyUnionFacet'):
                return self.applyUnionFacet(entry, dhash)
            return False
        vn = None
        if hasattr(dhash, 'findVarnode'):
            useaddr = entry.getFirstUseAddress() if hasattr(entry, 'getFirstUseAddress') else None
            hashval = entry.getHash() if hasattr(entry, 'getHash') else 0
            vn = dhash.findVarnode(self, useaddr, hashval)
        if vn is None:
            return False
        if hasattr(vn, 'getSymbolEntry') and vn.getSymbolEntry() is not None:
            return False  # Already labeled
        if category == EQUATE:
            if hasattr(vn, 'setSymbolEntry'):
                vn.setSymbolEntry(entry)
            return True
        esize = entry.getSize() if hasattr(entry, 'getSize') else 0
        if esize == vn.getSize():
            if hasattr(vn, 'setSymbolProperties'):
                if vn.setSymbolProperties(entry):
                    return True
        return False

    def attemptDynamicMappingLate(self, entry, dhash) -> bool:
        """Map the name of a dynamic symbol to a Varnode (late pass).

        Attaches the Symbol name but may not enforce the data-type. If the
        symbol did not lock its type, the Varnode's propagated type is used.

        C++ ref: ``Funcdata::attemptDynamicMappingLate``
        """
        if entry is None:
            return False
        if hasattr(dhash, 'clear'):
            dhash.clear()
        sym = entry.getSymbol() if hasattr(entry, 'getSymbol') else None
        if sym is None:
            return False
        UNION_FACET = 3
        EQUATE = 1
        if hasattr(sym, 'getCategory') and sym.getCategory() == UNION_FACET:
            if hasattr(self, 'applyUnionFacet'):
                return self.applyUnionFacet(entry, dhash)
            return False
        vn = None
        if hasattr(dhash, 'findVarnode'):
            useaddr = entry.getFirstUseAddress() if hasattr(entry, 'getFirstUseAddress') else None
            hashval = entry.getHash() if hasattr(entry, 'getHash') else 0
            vn = dhash.findVarnode(self, useaddr, hashval)
        if vn is None:
            return False
        if hasattr(vn, 'getSymbolEntry') and vn.getSymbolEntry() is not None:
            return False
        if hasattr(sym, 'getCategory') and sym.getCategory() == EQUATE:
            if hasattr(vn, 'setSymbolEntry'):
                vn.setSymbolEntry(entry)
            return True
        esize = entry.getSize() if hasattr(entry, 'getSize') else 0
        if vn.getSize() != esize:
            return False
        # Handle implied varnodes (cast insertion)
        if hasattr(vn, 'isImplied') and vn.isImplied():
            newvn = None
            if vn.isWritten() and vn.getDef().code() == OpCode.CPUI_CAST:
                newvn = vn.getDef().getIn(0)
            else:
                castop = vn.loneDescend() if hasattr(vn, 'loneDescend') else None
                if castop is not None and castop.code() == OpCode.CPUI_CAST:
                    newvn = castop.getOut()
            if newvn is not None and hasattr(newvn, 'isExplicit') and newvn.isExplicit():
                vn = newvn
        if hasattr(vn, 'setSymbolEntry'):
            vn.setSymbolEntry(entry)
        if hasattr(sym, 'isTypeLocked') and not sym.isTypeLocked():
            if self._localmap is not None and hasattr(self._localmap, 'retypeSymbol'):
                vntype = vn.getType() if hasattr(vn, 'getType') else None
                if vntype is not None:
                    self._localmap.retypeSymbol(sym, vntype)
        return True

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
        """Print description of memory ranges associated with local scopes.

        C++ ref: ``Funcdata::printLocalRange``
        """
        import io
        s = io.StringIO()
        if self._localmap is not None:
            if hasattr(self._localmap, 'printBounds'):
                s.write(self._localmap.printBounds())
            if hasattr(self._localmap, 'childrenBegin'):
                for child in self._localmap.childrenBegin():
                    if hasattr(child, 'printBounds'):
                        s.write(child.printBounds())
        return s.getvalue()

    # --- Misc helpers ---

    def constructConstSpacebase(self, spc):
        """Construct a constant representing the base of the given global address space.

        The constant will have the TypeSpacebase data-type set.

        C++ ref: ``Funcdata::constructConstSpacebase``
        """
        from ghidra.ir.varnode import Varnode as VnCls
        addrSize = spc.getAddrSize() if hasattr(spc, 'getAddrSize') else 4
        spacePtr = self.newConstant(addrSize, 0)
        if self._glb is not None and hasattr(self._glb, 'types') and self._glb.types is not None:
            ct = self._glb.types.getTypeSpacebase(spc, Address()) if hasattr(self._glb.types, 'getTypeSpacebase') else None
            if ct is not None and hasattr(self._glb.types, 'getTypePointer'):
                wordSize = spc.getWordSize() if hasattr(spc, 'getWordSize') else 1
                ptr = self._glb.types.getTypePointer(addrSize, ct, wordSize)
                spacePtr.updateType(ptr, True, True)
        spacePtr.setFlags(VnCls.spacebase)
        return spacePtr

    def spacebaseConstant(self, op, slot, entry, rampoint, origval, origsize) -> None:
        """Convert a constant pointer into a ram CPUI_PTRSUB.

        A constant known to be a pointer into an address space like ram is
        converted into a Varnode defined by CPUI_PTRSUB.  The PTRSUB takes
        the constant 0 (marked spacebase) as its first input.  An additional
        INT_ADD, INT_ZEXT, or SUBPIECE may be inserted to handle offsets and
        size mismatches.

        C++ ref: ``Funcdata::spacebaseConstant``
        """
        if rampoint is None or self._glb is None:
            return
        sz = rampoint.getAddrSize() if hasattr(rampoint, 'getAddrSize') else 4
        spaceid = rampoint.getSpace() if hasattr(rampoint, 'getSpace') else None

        # Build spacebase pointer type
        sb_type = None
        if hasattr(self._glb, 'types') and self._glb.types is not None:
            if hasattr(self._glb.types, 'getTypeSpacebase'):
                sb_type = self._glb.types.getTypeSpacebase(spaceid, Address())
                wordSize = spaceid.getWordSize() if spaceid is not None and hasattr(spaceid, 'getWordSize') else 1
                sb_type = self._glb.types.getTypePointer(sz, sb_type, wordSize)

        # Calculate extra offset from entry start (in address units)
        entry_off = entry.getAddr().getOffset() if hasattr(entry, 'getAddr') else 0
        extra = rampoint.getOffset() - entry_off
        if spaceid is not None and hasattr(spaceid, 'getWordSize') and spaceid.getWordSize() > 1:
            extra = extra // spaceid.getWordSize()

        isCopy = (op.code() == OpCode.CPUI_COPY)
        addOp = None
        extraOp = None
        zextOp = None
        subOp = None

        if isCopy:
            if sz < origsize:
                zextOp = op
            else:
                if hasattr(op, 'insertInput'):
                    op.insertInput(1)
                else:
                    self.opInsertInput(op, self.newConstant(1, 0), 1)
                if origsize < sz:
                    subOp = op
                elif extra != 0:
                    extraOp = op
                else:
                    addOp = op

        # Create spacebase constant varnode
        spacebase_vn = self.newConstant(sz, 0)
        if sb_type is not None:
            spacebase_vn.updateType(sb_type, True, True)
        spacebase_vn.setFlags(Varnode.spacebase)

        if addOp is None:
            addOp = self.newOp(2, op.getAddr())
            self.opSetOpcode(addOp, OpCode.CPUI_PTRSUB)
            self.newUniqueOut(sz, addOp)
            self.opInsertBefore(addOp, op)
        else:
            self.opSetOpcode(addOp, OpCode.CPUI_PTRSUB)

        outvn = addOp.getOut()

        # newconstoff preserves origval in address units
        mask = (1 << (sz * 8)) - 1
        newconstoff = (origval - extra) & mask
        newconst = self.newConstant(sz, newconstoff)
        if hasattr(newconst, 'setPtrCheck'):
            newconst.setPtrCheck()
        if spaceid is not None and hasattr(spaceid, 'isTruncated') and spaceid.isTruncated():
            if hasattr(addOp, 'setPtrFlow'):
                addOp.setPtrFlow()
        self.opSetInput(addOp, spacebase_vn, 0)
        self.opSetInput(addOp, newconst, 1)

        # Assign pointer type to output
        if entry is not None and outvn is not None:
            sym = entry.getSymbol() if hasattr(entry, 'getSymbol') else None
            if sym is not None and hasattr(self._glb, 'types') and self._glb.types is not None:
                entrytype = sym.getType() if hasattr(sym, 'getType') else None
                if entrytype is not None and hasattr(self._glb.types, 'getTypePointerStripArray'):
                    wordSize = spaceid.getWordSize() if spaceid is not None and hasattr(spaceid, 'getWordSize') else 1
                    ptrentrytype = self._glb.types.getTypePointerStripArray(sz, entrytype, wordSize)
                    typelock = sym.isTypeLocked() if hasattr(sym, 'isTypeLocked') else False
                    if typelock and hasattr(entrytype, 'getMetatype') and entrytype.getMetatype() == 10:  # TYPE_UNKNOWN
                        typelock = False
                    outvn.updateType(ptrentrytype, typelock, False)

        if extra != 0:
            if extraOp is None:
                extraOp = self.newOp(2, op.getAddr())
                self.opSetOpcode(extraOp, OpCode.CPUI_INT_ADD)
                self.newUniqueOut(sz, extraOp)
                self.opInsertBefore(extraOp, op)
            else:
                self.opSetOpcode(extraOp, OpCode.CPUI_INT_ADD)
            extconst = self.newConstant(sz, extra & mask)
            if hasattr(extconst, 'setPtrCheck'):
                extconst.setPtrCheck()
            self.opSetInput(extraOp, outvn, 0)
            self.opSetInput(extraOp, extconst, 1)
            outvn = extraOp.getOut()

        if sz < origsize:
            if zextOp is None:
                zextOp = self.newOp(1, op.getAddr())
                self.opSetOpcode(zextOp, OpCode.CPUI_INT_ZEXT)
                self.newUniqueOut(origsize, zextOp)
                self.opInsertBefore(zextOp, op)
            else:
                self.opSetOpcode(zextOp, OpCode.CPUI_INT_ZEXT)
            self.opSetInput(zextOp, outvn, 0)
            outvn = zextOp.getOut()
        elif origsize < sz:
            if subOp is None:
                subOp = self.newOp(2, op.getAddr())
                self.opSetOpcode(subOp, OpCode.CPUI_SUBPIECE)
                self.newUniqueOut(origsize, subOp)
                self.opInsertBefore(subOp, op)
            else:
                self.opSetOpcode(subOp, OpCode.CPUI_SUBPIECE)
            self.opSetInput(subOp, outvn, 0)
            self.opSetInput(subOp, self.newConstant(4, 0), 1)
            outvn = subOp.getOut()

        if not isCopy:
            self.opSetInput(op, outvn, slot)

    def switchOverJumpTables(self, flow) -> None:
        """Convert jump-table addresses to basic block indices."""
        for jt in self._jumpvec:
            if hasattr(jt, 'switchOver'):
                jt.switchOver(flow)

    def issueDatatypeWarnings(self) -> None:
        """Add warning headers for any data-types that have been modified.

        C++ ref: ``Funcdata::issueDatatypeWarnings``
        """
        if self._glb is None:
            return
        if hasattr(self._glb, 'types') and self._glb.types is not None:
            tf = self._glb.types
            if hasattr(tf, 'beginWarnings') and hasattr(tf, 'endWarnings'):
                for w in tf.beginWarnings():
                    msg = w.getWarning() if hasattr(w, 'getWarning') else str(w)
                    self.warningHeader(msg)
            elif hasattr(tf, 'getDirtyTypes'):
                for dt in tf.getDirtyTypes():
                    self.warningHeader("Data-type '%s' has been modified" % dt.getName())

    def enableJTCallback(self, cb) -> None:
        """Enable a jump-table callback."""
        self._jtcallback = cb

    def disableJTCallback(self) -> None:
        """Disable the jump-table callback."""
        self._jtcallback = None

    def stageJumpTable(self, partial, jt, op, flow):
        """Stage jump-table analysis on a partial clone of the function.

        If the partial Funcdata has not yet been analyzed for jump-table
        recovery, a truncated flow is generated and the 'jumptable' action
        group is run to simplify the partial function. Then the BRANCHIND
        in the partial is located and the JumpTable is asked to recover
        addresses from the simplified IR.

        C++ ref: ``Funcdata::stageJumpTable``

        Args:
            partial: A Funcdata clone used for jump-table analysis.
            jt: The JumpTable object to fill in.
            op: The BRANCHIND PcodeOp in the original function.
            flow: The FlowInfo for the original function (or None).

        Returns:
            A recovery mode string: 'success', 'fail_normal', 'fail_return',
            'fail_thunk', or None on error.
        """
        if not partial.isJumptableRecoveryOn():
            partial._flags |= Funcdata.jumptablerecovery_on
            partial.truncatedFlow(self, flow)

            if self._glb is not None and hasattr(self._glb, 'allacts'):
                oldactname = self._glb.allacts.getCurrentName() if hasattr(self._glb.allacts, 'getCurrentName') else None
                try:
                    if hasattr(self._glb.allacts, 'setCurrent'):
                        self._glb.allacts.setCurrent('jumptable')
                    if hasattr(self, '_jtcallback') and self._jtcallback is not None:
                        self._jtcallback(self, partial)
                    else:
                        cur = self._glb.allacts.getCurrent() if hasattr(self._glb.allacts, 'getCurrent') else None
                        if cur is not None:
                            cur.reset(partial)
                            cur.perform(partial)
                    if oldactname is not None and hasattr(self._glb.allacts, 'setCurrent'):
                        self._glb.allacts.setCurrent(oldactname)
                except Exception as err:
                    if oldactname is not None and hasattr(self._glb.allacts, 'setCurrent'):
                        self._glb.allacts.setCurrent(oldactname)
                    self.warning(str(err), op.getAddr())
                    return 'fail_normal'

        partop = partial.findOp(op.getSeqNum()) if hasattr(partial, 'findOp') else None

        if partop is None or partop.code() != OpCode.CPUI_BRANCHIND or partop.getAddr() != op.getAddr():
            from ghidra.core.error import LowlevelError
            raise LowlevelError("Error recovering jumptable: Bad partial clone")
        if partop.isDead():
            return 'success'

        # Test if the branch target is copied from the return address
        if self.testForReturnAddress(partop.getIn(0)):
            return 'fail_return'

        try:
            if flow is not None and hasattr(jt, 'setLoadCollect'):
                jt.setLoadCollect(flow.doesJumpRecord())
            if hasattr(jt, 'setIndirectOp'):
                jt.setIndirectOp(partop)
            if hasattr(jt, 'isPartial') and jt.isPartial():
                if hasattr(jt, 'recoverMultistage'):
                    jt.recoverMultistage(partial)
            else:
                if hasattr(jt, 'recoverAddresses'):
                    jt.recoverAddresses(partial)
        except Exception as err:
            err_str = str(err)
            if 'thunk' in err_str.lower():
                return 'fail_thunk'
            self.warning(err_str, op.getAddr())
            return 'fail_normal'
        return 'success'

    # --- Block routines ---

    def getBasicBlockCount(self) -> int:
        return self._bblocks.getSize()

    def getBlock(self, i: int):
        return self._bblocks.getBlock(i)

    def opInsertBegin(self, op: PcodeOp, bl: BlockBasic) -> None:
        """Insert op at the beginning of a basic block.

        C++ ref: ``Funcdata::opInsertBegin``
        """
        bl.insertOp(op, 0)
        self.opMarkAlive(op)

    def opInsertEnd(self, op: PcodeOp, bl: BlockBasic) -> None:
        """Insert op at the end of a basic block.

        C++ ref: ``Funcdata::opInsertEnd``
        """
        bl.addOp(op)
        self.opMarkAlive(op)

    def opInsertAfter(self, op: PcodeOp, prev: PcodeOp) -> None:
        """Insert op after a specific PcodeOp in its basic block.

        C++ ref: ``Funcdata::opInsertAfter``
        """
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
        """Insert op before a specific PcodeOp in its basic block.

        If the op being inserted is NOT an INDIRECT, walk backwards past
        any preceding INDIRECT ops so that non-INDIRECT ops are placed
        before the INDIRECT cluster.  This matches C++ semantics where
        INDIRECTs must remain immediately before their associated CALL.

        C++ ref: ``Funcdata::opInsertBefore``
        """
        from ghidra.core.opcodes import OpCode
        bl = follow.getParent()
        if bl is not None:
            ops = bl.getOpList()
            try:
                idx = ops.index(follow)
                if op.code() != OpCode.CPUI_INDIRECT:
                    while idx > 0 and ops[idx - 1].code() == OpCode.CPUI_INDIRECT:
                        idx -= 1
                bl.insertOp(op, idx)
            except ValueError:
                bl.addOp(op)
        self.opMarkAlive(op)

    # --- Warning / comment ---

    def warning(self, txt: str, ad: Address) -> None:
        """Add a warning comment in the function body.

        C++ ref: ``Funcdata::warning``
        """
        if (self._flags & Funcdata.jumptablerecovery_on) != 0:
            msg = "WARNING (jumptable): "
        else:
            msg = "WARNING: "
        msg += txt
        if self._glb is not None and hasattr(self._glb, 'commentdb') and self._glb.commentdb is not None:
            self._glb.commentdb.addCommentNoDuplicate(0x4, self._baseaddr, ad, msg)
        elif self._glb is not None and hasattr(self._glb, 'printMessage'):
            self._glb.printMessage(msg)

    def warningHeader(self, txt: str) -> None:
        """Add a warning comment in the function header.

        C++ ref: ``Funcdata::warningHeader``
        """
        if (self._flags & Funcdata.jumptablerecovery_on) != 0:
            msg = "WARNING (jumptable): "
        else:
            msg = "WARNING: "
        msg += txt
        if self._glb is not None and hasattr(self._glb, 'commentdb') and self._glb.commentdb is not None:
            self._glb.commentdb.addCommentNoDuplicate(0x8, self._baseaddr, self._baseaddr, msg)
        elif self._glb is not None and hasattr(self._glb, 'printMessage'):
            self._glb.printMessage(msg)

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
        """Generate a truncated set of p-code from an existing flow.

        C++ ref: ``Funcdata::truncatedFlow``
        """
        # Truncated flow re-uses an existing FlowInfo to generate ops/blocks
        # for a subset of the function body. Minimal implementation.
        if flow is not None and hasattr(flow, 'generateOps'):
            flow.generateOps()
        if flow is not None and hasattr(flow, 'generateBlocks'):
            flow.generateBlocks()

    def inlineFlow(self, inlinefd, flow, callop) -> int:
        """In-line the p-code of another function into \b this function.

        Raw p-code is generated for the in-lined function, then control-flow
        information is cloned into the current FlowInfo object. This method
        supports two in-lining models:
          - The EZ model: the in-lined function is a single basic-block
            with no calls or branches. P-code is cloned and simply replaces
            the CALL op.
          - The hard model: the in-lined function has real control-flow.
            The CALL op is converted to a BRANCH to the in-lined body, and
            the in-lined RETURN ops become branches back to the call site
            fall-through.

        C++ ref: ``Funcdata::inlineFlow``

        Args:
            inlinefd: Funcdata of the function being in-lined.
            flow: FlowInfo object for the current function.
            callop: The CALL PcodeOp being replaced.

        Returns:
            0 for EZ model success, 1 for hard model success, -1 on failure.
        """
        from ghidra.analysis.flow import FlowInfo

        if inlinefd.getArch() is not None and hasattr(inlinefd.getArch(), 'clearAnalysis'):
            inlinefd.getArch().clearAnalysis(inlinefd)

        inlineflow = FlowInfo(inlinefd, inlinefd._obank, inlinefd._bblocks, inlinefd._qlst)
        inlinefd._obank.setUniqId(self._obank.getUniqId())

        # Generate the pcode ops to be inlined
        baddr = Address(self._baseaddr.getSpace(), 0)
        eaddr = Address(self._baseaddr.getSpace(), 0xFFFFFFFFFFFFFFFF)
        inlineflow.setRange(baddr, eaddr)
        inlineflow.setFlags(FlowInfo.error_outofbounds | FlowInfo.error_unimplemented |
                            FlowInfo.error_reinterpreted | FlowInfo.flow_forinline)
        inlineflow.forwardRecursion(flow)
        inlineflow.generateOps()

        if inlineflow.checkEZModel():
            res = 0
            # With an EZ clone there are no jumptables to clone
            deadlist = list(self._obank.getDeadList()) if hasattr(self._obank, 'getDeadList') else []
            lastidx = len(deadlist) - 1  # There is at least one op

            flow.inlineEZClone(inlineflow, callop.getAddr())

            newdeadlist = list(self._obank.getDeadList()) if hasattr(self._obank, 'getDeadList') else []
            # Find ops that were added after the EZ clone
            newops = newdeadlist[lastidx + 1:] if lastidx + 1 < len(newdeadlist) else []

            if newops:
                firstop = newops[0]
                lastop = newops[-1]
                self._obank.moveSequenceDead(firstop, lastop, callop)
                if callop.isBlockStart():
                    firstop.setFlag(PcodeOp.startbasic)
                    flow.updateTarget(callop, firstop)
                else:
                    firstop.clearFlag(PcodeOp.startbasic)
            self.opDestroyRaw(callop)
        else:
            retaddr_ref = [Address()]
            if not flow.testHardInlineRestrictions(inlinefd, callop, retaddr_ref):
                return -1
            retaddr = retaddr_ref[0]
            res = 1
            # Clone any jumptables from inline piece
            for jt_orig in inlinefd._jumpvec:
                from ghidra.analysis.jumptable import JumpTable
                jtclone = JumpTable(jt_orig)
                self._jumpvec.append(jtclone)

            flow.inlineClone(inlineflow, retaddr)

            # Convert CALL op to a jump
            while callop.numInput() > 1:
                self.opRemoveInput(callop, callop.numInput() - 1)

            self.opSetOpcode(callop, OpCode.CPUI_BRANCH)
            inlineaddr = self.newCodeRef(inlinefd.getAddress())
            self.opSetInput(callop, inlineaddr, 0)

        self._obank.setUniqId(inlinefd._obank.getUniqId())

        return res

    def overrideFlow(self, addr, flowtype: int) -> None:
        """Override the control-flow p-code for a particular instruction.

        P-code in this function is modified to change the control-flow of
        the instruction at the given address, based on the Override type.

        C++ ref: ``Funcdata::overrideFlow``
        """
        # Override type constants (from override.hh)
        OVERRIDE_NONE = 0
        OVERRIDE_BRANCH = 1
        OVERRIDE_CALL = 2
        OVERRIDE_CALL_RETURN = 3
        OVERRIDE_RETURN = 4

        # Get iterator range for ops at this address
        ops_at_addr = []
        if hasattr(self._obank, 'beginDead'):
            for op in self._obank.beginDead():
                if op.getAddr() == addr:
                    ops_at_addr.append(op)

        op = None
        if flowtype == OVERRIDE_BRANCH:
            op = self.findPrimaryBranch(ops_at_addr, False, True, True)
        elif flowtype == OVERRIDE_CALL:
            op = self.findPrimaryBranch(ops_at_addr, True, False, True)
        elif flowtype == OVERRIDE_CALL_RETURN:
            op = self.findPrimaryBranch(ops_at_addr, True, True, True)
        elif flowtype == OVERRIDE_RETURN:
            op = self.findPrimaryBranch(ops_at_addr, True, True, False)

        if op is None or not op.isDead():
            from ghidra.core.error import LowlevelError
            raise LowlevelError("Could not apply flowoverride")

        opc = op.code()
        if flowtype == OVERRIDE_BRANCH:
            if opc == OpCode.CPUI_CALL:
                self.opSetOpcode(op, OpCode.CPUI_BRANCH)
            elif opc == OpCode.CPUI_CALLIND:
                self.opSetOpcode(op, OpCode.CPUI_BRANCHIND)
            elif opc == OpCode.CPUI_RETURN:
                self.opSetOpcode(op, OpCode.CPUI_BRANCHIND)
        elif flowtype in (OVERRIDE_CALL, OVERRIDE_CALL_RETURN):
            if opc == OpCode.CPUI_BRANCH:
                self.opSetOpcode(op, OpCode.CPUI_CALL)
            elif opc == OpCode.CPUI_BRANCHIND:
                self.opSetOpcode(op, OpCode.CPUI_CALLIND)
            elif opc == OpCode.CPUI_CBRANCH:
                from ghidra.core.error import LowlevelError
                raise LowlevelError("Do not currently support CBRANCH overrides")
            elif opc == OpCode.CPUI_RETURN:
                self.opSetOpcode(op, OpCode.CPUI_CALLIND)
            if flowtype == OVERRIDE_CALL_RETURN:
                # Insert a new return op after call
                newReturn = self.newOp(1, addr)
                self.opSetOpcode(newReturn, OpCode.CPUI_RETURN)
                self.opSetInput(newReturn, self.newConstant(1, 0), 0)
                self.opDeadInsertAfter(newReturn, op)
        elif flowtype == OVERRIDE_RETURN:
            if opc in (OpCode.CPUI_BRANCH, OpCode.CPUI_CBRANCH, OpCode.CPUI_CALL):
                from ghidra.core.error import LowlevelError
                raise LowlevelError("Do not currently support complex overrides")
            elif opc == OpCode.CPUI_BRANCHIND:
                self.opSetOpcode(op, OpCode.CPUI_RETURN)
            elif opc == OpCode.CPUI_CALLIND:
                self.opSetOpcode(op, OpCode.CPUI_RETURN)

    def doLiveInject(self, payload, addr, bl, pos) -> None:
        """Inject p-code from a payload into a live basic block.

        Raw PcodeOps are generated from the payload into the dead list,
        then each injected op is moved into the basic block at the given
        insertion point.  Branching injections are illegal and raise an error.

        C++ ref: ``Funcdata::doLiveInject``
        """
        if payload is None or self._glb is None:
            return
        if not hasattr(self._glb, 'pcodeinjectlib'):
            return
        injectlib = self._glb.pcodeinjectlib
        if injectlib is None:
            return

        # Set up emitter and context
        try:
            from ghidra.sleigh.pcodeemit import PcodeEmitFd
        except ImportError:
            return
        emitter = PcodeEmitFd()
        emitter.setFuncdata(self)

        context = None
        if hasattr(injectlib, 'getCachedContext'):
            context = injectlib.getCachedContext()
            if hasattr(context, 'clear'):
                context.clear()
            context.baseaddr = addr
            context.nextaddr = addr

        # Snapshot dead list boundary
        dead_before = list(self._obank.getDeadList()) if hasattr(self._obank, 'getDeadList') else []

        if hasattr(payload, 'inject') and context is not None:
            payload.inject(context, emitter)

        # Collect newly injected ops (appeared in dead list after inject)
        dead_after = list(self._obank.getDeadList()) if hasattr(self._obank, 'getDeadList') else []
        before_set = set(id(o) for o in dead_before)
        injected = [o for o in dead_after if id(o) not in before_set]

        # Insert each injected op into the basic block
        for op in injected:
            if hasattr(op, 'isCallOrBranch') and op.isCallOrBranch():
                from ghidra.core.error import LowlevelError
                raise LowlevelError("Illegal branching injection")
            self.opInsert(op, bl, pos)

    # --- Clone / Indirect ---

    def cloneOp(self, op, seq):
        """Clone a PcodeOp, copying control-flow properties.

        The data-type is not cloned.

        C++ ref: ``Funcdata::cloneOp``
        """
        newop = self._obank.create(op.numInput(), seq)
        self.opSetOpcode(newop, op.code())
        fl = op.flags & (PcodeOp.startmark | PcodeOp.startbasic)
        if fl != 0:
            newop.setFlag(fl)
        if op.getOut() is not None:
            self.opSetOutput(newop, self.cloneVarnode(op.getOut()))
        for i in range(op.numInput()):
            invn = op.getIn(i)
            if invn is not None:
                self.opSetInput(newop, self.cloneVarnode(invn), i)
        return newop

    def newIndirectOp(self, indeffect, addr, sz: int, extraFlags: int = 0):
        """Create a new CPUI_INDIRECT around a PcodeOp with an indirect effect.

        An output Varnode is automatically created.

        C++ ref: ``Funcdata::newIndirectOp``
        """
        from ghidra.core.opcodes import OpCode
        newin = self.newVarnode(sz, addr)
        newop = self.newOp(2, indeffect.getAddr())
        if extraFlags:
            newop.setFlag(extraFlags)
        self.newVarnodeOut(sz, addr, newop)
        self.opSetOpcode(newop, OpCode.CPUI_INDIRECT)
        self.opSetInput(newop, newin, 0)
        self.opSetInput(newop, self.newVarnodeIop(indeffect), 1)
        self.opInsertBefore(newop, indeffect)
        return newop

    def newIndirectCreation(self, indeffect, addr, sz: int, possibleout: bool):
        """Build a CPUI_INDIRECT op that indirectly creates a Varnode.

        An indirectly created Varnode has no data-flow before the INDIRECT.

        C++ ref: ``Funcdata::newIndirectCreation``
        """
        from ghidra.core.opcodes import OpCode
        newin = self.newConstant(sz, 0)
        newop = self.newOp(2, indeffect.getAddr())
        newop.setFlag(PcodeOp.indirect_creation)
        newout = self.newVarnodeOut(sz, addr, newop)
        if not possibleout:
            newin.setFlags(Varnode.indirect_creation)
        newout.setFlags(Varnode.indirect_creation)
        self.opSetOpcode(newop, OpCode.CPUI_INDIRECT)
        self.opSetInput(newop, newin, 0)
        self.opSetInput(newop, self.newVarnodeIop(indeffect), 1)
        self.opInsertBefore(newop, indeffect)
        return newop

    def markIndirectCreation(self, indop, possibleOutput: bool) -> None:
        """Mark an existing CPUI_INDIRECT as an indirect creation.

        C++ ref: ``Funcdata::markIndirectCreation``
        """
        outvn = indop.getOut()
        in0 = indop.getIn(0)
        indop.flags |= PcodeOp.indirect_creation
        if in0 is not None and not in0.isConstant():
            raise Exception("Indirect creation not properly formed")
        if not possibleOutput and in0 is not None:
            in0.flags |= Varnode.indirect_creation
        if outvn is not None:
            outvn.flags |= Varnode.indirect_creation

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
        """Remove a PcodeOp and recursively remove ops producing its inputs.

        PcodeOps are iteratively removed if the only data-flow path of
        their output is to the given op, and they are not a CALL or
        otherwise special.

        C++ ref: ``Funcdata::opDestroyRecursive``
        """
        if scratch is None:
            scratch = []
        scratch.clear()
        scratch.append(op)
        pos = 0
        while pos < len(scratch):
            curop = scratch[pos]
            pos += 1
            for i in range(curop.numInput()):
                vn = curop.getIn(i)
                if vn is None:
                    continue
                if not vn.isWritten():
                    continue
                if hasattr(vn, 'isAutoLive') and vn.isAutoLive():
                    continue
                if not hasattr(vn, 'loneDescend') or vn.loneDescend() is None:
                    continue
                defOp = vn.getDef()
                if defOp is None:
                    continue
                if defOp.isCall():
                    continue
                if hasattr(defOp, 'isIndirectSource') and defOp.isIndirectSource():
                    continue
                scratch.append(defOp)
            self.opDestroy(curop)

    # --- Varnode search / link ---

    def findLinkedVarnode(self, entry):
        """Return the first Varnode matching the given SymbolEntry.

        For dynamic entries, uses DynamicHash. For non-dynamic entries,
        iterates Varnodes at the entry's location, checking usepoint.

        C++ ref: ``Funcdata::findLinkedVarnode``
        """
        if entry is None:
            return None
        if hasattr(entry, 'isDynamic') and entry.isDynamic():
            try:
                from ghidra.analysis.dynamic import DynamicHash
                dhash = DynamicHash()
                vn = dhash.findVarnode(self, entry.getFirstUseAddress(), entry.getHash())
                if vn is not None and not vn.isAnnotation():
                    return vn
            except (ImportError, Exception):
                pass
            return None
        addr = entry.getAddr() if hasattr(entry, 'getAddr') else None
        sz = entry.getSize() if hasattr(entry, 'getSize') else 0
        if addr is None or sz == 0:
            return None
        usestart = entry.getFirstUseAddress() if hasattr(entry, 'getFirstUseAddress') else None
        if usestart is None or (hasattr(usestart, 'isInvalid') and usestart.isInvalid()):
            # No usepoint constraint — find first address-tied varnode at loc
            for vn in self._vbank.beginLoc():
                if vn.getAddr() == addr and vn.getSize() == sz:
                    if not (hasattr(vn, 'isAddrTied') and not vn.isAddrTied()):
                        return vn
            return None
        # With usepoint constraint — check inUse
        for vn in self._vbank.beginLoc():
            if vn.getAddr() == addr and vn.getSize() == sz:
                usepoint = vn.getUsePoint(self) if hasattr(vn, 'getUsePoint') else None
                if usepoint is not None and hasattr(entry, 'inUse') and entry.inUse(usepoint):
                    return vn
        return None

    def findLinkedVarnodes(self, entry, res: list) -> None:
        """Find Varnodes that map to the given SymbolEntry.

        For dynamic entries, uses DynamicHash. For non-dynamic entries,
        iterates Varnodes at the entry's location, checking usepoint.

        C++ ref: ``Funcdata::findLinkedVarnodes``
        """
        if entry is None:
            return
        if hasattr(entry, 'isDynamic') and entry.isDynamic():
            try:
                from ghidra.analysis.dynamic import DynamicHash
                dhash = DynamicHash()
                vn = dhash.findVarnode(self, entry.getFirstUseAddress(), entry.getHash())
                if vn is not None:
                    res.append(vn)
            except (ImportError, Exception):
                pass
            return
        addr = entry.getAddr() if hasattr(entry, 'getAddr') else None
        sz = entry.getSize() if hasattr(entry, 'getSize') else 0
        if addr is None or sz == 0:
            return
        for vn in self._vbank.beginLoc():
            if vn.getAddr() == addr and vn.getSize() == sz:
                usepoint = vn.getUsePoint(self) if hasattr(vn, 'getUsePoint') else None
                if usepoint is not None and hasattr(entry, 'inUse') and entry.inUse(usepoint):
                    res.append(vn)
                elif not hasattr(entry, 'inUse'):
                    res.append(vn)

    def linkSymbol(self, vn):
        """Find or create a Symbol associated with the given Varnode.

        If the Varnode is a proto-partial, delegate to linkProtoPartial first.
        Then check for an existing Symbol on the HighVariable. If none, query
        the local scope for an overlapping entry and either handle a conflict
        or create a new local symbol.

        C++ ref: ``Funcdata::linkSymbol``
        """
        if vn is None:
            return None
        if hasattr(vn, 'isProtoPartial') and vn.isProtoPartial():
            self.linkProtoPartial(vn)
        high = vn.getHigh() if hasattr(vn, 'getHigh') else None
        if high is not None and hasattr(high, 'getSymbol'):
            sym = high.getSymbol()
            if sym is not None:
                return sym
        if self._localmap is None:
            return None
        fl = 0
        usepoint = vn.getUsePoint(self) if hasattr(vn, 'getUsePoint') else Address()
        entry = None
        if hasattr(self._localmap, 'queryProperties'):
            entry = self._localmap.queryProperties(vn.getAddr(), 1, usepoint, fl)
        if entry is not None:
            sym = self.handleSymbolConflict(entry, vn)
        else:
            # Must create a symbol entry
            if not vn.isPersist():
                if hasattr(vn, 'isAddrTied') and vn.isAddrTied():
                    usepoint = Address()
                ct = high.getType() if high is not None and hasattr(high, 'getType') else None
                if hasattr(self._localmap, 'addSymbol'):
                    entry = self._localmap.addSymbol("", ct, vn.getAddr(), usepoint)
                    if entry is not None:
                        sym = entry.getSymbol() if hasattr(entry, 'getSymbol') else None
                        if hasattr(vn, 'setSymbolEntry'):
                            vn.setSymbolEntry(entry)
                    else:
                        sym = None
                else:
                    sym = None
            else:
                sym = None
        return sym

    def linkSymbolReference(self, vn):
        """Recover the Symbol referred to by a constant Varnode in a PTRSUB op.

        A reference to a symbol (&varname) is typically stored as a PTRSUB
        where the first input is a spacebase Varnode and the second is a
        constant encoding the symbol's address.

        C++ ref: ``Funcdata::linkSymbolReference``
        """
        if vn is None:
            return None
        op = vn.loneDescend() if hasattr(vn, 'loneDescend') else None
        if op is None:
            return None
        in0 = op.getIn(0)
        if in0 is None:
            return None
        high0 = in0.getHigh() if hasattr(in0, 'getHigh') else None
        if high0 is None:
            return None
        ptype = high0.getType() if hasattr(high0, 'getType') else None
        if ptype is None or not hasattr(ptype, 'getMetatype'):
            return None
        TYPE_PTR = 7  # Ghidra metatype constant
        TYPE_SPACEBASE = 12
        if ptype.getMetatype() != TYPE_PTR:
            return None
        sb = ptype.getPtrTo() if hasattr(ptype, 'getPtrTo') else None
        if sb is None or not hasattr(sb, 'getMetatype') or sb.getMetatype() != TYPE_SPACEBASE:
            return None
        scope = sb.getMap() if hasattr(sb, 'getMap') else None
        if scope is None:
            return None
        addr = sb.getAddress(vn.getOffset(), in0.getSize(), op.getAddr()) if hasattr(sb, 'getAddress') else None
        if addr is None or (hasattr(addr, 'isInvalid') and addr.isInvalid()):
            return None
        entry = scope.queryContainer(addr, 1, Address()) if hasattr(scope, 'queryContainer') else None
        if entry is None:
            return None
        off = int(addr.getOffset() - entry.getAddr().getOffset())
        if hasattr(entry, 'getOffset'):
            off += entry.getOffset()
        if hasattr(vn, 'setSymbolReference'):
            vn.setSymbolReference(entry, off)
        return entry.getSymbol() if hasattr(entry, 'getSymbol') else None

    def linkProtoPartial(self, vn) -> None:
        """Link a proto-partial Varnode to its whole Symbol.

        PIECE operations put the given Varnode into a larger structure.  Find
        the resulting whole Varnode, make sure it has a symbol assigned, and
        then assign the same symbol to the given Varnode piece.

        C++ ref: ``Funcdata::linkProtoPartial``
        """
        if vn is None or self._localmap is None:
            return
        high = vn.getHigh() if hasattr(vn, 'getHigh') else None
        if high is None:
            return
        if hasattr(high, 'getSymbol') and high.getSymbol() is not None:
            return  # Already linked
        # Try to find the root varnode via PieceNode.findRoot
        try:
            from ghidra.analysis.prefersplit import PieceNode
            rootVn = PieceNode.findRoot(vn)
        except (ImportError, AttributeError):
            rootVn = vn
        if rootVn is vn:
            return
        rootHigh = rootVn.getHigh() if hasattr(rootVn, 'getHigh') else None
        if rootHigh is None:
            return
        if hasattr(rootHigh, 'isSameGroup') and not rootHigh.isSameGroup(high):
            return
        nameRep = rootHigh.getNameRepresentative() if hasattr(rootHigh, 'getNameRepresentative') else rootVn
        sym = self.linkSymbol(nameRep)
        if sym is None:
            return
        if hasattr(rootHigh, 'establishGroupSymbolOffset'):
            rootHigh.establishGroupSymbolOffset()
        entry = sym.getFirstWholeMap() if hasattr(sym, 'getFirstWholeMap') else None
        if entry is not None and hasattr(vn, 'setSymbolEntry'):
            vn.setSymbolEntry(entry)

    def buildDynamicSymbol(self, vn) -> None:
        """Build a dynamic Symbol associated with the given Varnode.

        If a Symbol is already attached, no change is made. Otherwise a special
        dynamic Symbol is created that is associated with the Varnode via a hash
        of its local data-flow.

        C++ ref: ``Funcdata::buildDynamicSymbol``
        """
        if vn is None or self._localmap is None:
            return
        # C++ throws for locked varnodes; we silently skip
        if hasattr(vn, 'isTypeLock') and vn.isTypeLock():
            return
        if hasattr(vn, 'isNameLock') and vn.isNameLock():
            return
        # Check for existing symbol via HighVariable
        high = vn.getHigh() if hasattr(vn, 'getHigh') else None
        if high is not None and hasattr(high, 'getSymbol') and high.getSymbol() is not None:
            return  # Symbol already exists
        try:
            from ghidra.analysis.dynamic import DynamicHash
            dhash = DynamicHash()
            dhash.uniqueHash(vn, self)
            if dhash.getHash() == 0:
                return
            if vn.isConstant():
                if hasattr(self._localmap, 'addEquateSymbol'):
                    sym = self._localmap.addEquateSymbol("", 0x20, vn.getOffset(),
                                                         dhash.getAddress(), dhash.getHash())
                else:
                    return
            else:
                vntype = high.getType() if high is not None and hasattr(high, 'getType') else None
                if hasattr(self._localmap, 'addDynamicSymbol'):
                    sym = self._localmap.addDynamicSymbol("", vntype, dhash.getAddress(), dhash.getHash())
                else:
                    return
            if sym is not None and hasattr(sym, 'getFirstWholeMap'):
                entry = sym.getFirstWholeMap()
                if entry is not None and hasattr(vn, 'setSymbolEntry'):
                    vn.setSymbolEntry(entry)
        except (ImportError, Exception):
            # DynamicHash may not be available yet; fallback to simple addDynamicSymbol
            if hasattr(self._localmap, 'addDynamicSymbol'):
                self._localmap.addDynamicSymbol(vn)

    def combineInputVarnodes(self, vnHi, vnLo) -> None:
        """Combine two contiguous input Varnodes into one.

        Find all PIECE ops that directly combine vnHi and vnLo, convert them
        to COPYs of the new combined input. For other uses of vnHi/vnLo,
        create SUBPIECE ops to extract the original pieces.

        C++ ref: ``Funcdata::combineInputVarnodes``
        """
        if vnHi is None or vnLo is None:
            return
        if not vnHi.isInput() or not vnLo.isInput():
            return
        # Determine combined address based on endianness
        addr = vnLo.getAddr()
        isBigEndian = hasattr(addr, 'isBigEndian') and addr.isBigEndian()
        if isBigEndian:
            addr = vnHi.getAddr()

        # Find PIECE ops that directly combine hi and lo
        pieceList = []
        otherOpsHi = False
        otherOpsLo = False
        for op in list(vnHi.getDescendants()):
            if op.code() == OpCode.CPUI_PIECE and op.getIn(0) is vnHi and op.getIn(1) is vnLo:
                pieceList.append(op)
            else:
                otherOpsHi = True
        for op in list(vnLo.getDescendants()):
            if op.code() != OpCode.CPUI_PIECE or op.getIn(0) is not vnHi or op.getIn(1) is not vnLo:
                otherOpsLo = True

        # Remove the lo input from PIECE ops and unset hi input
        for pieceOp in pieceList:
            if hasattr(self, 'opRemoveInput'):
                self.opRemoveInput(pieceOp, 1)
            self.opUnsetInput(pieceOp, 0)

        # Create SUBPIECE replacements for non-PIECE uses
        subHi = None
        subLo = None
        bb = self._bblocks.getBlock(0) if self._bblocks.getSize() > 0 else None
        if otherOpsHi and bb is not None:
            subHi = self.newOp(2, bb.getStart())
            self.opSetOpcode(subHi, OpCode.CPUI_SUBPIECE)
            self.opSetInput(subHi, self.newConstant(4, vnLo.getSize()), 1)
            newHi = self.newVarnodeOut(vnHi.getSize(), vnHi.getAddr(), subHi)
            self.opInsertBegin(subHi, bb)
            self.totalReplace(vnHi, newHi)
        if otherOpsLo and bb is not None:
            subLo = self.newOp(2, bb.getStart())
            self.opSetOpcode(subLo, OpCode.CPUI_SUBPIECE)
            self.opSetInput(subLo, self.newConstant(4, 0), 1)
            newLo = self.newVarnodeOut(vnLo.getSize(), vnLo.getAddr(), subLo)
            self.opInsertBegin(subLo, bb)
            self.totalReplace(vnLo, newLo)

        # Destroy old inputs and create the combined input
        outSize = vnHi.getSize() + vnLo.getSize()
        self._vbank.destroy(vnHi)
        self._vbank.destroy(vnLo)
        inVn = self.newVarnode(outSize, addr)
        inVn = self.setInputVarnode(inVn)

        # Wire up PIECE ops as COPYs of the combined input
        for pieceOp in pieceList:
            self.opSetInput(pieceOp, inVn, 0)
            self.opSetOpcode(pieceOp, OpCode.CPUI_COPY)
        if subHi is not None:
            self.opSetInput(subHi, inVn, 0)
        if subLo is not None:
            self.opSetInput(subLo, inVn, 0)

    def findSpacebaseInput(self, spc):
        """Try to locate the unique input Varnode holding the base register for the given space.

        C++ ref: ``Funcdata::findSpacebaseInput``
        """
        if spc is None or not hasattr(spc, 'numSpacebase'):
            return None
        if spc.numSpacebase() == 0:
            return None
        base = spc.getSpacebase(0)
        addr = base.getAddr() if hasattr(base, 'getAddr') else Address(base.space, base.offset)
        if hasattr(self._vbank, 'findInput'):
            return self._vbank.findInput(base.size, addr)
        # Fallback: scan
        for vn in self._vbank.beginLoc():
            if vn.isInput() and vn.getAddr() == addr and vn.getSize() == base.size:
                return vn
        return None

    def constructSpacebaseInput(self, spc):
        """If it doesn't exist, create an input Varnode of the base register for the given space.

        If an input varnode for the spacebase already exists, return it.
        Otherwise create a new one, mark it as spacebase, and assign the
        TypeSpacebase pointer type.

        C++ ref: ``Funcdata::constructSpacebaseInput``
        """
        from ghidra.ir.varnode import Varnode as VnCls
        spacePtr = self.findSpacebaseInput(spc)
        if spacePtr is not None:
            return spacePtr
        if spc is None or not hasattr(spc, 'numSpacebase') or spc.numSpacebase() == 0:
            raise Exception("Unable to construct pointer into space: " + (spc.getName() if spc else "<null>"))
        base = spc.getSpacebase(0)
        addr = base.getAddr() if hasattr(base, 'getAddr') else Address(base.space, base.offset)
        # Build pointer type
        ptr = None
        if self._glb is not None and hasattr(self._glb, 'types') and self._glb.types is not None:
            ct = self._glb.types.getTypeSpacebase(spc, self.getAddress()) if hasattr(self._glb.types, 'getTypeSpacebase') else None
            if ct is not None and hasattr(self._glb.types, 'getTypePointer'):
                wordSize = spc.getWordSize() if hasattr(spc, 'getWordSize') else 1
                ptr = self._glb.types.getTypePointer(base.size, ct, wordSize)
        spacePtr = self.newVarnode(base.size, addr, ptr)
        spacePtr = self.setInputVarnode(spacePtr)
        spacePtr.setFlags(VnCls.spacebase)
        if ptr is not None:
            spacePtr.updateType(ptr, True, True)
        return spacePtr

    def newSpacebasePtr(self, spc):
        """Construct a new (non-input) spacebase Varnode for a given address space.

        C++ ref: ``Funcdata::newSpacebasePtr``
        """
        if spc is None or not hasattr(spc, 'numSpacebase') or spc.numSpacebase() == 0:
            raise Exception("Unable to construct pointer into space")
        base = spc.getSpacebase(0)
        addr = base.getAddr() if hasattr(base, 'getAddr') else Address(base.space, base.offset)
        return self.newVarnode(base.size, addr)

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

    def encodeVarnode(self, encoder, iter_vns) -> None:
        """Encode a set of Varnodes to stream.

        C++ ref: ``Funcdata::encodeVarnode``
        """
        for vn in iter_vns:
            vn.encode(encoder)

    def encode(self, encoder, uid: int = 0, savetree: bool = True) -> None:
        """Encode a description of this function to stream.

        C++ ref: ``Funcdata::encode``
        """
        from ghidra.core.marshal import (
            ELEM_FUNCTION, ATTRIB_ID, ATTRIB_NAME, ATTRIB_SIZE, ATTRIB_NOCODE,
        )
        encoder.openElement(ELEM_FUNCTION)
        if uid != 0:
            encoder.writeUnsignedInteger(ATTRIB_ID, uid)
        encoder.writeString(ATTRIB_NAME, self.name)
        encoder.writeSignedInteger(ATTRIB_SIZE, self.size)
        if self.hasNoCode():
            encoder.writeBool(ATTRIB_NOCODE, True)
        self.baseaddr.encode(encoder)

        if not self.hasNoCode():
            if self._localmap is not None and hasattr(self._localmap, 'encodeRecursive'):
                self._localmap.encodeRecursive(encoder, False)

        if savetree:
            self.encodeTree(encoder)
            self.encodeHigh(encoder)
        self.encodeJumpTable(encoder)
        self.funcp.encode(encoder)
        if hasattr(self, '_localoverride') and self._localoverride is not None:
            self._localoverride.encode(encoder, self._glb)
        encoder.closeElement(ELEM_FUNCTION)

    def decode(self, decoder) -> int:
        """Restore the state of this function from a stream.

        C++ ref: ``Funcdata::decode``
        """
        from ghidra.core.marshal import (
            ELEM_FUNCTION, ELEM_LOCALDB, ELEM_OVERRIDE, ELEM_PROTOTYPE,
            ELEM_JUMPTABLELIST, ATTRIB_NAME, ATTRIB_SIZE, ATTRIB_ID,
            ATTRIB_NOCODE, ATTRIB_LABEL,
        )
        self._name = ""
        self._size = -1
        uid = 0
        elemId = decoder.openElement(ELEM_FUNCTION)
        for _ in range(100):
            attribId = decoder.getNextAttributeId()
            if attribId == 0:
                break
            if attribId == ATTRIB_NAME.id:
                self._name = decoder.readString()
            elif attribId == ATTRIB_SIZE.id:
                self._size = decoder.readSignedInteger()
            elif attribId == ATTRIB_ID.id:
                uid = decoder.readUnsignedInteger()
            elif attribId == ATTRIB_NOCODE.id:
                if decoder.readBool():
                    self._flags |= Funcdata.no_code
            elif attribId == ATTRIB_LABEL.id:
                self._displayName = decoder.readString()
        if not self._name:
            raise RuntimeError("Missing function name")
        if not self._displayName:
            self._displayName = self._name
        if self._size == -1:
            raise RuntimeError("Missing function size")
        # Decode base address
        if hasattr(Address, 'decode'):
            self._baseaddr = Address.decode(decoder)
        # Decode child elements
        while True:
            subId = decoder.peekElement()
            if subId == 0:
                break
            if subId == ELEM_LOCALDB.id:
                # Decode local scope
                if self._glb is not None and hasattr(self._glb, 'symboltab'):
                    self._glb.symboltab.decodeScope(decoder, None)
            elif subId == ELEM_OVERRIDE.id:
                if hasattr(self, '_localoverride') and self._localoverride is not None:
                    self._localoverride.decode(decoder, self._glb)
                else:
                    decoder.skipElement()
            elif subId == ELEM_PROTOTYPE.id:
                if self._localmap is not None:
                    self._funcp.setScope(self._localmap, Address(self._baseaddr.getSpace(),
                                                                 self._baseaddr.getOffset() - 1))
                self._funcp.decode(decoder, self._glb)
            elif subId == ELEM_JUMPTABLELIST.id:
                self.decodeJumpTable(decoder)
            else:
                decoder.skipElement()
        decoder.closeElement(elemId)
        return uid

    def encodeTree(self, encoder) -> None:
        """Encode the p-code tree (varnodes, ops, blocks, edges) to stream.

        C++ ref: ``Funcdata::encodeTree``
        """
        from ghidra.core.marshal import (
            ELEM_AST, ELEM_VARNODES, ELEM_BLOCK, ELEM_BLOCKEDGE,
            ATTRIB_INDEX,
        )
        from ghidra.core.space import IPTR_IOP
        encoder.openElement(ELEM_AST)

        # Encode all varnodes grouped by address space
        encoder.openElement(ELEM_VARNODES)
        for i in range(self._glb.numSpaces()):
            base = self._glb.getSpace(i)
            if base is None or base.getType() == IPTR_IOP:
                continue
            vns = self._vbank.beginLocSpace(base)
            self.encodeVarnode(encoder, vns)
        encoder.closeElement(ELEM_VARNODES)

        # Encode each basic block with its ops
        for i in range(self._bblocks.getSize()):
            bs = self._bblocks.getBlock(i)
            encoder.openElement(ELEM_BLOCK)
            encoder.writeSignedInteger(ATTRIB_INDEX, bs.getIndex())
            bs.encodeBody(encoder)
            for op in bs.getOpList():
                op.encode(encoder)
            encoder.closeElement(ELEM_BLOCK)

        # Encode edges for blocks that have incoming edges
        for i in range(self._bblocks.getSize()):
            bs = self._bblocks.getBlock(i)
            if bs.sizeIn() == 0:
                continue
            encoder.openElement(ELEM_BLOCKEDGE)
            encoder.writeSignedInteger(ATTRIB_INDEX, bs.getIndex())
            bs.encodeEdges(encoder)
            encoder.closeElement(ELEM_BLOCKEDGE)

        encoder.closeElement(ELEM_AST)

    def encodeHigh(self, encoder) -> None:
        """Encode all HighVariables to stream.

        C++ ref: ``Funcdata::encodeHigh``
        """
        from ghidra.core.marshal import ELEM_HIGHLIST
        if not self.isHighOn():
            return
        encoder.openElement(ELEM_HIGHLIST)
        seen = set()
        for vn in self._vbank.allVarnodes():
            if vn.isAnnotation():
                continue
            high = vn.getHigh()
            if high is None:
                continue
            hid = id(high)
            if hid in seen:
                continue
            seen.add(hid)
            high.encode(encoder)
        encoder.closeElement(ELEM_HIGHLIST)

    def encodeJumpTable(self, encoder) -> None:
        """Encode jump-tables to stream.

        C++ ref: ``Funcdata::encodeJumpTable``
        """
        from ghidra.core.marshal import ELEM_JUMPTABLELIST
        if not hasattr(self, '_jumpvec') or not self._jumpvec:
            return
        encoder.openElement(ELEM_JUMPTABLELIST)
        for jt in self._jumpvec:
            jt.encode(encoder)
        encoder.closeElement(ELEM_JUMPTABLELIST)

    def decodeJumpTable(self, decoder) -> None:
        """Decode jump-tables from a stream.

        C++ ref: ``Funcdata::decodeJumpTable``
        """
        from ghidra.core.marshal import ELEM_JUMPTABLELIST
        from ghidra.analysis.jumptable import JumpTable
        elemId = decoder.openElement(ELEM_JUMPTABLELIST)
        while decoder.peekElement() != 0:
            jt = JumpTable(self._glb)
            jt.decode(decoder)
            self._jumpvec.append(jt)
        decoder.closeElement(elemId)

    # --- Data-flow / transformation helpers ---

    def syncVarnodesWithSymbols(self, lm=None, updateDatatypes: bool = False,
                                 unmappedAliasCheck: bool = False) -> bool:
        """Synchronize Varnode properties with their Symbol overlaps.

        For every Varnode in the local scope's address space, find any
        overlapping SymbolEntry, update the Varnode's flags (mapped,
        addrtied, nolocalalias, etc.) and optionally its data-type.

        C++ ref: ``Funcdata::syncVarnodesWithSymbols``
        """
        if lm is None:
            lm = self._localmap
        if lm is None:
            return False
        updateoccurred = False
        spaceId = lm.getSpaceId() if hasattr(lm, 'getSpaceId') else None
        if spaceId is None:
            return False
        vnlist = list(self._vbank.beginLoc(spaceId)) if hasattr(self._vbank, 'beginLoc') else []
        i = 0
        while i < len(vnlist):
            vnexemplar = vnlist[i]
            # Collect all varnodes at same size/addr
            group = [vnexemplar]
            j = i + 1
            while j < len(vnlist) and vnlist[j].getSize() == vnexemplar.getSize() and vnlist[j].getAddr() == vnexemplar.getAddr():
                group.append(vnlist[j])
                j += 1
            entry = lm.findOverlap(vnexemplar.getAddr(), vnexemplar.getSize()) if hasattr(lm, 'findOverlap') else None
            ct = None
            if entry is not None:
                fl = entry.getAllFlags() if hasattr(entry, 'getAllFlags') else 0
                if hasattr(entry, 'getSize') and entry.getSize() >= vnexemplar.getSize():
                    if updateDatatypes and hasattr(entry, 'getSizedType'):
                        ct = entry.getSizedType(vnexemplar.getAddr(), vnexemplar.getSize())
                        if ct is not None and hasattr(ct, 'getMetatype') and ct.getMetatype() == 15:  # TYPE_UNKNOWN
                            ct = None
                else:
                    fl &= ~(Varnode.typelock | Varnode.namelock)
            else:
                if hasattr(lm, 'inScope') and lm.inScope(vnexemplar.getAddr(), vnexemplar.getSize(),
                        vnexemplar.getUsePoint(self) if hasattr(vnexemplar, 'getUsePoint') else Address()):
                    fl = Varnode.mapped | Varnode.addrtied
                elif unmappedAliasCheck and hasattr(lm, 'isUnmappedUnaliased'):
                    fl = Varnode.nolocalalias if lm.isUnmappedUnaliased(vnexemplar) else 0
                else:
                    fl = 0
            if self.syncVarnodesWithSymbol(group, fl, ct):
                updateoccurred = True
            i = j
        return updateoccurred

    def transferVarnodeProperties(self, vn, newVn, lsbOffset: int = 0) -> None:
        """Transfer directwrite, addrforce, and consume properties.

        The consume mask is shifted right by lsbOffset bytes, with high bits
        filled in, and masked to the new Varnode's size.

        C++ ref: ``Funcdata::transferVarnodeProperties``
        """
        if vn is None or newVn is None:
            return
        # Compute shifted consume mask
        newConsume = (1 << 64) - 1  # ~0ULL
        if lsbOffset < 8:  # sizeof(uintb)
            fillBits = 0
            if lsbOffset != 0:
                fillBits = newConsume << (8 * (8 - lsbOffset))
            oldConsume = vn.getConsume() if hasattr(vn, 'getConsume') else newConsume
            mask = (1 << (8 * newVn.getSize())) - 1
            newConsume = ((oldConsume >> (8 * lsbOffset)) | fillBits) & mask
        vnFlags = vn.getFlags() & (Varnode.directwrite | Varnode.addrforce)
        newVn.setFlags(vnFlags)
        if hasattr(newVn, 'setConsume'):
            newVn.setConsume(newConsume)

    def fillinReadOnly(self, vn) -> bool:
        """Replace the given Varnode with its (constant) value in the load image.

        If the Varnode is written, mark a warning and return False.
        Otherwise load bytes from the load image, create a constant, and
        replace all read references.

        C++ ref: ``Funcdata::fillinReadOnly``
        """
        if vn.isWritten():
            defop = vn.getDef()
            if defop.isMarker():
                if hasattr(defop, 'setAdditionalFlag'):
                    defop.setAdditionalFlag(PcodeOp.warning)
            elif not (hasattr(defop, 'isWarning') and defop.isWarning()):
                if hasattr(defop, 'setAdditionalFlag'):
                    defop.setAdditionalFlag(PcodeOp.warning)
                if (not vn.isAddrForce()) or (not vn.hasNoDescend()):
                    msg = f"Read-only address ({vn.getSpace().getName()},{vn.getAddr()}) is written"
                    if hasattr(self, 'warning'):
                        self.warning(msg, defop.getAddr())
            return False
        if vn.getSize() > 8:
            return False
        # Load bytes from the load image
        if self._glb is None or not hasattr(self._glb, 'loader'):
            return False
        try:
            buf = bytearray(vn.getSize())
            self._glb.loader.loadFill(buf, vn.getSize(), vn.getAddr())
        except Exception:
            if hasattr(vn, 'clearFlags'):
                from ghidra.ir.varnode import Varnode as VnCls
                vn.clearFlags(VnCls.readonly)
            return True
        # Convert bytes to integer
        if vn.getSpace().isBigEndian():
            res = int.from_bytes(buf, 'big')
        else:
            res = int.from_bytes(buf, 'little')
        # Replace all read references with the constant
        changemade = False
        locktype = vn.getType() if (hasattr(vn, 'isTypeLock') and vn.isTypeLock()) else None
        descends = list(vn.getDescend()) if hasattr(vn, 'getDescend') else []
        for op in descends:
            slot = op.getSlot(vn) if hasattr(op, 'getSlot') else 0
            if op.isMarker():
                if op.code() != OpCode.CPUI_INDIRECT or slot != 0:
                    continue
                outvn = op.getOut()
                if outvn is not None and outvn.getAddr() == vn.getAddr():
                    continue
                if hasattr(self, 'opRemoveInput'):
                    self.opRemoveInput(op, 1)
                self.opSetOpcode(op, OpCode.CPUI_COPY)
            cvn = self.newConstant(vn.getSize(), res)
            if locktype is not None and hasattr(cvn, 'updateType'):
                cvn.updateType(locktype, True, True)
            self.opSetInput(op, cvn, slot)
            changemade = True
        return changemade

    def replaceVolatile(self, vn) -> bool:
        """Replace accesses of the given Varnode with volatile operations.

        The Varnode is assumed not fully linked. The read or write action is
        modeled by inserting a special user op (CALLOTHER) that represents
        the action. The given Varnode is replaced by a temporary Varnode
        within the data-flow, and the original address becomes a parameter.

        C++ ref: ``Funcdata::replaceVolatile``
        """
        if vn.isWritten():
            # Written value - insert volatile write user op after defining op
            vw_index = 0  # BUILTIN_VOLATILE_WRITE index
            if self._glb is not None and hasattr(self._glb, 'userops'):
                vw_op = self._glb.userops.registerBuiltin(1) if hasattr(self._glb.userops, 'registerBuiltin') else None
                if vw_op is not None and hasattr(vw_op, 'getIndex'):
                    vw_index = vw_op.getIndex()
            if not vn.hasNoDescend():
                return False  # Volatile memory was propagated
            defop = vn.getDef()
            newop = self.newOp(3, defop.getAddr())
            self.opSetOpcode(newop, OpCode.CPUI_CALLOTHER)
            self.opSetInput(newop, self.newConstant(4, vw_index), 0)
            # First parameter is the offset of volatile memory location
            annoteVn = self.newCodeRef(vn.getAddr()) if hasattr(self, 'newCodeRef') else self.newConstant(vn.getSize(), vn.getOffset())
            if hasattr(annoteVn, 'setFlags'):
                from ghidra.ir.varnode import Varnode as VnCls
                annoteVn.setFlags(VnCls.volatil)
            self.opSetInput(newop, annoteVn, 1)
            # Replace the volatile variable with a temp
            tmp = self.newUnique(vn.getSize())
            self.opSetOutput(defop, tmp)
            self.opSetInput(newop, tmp, 2)
            self.opInsertAfter(newop, defop)
        else:
            # Read value - insert volatile read user op before reading op
            vr_index = 0  # BUILTIN_VOLATILE_READ index
            if self._glb is not None and hasattr(self._glb, 'userops'):
                vr_op_obj = self._glb.userops.registerBuiltin(0) if hasattr(self._glb.userops, 'registerBuiltin') else None
                if vr_op_obj is not None and hasattr(vr_op_obj, 'getIndex'):
                    vr_index = vr_op_obj.getIndex()
            if vn.hasNoDescend():
                return False  # Dead
            readop = vn.loneDescend() if hasattr(vn, 'loneDescend') else None
            if readop is None:
                return False
            newop = self.newOp(2, readop.getAddr())
            self.opSetOpcode(newop, OpCode.CPUI_CALLOTHER)
            tmp = self.newUniqueOut(vn.getSize(), newop) if hasattr(self, 'newUniqueOut') else self.newUnique(vn.getSize())
            self.opSetInput(newop, self.newConstant(4, vr_index), 0)
            annoteVn = self.newCodeRef(vn.getAddr()) if hasattr(self, 'newCodeRef') else self.newConstant(vn.getSize(), vn.getOffset())
            if hasattr(annoteVn, 'setFlags'):
                from ghidra.ir.varnode import Varnode as VnCls
                annoteVn.setFlags(VnCls.volatil)
            self.opSetInput(newop, annoteVn, 1)
            slot = readop.getSlot(vn) if hasattr(readop, 'getSlot') else 0
            self.opSetInput(readop, tmp, slot)
            self.opInsertBefore(newop, readop)
        if vn.isTypeLock() and hasattr(newop, 'setAdditionalFlag'):
            newop.setAdditionalFlag(PcodeOp.special_prop)
        return True

    def remapVarnode(self, vn, sym, usepoint) -> None:
        """Remap a Symbol to a given Varnode using the local scope.

        Any previous links between Symbol and Varnode are removed, then
        a new mapping is created in the local scope.

        C++ ref: ``Funcdata::remapVarnode``
        """
        if hasattr(vn, 'clearSymbolLinks'):
            vn.clearSymbolLinks()
        if self._localmap is not None and hasattr(self._localmap, 'remapSymbol'):
            entry = self._localmap.remapSymbol(sym, vn.getAddr(), usepoint)
            if entry is not None and hasattr(vn, 'setSymbolEntry'):
                vn.setSymbolEntry(entry)

    def remapDynamicVarnode(self, vn, sym, usepoint, hashval) -> None:
        """Remap a Symbol to a Varnode using a new dynamic mapping.

        C++ ref: ``Funcdata::remapDynamicVarnode``
        """
        if hasattr(vn, 'clearSymbolLinks'):
            vn.clearSymbolLinks()
        if self._localmap is not None and hasattr(self._localmap, 'remapSymbolDynamic'):
            entry = self._localmap.remapSymbolDynamic(sym, hashval, usepoint)
            if entry is not None and hasattr(vn, 'setSymbolEntry'):
                vn.setSymbolEntry(entry)

    def newExtendedConstant(self, s: int, val, op):
        """Construct a constant Varnode up to 128 bits using INT_ZEXT or PIECE.

        If size <= 8, returns a normal constant. Otherwise, if the high
        64-bit chunk is zero, uses INT_ZEXT; otherwise uses PIECE to
        combine two 64-bit halves.

        C++ ref: ``Funcdata::newExtendedConstant``
        """
        if isinstance(val, (list, tuple)):
            lo = val[0]
            hi = val[1] if len(val) > 1 else 0
        else:
            lo = val
            hi = 0
        if s <= 8:
            return self.newConstant(s, lo)
        if hi == 0:
            extOp = self.newOp(1, op.getAddr())
            self.opSetOpcode(extOp, OpCode.CPUI_INT_ZEXT)
            newConstVn = self.newUniqueOut(s, extOp)
            self.opSetInput(extOp, self.newConstant(8, lo), 0)
            self.opInsertBefore(extOp, op)
        else:
            pieceOp = self.newOp(2, op.getAddr())
            self.opSetOpcode(pieceOp, OpCode.CPUI_PIECE)
            newConstVn = self.newUniqueOut(s, pieceOp)
            self.opSetInput(pieceOp, self.newConstant(8, hi), 0)  # Most significant
            self.opSetInput(pieceOp, self.newConstant(8, lo), 1)  # Least significant
            self.opInsertBefore(pieceOp, op)
        return newConstVn

    def adjustInputVarnodes(self, addr, sz: int) -> None:
        """Adjust input Varnodes contained in the given range.

        All input Varnodes in the range are replaced by SUBPIECE ops from
        a single new input Varnode covering the whole range.

        C++ ref: ``Funcdata::adjustInputVarnodes``
        """
        endaddr = addr + (sz - 1)
        inlist = []
        # Collect input varnodes in range
        for vn in list(self._vbank.beginLoc()):
            if not vn.isInput():
                continue
            if vn.getSpace() is not addr.getSpace():
                continue
            vn_off = vn.getOffset()
            if vn_off < addr.getOffset() or vn_off > endaddr.getOffset():
                continue
            if vn_off + (vn.getSize() - 1) > endaddr.getOffset():
                raise Exception("Cannot properly adjust input varnodes")
            inlist.append(vn)
        # Replace each with SUBPIECE
        for i, vn in enumerate(inlist):
            sa = addr.justifiedContain(sz, vn.getAddr(), vn.getSize(), False)
            if not vn.isInput() or sa < 0 or sz <= vn.getSize():
                raise Exception("Bad adjustment to input varnode")
            subop = self.newOp(2, self.getAddress())
            self.opSetOpcode(subop, OpCode.CPUI_SUBPIECE)
            self.opSetInput(subop, self.newConstant(4, sa), 1)
            newvn = self.newVarnodeOut(vn.getSize(), vn.getAddr(), subop)
            bl = self._bblocks.getBlock(0) if self._bblocks.getSize() > 0 else None
            if bl is not None:
                self.opInsertBegin(subop, bl)
            self.totalReplace(vn, newvn)
            self.deleteVarnode(vn)
            inlist[i] = newvn
        # Create new combined input
        invn = self.newVarnode(sz, addr)
        invn = self.setInputVarnode(invn)
        invn.setWriteMask()
        # Wire SUBPIECE ops to read from the new combined input
        for newvn in inlist:
            op = newvn.getDef()
            if op is not None:
                self.opSetInput(op, invn, 0)

    def findDisjointCover(self, vn):
        """Find range covering given Varnode and any intersecting Varnodes.

        Walk backwards and forwards through the location-sorted Varnode list
        to find the maximal range that covers the given Varnode and all
        overlapping Varnodes.

        C++ ref: ``Funcdata::findDisjointCover``
        """
        addr = vn.getAddr()
        endoff = addr.getOffset() + vn.getSize()
        # Walk backwards to extend start
        if hasattr(self._vbank, 'beginLoc'):
            for curvn in self._vbank.beginLoc():
                if curvn.getSpace() is not addr.getSpace():
                    continue
                curEnd = curvn.getOffset() + curvn.getSize()
                if curEnd <= addr.getOffset():
                    continue
                if curvn.getOffset() >= endoff:
                    break
                if curvn.getOffset() < addr.getOffset():
                    addr = Address(addr.getSpace(), curvn.getOffset())
                if curEnd > endoff:
                    endoff = curEnd
        sz = endoff - addr.getOffset()
        return (addr, sz)

    def checkForLanedRegister(self, sz: int, addr) -> None:
        """Check if a storage range is a potential laned register.

        If so, record the storage with the matching laned register record
        in the lanedMap.

        C++ ref: ``Funcdata::checkForLanedRegister``
        """
        if self._glb is None:
            return
        if not hasattr(self._glb, 'getLanedRegister'):
            return
        lanedReg = self._glb.getLanedRegister(addr, sz)
        if lanedReg is None:
            return
        if not hasattr(self, '_lanedMap'):
            self._lanedMap = {}
        key = (addr.getSpace(), addr.getOffset(), sz)
        self._lanedMap[key] = lanedReg

    def recoverJumpTable(self, op, flow=None, mode_ref=None):
        """Recover control-flow destinations for a BRANCHIND.

        If an existing and complete JumpTable exists for the BRANCHIND, it is
        returned immediately. Otherwise an attempt is made to analyze the
        current partial function and recover the set of destination addresses,
        which if successful will be returned as a new JumpTable object.

        C++ ref: ``Funcdata::recoverJumpTable``

        Args:
            op: The BRANCHIND PcodeOp.
            flow: Current FlowInfo for this function (or None).
            mode_ref: A list [mode] that receives the recovery mode string
                      ('success', 'fail_normal', 'fail_return', 'fail_thunk').
                      If None, mode is not returned.

        Returns:
            The recovered JumpTable, or None on failure.
        """
        if mode_ref is None:
            mode_ref = ['success']
        mode_ref[0] = 'success'

        # Search for pre-existing jumptable
        jt = self.linkJumpTable(op)
        if jt is not None:
            if not (hasattr(jt, 'isOverride') and jt.isOverride()):
                if not (hasattr(jt, 'isPartial') and jt.isPartial()):
                    return jt  # Previously calculated (NOT override, NOT incomplete)
            # Recover based on override / partial information
            partial = Funcdata(self._name + "_jtpartial", self._glb,
                               self._baseaddr, self._funcp, self._size) \
                if hasattr(self, '_name') else Funcdata("_jtpartial", self._glb,
                                                         self._baseaddr, self._funcp, 0)
            mode_ref[0] = self.stageJumpTable(partial, jt, op, flow)
            if mode_ref[0] != 'success':
                return None
            if hasattr(jt, 'setIndirectOp'):
                jt.setIndirectOp(op)  # Relink table back to original op
            return jt

        if (self._flags & Funcdata.jumptablerecovery_dont) != 0:
            return None  # Explicitly told not to recover jumptables

        mode_ref[0] = self.earlyJumpTableFail(op)
        if mode_ref[0] != 'success' and mode_ref[0] != 0:
            return None

        # Create a trial JumpTable
        try:
            from ghidra.analysis.jumptable import JumpTable
        except ImportError:
            return None

        trialjt = JumpTable(self._glb)
        partial = Funcdata(self._name + "_jtpartial", self._glb,
                           self._baseaddr, self._funcp, self._size) \
            if hasattr(self, '_name') else Funcdata("_jtpartial", self._glb,
                                                     self._baseaddr, self._funcp, 0)
        mode_ref[0] = self.stageJumpTable(partial, trialjt, op, flow)
        if mode_ref[0] != 'success':
            return None

        # Make the jumptable permanent
        jt = JumpTable(trialjt)
        self._jumpvec.append(jt)
        if hasattr(jt, 'setIndirectOp'):
            jt.setIndirectOp(op)  # Relink table back to original op
        return jt

    def earlyJumpTableFail(self, op):
        """Backtrack from the BRANCHIND, looking for ops that might affect the destination.

        If a CALLOTHER, which is not injected/inlined in some way, is in the flow path of
        the destination calculation, we know the jump-table analysis will fail and the
        failure mode is returned.

        C++ ref: ``Funcdata::earlyJumpTableFail``

        Returns:
            'success' if there is no early failure, or the failure mode string otherwise.
        """
        from ghidra.ir.op import PcodeOp as PcOp
        vn = op.getIn(0)
        countMax = 8
        # Walk backward through dead list
        if not hasattr(self._obank, 'beginDead'):
            return 'success'
        dead_ops = list(self._obank.beginDead())
        # Find position of op in dead list
        idx = -1
        for i, dop in enumerate(dead_ops):
            if dop is op:
                idx = i
                break
        if idx < 0:
            return 'success'
        while idx > 0:
            if vn.getSize() == 1:
                return 'success'
            countMax -= 1
            if countMax < 0:
                return 'success'
            idx -= 1
            cur = dead_ops[idx]
            outvn = cur.getOut()
            outhit = False
            if outvn is not None and hasattr(vn, 'intersects'):
                outhit = vn.intersects(outvn)
            evaltype = cur.getEvalType() if hasattr(cur, 'getEvalType') else 0
            if evaltype == PcOp.special:
                if cur.isCall():
                    opc = cur.code()
                    if opc == OpCode.CPUI_CALLOTHER:
                        # Check userop type for injected/jumpassist/segment
                        uid = int(cur.getIn(0).getOffset())
                        if self._glb is not None and hasattr(self._glb, 'userops'):
                            userop = self._glb.userops.getOp(uid) if hasattr(self._glb.userops, 'getOp') else None
                            if userop is not None and hasattr(userop, 'getType'):
                                utype = userop.getType()
                                # UserPcodeOp type constants: injected=1, jumpassist=4, segment=3
                                if utype in (1, 3, 4):
                                    return 'success'  # Don't backtrack through injection
                        if outhit:
                            return 'fail_callother'
                        # Assume CALLOTHER will not interfere, continue backtracking
                    else:
                        # CALL or CALLIND - Output has not been established yet
                        return 'success'
                elif cur.isBranch():
                    return 'success'
                else:
                    if cur.code() == OpCode.CPUI_STORE:
                        return 'success'
                    if outhit:
                        return 'success'  # Some special op generates address, don't assume failure
                    # Assume special will not interfere, continue backtracking
            elif evaltype == PcOp.unary:
                if outhit:
                    invn = cur.getIn(0)
                    if invn.getSize() != vn.getSize():
                        return 'success'
                    vn = invn
                # Continue backtracking
            elif evaltype == PcOp.binary:
                if outhit:
                    opc = cur.code()
                    if opc not in (OpCode.CPUI_INT_ADD, OpCode.CPUI_INT_SUB, OpCode.CPUI_INT_XOR):
                        return 'success'
                    if not cur.getIn(1).isConstant():
                        return 'success'  # Don't backtrack thru binary op, don't assume failure
                    invn = cur.getIn(0)
                    if invn.getSize() != vn.getSize():
                        return 'success'
                    vn = invn
                # Continue backtracking
            else:
                if outhit:
                    return 'success'
        return 'success'

    def testForReturnAddress(self, vn) -> bool:
        """Test if the given Varnode traces back to the return address input.

        Walk backwards through INDIRECT, COPY, and INT_AND (alignment mask)
        ops to see if the ultimate source is the default return address input.

        C++ ref: ``Funcdata::testForReturnAddress``
        """
        glb = self.getArch() if hasattr(self, 'getArch') else None
        if glb is None:
            return False
        retaddr = getattr(glb, 'defaultReturnAddr', None)
        if retaddr is None or (hasattr(retaddr, 'space') and retaddr.space is None):
            return False
        while vn.isWritten():
            op = vn.getDef()
            opc = op.code()
            if opc == OpCode.CPUI_INDIRECT or opc == OpCode.CPUI_COPY:
                vn = op.getIn(0)
            elif opc == OpCode.CPUI_INT_AND:
                if not op.getIn(1).isConstant():
                    return False
                vn = op.getIn(0)
            else:
                return False
        # Compare to default return address
        if hasattr(retaddr, 'space'):
            if vn.getSpace() != retaddr.space:
                return False
            if vn.getOffset() != retaddr.offset:
                return False
            if vn.getSize() != retaddr.size:
                return False
        elif hasattr(retaddr, 'getAddr'):
            if vn.getAddr() != retaddr.getAddr() or vn.getSize() != retaddr.size:
                return False
        else:
            return False
        return vn.isInput()

    def getInternalString(self, buf, size, ptrType, readOp):
        """Create a Varnode that will display as a string constant.

        The raw data for the encoded string is given. If it encodes a legal
        string, the string is stored via StringManager, and a CALLOTHER
        stringdata user-op is created whose output Varnode is returned.

        C++ ref: ``Funcdata::getInternalString``
        """
        if ptrType is None:
            return None
        meta = ptrType.getMetatype() if hasattr(ptrType, 'getMetatype') else -1
        from ghidra.types.type_base import TYPE_PTR
        if meta != TYPE_PTR:
            return None
        charType = ptrType.getPtrTo() if hasattr(ptrType, 'getPtrTo') else None
        if charType is None:
            return None
        addr = readOp.getAddr() if readOp is not None else None
        if addr is None or self._glb is None:
            return None
        # Register string data with StringManager
        sm = getattr(self._glb, 'stringManager', None)
        if sm is None or not hasattr(sm, 'registerInternalStringData'):
            return None
        hashVal = sm.registerInternalStringData(addr, buf, size, charType)
        if hashVal == 0:
            return None
        # Build CALLOTHER stringdata op
        BUILTIN_STRINGDATA = 3  # UserPcodeOp::BUILTIN_STRINGDATA
        if hasattr(self._glb, 'userops') and hasattr(self._glb.userops, 'registerBuiltin'):
            self._glb.userops.registerBuiltin(BUILTIN_STRINGDATA)
        stringOp = self.newOp(2, addr)
        self.opSetOpcode(stringOp, OpCode.CPUI_CALLOTHER)
        if hasattr(stringOp, 'clearFlag'):
            stringOp.clearFlag(PcodeOp.call)
        self.opSetInput(stringOp, self.newConstant(4, BUILTIN_STRINGDATA), 0)
        self.opSetInput(stringOp, self.newConstant(8, hashVal), 1)
        resVn = self.newUniqueOut(ptrType.getSize(), stringOp)
        if hasattr(resVn, 'updateType'):
            resVn.updateType(ptrType, True, False)
        self.opInsertBefore(stringOp, readOp)
        return resVn

    def moveRespectingCover(self, op, lastOp) -> bool:
        """Move \b op past \b lastOp, only crossing COPY/CAST ops, respecting covers.

        Uses HighVariable.markExpression to identify all HighVariables
        read by the expression rooted at \b op's output. If any crossed
        COPY/CAST writes to a marked High, there is a direct interference
        and the move is aborted. If the expression contains address-tied
        reads (typeVal != 0) and a crossed op writes an address-tied varnode,
        the move is also aborted (indirect interference).

        C++ ref: ``Funcdata::moveRespectingCover``
        """
        if op is lastOp:
            return True
        if op.isCall():
            return False
        prevOp = None
        if op.code() == OpCode.CPUI_CAST:
            vn = op.getIn(0)
            if hasattr(vn, 'isExplicit') and not vn.isExplicit():
                if not vn.isWritten():
                    return False
                prevOp = vn.getDef()
                if prevOp.isCall():
                    return False
                if op.previousOp() is not prevOp:
                    return False
        rootvn = op.getOut()
        if rootvn is None:
            return False

        # Mark expression variables for interference detection
        highList = []
        typeVal = 0
        try:
            from ghidra.ir.variable import HighVariable
            typeVal = HighVariable.markExpression(rootvn, highList)
        except (ImportError, Exception):
            pass

        curOp = op
        while curOp is not lastOp:
            nextOp = curOp.nextOp()
            if nextOp is None:
                break
            opc = nextOp.code()
            if opc != OpCode.CPUI_COPY and opc != OpCode.CPUI_CAST:
                break
            if rootvn is nextOp.getIn(0):
                break  # Data-flow order dependence
            copyVn = nextOp.getOut()
            if copyVn is not None:
                high = copyVn.getHigh() if hasattr(copyVn, 'getHigh') else None
                if high is not None and hasattr(high, 'isMark') and high.isMark():
                    break  # Direct interference: COPY writes what original op reads
                if typeVal != 0 and hasattr(copyVn, 'isAddrTied') and copyVn.isAddrTied():
                    break  # Possible indirect interference
            curOp = nextOp

        # Clear marks on expression
        for h in highList:
            if hasattr(h, 'clearMark'):
                h.clearMark()

        if curOp is lastOp:
            self.opUninsert(op)
            self.opInsertAfter(op, lastOp)
            if prevOp is not None:
                self.opUninsert(prevOp)
                self.opInsertAfter(prevOp, lastOp)
            return True
        return False

    def forceFacingType(self, parent, fieldNum: int, op, slot: int) -> None:
        """Force a specific field resolution for a data-type on a PcodeOp edge.

        C++ ref: ``Funcdata::forceFacingType``
        """
        baseType = parent
        if hasattr(baseType, 'getMetatype'):
            from ghidra.types.type_base import TYPE_PTR
            if baseType.getMetatype() == TYPE_PTR and hasattr(baseType, 'getPtrTo'):
                baseType = baseType.getPtrTo()
        if hasattr(parent, 'isPointerRel') and parent.isPointerRel():
            if self._glb is not None and hasattr(self._glb, 'types'):
                wordSize = parent.getWordSize() if hasattr(parent, 'getWordSize') else 1
                parent = self._glb.types.getTypePointer(parent.getSize(), baseType, wordSize)
        if hasattr(self, 'setUnionField'):
            from ghidra.types.type_base import ResolvedUnion
            resolve = ResolvedUnion(parent, fieldNum, self._glb.types) if self._glb is not None else None
            if resolve is not None:
                self.setUnionField(parent, op, slot, resolve)

    def inheritResolution(self, parent, op, slot: int, oldOp, oldSlot: int) -> int:
        """Copy a read/write facing resolution for a data-type from one PcodeOp to another.

        C++ ref: ``Funcdata::inheritResolution``
        """
        if self._unionMap is None:
            return -1
        resolve = self._unionMap.getUnionField(parent, oldOp, oldSlot)
        if resolve is None:
            return -1
        self.setUnionField(parent, op, slot, resolve)
        return resolve.getFieldNum() if hasattr(resolve, 'getFieldNum') else -1

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
        """Print raw p-code op descriptions.

        If no basic blocks exist, prints all raw ops from the op bank.
        Otherwise delegates to bblocks.printRaw() which prints blocks
        with their edges.

        C++ ref: ``Funcdata::printRaw``
        """
        import io
        s = io.StringIO()
        if self._bblocks.getSize() == 0:
            if self._obank.empty() if hasattr(self._obank, 'empty') else True:
                return "No operations to print"
            s.write("Raw operations:\n")
            for op in self._obank.beginAll() if hasattr(self._obank, 'beginAll') else []:
                s.write(f"{op.getSeqNum()}:\t")
                s.write(op.printRaw() if hasattr(op, 'printRaw') else str(op))
                s.write("\n")
        else:
            if hasattr(self._bblocks, 'printRaw'):
                s.write(self._bblocks.printRaw())
            else:
                for i in range(self._bblocks.getSize()):
                    bl = self._bblocks.getBlock(i)
                    if isinstance(bl, BlockBasic):
                        s.write(f"  Block {bl.getIndex()} ({bl.getStart()} - {bl.getStop()}):\n")
                        for op in bl.getOpList():
                            s.write(f"    {op.printRaw()}\n")
        return s.getvalue()

    def find(self, addr) -> Optional[Varnode]:
        """Find a Varnode by address."""
        return self._vbank.find(addr) if hasattr(self._vbank, 'find') else None

    # --- Debug methods (C++ OPACTION_DEBUG) ---

    def debugActivate(self) -> None:
        """Activate debug mode for the current action application."""
        pass

    def debugDeactivate(self) -> None:
        """Deactivate debug mode."""
        pass

    def debugEnable(self) -> None:
        """Enable the debug console."""
        pass

    def debugDisable(self) -> None:
        """Disable the debug console."""
        pass

    def debugBreak(self) -> bool:
        """Check if a debug breakpoint has been hit."""
        return False

    def debugHandleBreak(self) -> None:
        """Handle a debug breakpoint."""
        pass

    def debugSetBreak(self, addr) -> None:
        """Set a debug breakpoint at the given address."""
        pass

    def debugSetRange(self, addr1, addr2) -> None:
        """Set a debug address range."""
        pass

    def debugCheckRange(self, vn) -> bool:
        """Check if a Varnode falls in the debug range."""
        return False

    def debugPrintRange(self, count: int) -> None:
        """Print the debug range."""
        pass

    def debugModCheck(self, op) -> bool:
        """Check if an op modification should trigger debug output."""
        return False

    def debugModClear(self) -> None:
        """Clear the modification check state."""
        pass

    def debugModPrint(self, actionname: str) -> None:
        """Print a debug message for a modification."""
        pass

    def debugClear(self) -> None:
        """Clear all debug state."""
        pass

    def debugSize(self) -> int:
        """Return the number of debug records."""
        return 0

    def __repr__(self) -> str:
        return (f"Funcdata({self._name!r} @ {self._baseaddr}, "
                f"varnodes={self._vbank.size()}, "
                f"blocks={self._bblocks.getSize()})")
