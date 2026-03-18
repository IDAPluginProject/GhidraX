"""Lightweight emulation for PcodeOp objects and p-code snippets.

C++ ref: ``emulateutil.hh`` / ``emulateutil.cc``

Provides two emulator classes:
- **EmulatePcodeOp** — emulates using full PcodeOp/Varnode objects from a
  syntax tree (abstract; subclass must supply getVarnodeValue/setVarnodeValue
  and control-flow methods).
- **EmulateSnippet** — emulates a short self-contained sequence of
  PcodeOpRaw objects with only temporary-register and load-image access.
"""
from __future__ import annotations

from abc import ABC, abstractmethod
from typing import TYPE_CHECKING, Dict, List, Optional

from ghidra.core.address import Address, calc_mask
from ghidra.core.error import LowlevelError
from ghidra.core.opcodes import OpCode
from ghidra.core.pcoderaw import VarnodeData, PcodeOpRaw
from ghidra.core.opbehavior import OpBehavior
from ghidra.core.space import IPTR_CONSTANT, IPTR_INTERNAL, IPTR_PROCESSOR
from ghidra.core.translate import PcodeEmit

if TYPE_CHECKING:
    from ghidra.core.space import AddrSpace
    from ghidra.ir.op import PcodeOp
    from ghidra.ir.varnode import Varnode


# =========================================================================
# Helper – load image value with endianness
# =========================================================================

def _load_image_value(loader, spc: 'AddrSpace', offset: int, sz: int) -> int:
    """Pull *sz* bytes from *loader* at (*spc*, *offset*), respecting endianness."""
    buf = bytearray(8)
    loader.loadFill(buf, 8, Address(spc, offset))
    big = spc.isBigEndian()
    if big:
        val = int.from_bytes(buf[:8], 'big')
    else:
        val = int.from_bytes(buf[:8], 'little')
    if big and sz < 8:
        val >>= (8 - sz) * 8
    else:
        val &= calc_mask(sz)
    return val


# =========================================================================
# EmulatePcodeOp  (abstract)
# =========================================================================

class EmulatePcodeOp(ABC):
    """Emulation based on existing PcodeOp and Varnode objects.

    This is still abstract.  Derived classes must implement:
    - ``getVarnodeValue(vn)``
    - ``setVarnodeValue(vn, val)``
    - ``fallthruOp()``
    - ``executeBranch()``
    - ``executeBranchind()``
    - ``executeCall()``
    - ``executeCallind()``
    - ``executeCallother()``

    C++ ref: ``EmulatePcodeOp``
    """

    def __init__(self, glb) -> None:
        self.glb = glb
        self.currentOp: Optional['PcodeOp'] = None
        self.lastOp: Optional['PcodeOp'] = None
        self.currentBehave: Optional[OpBehavior] = None
        self.emu_halted: bool = True

    # -- abstract interface ------------------------------------------------

    @abstractmethod
    def getVarnodeValue(self, vn: 'Varnode') -> int:
        """Retrieve the current value of a Varnode from the machine state."""
        ...

    @abstractmethod
    def setVarnodeValue(self, vn: 'Varnode', val: int) -> None:
        """Set the value of a Varnode in the machine state."""
        ...

    @abstractmethod
    def fallthruOp(self) -> None:
        """Advance to the next PcodeOp after a fall-through."""
        ...

    @abstractmethod
    def executeBranch(self) -> None: ...

    @abstractmethod
    def executeBranchind(self) -> None: ...

    @abstractmethod
    def executeCall(self) -> None: ...

    @abstractmethod
    def executeCallind(self) -> None: ...

    @abstractmethod
    def executeCallother(self) -> None: ...

    # -- concrete helpers --------------------------------------------------

    def setCurrentOp(self, op: 'PcodeOp') -> None:
        """Establish the current PcodeOp being emulated."""
        self.currentOp = op
        self.currentBehave = op.getOpcode().getBehavior()

    def getExecuteAddress(self) -> Address:
        return self.currentOp.getAddr()

    def setHalt(self, val: bool) -> None:
        self.emu_halted = val

    def getHalt(self) -> bool:
        return self.emu_halted

    # -- virtual operation implementations ---------------------------------

    def getLoadImageValue(self, spc: 'AddrSpace', offset: int, sz: int) -> int:
        """Pull a value from the load image (default impl)."""
        return _load_image_value(self.glb.loader, spc, offset, sz)

    def executeUnary(self) -> None:
        in1 = self.getVarnodeValue(self.currentOp.getIn(0))
        out = self.currentBehave.evaluateUnary(
            self.currentOp.getOut().getSize(),
            self.currentOp.getIn(0).getSize(), in1)
        self.setVarnodeValue(self.currentOp.getOut(), out)

    def executeBinary(self) -> None:
        in1 = self.getVarnodeValue(self.currentOp.getIn(0))
        in2 = self.getVarnodeValue(self.currentOp.getIn(1))
        out = self.currentBehave.evaluateBinary(
            self.currentOp.getOut().getSize(),
            self.currentOp.getIn(0).getSize(), in1, in2)
        self.setVarnodeValue(self.currentOp.getOut(), out)

    def executeLoad(self) -> None:
        off = self.getVarnodeValue(self.currentOp.getIn(1))
        spc = self.currentOp.getIn(0).getSpaceFromConst()
        from ghidra.core.space import AddrSpace as _AS
        off = _AS.addressToByte(off, spc.getWordSize())
        sz = self.currentOp.getOut().getSize()
        res = self.getLoadImageValue(spc, off, sz)
        self.setVarnodeValue(self.currentOp.getOut(), res)

    def executeStore(self) -> None:
        # NULL implementation — nowhere to store in lightweight emulation
        pass

    def executeCbranch(self) -> bool:
        cond = self.getVarnodeValue(self.currentOp.getIn(1))
        return (cond != 0) != self.currentOp.isBooleanFlip()

    def executeMultiequal(self) -> None:
        bl = self.currentOp.getParent()
        last_bl = self.lastOp.getParent()
        found = -1
        for i in range(bl.sizeIn()):
            if bl.getIn(i) is last_bl:
                found = i
                break
        if found < 0:
            raise LowlevelError("Could not execute MULTIEQUAL")
        val = self.getVarnodeValue(self.currentOp.getIn(found))
        self.setVarnodeValue(self.currentOp.getOut(), val)

    def executeIndirect(self) -> None:
        val = self.getVarnodeValue(self.currentOp.getIn(0))
        self.setVarnodeValue(self.currentOp.getOut(), val)

    def executeSegmentOp(self) -> None:
        segdef = self.glb.userops.getSegmentOp(
            self.currentOp.getIn(0).getSpaceFromConst().getIndex())
        if segdef is None:
            raise LowlevelError("Segment operand missing definition")
        in1 = self.getVarnodeValue(self.currentOp.getIn(1))
        in2 = self.getVarnodeValue(self.currentOp.getIn(2))
        res = segdef.execute([in1, in2])
        self.setVarnodeValue(self.currentOp.getOut(), res)

    def executeCpoolRef(self) -> None:
        pass  # Ignore constant pool references

    def executeNew(self) -> None:
        pass  # Ignore new operations

    # -- main dispatch (mirrors C++ Emulate::executeCurrentOp) -------------

    def executeCurrentOp(self) -> None:
        """Execute the current PcodeOp."""
        if self.currentBehave is None:
            self.fallthruOp()
            return

        if self.currentBehave.isSpecial():
            opc = self.currentBehave.getOpcode()
            if opc == OpCode.CPUI_LOAD:
                self.executeLoad()
                self.fallthruOp()
            elif opc == OpCode.CPUI_STORE:
                self.executeStore()
                self.fallthruOp()
            elif opc == OpCode.CPUI_BRANCH:
                self.executeBranch()
            elif opc == OpCode.CPUI_CBRANCH:
                if self.executeCbranch():
                    self.executeBranch()
                else:
                    self.fallthruOp()
            elif opc == OpCode.CPUI_BRANCHIND:
                self.executeBranchind()
            elif opc == OpCode.CPUI_CALL:
                self.executeCall()
            elif opc == OpCode.CPUI_CALLIND:
                self.executeCallind()
            elif opc == OpCode.CPUI_CALLOTHER:
                self.executeCallother()
            elif opc == OpCode.CPUI_RETURN:
                self.executeBranchind()
            elif opc == OpCode.CPUI_MULTIEQUAL:
                self.executeMultiequal()
                self.fallthruOp()
            elif opc == OpCode.CPUI_INDIRECT:
                self.executeIndirect()
                self.fallthruOp()
            elif opc == OpCode.CPUI_SEGMENTOP:
                self.executeSegmentOp()
                self.fallthruOp()
            elif opc == OpCode.CPUI_CPOOLREF:
                self.executeCpoolRef()
                self.fallthruOp()
            elif opc == OpCode.CPUI_NEW:
                self.executeNew()
                self.fallthruOp()
            else:
                raise LowlevelError("Bad special op")
        elif self.currentBehave.isUnary():
            self.executeUnary()
            self.fallthruOp()
        else:
            self.executeBinary()
            self.fallthruOp()


# =========================================================================
# PcodeEmitCache
# =========================================================================

class PcodeEmitCache(PcodeEmit):
    """P-code emitter that caches raw Varnodes and PcodeOps for snippet emulation.

    C++ ref: ``PcodeEmitCache``
    """

    def __init__(self, opcache: List[PcodeOpRaw], varcache: List[VarnodeData],
                 inst: List[Optional[OpBehavior]], uniqReserve: int) -> None:
        self.opcache: List[PcodeOpRaw] = opcache
        self.varcache: List[VarnodeData] = varcache
        self.inst: List[Optional[OpBehavior]] = inst
        self.uniq: int = uniqReserve

    def _createVarnode(self, var: VarnodeData) -> VarnodeData:
        res = VarnodeData()
        res.space = var.space
        res.offset = var.offset
        res.size = var.size
        self.varcache.append(res)
        return res

    def dump(self, addr: Address, opc: OpCode,
             outvar: Optional[VarnodeData],
             vars_: List[VarnodeData], isize: int) -> None:
        op = PcodeOpRaw()
        op.setSeqNum(addr, self.uniq)
        self.opcache.append(op)
        behave = self.inst[int(opc)] if int(opc) < len(self.inst) else None
        op.setBehavior(behave)
        self.uniq += 1
        if outvar is not None:
            outvn = self._createVarnode(outvar)
            op.setOutput(outvn)
        for i in range(isize):
            invn = self._createVarnode(vars_[i])
            op.addInput(invn)


# =========================================================================
# EmulateSnippet
# =========================================================================

class EmulateSnippet:
    """Emulate a short snippet of PcodeOpRaw objects out of functional context.

    Control-flow is limited to p-code-relative branching within the snippet.
    Only temporary registers and load-image reads are supported.

    C++ ref: ``EmulateSnippet``
    """

    def __init__(self, glb) -> None:
        self.glb = glb
        self.opList: List[PcodeOpRaw] = []
        self.varList: List[VarnodeData] = []
        self.tempValues: Dict[int, int] = {}
        self.currentOp: Optional[PcodeOpRaw] = None
        self.currentBehave: Optional[OpBehavior] = None
        self.pos: int = 0
        self.emu_halted: bool = False
        self._spaceResolver = None  # Optional callback: index -> AddrSpace

    def getArch(self):
        return self.glb

    # -- snippet lifecycle -------------------------------------------------

    def resetMemory(self) -> None:
        """Reset memory state and set the first op as current."""
        self.tempValues.clear()
        self.setCurrentOp(0)
        self.emu_halted = False

    def buildEmitter(self, inst: List[Optional[OpBehavior]],
                     uniqReserve: int) -> PcodeEmitCache:
        """Build a PcodeEmit for populating this snippet's op list."""
        return PcodeEmitCache(self.opList, self.varList, inst, uniqReserve)

    def setCurrentOp(self, i: int) -> None:
        """Set the current executing p-code op by index."""
        self.pos = i
        self.currentOp = self.opList[i]
        self.currentBehave = self.currentOp.getBehavior()

    def setExecuteAddress(self, addr: Address) -> None:
        self.setCurrentOp(0)

    def getExecuteAddress(self) -> Address:
        return self.currentOp.getAddr()

    def setHalt(self, val: bool) -> None:
        self.emu_halted = val

    def getHalt(self) -> bool:
        return self.emu_halted

    # -- value access ------------------------------------------------------

    def setVarnodeValue(self, offset: int, val: int) -> None:
        """Set a temporary register value by its unique-space offset."""
        self.tempValues[offset] = val

    def getVarnodeValue(self, vn: VarnodeData) -> int:
        """Retrieve the value of a VarnodeData from the current state."""
        spc = vn.space
        if spc.getType() == IPTR_CONSTANT:
            return vn.offset
        if spc.getType() == IPTR_INTERNAL:
            val = self.tempValues.get(vn.offset)
            if val is not None:
                return val
            raise LowlevelError("Read before write in snippet emulation")
        return _load_image_value(self.glb.loader, vn.space, vn.offset, vn.size)

    def getTempValue(self, offset: int) -> int:
        """Retrieve a temporary register value directly."""
        return self.tempValues.get(offset, 0)

    # -- legality check ----------------------------------------------------

    def checkForLegalCode(self) -> bool:
        """Check that the snippet contains only legal operations."""
        illegal = {
            OpCode.CPUI_BRANCHIND, OpCode.CPUI_CALL, OpCode.CPUI_CALLIND,
            OpCode.CPUI_CALLOTHER, OpCode.CPUI_STORE, OpCode.CPUI_SEGMENTOP,
            OpCode.CPUI_CPOOLREF, OpCode.CPUI_NEW, OpCode.CPUI_MULTIEQUAL,
            OpCode.CPUI_INDIRECT,
        }
        for op in self.opList:
            opc = op.getOpcode()
            if opc in illegal:
                return False
            if opc == OpCode.CPUI_BRANCH:
                vn = op.getInput(0)
                if vn.space.getType() != IPTR_CONSTANT:
                    return False
            outvn = op.getOutput()
            if outvn is not None:
                if outvn.space.getType() != IPTR_INTERNAL:
                    return False
            for j in range(op.numInput()):
                invn = op.getInput(j)
                if invn.space.getType() == IPTR_PROCESSOR:
                    return False
        return True

    # -- execution methods -------------------------------------------------

    def executeUnary(self) -> None:
        in1 = self.getVarnodeValue(self.currentOp.getInput(0))
        out = self.currentBehave.evaluateUnary(
            self.currentOp.getOutput().size,
            self.currentOp.getInput(0).size, in1)
        self.setVarnodeValue(self.currentOp.getOutput().offset, out)

    def executeBinary(self) -> None:
        in1 = self.getVarnodeValue(self.currentOp.getInput(0))
        in2 = self.getVarnodeValue(self.currentOp.getInput(1))
        out = self.currentBehave.evaluateBinary(
            self.currentOp.getOutput().size,
            self.currentOp.getInput(0).size, in1, in2)
        self.setVarnodeValue(self.currentOp.getOutput().offset, out)

    def executeLoad(self) -> None:
        off = self.getVarnodeValue(self.currentOp.getInput(1))
        spc_vn = self.currentOp.getInput(0)
        spc = spc_vn.getSpaceFromConst()
        if spc is None and self._spaceResolver is not None:
            spc = self._spaceResolver(spc_vn.offset)
        if spc is None:
            raise LowlevelError("Cannot resolve target space in snippet LOAD")
        from ghidra.core.space import AddrSpace as _AS
        off = _AS.addressToByte(off, spc.getWordSize())
        sz = self.currentOp.getOutput().size
        res = _load_image_value(self.glb.loader, spc, off, sz)
        self.setVarnodeValue(self.currentOp.getOutput().offset, res)

    def executeStore(self) -> None:
        raise LowlevelError(
            "Illegal p-code operation in snippet: STORE")

    def executeBranch(self) -> None:
        vn = self.currentOp.getInput(0)
        if vn.space.getType() != IPTR_CONSTANT:
            raise LowlevelError(
                "Tried to emulate absolute branch in snippet code")
        rel = vn.offset
        if rel >= 0x80000000:
            rel -= 0x100000000
        self.pos += int(rel)
        if self.pos < 0 or self.pos > len(self.opList):
            raise LowlevelError(
                "Relative branch out of bounds in snippet code")
        if self.pos == len(self.opList):
            self.emu_halted = True
            return
        self.setCurrentOp(self.pos)

    def executeCbranch(self) -> bool:
        cond = self.getVarnodeValue(self.currentOp.getInput(1))
        return cond != 0

    def executeBranchind(self) -> None:
        raise LowlevelError(
            "Illegal p-code operation in snippet: BRANCHIND")

    def executeCall(self) -> None:
        raise LowlevelError(
            "Illegal p-code operation in snippet: CALL")

    def executeCallind(self) -> None:
        raise LowlevelError(
            "Illegal p-code operation in snippet: CALLIND")

    def executeCallother(self) -> None:
        raise LowlevelError(
            "Illegal p-code operation in snippet: CALLOTHER")

    def executeMultiequal(self) -> None:
        raise LowlevelError(
            "Illegal p-code operation in snippet: MULTIEQUAL")

    def executeIndirect(self) -> None:
        raise LowlevelError(
            "Illegal p-code operation in snippet: INDIRECT")

    def executeSegmentOp(self) -> None:
        raise LowlevelError(
            "Illegal p-code operation in snippet: SEGMENTOP")

    def executeCpoolRef(self) -> None:
        raise LowlevelError(
            "Illegal p-code operation in snippet: CPOOLREF")

    def executeNew(self) -> None:
        raise LowlevelError(
            "Illegal p-code operation in snippet: NEW")

    def fallthruOp(self) -> None:
        self.pos += 1
        if self.pos == len(self.opList):
            self.emu_halted = True
            return
        self.setCurrentOp(self.pos)

    # -- main dispatch -----------------------------------------------------

    def executeCurrentOp(self) -> None:
        """Execute the current PcodeOpRaw."""
        if self.currentBehave is None:
            self.fallthruOp()
            return

        if self.currentBehave.isSpecial():
            opc = self.currentBehave.getOpcode()
            if opc == OpCode.CPUI_LOAD:
                self.executeLoad()
                self.fallthruOp()
            elif opc == OpCode.CPUI_STORE:
                self.executeStore()
            elif opc == OpCode.CPUI_BRANCH:
                self.executeBranch()
            elif opc == OpCode.CPUI_CBRANCH:
                if self.executeCbranch():
                    self.executeBranch()
                else:
                    self.fallthruOp()
            elif opc == OpCode.CPUI_BRANCHIND:
                self.executeBranchind()
            elif opc == OpCode.CPUI_CALL:
                self.executeCall()
            elif opc == OpCode.CPUI_CALLIND:
                self.executeCallind()
            elif opc == OpCode.CPUI_CALLOTHER:
                self.executeCallother()
            elif opc == OpCode.CPUI_RETURN:
                self.executeBranchind()
            elif opc == OpCode.CPUI_MULTIEQUAL:
                self.executeMultiequal()
            elif opc == OpCode.CPUI_INDIRECT:
                self.executeIndirect()
            elif opc == OpCode.CPUI_SEGMENTOP:
                self.executeSegmentOp()
            elif opc == OpCode.CPUI_CPOOLREF:
                self.executeCpoolRef()
            elif opc == OpCode.CPUI_NEW:
                self.executeNew()
            else:
                raise LowlevelError("Bad special op in snippet")
        elif self.currentBehave.isUnary():
            self.executeUnary()
            self.fallthruOp()
        else:
            self.executeBinary()
            self.fallthruOp()
