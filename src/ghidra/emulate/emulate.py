"""
Corresponds to: emulate.hh / emulate.cc

P-code emulator: executes raw p-code operations on a MemoryState.
"""

from __future__ import annotations

from typing import TYPE_CHECKING, Dict, Optional, List

from ghidra.core.opcodes import OpCode
from ghidra.core.address import Address
from ghidra.core.pcoderaw import VarnodeData, PcodeOpRaw
from ghidra.core.opbehavior import OpBehavior
from ghidra.core.error import LowlevelError
from ghidra.core.space import AddrSpace
from ghidra.emulate.memstate import MemoryState

if TYPE_CHECKING:
    from ghidra.core.translate import Translate


# =========================================================================
# Break callback hierarchy
# =========================================================================

class BreakCallBack:
    """A single breakpoint callback.

    C++ ref: BreakCallBack
    """

    def __init__(self) -> None:
        self._emulate: Optional[Emulate] = None

    def setEmulate(self, emu: Emulate) -> None:
        self._emulate = emu

    def addressCallback(self, addr: Address) -> bool:
        """Return True if breakpoint takes effect (halts normal flow)."""
        return True

    def pcodeCallback(self, op: PcodeOpRaw) -> bool:
        """Return True if breakpoint takes effect."""
        return True


class BreakTable:
    """Abstract collection of breakpoints for an emulator.

    C++ ref: BreakTable
    """

    def setEmulate(self, emu: Emulate) -> None:
        pass

    def doPcodeOpBreak(self, op: PcodeOpRaw) -> bool:
        return False

    def doAddressBreak(self, addr: Address) -> bool:
        return False


class BreakTableCallBack(BreakTable):
    """Concrete BreakTable that uses registered callbacks.

    C++ ref: BreakTableCallBack
    """

    def __init__(self, trans: Translate) -> None:
        self._trans: Translate = trans
        self._emulate: Optional[Emulate] = None
        self._addresscallback: Dict[Address, BreakCallBack] = {}
        self._pcodecallback: Dict[int, BreakCallBack] = {}

    def registerPcodeCallback(self, name: str, func: BreakCallBack) -> None:
        """Register a breakpoint for a user-defined pcode op by name.

        C++ ref: BreakTableCallBack::registerPcodeCallback
        """
        func.setEmulate(self._emulate)
        userops: List[str] = []
        if hasattr(self._trans, 'getUserOpNames'):
            self._trans.getUserOpNames(userops)
        for i, opname in enumerate(userops):
            if opname == name:
                self._pcodecallback[i] = func
                return
        raise LowlevelError(f"Bad userop name: {name}")

    def registerAddressCallback(self, addr: Address, func: BreakCallBack) -> None:
        """Register a breakpoint at a specific address.

        C++ ref: BreakTableCallBack::registerAddressCallback
        """
        func.setEmulate(self._emulate)
        self._addresscallback[addr] = func

    def setEmulate(self, emu: Emulate) -> None:
        """C++ ref: BreakTableCallBack::setEmulate"""
        self._emulate = emu
        for cb in self._addresscallback.values():
            cb.setEmulate(emu)
        for cb in self._pcodecallback.values():
            cb.setEmulate(emu)

    def doPcodeOpBreak(self, op: PcodeOpRaw) -> bool:
        """C++ ref: BreakTableCallBack::doPcodeOpBreak"""
        val = op.getInput(0).offset
        cb = self._pcodecallback.get(val)
        if cb is None:
            return False
        return cb.pcodeCallback(op)

    def doAddressBreak(self, addr: Address) -> bool:
        """C++ ref: BreakTableCallBack::doAddressBreak"""
        cb = self._addresscallback.get(addr)
        if cb is None:
            return False
        return cb.addressCallback(addr)


# =========================================================================
# Emulate base (abstract dispatch loop)
# =========================================================================

class Emulate:
    """Abstract base for P-code emulators.

    C++ ref: Emulate
    Subclasses must implement the execute* and fallthruOp methods.
    """

    def __init__(self) -> None:
        self.currentOp: Optional[PcodeOpRaw] = None
        self.currentBehave: Optional[OpBehavior] = None
        self.emu_halted: bool = True

    def setHalt(self, val: bool) -> None:
        self.emu_halted = val

    def getHalt(self) -> bool:
        return self.emu_halted

    # -- abstract interface (subclasses must implement) --

    def setExecuteAddress(self, addr: Address) -> None:
        raise NotImplementedError

    def getExecuteAddress(self) -> Address:
        raise NotImplementedError

    def executeUnary(self) -> None:
        raise NotImplementedError

    def executeBinary(self) -> None:
        raise NotImplementedError

    def executeLoad(self) -> None:
        raise NotImplementedError

    def executeStore(self) -> None:
        raise NotImplementedError

    def executeBranch(self) -> None:
        raise NotImplementedError

    def executeCbranch(self) -> bool:
        raise NotImplementedError

    def executeBranchind(self) -> None:
        raise NotImplementedError

    def executeCall(self) -> None:
        raise NotImplementedError

    def executeCallind(self) -> None:
        raise NotImplementedError

    def executeCallother(self) -> None:
        raise NotImplementedError

    def executeMultiequal(self) -> None:
        raise NotImplementedError

    def executeIndirect(self) -> None:
        raise NotImplementedError

    def executeSegmentOp(self) -> None:
        raise NotImplementedError

    def executeCpoolRef(self) -> None:
        raise NotImplementedError

    def executeNew(self) -> None:
        raise NotImplementedError

    def fallthruOp(self) -> None:
        raise NotImplementedError

    # -- main dispatch (C++ ref: Emulate::executeCurrentOp) --

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
# EmulateMemory — raw PcodeOpRaw emulation using MemoryState
# =========================================================================

class EmulateMemory(Emulate):
    """Emulator that operates on raw PcodeOpRaw using a MemoryState.

    C++ ref: EmulateMemory
    """

    def __init__(self, memstate: MemoryState) -> None:
        super().__init__()
        self.memstate: MemoryState = memstate

    def getMemoryState(self) -> MemoryState:
        return self.memstate

    def executeUnary(self) -> None:
        """C++ ref: EmulateMemory::executeUnary"""
        in1 = self.memstate.getValue(
            self.currentOp.getInput(0).space,
            self.currentOp.getInput(0).offset,
            self.currentOp.getInput(0).size)
        out = self.currentBehave.evaluateUnary(
            self.currentOp.getOutput().size,
            self.currentOp.getInput(0).size, in1)
        self.memstate.setValue(
            self.currentOp.getOutput().space,
            self.currentOp.getOutput().offset,
            self.currentOp.getOutput().size, out)

    def executeBinary(self) -> None:
        """C++ ref: EmulateMemory::executeBinary"""
        in1 = self.memstate.getValue(
            self.currentOp.getInput(0).space,
            self.currentOp.getInput(0).offset,
            self.currentOp.getInput(0).size)
        in2 = self.memstate.getValue(
            self.currentOp.getInput(1).space,
            self.currentOp.getInput(1).offset,
            self.currentOp.getInput(1).size)
        out = self.currentBehave.evaluateBinary(
            self.currentOp.getOutput().size,
            self.currentOp.getInput(0).size, in1, in2)
        self.memstate.setValue(
            self.currentOp.getOutput().space,
            self.currentOp.getOutput().offset,
            self.currentOp.getOutput().size, out)

    def executeLoad(self) -> None:
        """C++ ref: EmulateMemory::executeLoad"""
        off = self.memstate.getValue(
            self.currentOp.getInput(1).space,
            self.currentOp.getInput(1).offset,
            self.currentOp.getInput(1).size)
        spc = self.currentOp.getInput(0).getSpaceFromConst()
        off = AddrSpace.addressToByte(off, spc.getWordSize())
        res = self.memstate.getValue(spc, off, self.currentOp.getOutput().size)
        self.memstate.setValue(
            self.currentOp.getOutput().space,
            self.currentOp.getOutput().offset,
            self.currentOp.getOutput().size, res)

    def executeStore(self) -> None:
        """C++ ref: EmulateMemory::executeStore"""
        val = self.memstate.getValue(
            self.currentOp.getInput(2).space,
            self.currentOp.getInput(2).offset,
            self.currentOp.getInput(2).size)
        off = self.memstate.getValue(
            self.currentOp.getInput(1).space,
            self.currentOp.getInput(1).offset,
            self.currentOp.getInput(1).size)
        spc = self.currentOp.getInput(0).getSpaceFromConst()
        off = AddrSpace.addressToByte(off, spc.getWordSize())
        self.memstate.setValue(spc, off, self.currentOp.getInput(2).size, val)

    def executeBranch(self) -> None:
        """C++ ref: EmulateMemory::executeBranch"""
        self.setExecuteAddress(self.currentOp.getInput(0).getAddr())

    def executeCbranch(self) -> bool:
        """C++ ref: EmulateMemory::executeCbranch"""
        cond = self.memstate.getValue(
            self.currentOp.getInput(1).space,
            self.currentOp.getInput(1).offset,
            self.currentOp.getInput(1).size)
        return cond != 0

    def executeBranchind(self) -> None:
        """C++ ref: EmulateMemory::executeBranchind"""
        off = self.memstate.getValue(
            self.currentOp.getInput(0).space,
            self.currentOp.getInput(0).offset,
            self.currentOp.getInput(0).size)
        self.setExecuteAddress(Address(self.currentOp.getAddr().getSpace(), off))

    def executeCall(self) -> None:
        """C++ ref: EmulateMemory::executeCall"""
        self.setExecuteAddress(self.currentOp.getInput(0).getAddr())

    def executeCallind(self) -> None:
        """C++ ref: EmulateMemory::executeCallind"""
        off = self.memstate.getValue(
            self.currentOp.getInput(0).space,
            self.currentOp.getInput(0).offset,
            self.currentOp.getInput(0).size)
        self.setExecuteAddress(Address(self.currentOp.getAddr().getSpace(), off))

    def executeCallother(self) -> None:
        raise LowlevelError("CALLOTHER emulation not currently supported")

    def executeMultiequal(self) -> None:
        raise LowlevelError("MULTIEQUAL appearing in unheritaged code?")

    def executeIndirect(self) -> None:
        raise LowlevelError("INDIRECT appearing in unheritaged code?")

    def executeSegmentOp(self) -> None:
        raise LowlevelError("SEGMENTOP emulation not currently supported")

    def executeCpoolRef(self) -> None:
        raise LowlevelError("Cannot currently emulate cpool operator")

    def executeNew(self) -> None:
        raise LowlevelError("Cannot currently emulate new operator")


# =========================================================================
# EmulatePcodeCache — caches decoded instruction p-code
# =========================================================================

class EmulatePcodeCache(EmulateMemory):
    """Emulator that caches the p-code translation of machine instructions.

    C++ ref: EmulatePcodeCache
    """

    def __init__(self, trans: Translate, memstate: MemoryState,
                 breaktable: BreakTable) -> None:
        super().__init__(memstate)
        self._trans: Translate = trans
        self._inst: List[Optional[OpBehavior]] = OpBehavior.registerInstructions(trans)
        self._breaktable: BreakTable = breaktable
        self._breaktable.setEmulate(self)
        self._opcache: List[PcodeOpRaw] = []
        self._varcache: List[VarnodeData] = []
        self._current_op: int = 0
        self._current_address: Address = Address()
        self._instruction_length: int = 0
        self._instruction_start: bool = True

    def clearCache(self) -> None:
        """C++ ref: EmulatePcodeCache::clearCache"""
        self._opcache.clear()
        self._varcache.clear()

    def createInstruction(self, addr: Address) -> None:
        """Translate machine instruction at addr into cached p-code.

        C++ ref: EmulatePcodeCache::createInstruction
        """
        self.clearCache()
        from ghidra.emulate.emulateutil import PcodeEmitCache
        emit = PcodeEmitCache(self._opcache, self._varcache, self._inst, 0)
        self._instruction_length = self._trans.oneInstruction(emit, addr)
        self._current_op = 0
        self._instruction_start = True

    def establishOp(self) -> None:
        """Set currentOp and currentBehave from the cache index.

        C++ ref: EmulatePcodeCache::establishOp
        """
        if self._current_op < len(self._opcache):
            self.currentOp = self._opcache[self._current_op]
            self.currentBehave = self.currentOp.getBehavior()
            return
        self.currentOp = None
        self.currentBehave = None

    def fallthruOp(self) -> None:
        """Advance to next cached op or next instruction.

        C++ ref: EmulatePcodeCache::fallthruOp
        """
        self._instruction_start = False
        self._current_op += 1
        if self._current_op >= len(self._opcache):
            self._current_address = Address(
                self._current_address.getSpace(),
                self._current_address.getOffset() + self._instruction_length)
            self.createInstruction(self._current_address)
        self.establishOp()

    def executeBranch(self) -> None:
        """Handle BRANCH with intra-instruction relative targets.

        C++ ref: EmulatePcodeCache::executeBranch
        """
        destaddr = self.currentOp.getInput(0).getAddr()
        if destaddr.isConstant():
            rel = destaddr.getOffset()
            if rel >= 0x80000000:
                rel -= 0x100000000
            idx = self._current_op + int(rel)
            self._current_op = idx
            if self._current_op == len(self._opcache):
                self.fallthruOp()
            elif self._current_op < 0 or self._current_op >= len(self._opcache):
                raise LowlevelError("Bad intra-instruction branch")
            else:
                self.establishOp()
        else:
            self.setExecuteAddress(destaddr)

    def executeCallother(self) -> None:
        """C++ ref: EmulatePcodeCache::executeCallother"""
        if not self._breaktable.doPcodeOpBreak(self.currentOp):
            raise LowlevelError("Userop not hooked")
        self.fallthruOp()

    def setExecuteAddress(self, addr: Address) -> None:
        """Set execution address and cache new instruction.

        C++ ref: EmulatePcodeCache::setExecuteAddress
        """
        self._current_address = Address(addr.getSpace(), addr.getOffset())
        self.createInstruction(self._current_address)
        self.establishOp()

    def getExecuteAddress(self) -> Address:
        return self._current_address

    def executeInstruction(self) -> None:
        """Execute a full machine instruction (like a debugger step).

        C++ ref: EmulatePcodeCache::executeInstruction
        """
        if self._instruction_start:
            if self._breaktable.doAddressBreak(self._current_address):
                return
        while True:
            self.executeCurrentOp()
            if self._instruction_start:
                break
