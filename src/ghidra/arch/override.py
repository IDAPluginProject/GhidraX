"""
Corresponds to: override.hh / override.cc

A system for sending override commands to the decompiler.
Overrides for prototypes, indirect calls, dead code, flow, goto, and multistage jumps.
"""

from __future__ import annotations

from typing import Dict, List, Optional

from ghidra.core.address import Address
from ghidra.core.error import LowlevelError

# ElementId constants (matching C++ override.cc)
ELEM_DEADCODEDELAY = 218
ELEM_FLOW = 219
ELEM_FORCEGOTO = 220
ELEM_INDIRECTOVERRIDE = 221
ELEM_MULTISTAGEJUMP = 222
ELEM_OVERRIDE = 223
ELEM_PROTOOVERRIDE = 224

# Attribute constants
ATTRIB_SPACE = "space"
ATTRIB_DELAY = "delay"
ATTRIB_TYPE = "type"


class Override:
    """Container of commands that override the decompiler's default behavior for a function.

    Overridable information includes:
      - sub-functions: how they are called and where they call to
      - jumptables: mark indirect jumps needing multistage analysis
      - deadcode: details about dead code elimination
      - data-flow: override interpretation of specific branch instructions
    """

    NONE = 0
    BRANCH = 1
    CALL = 2
    CALL_RETURN = 3
    RETURN = 4

    def __init__(self) -> None:
        self._forcegoto: Dict[Address, Address] = {}
        self._deadcodedelay: List[int] = []
        self._indirectover: Dict[Address, Address] = {}
        self._protoover: Dict[Address, object] = {}
        self._multistagejump: List[Address] = []
        self._flowoverride: Dict[Address, int] = {}

    def __del__(self) -> None:
        self.clear()

    def clear(self) -> None:
        self._forcegoto.clear()
        self._deadcodedelay.clear()
        self._indirectover.clear()
        self._protoover.clear()
        self._multistagejump.clear()
        self._flowoverride.clear()

    def insertForceGoto(self, targetpc: Address, destpc: Address) -> None:
        self._forcegoto[targetpc] = destpc

    @staticmethod
    def generateDeadcodeDelayMessage(index: int, glb) -> str:
        """Generate warning message related to a dead code delay.

        C++ ref: ``Override::generateDeadcodeDelayMessage``
        """
        spc = glb.getSpace(index)
        return f"Restarted to delay deadcode elimination for space: {spc.getName()}"

    def insertDeadcodeDelay(self, spc, delay: int) -> None:
        """Override the dead-code delay for a specific address space.

        C++ ref: ``Override::insertDeadcodeDelay``
        """
        idx = spc.getIndex()
        while idx >= len(self._deadcodedelay):
            self._deadcodedelay.append(-1)
        self._deadcodedelay[idx] = delay

    def hasDeadcodeDelay(self, spc) -> bool:
        """Check if a delay override is already installed for an address space.

        C++ ref: ``Override::hasDeadcodeDelay``
        """
        idx = spc.getIndex()
        if idx >= len(self._deadcodedelay):
            return False
        val = self._deadcodedelay[idx]
        if val == -1:
            return False
        return val != spc.getDeadcodeDelay()

    def getDeadcodeDelay(self, spc) -> int:
        idx = spc.getIndex()
        if idx >= len(self._deadcodedelay):
            return 0
        return self._deadcodedelay[idx]

    def insertIndirectOverride(self, callpoint: Address, directcall: Address) -> None:
        self._indirectover[callpoint] = directcall

    def insertProtoOverride(self, callpoint: Address, proto) -> None:
        """Override the assumed function prototype at a specific call site.

        C++ ref: ``Override::insertProtoOverride``
        """
        if callpoint in self._protoover:
            del self._protoover[callpoint]
        proto.setOverride(True)
        self._protoover[callpoint] = proto

    def insertMultistageJump(self, addr: Address) -> None:
        self._multistagejump.append(addr)

    def insertFlowOverride(self, addr: Address, tp: int) -> None:
        self._flowoverride[addr] = tp

    def queryMultistageJumptable(self, addr: Address) -> bool:
        for a in self._multistagejump:
            if a == addr:
                return True
        return False

    def hasFlowOverride(self) -> bool:
        return len(self._flowoverride) > 0

    def getFlowOverride(self, addr: Address) -> int:
        return self._flowoverride.get(addr, Override.NONE)

    def getForceGoto(self, targetpc: Address) -> Optional[Address]:
        return self._forcegoto.get(targetpc)

    def getIndirectOverride(self, callpoint: Address) -> Optional[Address]:
        return self._indirectover.get(callpoint)

    def getProtoOverride(self, callpoint: Address):
        return self._protoover.get(callpoint)

    def applyPrototype(self, data, fspecs) -> None:
        """Look for and apply a function prototype override.

        C++ ref: ``Override::applyPrototype``
        """
        if not self._protoover:
            return
        op = fspecs.getOp()
        proto = self._protoover.get(op.getAddr())
        if proto is not None:
            fspecs.copy(proto)

    def applyIndirect(self, data, fspecs) -> None:
        """Look for and apply destination overrides of indirect calls.

        C++ ref: ``Override::applyIndirect``
        """
        if not self._indirectover:
            return
        op = fspecs.getOp()
        direct = self._indirectover.get(op.getAddr())
        if direct is not None:
            fspecs.setAddress(direct)

    def applyDeadCodeDelay(self, data) -> None:
        """Apply any dead-code delay overrides to Heritage.

        C++ ref: ``Override::applyDeadCodeDelay``
        """
        glb = data.getArch()
        for i, delay in enumerate(self._deadcodedelay):
            if delay < 0:
                continue
            spc = glb.getSpace(i)
            data.setDeadCodeDelay(spc, delay)

    def applyForceGoto(self, data) -> None:
        """Push all the force-goto overrides into the function.

        C++ ref: ``Override::applyForceGoto``
        """
        for targetpc in sorted(self._forcegoto):
            data.forceGoto(targetpc, self._forcegoto[targetpc])

    def printRaw(self, s, glb) -> None:
        """Dump a description of the overrides to stream."""
        for targetpc in sorted(self._forcegoto):
            s.write(f"force goto at {targetpc} jumping to {self._forcegoto[targetpc]}\n")
        for i, delay in enumerate(self._deadcodedelay):
            if delay >= 0:
                spc = glb.getSpace(i)
                s.write(f"dead code delay on {spc.getName()} set to {delay}\n")
        for callpoint in sorted(self._indirectover):
            s.write(f"override indirect at {callpoint} to call directly to {self._indirectover[callpoint]}\n")
        for callpoint in sorted(self._protoover):
            proto = self._protoover[callpoint]
            s.write(f"override prototype at {callpoint} to {proto.printRaw('func')}\n")

    def generateOverrideMessages(self, messagelist, glb) -> None:
        """Create warning messages that describe current overrides.

        C++ ref: ``Override::generateOverrideMessages``
        """
        for i, delay in enumerate(self._deadcodedelay):
            if delay >= 0:
                messagelist.append(Override.generateDeadcodeDelayMessage(i, glb))

    def encode(self, encoder, glb) -> None:
        """Encode the override commands to a stream."""
        if (not self._forcegoto and not self._deadcodedelay and
                not self._indirectover and not self._protoover and
                not self._multistagejump and not self._flowoverride):
            return
        encoder.openElement(ELEM_OVERRIDE)
        for targetpc in sorted(self._forcegoto):
            destpc = self._forcegoto[targetpc]
            encoder.openElement(ELEM_FORCEGOTO)
            targetpc.encode(encoder)
            destpc.encode(encoder)
            encoder.closeElement(ELEM_FORCEGOTO)
        for i, delay in enumerate(self._deadcodedelay):
            if delay < 0:
                continue
            encoder.openElement(ELEM_DEADCODEDELAY)
            encoder.writeSpace(ATTRIB_SPACE, glb.getSpace(i))
            encoder.writeSignedInteger(ATTRIB_DELAY, delay)
            encoder.closeElement(ELEM_DEADCODEDELAY)
        for callpoint in sorted(self._indirectover):
            directcall = self._indirectover[callpoint]
            encoder.openElement(ELEM_INDIRECTOVERRIDE)
            callpoint.encode(encoder)
            directcall.encode(encoder)
            encoder.closeElement(ELEM_INDIRECTOVERRIDE)
        for callpoint in sorted(self._protoover):
            proto = self._protoover[callpoint]
            encoder.openElement(ELEM_PROTOOVERRIDE)
            callpoint.encode(encoder)
            proto.encode(encoder)
            encoder.closeElement(ELEM_PROTOOVERRIDE)
        for addr in self._multistagejump:
            encoder.openElement(ELEM_MULTISTAGEJUMP)
            addr.encode(encoder)
            encoder.closeElement(ELEM_MULTISTAGEJUMP)
        for addr in sorted(self._flowoverride):
            tp = self._flowoverride[addr]
            encoder.openElement(ELEM_FLOW)
            encoder.writeString(ATTRIB_TYPE, Override.typeToString(tp))
            addr.encode(encoder)
            encoder.closeElement(ELEM_FLOW)
        encoder.closeElement(ELEM_OVERRIDE)

    def decode(self, decoder, glb) -> None:
        """Decode override commands from a stream."""
        elemId = decoder.openElement(ELEM_OVERRIDE)
        while True:
            subId = decoder.openElement()
            if subId == 0:
                break
            if subId == ELEM_INDIRECTOVERRIDE:
                callpoint = Address.decode(decoder)
                directcall = Address.decode(decoder)
                self.insertIndirectOverride(callpoint, directcall)
            elif subId == ELEM_PROTOOVERRIDE:
                callpoint = Address.decode(decoder)
                from ghidra.fspec.fspec import FuncProto
                fp = FuncProto()
                fp.setInternal(glb.defaultfp, glb.types.getTypeVoid())
                fp.decode(decoder, glb)
                self.insertProtoOverride(callpoint, fp)
            elif subId == ELEM_FORCEGOTO:
                targetpc = Address.decode(decoder)
                destpc = Address.decode(decoder)
                self.insertForceGoto(targetpc, destpc)
            elif subId == ELEM_DEADCODEDELAY:
                delay = decoder.readSignedInteger(ATTRIB_DELAY)
                spc = decoder.readSpace(ATTRIB_SPACE)
                if delay < 0:
                    raise LowlevelError("Bad deadcodedelay tag")
                self.insertDeadcodeDelay(spc, delay)
            elif subId == ELEM_MULTISTAGEJUMP:
                callpoint = Address.decode(decoder)
                self.insertMultistageJump(callpoint)
            elif subId == ELEM_FLOW:
                tp = Override.stringToType(decoder.readString(ATTRIB_TYPE))
                addr = Address.decode(decoder)
                if tp == Override.NONE or addr.isInvalid():
                    raise LowlevelError("Bad flowoverride tag")
                self.insertFlowOverride(addr, tp)
            decoder.closeElement(subId)
        decoder.closeElement(elemId)

    @staticmethod
    def typeToString(tp: int) -> str:
        if tp == Override.BRANCH:
            return "branch"
        if tp == Override.CALL:
            return "call"
        if tp == Override.CALL_RETURN:
            return "callreturn"
        if tp == Override.RETURN:
            return "return"
        return "none"

    @staticmethod
    def stringToType(nm: str) -> int:
        if nm == "branch":
            return Override.BRANCH
        if nm == "call":
            return Override.CALL
        if nm == "callreturn":
            return Override.CALL_RETURN
        if nm == "return":
            return Override.RETURN
        return Override.NONE
