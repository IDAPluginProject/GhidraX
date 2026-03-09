"""
Corresponds to: override.hh / override.cc

A system for sending override commands to the decompiler.
Overrides for prototypes, indirect calls, dead code, flow, goto, and multistage jumps.
"""

from __future__ import annotations

from typing import Dict, List, Optional

from ghidra.core.address import Address

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
        self._forcegoto: Dict[int, Address] = {}
        self._deadcodedelay: List[int] = []
        self._indirectover: Dict[int, Address] = {}
        self._protoover: Dict[int, object] = {}
        self._multistagejump: List[Address] = []
        self._flowoverride: Dict[int, int] = {}

    def clear(self) -> None:
        self._forcegoto.clear()
        self._deadcodedelay.clear()
        self._indirectover.clear()
        self._protoover.clear()
        self._multistagejump.clear()
        self._flowoverride.clear()

    def insertForceGoto(self, targetpc: Address, destpc: Address) -> None:
        self._forcegoto[targetpc.getOffset()] = destpc

    def insertDeadcodeDelay(self, spc, delay: int) -> None:
        idx = spc.getIndex() if hasattr(spc, 'getIndex') else 0
        while idx >= len(self._deadcodedelay):
            self._deadcodedelay.append(0)
        self._deadcodedelay[idx] = delay

    def hasDeadcodeDelay(self, spc) -> bool:
        idx = spc.getIndex() if hasattr(spc, 'getIndex') else 0
        if idx >= len(self._deadcodedelay):
            return False
        return self._deadcodedelay[idx] != 0

    def getDeadcodeDelay(self, spc) -> int:
        idx = spc.getIndex() if hasattr(spc, 'getIndex') else 0
        if idx >= len(self._deadcodedelay):
            return 0
        return self._deadcodedelay[idx]

    def insertIndirectOverride(self, callpoint: Address, directcall: Address) -> None:
        self._indirectover[callpoint.getOffset()] = directcall

    def insertProtoOverride(self, callpoint: Address, proto) -> None:
        self._protoover[callpoint.getOffset()] = proto

    def insertMultistageJump(self, addr: Address) -> None:
        self._multistagejump.append(addr)

    def insertFlowOverride(self, addr: Address, tp: int) -> None:
        if tp == Override.NONE:
            self._flowoverride.pop(addr.getOffset(), None)
        else:
            self._flowoverride[addr.getOffset()] = tp

    def queryMultistageJumptable(self, addr: Address) -> bool:
        for a in self._multistagejump:
            if a == addr:
                return True
        return False

    def hasFlowOverride(self) -> bool:
        return len(self._flowoverride) > 0

    def getFlowOverride(self, addr: Address) -> int:
        return self._flowoverride.get(addr.getOffset(), Override.NONE)

    def getForceGoto(self, targetpc: Address) -> Optional[Address]:
        return self._forcegoto.get(targetpc.getOffset())

    def getIndirectOverride(self, callpoint: Address) -> Optional[Address]:
        return self._indirectover.get(callpoint.getOffset())

    def getProtoOverride(self, callpoint: Address):
        return self._protoover.get(callpoint.getOffset())

    def applyPrototype(self, data, fspecs) -> None:
        """Apply any prototype override to a FuncCallSpecs."""
        addr = fspecs.getOp().getAddr() if hasattr(fspecs, 'getOp') else None
        if addr is None:
            return
        proto = self.getProtoOverride(addr)
        if proto is not None and hasattr(fspecs, 'setForcedPrototype'):
            fspecs.setForcedPrototype(proto)

    def applyIndirect(self, data, fspecs) -> None:
        """Apply any indirect call override."""
        addr = fspecs.getOp().getAddr() if hasattr(fspecs, 'getOp') else None
        if addr is None:
            return
        direct = self.getIndirectOverride(addr)
        if direct is not None and hasattr(fspecs, 'setDirectCall'):
            fspecs.setDirectCall(direct)

    def applyDeadCodeDelay(self, data) -> None:
        """Apply dead code delay overrides to the function."""
        pass

    def applyForceGoto(self, data) -> None:
        """Apply forced goto overrides."""
        pass

    def printRaw(self, s, glb=None) -> None:
        """Dump a description of the overrides to stream."""
        for targetpc, destpc in self._forcegoto.items():
            s.write(f"override forcegoto at {targetpc:#x} to {destpc}\n")
        for i, delay in enumerate(self._deadcodedelay):
            if delay >= 0:
                spc_name = glb.getSpace(i).getName() if glb and hasattr(glb, 'getSpace') else f"space_{i}"
                s.write(f"override deadcodedelay for {spc_name} to {delay}\n")
        for callpoint, directcall in self._indirectover.items():
            s.write(f"override indirect at {callpoint:#x} to call directly to {directcall}\n")
        for callpoint, proto in self._protoover.items():
            s.write(f"override prototype at {callpoint:#x}\n")
        for addr in self._multistagejump:
            s.write(f"multistage jump at {addr}\n")
        for addr, tp in self._flowoverride.items():
            s.write(f"override flow at {addr:#x} to {Override.typeToString(tp)}\n")

    def generateOverrideMessages(self, glb=None) -> list:
        """Create warning messages that describe current overrides."""
        messagelist = []
        for i, delay in enumerate(self._deadcodedelay):
            if delay >= 0:
                spc_name = glb.getSpace(i).getName() if glb and hasattr(glb, 'getSpace') else f"space_{i}"
                messagelist.append(
                    f"Restarted to delay deadcode elimination for space: {spc_name}")
        return messagelist

    def encode(self, encoder, glb=None) -> None:
        """Encode the override commands to a stream."""
        if (not self._forcegoto and not self._deadcodedelay and
                not self._indirectover and not self._protoover and
                not self._multistagejump and not self._flowoverride):
            return
        encoder.openElement(ELEM_OVERRIDE)
        for targetpc, destpc in self._forcegoto.items():
            encoder.openElement(ELEM_FORCEGOTO)
            Address(None, targetpc).encode(encoder) if isinstance(targetpc, int) else targetpc.encode(encoder)
            destpc.encode(encoder)
            encoder.closeElement(ELEM_FORCEGOTO)
        for i, delay in enumerate(self._deadcodedelay):
            if delay < 0:
                continue
            encoder.openElement(ELEM_DEADCODEDELAY)
            if glb and hasattr(glb, 'getSpace'):
                encoder.writeSpace(ATTRIB_SPACE, glb.getSpace(i))
            encoder.writeSignedInteger(ATTRIB_DELAY, delay)
            encoder.closeElement(ELEM_DEADCODEDELAY)
        for callpoint, directcall in self._indirectover.items():
            encoder.openElement(ELEM_INDIRECTOVERRIDE)
            Address(None, callpoint).encode(encoder) if isinstance(callpoint, int) else callpoint.encode(encoder)
            directcall.encode(encoder)
            encoder.closeElement(ELEM_INDIRECTOVERRIDE)
        for callpoint, proto in self._protoover.items():
            encoder.openElement(ELEM_PROTOOVERRIDE)
            Address(None, callpoint).encode(encoder) if isinstance(callpoint, int) else callpoint.encode(encoder)
            if hasattr(proto, 'encode'):
                proto.encode(encoder)
            encoder.closeElement(ELEM_PROTOOVERRIDE)
        for addr in self._multistagejump:
            encoder.openElement(ELEM_MULTISTAGEJUMP)
            addr.encode(encoder)
            encoder.closeElement(ELEM_MULTISTAGEJUMP)
        for addr, tp in self._flowoverride.items():
            encoder.openElement(ELEM_FLOW)
            encoder.writeString(ATTRIB_TYPE, Override.typeToString(tp))
            Address(None, addr).encode(encoder) if isinstance(addr, int) else addr.encode(encoder)
            encoder.closeElement(ELEM_FLOW)
        encoder.closeElement(ELEM_OVERRIDE)

    def decode(self, decoder, glb=None) -> None:
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
                if glb is not None:
                    fp.setInternal(glb.defaultfp, glb.types.getTypeVoid() if glb.types else None)
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
                    raise RuntimeError("Bad deadcodedelay tag")
                self.insertDeadcodeDelay(spc, delay)
            elif subId == ELEM_MULTISTAGEJUMP:
                callpoint = Address.decode(decoder)
                self.insertMultistageJump(callpoint)
            elif subId == ELEM_FLOW:
                tp = Override.stringToType(decoder.readString(ATTRIB_TYPE))
                addr = Address.decode(decoder)
                if tp == Override.NONE or addr.isInvalid():
                    raise RuntimeError("Bad flowoverride tag")
                self.insertFlowOverride(addr, tp)
            decoder.closeElement(subId)
        decoder.closeElement(elemId)

    @staticmethod
    def typeToString(tp: int) -> str:
        _map = {0: "none", 1: "branch", 2: "call", 3: "callreturn", 4: "return"}
        return _map.get(tp, "unknown")

    @staticmethod
    def stringToType(nm: str) -> int:
        _map = {"none": 0, "branch": 1, "call": 2, "callreturn": 3, "return": 4}
        return _map.get(nm.lower(), 0)
