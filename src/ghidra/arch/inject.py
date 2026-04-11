"""
Corresponds to: inject_sleigh.hh / inject_sleigh.cc / pcodeinject.hh

P-code injection library for call fixups, callother fixups, and executable p-code.
"""

from __future__ import annotations
from typing import Optional, List, Dict
from ghidra.core.address import Address
from ghidra.core.error import LowlevelError


class InjectParameter:
    """An input or output parameter to a p-code injection payload."""

    def __init__(self, nm: str, sz: int) -> None:
        self.name: str = nm
        self.index: int = 0
        self.size: int = sz

    def getName(self) -> str:
        return self.name

    def getIndex(self) -> int:
        return self.index

    def getSize(self) -> int:
        return self.size


class InjectPayload:
    """A snippet of p-code that can be injected at various points."""

    CALLFIXUP_TYPE = 1
    CALLOTHERFIXUP_TYPE = 2
    CALLMECHANISM_TYPE = 3
    EXECUTABLEPCODE_TYPE = 4

    def __init__(self, nm: str = "", tp: int = 0) -> None:
        self.name: str = nm
        self.type: int = tp
        self.paramshift: int = 0
        self.dynamic: bool = False
        self.incidentalcopy: bool = False
        self.inputlist: List[InjectParameter] = []
        self.output: List[InjectParameter] = []

    def getName(self) -> str:
        return self.name

    def getType(self) -> int:
        return self.type

    def getParamShift(self) -> int:
        return self.paramshift

    def isDynamic(self) -> bool:
        return self.dynamic

    def isIncidentalCopy(self) -> bool:
        return self.incidentalcopy

    @staticmethod
    def decodeParameter(decoder) -> tuple[str, int]:
        """Parse one <input> or <output> element."""
        from ghidra.core.marshal import ATTRIB_NAME, ATTRIB_SIZE

        name = ""
        size = 0
        elemId = decoder.openElement()
        while True:
            attribId = decoder.getNextAttributeId()
            if attribId == 0:
                break
            if attribId == ATTRIB_NAME.id:
                name = decoder.readString()
            elif attribId == ATTRIB_SIZE.id:
                size = decoder.readUnsignedInteger()
        decoder.closeElement(elemId)
        if len(name) == 0:
            raise LowlevelError("Missing inject parameter name")
        return name, size

    def orderParameters(self) -> None:
        """Assign stable parameter indices: inputs first, then outputs."""
        ident = 0
        for param in self.inputlist:
            param.index = ident
            ident += 1
        for param in self.output:
            param.index = ident
            ident += 1

    def decodePayloadAttributes(self, decoder) -> None:
        """Decode attributes of the current <pcode> element."""
        from ghidra.core.marshal import (
            ATTRIB_DYNAMIC,
            ATTRIB_INCIDENTALCOPY,
            ATTRIB_INJECT,
            ATTRIB_PARAMSHIFT,
        )

        self.paramshift = 0
        self.dynamic = False
        for _ in range(1 << 30):
            attribId = decoder.getNextAttributeId()
            if attribId == 0:
                break
            if attribId == ATTRIB_PARAMSHIFT.id:
                self.paramshift = decoder.readSignedInteger()
            elif attribId == ATTRIB_DYNAMIC.id:
                self.dynamic = decoder.readBool()
            elif attribId == ATTRIB_INCIDENTALCOPY.id:
                self.incidentalcopy = decoder.readBool()
            elif attribId == ATTRIB_INJECT.id:
                uponType = decoder.readString()
                if uponType == "uponentry":
                    self.name = self.name + "@@inject_uponentry"
                else:
                    self.name = self.name + "@@inject_uponreturn"

    def decodePayloadParams(self, decoder) -> None:
        """Decode any <input> and <output> children of the current <pcode>."""
        from ghidra.core.marshal import ELEM_INPUT, ELEM_OUTPUT

        for _ in range(1 << 30):
            subId = decoder.peekElement()
            if subId == ELEM_INPUT.id:
                paramName, size = self.decodeParameter(decoder)
                self.inputlist.append(InjectParameter(paramName, size))
            elif subId == ELEM_OUTPUT.id:
                paramName, size = self.decodeParameter(decoder)
                self.output.append(InjectParameter(paramName, size))
            else:
                break
        self.orderParameters()

    def _decodePayloadAttributesElement(self, el) -> None:
        """Decode <pcode> attributes from an ElementTree element."""
        self.paramshift = int(el.get("paramshift", "0")) if el.get("paramshift") else 0
        self.dynamic = el.get("dynamic", "false").lower() == "true"
        self.incidentalcopy = el.get("incidentalcopy", "false").lower() == "true"
        inject_type = el.get("inject")
        if inject_type == "uponentry":
            self.name = self.name + "@@inject_uponentry"
        elif inject_type:
            self.name = self.name + "@@inject_uponreturn"

    def _decodePayloadParamsElement(self, el) -> None:
        """Decode <input>/<output> children from an ElementTree <pcode> element."""
        for child in el:
            if child.tag == "input":
                name = child.get("name", "")
                if not name:
                    raise LowlevelError("Missing inject parameter name")
                size = int(child.get("size", "0"))
                self.inputlist.append(InjectParameter(name, size))
            elif child.tag == "output":
                name = child.get("name", "")
                if not name:
                    raise LowlevelError("Missing inject parameter name")
                size = int(child.get("size", "0"))
                self.output.append(InjectParameter(name, size))
        self.orderParameters()

    def sizeInput(self) -> int:
        return len(self.inputlist)

    def sizeOutput(self) -> int:
        return len(self.output)

    def getInput(self, i: int) -> InjectParameter:
        return self.inputlist[i]

    def getOutput(self, i: int) -> InjectParameter:
        return self.output[i]

    def __del__(self) -> None:
        pass

    def inject(self, context, emit) -> None:
        raise NotImplementedError("InjectPayload.inject is pure virtual")

    def encode(self, encoder) -> None:
        pass

    def decode(self, decoder) -> None:
        raise NotImplementedError("InjectPayload.decode is pure virtual")

    def printTemplate(self, s) -> None:
        raise NotImplementedError("InjectPayload.printTemplate is pure virtual")

    def getSource(self) -> str:
        raise NotImplementedError("InjectPayload.getSource is pure virtual")


class InjectPayloadSleigh(InjectPayload):
    """An injection payload built by the SLEIGH engine.

    The p-code ops for the injection are described using SLEIGH syntax.
    """

    def __init__(self, src: str = "", nm: str = "", tp: int = 0) -> None:
        super().__init__(nm, tp)
        self.source: str = src
        self.parsestring: str = ""
        self.tpl = None  # ConstructTpl

    def __del__(self) -> None:
        self.tpl = None

    def decodeBody(self, decoder) -> None:
        """Decode the optional <body> subtag as raw p-code source."""
        from ghidra.core.marshal import ATTRIB_CONTENT, ELEM_BODY

        elemId = decoder.openElement()
        if elemId == ELEM_BODY:
            self.parsestring = decoder.readString(ATTRIB_CONTENT)
            decoder.closeElement(elemId)
        if len(self.parsestring) == 0 and (not self.dynamic):
            raise LowlevelError("Missing <body> subtag in <pcode>: " + self.getSource())

    def inject(self, context, emit) -> None:
        """Inject p-code into the given context and emitter."""
        from ghidra.core.opcodes import OpCode
        from ghidra.core.pcoderaw import VarnodeData

        if self.tpl is None:
            raise LowlevelError("Inject payload template has not been compiled: " + self.getSource())

        baseaddr = context.baseaddr
        nextaddr = context.nextaddr
        calladdr = getattr(context, "calladdr", Address())
        if calladdr is None:
            calladdr = Address()

        raw_ops = self.tpl.inject(
            baseaddr.getSpace().getName() if baseaddr.getSpace() is not None else "",
            baseaddr.getOffset(),
            nextaddr.getSpace().getName() if nextaddr.getSpace() is not None else "",
            nextaddr.getOffset(),
            calladdr.getSpace().getName() if calladdr.getSpace() is not None else "",
            calladdr.getOffset(),
            [
                (vn.space.getName() if vn.space is not None else "", vn.offset, vn.size)
                for vn in context.inputlist
            ],
            [
                (vn.space.getName() if vn.space is not None else "", vn.offset, vn.size)
                for vn in context.output
            ],
        )

        glb = getattr(context, "glb", None)
        if glb is None:
            raise LowlevelError("InjectContextSleigh is missing architecture binding")

        for raw_op in raw_ops:
            outvar = None
            out_desc = raw_op.get("output")
            if out_desc is not None:
                outvar = VarnodeData(
                    glb.getSpaceByName(out_desc["space"]),
                    out_desc["offset"],
                    out_desc["size"],
                )

            vars_: List[VarnodeData] = []
            for inp_desc in raw_op["inputs"]:
                vn = VarnodeData(
                    glb.getSpaceByName(inp_desc["space"]),
                    inp_desc["offset"],
                    inp_desc["size"],
                )
                space_ref_name = inp_desc.get("space_ref")
                if space_ref_name:
                    vn.setSpaceFromConst(glb.getSpaceByName(space_ref_name))
                vars_.append(vn)

            emit.dump(baseaddr, OpCode(raw_op["opcode"]), outvar, vars_, len(vars_))

    def decode(self, decoder) -> None:
        """Decode this payload from a stream."""
        from ghidra.core.marshal import ELEM_PCODE

        if hasattr(decoder, "tag"):
            self._decodePayloadAttributesElement(decoder)
            self._decodePayloadParamsElement(decoder)
            self._decodeBodyElement(decoder)
            return

        elemId = decoder.openElement(ELEM_PCODE)
        self.decodePayloadAttributes(decoder)
        self.decodePayloadParams(decoder)
        self.decodeBody(decoder)
        decoder.closeElement(elemId)

    def printTemplate(self, s) -> None:
        """Print the p-code template to stream."""
        if self.tpl is not None and hasattr(self.tpl, "print_template"):
            s.write(self.tpl.print_template())
        elif self.tpl is not None:
            s.write(str(self.tpl))
        else:
            s.write(self.parsestring)

    def getSource(self) -> str:
        """Return a description of the document containing the SLEIGH syntax."""
        return self.source

    @staticmethod
    def checkParameterRestrictions(con, inputlist: list, output: list, source: str) -> None:
        """Check that the parameters for injection are valid."""
        if len(inputlist) != len(con.inputlist):
            raise LowlevelError(
                "Injection parameter list has different number of parameters than p-code operation: "
                + source
            )
        for i, param in enumerate(inputlist):
            sz = param.getSize()
            if sz != 0 and sz != con.inputlist[i].size:
                raise LowlevelError(
                    "P-code input parameter size does not match injection specification: " + source
                )
        if len(output) != len(con.output):
            raise LowlevelError("Injection output does not match output of p-code operation: " + source)
        for i, param in enumerate(output):
            sz = param.getSize()
            if sz != 0 and sz != con.output[i].size:
                raise LowlevelError(
                    "P-code output size does not match injection specification: " + source
                )

    @staticmethod
    def setupParameters(con, walker, inputlist: list, output: list, source: str) -> None:
        """Set up injection parameters in the parsing context."""
        InjectPayloadSleigh.checkParameterRestrictions(con, inputlist, output, source)
        pos = walker.getParserContext()
        for i, param in enumerate(inputlist):
            pos.allocateOperand(param.getIndex(), walker)
            data = con.inputlist[i]
            hand = walker.getParentHandle()
            hand.space = data.space
            hand.offset_offset = data.offset
            hand.size = data.size
            hand.offset_space = None
            walker.popOperand()
        for i, param in enumerate(output):
            pos.allocateOperand(param.getIndex(), walker)
            data = con.output[i]
            hand = walker.getParentHandle()
            hand.space = data.space
            hand.offset_offset = data.offset
            hand.size = data.size
            hand.offset_space = None
            walker.popOperand()

    def _decodeBodyElement(self, el) -> None:
        for child in el:
            if child.tag == "body":
                content = child.get("content")
                if content is None:
                    content = child.text or ""
                self.parsestring = content.strip()
                break
        if len(self.parsestring) == 0 and (not self.dynamic):
            raise LowlevelError("Missing <body> subtag in <pcode>: " + self.getSource())


class InjectContext:
    """Context for a particular p-code injection site."""

    def __init__(self) -> None:
        self.glb = None
        self.baseaddr: Address = Address()
        self.nextaddr: Address = Address()
        self.calladdr: Address = Address()
        self.inputlist: list = []
        self.output: list = []

    def clear(self) -> None:
        self.inputlist.clear()
        self.output.clear()

    def __del__(self) -> None:
        pass

    def encode(self, encoder) -> None:
        raise NotImplementedError("InjectContext.encode is pure virtual")


class PcodeInjectLibrary:
    """A library of p-code injection payloads.

    Manages call fixups, callother fixups, and executable p-code snippets.
    Each payload is registered by name and assigned a unique id.
    """

    def __init__(self, glb=None, tmpbase: int = 0) -> None:
        self.glb = glb
        self.tempbase: int = tmpbase
        self._payloads: List[InjectPayload] = []
        self._namemap: Dict[str, int] = {}
        self._callFixupMap: Dict[str, int] = {}
        self._callOtherFixupMap: Dict[str, int] = {}
        self._callMechMap: Dict[str, int] = {}
        self._exePcodeMap: Dict[str, int] = {}
        self._callFixupNames: List[str] = []
        self._callOtherTargets: List[str] = []
        self._callMechNames: List[str] = []
        self._scriptNames: List[str] = []

    def __del__(self) -> None:
        self._payloads.clear()

    def registerPayload(self, payload: InjectPayload) -> int:
        idx = len(self._payloads)
        self._payloads.append(payload)
        self._namemap[payload.name] = idx
        if payload.type == InjectPayload.CALLFIXUP_TYPE:
            self._callFixupMap[payload.name] = idx
        elif payload.type == InjectPayload.CALLOTHERFIXUP_TYPE:
            self._callOtherFixupMap[payload.name] = idx
        elif payload.type == InjectPayload.CALLMECHANISM_TYPE:
            self._callMechMap[payload.name] = idx
        elif payload.type == InjectPayload.EXECUTABLEPCODE_TYPE:
            self._exePcodeMap[payload.name] = idx
        return idx

    def getPayload(self, idx: int) -> Optional[InjectPayload]:
        if 0 <= idx < len(self._payloads):
            return self._payloads[idx]
        return None

    def getPayloadByName(self, nm: str) -> Optional[InjectPayload]:
        idx = self._namemap.get(nm)
        if idx is not None:
            return self._payloads[idx]
        return None

    def getUniqueBase(self) -> int:
        return self.tempbase

    def getPayloadId(self, tp_or_name, nm: Optional[str] = None) -> int:
        if nm is None:
            return self._namemap.get(tp_or_name, -1)

        tp = tp_or_name
        if tp == InjectPayload.CALLFIXUP_TYPE:
            return self._callFixupMap.get(nm, -1)
        if tp == InjectPayload.CALLOTHERFIXUP_TYPE:
            return self._callOtherFixupMap.get(nm, -1)
        if tp == InjectPayload.CALLMECHANISM_TYPE:
            return self._callMechMap.get(nm, -1)
        return self._exePcodeMap.get(nm, -1)

    def numPayloads(self) -> int:
        return len(self._payloads)

    def getCallFixupId(self, nm: str) -> int:
        return self._callFixupMap.get(nm, -1)

    def getCallOtherFixupId(self, nm: str) -> int:
        return self._callOtherFixupMap.get(nm, -1)

    def getCallMechanismId(self, nm: str) -> int:
        return self._callMechMap.get(nm, -1)

    def hasCallFixup(self, nm: str) -> bool:
        return nm in self._callFixupMap

    def hasCallOtherFixup(self, nm: str) -> bool:
        return nm in self._callOtherFixupMap

    def registerCallFixup(self, fixupName: str, injectid: int) -> None:
        if fixupName in self._callFixupMap:
            raise LowlevelError("Duplicate <callfixup>: " + fixupName)
        self._callFixupMap[fixupName] = injectid
        while len(self._callFixupNames) <= injectid:
            self._callFixupNames.append("")
        self._callFixupNames[injectid] = fixupName

    def registerCallOtherFixup(self, fixupName: str, injectid: int) -> None:
        if fixupName in self._callOtherFixupMap:
            raise LowlevelError("Duplicate <callotherfixup>: " + fixupName)
        self._callOtherFixupMap[fixupName] = injectid
        while len(self._callOtherTargets) <= injectid:
            self._callOtherTargets.append("")
        self._callOtherTargets[injectid] = fixupName

    def registerCallMechanism(self, fixupName: str, injectid: int) -> None:
        if fixupName in self._callMechMap:
            raise LowlevelError("Duplicate <callmechanism>: " + fixupName)
        self._callMechMap[fixupName] = injectid
        while len(self._callMechNames) <= injectid:
            self._callMechNames.append("")
        self._callMechNames[injectid] = fixupName

    def registerExeScript(self, scriptName: str, injectid: int) -> None:
        if scriptName in self._exePcodeMap:
            raise LowlevelError("Duplicate <script>: " + scriptName)
        self._exePcodeMap[scriptName] = injectid
        while len(self._scriptNames) <= injectid:
            self._scriptNames.append("")
        self._scriptNames[injectid] = scriptName

    def getCallFixupName(self, injectid: int) -> str:
        if injectid < 0 or injectid >= len(self._callFixupNames):
            return ""
        return self._callFixupNames[injectid]

    def getCallOtherTarget(self, injectid: int) -> str:
        if injectid < 0 or injectid >= len(self._callOtherTargets):
            return ""
        return self._callOtherTargets[injectid]

    def getCallMechanismName(self, injectid: int) -> str:
        if injectid < 0 or injectid >= len(self._callMechNames):
            return ""
        return self._callMechNames[injectid]

    def decodeInject(self, src: str, nm: str, tp: int, decoder) -> int:
        injectid = self.allocateInject(src, nm, tp)
        payload = self.getPayload(injectid)
        if payload is None:
            raise LowlevelError("Unable to allocate injection payload")
        payload.decode(decoder)
        self.registerInject(injectid)
        return injectid

    def allocateInject(self, sourceName: str, name: str, tp: int) -> int:
        raise NotImplementedError("PcodeInjectLibrary.allocateInject is pure virtual")

    def registerInject(self, injectid: int) -> None:
        raise NotImplementedError("PcodeInjectLibrary.registerInject is pure virtual")

    def manualCallFixup(self, name: str, snippetstring: str) -> int:
        raise NotImplementedError("PcodeInjectLibrary.manualCallFixup is pure virtual")

    def getExePcodeId(self, nm: str) -> int:
        return self._exePcodeMap.get(nm, -1)

    def manualCallOtherFixup(self, name: str, outname: str,
                             inname: list, snippet: str) -> int:
        raise NotImplementedError("PcodeInjectLibrary.manualCallOtherFixup is pure virtual")

    def getExePcodePayload(self, nm: str):
        idx = self._exePcodeMap.get(nm, -1)
        if idx >= 0 and idx < len(self._payloads):
            return self._payloads[idx]
        return None

    def getCachedContext(self):
        raise NotImplementedError("PcodeInjectLibrary.getCachedContext is pure virtual")

    def getBehaviors(self):
        raise NotImplementedError("PcodeInjectLibrary.getBehaviors is pure virtual")

    def decodeDebug(self, decoder) -> None:
        """Decode debug injection information."""
        return None
