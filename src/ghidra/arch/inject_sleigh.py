"""
Corresponds to: inject_sleigh.hh / inject_sleigh.cc

Implementation of p-code injection using the internal SLEIGH engine to build
the p-code ops.  Provides InjectContextSleigh, InjectPayloadCallfixup,
InjectPayloadCallother, ExecutablePcodeSleigh, InjectPayloadDynamic, and
PcodeInjectLibrarySleigh.
"""

from __future__ import annotations

import xml.etree.ElementTree as ET
from typing import Optional, List, Dict, TYPE_CHECKING

from ghidra.core.error import LowlevelError
from ghidra.core.address import Address
from ghidra.core.pcoderaw import VarnodeData
from ghidra.arch.inject import (
    InjectParameter, InjectPayload, InjectPayloadSleigh, InjectContext, PcodeInjectLibrary,
)
from ghidra.emulate.emulateutil import EmulateSnippet
from ghidra.sleigh.sleigh import PcodeCacher

if TYPE_CHECKING:
    from ghidra.arch.architecture import Architecture


# =========================================================================
# InjectContextSleigh
# =========================================================================

class InjectContextSleigh(InjectContext):
    """Context for performing injection using the SLEIGH engine.

    Extends InjectContext with a p-code cacher and parser context
    that are used during actual injection.
    """

    def __init__(self) -> None:
        super().__init__()
        self.cacher = PcodeCacher()
        self.pos = None     # ParserContext in C++
        self.glb: Optional[Architecture] = None

    def __del__(self) -> None:
        self.pos = None

    def encode(self, encoder) -> None:
        # Not needed for sleigh injection
        pass


# =========================================================================
# InjectPayloadCallfixup
# =========================================================================

class InjectPayloadCallfixup(InjectPayloadSleigh):
    """An injection payload, described by SLEIGH, for replacing CALL ops
    to specific functions.
    """

    def __init__(self, sourceName: str = "") -> None:
        super().__init__(sourceName, "unknown", InjectPayload.CALLFIXUP_TYPE)
        self.targetSymbolNames: List[str] = []

    def decode(self, decoder) -> None:
        """Decode from a <callfixup> element."""
        if hasattr(decoder, 'tag'):
            el = decoder
            self.name = el.get("name", "unknown")
            for child in el:
                tag = child.tag
                if tag == "pcode":
                    self._decodePayloadAttributesElement(child)
                    self._decodePayloadParamsElement(child)
                    self._decodeBodyElement(child)
                elif tag == "target":
                    tname = child.get("name", "")
                    if tname:
                        self.targetSymbolNames.append(tname)
            if len(self.parsestring) == 0 and not self.dynamic:
                raise LowlevelError("<callfixup> is missing <pcode> subtag: " + self.name)
            return

        from ghidra.core.marshal import ATTRIB_NAME, ELEM_CALLFIXUP, ELEM_PCODE, ELEM_TARGET

        elemId = decoder.openElement(ELEM_CALLFIXUP)
        self.name = decoder.readString(ATTRIB_NAME)
        pcodeSubtag = False
        for _ in range(1 << 30):
            subId = decoder.peekElement()
            if subId == 0:
                break
            subId = decoder.openElement()
            if subId == ELEM_PCODE.id:
                self.decodePayloadAttributes(decoder)
                self.decodePayloadParams(decoder)
                self.decodeBody(decoder)
                pcodeSubtag = True
            elif subId == ELEM_TARGET.id:
                self.targetSymbolNames.append(decoder.readString(ATTRIB_NAME))
            decoder.closeElement(subId)
        decoder.closeElement(elemId)
        if not pcodeSubtag:
            raise LowlevelError("<callfixup> is missing <pcode> subtag: " + self.name)

    def _decodePayloadAttributesElement(self, el) -> None:
        if el.get("paramshift"):
            self.paramshift = int(el.get("paramshift", "0"))
        if el.get("dynamic", "false").lower() == "true":
            self.dynamic = True
        if el.get("incidentalcopy", "false").lower() == "true":
            self.incidentalcopy = True
        inject_type = el.get("inject")
        if inject_type == "uponentry":
            self.name = self.name + "@@inject_uponentry"
        elif inject_type:
            self.name = self.name + "@@inject_uponreturn"

    def _decodePayloadParamsElement(self, el) -> None:
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

    def _decodeBodyElement(self, el) -> None:
        for child in el:
            if child.tag == "body":
                content = child.get("content")
                if content is None:
                    content = child.text or ""
                self.parsestring = content.strip()
                return
        if not self.parsestring and not self.dynamic:
            raise LowlevelError("Missing <body> subtag in <pcode>: " + self.getSource())

    def getTargetSymbolNames(self) -> List[str]:
        return list(self.targetSymbolNames)


# =========================================================================
# InjectPayloadCallother
# =========================================================================

class InjectPayloadCallother(InjectPayloadSleigh):
    """An injection payload, described by SLEIGH, for replacing specific
    user (CALLOTHER) ops.
    """

    def __init__(self, sourceName: str = "") -> None:
        super().__init__(sourceName, "unknown", InjectPayload.CALLOTHERFIXUP_TYPE)

    def decode(self, decoder) -> None:
        """Decode from a <callotherfixup> element."""
        if hasattr(decoder, 'tag'):
            el = decoder
            self.name = el.get("targetop", el.get("name", "unknown"))
            for child in el:
                if child.tag == "pcode":
                    self._decodePayloadAttributesElement(child)
                    self._decodePayloadParamsElement(child)
                    self._decodeBodyElement(child)
                    break
            else:
                raise LowlevelError(
                    "<callotherfixup> does not contain a <pcode> tag")
            return

        from ghidra.core.marshal import ATTRIB_TARGETOP, ELEM_CALLOTHERFIXUP, ELEM_PCODE

        elemId = decoder.openElement(ELEM_CALLOTHERFIXUP)
        self.name = decoder.readString(ATTRIB_TARGETOP)
        subId = decoder.openElement()
        if subId != ELEM_PCODE.id:
            raise LowlevelError("<callotherfixup> does not contain a <pcode> tag")
        self.decodePayloadAttributes(decoder)
        self.decodePayloadParams(decoder)
        self.decodeBody(decoder)
        decoder.closeElement(subId)
        decoder.closeElement(elemId)

    def _decodePayloadAttributesElement(self, el) -> None:
        if el.get("paramshift"):
            self.paramshift = int(el.get("paramshift", "0"))
        if el.get("dynamic", "false").lower() == "true":
            self.dynamic = True
        if el.get("incidentalcopy", "false").lower() == "true":
            self.incidentalcopy = True

    def _decodePayloadParamsElement(self, el) -> None:
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

    def _decodeBodyElement(self, el) -> None:
        for child in el:
            if child.tag == "body":
                content = child.get("content")
                if content is None:
                    content = child.text or ""
                self.parsestring = content.strip()
                return
        if not self.parsestring and not self.dynamic:
            raise LowlevelError("Missing <body> subtag in <pcode>: " + self.getSource())


# =========================================================================
# ExecutablePcodeSleigh
# =========================================================================

class ExecutablePcodeSleigh(InjectPayloadSleigh):
    """A p-code snippet, described by SLEIGH, that can be executed as a script."""

    def __init__(self, glb: Optional[Architecture] = None,
                 src: str = "", nm: str = "") -> None:
        super().__init__(src, nm, InjectPayload.EXECUTABLEPCODE_TYPE)
        self._glb = glb
        self.built = False
        self.emulator = EmulateSnippet(glb)
        self.inputList: List[int] = []
        self.outputList: List[int] = []
        self.emitter = None

    def __del__(self) -> None:
        self.emitter = None
        super().__del__()

    def build(self) -> None:
        if self.built:
            return
        icontext = self._glb.pcodeinjectlib.getCachedContext()
        icontext.clear()
        uniqReserve = 0x10
        codeSpace = self._glb.getDefaultCodeSpace()
        uniqSpace = self._glb.getUniqueSpace()
        icontext.baseaddr = Address(codeSpace, 0x1000)
        icontext.nextaddr = icontext.baseaddr
        for i in range(self.sizeInput()):
            param = self.getInput(i)
            icontext.inputlist.append(VarnodeData(uniqSpace, uniqReserve, param.getSize()))
            self.inputList.append(uniqReserve)
            uniqReserve += 0x20
        for i in range(self.sizeOutput()):
            param = self.getOutput(i)
            icontext.output.append(VarnodeData(uniqSpace, uniqReserve, param.getSize()))
            self.outputList.append(uniqReserve)
            uniqReserve += 0x20
        self.emitter = self.emulator.buildEmitter(self._glb.pcodeinjectlib.getBehaviors(), uniqReserve)
        self.inject(icontext, self.emitter)
        self.emitter = None
        if not self.emulator.checkForLegalCode():
            raise LowlevelError("Illegal p-code in executable snippet")
        self.built = True

    def getSource(self) -> str:
        return self.source

    def evaluate(self, input: List[int]) -> int:
        self.build()
        self.emulator.resetMemory()
        if len(input) != len(self.inputList):
            raise LowlevelError("Wrong number of input parameters to executable snippet")
        if len(self.outputList) == 0:
            raise LowlevelError("No registered outputs to executable snippet")
        for i, val in enumerate(input):
            self.emulator.setVarnodeValue(self.inputList[i], val)
        while not self.emulator.getHalt():
            self.emulator.executeCurrentOp()
        return self.emulator.getTempValue(self.outputList[0])

    def inject(self, context, emit) -> None:
        """Inject the p-code into the given context and emitter."""
        super().inject(context, emit)

    def decode(self, decoder) -> None:
        """Decode from a <pcode>, <case_pcode>, etc. element."""
        from ghidra.core.error import DecoderError
        from ghidra.core.marshal import (
            ATTRIB_CONTENT,
            ELEM_ADDR_PCODE,
            ELEM_BODY,
            ELEM_CASE_PCODE,
            ELEM_DEFAULT_PCODE,
            ELEM_PCODE,
            ELEM_SIZE_PCODE,
        )

        allowed_tags = {"pcode", "case_pcode", "addr_pcode", "default_pcode", "size_pcode"}
        if hasattr(decoder, 'tag'):
            el = decoder
            if el.tag not in allowed_tags:
                raise DecoderError(
                    "Expecting <pcode>, <case_pcode>, <addr_pcode>, <default_pcode>, or <size_pcode>"
                )
            self._decodePayloadAttributesElement(el)
            self._decodePayloadParamsElement(el)
            self.parsestring = ""
            for child in el:
                if child.tag == "body":
                    content = child.get("content")
                    if content is None:
                        content = child.text or ""
                    self.parsestring = content.strip()
                    break
            if len(self.parsestring) == 0:
                raise LowlevelError("Missing <body> subtag in <pcode>: " + self.getSource())
            return

        elemId = decoder.openElement()
        if elemId not in {
            ELEM_PCODE.id,
            ELEM_CASE_PCODE.id,
            ELEM_ADDR_PCODE.id,
            ELEM_DEFAULT_PCODE.id,
            ELEM_SIZE_PCODE.id,
        }:
            raise DecoderError(
                "Expecting <pcode>, <case_pcode>, <addr_pcode>, <default_pcode>, or <size_pcode>"
            )
        self.decodePayloadAttributes(decoder)
        self.decodePayloadParams(decoder)
        subId = decoder.openElement(ELEM_BODY)
        self.parsestring = decoder.readString(ATTRIB_CONTENT)
        decoder.closeElement(subId)
        decoder.closeElement(elemId)

    def printTemplate(self, s) -> None:
        super().printTemplate(s)


# =========================================================================
# InjectPayloadDynamic
# =========================================================================

class InjectPayloadDynamic(InjectPayload):
    """A debugging placeholder for a payload that changes depending on context.

    Implemented as a simple map from an Address to an XML/data description
    of the p-code sequence to inject.
    """

    def __init__(self, glb: Optional[Architecture] = None,
                 base: Optional[InjectPayload] = None) -> None:
        if base is not None:
            super().__init__(base.getName(), base.getType())
            self.incidentalcopy = base.isIncidentalCopy()
            self.paramshift = base.getParamShift()
            self.inputlist = list(getattr(base, "inputlist", []))
            self.output = list(getattr(base, "output", []))
        else:
            super().__init__("", 0)
        self.dynamic = True
        self._glb = glb
        self._addrMap: Dict[object, object] = {}  # Address -> payload root

    def decodeEntry(self, decoder) -> None:
        """Decode a specific p-code sequence and the context Address."""
        from ghidra.core.address import Address
        from ghidra.core.marshal import ATTRIB_CONTENT, ELEM_PAYLOAD

        addr = Address.decode(decoder)
        subId = decoder.openElement(ELEM_PAYLOAD)
        payload_xml = decoder.readString(ATTRIB_CONTENT)
        try:
            self._addrMap[addr] = ET.fromstring(payload_xml)
        except ET.ParseError as exc:
            raise LowlevelError("Error decoding dynamic payload") from exc
        decoder.closeElement(subId)

    def inject(self, context, emit) -> None:
        """Inject p-code from the address map."""
        from ghidra.core.address import Address
        from ghidra.core.marshal import ELEM_INST, XmlDecode

        key = context.baseaddr if isinstance(context.baseaddr, Address) else None
        if key not in self._addrMap:
            raise LowlevelError("Missing dynamic inject")
        el = self._addrMap[key]
        spc_manager = self._glb
        if spc_manager is None and context.glb is not None:
            spc_manager = context.glb
        decoder = XmlDecode(spc_manager, el)
        rootId = decoder.openElement(ELEM_INST)
        addr = Address.decode(decoder)
        while decoder.peekElement() != 0:
            emit.decodeOp(addr, decoder)
        decoder.closeElement(rootId)

    def __del__(self) -> None:
        self._addrMap.clear()

    def decode(self, decoder) -> None:
        raise LowlevelError("decode not supported for InjectPayloadDynamic")

    def printTemplate(self, s) -> None:
        s.write("dynamic")

    def getSource(self) -> str:
        return "dynamic"


# =========================================================================
# PcodeInjectLibrarySleigh
# =========================================================================

class PcodeInjectLibrarySleigh(PcodeInjectLibrary):
    """An implementation of an injection library using the internal SLEIGH
    engine to build payloads.

    Payloads from compiler specs and other sources are parsed as SLEIGH
    syntax and stored internally as InjectPayloadSleigh objects.
    """

    def __init__(self, glb: Optional[Architecture] = None) -> None:
        tmpbase = 0
        if glb is not None and hasattr(glb, "getUniqueBase"):
            tmpbase = glb.getUniqueBase()
        super().__init__(glb, tmpbase)
        self._glb = self.glb
        self._slgh = None  # SleighBase
        self._inst: list = []  # OpBehavior list
        self._tempbase: int = self.tempbase
        self._contextCache = InjectContextSleigh()
        if self._glb is not None:
            self._contextCache.glb = self._glb
            if self._tempbase == 0 and hasattr(self._glb, "translate") and self._glb.translate is not None and hasattr(self._glb.translate, "getUniqueStart"):
                self._tempbase = self._glb.translate.getUniqueStart()
                self.tempbase = self._tempbase
            if hasattr(self._glb, 'translate') and self._glb.translate is not None:
                self._slgh = self._glb.translate

    def forceDebugDynamic(self, injectid: int) -> InjectPayloadDynamic:
        """Force a payload to become dynamic for debug injection."""
        old_payload = self.getPayload(injectid)
        if old_payload is None:
            raise LowlevelError("Unknown inject payload id")
        new_payload = InjectPayloadDynamic(self._glb, old_payload)
        self._payloads[injectid] = new_payload
        return new_payload

    def allocateInject(self, sourceName: str, name: str, tp: int) -> int:
        """Allocate an injection payload of the appropriate type."""
        if tp == InjectPayload.CALLFIXUP_TYPE:
            payload = InjectPayloadCallfixup(sourceName)
        elif tp == InjectPayload.CALLOTHERFIXUP_TYPE:
            payload = InjectPayloadCallother(sourceName)
        elif tp == InjectPayload.EXECUTABLEPCODE_TYPE:
            payload = ExecutablePcodeSleigh(self._glb, sourceName, name)
        else:
            payload = InjectPayloadSleigh(sourceName, name, tp)
        injectid = len(self._payloads)
        self._payloads.append(payload)
        self._namemap[payload.getName()] = injectid
        return injectid

    def registerInject(self, injectid: int) -> None:
        """Register and parse an allocated injection payload."""
        payload = self.getPayload(injectid)
        if payload is None:
            return
        if payload.isDynamic():
            payload = self.forceDebugDynamic(injectid)
        if payload.getType() == InjectPayload.CALLFIXUP_TYPE:
            self.registerCallFixup(payload.getName(), injectid)
        elif payload.getType() == InjectPayload.CALLOTHERFIXUP_TYPE:
            self.registerCallOtherFixup(payload.getName(), injectid)
        elif payload.getType() == InjectPayload.CALLMECHANISM_TYPE:
            self.registerCallMechanism(payload.getName(), injectid)
        elif payload.getType() == InjectPayload.EXECUTABLEPCODE_TYPE:
            self.registerExeScript(payload.getName(), injectid)
        else:
            raise LowlevelError("Unknown p-code inject type")
        self.parseInject(payload)

    def parseInject(self, payload: InjectPayload) -> None:
        self._parseInject(payload)

    def _parseInject(self, payload: InjectPayload) -> None:
        """Convert SLEIGH syntax to p-code templates.

        In the full C++ implementation, this uses the SLEIGH compiler
        (PcodeSnippet) to parse the payload's parsestring into ConstructTpl.
        """
        if payload.isDynamic():
            return
        if not isinstance(payload, InjectPayloadSleigh):
            return

        if self._glb is None:
            raise LowlevelError("Cannot compile p-code inject payload without an architecture")

        sla_path = ""
        if hasattr(self._glb, "getFilename"):
            try:
                sla_path = self._glb.getFilename()
            except Exception:
                sla_path = ""
        if not sla_path:
            sla_path = getattr(self._glb, "filename", "") or getattr(self._glb, "sla_path", "")

        target = ""
        if hasattr(self._glb, "getTarget"):
            try:
                target = self._glb.getTarget()
            except Exception:
                target = ""
        if not target:
            target = getattr(self._glb, "target", "") or getattr(self._glb, "archid", "")

        if not sla_path or not target:
            raise LowlevelError("Missing SLEIGH architecture metadata for inject payload compilation")

        from ghidra.sleigh.decompiler_native import InjectTemplateNative

        unique_base = 0x2000 if payload.getType() == InjectPayload.EXECUTABLEPCODE_TYPE else self._tempbase
        payload.tpl = InjectTemplateNative(
            sla_path,
            target,
            payload.getSource(),
            payload.parsestring,
            [(param.getName(), param.getSize()) for param in payload.inputlist],
            [(param.getName(), param.getSize()) for param in payload.output],
            unique_base,
        )
        payload.parsestring = ""
        if payload.getType() != InjectPayload.EXECUTABLEPCODE_TYPE:
            self._tempbase = payload.tpl.get_unique_base()
            self.tempbase = self._tempbase
            if hasattr(self._glb, "setUniqueBase"):
                self._glb.setUniqueBase(self._tempbase)

    def getCachedContext(self) -> InjectContextSleigh:
        return self._contextCache

    def getBehaviors(self) -> list:
        if not self._inst:
            self._glb.collectBehaviors(self._inst)
        return self._inst

    def decodeDebug(self, decoder) -> None:
        """Decode debug injection information."""
        from ghidra.core.marshal import ATTRIB_NAME, ATTRIB_TYPE, ELEM_INJECT, ELEM_INJECTDEBUG

        elemId = decoder.openElement(ELEM_INJECTDEBUG)
        for _ in range(1 << 30):
            subId = decoder.peekElement()
            if subId != ELEM_INJECT.id:
                break
            subId = decoder.openElement()
            name = decoder.readString(ATTRIB_NAME)
            tp = decoder.readSignedInteger(ATTRIB_TYPE)
            injectid = self.getPayloadId(tp, name)
            payload = self.getPayload(injectid)
            if not isinstance(payload, InjectPayloadDynamic):
                payload = self.forceDebugDynamic(injectid)
            payload.decodeEntry(decoder)
            decoder.closeElement(subId)
        decoder.closeElement(elemId)

    def manualCallFixup(self, name: str, snippetstring: str) -> int:
        """Manually register a call fixup from a p-code snippet string."""
        sourceName = f'(manual callfixup name="{name}")'
        injectid = self.allocateInject(sourceName, name, InjectPayload.CALLFIXUP_TYPE)
        payload = self.getPayload(injectid)
        if isinstance(payload, InjectPayloadSleigh):
            payload.parsestring = snippetstring
        self.registerInject(injectid)
        return injectid

    def manualCallOtherFixup(self, name: str, outname: str,
                             inname: List[str], snippet: str) -> int:
        """Manually register a callother fixup from a p-code snippet string."""
        sourceName = f'(manual callotherfixup name="{name}")'
        injectid = self.allocateInject(sourceName, name, InjectPayload.CALLOTHERFIXUP_TYPE)
        payload = self.getPayload(injectid)
        if isinstance(payload, InjectPayloadSleigh):
            for in_param in inname:
                payload.inputlist.append(InjectParameter(in_param, 0))
            if len(outname) != 0:
                payload.output.append(InjectParameter(outname, 0))
            payload.orderParameters()
            payload.parsestring = snippet
        self.registerInject(injectid)
        return injectid
