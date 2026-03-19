"""
Corresponds to: inject_sleigh.hh / inject_sleigh.cc

Implementation of p-code injection using the internal SLEIGH engine to build
the p-code ops.  Provides InjectContextSleigh, InjectPayloadCallfixup,
InjectPayloadCallother, ExecutablePcodeSleigh, InjectPayloadDynamic, and
PcodeInjectLibrarySleigh.
"""

from __future__ import annotations

from typing import Optional, List, Dict, TYPE_CHECKING

from ghidra.core.error import LowlevelError
from ghidra.arch.inject import (
    InjectPayload, InjectPayloadSleigh, InjectContext, PcodeInjectLibrary,
)

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
        self.cacher = None  # PcodeCacher in C++
        self.pos = None     # ParserContext in C++
        self.glb: Optional[Architecture] = None

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
            # XML Element-based decoding
            el = decoder
            self.name = el.get("name", "unknown")
            for child in el:
                tag = child.tag
                if tag == "pcode":
                    self._decodePayloadAttributes(child)
                    self._decodePayloadParams(child)
                    self._decodeBody(child)
                elif tag == "target":
                    tname = child.get("name", "")
                    if tname:
                        self.targetSymbolNames.append(tname)
        else:
            # Stream decoder interface (future)
            pass

    def _decodePayloadAttributes(self, el) -> None:
        """Extract attributes from a <pcode> element."""
        if el.get("paramshift"):
            self.paramshift = int(el.get("paramshift", "0"))
        if el.get("dynamic", "false").lower() == "true":
            self.dynamic = True
        if el.get("incidentalcopy", "false").lower() == "true":
            self.incidentalcopy = True

    def _decodePayloadParams(self, el) -> None:
        """Extract input/output parameter sub-elements from a <pcode> element."""
        for child in el:
            tag = child.tag
            if tag == "input":
                pass  # InjectParameter info — future
            elif tag == "output":
                pass  # InjectParameter info — future

    def _decodeBody(self, el) -> None:
        """Extract the <body> sub-element text."""
        for child in el:
            if child.tag == "body":
                self.parsestring = (child.text or "").strip()
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
                    self._decodePayloadAttributes(child)
                    self._decodePayloadParams(child)
                    self._decodeBody(child)
                    break
            else:
                raise LowlevelError(
                    "<callotherfixup> does not contain a <pcode> tag")

    def _decodePayloadAttributes(self, el) -> None:
        if el.get("paramshift"):
            self.paramshift = int(el.get("paramshift", "0"))
        if el.get("dynamic", "false").lower() == "true":
            self.dynamic = True

    def _decodePayloadParams(self, el) -> None:
        pass

    def _decodeBody(self, el) -> None:
        for child in el:
            if child.tag == "body":
                self.parsestring = (child.text or "").strip()
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

    def inject(self, context, emit) -> None:
        """Inject the p-code into the given context and emitter."""
        # Requires full SLEIGH engine infrastructure (SleighBuilder etc.)
        # which lives in the native module. This is a placeholder.
        pass

    def decode(self, decoder) -> None:
        """Decode from a <pcode>, <case_pcode>, etc. element."""
        if hasattr(decoder, 'tag'):
            el = decoder
            for child in el:
                if child.tag == "body":
                    self.parsestring = (child.text or "").strip()

    def printTemplate(self, s) -> None:
        if self.tpl is not None:
            s.write(str(self.tpl))
        else:
            s.write(self.parsestring)


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
        else:
            super().__init__("", 0)
        self.dynamic = True
        self._glb = glb
        self._addrMap: Dict[int, object] = {}  # offset -> payload data

    def decodeEntry(self, decoder) -> None:
        """Decode a specific p-code sequence and the context Address."""
        # In C++ this reads an Address then a <payload> element
        pass

    def inject(self, context, emit) -> None:
        """Inject p-code from the address map."""
        key = context.baseaddr.getOffset() if hasattr(context.baseaddr, 'getOffset') else 0
        if key not in self._addrMap:
            raise LowlevelError("Missing dynamic inject")

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
        super().__init__()
        self._glb = glb
        self._slgh = None  # SleighBase
        self._inst: list = []  # OpBehavior list
        self._contextCache = InjectContextSleigh()
        if glb is not None:
            self._contextCache.glb = glb
            if hasattr(glb, 'translate') and glb.translate is not None:
                self._slgh = glb.translate

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
        return self.registerPayload(payload)

    def registerInject(self, injectid: int) -> None:
        """Register and parse an allocated injection payload."""
        payload = self.getPayload(injectid)
        if payload is None:
            return
        if payload.isDynamic():
            dyn = InjectPayloadDynamic(self._glb, payload)
            self._payloads[injectid] = dyn
            payload = dyn
        self._parseInject(payload)

    def _parseInject(self, payload: InjectPayload) -> None:
        """Convert SLEIGH syntax to p-code templates.

        In the full C++ implementation, this uses the SLEIGH compiler
        (PcodeSnippet) to parse the payload's parsestring into ConstructTpl.
        In this Python port, parsing is deferred to the native engine.
        """
        if payload.isDynamic():
            return
        # Full SLEIGH compilation would happen here via native module
        # For now this is a no-op placeholder

    def getCachedContext(self) -> InjectContextSleigh:
        return self._contextCache

    def getBehaviors(self) -> list:
        if not self._inst and self._glb is not None:
            if hasattr(self._glb, 'collectBehaviors'):
                self._inst = self._glb.collectBehaviors()
        return self._inst

    def decodeDebug(self, decoder) -> None:
        """Decode debug injection information."""
        # In C++ this reads <injectdebug> with <inject> sub-elements
        pass

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
            payload.parsestring = snippet
        self.registerInject(injectid)
        return injectid
