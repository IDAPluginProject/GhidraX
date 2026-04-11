"""
Corresponds to: signature_ghidra.hh / signature_ghidra.cc

Feature/Signature generation commands issued by the Ghidra client.
Registers commands: generateSignatures, debugSignatures,
getSignatureSettings, setSignatureSettings.
"""

from __future__ import annotations

from io import StringIO
from typing import TYPE_CHECKING, ClassVar, Optional

from ghidra.core.error import LowlevelError
from ghidra.core.marshal import (
    ATTRIB_CONTENT,
    ATTRIB_OFFSET,
    ATTRIB_SPACE,
    ATTRIB_VAL,
    ElementId,
    PackedDecode,
    PackedEncode,
    XmlEncode,
)
from ghidra.console.ghidra_process import GhidraCapability, GhidraCommand
from ghidra.console.protocol import (
    read_string_stream,
    read_string_stream_raw,
    write_string_stream,
)
from ghidra.analysis.signature import (
    ATTRIB_BADDATA,
    ATTRIB_UNIMPL,
    ELEM_CALL,
    ELEM_SIG,
    ELEM_SIGNATURES,
    GraphSigManager,
    SigManager,
)

if TYPE_CHECKING:
    from typing import BinaryIO


def _get_or_create_element(name: str, id_: int) -> ElementId:
    for element in ElementId._list:
        if element.name == name:
            return element
    return ElementId(name, id_)


ELEM_SIGSETTINGS = _get_or_create_element("sigsettings", 294)
ELEM_MAJOR = _get_or_create_element("major", 295)
ELEM_MINOR = _get_or_create_element("minor", 296)
ELEM_SETTINGS = _get_or_create_element("settings", 297)


# ---------------------------------------------------------------------------
# SignaturesAt
# ---------------------------------------------------------------------------

class SignaturesAt(GhidraCommand):
    """Command to generate a feature vector from a function.

    The command expects to receive the entry point address of a function.
    The function is decompiled using the 'normalize' simplification style.
    Features are extracted and returned to the Ghidra client.

    Two forms:
    - debug=False: streamlined encoding for normal operation
    - debug=True: verbose encoding with meta-data for debugging
    """

    def __init__(
        self,
        debug: bool = False,
        sin: Optional[BinaryIO] = None,
        sout: Optional[BinaryIO] = None,
    ) -> None:
        super().__init__(sin, sout)
        self._debug: bool = debug
        self._addr = None

    def loadParameters(self) -> None:
        """Read the function address from the input stream."""
        super().loadParameters()
        addr_xml = read_string_stream_raw(self._sin)
        if addr_xml:
            from ghidra.core.address import Address

            decoder = PackedDecode(self.ghidra)
            decoder.ingestBytes(addr_xml)
            try:
                self._addr = Address.decode(decoder)
            except Exception:
                self._addr = _decode_addr(addr_xml, self.ghidra)

    def rawAction(self) -> None:
        """Decompile the function and generate signatures."""
        if self.ghidra is None or self._addr is None:
            raise LowlevelError("Bad address for signatures")

        fd = None
        if (hasattr(self.ghidra, 'symboltab') and self.ghidra.symboltab is not None
                and hasattr(self.ghidra.symboltab, 'getGlobalScope')):
            scope = self.ghidra.symboltab.getGlobalScope()
            if scope is not None and hasattr(scope, 'queryFunction'):
                fd = scope.queryFunction(self._addr)

        if fd is None:
            raise LowlevelError(_format_bad_signature_address(self._addr))

        if hasattr(fd, 'isProcStarted') and not fd.isProcStarted():
            if hasattr(self.ghidra, 'allacts'):
                curname = self.ghidra.allacts.getCurrentName()
                if curname != "normalize":
                    sigact = self.ghidra.allacts.setCurrent("normalize")
                else:
                    sigact = self.ghidra.allacts.getCurrent()
                sigact.reset(fd)
                sigact.perform(fd)
                if curname != "normalize":
                    self.ghidra.allacts.setCurrent(curname)

        self._sout.write(b"\x00\x00\x01\x0e")
        encoder = PackedEncode(self._sout)
        if self._debug:
            _encode_debug_signature(fd, encoder)
        else:
            _encode_simple_signature(fd, encoder)
        self._sout.write(b"\x00\x00\x01\x0f")


# ---------------------------------------------------------------------------
# GetSignatureSettings
# ---------------------------------------------------------------------------

class GetSignatureSettings(GhidraCommand):
    """Command to retrieve current signature generation settings."""

    def __init__(
        self,
        sin: Optional[BinaryIO] = None,
        sout: Optional[BinaryIO] = None,
    ) -> None:
        super().__init__(sin, sout)

    def rawAction(self) -> None:
        """Return settings as a packed encoding."""
        from ghidra.arch.architecture import ArchitectureCapability

        self._sout.write(b"\x00\x00\x01\x0e")
        encoder = PackedEncode(self._sout)
        encoder.openElement(ELEM_SIGSETTINGS)
        encoder.openElement(ELEM_MAJOR)
        encoder.writeSignedInteger(ATTRIB_CONTENT, ArchitectureCapability.getMajorVersion())
        encoder.closeElement(ELEM_MAJOR)
        encoder.openElement(ELEM_MINOR)
        encoder.writeSignedInteger(ATTRIB_CONTENT, ArchitectureCapability.getMinorVersion())
        encoder.closeElement(ELEM_MINOR)
        encoder.openElement(ELEM_SETTINGS)
        encoder.writeUnsignedInteger(ATTRIB_CONTENT, SigManager.getSettings())
        encoder.closeElement(ELEM_SETTINGS)
        encoder.closeElement(ELEM_SIGSETTINGS)
        self._sout.write(b"\x00\x00\x01\x0f")


# ---------------------------------------------------------------------------
# SetSignatureSettings
# ---------------------------------------------------------------------------

class SetSignatureSettings(GhidraCommand):
    """Command to set signature generation settings."""

    def __init__(
        self,
        sin: Optional[BinaryIO] = None,
        sout: Optional[BinaryIO] = None,
    ) -> None:
        super().__init__(sin, sout)
        self._settings: int = 0

    def loadParameters(self) -> None:
        """Read the settings value from the input stream."""
        super().loadParameters()
        setting_str = read_string_stream(self._sin)
        if setting_str:
            try:
                self._settings = int(setting_str.strip(), 0)
            except (ValueError, TypeError):
                self._settings = 0

    def rawAction(self) -> None:
        """Apply the settings."""
        if GraphSigManager.testSettings(self._settings):
            SigManager.setSettings(self._settings)
            write_string_stream(self._sout, "t")
        else:
            write_string_stream(self._sout, "f")


# ---------------------------------------------------------------------------
# GhidraSignatureCapability
# ---------------------------------------------------------------------------

class GhidraSignatureCapability(GhidraCapability):
    """Singleton capability that registers signature commands."""

    _instance: ClassVar[Optional[GhidraSignatureCapability]] = None

    def __init__(
        self,
        sin: Optional[BinaryIO] = None,
        sout: Optional[BinaryIO] = None,
    ) -> None:
        super().__init__("signature")
        self._sin = sin
        self._sout = sout

    def __copy__(self):
        raise TypeError("GhidraSignatureCapability is non-copyable")

    def __deepcopy__(self, memo):
        raise TypeError("GhidraSignatureCapability is non-copyable")

    @classmethod
    def getInstance(
        cls,
        sin: Optional[BinaryIO] = None,
        sout: Optional[BinaryIO] = None,
    ) -> GhidraSignatureCapability:
        if cls._instance is None:
            cls._instance = cls(sin, sout)
        else:
            if sin is not None:
                cls._instance._sin = sin
            if sout is not None:
                cls._instance._sout = sout
        return cls._instance

    def initialize(self) -> None:
        """Register signature commands for the Ghidra client."""
        GhidraCapability.commandmap["generateSignatures"] = SignaturesAt(False, self._sin, self._sout)
        GhidraCapability.commandmap["debugSignatures"] = SignaturesAt(True, self._sin, self._sout)
        GhidraCapability.commandmap["getSignatureSettings"] = GetSignatureSettings(self._sin, self._sout)
        GhidraCapability.commandmap["setSignatureSettings"] = SetSignatureSettings(self._sin, self._sout)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _decode_addr(xml_bytes, arch):
    """Decode address XML. Minimal implementation."""
    try:
        import xml.etree.ElementTree as ET
        if isinstance(xml_bytes, bytes):
            xml_bytes = xml_bytes.decode("utf-8", errors="replace")
        root = ET.fromstring(xml_bytes)
        space_name = root.get("space", "ram")
        offset_str = root.get("offset", "0x0")
        offset = int(offset_str, 0)
        from ghidra.core.address import Address
        space = None
        if arch is not None and hasattr(arch, 'numSpaces'):
            for i in range(arch.numSpaces()):
                spc = arch.getSpace(i)
                if spc is not None and spc.getName() == space_name:
                    space = spc
                    break
        return Address(space, offset) if space else Address(None, offset)
    except Exception:
        return None


def _format_bad_signature_address(addr) -> str:
    shortcut = ""
    get_shortcut = getattr(addr, "getShortcut", None)
    if callable(get_shortcut):
        shortcut = get_shortcut()

    raw = ""
    print_raw = getattr(addr, "printRaw", None)
    if callable(print_raw):
        try:
            raw = print_raw()
        except TypeError:
            stream = StringIO()
            print_raw(stream)
            raw = stream.getvalue()
    return f"Bad address for signatures: {shortcut}{raw}\n"


def _encode_simple_signature(fd, encoder) -> None:
    mgr = GraphSigManager()
    mgr.setCurrentFunction(fd)
    mgr.generate()
    vec = []
    mgr.getSignatureVector(vec)
    encoder.openElement(ELEM_SIGNATURES)
    if fd.hasUnimplemented():
        encoder.writeBool(ATTRIB_UNIMPL, True)
    if fd.hasBadData():
        encoder.writeBool(ATTRIB_BADDATA, True)
    for h in vec:
        encoder.openElement(ELEM_SIG)
        encoder.writeUnsignedInteger(ATTRIB_VAL, h)
        encoder.closeElement(ELEM_SIG)
    for i in range(fd.numCalls()):
        fc = fd.getCallSpecs(i)
        addr = fc.getEntryAddress()
        if not addr.isInvalid():
            encoder.openElement(ELEM_CALL)
            encoder.writeSpace(ATTRIB_SPACE, addr.getSpace())
            encoder.writeUnsignedInteger(ATTRIB_OFFSET, addr.getOffset())
            encoder.closeElement(ELEM_CALL)
    encoder.closeElement(ELEM_SIGNATURES)


def _simple_signature(fd, sout) -> None:
    """Generate a streamlined feature encoding for the function."""
    stream = StringIO()
    encoder = XmlEncode(stream, do_format=False)
    _encode_simple_signature(fd, encoder)
    sout.write(encoder.toString().encode("utf-8"))


def _encode_debug_signature(fd, encoder) -> None:
    mgr = GraphSigManager()
    mgr.setCurrentFunction(fd)
    mgr.generate()
    mgr.sortByHash()
    mgr.encode(encoder)


def _debug_signature(fd, sout) -> None:
    """Generate a verbose feature encoding with debug info."""
    stream = StringIO()
    encoder = XmlEncode(stream, do_format=False)
    _encode_debug_signature(fd, encoder)
    sout.write(encoder.toString().encode("utf-8"))
