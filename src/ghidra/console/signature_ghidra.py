"""
Corresponds to: signature_ghidra.hh / signature_ghidra.cc

Feature/Signature generation commands issued by the Ghidra client.
Registers commands: generateSignatures, debugSignatures,
getSignatureSettings, setSignatureSettings.
"""

from __future__ import annotations

from typing import TYPE_CHECKING, Optional

from ghidra.core.error import LowlevelError
from ghidra.console.protocol import (
    read_string_stream_raw, write_string_stream,
)
from ghidra.analysis.signature import SigManager, GraphSigManager

if TYPE_CHECKING:
    from typing import BinaryIO, Dict
    from ghidra.console.ghidra_process import GhidraCommand


# ---------------------------------------------------------------------------
# SignaturesAt
# ---------------------------------------------------------------------------

class SignaturesAt:
    """Command to generate a feature vector from a function.

    The command expects to receive the entry point address of a function.
    The function is decompiled using the 'normalize' simplification style.
    Features are extracted and returned to the Ghidra client.

    Two forms:
    - debug=False: streamlined encoding for normal operation
    - debug=True: verbose encoding with meta-data for debugging
    """

    def __init__(self, debug: bool = False) -> None:
        self._debug: bool = debug
        self._addr = None
        self._sin = None
        self._sout = None
        self.ghidra = None  # ArchitectureGhidra

    def set_streams(self, sin, sout) -> None:
        self._sin = sin
        self._sout = sout

    def loadParameters(self) -> None:
        """Read the function address from the input stream."""
        if self._sin is not None:
            addr_xml = read_string_stream_raw(self._sin)
            if self.ghidra is not None and addr_xml:
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
            raise LowlevelError(f"Bad address for signatures: {self._addr}")

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

        if self._sout is not None:
            self._sout.write(b"\x00\x00\x01\x0e")  # STRING_OPEN burst
            if self._debug:
                _debug_signature(fd, self._sout)
            else:
                _simple_signature(fd, self._sout)
            self._sout.write(b"\x00\x00\x01\x0f")  # STRING_CLOSE burst


# ---------------------------------------------------------------------------
# GetSignatureSettings
# ---------------------------------------------------------------------------

class GetSignatureSettings:
    """Command to retrieve current signature generation settings."""

    def __init__(self) -> None:
        self._sin = None
        self._sout = None
        self.ghidra = None

    def set_streams(self, sin, sout) -> None:
        self._sin = sin
        self._sout = sout

    def rawAction(self) -> None:
        """Return settings as XML."""
        if self._sout is None:
            return
        from ghidra.arch.architecture import ArchitectureCapability
        major = ArchitectureCapability.majorversion if hasattr(ArchitectureCapability, 'majorversion') else 0
        minor = ArchitectureCapability.minorversion if hasattr(ArchitectureCapability, 'minorversion') else 0
        settings = SigManager.getSettings()

        xml = (f"<sigsettings>"
               f"<major>{major}</major>"
               f"<minor>{minor}</minor>"
               f"<settings>{settings}</settings>"
               f"</sigsettings>")

        self._sout.write(b"\x00\x00\x01\x0e")
        self._sout.write(xml.encode("utf-8"))
        self._sout.write(b"\x00\x00\x01\x0f")


# ---------------------------------------------------------------------------
# SetSignatureSettings
# ---------------------------------------------------------------------------

class SetSignatureSettings:
    """Command to set signature generation settings."""

    def __init__(self) -> None:
        self._settings: int = 0
        self._sin = None
        self._sout = None
        self.ghidra = None

    def set_streams(self, sin, sout) -> None:
        self._sin = sin
        self._sout = sout

    def loadParameters(self) -> None:
        """Read the settings value from the input stream."""
        if self._sin is not None:
            setting_str = read_string_stream_raw(self._sin)
            if setting_str:
                try:
                    self._settings = int(setting_str.strip(), 0)
                except (ValueError, TypeError):
                    self._settings = 0

    def rawAction(self) -> None:
        """Apply the settings."""
        if self._sout is None:
            return
        if GraphSigManager.testSettings(self._settings):
            SigManager.setSettings(self._settings)
            write_string_stream(self._sout, "t")
        else:
            write_string_stream(self._sout, "f")


# ---------------------------------------------------------------------------
# GhidraSignatureCapability
# ---------------------------------------------------------------------------

class GhidraSignatureCapability:
    """Singleton capability that registers signature commands."""

    _instance: Optional[GhidraSignatureCapability] = None

    def __init__(self) -> None:
        self.name: str = "signature"

    @classmethod
    def getInstance(cls) -> GhidraSignatureCapability:
        if cls._instance is None:
            cls._instance = GhidraSignatureCapability()
        return cls._instance

    def initialize(self) -> dict:
        """Return the command map entries for signature commands."""
        return {
            "generateSignatures": SignaturesAt(debug=False),
            "debugSignatures": SignaturesAt(debug=True),
            "getSignatureSettings": GetSignatureSettings(),
            "setSignatureSettings": SetSignatureSettings(),
        }


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


def _simple_signature(fd, sout) -> None:
    """Generate a streamlined feature encoding for the function."""
    mgr = GraphSigManager()
    mgr.setCurrentFunction(fd)
    mgr.generate()
    mgr.sortByHash()
    vec = mgr.getSignatureVector()
    xml = "<signatures>"
    for h in vec:
        xml += f'<sig hash="{h}"/>'
    xml += "</signatures>"
    sout.write(xml.encode("utf-8"))


def _debug_signature(fd, sout) -> None:
    """Generate a verbose feature encoding with debug info."""
    import io as _io
    mgr = GraphSigManager()
    mgr.setCurrentFunction(fd)
    mgr.generate()
    mgr.sortByHash()
    xml = '<signatures debug="true">'
    for i in range(mgr.numSignatures()):
        sig = mgr.getSignature(i)
        origin = _io.StringIO()
        sig.printOrigin(origin)
        xml += f'<sig hash="{sig.getHash()}" origin="{origin.getvalue()}"/>'
    xml += "</signatures>"
    sout.write(xml.encode("utf-8"))
