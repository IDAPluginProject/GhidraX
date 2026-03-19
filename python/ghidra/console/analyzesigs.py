"""
Corresponds to: analyzesigs.hh / analyzesigs.cc

Console commands for feature/signature generation and analysis.
Registers commands: signature settings, print signatures, save signatures,
saveall signatures, produce signatures.
"""

from __future__ import annotations

import io
from typing import Optional, TYPE_CHECKING

from ghidra.console.interface import (
    IfaceCapability, IfaceStatus,
    IfaceParseError, IfaceExecutionError,
)
from ghidra.console.ifacedecomp import IfaceDecompCommand
from ghidra.analysis.signature import SigManager, GraphSigManager

if TYPE_CHECKING:
    from ghidra.analysis.funcdata import Funcdata


# =========================================================================
# IfcSignatureSettings
# =========================================================================

class IfcSignatureSettings(IfaceDecompCommand):
    """Change global settings for signature generation: `signature settings <val>`"""

    def execute(self, args: str) -> None:
        token = args.strip()
        if not token:
            raise IfaceParseError("Must specify settings integer")
        try:
            mysetting = int(token, 0)
        except ValueError as exc:
            raise IfaceParseError("Must specify settings integer") from exc
        if mysetting == 0:
            raise IfaceParseError("Must specify settings integer")
        SigManager.setSettings(mysetting)
        if self.status is not None and hasattr(self.status, 'optr') and self.status.optr is not None:
            self.status.optr.write(f"Signature settings set to 0x{mysetting:x}\n")


# =========================================================================
# IfcPrintSignatures
# =========================================================================

class IfcPrintSignatures(IfaceDecompCommand):
    """Calculate and print signatures for the current function: `print signatures`"""

    def execute(self, args: str) -> None:
        if self.dcp is None or self.dcp.fd is None:
            raise IfaceExecutionError("No function selected")
        if hasattr(self.dcp.fd, 'isProcComplete') and not self.dcp.fd.isProcComplete():
            raise IfaceExecutionError("Function has not been fully analyzed")

        smanage = GraphSigManager()
        optr = self.status.fileoptr if self.status and hasattr(self.status, 'fileoptr') else io.StringIO()

        name = self.dcp.fd.getName() if hasattr(self.dcp.fd, 'getName') else "unknown"
        optr.write(f"Signatures for {name}\n")

        smanage.setCurrentFunction(self.dcp.fd)
        smanage.generate()
        smanage.print(optr)


# =========================================================================
# IfcSaveSignatures
# =========================================================================

class IfcSaveSignatures(IfaceDecompCommand):
    """Calculate signatures and save them to a file: `save signatures <filename>`"""

    def execute(self, args: str) -> None:
        if self.dcp is None or self.dcp.fd is None:
            raise IfaceExecutionError("No function selected")
        if hasattr(self.dcp.fd, 'isProcComplete') and not self.dcp.fd.isProcComplete():
            raise IfaceExecutionError("Function has not been fully analyzed")

        sigfilename = args.strip()
        if not sigfilename:
            raise IfaceExecutionError("Need name of file to save signatures to")

        smanage = GraphSigManager()
        smanage.setCurrentFunction(self.dcp.fd)
        smanage.generate()

        try:
            with open(sigfilename, 'w', encoding='utf-8') as f:
                smanage.encode(None)  # Placeholder - would use XmlEncode
                vec = smanage.getSignatureVector()
                f.write("<signatures>")
                for h in vec:
                    f.write(f'<sig hash="{h}"/>')
                f.write("</signatures>\n")
        except OSError as exc:
            raise IfaceExecutionError(f"Unable to open signature save file: {sigfilename}") from exc

        optr = self.status.fileoptr if self.status and hasattr(self.status, 'fileoptr') else io.StringIO()
        name = self.dcp.fd.getName() if hasattr(self.dcp.fd, 'getName') else "unknown"
        optr.write(f"Successfully saved signatures for {name}\n")


# =========================================================================
# IfcSaveAllSignatures
# =========================================================================

class IfcSaveAllSignatures(IfaceDecompCommand):
    """Calculate signatures for all functions and save: `saveall signatures <filename>`"""

    def __init__(self) -> None:
        super().__init__()
        self._smanage: Optional[GraphSigManager] = None

    def execute(self, args: str) -> None:
        if self.dcp is None or not hasattr(self.dcp, 'conf') or self.dcp.conf is None:
            raise IfaceExecutionError("No architecture loaded")

        sigfilename = args.strip()
        if not sigfilename:
            raise IfaceExecutionError("Need name of file to save signatures to")

        self._smanage = GraphSigManager()
        # Placeholder: would iterate all functions and call iterationCallback
        raise IfaceExecutionError("saveall signatures not yet fully implemented")

    def iterationCallback(self, fd) -> None:
        """Called for each function during iteration."""
        if fd is None or (hasattr(fd, 'hasNoCode') and fd.hasNoCode()):
            return
        if self._smanage is None:
            return

        self._smanage.setCurrentFunction(fd)
        self._smanage.generate()

        numsigs = self._smanage.numSignatures()
        if numsigs > 0 and self.status and hasattr(self.status, 'fileoptr'):
            self._smanage.encode(None)  # Placeholder

        self._smanage.clear()


# =========================================================================
# IfcProduceSignatures
# =========================================================================

class IfcProduceSignatures(IfcSaveAllSignatures):
    """Calculate combined hash signatures for all functions: `produce signatures <filename>`"""

    def iterationCallback(self, fd) -> None:
        """Called for each function — writes name + overall hash."""
        if fd is None or (hasattr(fd, 'hasNoCode') and fd.hasNoCode()):
            return
        if self._smanage is None:
            return

        self._smanage.setCurrentFunction(fd)
        self._smanage.generate()

        finalsig = self._smanage.getOverallHash()
        if self.status and hasattr(self.status, 'fileoptr') and self.status.fileoptr is not None:
            name = fd.getName() if hasattr(fd, 'getName') else "unknown"
            self.status.fileoptr.write(f"{name} = 0x{finalsig:016x}\n")

        self._smanage.clear()


# =========================================================================
# IfaceAnalyzeSigsCapability
# =========================================================================

class IfaceAnalyzeSigsCapability(IfaceCapability):
    """Interface capability for signature analysis commands."""

    _instance: Optional[IfaceAnalyzeSigsCapability] = None

    def __init__(self) -> None:
        super().__init__("analyzesigs")

    @classmethod
    def getInstance(cls) -> IfaceAnalyzeSigsCapability:
        if cls._instance is None:
            cls._instance = IfaceAnalyzeSigsCapability()
        return cls._instance

    def registerCommands(self, status: IfaceStatus) -> None:
        status.registerCom(IfcSignatureSettings(), "signature", "settings")
        status.registerCom(IfcPrintSignatures(), "print", "signatures")
        status.registerCom(IfcSaveSignatures(), "save", "signatures")
        status.registerCom(IfcSaveAllSignatures(), "saveall", "signatures")
        status.registerCom(IfcProduceSignatures(), "produce", "signatures")
