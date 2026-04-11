"""
Corresponds to: analyzesigs.hh / analyzesigs.cc

Console commands for feature/signature generation and analysis.
Registers commands: signature settings, print signatures, save signatures,
saveall signatures, produce signatures.
"""

from __future__ import annotations

import io
import struct
from typing import BinaryIO, Optional, TYPE_CHECKING

from ghidra.console.interface import (
    IfaceCapability, IfaceStatus,
    IfaceParseError, IfaceExecutionError,
)
from ghidra.console.ifacedecomp import IfaceDecompCommand
from ghidra.analysis.signature import SigManager, GraphSigManager
from ghidra.core.marshal import XmlEncode
from ghidra.core.error import LowlevelError

if TYPE_CHECKING:
    from ghidra.analysis.funcdata import Funcdata


class _SignatureOutputStream:
    """Binary-backed stream that accepts both bytes and str writes."""

    def __init__(self, stream: BinaryIO) -> None:
        self._stream = stream

    def write(self, data) -> int:
        if isinstance(data, str):
            data = data.encode("utf-8")
        return self._stream.write(data)

    def flush(self) -> None:
        self._stream.flush()

    def close(self) -> None:
        self._stream.close()


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
        self.status.optr.write(f"Signature settings set to 0x{mysetting:x}\n")


# =========================================================================
# IfcPrintSignatures
# =========================================================================

class IfcPrintSignatures(IfaceDecompCommand):
    """Calculate and print signatures for the current function: `print signatures`"""

    def execute(self, args: str) -> None:
        if self.dcp is None or self.dcp.fd is None:
            raise IfaceExecutionError("No function selected")
        if not self.dcp.fd.isProcComplete():
            raise IfaceExecutionError("Function has not been fully analyzed")

        smanage = GraphSigManager()
        smanage.initializeFromStream(io.StringIO(args))

        self.status.fileoptr.write(f"Signatures for {self.dcp.fd.getName()}\n")

        smanage.setCurrentFunction(self.dcp.fd)
        smanage.generate()
        smanage.print(self.status.fileoptr)


# =========================================================================
# IfcSaveSignatures
# =========================================================================

class IfcSaveSignatures(IfaceDecompCommand):
    """Calculate signatures and save them to a file: `save signatures <filename>`"""

    def execute(self, args: str) -> None:
        if self.dcp is None or self.dcp.fd is None:
            raise IfaceExecutionError("No function selected")
        if not self.dcp.fd.isProcComplete():
            raise IfaceExecutionError("Function has not been fully analyzed")

        pieces = args.split(None, 1)
        sigfilename = pieces[0] if pieces else ""
        if not sigfilename:
            raise IfaceExecutionError("Need name of file to save signatures to")

        smanage = GraphSigManager()
        smanage.initializeFromStream(io.StringIO(pieces[1] if len(pieces) > 1 else ""))
        smanage.setCurrentFunction(self.dcp.fd)
        smanage.generate()

        try:
            with open(sigfilename, 'w', encoding='utf-8') as f:
                encoder = XmlEncode(f)
                smanage.encode(encoder)
        except OSError as exc:
            raise IfaceExecutionError(f"Unable to open signature save file: {sigfilename}") from exc

        self.status.fileoptr.write(f"Successfully saved signatures for {self.dcp.fd.getName()}\n")


# =========================================================================
# IfcSaveAllSignatures
# =========================================================================

class IfcSaveAllSignatures(IfaceDecompCommand):
    """Calculate signatures for all functions and save: `saveall signatures <filename>`"""

    def __init__(self) -> None:
        super().__init__()
        self._smanage: Optional[GraphSigManager] = None

    def __del__(self) -> None:
        self._smanage = None

    def execute(self, args: str) -> None:
        if self.dcp is None or self.dcp.conf is None:
            raise IfaceExecutionError("No architecture loaded")

        pieces = args.split(None, 1)
        sigfilename = pieces[0] if pieces else ""
        if not sigfilename:
            raise IfaceExecutionError("Need name of file to save signatures to")

        if self._smanage is not None:
            self._smanage = None
        self._smanage = GraphSigManager()
        self._smanage.initializeFromStream(io.StringIO(pieces[1] if len(pieces) > 1 else ""))

        saveoldfileptr = self.status.fileoptr
        try:
            rawstream = open(sigfilename, "wb")
        except OSError as exc:
            raise IfaceExecutionError(f"Unable to open signature save file: {sigfilename}") from exc
        self.status.fileoptr = _SignatureOutputStream(rawstream)

        oldactname = self.dcp.conf.allacts.getCurrentName()
        try:
            self.dcp.conf.allacts.setCurrent("normalize")
            self.iterateFunctionsAddrOrder()
        finally:
            self.status.fileoptr.close()
            self.status.fileoptr = saveoldfileptr
            self.dcp.conf.allacts.setCurrent(oldactname)
            self._smanage = None

    def iterationCallback(self, fd) -> None:
        if fd.hasNoCode():
            self.status.optr.write(f"No code for {fd.getName()}\n")
            return

        try:
            self.dcp.conf.clearAnalysis(fd)
            curact = self.dcp.conf.allacts.getCurrent()
            curact.reset(fd)
            curact.perform(fd)
            self.status.optr.write(f"Decompiled {fd.getName()}({fd.getSize()})\n")
        except LowlevelError as err:
            self.status.optr.write(f"Skipping {fd.getName()}: {err.explain}\n")
            return

        self._smanage.setCurrentFunction(fd)
        self._smanage.generate()

        numsigs = self._smanage.numSignatures()
        if numsigs != 0:
            addr = fd.getAddress()
            name = fd.getName().encode("utf-8")
            self.status.fileoptr.write(struct.pack("<I", addr.getSpace().getIndex()))
            self.status.fileoptr.write(struct.pack("<Q", addr.getOffset()))
            self.status.fileoptr.write(struct.pack("<I", numsigs))
            self.status.fileoptr.write(struct.pack("<I", len(name)))
            self.status.fileoptr.write(name)
            encoder = XmlEncode(self.status.fileoptr)
            self._smanage.encode(encoder)

        self._smanage.clear()
        self.dcp.conf.clearAnalysis(fd)


# =========================================================================
# IfcProduceSignatures
# =========================================================================

class IfcProduceSignatures(IfcSaveAllSignatures):
    """Calculate combined hash signatures for all functions: `produce signatures <filename>`"""

    def iterationCallback(self, fd) -> None:
        if fd.hasNoCode():
            self.status.optr.write(f"No code for {fd.getName()}\n")
            return

        try:
            self.dcp.conf.clearAnalysis(fd)
            curact = self.dcp.conf.allacts.getCurrent()
            curact.reset(fd)
            curact.perform(fd)
            self.status.optr.write(f"Decompiled {fd.getName()}({fd.getSize()})\n")
        except LowlevelError as err:
            self.status.optr.write(f"Skipping {fd.getName()}: {err.explain}\n")
            return

        self._smanage.setCurrentFunction(fd)
        self._smanage.generate()

        finalsig = self._smanage.getOverallHash()
        self.status.fileoptr.write(f"{fd.getName()} = 0x{finalsig:016x}\n")

        self._smanage.clear()
        self.dcp.conf.clearAnalysis(fd)


# =========================================================================
# IfaceAnalyzeSigsCapability
# =========================================================================

class IfaceAnalyzeSigsCapability(IfaceCapability):
    """Interface capability for signature analysis commands."""

    _instance: Optional[IfaceAnalyzeSigsCapability] = None

    def __init__(self) -> None:
        super().__init__("analyzesigs")

    def __copy__(self):
        raise TypeError("IfaceAnalyzeSigsCapability is non-copyable")

    def __deepcopy__(self, memo):
        raise TypeError("IfaceAnalyzeSigsCapability is non-copyable")

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
