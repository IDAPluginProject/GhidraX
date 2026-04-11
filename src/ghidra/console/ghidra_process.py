"""
Corresponds to: ghidra_process.hh / ghidra_process.cc

Command dispatch for the Ghidra decompiler binary protocol.
Seven commands are supported:
  - registerProgram
  - deregisterProgram
  - flushNative
  - decompileAt
  - structureGraph
  - setAction
  - setOptions
"""

from __future__ import annotations

import sys
from typing import BinaryIO, ClassVar, Dict, List, Optional, TYPE_CHECKING

from ghidra.core.capability import CapabilityPoint
from ghidra.core.address import Address
from ghidra.core.error import DecoderError, LowlevelError, RecovError
from ghidra.core.marshal import ElementId, PackedDecode, PackedEncode
from ghidra.core.xml import DocumentStorage
from ghidra.fspec.paramid import ParamIDAnalysis
from ghidra.console.protocol import (
    JavaError,
    read_to_any_burst, read_string_stream,
    send_cmd_response_open, send_cmd_response_close,
    send_int_open, send_int_close,
    send_warning_open, send_warning_close,
    pass_java_exception,
    BURST_COMMAND_OPEN, BURST_COMMAND_CLOSE,
    BURST_STRING_OPEN, BURST_STRING_CLOSE,
)

if TYPE_CHECKING:
    from ghidra.console.ghidra_arch import ArchitectureGhidra


# ---------------------------------------------------------------------------
# Architecture registry
# ---------------------------------------------------------------------------

_archlist: List[Optional[ArchitectureGhidra]] = []

ELEM_DOC = ElementId("doc", 229)


# ---------------------------------------------------------------------------
# Capability registration and command dispatch
# ---------------------------------------------------------------------------

class GhidraCapability(CapabilityPoint):
    """Capability point for commands available to the Ghidra client."""

    commandmap: ClassVar[Dict[str, GhidraCommand]] = {}

    def __init__(self, name: str = "") -> None:
        super().__init__()
        self.name = name

    def getName(self) -> str:
        return self.name

    @staticmethod
    def readCommand(sin: BinaryIO, sout: BinaryIO) -> int:
        """Read and dispatch a single command from the Ghidra client.

        C++ ref: ``GhidraCapability::readCommand``
        """
        while True:
            burst = read_to_any_burst(sin)
            if burst == BURST_COMMAND_OPEN:
                break

        function_name = read_string_stream(sin)
        cmd = GhidraCapability.commandmap.get(function_name)
        if cmd is None:
            send_cmd_response_open(sout)
            send_warning_open(sout)
            sout.write(f"Bad command: {function_name}".encode("utf-8"))
            send_warning_close(sout)
            send_cmd_response_close(sout)
            sout.flush()
            return 0

        return cmd.doit()

    @staticmethod
    def shutDown() -> None:
        GhidraCapability.commandmap.clear()


class GhidraDecompCapability(GhidraCapability):
    """Singleton capability registering the core decompiler commands."""

    _instance: ClassVar[Optional[GhidraDecompCapability]] = None

    def __init__(self, sin: Optional[BinaryIO] = None, sout: Optional[BinaryIO] = None) -> None:
        super().__init__("decomp")
        self._sin = sin
        self._sout = sout

    def __copy__(self):
        raise TypeError("GhidraDecompCapability is non-copyable")

    def __deepcopy__(self, memo):
        raise TypeError("GhidraDecompCapability is non-copyable")

    @classmethod
    def getInstance(
        cls,
        sin: Optional[BinaryIO] = None,
        sout: Optional[BinaryIO] = None,
    ) -> GhidraDecompCapability:
        if cls._instance is None:
            cls._instance = cls(sin, sout)
        else:
            if sin is not None:
                cls._instance._sin = sin
            if sout is not None:
                cls._instance._sout = sout
        return cls._instance

    def initialize(self) -> None:
        if self._sin is None or self._sout is None:
            raise LowlevelError("GhidraDecompCapability requires streams before initialize")

        GhidraCapability.commandmap.clear()
        GhidraCapability.commandmap.update(
            {
                "registerProgram": RegisterProgram(self._sin, self._sout),
                "deregisterProgram": DeregisterProgram(self._sin, self._sout),
                "flushNative": FlushNative(self._sin, self._sout),
                "decompileAt": DecompileAt(self._sin, self._sout),
                "structureGraph": StructureGraph(self._sin, self._sout),
                "setAction": SetAction(self._sin, self._sout),
                "setOptions": SetOptions(self._sin, self._sout),
            }
        )


# ---------------------------------------------------------------------------
# Base command class
# ---------------------------------------------------------------------------

class GhidraCommand:
    """Base class for a command from the Ghidra client.

    Lifecycle: loadParameters() → rawAction() → sendResult()

    C++ ref: ``ghidra_process.hh::GhidraCommand``
    """

    def __init__(self, sin: Optional[BinaryIO] = None, sout: Optional[BinaryIO] = None) -> None:
        self._sin: BinaryIO = sin if sin is not None else sys.stdin.buffer
        self._sout: BinaryIO = sout if sout is not None else sys.stdout.buffer
        self.ghidra: Optional[ArchitectureGhidra] = None
        self.status: int = 0  # 0 = continue, 1 = terminate

    def __del__(self) -> None:
        return None

    def loadParameters(self) -> None:
        """Read parameters. Default: read arch id.

        C++ ref: ``GhidraCommand::loadParameters`` — reads burst 14 (string-open),
        decimal integer, burst 15 (string-close).
        """
        arch_id = -1
        burst = read_to_any_burst(self._sin)
        if burst != BURST_STRING_OPEN:
            raise JavaError("alignment", "Expecting arch id start")
        id_str = _read_stream_content(self._sin)
        arch_id = int(id_str)
        burst2 = read_to_any_burst(self._sin)
        if burst2 != BURST_STRING_CLOSE:
            raise JavaError("alignment", "Expecting arch id end")

        if 0 <= arch_id < len(_archlist):
            self.ghidra = _archlist[arch_id]
        if self.ghidra is None:
            raise JavaError("decompiler", "No architecture registered with decompiler")
        self.ghidra.clearWarnings()

    def sendResult(self) -> None:
        """Send warnings back to the client.

        C++ ref: uses burst 0x10 (warning-open) / 0x11 (warning-close).
        """
        if self.ghidra is not None:
            send_warning_open(self._sout)
            self._sout.write(self.ghidra.getWarnings().encode("utf-8"))
            send_warning_close(self._sout)

    def rawAction(self) -> None:
        """Perform the command action. Must be overridden."""
        raise NotImplementedError

    def doit(self) -> int:
        """Execute the full command lifecycle.

        C++ ref: ``GhidraCommand::doit``
        """
        self.status = 0
        send_cmd_response_open(self._sout)
        try:
            self.loadParameters()
            burst = read_to_any_burst(self._sin)
            if burst != BURST_COMMAND_CLOSE:
                raise JavaError("alignment", "Missing end of command")
            self.rawAction()
        except DecoderError as err:
            if self.ghidra is not None:
                self.ghidra.printMessage("Marshaling error: " + err.explain)
        except JavaError as err:
            pass_java_exception(self._sout, err.type, err.explain)
            return self.status
        except RecovError as err:
            if self.ghidra is not None:
                self.ghidra.printMessage("Recoverable Error: " + err.explain)
        except LowlevelError as err:
            if self.ghidra is not None:
                self.ghidra.printMessage("Low-level Error: " + err.explain)

        self.sendResult()
        send_cmd_response_close(self._sout)
        self._sout.flush()
        return self.status


# ---------------------------------------------------------------------------
# RegisterProgram
# ---------------------------------------------------------------------------

class RegisterProgram(GhidraCommand):
    """Register a new program with the decompiler.

    Receives four XML strings: pspec, cspec, tspec, coretypes.
    Creates and initializes an ArchitectureGhidra.

    C++ ref: ``ghidra_process.cc::RegisterProgram``
    """

    def __init__(self, sin: BinaryIO, sout: BinaryIO) -> None:
        super().__init__(sin, sout)
        self._pspec: str = ""
        self._cspec: str = ""
        self._tspec: str = ""
        self._corespec: str = ""
        self.archid: int = -1

    def loadParameters(self) -> None:
        """Read four XML spec strings (no arch id for this command)."""
        self._pspec = ""
        self._cspec = ""
        self._tspec = ""
        self._corespec = ""
        self._pspec = read_string_stream(self._sin)
        self._cspec = read_string_stream(self._sin)
        self._tspec = read_string_stream(self._sin)
        self._corespec = read_string_stream(self._sin)

    def rawAction(self) -> None:
        from ghidra.console.ghidra_arch import ArchitectureGhidra

        # Find an open slot
        open_slot = -1
        for i, arch in enumerate(_archlist):
            if arch is None:
                open_slot = i

        self.ghidra = ArchitectureGhidra(
            self._pspec, self._cspec, self._tspec, self._corespec,
            self._sin, self._sout
        )
        self._pspec = ""
        self._cspec = ""
        self._tspec = ""
        self._corespec = ""

        # Initialize the architecture
        store = DocumentStorage()
        self.ghidra.init(store)

        if open_slot == -1:
            open_slot = len(_archlist)
            _archlist.append(None)
        _archlist[open_slot] = self.ghidra
        self.archid = open_slot

    def sendResult(self) -> None:
        send_int_open(self._sout)
        self._sout.write(str(self.archid).encode("utf-8"))
        send_int_close(self._sout)
        super().sendResult()


# ---------------------------------------------------------------------------
# DeregisterProgram
# ---------------------------------------------------------------------------

class DeregisterProgram(GhidraCommand):
    """Release all resources for a program.

    C++ ref: ``ghidra_process.cc::DeregisterProgram``
    """

    def __init__(self, sin: BinaryIO, sout: BinaryIO) -> None:
        super().__init__(sin, sout)
        self._inid: int = -1
        self.res: int = 0

    def loadParameters(self) -> None:
        burst = read_to_any_burst(self._sin)
        if burst != BURST_STRING_OPEN:
            raise JavaError("alignment", "Expecting deregister id start")
        id_str = _read_stream_content(self._sin)
        self._inid = int(id_str)
        burst2 = read_to_any_burst(self._sin)
        if burst2 != BURST_STRING_CLOSE:
            raise JavaError("alignment", "Expecting deregister id end")
        if 0 <= self._inid < len(_archlist):
            self.ghidra = _archlist[self._inid]
        if self.ghidra is None:
            raise JavaError("decompiler", "No architecture registered with decompiler")
        self.ghidra.clearWarnings()

    def rawAction(self) -> None:
        if self.ghidra is not None:
            self.res = 1
            _archlist[self._inid] = None
            self.ghidra = None
            self.status = 1  # Terminate
        else:
            self.res = 0

    def sendResult(self) -> None:
        send_int_open(self._sout)
        self._sout.write(str(self.res).encode("utf-8"))
        send_int_close(self._sout)
        super().sendResult()


# ---------------------------------------------------------------------------
# FlushNative
# ---------------------------------------------------------------------------

class FlushNative(GhidraCommand):
    """Flush all cached symbols, types, comments.

    C++ ref: ``ghidra_process.cc::FlushNative``
    """

    def __init__(self, sin: BinaryIO, sout: BinaryIO) -> None:
        super().__init__(sin, sout)
        self.res: int = 0

    def rawAction(self) -> None:
        if self.ghidra is not None:
            if self.ghidra.symboltab is not None:
                scope = self.ghidra.symboltab.getGlobalScope()
                if scope is not None:
                    scope.clear()
                    self.ghidra.symboltab.deleteSubScopes(scope)
            if self.ghidra.types is not None:
                self.ghidra.types.clearNoncore()
            if self.ghidra.commentdb is not None:
                self.ghidra.commentdb.clear()
            if self.ghidra.stringManager is not None:
                self.ghidra.stringManager.clear()
            if self.ghidra.cpool is not None:
                self.ghidra.cpool.clear()
        self.res = 0

    def sendResult(self) -> None:
        send_int_open(self._sout)
        self._sout.write(str(self.res).encode("utf-8"))
        send_int_close(self._sout)
        super().sendResult()


# ---------------------------------------------------------------------------
# DecompileAt
# ---------------------------------------------------------------------------

class DecompileAt(GhidraCommand):
    """Decompile a function at the given address.

    C++ ref: ``ghidra_process.cc::DecompileAt``
    """

    def __init__(self, sin: BinaryIO, sout: BinaryIO) -> None:
        super().__init__(sin, sout)
        self._addr = None

    def loadParameters(self) -> None:
        super().loadParameters()
        from ghidra.console.ghidra_arch import ArchitectureGhidra

        decoder = PackedDecode(self.ghidra)
        ArchitectureGhidra.readStringStream(self._sin, decoder)
        self._addr = Address.decode(decoder)

    def rawAction(self) -> None:
        assert self.ghidra is not None
        assert self._addr is not None

        fd = self.ghidra.symboltab.getGlobalScope().queryFunction(self._addr)
        if fd is None:
            message = (
                "Bad decompile address: "
                + self._addr.getShortcut()
                + self._addr.printRaw()
                + "\n"
                + self._addr.getSpace().getName()
                + " may not be a global space in the spec file."
            )
            raise LowlevelError(message)

        if not fd.isProcStarted():
            self.ghidra.allacts.getCurrent().reset(fd)
            self.ghidra.allacts.getCurrent().perform(fd)

        send_int_open(self._sout)
        if fd.isProcComplete():
            encoder = PackedEncode(self._sout)
            encoder.openElement(ELEM_DOC)
            if self.ghidra.getSendParamMeasures() and self.ghidra.allacts.getCurrentName() == "paramid":
                pidanalysis = ParamIDAnalysis(fd, True)
                pidanalysis.encode(encoder, True)
            else:
                if self.ghidra.getSendParamMeasures():
                    pidanalysis = ParamIDAnalysis(fd, False)
                    pidanalysis.encode(encoder, True)
                fd.encode(encoder, 0, self.ghidra.getSendSyntaxTree())
                if self.ghidra.getSendCCode() and self.ghidra.allacts.getCurrentName() == "decompile":
                    self.ghidra.print_.docFunction(fd)
            encoder.closeElement(ELEM_DOC)
        send_int_close(self._sout)


# ---------------------------------------------------------------------------
# StructureGraph
# ---------------------------------------------------------------------------

class StructureGraph(GhidraCommand):
    """Structure an arbitrary control-flow graph.

    C++ ref: ``ghidra_process.cc::StructureGraph``
    """

    def __init__(self, sin: BinaryIO, sout: BinaryIO) -> None:
        super().__init__(sin, sout)
        from ghidra.block.block import BlockGraph

        self.ingraph = BlockGraph()

    def loadParameters(self) -> None:
        super().loadParameters()
        from ghidra.console.ghidra_arch import ArchitectureGhidra

        decoder = PackedDecode(self.ghidra)
        ArchitectureGhidra.readStringStream(self._sin, decoder)
        self.ingraph.decode(decoder)

    def rawAction(self) -> None:
        from ghidra.block.block import BlockGraph
        from ghidra.block.blockaction import CollapseStructure

        resultgraph = BlockGraph()
        rootlist = []

        resultgraph.buildCopy(self.ingraph)
        resultgraph.structureLoops(rootlist)
        resultgraph.calcForwardDominator(rootlist)

        collapse = CollapseStructure(resultgraph)
        collapse.collapseAll()
        resultgraph.orderBlocks()

        send_int_open(self._sout)
        encoder = PackedEncode(self._sout)
        resultgraph.encode(encoder)
        send_int_close(self._sout)
        self.ingraph.clear()


# ---------------------------------------------------------------------------
# SetAction
# ---------------------------------------------------------------------------

class SetAction(GhidraCommand):
    """Set the root action and/or toggle output components.

    C++ ref: ``ghidra_process.cc::SetAction``
    """

    def __init__(self, sin: BinaryIO, sout: BinaryIO) -> None:
        super().__init__(sin, sout)
        self._actionstring: str = ""
        self._printstring: str = ""
        self.res: bool = False

    def loadParameters(self) -> None:
        super().loadParameters()
        from ghidra.console.ghidra_arch import ArchitectureGhidra

        self._actionstring = ""
        self._printstring = ""
        self._actionstring = ArchitectureGhidra.readStringStream(self._sin)
        self._printstring = ArchitectureGhidra.readStringStream(self._sin)

    def rawAction(self) -> None:
        from ghidra.analysis.flow import FlowInfo

        self.res = False

        if self._actionstring:
            self.ghidra.allacts.setCurrent(self._actionstring)

        if self._printstring:
            ps = self._printstring
            if ps == "tree":
                self.ghidra.setSendSyntaxTree(True)
            elif ps == "notree":
                self.ghidra.setSendSyntaxTree(False)
            elif ps == "c":
                self.ghidra.setSendCCode(True)
            elif ps == "noc":
                self.ghidra.setSendCCode(False)
            elif ps == "parammeasures":
                self.ghidra.setSendParamMeasures(True)
            elif ps == "noparammeasures":
                self.ghidra.setSendParamMeasures(False)
            elif ps == "jumpload":
                self.ghidra.flowoptions |= FlowInfo.record_jumploads
            elif ps == "nojumpload":
                self.ghidra.flowoptions &= ~FlowInfo.record_jumploads
            else:
                raise LowlevelError("Unknown print action: " + ps)

        self.res = True

    def sendResult(self) -> None:
        from ghidra.console.ghidra_arch import ArchitectureGhidra

        ArchitectureGhidra.writeStringStream(self._sout, "t" if self.res else "f")
        super().sendResult()


# ---------------------------------------------------------------------------
# SetOptions
# ---------------------------------------------------------------------------

class SetOptions(GhidraCommand):
    """Toggle decompiler options.

    C++ ref: ``ghidra_process.cc::SetOptions``
    """

    def __init__(self, sin: BinaryIO, sout: BinaryIO) -> None:
        super().__init__(sin, sout)
        self._decoder = None
        self.res: bool = False

    def __del__(self) -> None:
        self._decoder = None

    def loadParameters(self) -> None:
        super().loadParameters()
        from ghidra.console.ghidra_arch import ArchitectureGhidra

        self._decoder = PackedDecode(self.ghidra)
        ArchitectureGhidra.readStringStream(self._sin, self._decoder)

    def rawAction(self) -> None:
        self.res = False
        assert self.ghidra is not None
        assert self._decoder is not None

        self.ghidra.resetDefaults()
        self.ghidra.options.decode(self._decoder)
        self._decoder = None
        self.res = True

    def sendResult(self) -> None:
        from ghidra.console.ghidra_arch import ArchitectureGhidra

        ArchitectureGhidra.writeStringStream(self._sout, "t" if self.res else "f")
        super().sendResult()


# ---------------------------------------------------------------------------
# Remote console hook
# ---------------------------------------------------------------------------

def connect_to_console(fd) -> None:
    """Remote-console hook used only by native __REMOTE_SOCKET__ builds."""
    return None


# ---------------------------------------------------------------------------
# Command map and dispatch
# ---------------------------------------------------------------------------

def build_command_map(sin: BinaryIO, sout: BinaryIO) -> Dict[str, GhidraCommand]:
    """Create the command dispatch map.

    C++ ref: ``GhidraDecompCapability::initialize``
    """
    cap = GhidraDecompCapability.getInstance(sin, sout)
    cap.initialize()
    return GhidraCapability.commandmap


def read_command(sin: BinaryIO, sout: BinaryIO,
                 commandmap: Dict[str, GhidraCommand]) -> int:
    """Read and dispatch a single command from the Ghidra client.

    C++ ref: ``GhidraCapability::readCommand``
    """
    GhidraCapability.commandmap = commandmap
    return GhidraCapability.readCommand(sin, sout)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _read_stream_content(sin: BinaryIO) -> str:
    """Read raw stream content until a zero byte (burst boundary).

    After reading the string-open burst, this reads the decimal text
    payload before the string-close burst.  The zero byte that starts
    the next burst alignment is consumed but not included.
    """
    parts: list[bytes] = []
    c = sin.read(1)
    while c and c[0] > 0:
        parts.append(c)
        c = sin.read(1)
    return b"".join(parts).decode("utf-8", errors="replace")


def _decode_addr_xml(xml_bytes: bytes, arch) -> Optional:
    """Decode an <addr> XML element into an Address."""
    if not xml_bytes:
        return None
    try:
        import xml.etree.ElementTree as ET
        root = ET.fromstring(xml_bytes)
        space_name = root.get("space", "ram")
        offset_str = root.get("offset", "0x0")
        offset = int(offset_str, 0)

        from ghidra.core.address import Address
        # Try to resolve the space from the architecture
        space = None
        if arch is not None:
            for i in range(arch.numSpaces()):
                spc = arch.getSpace(i)
                if spc is not None and spc.getName() == space_name:
                    space = spc
                    break
        if space is None:
            return Address(None, offset)
        return Address(space, offset)
    except Exception:
        return None
