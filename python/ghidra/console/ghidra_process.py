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

from typing import BinaryIO, Dict, List, Optional, TYPE_CHECKING

from ghidra.core.error import LowlevelError, RecovError
from ghidra.console.protocol import (
    JavaError,
    read_to_any_burst, read_string_stream, read_string_stream_raw,
    write_string_stream,
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


# ---------------------------------------------------------------------------
# Base command class
# ---------------------------------------------------------------------------

class GhidraCommand:
    """Base class for a command from the Ghidra client.

    Lifecycle: loadParameters() → rawAction() → sendResult()

    C++ ref: ``ghidra_process.hh::GhidraCommand``
    """

    def __init__(self, sin: BinaryIO, sout: BinaryIO) -> None:
        self._sin: BinaryIO = sin
        self._sout: BinaryIO = sout
        self.ghidra: Optional[ArchitectureGhidra] = None
        self.status: int = 0  # 0 = continue, 1 = terminate

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
        except JavaError as err:
            pass_java_exception(self._sout, err.type, str(err))
            return self.status
        except RecovError as err:
            if self.ghidra is not None:
                self.ghidra.printMessage("Recoverable Error: " + str(err))
        except LowlevelError as err:
            if self.ghidra is not None:
                self.ghidra.printMessage("Low-level Error: " + str(err))
        except Exception as err:
            if self.ghidra is not None:
                self.ghidra.printMessage("Error: " + str(err))

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
        self.ghidra.init()

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
        # Read the encoded address
        addr_xml = read_string_stream_raw(self._sin)
        self._addr = _decode_addr_xml(addr_xml, self.ghidra)

    def rawAction(self) -> None:
        if self.ghidra is None or self._addr is None:
            raise LowlevelError("Bad decompile address")

        # Look up / create the function at the address
        fd = None
        if self.ghidra.symboltab is not None:
            scope = self.ghidra.symboltab.getGlobalScope()
            if scope is not None and hasattr(scope, 'queryFunction'):
                fd = scope.queryFunction(self._addr)

        if fd is None:
            raise LowlevelError(f"Bad decompile address: {self._addr}")

        if not fd.isProcStarted():
            act = self.ghidra.allacts.getCurrent()
            if act is not None:
                act.reset(fd)
                act.perform(fd)

        # Send results
        send_int_open(self._sout)

        if fd.isProcComplete():
            # TODO: encode fd (syntax tree XML) when getSendSyntaxTree()

            # Emit C code if requested
            if (self.ghidra.getSendCCode() and
                    self.ghidra.allacts.getCurrentName() == "decompile"):
                if self.ghidra.print_ is not None:
                    self.ghidra.print_.docFunction(fd)

            # Minimal <doc> wrapper — full encoding will be added later
            self._sout.write(b"<doc/>")

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
        self._graph_xml: bytes = b""

    def loadParameters(self) -> None:
        super().loadParameters()
        self._graph_xml = read_string_stream_raw(self._sin)

    def rawAction(self) -> None:
        # TODO: parse the graph XML, build BlockGraph, structure it, encode result
        from ghidra.block.block import BlockGraph
        from ghidra.block.blockaction import CollapseStructure

        # For now, send back an empty result
        send_int_open(self._sout)
        self._sout.write(b"<block/>")
        send_int_close(self._sout)


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
        self._actionstring = read_string_stream(self._sin)
        self._printstring = read_string_stream(self._sin)

    def rawAction(self) -> None:
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
                self.ghidra.flowoptions |= 0x20  # FlowInfo::record_jumploads
            elif ps == "nojumpload":
                self.ghidra.flowoptions &= ~0x20
            else:
                raise LowlevelError("Unknown print action: " + ps)

        self.res = True

    def sendResult(self) -> None:
        write_string_stream(self._sout, "t" if self.res else "f")
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
        self._options_xml: bytes = b""
        self.res: bool = False

    def loadParameters(self) -> None:
        super().loadParameters()
        self._options_xml = read_string_stream_raw(self._sin)

    def rawAction(self) -> None:
        self.res = False
        if self.ghidra is not None:
            self.ghidra.resetDefaults()
            if self.ghidra.options is not None and self._options_xml:
                # TODO: parse <optionslist> XML and apply to ghidra.options
                pass
            self.res = True

    def sendResult(self) -> None:
        write_string_stream(self._sout, "t" if self.res else "f")
        super().sendResult()


# ---------------------------------------------------------------------------
# Command map and dispatch
# ---------------------------------------------------------------------------

def build_command_map(sin: BinaryIO, sout: BinaryIO) -> Dict[str, GhidraCommand]:
    """Create the command dispatch map.

    C++ ref: ``GhidraDecompCapability::initialize``
    """
    return {
        "registerProgram": RegisterProgram(sin, sout),
        "deregisterProgram": DeregisterProgram(sin, sout),
        "flushNative": FlushNative(sin, sout),
        "decompileAt": DecompileAt(sin, sout),
        "structureGraph": StructureGraph(sin, sout),
        "setAction": SetAction(sin, sout),
        "setOptions": SetOptions(sin, sout),
    }


def read_command(sin: BinaryIO, sout: BinaryIO,
                 commandmap: Dict[str, GhidraCommand]) -> int:
    """Read and dispatch a single command from the Ghidra client.

    C++ ref: ``GhidraCapability::readCommand``
    """
    # Align to command-open burst
    while True:
        burst = read_to_any_burst(sin)
        if burst == BURST_COMMAND_OPEN:
            break

    # Read the command name
    function_name = read_string_stream(sin)

    cmd = commandmap.get(function_name)
    if cmd is None:
        # Unknown command — send error response (C++ uses warning bursts 0x10/0x11)
        send_cmd_response_open(sout)
        send_warning_open(sout)
        sout.write(f"Bad command: {function_name}".encode("utf-8"))
        send_warning_close(sout)
        send_cmd_response_close(sout)
        sout.flush()
        return 0

    return cmd.doit()


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
