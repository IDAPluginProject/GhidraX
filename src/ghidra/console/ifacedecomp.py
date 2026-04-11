"""
Corresponds to: ifacedecomp.hh / ifacedecomp.cc

Console interface commands for the decompiler engine.
Provides IfaceDecompData, IfaceDecompCommand, IfaceDecompCapability,
and the full set of decompiler console commands.
"""

from __future__ import annotations

import io
import os
import time
from typing import Optional, List, TYPE_CHECKING

from ghidra.console.interface import (
    IfaceData, IfaceCommand, IfaceCapability, IfaceStatus,
    IfaceError,
    IfaceParseError, IfaceExecutionError,
    IfcQuit, IfcHistory, IfcOpenfile, IfcOpenfileAppend, IfcClosefile, IfcEcho,
)
from ghidra.analysis.callgraph import CallGraph
from ghidra.analysis.dynamic import DynamicHash
from ghidra.analysis.graph import dump_controlflow_graph, dump_dataflow_graph, dump_dom_graph
from ghidra.analysis.prefersplit import PreferSplitRecord
from ghidra.analysis.rangeutil import ValueSetSolver, WidenerFull, WidenerNone
from ghidra.block.block import BlockGraph
from ghidra.block.collapse import CollapseStructure
from ghidra.core.address import Address
from ghidra.core.address import Range
from ghidra.core.address import SeqNum
from ghidra.core.globalcontext import TrackedContext
from ghidra.core.grammar import (
    parse_C,
    parse_machaddr,
    parse_protopieces,
    parse_toseparator,
    parse_type,
    parse_varnode,
)
from ghidra.core.marshal import XmlDecode, XmlEncode
from ghidra.core.opcodes import OpCode
from ghidra.core.error import LowlevelError, ParseError, RecovError
from ghidra.core.space import IPTR_CONSTANT, IPTR_INTERNAL, IPTR_PROCESSOR, IPTR_SPACEBASE
from ghidra.core.xml import DecoderError, DocumentStorage
from ghidra.arch.inject import InjectPayload
from ghidra.fspec.fspec import ParameterPieces, ProtoModel
from ghidra.fspec.paramid import ParamIDAnalysis
from ghidra.database.database import FunctionSymbol, Symbol
from ghidra.ir.varnode import Varnode
from ghidra.types.datatype import (
    Datatype,
    TypeFactory,
    TypePointerRel,
    TYPE_INT,
    TYPE_STRUCT,
    TYPE_UINT,
    TYPE_UNKNOWN,
    TYPE_UNION,
)
from ghidra.transform.action import Action
from ghidra.transform.rulecompile import RuleCompile
from ghidra.transform.unify import UnifyCPrinter

if TYPE_CHECKING:
    from ghidra.arch.architecture import Architecture
    from ghidra.ir.funcdata import Funcdata


# =========================================================================
# IfaceAssemblyEmit
# =========================================================================

class IfaceAssemblyEmit:
    """Disassembly emitter that prints to a console stream."""

    def __init__(self, ostream: io.TextIOBase, mnemonicpad: int = 10) -> None:
        self._ostream = ostream
        self._mnemonicpad = mnemonicpad

    def dump(self, addr, mnem: str, body: str) -> None:
        self._ostream.write(addr.printRaw())
        self._ostream.write(f": {mnem}")
        pad = self._mnemonicpad - len(mnem)
        if pad > 0:
            self._ostream.write(" " * pad)
        self._ostream.write(f"{body}\n")


def _get_print_language(conf):
    printer = getattr(conf, "print", None)
    if printer is None:
        printer = getattr(conf, "print_", None)
    if printer is None and hasattr(conf, "getPrintLanguage"):
        printer = conf.getPrintLanguage()
    return printer


def _print_data(ostream: io.TextIOBase, buffer, size: int, baseaddr: Address) -> None:
    if buffer is None:
        ostream.write("Address not present in binary image\n")
        return

    addr = baseaddr.getOffset()
    endaddr = addr + size
    start = addr & ~0xF

    while start < endaddr:
        ostream.write(f"{start:08x}: ")
        for i in range(16):
            cur = start + i
            if cur < addr or cur >= endaddr:
                ostream.write("   ")
            else:
                ostream.write(f"{int(buffer[cur - addr]):02x} ")
        ostream.write("  ")
        for i in range(16):
            cur = start + i
            if cur < addr or cur >= endaddr:
                ostream.write(" ")
            else:
                ch = int(buffer[cur - addr])
                ostream.write(chr(ch) if chr(ch).isprintable() else ".")
        ostream.write("\n")
        start += 16


def _clone_tracked_context(entry: TrackedContext) -> TrackedContext:
    clone = TrackedContext()
    loc = entry.loc
    if hasattr(loc, "space") and hasattr(loc, "offset") and hasattr(loc, "size"):
        clone.loc = type(loc)(loc.space, loc.offset, loc.size)
    else:
        clone.loc = loc
    clone.val = entry.val
    return clone


def _iter_register_pairs(reglist) -> list[tuple[object, str]]:
    if isinstance(reglist, dict):
        if not reglist:
            return []
        first_key = next(iter(reglist))
        if hasattr(first_key, "space") and hasattr(first_key, "offset") and hasattr(first_key, "size"):
            items = list(reglist.items())
        else:
            items = [(vndata, name) for name, vndata in reglist.items()]
    else:
        items = list(reglist)
    items.sort(key=lambda item: item[0])
    return items


def _read_stream_word(stream: io.TextIOBase) -> str:
    chars: list[str] = []
    while True:
        ch = stream.read(1)
        if not ch:
            return ""
        if not ch.isspace():
            chars.append(ch)
            break
    while True:
        ch = stream.read(1)
        if not ch or ch.isspace():
            break
        chars.append(ch)
    return "".join(chars)


def _read_nonspace_char(stream: io.TextIOBase) -> str:
    while True:
        ch = stream.read(1)
        if not ch or not ch.isspace():
            return ch


def _read_to_delimiter(stream: io.TextIOBase, delim: str) -> str:
    chars: list[str] = []
    while True:
        ch = stream.read(1)
        if not ch or ch == delim:
            break
        chars.append(ch)
    return "".join(chars)


def _read_decimal_int(stream: io.TextIOBase) -> Optional[int]:
    while True:
        pos = stream.tell()
        ch = stream.read(1)
        if not ch:
            return None
        if not ch.isspace():
            stream.seek(pos)
            break

    pos = stream.tell()
    sign = ""
    ch = stream.read(1)
    if ch in "+-":
        sign = ch
        ch = stream.read(1)
    if not ch or not ch.isdigit():
        stream.seek(pos)
        return None

    digits = [ch]
    while True:
        pos = stream.tell()
        ch = stream.read(1)
        if not ch or not ch.isdigit():
            stream.seek(pos)
            break
        digits.append(ch)
    return int(sign + "".join(digits), 10)


def _read_auto_int(stream: io.TextIOBase) -> Optional[int]:
    token = _read_stream_word(stream)
    if len(token) == 0:
        return None
    try:
        return int(token, 0)
    except ValueError:
        return None


# =========================================================================
# IfaceDecompData
# =========================================================================

class IfaceDecompData(IfaceData):
    """Common data shared by decompiler commands."""

    def __init__(self) -> None:
        super().__init__()
        self.fd: Optional[Funcdata] = None
        self.conf: Optional[Architecture] = None
        self.cgraph = None
        self.testCollection = None
        self.experimental_file = ""
        self.jumptabledebug = False

    def __del__(self) -> None:
        self.cgraph = None
        self.conf = None
        self.testCollection = None
        self.experimental_file = ""
        self.jumptabledebug = False

    def allocateCallGraph(self) -> None:
        self.cgraph = CallGraph(self.conf)

    def abortFunction(self, ostream) -> None:
        """Clear references to current function."""
        if self.fd is None:
            return
        ostream.write(f"Unable to proceed with function: {self.fd.getName()}\n")
        self.conf.clearAnalysis(self.fd)
        self.fd = None

    def clearArchitecture(self) -> None:
        """Free all resources for the current architecture/program."""
        self.conf = None
        self.fd = None

    def followFlow(self, ostream, size: int) -> None:
        """Generate raw p-code for the current function."""
        try:
            if self.jumptabledebug:
                self.fd.enableJTCallback(_jump_callback)
            if size == 0:
                spc = self.fd.getAddress().getSpace()
                baddr = Address(spc, 0)
                eaddr = Address(spc, spc.getHighest())
                self.fd.followFlow(baddr, eaddr)
            else:
                start = self.fd.getAddress()
                self.fd.followFlow(start, start + size)
            ostream.write(f"Function {self.fd.getName()}: ")
            ostream.write(self.fd.getAddress().printRaw())
            ostream.write("\n")
        except RecovError as err:
            ostream.write(f"Function {self.fd.getName()}: {err.explain}\n")

    def readVarnode(self, stream):
        """Read a varnode from the given stream."""
        if self.fd is None:
            raise IfaceExecutionError("No function selected")

        loc, defsize, pc, uq = parse_varnode(stream, self.conf.types)
        vn = None

        if loc.getSpace().getType() == IPTR_CONSTANT:
            if pc.isInvalid() or uq == -1:
                raise IfaceParseError("Missing p-code sequence number")
            op = self.fd.findOp(SeqNum(pc, uq))
            if op is not None:
                for slot in range(op.numInput()):
                    candidate = op.getIn(slot)
                    if candidate.getAddr() == loc:
                        vn = candidate
                        break
        elif pc.isInvalid() and uq == -1:
            vn = self.fd.findVarnodeInput(defsize, loc)
        elif (not pc.isInvalid()) and uq != -1:
            vn = self.fd.findVarnodeWritten(defsize, loc, pc, uq)
        else:
            for candidate in self.fd.beginLoc(defsize, loc):
                vn = candidate
                if vn.isFree():
                    continue
                if vn.isWritten():
                    if (not pc.isInvalid()) and vn.getDef().getAddr() == pc:
                        break
                    if uq != -1 and vn.getDef().getTime() == uq:
                        break

        if vn is None:
            raise IfaceExecutionError("Requested varnode does not exist")
        return vn

    def readSymbol(self, name: str) -> list:
        """Find a symbol by name."""
        scope = self.conf.symboltab.getGlobalScope() if self.fd is None else self.fd.getScopeLocal()
        basename: list[str] = []
        scope = self.conf.symboltab.resolveScopeFromSymbolName(name, "::", basename, scope)
        if scope is None:
            raise IfaceParseError("Bad namespace for symbol: " + name)
        symbol = scope.queryByName(basename[0])
        if symbol is None:
            return []
        if isinstance(symbol, list):
            return symbol
        return [symbol]


_jumpstack: list[object] = []
_dcp_callback: Optional[IfaceDecompData] = None
_status_callback: Optional[IfaceStatus] = None


def _jump_callback(orig, fd) -> None:
    newdcp = _dcp_callback
    newstatus = _status_callback
    assert newdcp is not None
    assert newstatus is not None

    _jumpstack.append(newdcp.fd)
    newdcp.fd = fd
    rootaction = newdcp.conf.allacts.getCurrent()
    rootaction.reset(newdcp.fd)
    rootaction.setBreakPoint(Action.tmpbreak_start, rootaction.getName())
    res = rootaction.perform(newdcp.fd)
    if res >= 0:
        raise LowlevelError("Did not catch jumptable breakpoint")
    newstatus.optr.write("Breaking for jumptable partial function\n")
    newstatus.optr.write(f"{newdcp.fd.getName()}\n")
    newstatus.optr.write('Type "cont" to continue debugging.\n')
    newstatus.optr.write('After completion type "quit" to continue in parent.\n')
    mainloop(newstatus)
    newstatus.done = False
    newstatus.optr.write("Finished jumptable partial function\n")
    newdcp.fd = _jumpstack.pop()


# =========================================================================
# IfaceDecompCommand
# =========================================================================

class IfaceDecompCommand(IfaceCommand):
    """Root class for all decompiler specific commands."""

    def __init__(self) -> None:
        super().__init__()
        self.status: Optional[IfaceStatus] = None
        self.dcp: Optional[IfaceDecompData] = None

    def setData(self, root: IfaceStatus, data) -> None:
        self.status = root
        self.dcp = data

    def getModule(self) -> str:
        return "decompile"

    def createData(self) -> IfaceDecompData:
        return IfaceDecompData()

    def iterationCallback(self, fd) -> None:
        """Per-function aspect of this command."""
        pass

    def iterateScopesRecursive(self, scope) -> None:
        """Iterate recursively over all functions in given scope."""
        if not scope.isGlobal():
            return
        self.iterateFunctionsAddrOrder(scope)
        for child in scope.childrenBegin():
            self.iterateScopesRecursive(child)

    def iterateFunctionsAddrOrder(self, scope=None) -> None:
        """Iterate over all functions in a given scope or all scopes."""
        if scope is not None:
            for entry in scope.begin():
                sym = entry.getSymbol()
                if isinstance(sym, FunctionSymbol):
                    self.iterationCallback(sym.getFunction())
            return
        if self.dcp is None or self.dcp.conf is None:
            raise IfaceExecutionError("No architecture loaded")
        self.iterateScopesRecursive(self.dcp.conf.symboltab.getGlobalScope())

    def iterateFunctionsLeafOrder(self) -> None:
        """Iterate command over all functions in a call-graph traversal."""
        if self.dcp is None or self.dcp.conf is None:
            raise IfaceExecutionError("No architecture loaded")
        if self.dcp.cgraph is None:
            raise IfaceExecutionError("No callgraph present")
        node = self.dcp.cgraph.initLeafWalk()
        while node is not None:
            if len(node.getName()) != 0:
                fd = node.getFuncdata()
                if fd is not None:
                    self.iterationCallback(fd)
            node = self.dcp.cgraph.nextLeaf(node)


# =========================================================================
# Comment commands
# =========================================================================

class IfcComment(IfaceDecompCommand):
    """A comment within a command script: `// ...` or `# ...` or `% ...`"""
    def execute(self, args: str) -> None:
        pass  # Do nothing


# =========================================================================
# Core decompiler commands
# =========================================================================

class IfcSource(IfaceDecompCommand):
    """Execute a command script: `source <filename>`"""
    def execute(self, args: str) -> None:
        filename = args.strip()
        if not filename:
            raise IfaceParseError("filename parameter required for source")
        if self.status is not None:
            self.status.pushScript(filename, f"{filename}> ")


class IfcOption(IfaceDecompCommand):
    """Adjust a decompiler option: `option <name> [<p1>] [<p2>] [<p3>]`"""
    def execute(self, args: str) -> None:
        if self.dcp is None or self.dcp.conf is None:
            raise IfaceExecutionError("No load image present")
        parts = args.split()
        if not parts:
            raise IfaceParseError("Missing option name")
        optname = parts[0]
        params = parts[1:4]
        if len(parts) > 4:
            raise IfaceParseError("Too many option parameters")
        p1 = params[0] if len(params) > 0 else ""
        p2 = params[1] if len(params) > 1 else ""
        p3 = params[2] if len(params) > 2 else ""
        try:
            from ghidra.core.marshal import ElementId

            res = self.dcp.conf.options.set(ElementId.find(optname, 0), p1, p2, p3)
            self.status.optr.write(f"{res}\n")
        except ParseError as err:
            self.status.optr.write(f"{err.explain}\n")
            raise IfaceParseError("Bad option") from err
        except RecovError as err:
            self.status.optr.write(f"{err.explain}\n")
            raise IfaceExecutionError("Bad option") from err


class IfcParseLine(IfaceDecompCommand):
    """Parse a line of C syntax: `parse line ...`"""
    def execute(self, args: str) -> None:
        if self.dcp is None or self.dcp.conf is None:
            raise IfaceExecutionError("No load image present")
        if not args.strip():
            raise IfaceParseError("No input")
        try:
            parse_C(self.dcp.conf, io.StringIO(args))
        except ParseError as err:
            self.status.optr.write(f"Error in C syntax: {err.explain}\n")
            raise IfaceExecutionError("Bad C syntax") from err


class IfcParseFile(IfaceDecompCommand):
    """Parse a file with C declarations: `parse file <filename>`"""
    def execute(self, args: str) -> None:
        if self.dcp is None or self.dcp.conf is None:
            raise IfaceExecutionError("No load image present")
        filename = args.strip()
        if not filename:
            raise IfaceParseError("Missing filename")
        if not os.path.exists(filename):
            raise IfaceExecutionError("Unable to open file: " + filename)
        with open(filename, "r", encoding="utf-8") as fs:
            try:
                parse_C(self.dcp.conf, fs)
            except ParseError as err:
                self.status.optr.write(f"Error in C syntax: {err.explain}\n")
                raise IfaceExecutionError("Bad C syntax") from err


class IfcAdjustVma(IfaceDecompCommand):
    """Change the base address: `adjust vma <offset>`"""
    def execute(self, args: str) -> None:
        if self.dcp is None or self.dcp.conf is None:
            raise IfaceExecutionError("No load image present")
        val = args.strip()
        if not val:
            raise IfaceParseError("No adjustment parameter")
        try:
            adjust = int(val, 0)
        except ValueError as e:
            raise IfaceParseError("No adjustment parameter") from e
        if adjust == 0:
            raise IfaceParseError("No adjustment parameter")
        self.dcp.conf.loader.adjustVma(adjust)


class IfcFuncload(IfaceDecompCommand):
    """Make a specific function current: `load function <functionname>`"""
    def execute(self, args: str) -> None:
        funcname = args.strip()
        if self.dcp is None or self.dcp.conf is None:
            raise IfaceExecutionError("No image loaded")
        basename: list[str] = []
        funcscope = self.dcp.conf.symboltab.resolveScopeFromSymbolName(funcname, "::", basename, None)
        if funcscope is None:
            raise IfaceExecutionError("Bad namespace: " + funcname)
        self.dcp.fd = funcscope.queryFunction(basename[0])
        if self.dcp.fd is None:
            raise IfaceExecutionError(f"Unknown function name: {funcname}")
        if not self.dcp.fd.hasNoCode():
            self.dcp.followFlow(self.status.optr, 0)


class IfcAddrrangeLoad(IfaceDecompCommand):
    """Create a new function at an address: `load addr <address> [<funcname>]`"""
    def execute(self, args: str) -> None:
        stream = io.StringIO(args)
        offset, size = parse_machaddr(stream, 0, self.dcp.conf.types)
        if size <= offset.getAddrSize():
            size = 0
        if self.dcp.conf.loader is None:
            raise IfaceExecutionError("No binary loaded")
        name = stream.read().strip()
        if not name:
            name = self.dcp.conf.nameFunction(offset)
        self.dcp.fd = self.dcp.conf.symboltab.getGlobalScope().addFunction(offset, name).getFunction()
        self.dcp.followFlow(self.status.optr, size)


class IfcCleararch(IfaceDecompCommand):
    """Clear the current architecture: `clear architecture`"""
    def execute(self, args: str) -> None:
        self.dcp.clearArchitecture()


class IfcReadSymbols(IfaceDecompCommand):
    """Read in symbols from the load image: `read symbols`"""
    def execute(self, args: str) -> None:
        if self.dcp is None or self.dcp.conf is None:
            raise IfaceExecutionError("No load image present")
        if self.dcp.conf.loader is None:
            raise IfaceExecutionError("No binary loaded")
        self.dcp.conf.readLoaderSymbols("::")


class IfcDecompile(IfaceDecompCommand):
    """Decompile the current function: `decompile`"""
    def execute(self, args: str) -> None:
        if self.dcp is None or self.dcp.fd is None:
            raise IfaceExecutionError("No function selected")
        fd = self.dcp.fd
        optr = self.status.optr if self.status else io.StringIO()

        if fd.hasNoCode():
            optr.write(f"No code for {fd.getName()}\n")
            return
        if fd.isProcStarted():
            optr.write("Clearing old decompilation\n")
            self.dcp.conf.clearAnalysis(fd)

        optr.write(f"Decompiling {fd.getName()}\n")
        act = self.dcp.conf.allacts.getCurrent()
        act.reset(fd)
        res = act.perform(fd)
        if res < 0:
            optr.write("Break at ")
            act.printState(optr)
        else:
            optr.write("Decompilation complete")
            if res == 0:
                optr.write(" (no change)")
        optr.write("\n")


class IfcPrintLanguage(IfaceDecompCommand):
    """Set the output language: `print language`"""
    def execute(self, args: str) -> None:
        if self.dcp is None or self.dcp.fd is None:
            raise IfaceExecutionError("No function selected")
        lang = args.split()
        if len(lang) == 0:
            raise IfaceParseError("No print language specified")
        langroot = lang[0] + "-language"
        printer = _get_print_language(self.dcp.conf)
        curlangname = printer.getName()
        self.dcp.conf.setPrintLanguage(langroot)
        printer = _get_print_language(self.dcp.conf)
        printer.setOutputStream(self.status.fileoptr if self.status else io.StringIO())
        printer.docFunction(self.dcp.fd)
        self.dcp.conf.setPrintLanguage(curlangname)


class IfcPrintCStruct(IfaceDecompCommand):
    """Print current function with structure: `print C`"""
    def execute(self, args: str) -> None:
        if self.dcp is None or self.dcp.fd is None:
            raise IfaceExecutionError("No function selected")
        printer = _get_print_language(self.dcp.conf)
        printer.setOutputStream(self.status.fileoptr if self.status else io.StringIO())
        printer.docFunction(self.dcp.fd)


class IfcPrintCFlat(IfaceDecompCommand):
    """Print current function without control-flow: `print C flat`"""
    def execute(self, args: str) -> None:
        if self.dcp is None or self.dcp.fd is None:
            raise IfaceExecutionError("No function selected")
        printer = _get_print_language(self.dcp.conf)
        printer.setOutputStream(self.status.fileoptr if self.status else io.StringIO())
        printer.setFlat(True)
        printer.docFunction(self.dcp.fd)
        printer.setFlat(False)


class IfcPrintCXml(IfaceDecompCommand):
    """Print C output in XML format: `print C xml`"""
    def execute(self, args: str) -> None:
        if self.dcp is None or self.dcp.fd is None:
            raise IfaceExecutionError("No function selected")
        printer = _get_print_language(self.dcp.conf)
        optr = self.status.fileoptr if self.status else io.StringIO()
        printer.setOutputStream(optr)
        printer.setMarkup(True)
        printer.setPackedOutput(False)
        printer.docFunction(self.dcp.fd)
        optr.write("\n")
        printer.setMarkup(False)


class IfcPrintCGlobals(IfaceDecompCommand):
    """Print declarations for global variables: `print C globals`"""
    def execute(self, args: str) -> None:
        if self.dcp is None or self.dcp.conf is None:
            raise IfaceExecutionError("No load image present")
        printer = _get_print_language(self.dcp.conf)
        printer.setOutputStream(self.status.fileoptr if self.status else io.StringIO())
        printer.docAllGlobals()


class IfcPrintCTypes(IfaceDecompCommand):
    """Print known data-types: `print C types`"""
    def execute(self, args: str) -> None:
        if self.dcp is None or self.dcp.conf is None:
            raise IfaceExecutionError("No load image present")
        if self.dcp.conf.types is not None:
            printer = _get_print_language(self.dcp.conf)
            printer.setOutputStream(self.status.fileoptr if self.status else io.StringIO())
            printer.docTypeDefinitions(self.dcp.conf.types)


class IfcProduceC(IfaceDecompCommand):
    """Decompile and produce C for all functions: `produce C`"""
    def execute(self, args: str) -> None:
        parts = args.split()
        if len(parts) == 0:
            raise IfaceParseError("Need file name to write to")
        printer = _get_print_language(self.dcp.conf)
        with open(parts[0], "w", encoding="utf-8") as ostream:
            printer.setOutputStream(ostream)
            self.iterateFunctionsAddrOrder()

    def iterationCallback(self, fd) -> None:
        if self.dcp is None or self.dcp.conf is None:
            return
        optr = self.status.optr if self.status else io.StringIO()
        if fd.hasNoCode():
            optr.write(f"No code for {fd.getName()}\n")
            return
        try:
            self.dcp.conf.clearAnalysis(fd)
            act = self.dcp.conf.allacts.getCurrent()
            act.reset(fd)
            start_time = time.process_time()
            act.perform(fd)
            end_time = time.process_time()
            duration = (end_time - start_time) * 1000.0
            optr.write(f"Decompiled {fd.getName()}({fd.getSize()})")
            optr.write(f" time={duration:.0f} ms\n")
            printer = _get_print_language(self.dcp.conf)
            printer.docFunction(fd)
        except LowlevelError as err:
            optr.write(f"Skipping {fd.getName()}: {err.explain}\n")
        self.dcp.conf.clearAnalysis(fd)


class IfcProducePrototypes(IfaceDecompCommand):
    """Produce prototypes for all functions: `produce prototypes`"""
    def execute(self, args: str) -> None:
        if self.dcp is None or self.dcp.conf is None:
            raise IfaceExecutionError("No load image")
        if self.dcp.cgraph is None:
            raise IfaceExecutionError("Callgraph has not been built")
        model = self.dcp.conf.evalfp_current
        optr = self.status.optr if self.status else io.StringIO()
        if model is None:
            optr.write("Always using default prototype\n")
            return
        if not model.isMerged():
            optr.write(f"Always using prototype {model.getName()}\n")
            return
        optr.write("Trying to distinguish between prototypes:\n")
        for i in range(model.numModels()):
            optr.write(f"  {model.getModel(i).getName()}\n")
        self.iterateFunctionsLeafOrder()

    def iterationCallback(self, fd) -> None:
        optr = self.status.optr if self.status else io.StringIO()
        optr.write(f"{fd.getName()} ")
        if fd.hasNoCode():
            optr.write("has no code\n")
            return
        if fd.getFuncProto().isInputLocked():
            optr.write("has locked prototype\n")
            return
        try:
            self.dcp.conf.clearAnalysis(fd)
            act = self.dcp.conf.allacts.getCurrent()
            act.reset(fd)
            start_time = time.process_time()
            act.perform(fd)
            end_time = time.process_time()
            duration = (end_time - start_time) * 1000.0
            proto = fd.getFuncProto()
            optr.write(f"proto={proto.getModelName()}")
            proto.setModelLock(True)
            optr.write(f" time={duration:.0f} ms\n")
        except LowlevelError as err:
            optr.write(f"Skipping {fd.getName()}: {err.explain}\n")
        self.dcp.conf.clearAnalysis(fd)


# =========================================================================
# Print / Debug commands (stubs)
# =========================================================================

class IfcPrintdisasm(IfaceDecompCommand):
    """Print disassembly: `disassemble`"""
    def execute(self, args: str) -> None:
        stream = io.StringIO(args)
        stream.read(0)
        fileoptr = self.status.fileoptr if self.status else io.StringIO()
        remaining = stream.read().lstrip()
        stream = io.StringIO(remaining)
        if remaining == "":
            if self.dcp is None or self.dcp.fd is None:
                raise IfaceExecutionError("No function selected")
            fileoptr.write(f"Assembly listing for {self.dcp.fd.getName()}\n")
            addr = self.dcp.fd.getAddress()
            size = self.dcp.fd.getSize()
            glb = self.dcp.fd.getArch()
        else:
            addr, size = parse_machaddr(stream, 0, self.dcp.conf.types)
            remaining = stream.read().lstrip()
            stream = io.StringIO(remaining)
            offset2, size = parse_machaddr(stream, 0, self.dcp.conf.types)
            size = offset2.getOffset() - addr.getOffset()
            glb = self.dcp.conf
        assem = IfaceAssemblyEmit(fileoptr, 10)
        while size > 0:
            sz = glb.translate.printAssembly(assem, addr)
            addr = addr + sz
            size -= sz


class IfcDump(IfaceDecompCommand):
    """Display bytes: `dump <address+size>`"""
    def execute(self, args: str) -> None:
        stream = io.StringIO(args)
        offset, size = parse_machaddr(stream, 0, self.dcp.conf.types)
        buffer = self.dcp.conf.loader.load(size, offset)
        _print_data(self.status.fileoptr if self.status else io.StringIO(), buffer, size, offset)


class IfcDumpbinary(IfaceDecompCommand):
    """Dump memory to file: `binary <address+size> <filename>`"""
    def execute(self, args: str) -> None:
        stream = io.StringIO(args)
        offset, size = parse_machaddr(stream, 0, self.dcp.conf.types)
        filename = stream.read().strip()
        if filename == "":
            raise IfaceParseError("Missing file name for binary dump")
        try:
            with open(filename, "wb") as ostream:
                buffer = self.dcp.conf.loader.load(size, offset)
                ostream.write(bytes(buffer))
        except OSError as err:
            raise IfaceExecutionError("Unable to open file " + filename) from err


class IfcPrintRaw(IfaceDecompCommand):
    """Print raw p-code: `print raw`"""
    def execute(self, args: str) -> None:
        if self.dcp is None or self.dcp.fd is None:
            raise IfaceExecutionError("No function selected")
        fileoptr = self.status.fileoptr if self.status else io.StringIO()
        self.dcp.fd.printRaw(fileoptr)


class IfcPrintTree(IfaceDecompCommand):
    """Print varnode tree: `print tree varnode`"""
    def execute(self, args: str) -> None:
        if self.dcp is None or self.dcp.fd is None:
            raise IfaceExecutionError("No function selected")
        self.dcp.fd.printVarnodeTree(self.status.fileoptr if self.status else io.StringIO())


class IfcPrintBlocktree(IfaceDecompCommand):
    """Print block tree: `print tree block`"""
    def execute(self, args: str) -> None:
        if self.dcp is None or self.dcp.fd is None:
            raise IfaceExecutionError("No function selected")
        self.dcp.fd.printBlockTree(self.status.fileoptr if self.status else io.StringIO())


class IfcPrintSpaces(IfaceDecompCommand):
    """Print address spaces: `print spaces`"""
    def execute(self, args: str) -> None:
        if self.dcp is None or self.dcp.conf is None:
            raise IfaceExecutionError("No load image present")
        fileoptr = self.status.fileoptr if self.status else io.StringIO()
        num = self.dcp.conf.numSpaces()
        for i in range(num):
            spc = self.dcp.conf.getSpace(i)
            if spc is None:
                continue
            fileoptr.write(f"{spc.getIndex()} : '{spc.getShortcut()}' {spc.getName()}")
            if spc.getType() == IPTR_CONSTANT:
                fileoptr.write(" constant ")
            elif spc.getType() == IPTR_PROCESSOR:
                fileoptr.write(" processor")
            elif spc.getType() == IPTR_SPACEBASE:
                fileoptr.write(" spacebase")
            elif spc.getType() == IPTR_INTERNAL:
                fileoptr.write(" internal ")
            else:
                fileoptr.write(" special  ")
            if spc.isBigEndian():
                fileoptr.write(" big  ")
            else:
                fileoptr.write(" small")
            fileoptr.write(f" addrsize={spc.getAddrSize()} wordsize={spc.getWordSize()}")
            fileoptr.write(f" delay={spc.getDelay()}\n")


class IfcPrintHigh(IfaceDecompCommand):
    """Print high-level variable: `print high`"""
    def execute(self, args: str) -> None:
        if self.dcp is None or self.dcp.fd is None:
            raise IfaceExecutionError("No function selected")
        varname = args.split(None, 1)[0] if args.split() else ""
        high = self.dcp.fd.findHigh(varname)
        if high is None:
            raise IfaceExecutionError("Unknown variable name: " + varname)
        optr = self.status.optr if self.status else io.StringIO()
        high.printInfo(optr)


class IfcPrintParamMeasures(IfaceDecompCommand):
    """Print parameter measures: `print parammeasures`"""
    def execute(self, args: str) -> None:
        if self.dcp is None or self.dcp.fd is None:
            raise IfaceExecutionError("No function selected")
        fileoptr = self.status.fileoptr if self.status else io.StringIO()
        pidanalysis = ParamIDAnalysis(self.dcp.fd, False)
        fileoptr.write(pidanalysis.savePretty(True))
        fileoptr.write("\n")


class IfcPrintVarnode(IfaceDecompCommand):
    """Print varnode: `print varnode`"""
    def execute(self, args: str) -> None:
        vn = self.dcp.readVarnode(io.StringIO(args))
        optr = self.status.optr if self.status else io.StringIO()
        if vn.isAnnotation() or (not self.dcp.fd.isHighOn()):
            vn.printInfo(optr)
        else:
            vn.getHigh().printInfo(optr)


class IfcPrintCover(IfaceDecompCommand):
    """Print cover for high: `print cover high`"""
    def execute(self, args: str) -> None:
        if self.dcp.fd is None:
            raise IfaceExecutionError("No function selected")
        pieces = args.split()
        name = pieces[0] if len(pieces) > 0 else ""
        if name == "":
            raise IfaceParseError("Missing variable name")
        high = self.dcp.fd.findHigh(name)
        if high is None:
            raise IfaceExecutionError("Unable to find variable: " + name)
        optr = self.status.optr if self.status else io.StringIO()
        high.printCover(optr)


class IfcVarnodeCover(IfaceDecompCommand):
    """Print cover for varnode: `print cover varnode`"""
    def execute(self, args: str) -> None:
        vn = self.dcp.readVarnode(io.StringIO(args))
        if vn is None:
            raise IfaceParseError("Unknown varnode")
        optr = self.status.optr if self.status else io.StringIO()
        vn.printCover(optr)


class IfcVarnodehighCover(IfaceDecompCommand):
    """Print varnodehigh cover: `print cover varnodehigh`"""
    def execute(self, args: str) -> None:
        vn = self.dcp.readVarnode(io.StringIO(args))
        if vn is None:
            raise IfaceParseError("Unknown varnode")
        optr = self.status.optr if self.status else io.StringIO()
        if vn.getHigh() is not None:
            vn.getHigh().printCover(optr)
        else:
            optr.write("Unmerged\n")


class IfcPrintExtrapop(IfaceDecompCommand):
    """Print extrapop: `print extrapop`"""
    def execute(self, args: str) -> None:
        pieces = args.split()
        name = pieces[0] if len(pieces) > 0 else ""
        optr = self.status.optr if self.status else io.StringIO()
        if name == "":
            if self.dcp.fd is not None:
                for i in range(self.dcp.fd.numCalls()):
                    fc = self.dcp.fd.getCallSpecs(i)
                    optr.write(f"ExtraPop for {fc.getName()}({fc.getOp().getAddr()}) ")
                    expop = fc.getEffectiveExtraPop()
                    optr.write("unknown" if expop == ProtoModel.extrapop_unknown else str(expop))
                    optr.write("(")
                    expop = fc.getExtraPop()
                    optr.write("unknown" if expop == ProtoModel.extrapop_unknown else str(expop))
                    optr.write(")\n")
            else:
                expop = self.dcp.conf.defaultfp.getExtraPop()
                optr.write("Default extra pop = ")
                optr.write("unknown\n" if expop == ProtoModel.extrapop_unknown else f"{expop}\n")
            return

        fd = self.dcp.conf.symboltab.getGlobalScope().queryFunction(name)
        if fd is None:
            raise IfaceExecutionError("Unknown function: " + name)
        expop = fd.getFuncProto().getExtraPop()
        optr.write(f"ExtraPop for function {name} is ")
        optr.write("unknown\n" if expop == ProtoModel.extrapop_unknown else f"{expop}\n")


class IfcPrintActionstats(IfaceDecompCommand):
    """Print action stats: `print actionstats`"""
    def execute(self, args: str) -> None:
        if self.dcp is None or self.dcp.conf is None:
            raise IfaceExecutionError("Image not loaded")
        current = self.dcp.conf.allacts.getCurrent()
        if current is None:
            raise IfaceExecutionError("No action set")
        current.printStatistics(self.status.fileoptr)


class IfcResetActionstats(IfaceDecompCommand):
    """Reset action stats: `reset actionstats`"""
    def execute(self, args: str) -> None:
        if self.dcp is None or self.dcp.conf is None:
            raise IfaceExecutionError("Image not loaded")
        current = self.dcp.conf.allacts.getCurrent()
        if current is None:
            raise IfaceExecutionError("No action set")
        current.resetStats()


class IfcPrintInputs(IfaceDecompCommand):
    """Print function inputs: `print inputs`"""
    @staticmethod
    def nonTrivialUse(vn) -> bool:
        vnlist = [vn]
        res = False
        proc = 0
        while proc < len(vnlist):
            tmpvn = vnlist[proc]
            proc += 1
            for op in tmpvn.beginDescend():
                if op.code() in (
                    OpCode.CPUI_COPY,
                    OpCode.CPUI_CAST,
                    OpCode.CPUI_INDIRECT,
                    OpCode.CPUI_MULTIEQUAL,
                ):
                    outvn = op.getOut()
                    if not outvn.isMark():
                        outvn.setMark()
                        vnlist.append(outvn)
                else:
                    res = True
                    break
        for marked_vn in vnlist:
            marked_vn.clearMark()
        return res

    @staticmethod
    def checkRestore(vn) -> int:
        vnlist = [vn]
        res = 0
        proc = 0
        while proc < len(vnlist):
            tmpvn = vnlist[proc]
            proc += 1
            if tmpvn.isInput():
                if tmpvn.getSize() != vn.getSize() or tmpvn.getAddr() != vn.getAddr():
                    res = 1
                    break
            elif not tmpvn.isWritten():
                res = 1
                break
            else:
                op = tmpvn.getDef()
                if op.code() in (OpCode.CPUI_COPY, OpCode.CPUI_CAST, OpCode.CPUI_INDIRECT):
                    prev_vn = op.getIn(0)
                    if not prev_vn.isMark():
                        prev_vn.setMark()
                        vnlist.append(prev_vn)
                elif op.code() == OpCode.CPUI_MULTIEQUAL:
                    for i in range(op.numInput()):
                        prev_vn = op.getIn(i)
                        if not prev_vn.isMark():
                            prev_vn.setMark()
                            vnlist.append(prev_vn)
                else:
                    res = 1
                    break
        for marked_vn in vnlist:
            marked_vn.clearMark()
        return res

    @staticmethod
    def findRestore(vn, fd) -> bool:
        count = 0
        for loc_vn in fd.beginLoc(vn.getAddr()):
            if not loc_vn.hasNoDescend():
                continue
            if not loc_vn.isWritten():
                continue
            op = loc_vn.getDef()
            if op.code() == OpCode.CPUI_INDIRECT:
                continue
            if IfcPrintInputs.checkRestore(loc_vn) != 0:
                return False
            count += 1
        return count > 0

    @staticmethod
    def print(fd, ostream) -> None:
        ostream.write(f"Function: {fd.getName()}\n")
        for vn in fd.beginDef(Varnode.input):
            raw = vn.printRaw()
            if raw is not None:
                ostream.write(raw)
            if fd.isHighOn():
                sym = vn.getHigh().getSymbol()
                if sym is not None:
                    ostream.write(f"    {sym.getName()}")
            findres = IfcPrintInputs.findRestore(vn, fd)
            nontriv = IfcPrintInputs.nonTrivialUse(vn)
            if findres and not nontriv:
                ostream.write("     restored")
            elif nontriv:
                ostream.write("     nontriv")
            ostream.write("\n")

    def execute(self, args: str) -> None:
        if self.dcp.fd is None:
            raise IfaceExecutionError("No function selected")
        IfcPrintInputs.print(self.dcp.fd, self.status.fileoptr)


class IfcPrintInputsAll(IfaceDecompCommand):
    """Print inputs for all functions: `print inputs all`"""
    def execute(self, args: str) -> None:
        if self.dcp.conf is None:
            raise IfaceExecutionError("No load image present")
        self.iterateFunctionsAddrOrder()

    def iterationCallback(self, fd) -> None:
        if fd.hasNoCode():
            self.status.optr.write(f"No code for {fd.getName()}\n")
            return
        try:
            self.dcp.conf.clearAnalysis(fd)
            current = self.dcp.conf.allacts.getCurrent()
            current.reset(fd)
            current.perform(fd)
            IfcPrintInputs.print(fd, self.status.fileoptr)
        except LowlevelError as err:
            self.status.optr.write(f"Skipping {fd.getName()}: {err.explain}\n")
        self.dcp.conf.clearAnalysis(fd)


class IfcPrintLocalrange(IfaceDecompCommand):
    """Print local range: `print localrange`"""
    def execute(self, args: str) -> None:
        if self.dcp.fd is None:
            raise IfaceExecutionError("No function selected")
        self.dcp.fd.printLocalRange(self.status.optr)


class IfcPrintMap(IfaceDecompCommand):
    """Print symbol map: `print map`"""
    def execute(self, args: str) -> None:
        if self.dcp is None or self.dcp.conf is None:
            raise IfaceExecutionError("No load image")

        parts = args.split(None, 1)
        name = parts[0] if parts else ""
        if name != "" or self.dcp.fd is None:
            fullname = name + "::a"
            basename: list[str] = []
            scope = self.dcp.conf.symboltab.resolveScopeFromSymbolName(fullname, "::", basename, None)
        else:
            scope = self.dcp.fd.getScopeLocal()

        if scope is None:
            raise IfaceExecutionError("No map named: " + name)

        fileoptr = self.status.fileoptr if self.status else io.StringIO()
        fileoptr.write(scope.getFullName() + "\n")
        scope.printBounds(fileoptr)
        scope.printEntries(fileoptr)


# =========================================================================
# Mapping commands (stubs)
# =========================================================================

class IfcMapaddress(IfaceDecompCommand):
    """Map a new symbol: `map address <address> <typedecl>`"""
    def execute(self, args: str) -> None:
        stream = io.StringIO(args)
        addr, size = parse_machaddr(stream, 0, self.dcp.conf.types)
        ct, name = parse_type(stream, self.dcp.conf)
        if self.dcp.fd is not None:
            sym = self.dcp.fd.getScopeLocal().addSymbol(name, ct, addr, Address()).getSymbol()
            sym.getScope().setAttribute(sym, Varnode.namelock | Varnode.typelock)
        else:
            flags = Varnode.namelock | Varnode.typelock
            flags |= self.dcp.conf.symboltab.getProperty(addr)
            basename: list[str] = []
            scope = self.dcp.conf.symboltab.findCreateScopeFromSymbolName(name, "::", basename, None)
            sym = scope.addSymbol(basename[0], ct, addr, Address()).getSymbol()
            sym.getScope().setAttribute(sym, flags)
            if scope.getParent() is not None:
                entry = sym.getFirstWholeMap()
                self.dcp.conf.symboltab.addRange(scope, entry.getAddr().getSpace(), entry.getFirst(), entry.getLast())


class IfcMaphash(IfaceDecompCommand):
    """Add a dynamic symbol: `map hash ...`"""
    def execute(self, args: str) -> None:
        if self.dcp.fd is None:
            raise IfaceExecutionError("No function loaded")
        stream = io.StringIO(args)
        addr, size = parse_machaddr(stream, 0, self.dcp.conf.types)
        remainder = stream.read().lstrip()
        parts = remainder.split(None, 1)
        hash_ = int(parts[0], 16)
        type_stream = io.StringIO(parts[1] if len(parts) > 1 else "")
        ct, name = parse_type(type_stream, self.dcp.conf)
        sym = self.dcp.fd.getScopeLocal().addDynamicSymbol(name, ct, addr, hash_)
        sym.getScope().setAttribute(sym, Varnode.namelock | Varnode.typelock)


class IfcMapParam(IfaceDecompCommand):
    """Map a parameter: `map param ...`"""
    def execute(self, args: str) -> None:
        if self.dcp.fd is None:
            raise IfaceExecutionError("No function loaded")
        parts = args.lstrip().split(None, 1)
        index = int(parts[0], 10)
        stream = io.StringIO(parts[1] if len(parts) > 1 else "")
        piece = ParameterPieces()
        piece.addr, size = parse_machaddr(stream, 0, self.dcp.conf.types)
        piece.type, name = parse_type(stream, self.dcp.conf)
        piece.flags = ParameterPieces.typelock | ParameterPieces.namelock
        self.dcp.fd.getFuncProto().setParam(index, name, piece)


class IfcMapReturn(IfaceDecompCommand):
    """Map return storage: `map return ...`"""
    def execute(self, args: str) -> None:
        if self.dcp.fd is None:
            raise IfaceExecutionError("No function loaded")
        stream = io.StringIO(args)
        piece = ParameterPieces()
        piece.addr, size = parse_machaddr(stream, 0, self.dcp.conf.types)
        piece.type, name = parse_type(stream, self.dcp.conf)
        piece.flags = ParameterPieces.typelock
        self.dcp.fd.getFuncProto().setOutput(piece)


class IfcMapfunction(IfaceDecompCommand):
    """Create a new function: `map function <address> [<name>]`"""
    def execute(self, args: str) -> None:
        if self.dcp.conf is None or self.dcp.conf.loader is None:
            raise IfaceExecutionError("No binary loaded")
        stream = io.StringIO(args)
        addr, size = parse_machaddr(stream, 0, self.dcp.conf.types)
        rest = stream.read().split()
        name = rest[0] if rest else ""
        if not name:
            name = self.dcp.conf.nameFunction(addr)
        basename: list[str] = []
        scope = self.dcp.conf.symboltab.findCreateScopeFromSymbolName(name, "::", basename, None)
        self.dcp.fd = scope.addFunction(addr, name).getFunction()
        nocode = rest[1] if len(rest) > 1 else ""
        if nocode == "nocode":
            self.dcp.fd.setNoCode(True)


class IfcMapexternalref(IfaceDecompCommand):
    """Create an external ref: `map externalref ...`"""
    def execute(self, args: str) -> None:
        stream = io.StringIO(args)
        addr1, size1 = parse_machaddr(stream, 0, self.dcp.conf.types)
        addr2, size2 = parse_machaddr(stream, 0, self.dcp.conf.types)
        tail = stream.read().split()
        name = tail[0] if tail else ""
        self.dcp.conf.symboltab.getGlobalScope().addExternalRef(addr1, addr2, name)


class IfcMaplabel(IfaceDecompCommand):
    """Create a code label: `map label <name> <address>`"""
    def execute(self, args: str) -> None:
        parts = args.split(None, 1)
        name = parts[0] if parts else ""
        if name == "":
            raise IfaceParseError("Need label name and address")
        stream = io.StringIO(parts[1] if len(parts) > 1 else "")
        addr, size = parse_machaddr(stream, 0, self.dcp.conf.types)
        scope = self.dcp.fd.getScopeLocal() if self.dcp.fd is not None else self.dcp.conf.symboltab.getGlobalScope()
        sym = scope.addCodeLabel(addr, name)
        scope.setAttribute(sym, Varnode.namelock | Varnode.typelock)


class IfcMapconvert(IfaceDecompCommand):
    """Create a convert directive: `map convert ...`"""
    def execute(self, args: str) -> None:
        if self.dcp.fd is None:
            raise IfaceExecutionError("No function loaded")
        parts = args.split(None, 1)
        name = parts[0] if parts else ""
        format_map = {
            "hex": Symbol.force_hex,
            "dec": Symbol.force_dec,
            "bin": Symbol.force_bin,
            "oct": Symbol.force_oct,
            "char": Symbol.force_char,
        }
        format_ = format_map.get(name, 0)
        if format_ == 0:
            raise IfaceParseError("Bad convert format")
        remainder = parts[1] if len(parts) > 1 else ""
        value_parts = remainder.lstrip().split(None, 1)
        value = int(value_parts[0], 16)
        stream = io.StringIO(value_parts[1] if len(value_parts) > 1 else "")
        addr, size = parse_machaddr(stream, 0, self.dcp.conf.types)
        hash_parts = stream.read().split()
        hash_ = int(hash_parts[0], 16)
        self.dcp.fd.getScopeLocal().addEquateSymbol("", format_, value, addr, hash_)


class IfcMapunionfacet(IfaceDecompCommand):
    """Create a union field directive: `map unionfacet ...`"""
    def execute(self, args: str) -> None:
        if self.dcp.fd is None:
            raise IfaceExecutionError("No function loaded")
        pieces = args.lstrip().split(None, 2)
        union_name = pieces[0] if pieces else ""
        ct = self.dcp.conf.types.findByName(union_name)
        if ct is None or ct.getMetatype() != TYPE_UNION:
            raise IfaceParseError("Bad union data-type: " + union_name)
        try:
            field_num = int(pieces[1], 10)
        except (IndexError, ValueError) as err:
            raise IfaceParseError("Bad field index") from err
        if field_num < -1 or field_num >= ct.numDepend():
            raise IfaceParseError("Bad field index")
        stream = io.StringIO(pieces[2] if len(pieces) > 2 else "")
        addr, size = parse_machaddr(stream, 0, self.dcp.conf.types)
        hash_parts = stream.read().split()
        hash_ = int(hash_parts[0], 16)
        sym_name = f"unionfacet{field_num + 1}_{addr.getOffset():x}"
        scope = self.dcp.fd.getScopeLocal()
        sym = scope.addUnionFacetSymbol(sym_name, ct, field_num, addr, hash_)
        scope.setAttribute(sym, Varnode.typelock | Varnode.namelock)


# =========================================================================
# Action/Override commands (stubs)
# =========================================================================

class IfcListaction(IfaceDecompCommand):
    """List available actions: `list action`"""
    def execute(self, args: str) -> None:
        if self.dcp is None or self.dcp.conf is None:
            raise IfaceExecutionError("Decompile action not loaded")
        fileoptr = self.status.fileoptr if self.status else io.StringIO()
        self.dcp.conf.allacts.getCurrent().print(fileoptr, 0, 0)


class IfcListOverride(IfaceDecompCommand):
    """List overrides: `list override`"""
    def execute(self, args: str) -> None:
        if self.dcp is None or self.dcp.fd is None:
            raise IfaceExecutionError("No function selected")
        optr = self.status.optr if self.status else io.StringIO()
        optr.write(f"Function: {self.dcp.fd.getName()}\n")
        self.dcp.fd.getOverride().printRaw(optr, self.dcp.conf)


class IfcListprototypes(IfaceDecompCommand):
    """List prototypes: `list prototypes`"""
    def execute(self, args: str) -> None:
        if self.dcp is None or self.dcp.conf is None:
            raise IfaceExecutionError("No load image present")
        optr = self.status.optr if self.status else io.StringIO()
        for model in self.dcp.conf.protoModels.values():
            optr.write(model.getName())
            if model == self.dcp.conf.defaultfp:
                optr.write(" default")
            elif model == self.dcp.conf.evalfp_called:
                optr.write(" eval called")
            elif model == self.dcp.conf.evalfp_current:
                optr.write(" eval current")
            optr.write("\n")


class IfcSetcontextrange(IfaceDecompCommand):
    """Set context: `set context ...`"""
    def execute(self, args: str) -> None:
        if self.dcp is None or self.dcp.conf is None:
            raise IfaceExecutionError("No load image present")
        parts = args.split(None, 2)
        name = parts[0] if parts else ""
        if name == "":
            raise IfaceParseError("Missing context variable name")
        try:
            value = int(parts[1], 0)
        except (IndexError, ValueError) as err:
            raise IfaceParseError("Missing context value") from err
        if len(parts) < 3:
            self.dcp.conf.context.setVariableDefault(name, value)
            return
        stream = io.StringIO(parts[2])
        addr1, size1 = parse_machaddr(stream, 0, self.dcp.conf.types)
        addr2, size2 = parse_machaddr(stream, 0, self.dcp.conf.types)
        if addr1.isInvalid() or addr2.isInvalid():
            raise IfaceParseError("Invalid address range")
        if addr2 <= addr1:
            raise IfaceParseError("Bad address range")
        self.dcp.conf.context.setVariableRegion(name, addr1, addr2, value)


class IfcSettrackedrange(IfaceDecompCommand):
    """Set tracked range: `set track ...`"""
    def execute(self, args: str) -> None:
        if self.dcp is None or self.dcp.conf is None:
            raise IfaceExecutionError("No load image present")
        parts = args.split(None, 2)
        name = parts[0] if parts else ""
        if name == "":
            raise IfaceParseError("Missing tracked register name")
        try:
            value = int(parts[1], 0)
        except (IndexError, ValueError) as err:
            raise IfaceParseError("Missing context value") from err
        if len(parts) < 3:
            track = self.dcp.conf.context.getTrackedDefault()
            track.append(TrackedContext())
            track[-1].loc = self.dcp.conf.translate.getRegister(name)
            track[-1].val = value
            return
        stream = io.StringIO(parts[2])
        addr1, size1 = parse_machaddr(stream, 0, self.dcp.conf.types)
        addr2, size2 = parse_machaddr(stream, 0, self.dcp.conf.types)
        if addr1.isInvalid() or addr2.isInvalid():
            raise IfaceParseError("Invalid address range")
        if addr2 <= addr1:
            raise IfaceParseError("Bad address range")
        track = self.dcp.conf.context.createSet(addr1, addr2)
        default_track = self.dcp.conf.context.getTrackedDefault()
        track[:] = [_clone_tracked_context(entry) for entry in default_track]
        track.append(TrackedContext())
        track[-1].loc = self.dcp.conf.translate.getRegister(name)
        track[-1].val = value


class IfcBreakstart(IfaceDecompCommand):
    """Set break at start: `break start`"""
    def execute(self, args: str) -> None:
        specify = args.strip()
        if specify == "":
            raise IfaceExecutionError("No action/rule specified")
        if self.dcp is None or self.dcp.conf is None:
            raise IfaceExecutionError("Decompile action not loaded")
        res = self.dcp.conf.allacts.getCurrent().setBreakPoint(Action.break_start, specify)
        if not res:
            raise IfaceExecutionError("Bad action/rule specifier: " + specify)


class IfcBreakaction(IfaceDecompCommand):
    """Set break at action: `break action <name>`"""
    def execute(self, args: str) -> None:
        specify = args.strip()
        if specify == "":
            raise IfaceExecutionError("No action/rule specified")
        if self.dcp is None or self.dcp.conf is None:
            raise IfaceExecutionError("Decompile action not loaded")
        res = self.dcp.conf.allacts.getCurrent().setBreakPoint(Action.break_action, specify)
        if not res:
            raise IfaceExecutionError("Bad action/rule specifier: " + specify)


class IfcContinue(IfaceDecompCommand):
    """Continue decompilation after a break: `continue`"""
    def execute(self, args: str) -> None:
        if self.dcp is None or self.dcp.conf is None:
            raise IfaceExecutionError("Decompile action not loaded")
        if self.dcp.fd is None:
            raise IfaceExecutionError("No function selected")

        act = self.dcp.conf.allacts.getCurrent()
        if act.getStatus() == Action.status_start:
            raise IfaceExecutionError("Decompilation has not been started")
        if act.getStatus() == Action.status_end:
            raise IfaceExecutionError("Decompilation is already complete")

        optr = self.status.optr if self.status else io.StringIO()
        res = act.perform(self.dcp.fd)
        if res < 0:
            optr.write("Break at ")
            act.printState(optr)
        else:
            optr.write("Decompilation complete")
            if res == 0:
                optr.write(" (no change)")
        optr.write("\n")


# =========================================================================
# Symbol manipulation commands (stubs)
# =========================================================================

class IfcRename(IfaceDecompCommand):
    """Rename a symbol: `rename`"""
    def execute(self, args: str) -> None:
        pieces = args.split()
        oldname = pieces[0] if len(pieces) > 0 else ""
        newname = pieces[1] if len(pieces) > 1 else ""
        if oldname == "":
            raise IfaceParseError("Missing old symbol name")
        if newname == "":
            raise IfaceParseError("Missing new name")

        sym_list = self.dcp.readSymbol(oldname)
        if len(sym_list) == 0:
            raise IfaceExecutionError("No symbol named: " + oldname)
        if len(sym_list) > 1:
            raise IfaceExecutionError("More than one symbol named: " + oldname)

        sym = sym_list[0]
        if sym.getCategory() == Symbol.function_parameter:
            self.dcp.fd.getFuncProto().setInputLock(True)
        scope = sym.getScope()
        scope.renameSymbol(sym, newname)
        scope.setAttribute(sym, Varnode.namelock | Varnode.typelock)


class IfcRetype(IfaceDecompCommand):
    """Retype a symbol: `retype`"""
    def execute(self, args: str) -> None:
        pieces = args.split(None, 1)
        name = pieces[0] if len(pieces) > 0 else ""
        if name == "":
            raise IfaceParseError("Must specify name of symbol")
        remainder = pieces[1] if len(pieces) > 1 else ""
        ct, newname = parse_type(io.StringIO(remainder), self.dcp.conf)

        sym_list = self.dcp.readSymbol(name)
        if len(sym_list) == 0:
            raise IfaceExecutionError("No symbol named: " + name)
        if len(sym_list) > 1:
            raise IfaceExecutionError("More than one symbol named : " + name)

        sym = sym_list[0]
        if sym.getCategory() == Symbol.function_parameter:
            self.dcp.fd.getFuncProto().setInputLock(True)
        scope = sym.getScope()
        scope.retypeSymbol(sym, ct)
        scope.setAttribute(sym, Varnode.typelock)
        if newname != "" and newname != name:
            scope.renameSymbol(sym, newname)
            scope.setAttribute(sym, Varnode.namelock)


class IfcRemove(IfaceDecompCommand):
    """Remove a symbol: `remove`"""
    def execute(self, args: str) -> None:
        pieces = args.split()
        name = pieces[0] if len(pieces) > 0 else ""
        if name == "":
            raise IfaceParseError("Missing symbol name")

        sym_list = self.dcp.readSymbol(name)
        if len(sym_list) == 0:
            raise IfaceExecutionError("No symbol named: " + name)
        if len(sym_list) > 1:
            raise IfaceExecutionError("More than one symbol named: " + name)
        sym = sym_list[0]
        sym.getScope().removeSymbol(sym)


class IfcIsolate(IfaceDecompCommand):
    """Isolate a symbol: `isolate`"""
    def execute(self, args: str) -> None:
        pieces = args.split()
        symbol_name = pieces[0] if len(pieces) > 0 else ""
        if symbol_name == "":
            raise IfaceParseError("Missing symbol name")

        sym_list = self.dcp.readSymbol(symbol_name)
        if len(sym_list) == 0:
            raise IfaceExecutionError("No symbol named: " + symbol_name)
        if len(sym_list) > 1:
            raise IfaceExecutionError("More than one symbol named: " + symbol_name)
        sym_list[0].setIsolated(True)


class IfcNameVarnode(IfaceDecompCommand):
    """Name a varnode: `name varnode`"""
    def execute(self, args: str) -> None:
        if self.dcp is None or self.dcp.fd is None:
            raise IfaceExecutionError("No function selected")
        stream = io.StringIO(args)
        loc, size, pc, uq = parse_varnode(stream, self.dcp.conf.types)
        pieces = stream.read().strip().split()
        token = pieces[0] if len(pieces) > 0 else ""
        if token == "":
            raise IfaceParseError("Must specify name")

        ct = self.dcp.conf.types.getBase(size, TYPE_UNKNOWN)
        self.dcp.conf.clearAnalysis(self.dcp.fd)

        scope = self.dcp.fd.getScopeLocal().discoverScope(loc, size, pc)
        if scope is None:
            scope = self.dcp.fd.getScopeLocal()
        sym = scope.addSymbol(token, ct, loc, pc).getSymbol()
        scope.setAttribute(sym, Varnode.namelock)

        fileoptr = self.status.fileoptr if self.status else io.StringIO()
        fileoptr.write(f"Successfully added {token} to scope {scope.getFullName()}\n")


class IfcTypeVarnode(IfaceDecompCommand):
    """Type a varnode: `type varnode`"""
    def execute(self, args: str) -> None:
        if self.dcp is None or self.dcp.fd is None:
            raise IfaceExecutionError("No function selected")
        stream = io.StringIO(args)
        loc, size, pc, uq = parse_varnode(stream, self.dcp.conf.types)
        ct, name = parse_type(stream, self.dcp.conf)

        self.dcp.conf.clearAnalysis(self.dcp.fd)

        scope = self.dcp.fd.getScopeLocal().discoverScope(loc, size, pc)
        if scope is None:
            scope = self.dcp.fd.getScopeLocal()
        sym = scope.addSymbol(name, ct, loc, pc).getSymbol()
        scope.setAttribute(sym, Varnode.typelock)
        sym.setIsolated(True)
        if len(name) > 0:
            scope.setAttribute(sym, Varnode.namelock)

        fileoptr = self.status.fileoptr if self.status else io.StringIO()
        fileoptr.write(f"Successfully added {sym.getName()} to scope {scope.getFullName()}\n")


class IfcForceFormat(IfaceDecompCommand):
    """Force format on varnode: `force varnode`"""
    def execute(self, args: str) -> None:
        stream = io.StringIO(args)
        vn = self.dcp.readVarnode(stream)
        if not vn.isConstant():
            raise IfaceExecutionError("Can only force format on a constant")
        mt = vn.getType().getMetatype()
        if mt not in (TYPE_INT, TYPE_UINT, TYPE_UNKNOWN):
            raise IfaceExecutionError("Can only force format on integer type constant")
        self.dcp.fd.buildDynamicSymbol(vn)
        sym = vn.getHigh().getSymbol()
        if sym is None:
            raise IfaceExecutionError("Unable to create symbol")
        pieces = stream.read().strip().split()
        format_string = pieces[0] if len(pieces) > 0 else ""
        try:
            format_value = Datatype.encodeIntegerFormat(format_string)
        except ValueError as err:
            raise LowlevelError(str(err)) from err
        sym.getScope().setDisplayFormat(sym, format_value)
        sym.getScope().setAttribute(sym, Varnode.typelock)
        optr = self.status.optr if self.status else io.StringIO()
        optr.write("Successfully forced format display\n")


class IfcForceDatatypeFormat(IfaceDecompCommand):
    """Force datatype format: `force datatype`"""
    def execute(self, args: str) -> None:
        stream = io.StringIO(args)
        pieces = stream.read().strip().split()
        type_name = pieces[0] if len(pieces) > 0 else ""
        dt = self.dcp.conf.types.findByName(type_name)
        if dt is None:
            raise IfaceExecutionError("Unknown data-type: " + type_name)
        format_string = pieces[1] if len(pieces) > 1 else ""
        try:
            format_value = Datatype.encodeIntegerFormat(format_string)
        except ValueError as err:
            raise LowlevelError(str(err)) from err
        self.dcp.conf.types.setDisplayFormat(dt, format_value)
        optr = self.status.optr if self.status else io.StringIO()
        optr.write("Successfully forced data-type display\n")


class IfcForcegoto(IfaceDecompCommand):
    """Force goto: `force goto`"""
    def execute(self, args: str) -> None:
        if self.dcp.fd is None:
            raise IfaceExecutionError("No function selected")

        stream = io.StringIO(args)
        target, _ = parse_machaddr(stream, 0, self.dcp.conf.types)
        dest, _ = parse_machaddr(stream, 0, self.dcp.conf.types)
        self.dcp.fd.getOverride().insertForceGoto(target, dest)


class IfcProtooverride(IfaceDecompCommand):
    """Override prototype: `override prototype`"""
    def execute(self, args: str) -> None:
        from ghidra.fspec.fspec import FuncProto, PrototypePieces

        if self.dcp.fd is None:
            raise IfaceExecutionError("No function selected")

        stream = io.StringIO(args)
        callpoint, _ = parse_machaddr(stream, 0, self.dcp.conf.types)
        fd = self.dcp.fd
        for i in range(fd.numCalls()):
            if fd.getCallSpecs(i).getOp().getAddr() == callpoint:
                break
        else:
            raise IfaceExecutionError("No call is made at this address")

        pieces = PrototypePieces()
        parse_protopieces(pieces, stream, self.dcp.conf)

        newproto = FuncProto()
        newproto.setInternal(pieces.model, self.dcp.conf.types.getTypeVoid())
        newproto.setPieces(pieces)
        fd.getOverride().insertProtoOverride(callpoint, newproto)
        fd.clear()


class IfcJumpOverride(IfaceDecompCommand):
    """Override jump table: `override jumptable`"""
    def execute(self, args: str) -> None:
        if self.dcp.fd is None:
            raise IfaceExecutionError("No function selected")

        stream = io.StringIO(args)
        jmpaddr, _ = parse_machaddr(stream, 0, self.dcp.conf.types)
        jt = self.dcp.fd.installJumpTable(jmpaddr)
        adtable: list[Address] = []
        naddr = Address()
        h = 0
        sv = 0
        tokens = stream.read().split()
        index = 0
        if index < len(tokens) and tokens[index] == "startval":
            if index + 1 < len(tokens):
                try:
                    sv = int(tokens[index + 1], 0)
                except ValueError:
                    index = len(tokens)
                else:
                    index += 2
            else:
                index = len(tokens)
        if index < len(tokens) and tokens[index] == "table":
            for token in tokens[index + 1:]:
                addr, _ = parse_machaddr(io.StringIO(token), 0, self.dcp.conf.types)
                adtable.append(addr)
        if not adtable:
            raise IfaceExecutionError("Missing jumptable address entries")
        jt.setOverride(adtable, naddr, h, sv)
        self.status.optr.write("Successfully installed jumptable override\n")


class IfcFlowOverride(IfaceDecompCommand):
    """Override flow: `override flow`"""
    def execute(self, args: str) -> None:
        from ghidra.arch.override import Override

        if self.dcp.fd is None:
            raise IfaceExecutionError("No function selected")

        stream = io.StringIO(args)
        addr, _ = parse_machaddr(stream, 0, self.dcp.conf.types)
        pieces = stream.read().split()
        token = pieces[0] if pieces else ""
        if token == "":
            raise IfaceParseError("Missing override type")
        type_ = Override.stringToType(token)
        if type_ == Override.NONE:
            raise IfaceParseError("Bad override type")

        self.dcp.fd.getOverride().insertFlowOverride(addr, type_)
        self.status.optr.write("Successfully added override\n")


class IfcDeadcodedelay(IfaceDecompCommand):
    """Set deadcode delay: `deadcode delay`"""
    def execute(self, args: str) -> None:
        pieces = args.split()
        name = pieces[0] if pieces else ""
        delay = -1
        if len(pieces) > 1:
            try:
                delay = int(pieces[1], 10)
            except ValueError:
                delay = -1

        try:
            spc = self.dcp.conf.getSpaceByName(name)
        except LowlevelError as err:
            raise IfaceParseError("Bad space: " + name) from err
        if delay == -1:
            raise IfaceParseError("Need delay integer")
        if self.dcp.fd is not None:
            self.dcp.fd.getOverride().insertDeadcodeDelay(spc, delay)
            self.status.optr.write("Successfully overrided deadcode delay for single function\n")
        else:
            self.dcp.conf.setDeadcodeDelay(spc, delay)
            self.status.optr.write("Successfully overrided deadcode delay for all functions\n")


# =========================================================================
# Global commands (stubs)
# =========================================================================

class IfcGlobalAdd(IfaceDecompCommand):
    """Add a global range: `global add`"""
    def execute(self, args: str) -> None:
        if self.dcp.conf is None:
            raise IfaceExecutionError("No image loaded")

        stream = io.StringIO(args)
        addr, size = parse_machaddr(stream, 0, self.dcp.conf.types)
        first = addr.getOffset()
        last = first + (size - 1)

        scope = self.dcp.conf.symboltab.getGlobalScope()
        self.dcp.conf.symboltab.addRange(scope, addr.getSpace(), first, last)


class IfcGlobalRemove(IfaceDecompCommand):
    """Remove a global range: `global remove`"""
    def execute(self, args: str) -> None:
        if self.dcp.conf is None:
            raise IfaceExecutionError("No image loaded")

        stream = io.StringIO(args)
        addr, size = parse_machaddr(stream, 0, self.dcp.conf.types)
        first = addr.getOffset()
        last = first + (size - 1)

        scope = self.dcp.conf.symboltab.getGlobalScope()
        self.dcp.conf.symboltab.removeRange(scope, addr.getSpace(), first, last)


class IfcGlobalify(IfaceDecompCommand):
    """Globalize spaces: `global spaces`"""
    def execute(self, args: str) -> None:
        if self.dcp.conf is None:
            raise IfaceExecutionError("No load image present")
        self.dcp.conf.globalify()
        self.status.optr.write("Successfully made all registers/memory locations global\n")


class IfcGlobalRegisters(IfaceDecompCommand):
    """Globalize registers: `global registers`"""
    def execute(self, args: str) -> None:
        if self.dcp.conf is None:
            raise IfaceExecutionError("No load image present")

        reglist = self.dcp.conf.translate.getAllRegisters()
        spc = None
        lastoff = 0
        globalscope = self.dcp.conf.symboltab.getGlobalScope()
        count = 0
        for dat, name in _iter_register_pairs(reglist):
            if dat.space == spc and dat.offset <= lastoff:
                continue
            spc = dat.space
            lastoff = dat.offset + dat.size - 1
            addr = Address(spc, dat.offset)
            flags_ref = [0]
            globalscope.queryProperties(addr, dat.size, Address(), flags_ref)
            if (flags_ref[0] & Varnode.persist) != 0:
                ct = self.dcp.conf.types.getBase(dat.size, TYPE_UINT)
                globalscope.addSymbol(name, ct, addr, Address())
                count += 1
        if count == 0:
            self.status.optr.write("No global registers\n")
        else:
            self.status.optr.write(f"Successfully made a global symbol for {count} registers\n")


# =========================================================================
# Graph commands (stubs)
# =========================================================================

class IfcGraphDataflow(IfaceDecompCommand):
    """Graph dataflow: `graph dataflow`"""
    def execute(self, args: str) -> None:
        if self.dcp is None or self.dcp.fd is None:
            raise IfaceExecutionError("No function selected")

        parts = args.split(None, 1)
        filename = parts[0] if parts else ""
        if filename == "":
            raise IfaceParseError("Missing output file")
        if not self.dcp.fd.isProcStarted():
            raise IfaceExecutionError("Syntax tree not calculated")
        try:
            with open(filename, "w", encoding="utf-8") as thefile:
                dump_dataflow_graph(self.dcp.fd, thefile)
        except OSError as err:
            raise IfaceExecutionError("Unable to open output file: " + filename) from err


class IfcGraphControlflow(IfaceDecompCommand):
    """Graph control flow: `graph controlflow`"""
    def execute(self, args: str) -> None:
        if self.dcp is None or self.dcp.fd is None:
            raise IfaceExecutionError("No function selected")

        parts = args.split(None, 1)
        filename = parts[0] if parts else ""
        if filename == "":
            raise IfaceParseError("Missing output file")
        if self.dcp.fd.getBasicBlocks().getSize() == 0:
            raise IfaceExecutionError("Basic block structure not calculated")
        try:
            with open(filename, "w", encoding="utf-8") as thefile:
                dump_controlflow_graph(self.dcp.fd.getName(), self.dcp.fd.getBasicBlocks(), thefile)
        except OSError as err:
            raise IfaceExecutionError("Unable to open output file: " + filename) from err


class IfcGraphDom(IfaceDecompCommand):
    """Graph dominators: `graph dom`"""
    def execute(self, args: str) -> None:
        if self.dcp is None or self.dcp.fd is None:
            raise IfaceExecutionError("No function selected")

        parts = args.split(None, 1)
        filename = parts[0] if parts else ""
        if filename == "":
            raise IfaceParseError("Missing output file")
        if not self.dcp.fd.isProcStarted():
            raise IfaceExecutionError("Basic block structure not calculated")
        try:
            with open(filename, "w", encoding="utf-8") as thefile:
                dump_dom_graph(self.dcp.fd.getName(), self.dcp.fd.getBasicBlocks(), thefile)
        except OSError as err:
            raise IfaceExecutionError("Unable to open output file: " + filename) from err


# =========================================================================
# Prototype/Fixup commands (stubs)
# =========================================================================

class IfcLockPrototype(IfaceDecompCommand):
    """Lock prototype: `prototype lock`"""
    def execute(self, args: str) -> None:
        if self.dcp.fd is None:
            raise IfaceExecutionError("No function selected")
        self.dcp.fd.getFuncProto().setInputLock(True)
        self.dcp.fd.getFuncProto().setOutputLock(True)


class IfcUnlockPrototype(IfaceDecompCommand):
    """Unlock prototype: `prototype unlock`"""
    def execute(self, args: str) -> None:
        if self.dcp.fd is None:
            raise IfaceExecutionError("No function selected")
        self.dcp.fd.getFuncProto().setInputLock(False)
        self.dcp.fd.getFuncProto().setOutputLock(False)


class IfcCallFixup(IfaceDecompCommand):
    """Apply a call fixup: `fixup call`"""
    @staticmethod
    def readPcodeSnippet(stream) -> tuple[str, str, list[str], str]:
        if isinstance(stream, str):
            stream = io.StringIO(stream)

        outname = _read_stream_word(stream)
        name = parse_toseparator(stream)
        bracket = _read_nonspace_char(stream)
        if outname == "void":
            outname = ""
        if bracket != "(":
            raise IfaceParseError("Missing '('")

        inname: list[str] = []
        while bracket != ")":
            param = parse_toseparator(stream)
            bracket = _read_nonspace_char(stream)
            if param:
                inname.append(param)

        bracket = _read_nonspace_char(stream)
        if bracket != "{":
            raise IfaceParseError("Missing '{'")

        pcodestring = _read_to_delimiter(stream, "}")
        return name, outname, inname, pcodestring

    def execute(self, args: str) -> None:
        name, _outname, _inname, pcodestring = self.readPcodeSnippet(io.StringIO(args))
        try:
            injectid = self.dcp.conf.pcodeinjectlib.manualCallFixup(name, pcodestring)
        except LowlevelError as err:
            self.status.optr.write(f"Error compiling pcode: {err.explain}\n")
            return
        payload = self.dcp.conf.pcodeinjectlib.getPayload(injectid)
        payload.printTemplate(self.status.optr)


class IfcCallOtherFixup(IfaceDecompCommand):
    """Apply a callother fixup: `fixup callother`"""
    def execute(self, args: str) -> None:
        useropname, outname, inname, pcodestring = IfcCallFixup.readPcodeSnippet(io.StringIO(args))
        self.dcp.conf.userops.manualCallOtherFixup(
            useropname,
            outname,
            inname,
            pcodestring,
            self.dcp.conf,
        )
        self.status.optr.write("Successfully registered callotherfixup\n")


class IfcFixupApply(IfaceDecompCommand):
    """Apply fixups: `fixup apply`"""
    def execute(self, args: str) -> None:
        if self.dcp is None or self.dcp.conf is None:
            raise IfaceExecutionError("No load image present")

        stream = io.StringIO(args)
        fixup_name = _read_stream_word(stream)
        if not fixup_name:
            raise IfaceParseError("Missing fixup name")
        func_name = _read_stream_word(stream)
        if not func_name:
            raise IfaceParseError("Missing function name")

        injectid = self.dcp.conf.pcodeinjectlib.getPayloadId(InjectPayload.CALLFIXUP_TYPE, fixup_name)
        if injectid < 0:
            raise IfaceExecutionError("Unknown fixup: " + fixup_name)

        basename: list[str] = []
        funcscope = self.dcp.conf.symboltab.resolveScopeFromSymbolName(func_name, "::", basename, None)
        if funcscope is None:
            raise IfaceExecutionError("Bad namespace: " + func_name)
        fd = funcscope.queryFunction(basename[0])
        if fd is None:
            raise IfaceExecutionError("Unknown function name: " + func_name)

        fd.getFuncProto().setInjectId(injectid)
        self.status.optr.write("Successfully applied callfixup\n")


# =========================================================================
# Miscellaneous commands (stubs)
# =========================================================================

class IfcCommentInstr(IfaceDecompCommand):
    """Comment an instruction: `comment instruction`"""
    def execute(self, args: str) -> None:
        if self.dcp is None or self.dcp.conf is None:
            raise IfaceExecutionError("Decompile action not loaded")
        if self.dcp.fd is None:
            raise IfaceExecutionError("No function selected")

        stream = io.StringIO(args)
        addr, size = parse_machaddr(stream, 0, self.dcp.conf.types)
        comment = stream.read().lstrip()
        comment_type = self.dcp.conf.print.getInstructionComment()
        self.dcp.conf.commentdb.addComment(comment_type, self.dcp.fd.getAddress(), addr, comment)


class IfcDuplicateHash(IfaceDecompCommand):
    """Check duplicate hashes: `duplicate hash`"""
    def execute(self, args: str) -> None:
        self.iterateFunctionsAddrOrder()

    def iterationCallback(self, fd) -> None:
        optr = self.status.optr if self.status else io.StringIO()
        if fd.hasNoCode():
            optr.write(f"No code for {fd.getName()}\n")
            return
        try:
            self.dcp.conf.clearAnalysis(fd)
            current = self.dcp.conf.allacts.getCurrent()
            current.reset(fd)
            start_time = time.process_time()
            current.perform(fd)
            end_time = time.process_time()
            duration = (end_time - start_time) * 1000.0
            optr.write(f"Decompiled {fd.getName()}({fd.getSize()})")
            optr.write(f" time={duration:.0f} ms\n")
            self.check(fd, optr)
        except LowlevelError as err:
            optr.write(f"Skipping {fd.getName()}: {err.explain}\n")
        self.dcp.conf.clearAnalysis(fd)

    @staticmethod
    def check(fd, out) -> None:
        dhash = DynamicHash()
        for vn in fd.beginLoc():
            if vn.isAnnotation():
                continue
            if vn.isConstant():
                op = vn.loneDescend()
                slot = op.getSlot(vn)
                if slot == 0 and op.code() in (
                    OpCode.CPUI_LOAD,
                    OpCode.CPUI_STORE,
                    OpCode.CPUI_RETURN,
                ):
                    continue
            elif vn.getSpace().getType() != IPTR_INTERNAL:
                continue
            elif vn.isImplied():
                continue
            dhash.uniqueHash(vn, fd)
            if dhash.getHash() == 0:
                op = next(vn.beginDescend(), None)
                if op is None:
                    op = vn.getDef()
                out.write("Could not get unique hash for : ")
                out.write(vn.printRaw())
                out.write(" : ")
                if op is not None:
                    out.write(op.printRaw())
                out.write("\n")
                return
            total = DynamicHash.getTotalFromHash(dhash.getHash())
            if total != 1:
                op = next(vn.beginDescend(), None)
                if op is None:
                    op = vn.getDef()
                out.write("Duplicate : ")
                out.write(f"{DynamicHash.getPositionFromHash(dhash.getHash())} out of {total} : ")
                out.write(vn.printRaw())
                out.write(" : ")
                if op is not None:
                    out.write(op.printRaw())
                out.write("\n")


class IfcCountPcode(IfaceDecompCommand):
    """Count pcode ops: `count pcode`"""
    def execute(self, args: str) -> None:
        if self.dcp is None or self.dcp.conf is None:
            raise IfaceExecutionError("Image not loaded")
        if self.dcp.fd is None:
            raise IfaceExecutionError("No function selected")

        count = 0
        beginiter = self.dcp.fd.beginOpAlive()
        enditer = self.dcp.fd.endOpAlive()
        for op in beginiter:
            if op is enditer:
                break
            count += 1
        self.status.optr.write(f"Count - pcode = {count}\n")


class IfcVolatile(IfaceDecompCommand):
    """Mark volatile: `volatile`"""
    def execute(self, args: str) -> None:
        size = 0
        if self.dcp.conf is None:
            raise IfaceExecutionError("No load image present")
        addr, size = parse_machaddr(io.StringIO(args), size, self.dcp.conf.types)
        if size == 0:
            raise IfaceExecutionError("Must specify a size")
        range_ = Range(addr.getSpace(), addr.getOffset(), addr.getOffset() + (size - 1))
        self.dcp.conf.symboltab.setPropertyRange(Varnode.volatil, range_)
        self.status.optr.write("Successfully marked range as volatile\n")


class IfcReadonly(IfaceDecompCommand):
    """Mark readonly: `readonly`"""
    def execute(self, args: str) -> None:
        size = 0
        if self.dcp.conf is None:
            raise IfaceExecutionError("No load image present")
        addr, size = parse_machaddr(io.StringIO(args), size, self.dcp.conf.types)
        if size == 0:
            raise IfaceExecutionError("Must specify a size")
        range_ = Range(addr.getSpace(), addr.getOffset(), addr.getOffset() + (size - 1))
        self.dcp.conf.symboltab.setPropertyRange(Varnode.readonly, range_)
        self.status.optr.write("Successfully marked range as readonly\n")


class IfcPointerSetting(IfaceDecompCommand):
    """Pointer setting: `pointer setting`"""
    def execute(self, args: str) -> None:
        if self.dcp.conf is None:
            raise IfaceExecutionError("No load image present")

        stream = io.StringIO(args)
        typeName = _read_stream_word(stream)
        if not typeName:
            raise IfaceParseError("Missing name")
        baseType = _read_stream_word(stream)
        if not baseType:
            raise IfaceParseError("Missing base-type")
        setting = _read_stream_word(stream)
        if not setting:
            raise IfaceParseError("Missing setting")

        if setting == "offset":
            off_token = _read_stream_word(stream)
            if not off_token:
                raise IfaceParseError("Missing offset")
            try:
                off = int(off_token, 0)
            except ValueError as err:
                raise IfaceParseError("Missing offset") from err
            if off <= 0:
                raise IfaceParseError("Missing offset")
            bt = self.dcp.conf.types.findByName(baseType)
            if bt is None or not hasattr(bt, "getMetatype") or bt.getMetatype() != TYPE_STRUCT:
                raise IfaceParseError("Base-type must be a structure")
            ptrto = TypePointerRel.getPtrToFromParent(bt, off, self.dcp.conf.types)
            spc = self.dcp.conf.getDefaultDataSpace()
            new_type = self.dcp.conf.types.getTypePointerRel(
                spc.getAddrSize(), ptrto, bt, off, spc.getWordSize()
            )
            new_type.name = typeName
            new_type.displayName = typeName
            new_type.id = Datatype.hashName(typeName)
        elif setting == "space":
            spaceName = _read_stream_word(stream)
            if len(spaceName) == 0:
                raise IfaceParseError("Missing name of address space")
            ptrTo = self.dcp.conf.types.findByName(baseType)
            if ptrTo is None:
                raise IfaceParseError("Unknown base data-type: " + baseType)
            spc = self.dcp.conf.getSpaceByName(spaceName)
            if spc is None:
                raise IfaceParseError("Unknown space: " + spaceName)
            self.dcp.conf.types.getTypePointerWithSpace(ptrTo, spc, typeName)
        else:
            raise IfaceParseError("Unknown pointer setting: " + setting)
        self.status.optr.write(f"Successfully created pointer: {typeName}\n")


class IfcPreferSplit(IfaceDecompCommand):
    """Prefer split: `prefersplit`"""
    def execute(self, args: str) -> None:
        size = 0
        if self.dcp.conf is None:
            raise IfaceExecutionError("No load image present")
        stream = io.StringIO(args)
        addr, size = parse_machaddr(stream, size, self.dcp.conf.types)
        if size == 0:
            raise IfaceExecutionError("Must specify a size")

        split_token = _read_stream_word(stream)
        if not split_token:
            raise IfaceParseError("Missing split offset")
        try:
            split = int(split_token, 10)
        except ValueError as err:
            raise IfaceParseError("Bad split offset") from err
        if split == -1:
            raise IfaceParseError("Bad split offset")

        rec = PreferSplitRecord()
        rec.init(addr, split, size)
        self.dcp.conf.splitrecords.append(rec)
        self.status.optr.write("Successfully added split record\n")


class IfcStructureBlocks(IfaceDecompCommand):
    """Structure blocks: `structure blocks`"""
    def execute(self, args: str) -> None:
        if self.dcp.conf is None:
            raise IfaceExecutionError("No load image present")

        parts = args.split()
        infile = parts[0] if parts else ""
        outfile = parts[1] if len(parts) > 1 else ""
        if infile == "":
            raise IfaceParseError("Missing input file")
        if outfile == "":
            raise IfaceParseError("Missing output file")

        try:
            with open(infile, "r", encoding="utf-8") as fs:
                store = DocumentStorage()
                doc = store.parseDocument(fs)
        except OSError as err:
            raise IfaceExecutionError("Unable to open file: " + infile) from err

        try:
            ingraph = BlockGraph()
            decoder = XmlDecode(self.dcp.conf, doc.getRoot())
            ingraph.decode(decoder)

            resultgraph = BlockGraph()
            rootlist: list[object] = []
            resultgraph.buildCopy(ingraph)
            resultgraph.structureLoops(rootlist)
            resultgraph.calcForwardDominator(rootlist)

            collapse = CollapseStructure(resultgraph)
            collapse.collapseAll()

            try:
                with open(outfile, "w", encoding="utf-8") as sout:
                    encoder = XmlEncode(sout)
                    resultgraph.encode(encoder)
            except OSError as err:
                raise IfaceExecutionError("Unable to open output file: " + outfile) from err
        except LowlevelError as err:
            self.status.optr.write(f"{err.explain}\n")


class IfcAnalyzeRange(IfaceDecompCommand):
    """Analyze range: `analyze range`"""
    def execute(self, args: str) -> None:
        if self.dcp.conf is None:
            raise IfaceExecutionError("Image not loaded")
        if self.dcp.fd is None:
            raise IfaceExecutionError("No function selected")

        stream = io.StringIO(args)
        token = _read_stream_word(stream)
        if token == "full":
            useFullWidener = True
        elif token == "partial":
            useFullWidener = False
        else:
            raise IfaceParseError('Must specify "full" or "partial" widening')

        vn = self.dcp.readVarnode(stream)
        sinks = [vn]
        reads = []
        for op in vn.beginDescend():
            if op.code() in (OpCode.CPUI_LOAD, OpCode.CPUI_STORE):
                reads.append(op)

        stackReg = self.dcp.fd.findSpacebaseInput(self.dcp.conf.getStackSpace())
        vsSolver = ValueSetSolver()
        vsSolver.establishValueSets(sinks, reads, stackReg, False)
        if useFullWidener:
            widener = WidenerFull()
            vsSolver.solve(10000, widener)
        else:
            widener = WidenerNone()
            vsSolver.solve(10000, widener)

        for valueSet in vsSolver.beginValueSets():
            self.status.optr.write(valueSet.printRaw())
            self.status.optr.write("\n")
        for _, valueSetRead in vsSolver.beginValueSetReads():
            self.status.optr.write(valueSetRead.printRaw())
            self.status.optr.write("\n")


# =========================================================================
# CallGraph commands (stubs)
# =========================================================================

class IfcCallGraphBuild(IfaceDecompCommand):
    """Build call graph: `callgraph build`"""
    def __init__(self) -> None:
        super().__init__()
        self.quick = False

    def execute(self, args: str) -> None:
        self.dcp.allocateCallGraph()
        self.dcp.cgraph.buildAllNodes()
        self.quick = False
        self.iterateFunctionsAddrOrder()
        optr = self.status.optr if self.status else io.StringIO()
        optr.write("Successfully built callgraph\n")

    def iterationCallback(self, fd) -> None:
        optr = self.status.optr if self.status else io.StringIO()
        if fd.hasNoCode():
            optr.write(f"No code for {fd.getName()}\n")
            return
        if self.quick:
            self.dcp.fd = fd
            self.dcp.followFlow(optr, 0)
        else:
            try:
                self.dcp.conf.clearAnalysis(fd)
                current = self.dcp.conf.allacts.getCurrent()
                current.reset(fd)
                start_time = time.process_time()
                current.perform(fd)
                end_time = time.process_time()
                duration = (end_time - start_time) * 1000.0
                optr.write(f"Decompiled {fd.getName()}({fd.getSize()})")
                optr.write(f" time={duration:.0f} ms\n")
            except LowlevelError as err:
                optr.write(f"Skipping {fd.getName()}: {err.explain}\n")
        self.dcp.cgraph.buildEdges(fd)
        self.dcp.conf.clearAnalysis(fd)


class IfcCallGraphBuildQuick(IfcCallGraphBuild):
    """Build call graph quickly: `callgraph build quick`"""
    def execute(self, args: str) -> None:
        self.dcp.allocateCallGraph()
        self.dcp.cgraph.buildAllNodes()
        self.quick = True
        self.iterateFunctionsAddrOrder()
        optr = self.status.optr if self.status else io.StringIO()
        optr.write("Successfully built callgraph\n")


class IfcCallGraphDump(IfaceDecompCommand):
    """Dump call graph: `callgraph dump`"""
    def execute(self, args: str) -> None:
        if self.dcp is None or self.dcp.cgraph is None:
            raise IfaceExecutionError("No callgraph has been built")

        parts = args.split(None, 1)
        name = parts[0] if parts else ""
        if name == "":
            raise IfaceParseError("Need file name to write callgraph to")

        try:
            with open(name, "w", encoding="utf-8") as os:
                encoder = XmlEncode(os)
                self.dcp.cgraph.encode(encoder)
        except OSError as err:
            raise IfaceExecutionError("Unable to open file " + name) from err

        optr = self.status.optr if self.status else io.StringIO()
        optr.write(f"Successfully saved callgraph to {name}\n")


class IfcCallGraphLoad(IfaceDecompCommand):
    """Load call graph: `callgraph load`"""
    def execute(self, args: str) -> None:
        if self.dcp is None or self.dcp.conf is None:
            raise IfaceExecutionError("Decompile action not loaded")
        if self.dcp.cgraph is not None:
            raise IfaceExecutionError("Callgraph already loaded")

        parts = args.split(None, 1)
        name = parts[0] if parts else ""
        if name == "":
            raise IfaceExecutionError("Need name of file to read callgraph from")

        try:
            with open(name, "r", encoding="utf-8") as is_:
                store = DocumentStorage()
                doc = store.parseDocument(is_)
        except OSError as err:
            raise IfaceExecutionError("Unable to open callgraph file " + name) from err

        self.dcp.allocateCallGraph()
        decoder = XmlDecode(self.dcp.conf, doc.getRoot())
        self.dcp.cgraph.decoder(decoder)

        optr = self.status.optr if self.status else io.StringIO()
        optr.write("Successfully read in callgraph\n")

        gscope = self.dcp.conf.symboltab.getGlobalScope()
        for _, node in self.dcp.cgraph.begin():
            fd = gscope.queryFunction(node.getName())
            if fd is None:
                raise IfaceExecutionError("Function:" + node.getName() + " in callgraph has not been loaded")
            node.setFuncdata(fd)

        optr.write("Successfully associated functions with callgraph nodes\n")


class IfcCallGraphList(IfaceDecompCommand):
    """List call graph: `callgraph list`"""
    def execute(self, args: str) -> None:
        if self.dcp is None or self.dcp.cgraph is None:
            raise IfaceExecutionError("Callgraph not generated")
        self.iterateFunctionsLeafOrder()

    def iterationCallback(self, fd) -> None:
        optr = self.status.optr if self.status else io.StringIO()
        optr.write(f"{fd.getName()}\n")


# =========================================================================
# FunctionTestCollection
# =========================================================================

class FunctionTestCollection:
    """Minimal executable environment for decompiler test files."""

    def __init__(self, console) -> None:
        self.console = console
        self.dcp = console.getData("decompile") if hasattr(console, "getData") else None
        self.fileName = ""
        self.commands: list[str] = []
        self.numTestsApplied = 0
        self.numTestsSucceeded = 0

    def clear(self) -> None:
        if self.dcp is not None:
            self.dcp.clearArchitecture()
        self.commands.clear()
        if hasattr(self.console, "reset"):
            self.console.reset()

    @staticmethod
    def stripNewlines(ref: str) -> str:
        chars: list[str] = []
        for ch in ref:
            if ch == "\r":
                continue
            if ch == "\n":
                ch = " "
            chars.append(ch)
        return "".join(chars)

    def restoreXmlCommands(self, el) -> None:
        for subel in el.getChildren():
            self.commands.append(self.stripNewlines(subel.getContent()))

    def buildProgram(self, docStorage: DocumentStorage) -> None:
        from ghidra.arch.architecture import ArchitectureCapability
        from ghidra.arch.xml_arch import XmlArchitectureCapability

        capa = ArchitectureCapability.getCapability("xml")
        if capa is None:
            capa = XmlArchitectureCapability()
            capa.initialize()
        self.dcp.conf = capa.buildArchitecture("test", "", self.console.optr)
        errmsg = ""
        iserror = False
        try:
            self.dcp.conf.init(docStorage)
            self.dcp.conf.readLoaderSymbols("::")
        except DecoderError as err:
            errmsg = err.explain
            iserror = True
        except LowlevelError as err:
            errmsg = err.explain
            iserror = True
        if iserror:
            raise IfaceExecutionError("Error during architecture initialization: " + errmsg)

    def restoreXml(self, store: DocumentStorage, el) -> None:
        sawScript = False
        sawTests = False
        sawProgram = False
        for subel in el.getChildren():
            name = subel.getName()
            if name == "script":
                sawScript = True
                self.restoreXmlCommands(subel)
            elif name == "stringmatch":
                sawTests = True
            elif name == "binaryimage":
                sawProgram = True
                store.registerTag(subel)
                self.buildProgram(store)
            else:
                raise IfaceParseError("Unknown tag in <decompilertest>: " + name)
        if not sawScript:
            raise IfaceParseError("Did not see <script> tag in <decompilertest>")
        if not sawTests:
            raise IfaceParseError("Did not see any <stringmatch> tags in <decompilertest>")
        if not sawProgram:
            raise IfaceParseError("No <binaryimage> tag in <decompilertest>")

    def restoreXmlOldForm(self, store: DocumentStorage, el) -> None:
        raise IfaceParseError("Old format test not supported")

    def numCommands(self) -> int:
        return len(self.commands)

    def getCommand(self, i: int) -> str:
        return self.commands[i]

    def loadTest(self, filename: str) -> None:
        self.fileName = filename
        docStorage = DocumentStorage()
        doc = docStorage.openDocument(filename)
        el = doc.getRoot()
        if el.getName() == "decompilertest":
            self.restoreXml(docStorage, el)
        elif el.getName() == "binaryimage":
            self.restoreXmlOldForm(docStorage, el)
        else:
            raise IfaceParseError(
                "Test file " + filename + " has unrecognized XML tag: " + el.getName()
            )


# =========================================================================
# Test commands
# =========================================================================

class IfcLoadTestFile(IfaceDecompCommand):
    """Load test file: `load test file`"""
    def execute(self, args: str) -> None:
        filename = _read_stream_word(io.StringIO(args))
        if self.dcp.conf is not None:
            raise IfaceExecutionError("Load image already present")
        self.dcp.testCollection = FunctionTestCollection(self.status)
        self.dcp.testCollection.loadTest(filename)
        self.status.optr.write(
            f"{filename} test successfully loaded: {self.dcp.conf.getDescription()}\n"
        )


class IfcListTestCommands(IfaceDecompCommand):
    """List test commands: `list test commands`"""
    def execute(self, args: str) -> None:
        if self.dcp.testCollection is None:
            raise IfaceExecutionError("No test file is loaded")
        for i in range(self.dcp.testCollection.numCommands()):
            self.status.optr.write(f" {i + 1}: {self.dcp.testCollection.getCommand(i)}\n")


class IfcExecuteTestCommand(IfaceDecompCommand):
    """Execute test command: `execute test command`"""
    def execute(self, args: str) -> None:
        if self.dcp.testCollection is None:
            raise IfaceExecutionError("No test file is loaded")

        stream = io.StringIO(args)
        first = _read_decimal_int(stream)
        if first is None:
            first = -1
        first -= 1
        if first < 0 or first > self.dcp.testCollection.numCommands():
            raise IfaceExecutionError("Command index out of bounds")

        ch = _read_nonspace_char(stream)
        if ch:
            if ch != "-":
                raise IfaceExecutionError("Missing hyphenated command range")
            last = _read_decimal_int(stream)
            if last is None:
                last = -1
            last -= 1
            if (
                last < 0
                or last < first
                or last > self.dcp.testCollection.numCommands()
            ):
                raise IfaceExecutionError("Command index out of bounds")
        else:
            last = first

        script = io.StringIO(
            "".join(
                f"{self.dcp.testCollection.getCommand(i)}\n"
                for i in range(first, last + 1)
            )
        )
        self.status.pushScript(script, "test> ")


class IfcParseRule(IfaceDecompCommand):
    """Parse rule: `parse rule`"""

    def execute(self, args: str) -> None:
        stream = io.StringIO(args)
        filename = _read_stream_word(stream)
        if len(filename) == 0:
            raise IfaceParseError("Missing rule input file")

        debug = False
        flag = _read_stream_word(stream)
        if flag in ("true", "debug"):
            debug = True

        try:
            with open(filename, "r", encoding="utf-8") as thefile:
                rule_text = thefile.read()
        except OSError as err:
            raise IfaceExecutionError("Unable to open rule file: " + filename) from err

        ruler = RuleCompile()
        ruler.setErrorStream(self.status.optr)
        ruler.run(rule_text, debug)
        if ruler.numErrors() != 0:
            self.status.optr.write("Parsing aborted on error\n")
            return

        opcodelist: list[int] = []
        opparam = ruler.postProcessRule(opcodelist)
        cprinter = UnifyCPrinter()
        cprinter.initializeRuleAction(ruler.getRule(), opparam, opcodelist)
        cprinter.addNames(ruler.namemap)
        cprinter.print(self.status.optr)


class IfcExperimentalRules(IfaceDecompCommand):
    """Experimental rules: `experimental rules`"""

    def execute(self, args: str) -> None:
        if self.dcp.conf is not None:
            raise IfaceExecutionError(
                "Experimental rules must be registered before loading architecture"
            )
        filename = _read_stream_word(io.StringIO(args))
        if len(filename) == 0:
            raise IfaceParseError("Missing name of file containing experimental rules")
        self.dcp.experimental_file = filename
        self.status.optr.write(f"Successfully registered experimental file {filename}\n")


class IfcDebugAction(IfaceDecompCommand):
    """Debug action: `debug action`"""

    def execute(self, args: str) -> None:
        if self.dcp.fd is None:
            raise IfaceExecutionError("No function selected")
        actionname = _read_stream_word(io.StringIO(args))
        if actionname == "":
            raise IfaceParseError("Missing name of action to debug")
        if not self.dcp.conf.allacts.getCurrent().turnOnDebug(actionname):
            raise IfaceParseError("Unable to find action " + actionname)


class IfcTraceBreak(IfaceDecompCommand):
    """Trace break: `trace break`"""

    def execute(self, args: str) -> None:
        if self.dcp.fd is None:
            raise IfaceExecutionError("No function selected")
        count = _read_auto_int(io.StringIO(args))
        if count is None or count == -1:
            raise IfaceParseError("Missing trace count")
        self.dcp.fd.debugSetBreak(count)


class IfcTraceAddress(IfaceDecompCommand):
    """Trace address: `trace address`"""

    def execute(self, args: str) -> None:
        if self.dcp.fd is None:
            raise IfaceExecutionError("No function selected")

        stream = io.StringIO(args)
        discard = 0
        pclow = Address()
        pchigh = pclow

        pos = stream.tell()
        if _read_nonspace_char(stream):
            stream.seek(pos)
            pclow, discard = parse_machaddr(stream, discard, self.dcp.conf.types)
            pchigh = pclow
            pos = stream.tell()
            if _read_nonspace_char(stream):
                stream.seek(pos)
                pchigh, discard = parse_machaddr(stream, discard, self.dcp.conf.types)

        uqlow = uqhigh = 0xFFFFFFFFFFFFFFFF
        pos = stream.tell()
        tail = _read_nonspace_char(stream)
        if tail:
            stream.seek(pos)
            parsed_low = _read_auto_int(stream)
            parsed_high = _read_auto_int(stream)
            if parsed_low is not None and parsed_high is not None:
                uqlow = parsed_low
                uqhigh = parsed_high

        self.dcp.fd.debugSetRange(pclow, pchigh, uqlow, uqhigh)
        self.status.optr.write(f"OK ({self.dcp.fd.debugSize()} ranges)\n")


class IfcTraceEnable(IfaceDecompCommand):
    """Trace enable: `trace enable`"""

    def execute(self, args: str) -> None:
        if self.dcp.fd is None:
            raise IfaceExecutionError("No function selected")
        self.dcp.fd.debugEnable()
        self.status.optr.write("OK\n")


class IfcTraceDisable(IfaceDecompCommand):
    """Trace disable: `trace disable`"""

    def execute(self, args: str) -> None:
        if self.dcp.fd is None:
            raise IfaceExecutionError("No function selected")
        self.dcp.fd.debugDisable()
        self.status.optr.write("OK\n")


class IfcTraceClear(IfaceDecompCommand):
    """Trace clear: `trace clear`"""

    def execute(self, args: str) -> None:
        if self.dcp.fd is None:
            raise IfaceExecutionError("No function selected")
        self.status.optr.write(f"{self.dcp.fd.debugSize()} ranges cleared\n")
        self.dcp.fd.debugDisable()
        self.dcp.fd.debugClear()


class IfcTraceList(IfaceDecompCommand):
    """Trace list: `trace list`"""

    def execute(self, args: str) -> None:
        if self.dcp.fd is None:
            raise IfaceExecutionError("No function selected")
        size = self.dcp.fd.debugSize()
        if getattr(self.dcp.fd, "_opactdbg_on", False):
            self.status.optr.write("Trace enabled (")
        else:
            self.status.optr.write("Trace disabled (")
        self.status.optr.write(f"{size} total ranges)\n")
        for i in range(size):
            self.dcp.fd.debugPrintRange(i)


class IfcBreakjump(IfaceDecompCommand):
    """Break jumptable: `break jumptable`"""

    def execute(self, args: str) -> None:
        global _dcp_callback, _status_callback

        self.dcp.jumptabledebug = True
        _dcp_callback = self.dcp
        _status_callback = self.status
        self.status.optr.write("Jumptable debugging enabled\n")
        if self.dcp.fd is not None:
            self.dcp.fd.enableJTCallback(_jump_callback)


class IfcTracePropagation(IfaceDecompCommand):
    """Trace propagation: `trace propagation`"""

    def execute(self, args: str) -> None:
        token = _read_stream_word(io.StringIO(args))
        if token == "on":
            TypeFactory.propagatedbg_on = True
        elif token == "off":
            TypeFactory.propagatedbg_on = False
        else:
            raise IfaceParseError("Must specific on/off")
        self.status.optr.write(f"Data-type propagation trace set to: {token}\n")


# =========================================================================
# IfaceDecompCapability
# =========================================================================

class IfaceDecompCapability(IfaceCapability):
    """Interface capability point for all decompiler commands."""

    _instance: Optional[IfaceDecompCapability] = None

    def __init__(self) -> None:
        super().__init__("decomp")

    def __copy__(self):
        raise TypeError("IfaceDecompCapability is non-copyable")

    def __deepcopy__(self, memo):
        raise TypeError("IfaceDecompCapability is non-copyable")

    @classmethod
    def getInstance(cls) -> IfaceDecompCapability:
        if cls._instance is None:
            cls._instance = IfaceDecompCapability()
        return cls._instance

    def registerCommands(self, status: IfaceStatus) -> None:
        """Register all decompiler commands with the given status."""
        # Comments
        status.registerCom(IfcComment(), "//")
        status.registerCom(IfcComment(), "#")
        status.registerCom(IfcComment(), "%")

        # Base commands (re-registered for decompiler module)
        status.registerCom(IfcQuit(), "quit")
        status.registerCom(IfcHistory(), "history")
        status.registerCom(IfcOpenfile(), "openfile", "write")
        status.registerCom(IfcOpenfileAppend(), "openfile", "append")
        status.registerCom(IfcClosefile(), "closefile")
        status.registerCom(IfcEcho(), "echo")

        # Decompiler-specific commands
        status.registerCom(IfcSource(), "source")
        status.registerCom(IfcOption(), "option")
        status.registerCom(IfcParseFile(), "parse", "file")
        status.registerCom(IfcParseLine(), "parse", "line")
        status.registerCom(IfcAdjustVma(), "adjust", "vma")
        status.registerCom(IfcFuncload(), "load", "function")
        status.registerCom(IfcAddrrangeLoad(), "load", "addr")
        status.registerCom(IfcReadSymbols(), "read", "symbols")
        status.registerCom(IfcCleararch(), "clear", "architecture")
        status.registerCom(IfcMapaddress(), "map", "address")
        status.registerCom(IfcMaphash(), "map", "hash")
        status.registerCom(IfcMapParam(), "map", "param")
        status.registerCom(IfcMapReturn(), "map", "return")
        status.registerCom(IfcMapfunction(), "map", "function")
        status.registerCom(IfcMapexternalref(), "map", "externalref")
        status.registerCom(IfcMaplabel(), "map", "label")
        status.registerCom(IfcMapconvert(), "map", "convert")
        status.registerCom(IfcMapunionfacet(), "map", "unionfacet")
        status.registerCom(IfcPrintdisasm(), "disassemble")
        status.registerCom(IfcDecompile(), "decompile")
        status.registerCom(IfcDump(), "dump")
        status.registerCom(IfcDumpbinary(), "binary")
        status.registerCom(IfcForcegoto(), "force", "goto")
        status.registerCom(IfcForceFormat(), "force", "varnode")
        status.registerCom(IfcForceDatatypeFormat(), "force", "datatype")
        status.registerCom(IfcProtooverride(), "override", "prototype")
        status.registerCom(IfcJumpOverride(), "override", "jumptable")
        status.registerCom(IfcFlowOverride(), "override", "flow")
        status.registerCom(IfcDeadcodedelay(), "deadcode", "delay")
        status.registerCom(IfcGlobalAdd(), "global", "add")
        status.registerCom(IfcGlobalRemove(), "global", "remove")
        status.registerCom(IfcGlobalify(), "global", "spaces")
        status.registerCom(IfcGlobalRegisters(), "global", "registers")
        status.registerCom(IfcGraphDataflow(), "graph", "dataflow")
        status.registerCom(IfcGraphControlflow(), "graph", "controlflow")
        status.registerCom(IfcGraphDom(), "graph", "dom")
        status.registerCom(IfcPrintLanguage(), "print", "language")
        status.registerCom(IfcPrintCStruct(), "print", "C")
        status.registerCom(IfcPrintCFlat(), "print", "C", "flat")
        status.registerCom(IfcPrintCGlobals(), "print", "C", "globals")
        status.registerCom(IfcPrintCTypes(), "print", "C", "types")
        status.registerCom(IfcPrintCXml(), "print", "C", "xml")
        status.registerCom(IfcPrintParamMeasures(), "print", "parammeasures")
        status.registerCom(IfcProduceC(), "produce", "C")
        status.registerCom(IfcProducePrototypes(), "produce", "prototypes")
        status.registerCom(IfcPrintRaw(), "print", "raw")
        status.registerCom(IfcPrintInputs(), "print", "inputs")
        status.registerCom(IfcPrintInputsAll(), "print", "inputs", "all")
        status.registerCom(IfcListaction(), "list", "action")
        status.registerCom(IfcListOverride(), "list", "override")
        status.registerCom(IfcListprototypes(), "list", "prototypes")
        status.registerCom(IfcSetcontextrange(), "set", "context")
        status.registerCom(IfcSettrackedrange(), "set", "track")
        status.registerCom(IfcBreakstart(), "break", "start")
        status.registerCom(IfcBreakaction(), "break", "action")
        status.registerCom(IfcPrintSpaces(), "print", "spaces")
        status.registerCom(IfcPrintHigh(), "print", "high")
        status.registerCom(IfcPrintTree(), "print", "tree", "varnode")
        status.registerCom(IfcPrintBlocktree(), "print", "tree", "block")
        status.registerCom(IfcPrintLocalrange(), "print", "localrange")
        status.registerCom(IfcPrintMap(), "print", "map")
        status.registerCom(IfcPrintVarnode(), "print", "varnode")
        status.registerCom(IfcPrintCover(), "print", "cover", "high")
        status.registerCom(IfcVarnodeCover(), "print", "cover", "varnode")
        status.registerCom(IfcVarnodehighCover(), "print", "cover", "varnodehigh")
        status.registerCom(IfcPrintExtrapop(), "print", "extrapop")
        status.registerCom(IfcPrintActionstats(), "print", "actionstats")
        status.registerCom(IfcResetActionstats(), "reset", "actionstats")
        status.registerCom(IfcCountPcode(), "count", "pcode")
        status.registerCom(IfcTypeVarnode(), "type", "varnode")
        status.registerCom(IfcNameVarnode(), "name", "varnode")
        status.registerCom(IfcRename(), "rename")
        status.registerCom(IfcRetype(), "retype")
        status.registerCom(IfcRemove(), "remove")
        status.registerCom(IfcIsolate(), "isolate")
        status.registerCom(IfcLockPrototype(), "prototype", "lock")
        status.registerCom(IfcUnlockPrototype(), "prototype", "unlock")
        status.registerCom(IfcCommentInstr(), "comment", "instruction")
        status.registerCom(IfcDuplicateHash(), "duplicate", "hash")
        status.registerCom(IfcCallGraphBuild(), "callgraph", "build")
        status.registerCom(IfcCallGraphBuildQuick(), "callgraph", "build", "quick")
        status.registerCom(IfcCallGraphDump(), "callgraph", "dump")
        status.registerCom(IfcCallGraphLoad(), "callgraph", "load")
        status.registerCom(IfcCallGraphList(), "callgraph", "list")
        status.registerCom(IfcCallFixup(), "fixup", "call")
        status.registerCom(IfcCallOtherFixup(), "fixup", "callother")
        status.registerCom(IfcFixupApply(), "fixup", "apply")
        status.registerCom(IfcVolatile(), "volatile")
        status.registerCom(IfcReadonly(), "readonly")
        status.registerCom(IfcPointerSetting(), "pointer", "setting")
        status.registerCom(IfcPreferSplit(), "prefersplit")
        status.registerCom(IfcStructureBlocks(), "structure", "blocks")
        status.registerCom(IfcAnalyzeRange(), "analyze", "range")
        status.registerCom(IfcLoadTestFile(), "load", "test", "file")
        status.registerCom(IfcListTestCommands(), "list", "test", "commands")
        status.registerCom(IfcExecuteTestCommand(), "execute", "test", "command")
        status.registerCom(IfcParseRule(), "parse", "rule")
        status.registerCom(IfcExperimentalRules(), "experimental", "rules")
        status.registerCom(IfcContinue(), "continue")
        status.registerCom(IfcDebugAction(), "debug", "action")
        status.registerCom(IfcTraceBreak(), "trace", "break")
        status.registerCom(IfcTraceAddress(), "trace", "address")
        status.registerCom(IfcTraceEnable(), "trace", "enable")
        status.registerCom(IfcTraceDisable(), "trace", "disable")
        status.registerCom(IfcTraceClear(), "trace", "clear")
        status.registerCom(IfcTraceList(), "trace", "list")
        status.registerCom(IfcBreakjump(), "break", "jumptable")
        status.registerCom(IfcTracePropagation(), "trace", "propagation")


# =========================================================================
# Helper functions
# =========================================================================

def execute(status: IfaceStatus, dcp: IfaceDecompData) -> None:
    """Execute one command for the console."""
    try:
        status.runCommand()
        return
    except IfaceParseError as err:
        status.optr.write(f"Command parsing error: {err}\n")
    except IfaceExecutionError as err:
        status.optr.write(f"Execution error: {err}\n")
    except IfaceError as err:
        status.optr.write(f"ERROR: {err}\n")
    except ParseError as err:
        status.optr.write(f"Parse ERROR: {err.explain}\n")
    except RecovError as err:
        status.optr.write(f"Function ERROR: {err.explain}\n")
    except LowlevelError as err:
        status.optr.write(f"Low-level ERROR: {err.explain}\n")
        dcp.abortFunction(status.optr)
    except DecoderError as err:
        status.optr.write(f"Decoding ERROR: {err.explain}\n")
        dcp.abortFunction(status.optr)


def mainloop(status: IfaceStatus) -> None:
    """Execute commands as they become available."""
    dcp = status.getData("decompile")
    while True:
        while not status.isStreamFinished():
            status.writePrompt()
            status.optr.flush()
            execute(status, dcp)
        if status.done:
            break
        if status.getNumInputStreamSize() == 0:
            break
        status.popScript()
