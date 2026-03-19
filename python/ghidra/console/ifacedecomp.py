"""
Corresponds to: ifacedecomp.hh / ifacedecomp.cc

Console interface commands for the decompiler engine.
Provides IfaceDecompData, IfaceDecompCommand, IfaceDecompCapability,
and the full set of decompiler console commands.
"""

from __future__ import annotations

import io
from typing import Optional, List, TYPE_CHECKING

from ghidra.console.interface import (
    IfaceData, IfaceCommand, IfaceCapability, IfaceStatus,
    IfaceParseError, IfaceExecutionError,
    IfcQuit, IfcHistory, IfcOpenfile, IfcOpenfileAppend, IfcClosefile, IfcEcho,
)

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
        if hasattr(addr, 'printRaw'):
            addr.printRaw(self._ostream)
        else:
            self._ostream.write(f"{addr}")
        self._ostream.write(f": {mnem}")
        pad = self._mnemonicpad - len(mnem)
        if pad > 0:
            self._ostream.write(" " * pad)
        self._ostream.write(f"{body}\n")


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

    def allocateCallGraph(self) -> None:
        """Allocate the call-graph object."""
        self.cgraph = None  # Placeholder — CallGraph not yet ported

    def abortFunction(self, ostream) -> None:
        """Clear references to current function."""
        if self.fd is None:
            return
        ostream.write(f"Unable to proceed with function: {self.fd.getName()}\n")
        if self.conf is not None and hasattr(self.conf, 'clearAnalysis'):
            self.conf.clearAnalysis(self.fd)
        self.fd = None

    def clearArchitecture(self) -> None:
        """Free all resources for the current architecture/program."""
        self.conf = None
        self.fd = None

    def followFlow(self, ostream, size: int) -> None:
        """Generate raw p-code for the current function."""
        if self.fd is None:
            return
        try:
            if size == 0:
                spc = self.fd.getAddress().getSpace()
                from ghidra.core.address import Address
                baddr = Address(spc, 0)
                eaddr = Address(spc, spc.getHighest())
                self.fd.followFlow(baddr, eaddr)
            else:
                start = self.fd.getAddress()
                self.fd.followFlow(start, start + size)
            ostream.write(f"Function {self.fd.getName()}: ")
            if hasattr(self.fd.getAddress(), 'printRaw'):
                self.fd.getAddress().printRaw(ostream)
            else:
                ostream.write(f"{self.fd.getAddress()}")
            ostream.write("\n")
        except Exception as err:
            ostream.write(f"Function {self.fd.getName()}: {err}\n")

    def readVarnode(self, args: str):
        """Read a varnode from the given args string. Placeholder."""
        raise IfaceExecutionError("readVarnode not yet implemented")

    def readSymbol(self, name: str) -> list:
        """Find a symbol by name. Placeholder."""
        if self.conf is None:
            raise IfaceExecutionError("No architecture loaded")
        return []


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
        self.iterateFunctionsAddrOrder_scope(scope)
        for child in scope.childrenIter():
            self.iterateScopesRecursive(child)

    def iterateFunctionsAddrOrder_scope(self, scope) -> None:
        """Iterate over all functions in a given scope."""
        for entry in scope:
            sym = entry.getSymbol()
            if hasattr(sym, 'getFunction'):
                self.iterationCallback(sym.getFunction())

    def iterateFunctionsAddrOrder(self) -> None:
        """Iterate command over all functions in all scopes."""
        if self.dcp is None or self.dcp.conf is None:
            raise IfaceExecutionError("No architecture loaded")
        self.iterateScopesRecursive(self.dcp.conf.symboltab.getGlobalScope())

    def iterateFunctionsLeafOrder(self) -> None:
        """Iterate command over all functions in a call-graph traversal."""
        if self.dcp is None or self.dcp.conf is None:
            raise IfaceExecutionError("No architecture loaded")
        if self.dcp.cgraph is None:
            raise IfaceExecutionError("No callgraph present")
        raise IfaceExecutionError("Call-graph traversal not yet implemented")


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
            raise IfaceParseError("No filename specified")
        if self.status is not None:
            self.status.pushScript(filename, f"[{filename}]> ")


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
            if hasattr(self.dcp.conf, 'options') and self.dcp.conf.options is not None:
                res = self.dcp.conf.options.set(optname, p1, p2, p3)
                if self.status is not None:
                    self.status.optr.write(f"{res}\n")
        except Exception as err:
            if self.status is not None:
                self.status.optr.write(f"{err}\n")
            raise IfaceExecutionError("Bad option") from err


class IfcParseLine(IfaceDecompCommand):
    """Parse a line of C syntax: `parse line ...`"""
    def execute(self, args: str) -> None:
        if self.dcp is None or self.dcp.conf is None:
            raise IfaceExecutionError("No load image present")
        if not args.strip():
            raise IfaceParseError("No input")
        # C parsing not yet implemented in Python
        raise IfaceExecutionError("C parsing not yet implemented")


class IfcParseFile(IfaceDecompCommand):
    """Parse a file with C declarations: `parse file <filename>`"""
    def execute(self, args: str) -> None:
        if self.dcp is None or self.dcp.conf is None:
            raise IfaceExecutionError("No load image present")
        filename = args.strip()
        if not filename:
            raise IfaceParseError("Missing filename")
        raise IfaceExecutionError("C file parsing not yet implemented")


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
            raise IfaceParseError("Bad adjustment value") from e
        if adjust == 0:
            raise IfaceParseError("No adjustment parameter")
        if self.dcp.conf.loader is not None:
            self.dcp.conf.loader.adjustVma(adjust)


class IfcFuncload(IfaceDecompCommand):
    """Make a specific function current: `load function <functionname>`"""
    def execute(self, args: str) -> None:
        funcname = args.strip()
        if self.dcp is None or self.dcp.conf is None:
            raise IfaceExecutionError("No image loaded")
        if not funcname:
            raise IfaceParseError("Missing function name")
        # Resolve scope from symbol name
        if hasattr(self.dcp.conf, 'symboltab') and self.dcp.conf.symboltab is not None:
            scope = self.dcp.conf.symboltab.getGlobalScope()
            if scope is not None and hasattr(scope, 'queryFunction'):
                self.dcp.fd = scope.queryFunction(funcname)
        if self.dcp.fd is None:
            raise IfaceExecutionError(f"Unknown function name: {funcname}")
        if not self.dcp.fd.hasNoCode() and self.status is not None:
            self.dcp.followFlow(self.status.optr, 0)


class IfcAddrrangeLoad(IfaceDecompCommand):
    """Create a new function at an address: `load addr <address> [<funcname>]`"""
    def execute(self, args: str) -> None:
        if self.dcp is None or self.dcp.conf is None:
            raise IfaceExecutionError("No binary loaded")
        raise IfaceExecutionError("load addr not yet implemented")


class IfcCleararch(IfaceDecompCommand):
    """Clear the current architecture: `clear architecture`"""
    def execute(self, args: str) -> None:
        if self.dcp is not None:
            self.dcp.clearArchitecture()


class IfcReadSymbols(IfaceDecompCommand):
    """Read in symbols from the load image: `read symbols`"""
    def execute(self, args: str) -> None:
        if self.dcp is None or self.dcp.conf is None:
            raise IfaceExecutionError("No load image present")
        if hasattr(self.dcp.conf, 'readLoaderSymbols'):
            self.dcp.conf.readLoaderSymbols("::")


class IfcDecompile(IfaceDecompCommand):
    """Decompile the current function: `decompile`"""
    def execute(self, args: str) -> None:
        if self.dcp is None or self.dcp.fd is None:
            raise IfaceExecutionError("No function selected")
        if self.dcp.conf is None:
            raise IfaceExecutionError("No architecture loaded")
        fd = self.dcp.fd
        optr = self.status.optr if self.status else io.StringIO()

        if fd.hasNoCode():
            optr.write(f"No code for {fd.getName()}\n")
            return
        if fd.isProcStarted():
            optr.write("Clearing old decompilation\n")
            self.dcp.conf.clearAnalysis(fd)

        optr.write(f"Decompiling {fd.getName()}\n")
        try:
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
        except Exception as err:
            optr.write(f"Decompilation error: {err}\n")


class IfcPrintLanguage(IfaceDecompCommand):
    """Set the output language: `print language`"""
    def execute(self, args: str) -> None:
        if self.dcp is None or self.dcp.conf is None:
            raise IfaceExecutionError("No load image present")
        lang = args.strip()
        if not lang:
            raise IfaceParseError("No language specified")
        # Language switching not yet implemented
        if self.status is not None:
            self.status.optr.write(f"Language set request: {lang}\n")


class IfcPrintCStruct(IfaceDecompCommand):
    """Print current function with structure: `print C`"""
    def execute(self, args: str) -> None:
        if self.dcp is None or self.dcp.fd is None:
            raise IfaceExecutionError("No function selected")
        if self.dcp.conf is None or not hasattr(self.dcp.conf, 'print') or self.dcp.conf.print is None:
            raise IfaceExecutionError("No print language configured")
        optr = self.status.fileoptr if self.status else io.StringIO()
        self.dcp.conf.print.setOutputStream(optr)
        self.dcp.conf.print.docFunction(self.dcp.fd)


class IfcPrintCFlat(IfaceDecompCommand):
    """Print current function without control-flow: `print C flat`"""
    def execute(self, args: str) -> None:
        if self.dcp is None or self.dcp.fd is None:
            raise IfaceExecutionError("No function selected")
        if self.dcp.conf is None or not hasattr(self.dcp.conf, 'print') or self.dcp.conf.print is None:
            raise IfaceExecutionError("No print language configured")
        optr = self.status.fileoptr if self.status else io.StringIO()
        self.dcp.conf.print.setOutputStream(optr)
        self.dcp.conf.print.setFlat(True)
        self.dcp.conf.print.docFunction(self.dcp.fd)
        self.dcp.conf.print.setFlat(False)


class IfcPrintCXml(IfaceDecompCommand):
    """Print C output in XML format: `print C xml`"""
    def execute(self, args: str) -> None:
        raise IfaceExecutionError("print C xml not yet implemented")


class IfcPrintCGlobals(IfaceDecompCommand):
    """Print declarations for global variables: `print C globals`"""
    def execute(self, args: str) -> None:
        if self.dcp is None or self.dcp.conf is None:
            raise IfaceExecutionError("No load image present")
        if not hasattr(self.dcp.conf, 'print') or self.dcp.conf.print is None:
            raise IfaceExecutionError("No print language configured")
        optr = self.status.fileoptr if self.status else io.StringIO()
        self.dcp.conf.print.setOutputStream(optr)
        self.dcp.conf.print.docAllGlobals()


class IfcPrintCTypes(IfaceDecompCommand):
    """Print known data-types: `print C types`"""
    def execute(self, args: str) -> None:
        if self.dcp is None or self.dcp.conf is None:
            raise IfaceExecutionError("No load image present")
        raise IfaceExecutionError("print C types not yet implemented")


class IfcProduceC(IfaceDecompCommand):
    """Decompile and produce C for all functions: `produce C`"""
    def execute(self, args: str) -> None:
        if self.dcp is None or self.dcp.conf is None:
            raise IfaceExecutionError("No load image present")
        self.iterateFunctionsAddrOrder()

    def iterationCallback(self, fd) -> None:
        if self.dcp is None or self.dcp.conf is None:
            return
        try:
            self.dcp.conf.clearAnalysis(fd)
            act = self.dcp.conf.allacts.getCurrent()
            act.reset(fd)
            act.perform(fd)
            if hasattr(self.dcp.conf, 'print') and self.dcp.conf.print is not None:
                optr = self.status.fileoptr if self.status else io.StringIO()
                self.dcp.conf.print.setOutputStream(optr)
                self.dcp.conf.print.docFunction(fd)
        except Exception as err:
            if self.status is not None:
                self.status.optr.write(f"Error decompiling {fd.getName()}: {err}\n")


class IfcProducePrototypes(IfaceDecompCommand):
    """Produce prototypes for all functions: `produce prototypes`"""
    def execute(self, args: str) -> None:
        if self.dcp is None or self.dcp.conf is None:
            raise IfaceExecutionError("No load image present")
        self.iterateFunctionsAddrOrder()

    def iterationCallback(self, fd) -> None:
        if self.status is not None:
            self.status.optr.write(f"{fd.getName()}\n")


# =========================================================================
# Print / Debug commands (stubs)
# =========================================================================

class IfcPrintdisasm(IfaceDecompCommand):
    """Print disassembly: `disassemble`"""
    def execute(self, args: str) -> None:
        if self.dcp is None or self.dcp.fd is None:
            raise IfaceExecutionError("No function selected")
        raise IfaceExecutionError("disassemble not yet implemented")


class IfcDump(IfaceDecompCommand):
    """Display bytes: `dump <address+size>`"""
    def execute(self, args: str) -> None:
        raise IfaceExecutionError("dump not yet implemented")


class IfcDumpbinary(IfaceDecompCommand):
    """Dump memory to file: `binary <address+size> <filename>`"""
    def execute(self, args: str) -> None:
        raise IfaceExecutionError("binary dump not yet implemented")


class IfcPrintRaw(IfaceDecompCommand):
    """Print raw p-code: `print raw`"""
    def execute(self, args: str) -> None:
        if self.dcp is None or self.dcp.fd is None:
            raise IfaceExecutionError("No function selected")
        raise IfaceExecutionError("print raw not yet implemented")


class IfcPrintTree(IfaceDecompCommand):
    """Print varnode tree: `print tree varnode`"""
    def execute(self, args: str) -> None:
        raise IfaceExecutionError("print tree varnode not yet implemented")


class IfcPrintBlocktree(IfaceDecompCommand):
    """Print block tree: `print tree block`"""
    def execute(self, args: str) -> None:
        raise IfaceExecutionError("print tree block not yet implemented")


class IfcPrintSpaces(IfaceDecompCommand):
    """Print address spaces: `print spaces`"""
    def execute(self, args: str) -> None:
        if self.dcp is None or self.dcp.conf is None:
            raise IfaceExecutionError("No load image present")
        optr = self.status.optr if self.status else io.StringIO()
        if hasattr(self.dcp.conf, 'numSpaces'):
            for i in range(self.dcp.conf.numSpaces()):
                spc = self.dcp.conf.getSpace(i)
                if spc is not None:
                    optr.write(f"{spc.getName()} ({spc.getType()})\n")


class IfcPrintHigh(IfaceDecompCommand):
    """Print high-level variable: `print high`"""
    def execute(self, args: str) -> None:
        raise IfaceExecutionError("print high not yet implemented")


class IfcPrintParamMeasures(IfaceDecompCommand):
    """Print parameter measures: `print parammeasures`"""
    def execute(self, args: str) -> None:
        raise IfaceExecutionError("print parammeasures not yet implemented")


class IfcPrintVarnode(IfaceDecompCommand):
    """Print varnode: `print varnode`"""
    def execute(self, args: str) -> None:
        raise IfaceExecutionError("print varnode not yet implemented")


class IfcPrintCover(IfaceDecompCommand):
    """Print cover for high: `print cover high`"""
    def execute(self, args: str) -> None:
        raise IfaceExecutionError("print cover high not yet implemented")


class IfcVarnodeCover(IfaceDecompCommand):
    """Print cover for varnode: `print cover varnode`"""
    def execute(self, args: str) -> None:
        raise IfaceExecutionError("print cover varnode not yet implemented")


class IfcVarnodehighCover(IfaceDecompCommand):
    """Print varnodehigh cover: `print cover varnodehigh`"""
    def execute(self, args: str) -> None:
        raise IfaceExecutionError("print cover varnodehigh not yet implemented")


class IfcPrintExtrapop(IfaceDecompCommand):
    """Print extrapop: `print extrapop`"""
    def execute(self, args: str) -> None:
        raise IfaceExecutionError("print extrapop not yet implemented")


class IfcPrintActionstats(IfaceDecompCommand):
    """Print action stats: `print actionstats`"""
    def execute(self, args: str) -> None:
        raise IfaceExecutionError("print actionstats not yet implemented")


class IfcResetActionstats(IfaceDecompCommand):
    """Reset action stats: `reset actionstats`"""
    def execute(self, args: str) -> None:
        if self.dcp is None or self.dcp.conf is None:
            raise IfaceExecutionError("No architecture loaded")
        # Reset stats on all actions
        if self.status is not None:
            self.status.optr.write("Action stats reset\n")


class IfcPrintInputs(IfaceDecompCommand):
    """Print function inputs: `print inputs`"""
    def execute(self, args: str) -> None:
        raise IfaceExecutionError("print inputs not yet implemented")


class IfcPrintInputsAll(IfaceDecompCommand):
    """Print inputs for all functions: `print inputs all`"""
    def execute(self, args: str) -> None:
        raise IfaceExecutionError("print inputs all not yet implemented")


class IfcPrintLocalrange(IfaceDecompCommand):
    """Print local range: `print localrange`"""
    def execute(self, args: str) -> None:
        raise IfaceExecutionError("print localrange not yet implemented")


class IfcPrintMap(IfaceDecompCommand):
    """Print symbol map: `print map`"""
    def execute(self, args: str) -> None:
        raise IfaceExecutionError("print map not yet implemented")


# =========================================================================
# Mapping commands (stubs)
# =========================================================================

class IfcMapaddress(IfaceDecompCommand):
    """Map a new symbol: `map address <address> <typedecl>`"""
    def execute(self, args: str) -> None:
        raise IfaceExecutionError("map address not yet implemented")


class IfcMaphash(IfaceDecompCommand):
    """Add a dynamic symbol: `map hash ...`"""
    def execute(self, args: str) -> None:
        raise IfaceExecutionError("map hash not yet implemented")


class IfcMapParam(IfaceDecompCommand):
    """Map a parameter: `map param ...`"""
    def execute(self, args: str) -> None:
        raise IfaceExecutionError("map param not yet implemented")


class IfcMapReturn(IfaceDecompCommand):
    """Map return storage: `map return ...`"""
    def execute(self, args: str) -> None:
        raise IfaceExecutionError("map return not yet implemented")


class IfcMapfunction(IfaceDecompCommand):
    """Create a new function: `map function <address> [<name>]`"""
    def execute(self, args: str) -> None:
        raise IfaceExecutionError("map function not yet implemented")


class IfcMapexternalref(IfaceDecompCommand):
    """Create an external ref: `map externalref ...`"""
    def execute(self, args: str) -> None:
        raise IfaceExecutionError("map externalref not yet implemented")


class IfcMaplabel(IfaceDecompCommand):
    """Create a code label: `map label <name> <address>`"""
    def execute(self, args: str) -> None:
        raise IfaceExecutionError("map label not yet implemented")


class IfcMapconvert(IfaceDecompCommand):
    """Create a convert directive: `map convert ...`"""
    def execute(self, args: str) -> None:
        raise IfaceExecutionError("map convert not yet implemented")


class IfcMapunionfacet(IfaceDecompCommand):
    """Create a union field directive: `map unionfacet ...`"""
    def execute(self, args: str) -> None:
        raise IfaceExecutionError("map unionfacet not yet implemented")


# =========================================================================
# Action/Override commands (stubs)
# =========================================================================

class IfcListaction(IfaceDecompCommand):
    """List available actions: `list action`"""
    def execute(self, args: str) -> None:
        if self.dcp is None or self.dcp.conf is None:
            raise IfaceExecutionError("No architecture loaded")
        optr = self.status.optr if self.status else io.StringIO()
        if hasattr(self.dcp.conf, 'allacts'):
            act = self.dcp.conf.allacts.getCurrent()
            if act is not None and hasattr(act, 'printState'):
                act.printState(optr)
            optr.write("\n")


class IfcListOverride(IfaceDecompCommand):
    """List overrides: `list override`"""
    def execute(self, args: str) -> None:
        raise IfaceExecutionError("list override not yet implemented")


class IfcListprototypes(IfaceDecompCommand):
    """List prototypes: `list prototypes`"""
    def execute(self, args: str) -> None:
        if self.dcp is None or self.dcp.conf is None:
            raise IfaceExecutionError("No architecture loaded")
        optr = self.status.optr if self.status else io.StringIO()
        if hasattr(self.dcp.conf, 'protoModels'):
            for name in self.dcp.conf.protoModels:
                optr.write(f"{name}\n")


class IfcSetcontextrange(IfaceDecompCommand):
    """Set context: `set context ...`"""
    def execute(self, args: str) -> None:
        raise IfaceExecutionError("set context not yet implemented")


class IfcSettrackedrange(IfaceDecompCommand):
    """Set tracked range: `set track ...`"""
    def execute(self, args: str) -> None:
        raise IfaceExecutionError("set track not yet implemented")


class IfcBreakstart(IfaceDecompCommand):
    """Set break at start: `break start`"""
    def execute(self, args: str) -> None:
        raise IfaceExecutionError("break start not yet implemented")


class IfcBreakaction(IfaceDecompCommand):
    """Set break at action: `break action <name>`"""
    def execute(self, args: str) -> None:
        raise IfaceExecutionError("break action not yet implemented")


class IfcContinue(IfaceDecompCommand):
    """Continue decompilation after a break: `continue`"""
    def execute(self, args: str) -> None:
        if self.dcp is None or self.dcp.fd is None:
            raise IfaceExecutionError("No function selected")
        if self.dcp.conf is None:
            raise IfaceExecutionError("No architecture loaded")
        optr = self.status.optr if self.status else io.StringIO()
        try:
            act = self.dcp.conf.allacts.getCurrent()
            res = act.perform(self.dcp.fd)
            if res < 0:
                optr.write("Break at ")
                act.printState(optr)
            else:
                optr.write("Decompilation complete")
                if res == 0:
                    optr.write(" (no change)")
            optr.write("\n")
        except Exception as err:
            optr.write(f"Decompilation error: {err}\n")


# =========================================================================
# Symbol manipulation commands (stubs)
# =========================================================================

class IfcRename(IfaceDecompCommand):
    """Rename a symbol: `rename`"""
    def execute(self, args: str) -> None:
        raise IfaceExecutionError("rename not yet implemented")


class IfcRetype(IfaceDecompCommand):
    """Retype a symbol: `retype`"""
    def execute(self, args: str) -> None:
        raise IfaceExecutionError("retype not yet implemented")


class IfcRemove(IfaceDecompCommand):
    """Remove a symbol: `remove`"""
    def execute(self, args: str) -> None:
        raise IfaceExecutionError("remove not yet implemented")


class IfcIsolate(IfaceDecompCommand):
    """Isolate a symbol: `isolate`"""
    def execute(self, args: str) -> None:
        raise IfaceExecutionError("isolate not yet implemented")


class IfcNameVarnode(IfaceDecompCommand):
    """Name a varnode: `name varnode`"""
    def execute(self, args: str) -> None:
        raise IfaceExecutionError("name varnode not yet implemented")


class IfcTypeVarnode(IfaceDecompCommand):
    """Type a varnode: `type varnode`"""
    def execute(self, args: str) -> None:
        raise IfaceExecutionError("type varnode not yet implemented")


class IfcForceFormat(IfaceDecompCommand):
    """Force format on varnode: `force varnode`"""
    def execute(self, args: str) -> None:
        raise IfaceExecutionError("force varnode not yet implemented")


class IfcForceDatatypeFormat(IfaceDecompCommand):
    """Force datatype format: `force datatype`"""
    def execute(self, args: str) -> None:
        raise IfaceExecutionError("force datatype not yet implemented")


class IfcForcegoto(IfaceDecompCommand):
    """Force goto: `force goto`"""
    def execute(self, args: str) -> None:
        raise IfaceExecutionError("force goto not yet implemented")


class IfcProtooverride(IfaceDecompCommand):
    """Override prototype: `override prototype`"""
    def execute(self, args: str) -> None:
        raise IfaceExecutionError("override prototype not yet implemented")


class IfcJumpOverride(IfaceDecompCommand):
    """Override jump table: `override jumptable`"""
    def execute(self, args: str) -> None:
        raise IfaceExecutionError("override jumptable not yet implemented")


class IfcFlowOverride(IfaceDecompCommand):
    """Override flow: `override flow`"""
    def execute(self, args: str) -> None:
        raise IfaceExecutionError("override flow not yet implemented")


class IfcDeadcodedelay(IfaceDecompCommand):
    """Set deadcode delay: `deadcode delay`"""
    def execute(self, args: str) -> None:
        raise IfaceExecutionError("deadcode delay not yet implemented")


# =========================================================================
# Global commands (stubs)
# =========================================================================

class IfcGlobalAdd(IfaceDecompCommand):
    """Add a global range: `global add`"""
    def execute(self, args: str) -> None:
        raise IfaceExecutionError("global add not yet implemented")


class IfcGlobalRemove(IfaceDecompCommand):
    """Remove a global range: `global remove`"""
    def execute(self, args: str) -> None:
        raise IfaceExecutionError("global remove not yet implemented")


class IfcGlobalify(IfaceDecompCommand):
    """Globalize spaces: `global spaces`"""
    def execute(self, args: str) -> None:
        raise IfaceExecutionError("global spaces not yet implemented")


class IfcGlobalRegisters(IfaceDecompCommand):
    """Globalize registers: `global registers`"""
    def execute(self, args: str) -> None:
        raise IfaceExecutionError("global registers not yet implemented")


# =========================================================================
# Graph commands (stubs)
# =========================================================================

class IfcGraphDataflow(IfaceDecompCommand):
    """Graph dataflow: `graph dataflow`"""
    def execute(self, args: str) -> None:
        raise IfaceExecutionError("graph dataflow not yet implemented")


class IfcGraphControlflow(IfaceDecompCommand):
    """Graph control flow: `graph controlflow`"""
    def execute(self, args: str) -> None:
        raise IfaceExecutionError("graph controlflow not yet implemented")


class IfcGraphDom(IfaceDecompCommand):
    """Graph dominators: `graph dom`"""
    def execute(self, args: str) -> None:
        raise IfaceExecutionError("graph dom not yet implemented")


# =========================================================================
# Prototype/Fixup commands (stubs)
# =========================================================================

class IfcLockPrototype(IfaceDecompCommand):
    """Lock prototype: `prototype lock`"""
    def execute(self, args: str) -> None:
        raise IfaceExecutionError("prototype lock not yet implemented")


class IfcUnlockPrototype(IfaceDecompCommand):
    """Unlock prototype: `prototype unlock`"""
    def execute(self, args: str) -> None:
        raise IfaceExecutionError("prototype unlock not yet implemented")


class IfcCallFixup(IfaceDecompCommand):
    """Apply a call fixup: `fixup call`"""
    def execute(self, args: str) -> None:
        raise IfaceExecutionError("fixup call not yet implemented")


class IfcCallOtherFixup(IfaceDecompCommand):
    """Apply a callother fixup: `fixup callother`"""
    def execute(self, args: str) -> None:
        raise IfaceExecutionError("fixup callother not yet implemented")


class IfcFixupApply(IfaceDecompCommand):
    """Apply fixups: `fixup apply`"""
    def execute(self, args: str) -> None:
        raise IfaceExecutionError("fixup apply not yet implemented")


# =========================================================================
# Miscellaneous commands (stubs)
# =========================================================================

class IfcCommentInstr(IfaceDecompCommand):
    """Comment an instruction: `comment instruction`"""
    def execute(self, args: str) -> None:
        raise IfaceExecutionError("comment instruction not yet implemented")


class IfcDuplicateHash(IfaceDecompCommand):
    """Check duplicate hashes: `duplicate hash`"""
    def execute(self, args: str) -> None:
        raise IfaceExecutionError("duplicate hash not yet implemented")


class IfcCountPcode(IfaceDecompCommand):
    """Count pcode ops: `count pcode`"""
    def execute(self, args: str) -> None:
        raise IfaceExecutionError("count pcode not yet implemented")


class IfcVolatile(IfaceDecompCommand):
    """Mark volatile: `volatile`"""
    def execute(self, args: str) -> None:
        raise IfaceExecutionError("volatile not yet implemented")


class IfcReadonly(IfaceDecompCommand):
    """Mark readonly: `readonly`"""
    def execute(self, args: str) -> None:
        raise IfaceExecutionError("readonly not yet implemented")


class IfcPointerSetting(IfaceDecompCommand):
    """Pointer setting: `pointer setting`"""
    def execute(self, args: str) -> None:
        raise IfaceExecutionError("pointer setting not yet implemented")


class IfcPreferSplit(IfaceDecompCommand):
    """Prefer split: `prefersplit`"""
    def execute(self, args: str) -> None:
        raise IfaceExecutionError("prefersplit not yet implemented")


class IfcStructureBlocks(IfaceDecompCommand):
    """Structure blocks: `structure blocks`"""
    def execute(self, args: str) -> None:
        raise IfaceExecutionError("structure blocks not yet implemented")


class IfcAnalyzeRange(IfaceDecompCommand):
    """Analyze range: `analyze range`"""
    def execute(self, args: str) -> None:
        raise IfaceExecutionError("analyze range not yet implemented")


# =========================================================================
# CallGraph commands (stubs)
# =========================================================================

class IfcCallGraphBuild(IfaceDecompCommand):
    """Build call graph: `callgraph build`"""
    def execute(self, args: str) -> None:
        raise IfaceExecutionError("callgraph build not yet implemented")


class IfcCallGraphBuildQuick(IfcCallGraphBuild):
    """Build call graph quickly: `callgraph build quick`"""
    def execute(self, args: str) -> None:
        raise IfaceExecutionError("callgraph build quick not yet implemented")


class IfcCallGraphDump(IfaceDecompCommand):
    """Dump call graph: `callgraph dump`"""
    def execute(self, args: str) -> None:
        raise IfaceExecutionError("callgraph dump not yet implemented")


class IfcCallGraphLoad(IfaceDecompCommand):
    """Load call graph: `callgraph load`"""
    def execute(self, args: str) -> None:
        raise IfaceExecutionError("callgraph load not yet implemented")


class IfcCallGraphList(IfaceDecompCommand):
    """List call graph: `callgraph list`"""
    def execute(self, args: str) -> None:
        raise IfaceExecutionError("callgraph list not yet implemented")


# =========================================================================
# Test commands (stubs)
# =========================================================================

class IfcLoadTestFile(IfaceDecompCommand):
    """Load test file: `load test file`"""
    def execute(self, args: str) -> None:
        raise IfaceExecutionError("load test file not yet implemented")


class IfcListTestCommands(IfaceDecompCommand):
    """List test commands: `list test commands`"""
    def execute(self, args: str) -> None:
        raise IfaceExecutionError("list test commands not yet implemented")


class IfcExecuteTestCommand(IfaceDecompCommand):
    """Execute test command: `execute test command`"""
    def execute(self, args: str) -> None:
        raise IfaceExecutionError("execute test command not yet implemented")


# =========================================================================
# IfaceDecompCapability
# =========================================================================

class IfaceDecompCapability(IfaceCapability):
    """Interface capability point for all decompiler commands."""

    _instance: Optional[IfaceDecompCapability] = None

    def __init__(self) -> None:
        super().__init__("decomp")

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
        status.registerCom(IfcContinue(), "continue")


# =========================================================================
# Helper functions
# =========================================================================

def execute(status: IfaceStatus, dcp: IfaceDecompData) -> None:
    """Execute one command for the console."""
    try:
        status.runCommand()
    except Exception as err:
        status.optr.write(f"ERROR: {err}\n")
        dcp.abortFunction(status.optr)
        status.evaluateError()


def mainloop(status: IfaceStatus) -> None:
    """Execute commands as they become available."""
    while not status.done and not status.isStreamFinished():
        dcp = status.getData("decompile")
        try:
            status.runCommand()
        except Exception as err:
            status.optr.write(f"ERROR: {err}\n")
            if isinstance(dcp, IfaceDecompData):
                dcp.abortFunction(status.optr)
            status.evaluateError()
