"""
Corresponds to: codedata.hh / codedata.cc

Code/data analysis module for distinguishing code from data in binary images.
Provides disassembly-based analysis, cross-reference tracking, taint propagation,
and target hit detection.
"""

from __future__ import annotations

import io
from typing import Dict, List, Optional, TYPE_CHECKING

from ghidra.console.interface import (
    IfaceData, IfaceCommand, IfaceCapability, IfaceStatus,
    IfaceParseError, IfaceExecutionError,
)

if TYPE_CHECKING:
    from ghidra.core.address import Address
    from ghidra.arch.architecture import Architecture


# =========================================================================
# CodeUnit
# =========================================================================

class CodeUnit:
    """Represents a single code unit with flags and size."""

    # Flag constants
    fallthru = 1
    jump = 2
    call = 4
    notcode = 8
    hit_by_fallthru = 16
    hit_by_jump = 32
    hit_by_call = 64
    errantstart = 128
    targethit = 256
    thunkhit = 512

    def __init__(self, flags: int = 0, size: int = 0) -> None:
        self.flags: int = flags
        self.size: int = size


# =========================================================================
# DisassemblyResult
# =========================================================================

class DisassemblyResult:
    """Result of a single disassembly attempt."""

    def __init__(self) -> None:
        self.success: bool = False
        self.length: int = 0
        self.flags: int = 0
        self.jumpaddress = None  # Address
        self.targethit: int = 0


# =========================================================================
# AddrLink
# =========================================================================

class AddrLink:
    """A pair of addresses used as a cross-reference key."""

    def __init__(self, a, b=None) -> None:
        self.a = a
        self.b = b

    def __lt__(self, other: AddrLink) -> bool:
        if self.a != other.a:
            return self.a < other.a
        if self.b is None and other.b is None:
            return False
        if self.b is None:
            return True
        if other.b is None:
            return False
        return self.b < other.b

    def __eq__(self, other) -> bool:
        if not isinstance(other, AddrLink):
            return NotImplemented
        return self.a == other.a and self.b == other.b

    def __hash__(self) -> int:
        return hash((self.a, self.b))


# =========================================================================
# TargetHit
# =========================================================================

class TargetHit:
    """Records a hit on a target function."""

    def __init__(self, funcstart, codeaddr, thunkaddr, mask: int) -> None:
        self.funcstart = funcstart
        self.codeaddr = codeaddr
        self.thunkaddr = thunkaddr
        self.mask: int = mask

    def __lt__(self, other: TargetHit) -> bool:
        return self.funcstart < other.funcstart


# =========================================================================
# TargetFeature
# =========================================================================

class TargetFeature:
    """Feature description for a target function."""

    def __init__(self, name: str = "", featuremask: int = 0) -> None:
        self.name: str = name
        self.featuremask: int = featuremask


# =========================================================================
# DisassemblyEngine
# =========================================================================

class DisassemblyEngine:
    """Lightweight disassembly engine that tracks jumps, calls, and target hits."""

    def __init__(self) -> None:
        self._trans = None
        self._jumpaddr: List = []
        self._targetoffsets: set = set()
        self._lastop: int = 0
        self._hascall: bool = False
        self._hitsaddress: bool = False
        self._targethit: int = 0

    def init(self, trans) -> None:
        """Initialize with a Translate object."""
        self._trans = trans
        self._jumpaddr.clear()
        self._targetoffsets.clear()

    def addTarget(self, addr) -> None:
        """Add a target address to watch for."""
        self._targetoffsets.add(addr.getOffset() if hasattr(addr, 'getOffset') else addr)

    def dump(self, addr, opc: int, outvar, invars, isize: int) -> None:
        """P-code emit callback — tracks branches, calls, and target hits."""
        from ghidra.core.opcodes import OpCode
        self._lastop = opc
        if opc in (OpCode.CPUI_CALL, OpCode.CPUI_BRANCH, OpCode.CPUI_CBRANCH):
            if opc == OpCode.CPUI_CALL:
                self._hascall = True
            if invars and len(invars) > 0:
                v = invars[0]
                jaddr = v if not hasattr(v, 'space') else None
                if hasattr(v, 'space') and hasattr(v, 'offset'):
                    from ghidra.core.address import Address as Addr
                    jaddr = Addr(v.space, v.offset)
                if jaddr is not None:
                    self._jumpaddr.append(jaddr)
        elif opc in (OpCode.CPUI_COPY, OpCode.CPUI_BRANCHIND, OpCode.CPUI_CALLIND):
            if invars and len(invars) > 0:
                off = invars[0].offset if hasattr(invars[0], 'offset') else invars[0]
                if off in self._targetoffsets:
                    self._hitsaddress = True
                    self._targethit = off
        elif opc == OpCode.CPUI_LOAD:
            if invars and len(invars) > 1:
                off = invars[1].offset if hasattr(invars[1], 'offset') else invars[1]
                if off in self._targetoffsets:
                    self._hitsaddress = True
                    self._targethit = off

    def disassemble(self, addr, res: DisassemblyResult) -> None:
        """Disassemble a single instruction at the given address."""
        self._jumpaddr.clear()
        self._lastop = 0  # CPUI_COPY
        self._hascall = False
        self._hitsaddress = False
        res.flags = 0

        if self._trans is None:
            res.success = False
            return

        try:
            res.length = self._trans.oneInstruction(self, addr)
        except Exception:
            res.success = False
            return

        res.success = True
        if self._hascall:
            res.flags |= CodeUnit.call
        if self._hitsaddress:
            res.flags |= CodeUnit.targethit
            res.targethit = self._targethit

        from ghidra.core.opcodes import OpCode
        if self._lastop in (OpCode.CPUI_BRANCH, OpCode.CPUI_BRANCHIND):
            if self._hitsaddress:
                res.flags |= CodeUnit.thunkhit
        elif self._lastop == OpCode.CPUI_RETURN:
            pass  # No fallthrough
        else:
            res.flags |= CodeUnit.fallthru

        lastaddr = addr + res.length if hasattr(addr, '__add__') else None
        for ja in self._jumpaddr:
            if lastaddr is not None and ja == lastaddr:
                res.flags |= CodeUnit.fallthru
            elif ja != addr:
                res.flags |= CodeUnit.jump
                res.jumpaddress = ja


# =========================================================================
# CodeDataAnalysis
# =========================================================================

class CodeDataAnalysis(IfaceData):
    """Code/data analysis engine — distinguishes code from data in binaries."""

    def __init__(self) -> None:
        super().__init__()
        self.alignment: int = 1
        self.glb: Optional[Architecture] = None
        self.disengine: DisassemblyEngine = DisassemblyEngine()
        self.codeunit: Dict = {}  # Address -> CodeUnit (ordered by address)
        self.fromto_crossref: Dict = {}  # AddrLink -> flags
        self.tofrom_crossref: Dict = {}  # AddrLink -> flags
        self.taintlist: List = []
        self.unlinkedstarts: List = []
        self.targethits: List[TargetHit] = []
        self.targets: Dict = {}  # Address -> TargetFeature

    def init(self, glb) -> None:
        """Initialize analysis with an Architecture."""
        self.glb = glb
        if glb is not None and hasattr(glb, 'translate') and glb.translate is not None:
            self.disengine.init(glb.translate)
            self.alignment = glb.translate.getAlignment() if hasattr(glb.translate, 'getAlignment') else 1
        self.codeunit.clear()
        self.fromto_crossref.clear()
        self.tofrom_crossref.clear()
        self.taintlist.clear()
        self.unlinkedstarts.clear()
        self.targethits.clear()
        self.targets.clear()

    def addTarget(self, name: str, addr, mask: int) -> None:
        """Add a target thunk to search for."""
        feat = TargetFeature(name, mask)
        self.targets[addr] = feat
        self.disengine.addTarget(addr)

    def getNumTargets(self) -> int:
        return len(self.targets)

    def getTargetHits(self) -> List[TargetHit]:
        return self.targethits

    def clearHitBy(self) -> None:
        """Clear all hit_by flags from all code units."""
        mask = ~(CodeUnit.hit_by_fallthru | CodeUnit.hit_by_jump | CodeUnit.hit_by_call)
        for cu in self.codeunit.values():
            cu.flags &= mask

    def markFallthruHits(self) -> None:
        """Mark every code unit that has another code unit fall into it."""
        fallthru_addr = None
        for addr, cu in sorted(self.codeunit.items()):
            if cu.flags & CodeUnit.notcode:
                fallthru_addr = None
                continue
            if fallthru_addr is not None and addr == fallthru_addr:
                cu.flags |= CodeUnit.hit_by_fallthru
            if cu.flags & CodeUnit.fallthru:
                fallthru_addr = addr + cu.size if hasattr(addr, '__add__') else None
            else:
                fallthru_addr = None

    def markCrossHits(self) -> None:
        """Mark every code unit hit by a call or jump."""
        for link, flags in self.tofrom_crossref.items():
            target_addr = link.a
            if target_addr not in self.codeunit:
                continue
            cu = self.codeunit[target_addr]
            if flags & CodeUnit.call:
                cu.flags |= CodeUnit.hit_by_call
            elif flags & CodeUnit.jump:
                cu.flags |= CodeUnit.hit_by_jump

    def findUnlinked(self) -> None:
        """Find all code units with no jump/call/fallthru to them."""
        for addr, cu in self.codeunit.items():
            check = (CodeUnit.hit_by_fallthru | CodeUnit.hit_by_jump |
                     CodeUnit.hit_by_call | CodeUnit.notcode | CodeUnit.errantstart)
            if (cu.flags & check) == 0:
                self.unlinkedstarts.append(addr)

    def findFunctionStart(self, addr):
        """Find the starting address of a function containing addr."""
        for link, flags in sorted(self.tofrom_crossref.items(), reverse=True):
            if link.a <= addr and (flags & CodeUnit.call):
                return link.a
        return None

    def dumpModelHits(self, s) -> None:
        """Dump model hit ranges."""
        s.write("[CodeDataAnalysis model hits]\n")

    def dumpCrossRefs(self, s) -> None:
        """Dump cross-references."""
        for link, flags in self.fromto_crossref.items():
            a_off = link.a.getOffset() if hasattr(link.a, 'getOffset') else link.a
            b_off = link.b.getOffset() if hasattr(link.b, 'getOffset') else link.b
            line = f"0x{a_off:x} -> 0x{b_off:x}"
            if flags & CodeUnit.call:
                line += " call"
            s.write(line + "\n")

    def dumpFunctionStarts(self, s) -> None:
        """Dump function start addresses."""
        for link, flags in self.tofrom_crossref.items():
            if flags & CodeUnit.call:
                off = link.a.getOffset() if hasattr(link.a, 'getOffset') else link.a
                s.write(f"0x{off:x}\n")

    def dumpUnlinked(self, s) -> None:
        """Dump unlinked start addresses."""
        for addr in self.unlinkedstarts:
            off = addr.getOffset() if hasattr(addr, 'getOffset') else addr
            s.write(f"0x{off:x}\n")

    def dumpTargetHits(self, s) -> None:
        """Dump target hits."""
        for hit in self.targethits:
            func_off = hit.funcstart
            code_off = hit.codeaddr
            thunk = hit.thunkaddr
            name = ""
            if thunk in self.targets:
                name = self.targets[thunk].name
            if func_off is not None:
                f = func_off.getOffset() if hasattr(func_off, 'getOffset') else func_off
                s.write(f"{f:x} ")
            else:
                s.write("nostart ")
            c = code_off.getOffset() if hasattr(code_off, 'getOffset') else code_off
            s.write(f"{c:x} {name}\n")


# =========================================================================
# Console commands
# =========================================================================

class IfaceCodeDataCommand(IfaceCommand):
    """Base class for code/data analysis commands."""

    def __init__(self) -> None:
        super().__init__()
        self.status: Optional[IfaceStatus] = None
        self.dcp = None  # IfaceDecompData
        self.codedata: Optional[CodeDataAnalysis] = None

    def setData(self, root: IfaceStatus, data) -> None:
        self.status = root
        self.codedata = data
        self.dcp = root.getData("decompile") if root is not None else None

    def getModule(self) -> str:
        return "codedata"

    def createData(self) -> CodeDataAnalysis:
        return CodeDataAnalysis()


class IfcCodeDataInit(IfaceCodeDataCommand):
    """Initialize code/data analysis: `codedata init`"""
    def execute(self, args: str) -> None:
        if self.codedata is None or self.dcp is None:
            raise IfaceExecutionError("No code data or decompiler context")
        if not hasattr(self.dcp, 'conf') or self.dcp.conf is None:
            raise IfaceExecutionError("No architecture loaded")
        self.codedata.init(self.dcp.conf)


class IfcCodeDataTarget(IfaceCodeDataCommand):
    """Add a target for analysis: `codedata target <name>`"""
    def execute(self, args: str) -> None:
        token = args.strip()
        if not token:
            raise IfaceParseError("Missing system call name")
        raise IfaceExecutionError("codedata target not yet fully implemented (requires BFD)")


class IfcCodeDataRun(IfaceCodeDataCommand):
    """Run code/data analysis: `codedata run`"""
    def execute(self, args: str) -> None:
        if self.codedata is None:
            raise IfaceExecutionError("No code data context")
        raise IfaceExecutionError("codedata run not yet fully implemented")


class IfcCodeDataDumpModelHits(IfaceCodeDataCommand):
    """Dump model hits: `codedata dump hits`"""
    def execute(self, args: str) -> None:
        if self.codedata is None:
            raise IfaceExecutionError("No code data context")
        optr = self.status.fileoptr if self.status else io.StringIO()
        self.codedata.dumpModelHits(optr)


class IfcCodeDataDumpCrossRefs(IfaceCodeDataCommand):
    """Dump cross-references: `codedata dump crossrefs`"""
    def execute(self, args: str) -> None:
        if self.codedata is None:
            raise IfaceExecutionError("No code data context")
        optr = self.status.fileoptr if self.status else io.StringIO()
        self.codedata.dumpCrossRefs(optr)


class IfcCodeDataDumpStarts(IfaceCodeDataCommand):
    """Dump function starts: `codedata dump starts`"""
    def execute(self, args: str) -> None:
        if self.codedata is None:
            raise IfaceExecutionError("No code data context")
        optr = self.status.fileoptr if self.status else io.StringIO()
        self.codedata.dumpFunctionStarts(optr)


class IfcCodeDataDumpUnlinked(IfaceCodeDataCommand):
    """Dump unlinked starts: `codedata dump unlinked`"""
    def execute(self, args: str) -> None:
        if self.codedata is None:
            raise IfaceExecutionError("No code data context")
        optr = self.status.fileoptr if self.status else io.StringIO()
        self.codedata.dumpUnlinked(optr)


class IfcCodeDataDumpTargetHits(IfaceCodeDataCommand):
    """Dump target hits: `codedata dump targethits`"""
    def execute(self, args: str) -> None:
        if self.codedata is None:
            raise IfaceExecutionError("No code data context")
        optr = self.status.fileoptr if self.status else io.StringIO()
        self.codedata.dumpTargetHits(optr)


# =========================================================================
# IfaceCodeDataCapability
# =========================================================================

class IfaceCodeDataCapability(IfaceCapability):
    """Interface capability for code/data analysis commands."""

    _instance: Optional[IfaceCodeDataCapability] = None

    def __init__(self) -> None:
        super().__init__("codedata")

    @classmethod
    def getInstance(cls) -> IfaceCodeDataCapability:
        if cls._instance is None:
            cls._instance = IfaceCodeDataCapability()
        return cls._instance

    def registerCommands(self, status: IfaceStatus) -> None:
        status.registerCom(IfcCodeDataInit(), "codedata", "init")
        status.registerCom(IfcCodeDataTarget(), "codedata", "target")
        status.registerCom(IfcCodeDataRun(), "codedata", "run")
        status.registerCom(IfcCodeDataDumpModelHits(), "codedata", "dump", "hits")
        status.registerCom(IfcCodeDataDumpCrossRefs(), "codedata", "dump", "crossrefs")
        status.registerCom(IfcCodeDataDumpStarts(), "codedata", "dump", "starts")
        status.registerCom(IfcCodeDataDumpUnlinked(), "codedata", "dump", "unlinked")
        status.registerCom(IfcCodeDataDumpTargetHits(), "codedata", "dump", "targethits")
