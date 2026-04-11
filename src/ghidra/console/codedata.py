"""
Corresponds to: codedata.hh / codedata.cc

Code/data analysis module for distinguishing code from data in binary images.
Provides disassembly-based analysis, cross-reference tracking, taint propagation,
and target hit detection.
"""

from __future__ import annotations

from typing import Dict, List, Optional, TYPE_CHECKING

from ghidra.arch.loadimage import DataUnavailError, LoadImageSection
from ghidra.console.interface import (
    IfaceData, IfaceCommand, IfaceCapability, IfaceStatus,
    IfaceParseError, IfaceExecutionError,
)
from ghidra.core.error import BadDataError, LowlevelError, UnimplError

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
        if b is None:
            from ghidra.core.address import Address
            b = Address()
        self.a = a
        self.b = b

    def __lt__(self, other: AddrLink) -> bool:
        if self.a != other.a:
            return self.a < other.a
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
        self._targetoffsets.add(addr.getOffset())

    def dump(self, addr, opc: int, outvar, invars, isize: int) -> None:
        """P-code emit callback — tracks branches, calls, and target hits."""
        from ghidra.core.address import Address
        from ghidra.core.opcodes import OpCode

        self._lastop = opc
        if opc in (OpCode.CPUI_CALL, OpCode.CPUI_BRANCH, OpCode.CPUI_CBRANCH):
            if opc == OpCode.CPUI_CALL:
                self._hascall = True
            self._jumpaddr.append(Address(invars[0].space, invars[0].offset))
        elif opc in (OpCode.CPUI_COPY, OpCode.CPUI_BRANCHIND, OpCode.CPUI_CALLIND):
            if invars[0].offset in self._targetoffsets:
                self._hitsaddress = True
                self._targethit = invars[0].offset
        elif opc == OpCode.CPUI_LOAD:
            if invars[1].offset in self._targetoffsets:
                self._hitsaddress = True
                self._targethit = invars[1].offset

    def disassemble(self, addr, res: DisassemblyResult) -> None:
        """Disassemble a single instruction at the given address."""
        from ghidra.core.opcodes import OpCode

        self._jumpaddr.clear()
        self._lastop = OpCode.CPUI_COPY
        self._hascall = False
        self._hitsaddress = False
        res.flags = 0

        try:
            res.length = self._trans.oneInstruction(self, addr)
        except BadDataError:
            res.success = False
            return
        except DataUnavailError:
            res.success = False
            return
        except UnimplError as err:
            res.length = err.instruction_length

        res.success = True
        if self._hascall:
            res.flags |= CodeUnit.call
        if self._hitsaddress:
            res.flags |= CodeUnit.targethit
            res.targethit = self._targethit

        if self._lastop in (OpCode.CPUI_BRANCH, OpCode.CPUI_BRANCHIND):
            if self._hitsaddress:
                res.flags |= CodeUnit.thunkhit
        elif self._lastop == OpCode.CPUI_RETURN:
            pass  # No fallthrough
        else:
            res.flags |= CodeUnit.fallthru

        lastaddr = addr + res.length
        for ja in self._jumpaddr:
            if ja == lastaddr:
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
        from ghidra.core.address import RangeList

        super().__init__()
        self.alignment: int = 1
        self.glb: Optional[Architecture] = None
        self.disengine: DisassemblyEngine = DisassemblyEngine()
        self.modelhits = RangeList()
        self.codeunit: Dict = {}  # Address -> CodeUnit (ordered by address)
        self.fromto_crossref: Dict = {}  # AddrLink -> flags
        self.tofrom_crossref: Dict = {}  # AddrLink -> flags
        self.taintlist: List = []
        self.unlinkedstarts: List = []
        self.targethits: List[TargetHit] = []
        self.targets: Dict = {}  # Address -> TargetFeature

    def __del__(self) -> None:
        pass

    def init(self, glb) -> None:
        """Initialize analysis with an Architecture."""
        self.glb = glb
        self.disengine.init(glb.translate)
        self.alignment = glb.translate.getAlignment()
        self.modelhits.clear()
        self.codeunit.clear()
        self.fromto_crossref.clear()
        self.tofrom_crossref.clear()
        self.taintlist.clear()
        self.unlinkedstarts.clear()
        self.targethits.clear()
        self.targets.clear()

    def pushTaintAddress(self, addr) -> None:
        ordered = sorted(self.codeunit)
        index = 0
        while index < len(ordered) and ordered[index] <= addr:
            index += 1
        if index == 0:
            return
        startaddr = ordered[index - 1]
        cu = self.codeunit[startaddr]
        if startaddr.getOffset() + cu.size - 1 < addr.getOffset():
            return
        if (cu.flags & CodeUnit.notcode) != 0:
            return
        self.taintlist.append(startaddr)

    def processTaint(self) -> None:
        startaddr = self.taintlist.pop()
        cu = self.codeunit[startaddr]
        cu.flags |= CodeUnit.notcode
        endaddr = startaddr + cu.size

        ordered = sorted(self.codeunit)
        index = ordered.index(startaddr)
        if index != 0:
            prevaddr = ordered[index - 1]
            cu2 = self.codeunit[prevaddr]
            if (cu2.flags & (CodeUnit.fallthru & CodeUnit.notcode)) == CodeUnit.fallthru:
                addr2 = prevaddr + cu.size
                if addr2 == startaddr:
                    self.taintlist.append(prevaddr)

        startlink = AddrLink(startaddr)
        endlink = AddrLink(endaddr)
        delete_from = [key for key in sorted(self.fromto_crossref) if not (key < startlink) and key < endlink]
        for key in delete_from:
            del self.fromto_crossref[key]

        delete_to = [key for key in sorted(self.tofrom_crossref) if not (key < startlink) and key < endlink]
        for key in delete_to:
            self.pushTaintAddress(key.b)
            del self.tofrom_crossref[key]

    def commitCodeVec(self, addr, codevec, fromto_vec):
        curaddr = addr
        for cu in codevec:
            self.codeunit[curaddr] = cu
            curaddr = curaddr + cu.size
        for fromto, flags in sorted(fromto_vec.items()):
            self.fromto_crossref[fromto] = flags
            self.tofrom_crossref[AddrLink(fromto.b, fromto.a)] = flags
        return curaddr

    def clearCrossRefs(self, addr, endaddr) -> None:
        startlink = AddrLink(addr)
        endlink = AddrLink(endaddr)
        delete_from = [key for key in sorted(self.fromto_crossref) if not (key < startlink) and key < endlink]
        for fromto in delete_from:
            tofrom = AddrLink(fromto.b, fromto.a)
            if tofrom in self.tofrom_crossref:
                del self.tofrom_crossref[tofrom]
        for fromto in delete_from:
            del self.fromto_crossref[fromto]

    def clearCodeUnits(self, addr, endaddr) -> None:
        delete_units = [key for key in sorted(self.codeunit) if not (key < addr) and key < endaddr]
        for key in delete_units:
            del self.codeunit[key]
        self.clearCrossRefs(addr, endaddr)

    def addTarget(self, name: str, addr, mask: int) -> None:
        """Add a target thunk to search for."""
        feat = TargetFeature(name, mask)
        self.targets[addr] = feat
        self.disengine.addTarget(addr)

    def getNumTargets(self) -> int:
        return len(self.targets)

    def getTargetHits(self) -> List[TargetHit]:
        return self.targethits

    def disassembleBlock(self, addr, endaddr):
        disresult = DisassemblyResult()
        codevec = []
        fromto_vec = {}
        flowin = False
        hardend = False

        curaddr = addr
        ordered = sorted(self.codeunit)
        iter_index = 0
        while iter_index < len(ordered) and ordered[iter_index] < addr:
            iter_index += 1

        if iter_index != len(ordered):
            lastaddr = ordered[iter_index]
            if endaddr < lastaddr:
                lastaddr = endaddr
                hardend = True
        else:
            lastaddr = endaddr
            hardend = True

        while True:
            self.disengine.disassemble(curaddr, disresult)
            codevec.append(CodeUnit())
            if not disresult.success:
                codevec[-1].flags = CodeUnit.notcode
                codevec[-1].size = 1
                curaddr = curaddr + 1
                break
            if (disresult.flags & CodeUnit.jump) != 0:
                fromto_vec[AddrLink(curaddr, disresult.jumpaddress)] = disresult.flags
            codevec[-1].flags = disresult.flags
            codevec[-1].size = disresult.length
            curaddr = curaddr + disresult.length
            while lastaddr < curaddr:
                if (not hardend) and ((self.codeunit[ordered[iter_index]].flags & CodeUnit.notcode) != 0):
                    if self.codeunit[ordered[iter_index]].size == 1:
                        del self.codeunit[ordered[iter_index]]
                        ordered = sorted(self.codeunit)
                        if iter_index != len(ordered):
                            lastaddr = ordered[iter_index]
                            if endaddr < lastaddr:
                                lastaddr = endaddr
                                hardend = True
                        else:
                            lastaddr = endaddr
                            hardend = True
                    else:
                        disresult.success = False
                        flowin = True
                        break
                else:
                    disresult.success = False
                    break
            if not disresult.success:
                break
            if curaddr == lastaddr:
                if (self.codeunit[ordered[iter_index]].flags & CodeUnit.notcode) != 0:
                    flowin = True
                    break
            if ((disresult.flags & CodeUnit.fallthru) == 0) or (curaddr == lastaddr):
                return self.commitCodeVec(addr, codevec, fromto_vec)

        cu = self.codeunit.setdefault(addr, CodeUnit())
        cu.flags = CodeUnit.notcode
        if hardend and (lastaddr < curaddr):
            curaddr = lastaddr
        wholesize = curaddr.getOffset() - addr.getOffset()
        if (not flowin) and (wholesize < 10):
            wholesize = 1
        cu.size = wholesize
        return addr + cu.size

    def disassembleRange(self, rangeobj) -> None:
        addr = rangeobj.getFirstAddr()
        lastaddr = rangeobj.getLastAddr()
        while addr <= lastaddr:
            addr = self.disassembleBlock(addr, lastaddr)

    def disassembleRangeList(self, rangelist) -> None:
        for rangeobj in rangelist:
            self.disassembleRange(rangeobj)

    def findNotCodeUnits(self) -> None:
        for addr, cu in sorted(self.codeunit.items()):
            if (cu.flags & CodeUnit.notcode) != 0:
                self.taintlist.append(addr)
        while self.taintlist:
            self.processTaint()

    def clearHitBy(self) -> None:
        """Clear all hit_by flags from all code units."""
        mask = ~(CodeUnit.hit_by_fallthru | CodeUnit.hit_by_jump | CodeUnit.hit_by_call)
        for cu in self.codeunit.values():
            cu.flags &= mask

    def markFallthruHits(self) -> None:
        """Mark every code unit that has another code unit fall into it."""
        from ghidra.core.address import Address

        fallthru_addr = Address()
        for addr, cu in sorted(self.codeunit.items()):
            if cu.flags & CodeUnit.notcode:
                continue
            if fallthru_addr == addr:
                cu.flags |= CodeUnit.hit_by_fallthru
            if cu.flags & CodeUnit.fallthru:
                fallthru_addr = addr + cu.size

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

    def addTargetHit(self, codeaddr, targethit: int) -> None:
        from ghidra.core.address import Address

        funcstart = self.findFunctionStart(codeaddr)
        if funcstart is None:
            funcstart = Address()
        thunkaddr = Address(self.glb.translate.getDefaultCodeSpace(), targethit)
        titer = self.targets.get(thunkaddr)
        if titer is None:
            raise LowlevelError("Found thunk without a feature mask")
        self.targethits.append(TargetHit(funcstart, codeaddr, thunkaddr, titer.featuremask))

    def resolveThunkHit(self, codeaddr, targethit: int) -> None:
        startlink = AddrLink(codeaddr)
        endlink = AddrLink(codeaddr + 1)
        for link in [key for key in sorted(self.tofrom_crossref) if not (key < startlink) and key < endlink]:
            flags = self.tofrom_crossref[link]
            if (flags & CodeUnit.call) != 0:
                self.addTargetHit(link.b, targethit)

    def findUnlinked(self) -> None:
        """Find all code units with no jump/call/fallthru to them."""
        for addr, cu in sorted(self.codeunit.items()):
            check = (CodeUnit.hit_by_fallthru | CodeUnit.hit_by_jump |
                     CodeUnit.hit_by_call | CodeUnit.notcode | CodeUnit.errantstart)
            if (cu.flags & check) == 0:
                self.unlinkedstarts.append(addr)
            if (cu.flags & (CodeUnit.targethit | CodeUnit.notcode)) == CodeUnit.targethit:
                res = DisassemblyResult()
                self.disengine.disassemble(addr, res)
                if (cu.flags & CodeUnit.thunkhit) != 0:
                    self.resolveThunkHit(addr, res.targethit)
                else:
                    self.addTargetHit(addr, res.targethit)

    def checkErrantStart(self, iteraddr) -> bool:
        count = 0
        ordered = sorted(self.codeunit)
        try:
            index = ordered.index(iteraddr)
        except ValueError:
            return False
        while count < 1000:
            cu = self.codeunit[ordered[index]]
            if (cu.flags & (CodeUnit.hit_by_jump | CodeUnit.hit_by_call)) != 0:
                return False
            if (cu.flags & CodeUnit.hit_by_fallthru) == 0:
                cu.flags |= CodeUnit.errantstart
                return True
            if index == 0:
                return False
            index -= 1
            count += 1
        return False

    def repairJump(self, addr, maxcount: int) -> bool:
        disresult = DisassemblyResult()
        codevec = []
        fromto_vec = {}
        curaddr = addr
        ordered = sorted(self.codeunit)
        iter_index = 0
        count = 0

        while iter_index < len(ordered) and ordered[iter_index] < addr:
            iter_index += 1
        if iter_index == len(ordered):
            return False

        while True:
            count += 1
            if count >= maxcount:
                return False
            while ordered[iter_index] < curaddr:
                iter_index += 1
                if iter_index == len(ordered):
                    return False
            if curaddr == ordered[iter_index]:
                break
            self.disengine.disassemble(curaddr, disresult)
            if not disresult.success:
                return False
            codevec.append(CodeUnit())
            if (disresult.flags & CodeUnit.jump) != 0:
                fromto_vec[AddrLink(curaddr, disresult.jumpaddress)] = disresult.flags
            codevec[-1].flags = disresult.flags
            codevec[-1].size = disresult.length
            curaddr = curaddr + disresult.length

        self.clearCodeUnits(addr, curaddr)
        self.commitCodeVec(addr, codevec, fromto_vec)
        return True

    def findOffCut(self) -> None:
        ordered_links = sorted(self.tofrom_crossref)
        index = 0
        while index < len(ordered_links):
            addrlink = ordered_links[index]
            addr = addrlink.a
            ordered_units = sorted(self.codeunit)
            citer_index = 0
            while citer_index < len(ordered_units) and ordered_units[citer_index] < addr:
                citer_index += 1
            if citer_index != len(ordered_units) and ordered_units[citer_index] == addr:
                cu = self.codeunit[ordered_units[citer_index]]
                if ((cu.flags & (CodeUnit.hit_by_fallthru | CodeUnit.hit_by_call)) ==
                        (CodeUnit.hit_by_fallthru | CodeUnit.hit_by_call) and citer_index != 0):
                    self.checkErrantStart(ordered_units[citer_index - 1])
                index += 1
                continue
            if citer_index == 0:
                index += 1
                continue
            citer_index -= 1
            if ordered_units[citer_index] == addr:
                index += 1
                continue
            endaddr = ordered_units[citer_index] + self.codeunit[ordered_units[citer_index]].size
            if endaddr <= addr:
                index += 1
                continue
            if not self.checkErrantStart(ordered_units[citer_index]):
                index += 1
                continue
            self.repairJump(addr, 10)
            ordered_links = sorted(self.tofrom_crossref)
            index = 0
            while index < len(ordered_links) and not (addrlink < ordered_links[index]):
                index += 1

    def findFunctionStart(self, addr):
        """Find the starting address of a function containing addr."""
        from ghidra.core.address import Address

        startlink = AddrLink(addr)
        ordered = sorted(self.tofrom_crossref)
        index = 0
        while index < len(ordered) and ordered[index] < startlink:
            index += 1
        while index != 0:
            index -= 1
            link = ordered[index]
            flags = self.tofrom_crossref[link]
            if (flags & CodeUnit.call) != 0:
                return link.a
        return Address()

    def dumpModelHits(self, s) -> None:
        """Dump model hit ranges."""
        ranges = list(self.modelhits)
        for index, rng in enumerate(ranges):
            off = rng.getFirst()
            endoff = rng.getLast()
            s.write(f"0x{off:x} 0x{endoff:x}")
            if index + 1 < len(ranges):
                nextoff = ranges[index + 1].getFirst()
                s.write(f" {nextoff - endoff}")
            s.write("\n")

    def dumpCrossRefs(self, s) -> None:
        """Dump cross-references."""
        for link, flags in sorted(self.fromto_crossref.items()):
            line = f"0x{link.a.getOffset():x} -> 0x{link.b.getOffset():x}"
            if flags & CodeUnit.call:
                line += " call"
            s.write(line + "\n")

    def dumpFunctionStarts(self, s) -> None:
        """Dump function start addresses."""
        for link, flags in sorted(self.tofrom_crossref.items()):
            if flags & CodeUnit.call:
                s.write(f"0x{link.a.getOffset():x}\n")

    def dumpUnlinked(self, s) -> None:
        """Dump unlinked start addresses."""
        for addr in self.unlinkedstarts:
            s.write(f"0x{addr.getOffset():x}\n")

    def dumpTargetHits(self, s) -> None:
        """Dump target hits."""
        for hit in self.targethits:
            name = self.targets[hit.thunkaddr].name
            if not hit.funcstart.isInvalid():
                s.write(f"{hit.funcstart.getOffset():x} ")
            else:
                s.write("nostart ")
            s.write(f"{hit.codeaddr.getOffset():x} {name}\n")

    def runModel(self) -> None:
        from ghidra.core.address import Address

        loadimage = self.glb.loader
        secinfo = LoadImageSection()
        loadimage.openSectionInfo()
        lastaddr = Address()
        while True:
            moresections = loadimage.getNextSection(secinfo)
            endaddr = secinfo.address + secinfo.size
            if secinfo.size != 0:
                if lastaddr.isInvalid():
                    lastaddr = endaddr
                elif lastaddr < endaddr:
                    lastaddr = endaddr

                if (secinfo.flags & (LoadImageSection.unalloc | LoadImageSection.noload)) == 0:
                    self.modelhits.insertRange(
                        secinfo.address.getSpace(),
                        secinfo.address.getOffset(),
                        endaddr.getOffset(),
                    )
            if not moresections:
                break
        loadimage.closeSectionInfo()
        cu = self.codeunit.setdefault(lastaddr, CodeUnit())
        cu.size = 100
        cu.flags = CodeUnit.notcode
        self.disassembleRangeList(self.modelhits)
        self.findNotCodeUnits()
        self.markFallthruHits()
        self.markCrossHits()
        self.findOffCut()
        self.clearHitBy()
        self.markFallthruHits()
        self.markCrossHits()
        self.findUnlinked()
        self.targethits.sort()


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
        self.dcp = root.getData("decompile")

    def getModule(self) -> str:
        return "codedata"

    def createData(self) -> CodeDataAnalysis:
        return CodeDataAnalysis()


class IfcCodeDataInit(IfaceCodeDataCommand):
    """Initialize code/data analysis: `codedata init`"""
    def execute(self, args: str) -> None:
        self.codedata.init(self.dcp.conf)


class IfcCodeDataTarget(IfaceCodeDataCommand):
    """Add a target for analysis: `codedata target <name>`"""
    def execute(self, args: str) -> None:
        token = args.lstrip()
        if not token:
            raise IfaceParseError("Missing system call name")
        token = token.split()[0]
        irec = []
        loadbfd = self.dcp.conf.loader
        loadbfd.getImportTable(irec)
        for rec in irec:
            if rec.funcname == token:
                self.codedata.addTarget(rec.funcname, rec.thunkaddress, 1)
                return
        self.status.fileoptr.write(f"Unable to find reference to call {token}\n")


class IfcCodeDataRun(IfaceCodeDataCommand):
    """Run code/data analysis: `codedata run`"""
    def execute(self, args: str) -> None:
        self.codedata.runModel()


class IfcCodeDataDumpModelHits(IfaceCodeDataCommand):
    """Dump model hits: `codedata dump hits`"""
    def execute(self, args: str) -> None:
        self.codedata.dumpModelHits(self.status.fileoptr)


class IfcCodeDataDumpCrossRefs(IfaceCodeDataCommand):
    """Dump cross-references: `codedata dump crossrefs`"""
    def execute(self, args: str) -> None:
        self.codedata.dumpCrossRefs(self.status.fileoptr)


class IfcCodeDataDumpStarts(IfaceCodeDataCommand):
    """Dump function starts: `codedata dump starts`"""
    def execute(self, args: str) -> None:
        self.codedata.dumpFunctionStarts(self.status.fileoptr)


class IfcCodeDataDumpUnlinked(IfaceCodeDataCommand):
    """Dump unlinked starts: `codedata dump unlinked`"""
    def execute(self, args: str) -> None:
        self.codedata.dumpUnlinked(self.status.fileoptr)


class IfcCodeDataDumpTargetHits(IfaceCodeDataCommand):
    """Dump target hits: `codedata dump targethits`"""
    def execute(self, args: str) -> None:
        self.codedata.dumpTargetHits(self.status.fileoptr)


# =========================================================================
# IfaceCodeDataCapability
# =========================================================================

class IfaceCodeDataCapability(IfaceCapability):
    """Interface capability for code/data analysis commands."""

    _instance: Optional[IfaceCodeDataCapability] = None

    def __init__(self) -> None:
        super().__init__("codedata")

    def __copy__(self):
        raise TypeError("IfaceCodeDataCapability is non-copyable")

    def __deepcopy__(self, memo):
        raise TypeError("IfaceCodeDataCapability is non-copyable")

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
