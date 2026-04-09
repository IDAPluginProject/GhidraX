"""
Standalone Architecture shim for the pure-Python decompiler pipeline.

Provides a minimal Architecture-like object that wraps the Lifter's
AddrSpaceManager, builds a default ProtoModel with return register
and effect list, and exposes the contract expected by Heritage,
Action/Rule, and PrintC subsystems.

C++ ref: architecture.hh / architecture.cc (subset)
"""

from __future__ import annotations

from pathlib import Path
import xml.etree.ElementTree as ET
from typing import Callable, List, Optional

from ghidra.core.address import Address, RangeList
from ghidra.arch.userop import UserOpManage
from ghidra.ir.typeop import registerTypeOps
from ghidra.output.printlanguage import PrintLanguageCapability
from ghidra.output.printc import PrintC  # Register default print capability
from ghidra.types.datatype import TypeFactory
from ghidra.transform.action import ActionDatabase


def _build_shim_type_factory(spc_mgr) -> TypeFactory:
    tf = TypeFactory()
    tf.setupCoreTypes()
    code_space = getattr(spc_mgr, '_defaultCodeSpace', None)
    if code_space is not None and hasattr(code_space, 'getAddrSize'):
        ptr_size = code_space.getAddrSize()
        if ptr_size:
            tf._sizeOfPointer = ptr_size
    return tf


def _build_default_proto_model(spc_mgr, glb, target: str | None = None) -> 'ProtoModel':
    """Build a minimal default ProtoModel with return register and effect list.

    For x86-32: EAX (register offset 0, size 4) as return register.
    For x86-64: RAX (register offset 0, size 8) as return register.
    This enables Heritage's guardReturns() to identify the return register
    and add it as input to RETURN ops via characterizeAsOutput().

    Also populates the effect list so that ``Heritage::guardCalls`` can
    distinguish callee-saved (unaffected) from volatile (killedbycall)
    registers, avoiding excessive INDIRECT op creation.

    C++ ref: ``ProtoModel::hasEffect`` → ``lookupEffect``
    """
    from ghidra.fspec.fspec import ProtoModel, ParamListStandard, ParamEntry, EffectRecord
    model_name = "__fastcall"
    # Determine register space and pointer size
    reg_space = None
    ram_space = None
    ptr_size = 4
    try:
        reg_space = spc_mgr.getSpaceByName("register")
    except Exception:
        pass
    try:
        ram_space = spc_mgr.getSpaceByName("ram")
    except Exception:
        pass
    code_space = getattr(spc_mgr, '_defaultCodeSpace', None)
    if code_space is not None and hasattr(code_space, 'getAddrSize'):
        ptr_size = code_space.getAddrSize()
    ret_size = 8 if ptr_size == 8 else 4
    is_64 = (ptr_size == 8)
    if not is_64:
        # Match x86win.cspec default_proto for the current PE-based workflow.
        model_name = "__stdcall"
    model = ProtoModel(model_name, glb)

    # Build output parameter list
    out_list = ParamListStandard()
    if reg_space is not None:
        if is_64:
            # x86-64 Windows __fastcall (from x86-64-win.cspec):
            #   <pentry minsize="4" maxsize="8" metatype="float"><register name="XMM0_Qa"/></pentry>
            #   <pentry minsize="1" maxsize="8"><register name="RAX"/></pentry>
            entry_xmm0 = ParamEntry(0)
            entry_xmm0.spaceid = reg_space
            entry_xmm0.addressbase = 0x1200  # XMM0_Qa offset in x86-64 SLEIGH register space
            entry_xmm0.size = 8
            entry_xmm0.minsize = 4
            entry_xmm0.alignment = 0
            entry_xmm0.flags = ParamEntry.first_storage | ParamEntry.force_left_justify
            out_list.addEntry(entry_xmm0)
            entry_rax = ParamEntry(0)
            entry_rax.spaceid = reg_space
            entry_rax.addressbase = 0  # RAX offset
            entry_rax.size = 8
            entry_rax.minsize = 1
            entry_rax.alignment = 0
            entry_rax.flags = ParamEntry.first_storage | ParamEntry.force_left_justify
            out_list.addEntry(entry_rax)
        else:
            # x86-32 Windows default proto (from x86win.cspec):
            #   <pentry minsize="4" maxsize="10" metatype="float"><register name="ST0"/></pentry>
            #   <pentry minsize="1" maxsize="4"><register name="EAX"/></pentry>
            #   <pentry minsize="5" maxsize="8"><addr space="join" piece1="EDX" piece2="EAX"/></pentry>
            entry_st0 = ParamEntry(0)
            entry_st0.spaceid = reg_space
            entry_st0.addressbase = 0x1100  # ST0 offset in x86-32 SLEIGH register space
            entry_st0.size = 10
            entry_st0.minsize = 4
            entry_st0.alignment = 0
            entry_st0.flags = ParamEntry.first_storage | ParamEntry.force_left_justify
            out_list.addEntry(entry_st0)
            entry_eax = ParamEntry(0)
            entry_eax.spaceid = reg_space
            entry_eax.addressbase = 0  # EAX offset
            entry_eax.size = 4
            entry_eax.minsize = 1
            entry_eax.alignment = 0
            entry_eax.flags = ParamEntry.first_storage | ParamEntry.force_left_justify
            out_list.addEntry(entry_eax)
            # EDX (part of EDX:EAX join for 5-8 byte returns)
            entry_edx = ParamEntry(0)
            entry_edx.spaceid = reg_space
            entry_edx.addressbase = 0x8  # EDX offset
            entry_edx.size = 4
            entry_edx.minsize = 4
            entry_edx.alignment = 0
            entry_edx.flags = ParamEntry.force_left_justify
            out_list.addEntry(entry_edx)
    model.output = out_list
    if model.output.entry:
        maxgroup = max(
            (entry.getAllGroups()[-1] if entry.getAllGroups() else entry.getGroup())
            for entry in model.output.entry
        ) + 1
        model.output.numgroup = maxgroup
        model.output.resourceStart = [maxgroup]
    # Build input parameter list from cspec
    in_list = ParamListStandard()
    stack_space = getattr(spc_mgr, '_stackSpace', None)
    if reg_space is not None:
        if is_64:
            # x86-64 Windows __fastcall input params (from x86-64-win.cspec)
            # Group 0: XMM0_Qa (float) / RCX (int)
            # Group 1: XMM1_Qa (float) / RDX (int)
            # Group 2: XMM2_Qa (float) / R8 (int)
            # Group 3: XMM3_Qa (float) / R9 (int)
            # Register offsets: RCX=0x08, RDX=0x10, R8=0x80, R9=0x88
            # XMM0_Qa=0x1200, XMM1_Qa=0x1240, XMM2_Qa=0x1280, XMM3_Qa=0x12c0
            input_regs = [
                # (group, offset, size, minsize, is_float)
                (0, 0x1200, 8, 4, True),   # XMM0_Qa
                (0, 0x08,   8, 1, False),  # RCX
                (1, 0x1240, 8, 4, True),   # XMM1_Qa
                (1, 0x10,   8, 1, False),  # RDX
                (2, 0x1280, 8, 4, True),   # XMM2_Qa
                (2, 0x80,   8, 1, False),  # R8
                (3, 0x12c0, 8, 4, True),   # XMM3_Qa
                (3, 0x88,   8, 1, False),  # R9
            ]
            for grp, off, sz, minsz, is_float in input_regs:
                e = ParamEntry(grp)
                e.spaceid = reg_space
                e.addressbase = off
                e.size = sz
                e.minsize = minsz
                e.alignment = 0
                e.flags = ParamEntry.is_grouped | ParamEntry.first_storage | ParamEntry.force_left_justify
                if is_float:
                    from ghidra.types.datatype import TypeClass
                    e.type = TypeClass.TYPECLASS_FLOAT
                in_list.addEntry(e)
            if stack_space is not None:
                e = ParamEntry(4)
                e.spaceid = stack_space
                e.addressbase = 40
                e.size = 500
                e.minsize = 1
                e.alignment = 8
                e.numslots = 500 // 8
                e.flags = ParamEntry.first_storage | ParamEntry.force_left_justify
                in_list.addEntry(e)
        else:
            # x86-32 Windows default proto: all params are on the stack.
            #   <pentry minsize="1" maxsize="500" align="4">
            #     <addr offset="4" space="stack"/>
            #   </pentry>
            if stack_space is not None:
                e = ParamEntry(0)
                e.spaceid = stack_space
                e.addressbase = 4  # after return address
                e.size = 500
                e.minsize = 1
                e.alignment = 4
                e.numslots = 500 // 4
                e.flags = ParamEntry.first_storage | ParamEntry.force_left_justify
                in_list.addEntry(e)
    model.input = in_list
    if model.input.entry:
        maxgroup = max(
            (entry.getAllGroups()[-1] if entry.getAllGroups() else entry.getGroup())
            for entry in model.input.entry
        ) + 1
        model.input.numgroup = maxgroup
        model.input.resourceStart = [maxgroup]
    if stack_space is not None:
        model.input.spacebase = stack_space
    model.input.calcDelay()
    if stack_space is not None:
        model._stackgrowsnegative = stack_space.stackGrowsNegative()
        model.input.getRangeList(stack_space, model.defaultParamRange)
        model._defaultLocalRange()
        if model.defaultParamRange.empty():
            model._defaultParamRange()
        model.stackshift = 8 if is_64 else 4
    if not is_64:
        model.setExtraPop(ProtoModel.extrapop_unknown)

    # Build effect list from cspec
    if reg_space is not None:
        effects = []
        if is_64:
            # x86-64 Windows __fastcall (from x86-64-win.cspec)
            # Register offsets from x86-64.sla get_registers():
            # RAX=0x00/8, RCX=0x08/8, RDX=0x10/8, RBX=0x18/8, RSP=0x20/8,
            # RBP=0x28/8, RSI=0x30/8, RDI=0x38/8, R8=0x80/8, R9=0x88/8,
            # R10=0x90/8, R11=0x98/8, R12=0xa0/8, R13=0xa8/8, R14=0xb0/8,
            # R15=0xb8/8, DF=0x20a/1, GS_OFFSET=0x118/8, XMM0=0x1200/16,
            # XMM6-15 at 0x1380,0x13c0,0x1400,0x1440,0x1480,0x14c0,0x1500,
            # 0x1540,0x1580,0x15c0 (each 16 bytes)

            # unaffected (callee-saved)
            for off, sz in (
                (0x18, 8),   # RBX
                (0x28, 8),   # RBP
                (0x38, 8),   # RDI
                (0x30, 8),   # RSI
                (0x20, 8),   # RSP
                (0xa0, 8),   # R12
                (0xa8, 8),   # R13
                (0xb0, 8),   # R14
                (0xb8, 8),   # R15
                (0x20a, 1),  # DF
                (0x118, 8),  # GS_OFFSET
                (0x1380, 16),  # XMM6
                (0x13c0, 16),  # XMM7
                (0x1400, 16),  # XMM8
                (0x1440, 16),  # XMM9
                (0x1480, 16),  # XMM10
                (0x14c0, 16),  # XMM11
                (0x1500, 16),  # XMM12
                (0x1540, 16),  # XMM13
                (0x1580, 16),  # XMM14
                (0x15c0, 16),  # XMM15
            ):
                effects.append(EffectRecord(Address(reg_space, off), sz, EffectRecord.unaffected))
            # killedbycall (volatile): RAX, XMM0
            for off, sz in ((0x00, 8), (0x1200, 16)):
                effects.append(EffectRecord(Address(reg_space, off), sz, EffectRecord.killedbycall))
        else:
            # x86-32 Windows __stdcall effect list (from x86win.cspec)
            # unaffected: ram[0:4], ESP=0x10, EBP=0x14, ESI=0x18,
            # EDI=0x1c, EBX=0xc, DF=0x20a, FS_OFFSET=0x110
            if ram_space is not None:
                effects.append(EffectRecord(Address(ram_space, 0), 4, EffectRecord.unaffected))
            for off, sz in (
                (0x10, 4),
                (0x14, 4),
                (0x18, 4),
                (0x1c, 4),
                (0x0c, 4),
                (0x20a, 1),
                (0x110, 4),
            ):
                effects.append(EffectRecord(Address(reg_space, off), sz, EffectRecord.unaffected))
            # killedbycall (volatile): ECX=0x4, EDX=0x8, ST0=0x1100, ST1=0x1110.
            # Keep EAX explicit until the shim derives output killedbycall
            # directly from ParamListStandard metadata like native does.
            for off, sz in ((0x00, 4), (0x04, 4), (0x08, 4), (0x1100, 10), (0x1110, 10)):
                effects.append(EffectRecord(Address(reg_space, off), sz, EffectRecord.killedbycall))
        if stack_space is not None:
            # Match the x86 compiler specs, which model the caller return
            # address as living at stack[0] on function entry.
            effects.append(EffectRecord(Address(stack_space, 0), ret_size, EffectRecord.return_address))
        # Sort by offset for lookupEffect binary search. Keep both attribute
        # names in sync because different ports still read either
        # ``effectlist`` or ``_effectlist``.
        effects.sort(key=lambda e: e.getAddress().getOffset())
        model.effectlist = effects
        model._effectlist = effects

    if is_64:
        model.extrapop = 8
    else:
        model.extrapop = ProtoModel.extrapop_unknown
    return model


class _TranslateShim:
    """Minimal Translate-like shim backed by the native SLEIGH binding."""

    def __init__(self, spc_mgr) -> None:
        self._spc_mgr = spc_mgr
        self._native = getattr(spc_mgr, '_native', None)

    def getRegisterName(self, base, off: int, size: int) -> str:
        if self._native is None:
            return ""
        spc_name = base.getName() if hasattr(base, 'getName') else str(base) if base else "register"
        try:
            return self._native.get_register_name(spc_name, off, size)
        except Exception:
            return ""

    def oneInstruction(self, emit, addr: Address) -> int:
        """Decode one instruction and stream its p-code to *emit*."""
        if self._native is None:
            return 0

        from ghidra.core.opcodes import OpCode
        from ghidra.core.pcoderaw import VarnodeData

        result = self._native.pcode(addr.getOffset())
        for native_op in result.ops:
            outvar = None
            if native_op.has_output:
                out = native_op.output
                outvar = VarnodeData(self._spc_mgr.getSpaceByName(out.space), out.offset, out.size)

            vars_ = []
            for inp in native_op.inputs:
                vars_.append(VarnodeData(self._spc_mgr.getSpaceByName(inp.space), inp.offset, inp.size))

            emit.dump(addr, OpCode(native_op.opcode), outvar, vars_, len(vars_))
        return result.length


class ArchitectureStandalone:
    """Minimal Architecture-like object for Heritage and Action pipeline.

    Heritage needs Architecture to enumerate address spaces via
    numSpaces()/getSpace(). The Action pipeline also needs printMessage(),
    clearAnalysis(), getStackSpace(), and a context attribute.
    This shim wraps the Lifter's AddrSpaceManager.
    """

    def __init__(self, spc_mgr, target: str | None = None, sla_path: str | None = None) -> None:
        self._spc_mgr = spc_mgr
        self.context = None  # No tracked context by default
        self.types = _build_shim_type_factory(spc_mgr)
        self.types.glb = self
        self.analyze_for_loops = True
        self.nan_ignore_all = False
        self.nan_ignore_compare = True
        self.alias_block_level = 2
        self.cpool = None
        self._unique_base: int = 0x10000000
        self._errors: List[str] = []
        self.trim_recurse_max = 5
        self.max_implied_ref = 2
        self.max_term_duplication = 2
        self.max_instructions = 100000
        self.flowoptions = 0x20
        self.extra_pop = 0
        self.commentdb = None
        self.loader = None
        self.pcodeinjectlib = None
        self.inst = []
        self.lanerecords = []
        self.splitrecords = []
        self.allacts = ActionDatabase()
        self.userops = UserOpManage()
        self.print_ = PrintLanguageCapability.getDefault().buildLanguage(self)
        self.translate = _TranslateShim(spc_mgr)
        self._restart_rebuilder: Optional[Callable] = None
        self.inst = registerTypeOps(self.types, self.translate)
        self._load_laned_registers(sla_path)
        self.nohighptr = RangeList()
        # Create a symbol database with a global scope
        from ghidra.database.database import Database
        self.symboltab = Database(self)
        self.symboltab.createGlobalScope("global")
        global_scope = self.symboltab.getGlobalScope()
        default_data = self.getDefaultDataSpace()
        if global_scope is not None and default_data is not None:
            self.symboltab.addRange(global_scope, default_data, 0, default_data.getHighest())
        # Build a minimal default prototype model with return register info
        self.defaultfp = _build_default_proto_model(spc_mgr, self, target)
        self.evalfp_current = None
        self.evalfp_called = None
        self.userops.initialize(self)
        if self.print_ is not None and hasattr(self.print_, "initializeFromArchitecture"):
            self.print_.initializeFromArchitecture()

    def _load_laned_registers(self, sla_path: str | None) -> None:
        if not sla_path:
            return
        pspec_path = Path(sla_path).with_suffix(".pspec")
        if not pspec_path.is_file():
            return
        native = getattr(self._spc_mgr, "_native", None)
        if native is None or not hasattr(native, "get_registers"):
            return
        try:
            regs = native.get_registers()
            root = ET.parse(pspec_path).getroot()
        except Exception:
            return

        from ghidra.transform.transform import LanedRegister

        mask_list: list[int] = []
        for reg_elem in root.findall(".//register_data/register"):
            lane_sizes = reg_elem.get("vector_lane_sizes", "")
            if not lane_sizes:
                continue
            reg_name = reg_elem.get("name", "")
            reg_info = regs.get(reg_name)
            if reg_info is None:
                continue
            size = int(reg_info[2])
            laned_register = LanedRegister()
            laned_register.parseSizes(size, lane_sizes)
            size_index = laned_register.getWholeSize()
            while len(mask_list) <= size_index:
                mask_list.append(0)
            mask_list[size_index] |= laned_register.getSizeBitMask()

        self.lanerecords = [
            LanedRegister(size, mask)
            for size, mask in enumerate(mask_list)
            if mask != 0
        ]

    def numSpaces(self) -> int:
        return self._spc_mgr.numSpaces()

    def getSpace(self, i):
        return self._spc_mgr.getSpaceByIndex(i)

    def getConstantSpace(self):
        return self._spc_mgr._constantSpace

    def getUniqueSpace(self):
        return self._spc_mgr._uniqueSpace

    def getUniqueBase(self) -> int:
        return self._unique_base

    def setUniqueBase(self, val: int) -> None:
        if val > self._unique_base:
            self._unique_base = val

    def getSpaceByName(self, name: str):
        return self._spc_mgr.getSpaceByName(name)

    def getDefaultCodeSpace(self):
        return self._spc_mgr._defaultCodeSpace

    def getDefaultDataSpace(self):
        return self._spc_mgr._defaultDataSpace

    def getPrintLanguage(self):
        return self.print_

    def getJoinSpace(self):
        return getattr(self._spc_mgr, '_joinSpace', None)

    def getIopSpace(self):
        return getattr(self._spc_mgr, '_iopSpace', None)

    def getFspecSpace(self):
        return getattr(self._spc_mgr, '_fspecSpace', None)

    def getStackSpace(self):
        """Return the stack space (may be None for raw binaries)."""
        return getattr(self._spc_mgr, '_stackSpace', None)

    def highPtrPossible(self, loc: Address, size: int) -> bool:
        from ghidra.core.space import IPTR_INTERNAL

        if loc.getSpace() is not None and loc.getSpace().getType() == IPTR_INTERNAL:
            return False
        return not self.nohighptr.inRange(loc, size)

    def getLanedRegister(self, loc: Address, size: int):
        for record in self.lanerecords:
            if hasattr(record, "getWholeSize") and record.getWholeSize() == size:
                return record
        return None

    def getMinimumLanedRegisterSize(self) -> int:
        if not self.lanerecords:
            return -1
        first = self.lanerecords[0]
        return first.getWholeSize() if hasattr(first, "getWholeSize") else -1

    def getSpaceBySpacebase(self, loc, size: int):
        """Find the address space associated with a spacebase register.

        Given the Address of a register (e.g. ESP at register:0x10),
        find the spacebase space (e.g. stack) that uses it as its base.

        C++ ref: ``Architecture::getSpaceBySpacebase``
        """
        from ghidra.core.space import IPTR_SPACEBASE
        for i in range(self.numSpaces()):
            spc = self.getSpace(i)
            if spc is None:
                continue
            if spc.getType() != IPTR_SPACEBASE:
                continue
            numbase = spc.numSpacebase() if hasattr(spc, 'numSpacebase') else 0
            for j in range(numbase):
                point = spc.getSpacebase(j)
                if point is None:
                    continue
                p_space = point.space if hasattr(point, 'space') else None
                p_offset = point.offset if hasattr(point, 'offset') else 0
                p_size = point.size if hasattr(point, 'size') else 0
                if p_space is loc.getSpace() and p_offset == loc.getOffset() and p_size == size:
                    return spc
        return None

    def printMessage(self, msg: str) -> None:
        """Collect messages from the action pipeline."""
        self._errors.append(msg)

    def getMessages(self) -> List[str]:
        return list(self._errors)

    def drainMessages(self) -> List[str]:
        msgs = list(self._errors)
        self._errors.clear()
        return msgs

    def setRestartRebuilder(self, rebuilder: Optional[Callable]) -> None:
        self._restart_rebuilder = rebuilder

    def clearAnalysis(self, data) -> None:
        """Called by ActionRestartGroup between restart iterations."""
        rebuilder = self._restart_rebuilder
        if rebuilder is not None and data is not None:
            rebuilder(data)
        elif data is not None and hasattr(data, "clear"):
            data.clear()
        commentdb = getattr(self, "commentdb", None)
        if commentdb is not None and hasattr(commentdb, "clearType") and data is not None and hasattr(data, "getAddress"):
            commentdb.clearType(data.getAddress(), 0x6)
