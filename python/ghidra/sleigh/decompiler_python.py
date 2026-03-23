"""
Pure-Python replacement for decompiler_native (C++ pybind11).

Provides the same interface as DecompilerNative so the IDA plugin can
switch from C++ to Python by changing a single import line.

Internally uses:
  - sleigh_native (C++ pybind11, SLEIGH only) for instruction lifting
  - Python Lifter → Python Funcdata/Varnode/PcodeOp/Address/AddrSpace
  - Python FlowInfo → basic block construction      [Module 2 - TODO]
  - Python Heritage → SSA form                      [Module 3 - TODO]
  - Python Actions/Rules → optimization             [Module 4 - TODO]
  - Python PrintC → C code generation               [Module 5 - TODO]

Each module can be enabled independently.  When a module is not yet
ready, the pipeline falls back to a simpler output strategy.
"""

from __future__ import annotations

import os
from typing import List, Dict

from ghidra.sleigh.lifter import Lifter
from ghidra.sleigh.arch_map import add_sla_search_dir
from ghidra.core.address import Address
from ghidra.core.opcodes import OpCode
from ghidra.types.datatype import TypeFactory


def _build_shim_type_factory(spc_mgr) -> TypeFactory:
    tf = TypeFactory()
    tf.setupCoreTypes()
    code_space = getattr(spc_mgr, '_defaultCodeSpace', None)
    if code_space is not None and hasattr(code_space, 'getAddrSize'):
        ptr_size = code_space.getAddrSize()
        if ptr_size:
            tf._sizeOfPointer = ptr_size
    return tf


def _build_default_proto_model(spc_mgr, glb) -> 'ProtoModel':
    """Build a minimal default ProtoModel with return register and effect list.

    For x86-32: EAX (register offset 0, size 4) as return register.
    For x86-64: RAX (register offset 0, size 8) as return register.
    This enables Heritage's guardReturns() to identify the return register
    and add it as input to RETURN ops via characterizeAsOutput().

    Also populates the x86-32 cdecl effect list so that
    ``Heritage::guardCalls`` can distinguish callee-saved (unaffected)
    from volatile (killedbycall) registers, avoiding excessive INDIRECT
    op creation.

    C++ ref: ``ProtoModel::hasEffect`` → ``lookupEffect``
    """
    from ghidra.fspec.fspec import ProtoModel, ParamListStandard, ParamEntry, EffectRecord
    model = ProtoModel("__cdecl", glb)
    # Determine register space and pointer size
    reg_space = None
    ptr_size = 4
    try:
        reg_space = spc_mgr.getSpaceByName("register")
    except Exception:
        pass
    code_space = getattr(spc_mgr, '_defaultCodeSpace', None)
    if code_space is not None and hasattr(code_space, 'getAddrSize'):
        ptr_size = code_space.getAddrSize()
    ret_size = 8 if ptr_size == 8 else 4
    # Build output parameter list from cspec output entries.
    # x86-32 cdecl (from x86win.cspec / x86gcc.cspec):
    #   <pentry minsize="4" maxsize="10" metatype="float"><register name="ST0"/></pentry>
    #   <pentry minsize="1" maxsize="4"><register name="EAX"/></pentry>
    #   <pentry minsize="5" maxsize="8"><addr space="join" piece1="EDX" piece2="EAX"/></pentry>
    # For heritage, we need characterizeAsOutput() to return non-zero for both
    # EAX (offset 0) and EDX (offset 8) so guardReturns adds both to RETURN ops.
    # The join entry (EDX:EAX) means EDX is a potential return register piece.
    out_list = ParamListStandard()
    if reg_space is not None:
        # Entry 0: ST0 (float return, register offset from SLEIGH spec)
        entry_st0 = ParamEntry(0)
        entry_st0.spaceid = reg_space
        entry_st0.addressbase = 0x1100  # ST0 offset in x86 SLEIGH register space
        entry_st0.size = 10
        entry_st0.minsize = 4
        entry_st0.alignment = 0
        entry_st0.flags = ParamEntry.first_storage
        out_list.addEntry(entry_st0)
        # Entry 1: EAX (integer return, 1-4 bytes)
        entry_eax = ParamEntry(0)
        entry_eax.spaceid = reg_space
        entry_eax.addressbase = 0  # EAX/RAX offset
        entry_eax.size = ret_size
        entry_eax.minsize = 1
        entry_eax.alignment = 0
        entry_eax.flags = ParamEntry.first_storage
        out_list.addEntry(entry_eax)
        if ptr_size == 4:
            # Entry 2: EDX (part of EDX:EAX join for 5-8 byte returns)
            # Heritage needs to recognize EDX as potential return storage.
            entry_edx = ParamEntry(0)
            entry_edx.spaceid = reg_space
            entry_edx.addressbase = 0x8  # EDX offset
            entry_edx.size = 4
            entry_edx.minsize = 4
            entry_edx.alignment = 0
            entry_edx.flags = 0
            out_list.addEntry(entry_edx)
    model.output = out_list
    # Build empty input parameter list with stack spacebase
    model.input = ParamListStandard()
    stack_space = getattr(spc_mgr, '_stackSpace', None)
    if stack_space is not None:
        model.input.spacebase = stack_space

    # Build x86-32 cdecl effect list (from x86gcc.cspec)
    if reg_space is not None:
        effects = []
        # x86-32 register offsets (from SLEIGH spec)
        # unaffected (callee-saved): ESP=0x10, EBP=0x14, ESI=0x18, EDI=0x1c, EBX=0xc, DF=0x20a
        for off, sz in ((0x10, 4), (0x14, 4), (0x18, 4), (0x1c, 4), (0x0c, 4), (0x20a, 1)):
            effects.append(EffectRecord(Address(reg_space, off), sz, EffectRecord.unaffected))
        # killedbycall (volatile): ECX=0x4, EDX=0x8, ST0=0x1100, ST1=0x1110
        # EAX=0x0 is killedbycall via autoKilledByCall (output killedbycall="true" in cspec)
        for off, sz in ((0x00, 4), (0x04, 4), (0x08, 4), (0x1100, 10), (0x1110, 10)):
            effects.append(EffectRecord(Address(reg_space, off), sz, EffectRecord.killedbycall))
        # Sort by offset for lookupEffect binary search
        effects.sort(key=lambda e: e.getAddress().getOffset())
        model._effectlist = effects

    # x86-32 cdecl: extrapop = 4 (return address popped by caller)
    model.extrapop = 4
    return model


class _ArchitectureShim:
    """Minimal Architecture-like object for Heritage and Action pipeline.

    Heritage needs Architecture to enumerate address spaces via
    numSpaces()/getSpace(). The Action pipeline also needs printMessage(),
    clearAnalysis(), getStackSpace(), and a context attribute.
    This shim wraps the Lifter's AddrSpaceManager.
    """

    def __init__(self, spc_mgr) -> None:
        self._spc_mgr = spc_mgr
        self.context = None  # No tracked context by default
        self.types = _build_shim_type_factory(spc_mgr)
        self.analyze_for_loops = False
        self.nan_ignore_all = False
        self.cpool = None
        self._unique_base: int = 0x10000000
        self._errors: List[str] = []
        self.trim_recurse_max = 5
        # Build a minimal default prototype model with return register info
        self.defaultfp = _build_default_proto_model(spc_mgr, self)
        self.evalfp_current = None
        self.evalfp_called = None

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

    def getJoinSpace(self):
        return getattr(self._spc_mgr, '_joinSpace', None)

    def getIopSpace(self):
        return getattr(self._spc_mgr, '_iopSpace', None)

    def getStackSpace(self):
        """Return the stack space (may be None for raw binaries)."""
        return getattr(self._spc_mgr, '_stackSpace', None)

    def printMessage(self, msg: str) -> None:
        """Collect messages from the action pipeline."""
        self._errors.append(msg)

    def getMessages(self) -> List[str]:
        return list(self._errors)

    def drainMessages(self) -> List[str]:
        msgs = list(self._errors)
        self._errors.clear()
        return msgs

    def clearAnalysis(self, data) -> None:
        """Called by ActionRestartGroup between restart iterations."""
        pass


# =========================================================================
# Register name table for x86 (offset → human-readable name)
# Populated from the SLEIGH spec; this is a fallback for raw output.
# =========================================================================
_X86_32_REG_NAMES: Dict[int, str] = {
    0x00: "EAX", 0x04: "ECX", 0x08: "EDX", 0x0C: "EBX",
    0x10: "ESP", 0x14: "EBP", 0x18: "ESI", 0x1C: "EDI",
    0x200: "CF",
}

_X86_64_REG_NAMES: Dict[int, str] = {
    0x00: "RAX", 0x08: "RCX", 0x10: "RDX", 0x18: "RBX",
    0x20: "RSP", 0x28: "RBP", 0x30: "RSI", 0x38: "RDI",
    0x200: "CF",
}


def _vn_str(vn) -> str:
    """Format a Varnode as a human-readable string."""
    spc = vn.getSpace()
    name = spc.getName()
    off = vn.getAddr().getOffset()
    sz = vn.getSize()

    if name == "const":
        if sz <= 4:
            return f"0x{off & 0xFFFFFFFF:x}"
        return f"0x{off:x}"
    if name == "register":
        # Try to look up a human-readable name
        return f"reg_{off:x}"
    if name == "unique":
        return f"tmp_{off:x}"
    if name == "ram":
        return f"mem[0x{off:x}]"
    return f"{name}[0x{off:x}:{sz}]"


def _op_str(op) -> str:
    """Format a PcodeOp as a C-like statement."""
    opc = op.code()
    out = op.getOut()
    nin = op.numInput()
    ins = [op.getIn(i) for i in range(nin)]
    ins_s = [_vn_str(v) for v in ins if v is not None]

    lhs = _vn_str(out) if out else None

    # Binary ops
    _binop = {
        OpCode.CPUI_INT_ADD: "+", OpCode.CPUI_INT_SUB: "-",
        OpCode.CPUI_INT_MULT: "*", OpCode.CPUI_INT_DIV: "/",
        OpCode.CPUI_INT_SDIV: "s/", OpCode.CPUI_INT_REM: "%",
        OpCode.CPUI_INT_SREM: "s%",
        OpCode.CPUI_INT_AND: "&", OpCode.CPUI_INT_OR: "|",
        OpCode.CPUI_INT_XOR: "^",
        OpCode.CPUI_INT_LEFT: "<<", OpCode.CPUI_INT_RIGHT: ">>",
        OpCode.CPUI_INT_SRIGHT: "s>>",
        OpCode.CPUI_INT_EQUAL: "==", OpCode.CPUI_INT_NOTEQUAL: "!=",
        OpCode.CPUI_INT_LESS: "<", OpCode.CPUI_INT_LESSEQUAL: "<=",
        OpCode.CPUI_INT_SLESS: "s<", OpCode.CPUI_INT_SLESSEQUAL: "s<=",
        OpCode.CPUI_INT_CARRY: "CARRY", OpCode.CPUI_INT_SCARRY: "SCARRY",
        OpCode.CPUI_INT_SBORROW: "SBORROW",
        OpCode.CPUI_BOOL_AND: "&&", OpCode.CPUI_BOOL_OR: "||",
        OpCode.CPUI_BOOL_XOR: "^^",
        OpCode.CPUI_FLOAT_ADD: "f+", OpCode.CPUI_FLOAT_SUB: "f-",
        OpCode.CPUI_FLOAT_MULT: "f*", OpCode.CPUI_FLOAT_DIV: "f/",
        OpCode.CPUI_FLOAT_EQUAL: "f==", OpCode.CPUI_FLOAT_NOTEQUAL: "f!=",
        OpCode.CPUI_FLOAT_LESS: "f<", OpCode.CPUI_FLOAT_LESSEQUAL: "f<=",
        OpCode.CPUI_PIECE: "PIECE",
    }

    # Unary ops
    _unop = {
        OpCode.CPUI_INT_NEGATE: "~", OpCode.CPUI_INT_2COMP: "-",
        OpCode.CPUI_BOOL_NEGATE: "!",
        OpCode.CPUI_FLOAT_NEG: "f-", OpCode.CPUI_FLOAT_ABS: "fabs",
        OpCode.CPUI_FLOAT_SQRT: "fsqrt",
        OpCode.CPUI_POPCOUNT: "POPCOUNT", OpCode.CPUI_LZCOUNT: "LZCOUNT",
    }

    if opc in _binop and len(ins_s) >= 2 and lhs:
        sym = _binop[opc]
        if sym in ("CARRY", "SCARRY", "SBORROW", "PIECE"):
            return f"{lhs} = {sym}({ins_s[0]}, {ins_s[1]})"
        return f"{lhs} = {ins_s[0]} {sym} {ins_s[1]}"

    if opc in _unop and len(ins_s) >= 1 and lhs:
        sym = _unop[opc]
        if sym in ("fabs", "fsqrt", "POPCOUNT", "LZCOUNT"):
            return f"{lhs} = {sym}({ins_s[0]})"
        return f"{lhs} = {sym}{ins_s[0]}"

    if opc == OpCode.CPUI_COPY and lhs and len(ins_s) >= 1:
        return f"{lhs} = {ins_s[0]}"

    if opc == OpCode.CPUI_LOAD and lhs and len(ins_s) >= 2:
        return f"{lhs} = *{ins_s[1]}"

    if opc == OpCode.CPUI_STORE and len(ins_s) >= 3:
        return f"*{ins_s[1]} = {ins_s[2]}"

    if opc == OpCode.CPUI_BRANCH and len(ins_s) >= 1:
        return f"goto {ins_s[0]}"

    if opc == OpCode.CPUI_CBRANCH and len(ins_s) >= 2:
        return f"if ({ins_s[1]}) goto {ins_s[0]}"

    if opc == OpCode.CPUI_BRANCHIND and len(ins_s) >= 1:
        return f"goto *{ins_s[0]}"

    if opc == OpCode.CPUI_CALL and len(ins_s) >= 1:
        args = ", ".join(ins_s[1:])
        return f"CALL {ins_s[0]}({args})"

    if opc == OpCode.CPUI_CALLIND and len(ins_s) >= 1:
        args = ", ".join(ins_s[1:])
        return f"CALLIND *{ins_s[0]}({args})"

    if opc == OpCode.CPUI_RETURN:
        if len(ins_s) >= 2:
            return f"return {ins_s[1]}"
        return "return"

    if opc == OpCode.CPUI_INT_ZEXT and lhs and len(ins_s) >= 1:
        return f"{lhs} = ZEXT({ins_s[0]})"

    if opc == OpCode.CPUI_INT_SEXT and lhs and len(ins_s) >= 1:
        return f"{lhs} = SEXT({ins_s[0]})"

    if opc == OpCode.CPUI_SUBPIECE and lhs and len(ins_s) >= 2:
        return f"{lhs} = SUBPIECE({ins_s[0]}, {ins_s[1]})"

    if opc == OpCode.CPUI_FLOAT_INT2FLOAT and lhs and len(ins_s) >= 1:
        return f"{lhs} = INT2FLOAT({ins_s[0]})"

    if opc == OpCode.CPUI_FLOAT_TRUNC and lhs and len(ins_s) >= 1:
        return f"{lhs} = TRUNC({ins_s[0]})"

    if opc == OpCode.CPUI_FLOAT_NAN and lhs and len(ins_s) >= 1:
        return f"{lhs} = NAN({ins_s[0]})"

    if opc == OpCode.CPUI_FLOAT_FLOAT2FLOAT and lhs and len(ins_s) >= 1:
        return f"{lhs} = FLOAT2FLOAT({ins_s[0]})"

    if opc == OpCode.CPUI_FLOAT_CEIL and lhs and len(ins_s) >= 1:
        return f"{lhs} = CEIL({ins_s[0]})"

    if opc == OpCode.CPUI_FLOAT_FLOOR and lhs and len(ins_s) >= 1:
        return f"{lhs} = FLOOR({ins_s[0]})"

    if opc == OpCode.CPUI_FLOAT_ROUND and lhs and len(ins_s) >= 1:
        return f"{lhs} = ROUND({ins_s[0]})"

    if opc == OpCode.CPUI_PTRADD and lhs and len(ins_s) >= 3:
        return f"{lhs} = PTRADD({ins_s[0]}, {ins_s[1]}, {ins_s[2]})"

    if opc == OpCode.CPUI_PTRSUB and lhs and len(ins_s) >= 2:
        return f"{lhs} = PTRSUB({ins_s[0]}, {ins_s[1]})"

    # Fallback: generic format
    arg_str = ", ".join(ins_s)
    if lhs:
        return f"{lhs} = {opc.name}({arg_str})"
    return f"{opc.name}({arg_str})"


def _split_basic_blocks(fd, lifter=None) -> None:
    """Module 2: Split a single-block Funcdata into proper basic blocks.

    Analyzes PcodeOps for branch/return instructions and splits the
    single basic block created by the Lifter into multiple basic blocks
    at branch boundaries.

    Uses pure Python: Funcdata, PcodeOp, BlockBasic, BlockGraph, Address.
    """
    bblocks = fd.getBasicBlocks()
    if bblocks.getSize() != 1:
        return  # Already split or empty

    old_bb = bblocks.getBlock(0)
    all_ops = list(old_bb.getOpList())
    if not all_ops:
        return

    # Resolved jump tables from lifter (branchind_addr -> [target_addrs])
    jumptables: Dict[int, list] = {}
    if lifter is not None and hasattr(lifter, '_jumptables'):
        jumptables = lifter._jumptables

    # Instruction fall-through map (addr -> addr+length) for x86 overlap handling
    insn_fall_throughs: Dict[int, int] = {}
    if lifter is not None and hasattr(lifter, '_insn_fall_throughs'):
        insn_fall_throughs = lifter._insn_fall_throughs

    # --- Step 0b: Convert BRANCHIND → CALLIND + synthetic RETURN ---
    # C++ FlowInfo::truncateIndirectJump converts unresolved BRANCHIND ops
    # to CALLIND and inserts a synthetic RETURN after them.
    # For resolved jump tables, keep BRANCHIND as-is.
    original_ops = set(id(op) for op in all_ops)  # track original block ops
    new_all_ops = []
    for op in all_ops:
        new_all_ops.append(op)
        if op.code() == OpCode.CPUI_BRANCHIND:
            op_addr = op.getSeqNum().getAddr().getOffset()
            if op_addr in jumptables:
                # Jump table resolved — keep BRANCHIND, don't convert
                continue
            # Convert BRANCHIND → CALLIND
            op.setOpcodeEnum(OpCode.CPUI_CALLIND)
            # Create synthetic RETURN op after the CALLIND
            # Matches C++ FlowInfo::artificialHalt which calls
            # newVarnodeIop → newConstant(sizeof(op), op->getTime())
            ret_op = fd.newOp(1, op.getSeqNum().getAddr())
            ret_op.setOpcodeEnum(OpCode.CPUI_RETURN)
            # Create const varnode matching C++ newVarnodeIop behavior
            uniq = ret_op.getSeqNum().getTime() if hasattr(ret_op.getSeqNum(), 'getTime') else 0
            ret_in = fd.newConstant(4, uniq)
            fd.opSetInput(ret_op, ret_in, 0)
            new_all_ops.append(ret_op)
    all_ops = new_all_ops

    # --- Step 0c: Add trailing RETURN if function doesn't end with terminator ---
    # C++ FlowInfo::artificialHalt adds a synthetic RETURN when flow falls off
    # the end of a function without an explicit return/branch instruction.
    if all_ops:
        last_opc = all_ops[-1].code()
        terminators = {OpCode.CPUI_RETURN, OpCode.CPUI_BRANCH, OpCode.CPUI_CBRANCH,
                       OpCode.CPUI_BRANCHIND, OpCode.CPUI_CALLIND}
        if last_opc not in terminators:
            last_addr = all_ops[-1].getSeqNum().getAddr()
            # Compute the next address after the last instruction
            last_off = last_addr.getOffset()
            # Find the machine instruction length from the last op's address
            # by looking for the next different machine address in ops
            next_off = last_off + 1  # default: 1 byte past last op
            # Try to find the actual instruction end from the lifting context
            # For now, use the address right after last op
            next_addr = Address(last_addr.getSpace(), next_off)
            ret_op = fd.newOp(1, next_addr)
            ret_op.setOpcodeEnum(OpCode.CPUI_RETURN)
            uniq = ret_op.getSeqNum().getTime() if hasattr(ret_op.getSeqNum(), 'getTime') else 0
            ret_in = fd.newConstant(4, uniq)
            fd.opSetInput(ret_op, ret_in, 0)
            all_ops.append(ret_op)

    # --- Step 0d: checkContainedCall — convert CALL→BRANCH for PIC ---
    # C++ FlowInfo::checkContainedCall converts CALL ops whose target
    # address is an already-decoded instruction within the function to
    # BRANCH ops.  This handles Position Independent Code constructions
    # where a CALL is used as a jump within the same function.
    # C++ skips conversion when the callee has a known Funcdata (which
    # includes self-recursion).  Since Python has no function database,
    # we exclude calls to the function's own entry point.
    # NOTE: must run BEFORE fillinBranchStubs so stub addresses don't
    # appear in decoded_addrs.
    func_entry = fd.getAddress().getOffset() if fd.getAddress() else None
    decoded_addrs: set = set()
    for op in all_ops:
        decoded_addrs.add(op.getSeqNum().getAddr().getOffset())

    # C++ iterates qlst (call specs) with a for-loop that does ++iter
    # after the body.  After qlst.erase(iter), the returned iter already
    # points to the next element, so ++iter skips one.  We replicate
    # this by collecting CALL ops in qlst order and applying the skip.
    call_ops = [op for op in all_ops if op.code() == OpCode.CPUI_CALL]
    skip_next = False
    for op in call_ops:
        if skip_next:
            skip_next = False
            continue
        target_vn = op.getIn(0)
        if target_vn is None:
            continue
        tgt_addr = target_vn.getAddr()
        if tgt_addr.isConstant():
            continue
        tgt_off = tgt_addr.getOffset()
        # Skip self-recursive calls (callee is the current function)
        if tgt_off == func_entry:
            continue
        # Only convert if target is an already-decoded instruction start
        if tgt_off in decoded_addrs:
            op.setOpcodeEnum(OpCode.CPUI_BRANCH)
            skip_next = True  # C++ iterator skip after erase

    # --- Step 0e: fillinBranchStubs — stub blocks for out-of-range targets ---
    # C++ FlowInfo::fillinBranchStubs creates artificial halt (RETURN) ops at
    # branch targets that fell outside the function's address range.  These
    # become single-op stub blocks so that BRANCH ops have valid edge targets.
    unprocessed: List[int] = []
    if lifter is not None and hasattr(lifter, '_unprocessed'):
        unprocessed = lifter._unprocessed
    if unprocessed:
        code_spc = all_ops[0].getSeqNum().getAddr().getSpace() if all_ops else None
        seen_unproc: set = set()
        for uaddr in unprocessed:
            if uaddr in seen_unproc:
                continue
            seen_unproc.add(uaddr)
            if code_spc is not None:
                stub_addr = Address(code_spc, uaddr)
                stub_op = fd.newOp(1, stub_addr)
                stub_op.setOpcodeEnum(OpCode.CPUI_RETURN)
                uniq = stub_op.getSeqNum().getTime() if hasattr(stub_op.getSeqNum(), 'getTime') else 0
                stub_in = fd.newConstant(4, uniq)
                fd.opSetInput(stub_op, stub_in, 0)
                all_ops.append(stub_op)

    # --- Step 1: Identify basic block start indices ---
    # The first op always starts a block
    block_starts: set = {0}

    # Build address→index map for resolving branch targets
    addr_to_first_idx: Dict[int, int] = {}
    for i, op in enumerate(all_ops):
        pc = op.getSeqNum().getAddr().getOffset()
        if pc not in addr_to_first_idx:
            addr_to_first_idx[pc] = i

    # Build per-instruction op groups for resolving constant branch targets.
    # SLEIGH BRANCH/CBRANCH const[N] means "jump N p-code ops forward from
    # the current op within the same instruction" (relative offset, signed).
    # Used by REP-prefix instructions, etc.
    insn_groups: Dict[int, List[int]] = {}  # addr -> [all_ops indices]
    for i, op in enumerate(all_ops):
        pc = op.getSeqNum().getAddr().getOffset()
        insn_groups.setdefault(pc, []).append(i)

    # Map all_ops index -> position within instruction group
    op_idx_to_insn_pos: Dict[int, int] = {}
    for pc, group in insn_groups.items():
        for pos, idx in enumerate(group):
            op_idx_to_insn_pos[idx] = pos

    def _resolve_const_target(branch_op_idx: int, const_offset: int) -> int:
        """Resolve a constant branch target to an all_ops index.

        const_offset is a RELATIVE offset from the branch op's position
        within the instruction.  Sign-extend for backward branches.
        """
        pc = all_ops[branch_op_idx].getSeqNum().getAddr().getOffset()
        group = insn_groups.get(pc, [])
        if not group:
            return -1
        # Sign-extend const_offset (treat as signed 32-bit)
        if const_offset >= 0x80000000:
            const_offset -= 0x100000000
        # Current op's position within the instruction
        cur_pos = op_idx_to_insn_pos.get(branch_op_idx, 0)
        target_pos = cur_pos + const_offset
        if 0 <= target_pos < len(group):
            return group[target_pos]
        # If target is past the end, it falls through to the next instruction
        if target_pos >= len(group):
            last_idx = group[-1]
            if last_idx + 1 < len(all_ops):
                return last_idx + 1
        return -1

    for i, op in enumerate(all_ops):
        opc = op.code()
        if opc in (OpCode.CPUI_BRANCH, OpCode.CPUI_CBRANCH):
            # Op after this branch starts a new block
            if i + 1 < len(all_ops):
                block_starts.add(i + 1)
            # Branch target starts a new block
            target_vn = op.getIn(0)
            if target_vn is not None:
                tgt_addr = target_vn.getAddr()
                if not tgt_addr.isConstant():
                    tgt_off = tgt_addr.getOffset()
                    if tgt_off in addr_to_first_idx:
                        block_starts.add(addr_to_first_idx[tgt_off])
                else:
                    # Internal p-code branch: const[N] = Nth op in this insn
                    tgt_idx = _resolve_const_target(i, tgt_addr.getOffset())
                    if 0 <= tgt_idx < len(all_ops):
                        block_starts.add(tgt_idx)
        elif opc == OpCode.CPUI_BRANCHIND:
            # Resolved jump table: op after BRANCHIND starts a new block,
            # and each jump table target starts a new block
            if i + 1 < len(all_ops):
                block_starts.add(i + 1)
            op_addr = op.getSeqNum().getAddr().getOffset()
            if op_addr in jumptables:
                for tgt_off in jumptables[op_addr]:
                    if tgt_off in addr_to_first_idx:
                        block_starts.add(addr_to_first_idx[tgt_off])
        elif opc == OpCode.CPUI_RETURN:
            # Op after RETURN terminates the block
            if i + 1 < len(all_ops):
                block_starts.add(i + 1)

    if len(block_starts) <= 1:
        # No splitting needed, but if we added synthetic ops (e.g. RETURN
        # after converted CALLIND), rebuild the single block's op list.
        if len(all_ops) != len(original_ops):
            for op in list(old_bb.getOpList()):
                old_bb.removeOp(op)
                op.setParent(None)
            for op in all_ops:
                old_bb.addOp(op)
                op.setParent(old_bb)
                fd.opMarkAlive(op)
            first_addr = all_ops[0].getSeqNum().getAddr()
            last_addr = all_ops[-1].getSeqNum().getAddr()
            old_bb.setInitialRange(first_addr, last_addr)
        # Normalize branch target sizes and add self-loop edges
        func_off = fd.getAddress().getOffset() if fd.getAddress() else None
        for op in all_ops:
            opc = op.code()
            if opc in (OpCode.CPUI_BRANCH, OpCode.CPUI_CBRANCH):
                target_vn = op.getIn(0)
                if target_vn is not None and target_vn.getSize() != 1:
                    target_vn._size = 1
                # Add self-loop edge if branch targets own block
                if target_vn is not None:
                    tgt_addr = target_vn.getAddr()
                    if not tgt_addr.isConstant():
                        tgt_off = tgt_addr.getOffset()
                        if tgt_off == func_off:
                            bblocks.addEdge(old_bb, old_bb)
        # --- C++ generateBlocks: ensure entry block has no incoming edges ---
        _ensure_entry_no_incoming(bblocks, fd)
        return

    # --- Step 1b: Normalize branch target varnode sizes to 1 ---
    # C++ FlowInfo sets BRANCH/CBRANCH target address varnodes to size=1
    # (they represent labels, not real data addresses).  This applies to
    # both code-space labels and constant-offset relative targets.
    for op in all_ops:
        opc = op.code()
        if opc in (OpCode.CPUI_BRANCH, OpCode.CPUI_CBRANCH):
            target_vn = op.getIn(0)
            if target_vn is not None and target_vn.getSize() != 1:
                target_vn._size = 1

    # --- Step 2: Remove all ops from the old block ---
    # Only remove ops that were originally in the block (not synthetic ones)
    for op in all_ops:
        if id(op) in original_ops:
            old_bb.removeOp(op)
            op.setParent(None)

    # Remove the old block from the graph
    bblocks.clear()

    # --- Step 3: Create new blocks and assign ops ---
    sorted_starts = sorted(block_starts)

    for si, start_idx in enumerate(sorted_starts):
        end_idx = sorted_starts[si + 1] if si + 1 < len(sorted_starts) else len(all_ops)
        block_ops = all_ops[start_idx:end_idx]
        if not block_ops:
            continue

        bb = bblocks.newBlockBasic(fd)
        bb._index = si  # Assign sequential block index
        first_addr = block_ops[0].getSeqNum().getAddr()
        last_addr = block_ops[-1].getSeqNum().getAddr()
        bb.setInitialRange(first_addr, last_addr)

        for op in block_ops:
            bb.addOp(op)
            op.setParent(bb)
            fd.opMarkAlive(op)

    # --- Step 4: Add edges between blocks ---
    # Build block lookup: entry_offset → block_index
    block_by_entry: Dict[int, int] = {}
    for bi in range(bblocks.getSize()):
        bb = bblocks.getBlock(bi)
        entry = bb.getEntryAddr()
        if entry and not entry.isInvalid():
            off = entry.getOffset()
            if off not in block_by_entry:
                block_by_entry[off] = bi

    # Build identity-based maps for constant branch target resolution
    op_id_to_allidx: Dict[int, int] = {id(op): i for i, op in enumerate(all_ops)}
    # Map: first-op identity → block index (for finding target block)
    first_op_id_to_bi: Dict[int, int] = {}
    for bi in range(bblocks.getSize()):
        bb_ops = bblocks.getBlock(bi).getOpList()
        if bb_ops:
            first_op_id_to_bi[id(bb_ops[0])] = bi

    for bi in range(bblocks.getSize()):
        bb = bblocks.getBlock(bi)
        ops = bb.getOpList()
        if not ops:
            continue
        last_op = ops[-1]
        opc = last_op.code()

        # Fall-through edge (if not unconditional branch/branchind or return)
        if opc not in (OpCode.CPUI_BRANCH, OpCode.CPUI_BRANCHIND, OpCode.CPUI_RETURN):
            # Use instruction-level fall-through to handle x86 overlaps:
            # when a mid-instruction branch target creates a block between
            # the original instruction and its real fall-through address.
            # BUT only at real instruction boundaries — not at internal
            # p-code splits within the same instruction (e.g. REP prefix).
            ft_target_bi = None
            if insn_fall_throughs and bi + 1 < bblocks.getSize():
                last_insn_addr = last_op.getSeqNum().getAddr().getOffset()
                next_bb = bblocks.getBlock(bi + 1)
                next_ops = next_bb.getOpList()
                if next_ops:
                    next_insn_addr = next_ops[0].getSeqNum().getAddr().getOffset()
                    # Only use instruction fall-through when next block is
                    # at a different instruction address (real boundary).
                    if next_insn_addr != last_insn_addr:
                        ft_addr = insn_fall_throughs.get(last_insn_addr)
                        if ft_addr is not None and ft_addr != next_insn_addr:
                            ft_target_bi = block_by_entry.get(ft_addr)
            if ft_target_bi is not None:
                bblocks.addEdge(bb, bblocks.getBlock(ft_target_bi))
            elif bi + 1 < bblocks.getSize():
                bblocks.addEdge(bb, bblocks.getBlock(bi + 1))

        # Resolved BRANCHIND: add edges to all unique jump table targets
        if opc == OpCode.CPUI_BRANCHIND:
            op_addr = last_op.getSeqNum().getAddr().getOffset()
            if op_addr in jumptables:
                seen_targets: set = set()
                for tgt_off in jumptables[op_addr]:
                    tgt_bi = block_by_entry.get(tgt_off)
                    if tgt_bi is not None and tgt_bi not in seen_targets:
                        seen_targets.add(tgt_bi)
                        bblocks.addEdge(bb, bblocks.getBlock(tgt_bi))

        # Branch edge
        if opc in (OpCode.CPUI_BRANCH, OpCode.CPUI_CBRANCH):
            target_vn = last_op.getIn(0)
            if target_vn is not None:
                tgt_addr = target_vn.getAddr()
                if not tgt_addr.isConstant():
                    tgt_off = tgt_addr.getOffset()
                    tgt_bi = block_by_entry.get(tgt_off)
                    if tgt_bi is not None:
                        bblocks.addEdge(bb, bblocks.getBlock(tgt_bi))
                else:
                    # Internal p-code branch: resolve const target to block
                    last_op_idx = op_id_to_allidx.get(id(last_op), -1)
                    if last_op_idx >= 0:
                        tgt_idx = _resolve_const_target(last_op_idx, tgt_addr.getOffset())
                        if 0 <= tgt_idx < len(all_ops):
                            tgt_op = all_ops[tgt_idx]
                            tgt_bi2 = first_op_id_to_bi.get(id(tgt_op))
                            if tgt_bi2 is not None:
                                bblocks.addEdge(bb, bblocks.getBlock(tgt_bi2))

        # CBRANCH also has fall-through
        if opc == OpCode.CPUI_CBRANCH:
            if bi + 1 < bblocks.getSize():
                # Already added above in the fall-through case
                pass

    # --- C++ generateBlocks: ensure entry block has no incoming edges ---
    _ensure_entry_no_incoming(bblocks, fd)


def _ensure_entry_no_incoming(bblocks, fd) -> None:
    """If the entry block has incoming edges, create an empty front block.

    C++ FlowInfo::generateBlocks (flow.cc) checks if the start block has
    sizeIn != 0.  If so, it creates a new empty BasicBlock that flows into
    the old entry block and sets the new block as the start.  This happens
    for self-loop functions like ``JMP self`` and for functions where the
    entry instruction is a loop target.
    """
    if bblocks.getSize() == 0:
        return
    # In C++, block 0 is the entry block (set by setStartBlock in splitBasic).
    # In Python, blocks are ordered by address, so find the entry block by
    # matching the function entry address.
    func_addr = fd.getAddress()
    if func_addr is None:
        return
    func_off = func_addr.getOffset()
    startblock = None
    for bi in range(bblocks.getSize()):
        blk = bblocks.getBlock(bi)
        entry = blk.getEntryAddr()
        if entry and entry.getOffset() == func_off:
            startblock = blk
            break
    if startblock is None:
        return
    if startblock.sizeIn() == 0:
        return
    newfront = bblocks.newBlockBasic(fd)
    newfront.setInitialRange(func_addr, func_addr)
    bblocks.addEdge(newfront, startblock)
    bblocks.setStartBlock(newfront)


def _inject_tracked_context(fd, lifter=None) -> None:
    """Inject COPY ops for tracked context registers at function entry.

    C++ ``ActionConstbase::apply`` reads the tracked context set from
    ``arch->context->getTrackedSet(funcAddr)`` and inserts a COPY from a
    constant for each tracked register at the start of block 0.

    For x86-32, the only tracked context register is DF (direction flag)
    at register offset 0x20a, size 1, value 0.

    C++ ref: coreaction.cc  ActionConstbase::apply
    """
    bblocks = fd.getBasicBlocks()
    if bblocks.getSize() == 0:
        return

    # Find the block at the function entry address (not necessarily block 0).
    # For functions with backward jumps, block 0 may be before the entry.
    func_entry = fd.getAddress()
    func_off = func_entry.getOffset() if func_entry else None
    bb = bblocks.getBlock(0)  # default fallback
    for bi in range(bblocks.getSize()):
        blk = bblocks.getBlock(bi)
        blk_start = blk.getStart() if hasattr(blk, 'getStart') else None
        if blk_start and blk_start.getOffset() == func_off:
            bb = blk
            break
    entry_addr = bb.getStart() if hasattr(bb, 'getStart') else func_entry

    # For x86-32: DF (direction flag) = 0
    # register offset 0x20a, size 1, value 0
    tracked_regs = []
    arch = fd.getArch() if hasattr(fd, 'getArch') else None
    if arch is not None:
        reg_space = None
        try:
            reg_space = arch.getSpaceByName("register")
        except Exception:
            pass
        if reg_space is not None:
            # x86-32 tracked context: DF at offset 0x20a, size 1, value 0
            tracked_regs.append((reg_space, 0x20a, 1, 0))

    for reg_space, offset, size, val in tracked_regs:
        op = fd.newOp(1, entry_addr)
        out_addr = Address(reg_space, offset)
        fd.newVarnodeOut(size, out_addr, op)
        vn_const = fd.newConstant(size, val)
        fd.opSetOpcode(op, OpCode.CPUI_COPY)
        fd.opSetInput(op, vn_const, 0)
        fd.opInsertBegin(op, bb)


def _run_prerequisite_actions(fd) -> None:
    """Run the C++ prerequisite actions before heritage.

    C++ decompiler_bind.cpp runs these actions in order before opHeritage():
      ActionStart, ActionConstbase, ActionNormalizeSetup, ActionDefaultParams,
      ActionExtraPopSetup, ActionPrototypeTypes, ActionFuncLink,
      ActionFuncLinkOutOnly, ActionUnreachable, ActionVarnodeProps.

    ActionStart (startProcessing/FlowInfo) and ActionConstbase (tracked context)
    are handled separately by the Lifter and _inject_tracked_context().
    This function runs the remaining actions.

    C++ ref: decompiler_bind.cpp lines 384-393
    """
    from ghidra.transform.coreaction2 import (
        ActionNormalizeSetup, ActionDefaultParams, ActionExtraPopSetup,
        ActionPrototypeTypes, ActionFuncLink, ActionFuncLinkOutOnly,
    )
    from ghidra.transform.coreaction import ActionUnreachable, ActionVarnodeProps

    arch = fd.getArch() if hasattr(fd, 'getArch') else None
    stackspace = arch.getStackSpace() if arch is not None else None

    # ActionStart normally calls startProcessing() which calls structureReset().
    # structureReset() → structureLoops() → findSpanningTree() reorders blocks
    # into reverse-post-order (matching C++ block numbering).
    # We call structureReset() directly since blocks are already built.
    if hasattr(fd, 'structureReset'):
        fd.structureReset()
    if hasattr(fd, 'sortCallSpecs'):
        fd.sortCallSpecs()

    actions = [
        ActionNormalizeSetup("normalanalysis"),
        ActionDefaultParams("base"),
        ActionExtraPopSetup("base", stackspace),
        ActionPrototypeTypes("protorecovery"),
        ActionFuncLink("protorecovery"),
        ActionFuncLinkOutOnly("noproto"),
        ActionUnreachable("base"),
        ActionVarnodeProps("base"),
    ]
    for act in actions:
        try:
            act.reset(fd)
            act.apply(fd)
        except Exception:
            pass  # Non-fatal: action may need infrastructure not yet available


def _setup_call_specs(fd, lifter=None) -> None:
    """Create FuncCallSpecs for every CALL/CALLIND op in the Funcdata.

    C++ FlowInfo::setupCallSpecs / setupCallindSpecs creates these during
    startProcessing().  The Python Lifter path skips FlowInfo, so we must
    create them after _split_basic_blocks so that Heritage::guardCalls can
    insert INDIRECT ops for call effects.

    The default ProtoModel (with effect list) is taken from
    ``fd.getArch().defaultfp`` if available, so that ``hasEffect()``
    returns proper ``unaffected`` / ``killedbycall`` for x86-32 cdecl
    registers.

    C++ ref: flow.cc  FlowInfo::setupCallSpecs / setupCallindSpecs
    """
    from ghidra.fspec.fspec import FuncCallSpecs

    # Get default model from architecture (already has effect list)
    default_model = None
    arch = fd.getArch() if hasattr(fd, 'getArch') else None
    if arch is not None and hasattr(arch, 'defaultfp'):
        default_model = arch.defaultfp

    bblocks = fd.getBasicBlocks()
    for bi in range(bblocks.getSize()):
        bb = bblocks.getBlock(bi)
        for op in bb.getOpList():
            opc = op.code()
            if opc in (OpCode.CPUI_CALL, OpCode.CPUI_CALLIND):
                fc = FuncCallSpecs(op)
                # For direct CALL, record the target address
                if opc == OpCode.CPUI_CALL and op.numInput() > 0:
                    tgt = op.getIn(0).getAddr()
                    if tgt is not None and not tgt.isConstant():
                        fc.setAddress(tgt)
                # Attach default prototype model so hasEffect works properly.
                # Use direct assignment (not setModel) to keep extrapop at
                # unknown (0x8000), matching C++ heritage behavior where
                # ExtraPopSetup creates INDIRECT(ESP) before calls.
                if default_model is not None and hasattr(fc, 'proto'):
                    fc.proto.model = default_model
                fd.addCallSpecs(fc)


def _run_mini_pipeline(fd) -> None:
    """Run a minimal optimization pipeline on the Funcdata.

    This is a focused subset of the full universalAction pipeline,
    containing only safe transformations that don't require prototype
    recovery, type recovery, block structure, or merge infrastructure.

    Steps:
      1. Heritage (SSA construction)
      2. Rule pool: copy propagation, early removal, constant folding,
         trivial arithmetic, boolean simplification
      3. Dead code elimination
    """
    from ghidra.transform.action import Action, ActionGroup, ActionPool
    from ghidra.transform.coreaction import ActionHeritage, ActionNonzeroMask
    from ghidra.transform.deadcode import ActionDeadCode
    from ghidra.transform.ruleaction import (
        RuleEarlyRemoval, RulePiece2Zext, RulePiece2Sext,
        RuleTermOrder, RuleTrivialArith, RuleTrivialBool,
        RuleBxor2NotEqual,
        RuleShift2Mult,
        RuleIdentityEl, RuleOrMask, RuleAndMask, RuleOrCollapse,
        RuleNegateIdentity, RuleCollapseConstants,
        RulePropagateCopy, Rule2Comp2Mult, RuleSub2Add,
        RuleXorCollapse,
    )
    from ghidra.transform.ruleaction_batch1a import RuleTrivialShift
    from ghidra.transform.ruleaction_batch1d import RuleBoolNegate

    # Build a mini action group: heritage → rules → deadcode
    act = ActionGroup(0, "mini_pipeline")

    # Step 1: Heritage (SSA)
    act.addAction(ActionHeritage("base"))

    # Step 2: Rule pool (runs rules until no more changes)
    pool = ActionPool(Action.rule_repeatapply, "mini_pool")
    pool.addRule(RuleEarlyRemoval("deadcode"))
    pool.addRule(RuleTermOrder("analysis"))
    pool.addRule(RuleTrivialArith("analysis"))
    pool.addRule(RuleTrivialBool("analysis"))
    pool.addRule(RuleTrivialShift("analysis"))
    pool.addRule(RuleIdentityEl("analysis"))
    pool.addRule(RuleOrMask("analysis"))
    pool.addRule(RuleAndMask("analysis"))
    pool.addRule(RuleOrCollapse("analysis"))
    pool.addRule(RuleBxor2NotEqual("analysis"))
    pool.addRule(RuleShift2Mult("analysis"))
    pool.addRule(RuleXorCollapse("analysis"))
    pool.addRule(RuleCollapseConstants("analysis"))
    pool.addRule(RulePropagateCopy("analysis"))
    pool.addRule(RuleSub2Add("analysis"))
    pool.addRule(Rule2Comp2Mult("analysis"))
    pool.addRule(RuleBoolNegate("analysis"))
    pool.addRule(RuleNegateIdentity("analysis"))
    pool.addRule(RulePiece2Zext("analysis"))
    pool.addRule(RulePiece2Sext("analysis"))
    act.addAction(pool)

    # Step 3: Dead code elimination
    act.addAction(ActionDeadCode("deadcode"))

    # Step 4: Non-zero mask
    act.addAction(ActionNonzeroMask("analysis"))

    # Run the pipeline
    act.reset(fd)
    act.perform(fd)


def _run_full_decompile_action(fd) -> None:
    from ghidra.transform.action import ActionDatabase

    allacts = ActionDatabase()
    allacts.universalAction(fd.getArch())
    allacts.resetDefaults()
    root = allacts.getCurrent()
    root.reset(fd)
    root.perform(fd)


def _seed_default_return_output(fd, target: str) -> None:
    """Lock the output prototype with the return register so that
    ActionPrototypeTypes will wire it to RETURN ops before Heritage.

    For the full actions pipeline, ActionPrototypeTypes (which runs before
    Heritage) will add the return register as a free varnode input on each
    RETURN op. Heritage then builds MULTIEQUALs connecting the actual
    register writes to those inputs.

    We must NOT also manually wire varnodes here, as that would create
    duplicate inputs that ActionPrototypeTypes adds on top of.
    """
    parts = target.split(":")
    if len(parts) < 3:
        return
    arch = parts[0].lower()
    if "x86" not in arch:
        return

    bitness = int(parts[2])
    ret_size = 8 if bitness == 64 else 4
    reg_space = fd.getArch().getSpace(1) if fd.getArch() is not None else None
    if reg_space is None or getattr(reg_space, "getName", lambda: "")() != "register":
        try:
            reg_space = fd.getArch()._spc_mgr.getSpaceByName("register")
        except Exception:
            reg_space = None
    if reg_space is None:
        return

    ret_addr = Address(reg_space, 0)

    # Lock the output prototype with the return register so that
    # ActionPrototypeTypes will add it to RETURN ops.
    proto = fd.getFuncProto()
    if not proto.isOutputLocked():
        glb = fd.getArch()
        int_type = None
        if glb is not None and hasattr(glb, 'types'):
            int_type = glb.types.getBase(ret_size, 8)  # TYPE_INT = 8
        from ghidra.fspec.fspec import ProtoParameter
        outparam = ProtoParameter("", int_type, ret_addr, ret_size)
        outparam.setTypeLock(True)
        proto.outparam = outparam


def _printc_from_funcdata(fd) -> str:
    """Generate C pseudocode using the full PrintC emitter in flat mode.

    Uses PrintC's op handlers, RPN stack, register naming, and expression
    emission infrastructure. Falls back to _raw_c_from_funcdata on error.

    Since we don't have block structure recovery or full FuncProto,
    we manually emit the function header and use emitBlockBasic for
    each basic block in flat mode.
    """
    from ghidra.output.prettyprint import EmitMarkup, SyntaxHighlight
    from ghidra.output.printc import PrintC
    from ghidra.output.printlanguage import PrintLanguage

    emit = EmitMarkup()
    printer = PrintC(fd.getArch(), "c-language")
    printer.setEmitter(emit)

    # --- Function header ---
    name = fd.getDisplayName() if hasattr(fd, 'getDisplayName') else fd.getName()
    emit.tagLine()
    emit.print("void", SyntaxHighlight.keyword_color)
    emit.spaces(1)
    emit.tagFuncName(name, SyntaxHighlight.funcname_color, fd, None)
    emit.print("(")
    emit.print("void", SyntaxHighlight.keyword_color)
    emit.print(")")
    emit.tagLine()
    emit.print("{")
    emit.indentlevel += emit.indentincrement

    graph = fd.getStructure()
    if graph.getSize() != 0:
        graph.emit(printer)
    else:
        printer.setMod(PrintLanguage.flat)
        bblocks = fd.getBasicBlocks()
        for bi in range(bblocks.getSize()):
            bb = bblocks.getBlock(bi)
            printer.emitBlockBasic(bb)

    # --- Close function ---
    emit.indentlevel -= emit.indentincrement
    emit.tagLine()
    emit.print("}")
    emit.tagLine()

    return emit.getOutput()


def _raw_c_from_funcdata(fd) -> str:
    """Generate raw C-like pseudocode directly from Python Funcdata.

    This is the Module-1 level output: no analysis, no optimization,
    just a direct translation of PcodeOps to C-like statements.
    Uses pure Python Funcdata/Varnode/PcodeOp/Address/AddrSpace objects.
    """
    lines: List[str] = []
    name = fd.getName()
    addr = fd.getAddress()
    size = fd.getSize()

    bblocks = fd.getBasicBlocks()
    num_blocks = bblocks.getSize()
    flow_status = "Python" if num_blocks > 1 else "-"

    lines.append("// Decompiled by PyGhidra (pure Python pipeline)")
    lines.append(f"// Function: {name} @ 0x{addr.getOffset():x}, size={size}")
    lines.append("// Pipeline: sleigh_native → Lifter → Python IR → raw output")
    lines.append(f"// Modules active: [SLEIGH(C++)] [IR(Python)] [FlowInfo({flow_status})] [Heritage(-)] [Rules(-)] [PrintC(-)]")
    lines.append("")
    lines.append(f"void {name}(void)")
    lines.append("{")

    for bi in range(num_blocks):
        bb = bblocks.getBlock(bi)
        ops = bb.getOpList() if hasattr(bb, 'getOpList') else []

        if num_blocks > 1:
            entry = bb.getEntryAddr() if hasattr(bb, 'getEntryAddr') else None
            label = f"0x{entry.getOffset():x}" if entry and not entry.isInvalid() else f"block_{bi}"
            lines.append(f"  // --- Block {bi} ({label}) ---")

        for op in ops:
            stmt = _op_str(op)
            seq = op.getSeqNum()
            pc = seq.getAddr().getOffset() if seq else 0
            lines.append(f"    {stmt};  // @0x{pc:x}")

    lines.append(f"}}")
    lines.append(f"")
    return "\n".join(lines)


class DecompilerPython:
    """Pure-Python replacement for DecompilerNative.

    Same interface:
        - add_spec_path(path)
        - add_ghidra_root(path)
        - initialize()
        - decompile(sla_path, target, image, base_addr, entry, func_size) → str
        - get_errors() → str

    Internally routes through the pure Python pipeline.
    """

    def __init__(self) -> None:
        self._initialized: bool = False
        self._errors: str = ""
        self._warnings: str = ""

        # Module flags — enable/disable each Python module
        self.use_python_ir: bool = True       # Module 1: Lifter → Python Funcdata
        self.use_python_flow: bool = True      # Module 2: Python FlowInfo
        self.use_python_heritage: bool = False # Module 3: Python Heritage/SSA
        self.use_python_rules: bool = False    # Module 4: Python Actions/Rules
        self.use_python_full_actions: bool = False
        self.use_python_printc: bool = False   # Module 5: Python PrintC

    def add_spec_path(self, path: str) -> None:
        """Add a flat directory containing .sla/.ldefs/.pspec/.cspec files."""
        add_sla_search_dir(path)

    def add_ghidra_root(self, path: str) -> None:
        """Add a Ghidra-layout root directory."""
        proc_dir = os.path.join(path, "Ghidra", "Processors")
        if os.path.isdir(proc_dir):
            for proc in os.listdir(proc_dir):
                lang_dir = os.path.join(proc_dir, proc, "data", "languages")
                if os.path.isdir(lang_dir):
                    add_sla_search_dir(lang_dir)

    def initialize(self) -> None:
        """Initialize the decompiler (no-op for Python — lazy init per call)."""
        self._initialized = True

    def decompile(self, sla_path: str, target: str,
                  image: bytes, base_addr: int,
                  entry: int, func_size: int = 0) -> str:
        """Decompile a function using the pure Python pipeline.

        Args:
            sla_path: Path to the .sla file
            target:   Language id (e.g. 'x86:LE:64:default')  [unused by Python path]
            image:    Raw binary bytes
            base_addr: Base address of the image
            entry:    Entry point of the function
            func_size: Size of the function in bytes

        Returns:
            C-like pseudocode as a string.
        """
        self._errors = ""
        self._warnings = ""

        try:
            if not self._initialized:
                self.initialize()

            # Determine context from target string (e.g. "x86:LE:32:default")
            context = {}
            parts = target.split(":")
            if len(parts) >= 3:
                bitness = int(parts[2])
                if bitness == 32 and "x86" in parts[0].lower():
                    context = {"addrsize": 1, "opsize": 1}

            # --- Module 1: SLEIGH lifting → Python IR ---
            lifter = Lifter(sla_path, context)
            lifter.set_image(base_addr, image)

            func_name = f"func_{entry:x}"
            fd = lifter.lift_function(func_name, entry, func_size)

            # --- Module 2: FlowInfo (basic block construction) ---
            if self.use_python_flow:
                try:
                    _split_basic_blocks(fd, lifter=lifter)
                except Exception as e:
                    self._errors += f"FlowInfo error: {e}\n"

            # --- Attach Architecture shim (needed by Heritage and Actions) ---
            arch_shim = _ArchitectureShim(lifter._spc_mgr)
            fd.setArch(arch_shim)

            if self.use_python_full_actions:
                _seed_default_return_output(fd, target)

            ran_full_actions = False

            # --- Module 4: Full Actions/Rules ---
            if self.use_python_full_actions:
                try:
                    _run_full_decompile_action(fd)
                    ran_full_actions = True
                except Exception as e:
                    self._errors += f"Full actions error: {e}\n"
                    import traceback
                    self._errors += traceback.format_exc()

            # --- Module 3: Heritage (SSA construction) ---
            if self.use_python_heritage and not ran_full_actions:
                try:
                    fd.opHeritage()
                except Exception as e:
                    self._errors += f"Heritage error: {e}\n"

            # --- Module 4: Actions/Rules (optimization) ---
            if self.use_python_rules and not ran_full_actions:
                try:
                    _run_mini_pipeline(fd)
                except Exception as e:
                    self._errors += f"Rules error: {e}\n"
                    import traceback
                    self._errors += traceback.format_exc()
            for msg in arch_shim.drainMessages():
                self._warnings += f"{msg}\n"

            # --- Module 5: PrintC (C code generation) ---
            if self.use_python_printc:
                try:
                    c_code = _printc_from_funcdata(fd)
                    if c_code and c_code.strip():
                        return c_code
                    self._errors += "PrintC produced empty output, using raw fallback\n"
                except Exception as e:
                    self._errors += f"PrintC error: {e}\n"
                    import traceback
                    self._errors += traceback.format_exc()

            # --- Fallback: raw C output from Python IR ---
            return _raw_c_from_funcdata(fd)

        except Exception as e:
            self._errors += f"Decompile error: {e}\n"
            import traceback
            self._errors += traceback.format_exc()
            return f"// ERROR: {e}\n"

    def get_errors(self) -> str:
        """Get error messages from the last operation."""
        return self._errors

    def get_warnings(self) -> str:
        """Get warning messages from the last operation."""
        return self._warnings
