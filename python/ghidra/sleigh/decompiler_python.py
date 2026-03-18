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


def _split_basic_blocks(fd) -> None:
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

    # --- Step 1: Identify basic block start indices ---
    # The first op always starts a block
    block_starts: set = {0}

    # Build address→index map for resolving branch targets
    addr_to_first_idx: Dict[int, int] = {}
    for i, op in enumerate(all_ops):
        pc = op.getSeqNum().getAddr().getOffset()
        if pc not in addr_to_first_idx:
            addr_to_first_idx[pc] = i

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
        elif opc in (OpCode.CPUI_CALL, OpCode.CPUI_CALLIND):
            # C++ FlowInfo splits at call sites
            if i + 1 < len(all_ops):
                block_starts.add(i + 1)
            # C++ converts CALL→BRANCH, so the call target is also a block leader
            if opc == OpCode.CPUI_CALL:
                target_vn = op.getIn(0)
                if target_vn is not None:
                    tgt_addr = target_vn.getAddr()
                    if not tgt_addr.isConstant():
                        tgt_off = tgt_addr.getOffset()
                        if tgt_off in addr_to_first_idx:
                            block_starts.add(addr_to_first_idx[tgt_off])
        elif opc in (OpCode.CPUI_BRANCHIND, OpCode.CPUI_RETURN):
            # Op after this terminates the block
            if i + 1 < len(all_ops):
                block_starts.add(i + 1)

    if len(block_starts) <= 1:
        return  # No splitting needed

    # --- Step 1b: Convert intra-function CALL→BRANCH (matching C++ FlowInfo) ---
    # C++ FlowInfo converts CALL ops whose target is within the function into
    # BRANCH ops.  Reproduce the same transformation here so that the Python
    # IR matches the C++ IR at the flow stage.
    for op in all_ops:
        opc = op.code()
        if opc == OpCode.CPUI_CALL:
            target_vn = op.getIn(0)
            if target_vn is not None:
                tgt_addr = target_vn.getAddr()
                if not tgt_addr.isConstant():
                    tgt_off = tgt_addr.getOffset()
                    if tgt_off in addr_to_first_idx:
                        op.setOpcodeEnum(OpCode.CPUI_BRANCH)

    # --- Step 1c: Normalize branch target varnode sizes to 1 ---
    # C++ FlowInfo sets BRANCH/CBRANCH target address varnodes to size=1
    # (they represent labels, not real data addresses).
    for op in all_ops:
        opc = op.code()
        if opc in (OpCode.CPUI_BRANCH, OpCode.CPUI_CBRANCH):
            target_vn = op.getIn(0)
            if target_vn is not None and not target_vn.getAddr().isConstant():
                if target_vn.getSize() != 1:
                    target_vn._size = 1

    # --- Step 2: Remove all ops from the old block ---
    for op in all_ops:
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
            block_by_entry[entry.getOffset()] = bi

    for bi in range(bblocks.getSize()):
        bb = bblocks.getBlock(bi)
        ops = bb.getOpList()
        if not ops:
            continue
        last_op = ops[-1]
        opc = last_op.code()

        # Fall-through edge (if not unconditional branch or return)
        if opc not in (OpCode.CPUI_BRANCH, OpCode.CPUI_BRANCHIND, OpCode.CPUI_RETURN):
            if bi + 1 < bblocks.getSize():
                bblocks.addEdge(bb, bblocks.getBlock(bi + 1))

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

        # CBRANCH also has fall-through
        if opc == OpCode.CPUI_CBRANCH:
            if bi + 1 < bblocks.getSize():
                # Already added above in the fall-through case
                pass


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
    default_vn = fd.findVarnodeInput(ret_size, ret_addr)
    if default_vn is None:
        default_vn = fd.setInputVarnode(fd.newVarnode(ret_size, ret_addr))

    ret_cache = {}
    ret_visiting = set()

    def find_reaching_ret_vn(bl):
        bid = id(bl)
        cached = ret_cache.get(bid)
        if cached is not None:
            return cached
        if bid in ret_visiting:
            return default_vn
        ret_visiting.add(bid)
        try:
            if hasattr(bl, "getOpList"):
                for op in bl.getOpList():
                    if op.code() == OpCode.CPUI_MULTIEQUAL:
                        out = op.getOut()
                        if out is not None and out.getAddr() == ret_addr and out.getSize() == ret_size:
                            ret_cache[bid] = out
                            return out
                for op in reversed(bl.getOpList()):
                    out = op.getOut()
                    if out is None:
                        continue
                    if out.getAddr() == ret_addr and out.getSize() == ret_size:
                        ret_cache[bid] = out
                        return out
            if bl.sizeIn() == 0:
                ret_cache[bid] = default_vn
                return default_vn
            if bl.sizeIn() == 1 and bl.sizeOut() <= 1:
                res = find_reaching_ret_vn(bl.getIn(0))
                ret_cache[bid] = res
                return res
            if bl.sizeIn() > 1 and bl.sizeOut() <= 1:
                multi = fd.newOp(bl.sizeIn(), bl.getStart() if hasattr(bl, "getStart") else ret_addr)
                fd.opSetOpcode(multi, OpCode.CPUI_MULTIEQUAL)
                outvn = fd.newVarnodeOut(ret_size, ret_addr, multi)
                ret_cache[bid] = outvn
                for slot in range(bl.sizeIn()):
                    fd.opSetInput(multi, find_reaching_ret_vn(bl.getIn(slot)), slot)
                fd.opInsertBegin(multi, bl)
                return outvn
            ret_cache[bid] = default_vn
            return default_vn
        finally:
            ret_visiting.discard(bid)

    bblocks = fd.getBasicBlocks()
    for bi in range(bblocks.getSize()):
        bb = bblocks.getBlock(bi)
        retop = bb.lastOp() if hasattr(bb, "lastOp") else None
        if retop is None or retop.code() != OpCode.CPUI_RETURN:
            continue
        if retop.numInput() > 1:
            continue
        fd.opInsertInput(retop, find_reaching_ret_vn(bb), retop.numInput())


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
                    _split_basic_blocks(fd)
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
                self._errors += f"{msg}\n"

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
        """Get error/warning messages from the last operation."""
        return self._errors
