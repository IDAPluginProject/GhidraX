"""
Flow-stage helpers for the Lifter → Funcdata pipeline.

Bridges the gap between the SLEIGH Lifter (which produces a single-block
Funcdata with raw p-code ops) and the Heritage stage (which expects
properly split basic blocks with edges, call specs, and tracked context).

These functions replicate the behavior of C++ FlowInfo methods
(flow.cc) that run between instruction decoding and Heritage:
  - _split_basic_blocks   → FlowInfo::generateBlocks + truncateIndirectJump
                             + checkContainedCall + fillinBranchStubs
  - _setup_call_specs     → FlowInfo::setupCallSpecs / setupCallindSpecs
  - _inject_tracked_context → ActionConstbase::apply
  - _run_prerequisite_actions → pre-heritage action sequence

C++ ref: flow.cc, coreaction.cc
"""

from __future__ import annotations

from typing import List, Dict

from ghidra.core.address import Address
from ghidra.core.opcodes import OpCode


# =========================================================================
# _split_basic_blocks
# =========================================================================

def _split_basic_blocks(fd, lifter=None) -> None:
    """Split a single-block Funcdata into proper basic blocks.

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
            next_off = last_off + 1  # default: 1 byte past last op
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
    # C++ skips conversion when the callee has a known Funcdata (fd != NULL).
    # We mirror this by skipping targets in lifter._known_functions.
    # NOTE: must run BEFORE fillinBranchStubs so stub addresses don't
    # appear in decoded_addrs.
    func_entry = fd.getAddress().getOffset() if fd.getAddress() else None
    decoded_addrs: set = set()
    for op in all_ops:
        decoded_addrs.add(op.getSeqNum().getAddr().getOffset())

    # Known function entries — C++ skips conversion when callee has Funcdata
    known_funcs: set = set()
    if lifter is not None and hasattr(lifter, '_known_functions'):
        known_funcs = lifter._known_functions

    call_ops = [op for op in all_ops if op.code() == OpCode.CPUI_CALL]
    for op in call_ops:
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
        # Skip calls to known functions (C++ fd != NULL check)
        if tgt_off in known_funcs:
            continue
        # Only convert if target is an already-decoded instruction start
        if tgt_off in decoded_addrs:
            op.setOpcodeEnum(OpCode.CPUI_BRANCH)

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

    # Function entry must always be a block boundary (even if it has a
    # higher address than other decoded code, e.g. JMP thunk at entry
    # jumping backward into the function body).
    if func_entry is not None and func_entry in addr_to_first_idx:
        block_starts.add(addr_to_first_idx[func_entry])

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
        bblocks.setStartBlock(startblock)
        return
    newfront = bblocks.newBlockBasic(fd)
    newfront.setInitialRange(func_addr, func_addr)
    bblocks.addEdge(newfront, startblock)
    bblocks.setStartBlock(newfront)


# =========================================================================
# _inject_tracked_context
# =========================================================================

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


# =========================================================================
# _setup_call_specs
# =========================================================================

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
                # setModel propagates extrapop from the model (e.g. 8 for
                # x86-64, 4 for x86-32), so ActionExtraPopSetup creates
                # INT_ADD ops for stack-pointer adjustment, matching C++.
                if default_model is not None and hasattr(fc, 'proto'):
                    fc.proto.setModel(default_model)
                fd.addCallSpecs(fc)


# =========================================================================
# _run_prerequisite_actions
# =========================================================================

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
