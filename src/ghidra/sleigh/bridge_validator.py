"""
Bridge A: Snapshot Comparison Validator

Runs both C++ (decompiler_native) and Python (DecompilerPython) pipelines
on the same input, captures IR snapshots at each stage, and reports
discrepancies.

Usage:
    from ghidra.sleigh.bridge_validator import BridgeValidator

    bv = BridgeValidator(spec_dir="path/to/specs")
    report = bv.compare(
        sla_path="path/to/x86-64.sla",
        target="x86:LE:64:default",
        image=b"\\x55\\x48\\x89\\xe5...",
        base_addr=0x401000,
        entry=0x401000,
        func_size=32,
        stages=["flow", "heritage"],  # which stages to compare
    )
    print(report.summary())
"""

from __future__ import annotations

import os
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional

from ghidra.core.opcodes import OpCode


# ---------------------------------------------------------------------------
# Data classes for normalized IR representation
# ---------------------------------------------------------------------------

@dataclass
class NVarnode:
    """Normalized varnode for comparison."""
    space: str
    offset: int
    size: int

    @property
    def is_spaceid_ptr(self) -> bool:
        """True if this is an address-space-id pointer constant.

        In LOAD/STORE pcode ops, the first input is a constant encoding the
        AddrSpace* pointer.  The raw pointer value differs between C++ and
        Python, so we treat any large (>= 8-byte) constant as a space-id
        and compare only the space name, not the offset.
        """
        return self.space == "const" and self.size >= 8

    @property
    def is_iop_ptr(self) -> bool:
        """True if this is a PcodeOp annotation varnode (space='iop').

        INDIRECT ops use iop-space varnodes to reference their indirect-effect
        PcodeOp. The offset encodes a raw pointer (C++) or id(op) (Python),
        so we compare only by space name, not offset.
        """
        return self.space == "iop"

    @property
    def is_fspec_ptr(self) -> bool:
        """True if this is a FuncCallSpecs pointer varnode.

        C++ FlowInfo::setupCallSpecs replaces the CALL target input with a
        varnode pointing to a FuncCallSpecs object (space='fspec', size=8).
        Python keeps the raw address (space='ram', size=4).
        """
        return self.space == "fspec"

    def __eq__(self, other):
        if not isinstance(other, NVarnode):
            return False
        # Both are space-id pointers → semantically equal (different runtime ptrs)
        if self.is_spaceid_ptr and other.is_spaceid_ptr:
            return True
        # Both are iop annotation pointers → semantically equal
        if self.is_iop_ptr and other.is_iop_ptr:
            return True
        return (self.space == other.space and
                self.offset == other.offset and
                self.size == other.size)

    def __hash__(self):
        if self.is_spaceid_ptr:
            return hash(("const", "__spaceid__", self.size))
        if self.is_iop_ptr:
            return hash(("iop", "__iop__"))
        return hash((self.space, self.offset, self.size))

    def __repr__(self):
        if self.is_spaceid_ptr:
            return f"const[SPACEID:{self.size}]"
        if self.is_iop_ptr:
            return f"iop[{self.offset:#x}:{self.size}]"
        return f"{self.space}[0x{self.offset:x}:{self.size}]"


@dataclass
class NOp:
    """Normalized pcode op for comparison."""
    opcode: int
    addr: int
    seq_order: int
    output: Optional[NVarnode]
    inputs: List[NVarnode]

    def matches(self, other: NOp, strict: bool = True) -> bool:
        """Check if this op matches another."""
        if self.opcode != other.opcode:
            return False
        if self.addr != other.addr:
            return False
        if strict and self.seq_order != other.seq_order:
            return False
        if (self.output is None) != (other.output is None):
            return False
        if self.output and self.output != other.output:
            return False
        if len(self.inputs) != len(other.inputs):
            return False
        for a, b in zip(self.inputs, other.inputs):
            if a != b:
                return False
        return True

    def __repr__(self):
        opc_name = OpCode(self.opcode).name if self.opcode < 80 else str(self.opcode)
        out_s = str(self.output) if self.output else "void"
        in_s = ", ".join(str(i) for i in self.inputs)
        return f"@0x{self.addr:x}#{self.seq_order} {out_s} = {opc_name}({in_s})"


@dataclass
class NBlock:
    """Normalized basic block for comparison."""
    index: int
    start: int
    stop: int
    successors: List[int]
    predecessors: List[int]
    ops: List[NOp]
    num_ops: int

    def __repr__(self):
        return (f"Block[{self.index}] 0x{self.start:x}-0x{self.stop:x} "
                f"ops={self.num_ops} succ={self.successors} pred={self.predecessors}")


@dataclass
class IrSnapshot:
    """Normalized IR snapshot from either C++ or Python pipeline."""
    source: str  # "cpp" or "python"
    stage: str   # "flow", "heritage", "full"
    blocks: List[NBlock] = field(default_factory=list)
    num_blocks: int = 0
    all_ops: List[NOp] = field(default_factory=list)
    num_ops: int = 0
    c_code: str = ""
    errors: str = ""


@dataclass
class DiffRecord:
    """Single classified difference entry."""
    category: str
    message: str
    expected: bool = False
    scope: str = "generic"


@dataclass
class StageDiff:
    """Differences found at a specific pipeline stage."""
    stage: str
    block_count_match: bool = True
    block_diffs: List[str] = field(default_factory=list)
    op_count_match: bool = True
    op_diffs: List[str] = field(default_factory=list)
    diff_records: List[DiffRecord] = field(default_factory=list)
    categorized_diffs: Dict[str, List[str]] = field(default_factory=dict)
    expected_diffs: Dict[str, List[str]] = field(default_factory=dict)
    summary_lines: List[str] = field(default_factory=list)

    @property
    def is_match(self) -> bool:
        return (self.block_count_match and
                not self.block_diffs and
                self.op_count_match and
                not self.op_diffs)

    @property
    def has_expected_diffs(self) -> bool:
        return any(self.expected_diffs.values())


def _append_diff(diff: StageDiff, category: str, message: str, *,
                 expected: bool = False, scope: str = "generic",
                 legacy_bucket: Optional[str] = None) -> None:
    """Append a classified difference while preserving legacy fields."""
    diff.diff_records.append(DiffRecord(
        category=category,
        message=message,
        expected=expected,
        scope=scope,
    ))
    if expected:
        diff.expected_diffs.setdefault(category, []).append(message)
        return
    diff.categorized_diffs.setdefault(category, []).append(message)
    if legacy_bucket == "block":
        diff.block_diffs.append(message)
    elif legacy_bucket == "op":
        diff.op_diffs.append(message)


def _format_category_counts(items: Dict[str, List[str]]) -> str:
    parts = [f"{name}={len(vals)}" for name, vals in sorted(items.items()) if vals]
    return ", ".join(parts)


def _is_expected_opcode_diff(cpp_op: NOp, py_op: NOp, stage: str) -> bool:
    """Known expected semantic differences between the pipelines."""
    if stage != "flow":
        return False
    pair = {cpp_op.opcode, py_op.opcode}
    # C++ may convert intra-function CALL→BRANCH
    if pair == {OpCode.CPUI_CALL.value, OpCode.CPUI_BRANCH.value}:
        return True
    # C++ truncateIndirectJump: BRANCHIND→CALLIND
    if pair == {OpCode.CPUI_CALLIND.value, OpCode.CPUI_BRANCHIND.value}:
        return True
    # C++ setupCallindSpecs: CALLIND→CALL (when target address is resolved)
    if pair == {OpCode.CPUI_CALL.value, OpCode.CPUI_CALLIND.value}:
        return True
    return False


def _is_expected_varnode_diff(cpp_op: NOp, py_op: NOp) -> bool:
    """True if the varnode diff is a known expected difference.

    Handles:
    - C++ fspec ptr vs Python raw address in CALL/CALLIND
    - Synthetic RETURN iop const varnode time difference
    """
    if cpp_op.addr != py_op.addr:
        return False

    # RETURN: iop const varnode (annotation encoding differs between pipelines).
    # C++ serialises the IOP-space annotation as const offset=1; Python may use
    # a different constant value.  All other inputs (output registers) must match.
    # Also handle halt/void returns where C++ has only the annotation (1 input)
    # while Python adds default output registers (extra register inputs).
    # Must be checked BEFORE the input-count guard below.
    if cpp_op.opcode == py_op.opcode == OpCode.CPUI_RETURN.value:
        if len(cpp_op.inputs) >= 1 and len(py_op.inputs) >= 1:
            ci = cpp_op.inputs[0]
            pi = py_op.inputs[0]
            if ci.space == "const" and pi.space == "const" and ci.size == pi.size:
                if len(cpp_op.inputs) == len(py_op.inputs):
                    # Same input count: check remaining inputs match exactly
                    if all(a == b for a, b in zip(cpp_op.inputs[1:], py_op.inputs[1:])):
                        return True
                elif len(cpp_op.inputs) == 1 and len(py_op.inputs) > 1:
                    # C++ halt/void: only annotation; Python adds output regs
                    if all(i.space == "register" for i in py_op.inputs[1:]):
                        return True

    # CALL/CALLIND: C++ may have more inputs than Python.
    # C++ resolves import symbols with locked prototypes, so
    # ActionFuncLink::funcLinkInput adds parameter register varnodes
    # (e.g. RCX, RDX, R8, R9 for x64 fastcall) to the CALL op.
    # Python has no function database, so CALL ops keep only the
    # target + stack placeholder.  This is a pre-Heritage representation
    # difference, not a Heritage semantics issue (Heritage creates the
    # same INDIRECT ops regardless of CALL input varnodes).
    call_opcodes = {OpCode.CPUI_CALL.value, OpCode.CPUI_CALLIND.value}

    def _vn_match_call(a: NVarnode, b: NVarnode) -> bool:
        """Relaxed varnode match for CALL inputs: tolerate unique-space offsets."""
        if a == b:
            return True
        if a.space == "unique" and b.space == "unique" and a.size == b.size:
            return True
        return False

    if cpp_op.opcode in call_opcodes and py_op.opcode in call_opcodes:
        n_cpp = len(cpp_op.inputs)
        n_py = len(py_op.inputs)
        if n_cpp >= n_py >= 1:
            # C++ locked prototypes may insert extra register inputs at
            # arbitrary positions (not just appended at end).  Check that
            # all Python inputs appear as a subsequence in C++ inputs and
            # all unmatched C++ inputs are register varnodes.
            ci0 = cpp_op.inputs[0]
            pi0 = py_op.inputs[0]
            target_ok = (ci0 == pi0) or (ci0.is_fspec_ptr and not pi0.is_fspec_ptr) or _vn_match_call(ci0, pi0)
            if target_ok:
                # Try to match Python inputs[1:] as subsequence of C++ inputs[1:]
                cpp_rest = cpp_op.inputs[1:]
                py_rest = py_op.inputs[1:]
                ci = 0
                pi = 0
                unmatched_ok = True
                while pi < len(py_rest) and ci < len(cpp_rest):
                    if _vn_match_call(cpp_rest[ci], py_rest[pi]):
                        pi += 1
                        ci += 1
                    elif cpp_rest[ci].space == "register":
                        ci += 1  # skip extra C++ register input
                    else:
                        unmatched_ok = False
                        break
                # All remaining C++ inputs must be registers
                while ci < len(cpp_rest):
                    if cpp_rest[ci].space != "register":
                        unmatched_ok = False
                        break
                    ci += 1
                if unmatched_ok and pi == len(py_rest):
                    return True

    if len(cpp_op.inputs) != len(py_op.inputs):
        return False

    # CALL/CALLIND: fspec vs ram target encoding (same input count)
    if cpp_op.opcode in call_opcodes and py_op.opcode in call_opcodes:
        if len(cpp_op.inputs) >= 1:
            ci = cpp_op.inputs[0]
            pi = py_op.inputs[0]
            if ci.is_fspec_ptr and not pi.is_fspec_ptr:
                return True

    # Unique-space offset differences: C++ and Python allocate unique-space
    # temporaries at different offsets.  If all non-unique varnodes match and
    # the only differences are unique-space offsets (with matching sizes),
    # treat as expected.
    def _vn_match_relaxed(a: NVarnode, b: NVarnode) -> bool:
        if a == b:
            return True
        if a.space == "unique" and b.space == "unique" and a.size == b.size:
            return True
        return False

    if cpp_op.opcode == py_op.opcode:
        out_ok = True
        if cpp_op.output is not None and py_op.output is not None:
            out_ok = _vn_match_relaxed(cpp_op.output, py_op.output)
        elif (cpp_op.output is None) != (py_op.output is None):
            out_ok = False
        inp_ok = all(_vn_match_relaxed(a, b)
                     for a, b in zip(cpp_op.inputs, py_op.inputs))
        if out_ok and inp_ok:
            return True

    return False


@dataclass
class CompareReport:
    """Full comparison report across all stages."""
    sla_path: str
    target: str
    entry: int
    stage_diffs: Dict[str, StageDiff] = field(default_factory=dict)
    cpp_snapshots: Dict[str, IrSnapshot] = field(default_factory=dict)
    py_snapshots: Dict[str, IrSnapshot] = field(default_factory=dict)
    errors: List[str] = field(default_factory=list)

    def summary(self) -> str:
        lines = []
        lines.append("=" * 60)
        lines.append(f"Bridge Validator Report: func @ 0x{self.entry:x}")
        lines.append(f"  SLA: {os.path.basename(self.sla_path)}")
        lines.append(f"  Target: {self.target}")
        lines.append("=" * 60)

        if self.errors:
            lines.append("\n[ERRORS]")
            for e in self.errors:
                lines.append(f"  ! {e}")

        for stage, diff in self.stage_diffs.items():
            if diff.is_match and diff.has_expected_diffs:
                status = "EXPECTED_DIFF"
            else:
                status = "MATCH" if diff.is_match else "DIFF"
            lines.append(f"\n--- Stage: {stage} [{status}] ---")
            for sl in diff.summary_lines:
                lines.append(f"  {sl}")
            if diff.expected_diffs:
                lines.append("  Expected differences:")
                for cat, msgs in sorted(diff.expected_diffs.items()):
                    lines.append(f"    [{cat}] {len(msgs)}")
                    for msg in msgs[:10]:
                        lines.append(f"      {msg}")
                    if len(msgs) > 10:
                        lines.append(f"      ... and {len(msgs) - 10} more")
            if diff.block_diffs:
                lines.append("  Block differences:")
                for bd in diff.block_diffs[:20]:
                    lines.append(f"    {bd}")
                if len(diff.block_diffs) > 20:
                    lines.append(f"    ... and {len(diff.block_diffs) - 20} more")
            if diff.op_diffs:
                lines.append("  Op differences:")
                for od in diff.op_diffs[:30]:
                    lines.append(f"    {od}")
                if len(diff.op_diffs) > 30:
                    lines.append(f"    ... and {len(diff.op_diffs) - 30} more")

        lines.append("")
        all_match = all(d.is_match for d in self.stage_diffs.values())
        lines.append(f"Overall: {'ALL STAGES MATCH' if all_match else 'DIFFERENCES FOUND'}")
        lines.append("=" * 60)
        return "\n".join(lines)


# ---------------------------------------------------------------------------
# Snapshot extraction helpers
# ---------------------------------------------------------------------------

def _snapshot_from_cpp_dict(stage: str, cpp_ir: Dict[str, Any]) -> IrSnapshot:
    """Convert the C++ decompile_staged() result dict into an IrSnapshot."""
    snap = IrSnapshot(source="cpp", stage=stage)
    ir = cpp_ir.get("ir", {})

    snap.num_blocks = ir.get("num_blocks", 0)
    snap.num_ops = ir.get("num_ops", 0)

    for bd in ir.get("blocks", []):
        ops = []
        for od in bd.get("ops", []):
            out_d = od.get("output")
            output = None
            if out_d is not None:
                output = NVarnode(out_d["space"], out_d["offset"], out_d["size"])
            inputs = [NVarnode(i["space"], i["offset"], i["size"]) for i in od.get("inputs", [])]
            ops.append(NOp(od["opcode"], od["addr"], od["seq_order"], output, inputs))

        snap.blocks.append(NBlock(
            index=bd["index"],
            start=bd["start"],
            stop=bd["stop"],
            successors=list(bd.get("successors", [])),
            predecessors=list(bd.get("predecessors", [])),
            ops=ops,
            num_ops=bd.get("num_ops", len(ops)),
        ))

    for od in ir.get("all_ops", []):
        out_d = od.get("output")
        output = None
        if out_d is not None:
            output = NVarnode(out_d["space"], out_d["offset"], out_d["size"])
        inputs = [NVarnode(i["space"], i["offset"], i["size"]) for i in od.get("inputs", [])]
        snap.all_ops.append(NOp(od["opcode"], od["addr"], od["seq_order"], output, inputs))

    snap.c_code = cpp_ir.get("c_code", "")
    snap.errors = cpp_ir.get("errors", "")
    return snap


def _snapshot_from_python_fd(stage: str, fd) -> IrSnapshot:
    """Extract an IrSnapshot from a Python Funcdata object."""
    snap = IrSnapshot(source="python", stage=stage)

    bblocks = fd.getBasicBlocks()
    snap.num_blocks = bblocks.getSize()

    for bi in range(bblocks.getSize()):
        bb = bblocks.getBlock(bi)
        ops_list = bb.getOpList() if hasattr(bb, 'getOpList') else []
        ops = []
        for op in ops_list:
            out = op.getOut()
            output = None
            if out is not None:
                output = NVarnode(out.getSpace().getName(), out.getAddr().getOffset(), out.getSize())
            inputs = []
            for k in range(op.numInput()):
                inv = op.getIn(k)
                if inv is not None:
                    inputs.append(NVarnode(inv.getSpace().getName(), inv.getAddr().getOffset(), inv.getSize()))
            ops.append(NOp(
                opcode=op.code().value if hasattr(op.code(), 'value') else int(op.code()),
                addr=op.getSeqNum().getAddr().getOffset(),
                seq_order=op.getSeqNum().getOrder(),
                output=output,
                inputs=inputs,
            ))
        snap.all_ops.extend(ops)

        entry = bb.getEntryAddr() if hasattr(bb, 'getEntryAddr') else None
        start = entry.getOffset() if entry and not entry.isInvalid() else 0
        stop_addr = bb.getStop() if hasattr(bb, 'getStop') else None
        stop = stop_addr.getOffset() if stop_addr and hasattr(stop_addr, 'getOffset') else start

        succs = [bb.getOut(j).getIndex() for j in range(bb.sizeOut())] if hasattr(bb, 'sizeOut') else []
        preds = [bb.getIn(j).getIndex() for j in range(bb.sizeIn())] if hasattr(bb, 'sizeIn') else []

        snap.blocks.append(NBlock(
            index=bb.getIndex() if hasattr(bb, 'getIndex') else bi,
            start=start,
            stop=stop,
            successors=succs,
            predecessors=preds,
            ops=ops,
            num_ops=len(ops),
        ))

    snap.num_ops = len(snap.all_ops)
    return snap


# ---------------------------------------------------------------------------
# Comparison logic
# ---------------------------------------------------------------------------

def _remap_edges(blocks: List[NBlock], idx_to_addr: Dict[int, int],
                  addr_to_canonical: Dict[int, int]) -> None:
    """Remap successor/predecessor indices through address-based canonical mapping."""
    for b in blocks:
        b.successors = sorted(
            addr_to_canonical.get(idx_to_addr.get(s, -1), s)
            for s in b.successors
        )
        b.predecessors = sorted(
            addr_to_canonical.get(idx_to_addr.get(p, -1), p)
            for p in b.predecessors
        )


def _compare_snapshots(cpp_snap: IrSnapshot, py_snap: IrSnapshot, stage: str) -> StageDiff:
    """Compare two IR snapshots and produce a diff.

    Blocks are matched by start address (not by index) to handle
    different block orderings between C++ (DFS) and Python (address order).
    """
    diff = StageDiff(stage=stage)

    # Block count
    if cpp_snap.num_blocks != py_snap.num_blocks:
        diff.block_count_match = False
        diff.summary_lines.append(
            f"Block count: C++={cpp_snap.num_blocks}, Python={py_snap.num_blocks}")
    else:
        diff.summary_lines.append(f"Block count: {cpp_snap.num_blocks} (match)")

    # Op count
    if cpp_snap.num_ops != py_snap.num_ops:
        diff.op_count_match = False
        diff.summary_lines.append(
            f"Op count: C++={cpp_snap.num_ops}, Python={py_snap.num_ops}")
    else:
        diff.summary_lines.append(f"Op count: {cpp_snap.num_ops} (match)")

    # Build index→address maps for edge remapping
    cpp_idx_to_addr = {b.index: b.start for b in cpp_snap.blocks}
    py_idx_to_addr = {b.index: b.start for b in py_snap.blocks}

    # Canonical index = sorted unique address order
    all_addrs = sorted(set(b.start for b in cpp_snap.blocks) |
                       set(b.start for b in py_snap.blocks))
    addr_to_canonical = {addr: i for i, addr in enumerate(all_addrs)}

    # Remap edges on original blocks FIRST (before merging)
    _remap_edges(cpp_snap.blocks, cpp_idx_to_addr, addr_to_canonical)
    _remap_edges(py_snap.blocks, py_idx_to_addr, addr_to_canonical)

    # Build address-based block maps AFTER remapping.  When multiple blocks
    # share the same start address (multiple pcode ops from one machine
    # instruction split into separate blocks), merge into one virtual block.
    def _build_addr_map(blocks: List[NBlock]) -> Dict[int, NBlock]:
        m: Dict[int, NBlock] = {}
        for b in blocks:
            if b.start not in m:
                m[b.start] = b
            else:
                existing = m[b.start]
                merged_ops = list(existing.ops) + list(b.ops)
                merged_stop = max(existing.stop, b.stop)
                # Deduplicate remapped canonical successor/predecessor indices
                merged_succs = sorted(set(existing.successors + b.successors))
                merged_preds = sorted(set(existing.predecessors + b.predecessors))
                m[b.start] = NBlock(
                    index=existing.index,
                    start=existing.start,
                    stop=merged_stop,
                    successors=merged_succs,
                    predecessors=merged_preds,
                    ops=merged_ops,
                    num_ops=len(merged_ops),
                )
        return m

    cpp_by_addr = _build_addr_map(cpp_snap.blocks)
    py_by_addr = _build_addr_map(py_snap.blocks)

    # Compare blocks matched by address
    matched_addrs = sorted(set(cpp_by_addr.keys()) & set(py_by_addr.keys()))
    cpp_only = sorted(set(cpp_by_addr.keys()) - set(py_by_addr.keys()))
    py_only = sorted(set(py_by_addr.keys()) - set(cpp_by_addr.keys()))

    for addr in matched_addrs:
        cb = cpp_by_addr[addr]
        pb = py_by_addr[addr]
        ci = addr_to_canonical[addr]

        if cb.stop != pb.stop:
            _append_diff(
                diff, "block",
                f"Block[{ci}] @0x{addr:x} stop: C++=0x{cb.stop:x}, Py=0x{pb.stop:x}",
                scope="block", legacy_bucket="block")
        if cb.successors != pb.successors:
            _append_diff(
                diff, "edge",
                f"Block[{ci}] @0x{addr:x} succs: C++={cb.successors}, Py={pb.successors}",
                scope="block", legacy_bucket="block")
        if cb.predecessors != pb.predecessors:
            _append_diff(
                diff, "edge",
                f"Block[{ci}] @0x{addr:x} preds: C++={cb.predecessors}, Py={pb.predecessors}",
                scope="block", legacy_bucket="block")
        if cb.num_ops != pb.num_ops:
            _append_diff(
                diff, "block",
                f"Block[{ci}] @0x{addr:x} ops: C++={cb.num_ops}, Py={pb.num_ops}",
                scope="block", legacy_bucket="block")

        # Per-op comparison within matched block.
        # 1) MULTIEQUALs at block start are order-independent (phi-nodes).
        # 2) Ops at the same address (e.g. SUBPIECEs from splitJoin, or
        #    INDIRECTs from guardCalls) may be in any order.
        # Sort groups of same-opcode-same-address ops to canonicalize.
        def _op_sort_key(op):
            """Sort key for ops: by output varnode address."""
            if op.output is not None:
                return (op.output.space, op.output.offset, op.output.size)
            return ("", 0, 0)

        def _normalize_op_order(ops):
            """Move all MULTIEQUALs to front (matching C++ opInsertBegin),
            sort them, then sort adjacent same-addr non-MEQ ops."""
            ops = list(ops)
            # Phase 1: gather ALL MULTIEQUALs and move to front.
            # When multiple sub-blocks at the same address are merged,
            # MEQs from a later sub-block may appear after non-MEQs
            # from an earlier sub-block.  C++ always places MEQs at
            # the very beginning of a block.
            meqs = [op for op in ops if op.opcode == OpCode.CPUI_MULTIEQUAL]
            non_meqs = [op for op in ops if op.opcode != OpCode.CPUI_MULTIEQUAL]
            if meqs:
                meqs.sort(key=_op_sort_key)
            ops = meqs + non_meqs
            meq_end = len(meqs)
            # Phase 2: sort adjacent groups of non-MEQ ops at the same address
            i = meq_end
            while i < len(ops):
                j = i + 1
                while j < len(ops) and ops[j].addr == ops[i].addr:
                    j += 1
                if j - i > 1:
                    ops[i:j] = sorted(ops[i:j], key=_op_sort_key)
                i = j
            return ops

        c_ops = _normalize_op_order(cb.ops)
        p_ops = _normalize_op_order(pb.ops)
        n_ops = min(len(c_ops), len(p_ops))
        for j in range(n_ops):
            co = c_ops[j]
            po = p_ops[j]
            if not co.matches(po, strict=False):
                if co.opcode != po.opcode:
                    msg = f"Block[{ci}] Op[{j}] opcode: C++={co} | Py={po}"
                    _append_diff(
                        diff, "opcode", msg,
                        expected=_is_expected_opcode_diff(co, po, stage),
                        scope="op", legacy_bucket="op")
                else:
                    msg = f"Block[{ci}] Op[{j}] varnode: C++={co} | Py={po}"
                    _append_diff(
                        diff, "varnode", msg,
                        expected=_is_expected_varnode_diff(co, po),
                        scope="op", legacy_bucket="op")

    for addr in cpp_only:
        ci = addr_to_canonical[addr]
        _append_diff(
            diff, "block",
            f"Block[{ci}] only in C++: {cpp_by_addr[addr]}",
            scope="block", legacy_bucket="block")
    for addr in py_only:
        ci = addr_to_canonical[addr]
        _append_diff(
            diff, "block",
            f"Block[{ci}] only in Python: {py_by_addr[addr]}",
            scope="block", legacy_bucket="block")

    unexpected_counts = _format_category_counts(diff.categorized_diffs)
    expected_counts = _format_category_counts(diff.expected_diffs)
    if unexpected_counts:
        diff.summary_lines.append(f"Unexpected diff categories: {unexpected_counts}")
    if expected_counts:
        diff.summary_lines.append(f"Expected diff categories: {expected_counts}")

    return diff


# ---------------------------------------------------------------------------
# Main validator class
# ---------------------------------------------------------------------------

class BridgeValidator:
    """Snapshot comparison bridge between C++ and Python decompiler pipelines.

    Runs both pipelines on the same input and compares IR at each stage.
    """

    def __init__(self, spec_dir: Optional[str] = None, ghidra_root: Optional[str] = None):
        self._spec_dir = spec_dir
        self._ghidra_root = ghidra_root
        self._cpp_engine = None
        self._py_engine = None

    def _ensure_engines(self):
        """Lazily create both C++ and Python decompiler engines."""
        if self._cpp_engine is None:
            from ghidra.sleigh.decompiler_native import DecompilerNative
            self._cpp_engine = DecompilerNative()
            if self._spec_dir:
                self._cpp_engine.add_spec_path(self._spec_dir)
            if self._ghidra_root:
                self._cpp_engine.add_ghidra_root(self._ghidra_root)
            self._cpp_engine.initialize()

        if self._py_engine is None:
            from ghidra.sleigh.decompiler_python import DecompilerPython
            self._py_engine = DecompilerPython()
            if self._spec_dir:
                self._py_engine.add_spec_path(self._spec_dir)
            if self._ghidra_root:
                self._py_engine.add_ghidra_root(self._ghidra_root)
            self._py_engine.initialize()

    def _get_cpp_snapshot(self, sla_path: str, target: str,
                          image: bytes, base_addr: int,
                          entry: int, func_size: int,
                          stage: str) -> IrSnapshot:
        """Run C++ pipeline to a stage and capture snapshot."""
        result = self._cpp_engine.decompile_staged(
            sla_path, target, image, base_addr, entry, func_size, stage)
        return _snapshot_from_cpp_dict(stage, result)

    def _get_python_snapshot(self, sla_path: str, target: str,
                             image: bytes, base_addr: int,
                             entry: int, func_size: int,
                             stage: str) -> IrSnapshot:
        """Run Python pipeline to a stage and capture snapshot."""
        from ghidra.sleigh.lifter import Lifter
        from ghidra.sleigh.decompiler_python import _split_basic_blocks, _ArchitectureShim

        from ghidra.sleigh.arch_map import default_context_for_target

        context = default_context_for_target(target)

        lifter = Lifter(sla_path, context)
        lifter.set_image(base_addr, image)
        func_name = f"func_{entry:x}"
        fd = lifter.lift_function(func_name, entry, func_size)

        if stage in ("flow", "heritage", "full"):
            _split_basic_blocks(fd)

        if stage in ("heritage", "full"):
            arch_shim = _ArchitectureShim(lifter._spc_mgr)
            fd.setArch(arch_shim)
            try:
                fd.opHeritage()
            except Exception as e:
                snap = _snapshot_from_python_fd(stage, fd)
                snap.errors = f"Heritage error: {e}"
                return snap

        return _snapshot_from_python_fd(stage, fd)

    def compare(self, sla_path: str, target: str,
                image: bytes, base_addr: int,
                entry: int, func_size: int = 0,
                stages: Optional[List[str]] = None) -> CompareReport:
        """Run both pipelines and compare at specified stages.

        Args:
            sla_path: Path to the .sla file
            target: Language id (e.g. 'x86:LE:64:default')
            image: Raw binary bytes
            base_addr: Base address
            entry: Function entry point
            func_size: Function size in bytes
            stages: List of stages to compare: "flow", "heritage", "full"
                    Defaults to ["flow"]

        Returns:
            CompareReport with per-stage diffs
        """
        if stages is None:
            stages = ["flow"]

        self._ensure_engines()

        report = CompareReport(sla_path=sla_path, target=target, entry=entry)

        for stage in stages:
            try:
                cpp_snap = self._get_cpp_snapshot(
                    sla_path, target, image, base_addr, entry, func_size, stage)
                report.cpp_snapshots[stage] = cpp_snap
            except Exception as e:
                report.errors.append(f"C++ {stage} error: {e}")
                continue

            try:
                py_snap = self._get_python_snapshot(
                    sla_path, target, image, base_addr, entry, func_size, stage)
                report.py_snapshots[stage] = py_snap
            except Exception as e:
                report.errors.append(f"Python {stage} error: {e}")
                continue

            diff = _compare_snapshots(cpp_snap, py_snap, stage)
            report.stage_diffs[stage] = diff

        return report
