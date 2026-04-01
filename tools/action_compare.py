#!/usr/bin/env python3
"""
Action-level comparison between C++ and Python decompiler engines.

For each function, runs both engines through their full pipelines and
compares the IR state at key stages (flow / heritage / full) plus the
final C-code output.

The Python engine is additionally instrumented to capture IR summaries
after each top-level action in the pipeline, so divergences can be
narrowed down to a specific action.

Usage:
    python action_compare.py examples/cp.exe 0x401000
    python action_compare.py examples/cp.exe 0x401000 --detail
    python action_compare.py examples/cp.exe --batch 0x401000 0x401020
    python action_compare.py examples/cp.exe --scan --limit 5
"""

from __future__ import annotations

import argparse
import os
import struct
import sys
import time
import traceback
from collections import Counter
from typing import Any, Dict, List, Optional, Tuple

# ---------------------------------------------------------------------------
# Ensure src/ is on sys.path
# ---------------------------------------------------------------------------
_TOOLS_DIR = os.path.dirname(os.path.abspath(__file__))
_PROJECT_ROOT = os.path.dirname(_TOOLS_DIR)
_SRC_DIR = os.path.join(_PROJECT_ROOT, "src")
if _SRC_DIR not in sys.path:
    sys.path.insert(0, _SRC_DIR)


# ===========================================================================
# Opcode name table (matches C++ OpCode enum values)
# ===========================================================================
_OPCODE_NAMES: Dict[int, str] = {}


def _init_opcode_names() -> None:
    global _OPCODE_NAMES
    if _OPCODE_NAMES:
        return
    try:
        from ghidra.core.opcodes import OpCode
        for member in OpCode:
            _OPCODE_NAMES[int(member)] = member.name
    except Exception:
        pass


def opcode_name(code: int) -> str:
    _init_opcode_names()
    return _OPCODE_NAMES.get(code, f"OP_{code}")


# ===========================================================================
# Minimal PE parser (same as console.py)
# ===========================================================================
class PEInfo:
    def __init__(self, path: str) -> None:
        self.path = path
        with open(path, "rb") as f:
            self.data = f.read()
        self.image_base: int = 0
        self.bitness: int = 32
        self.entry_rva: int = 0
        self.sections: List[Dict[str, Any]] = []
        self._parse()

    def _parse(self) -> None:
        if self.data[:2] != b"MZ":
            raise ValueError(f"Not a PE file: {self.path}")
        pe_off = struct.unpack_from("<I", self.data, 0x3C)[0]
        if self.data[pe_off:pe_off + 4] != b"PE\x00\x00":
            raise ValueError("Invalid PE signature")
        coff = pe_off + 4
        num_sections = struct.unpack_from("<H", self.data, coff + 2)[0]
        opt_hdr_size = struct.unpack_from("<H", self.data, coff + 16)[0]
        opt = coff + 20
        magic = struct.unpack_from("<H", self.data, opt)[0]
        if magic == 0x20B:
            self.bitness = 64
            self.entry_rva = struct.unpack_from("<I", self.data, opt + 16)[0]
            self.image_base = struct.unpack_from("<Q", self.data, opt + 24)[0]
        else:
            self.bitness = 32
            self.entry_rva = struct.unpack_from("<I", self.data, opt + 16)[0]
            self.image_base = struct.unpack_from("<I", self.data, opt + 28)[0]
        sec_start = opt + opt_hdr_size
        for i in range(num_sections):
            off = sec_start + i * 40
            name = self.data[off:off + 8].rstrip(b'\x00').decode('ascii', 'replace')
            vsize = struct.unpack_from("<I", self.data, off + 8)[0]
            rva = struct.unpack_from("<I", self.data, off + 12)[0]
            rawsz = struct.unpack_from("<I", self.data, off + 16)[0]
            rawoff = struct.unpack_from("<I", self.data, off + 20)[0]
            chars = struct.unpack_from("<I", self.data, off + 36)[0]
            self.sections.append({
                "name": name, "rva": rva, "vsize": vsize,
                "rawoff": rawoff, "rawsz": rawsz, "chars": chars,
            })

    def flat_image(self) -> bytes:
        """Build a flat memory image with sections mapped at their RVAs.

        The returned buffer is indexed as: buf[va - image_base].
        This matches what BufferImage.loadFill() expects.
        """
        # Find the total virtual size needed
        max_va = 0
        for sec in self.sections:
            end = sec["rva"] + max(sec["vsize"], sec["rawsz"])
            if end > max_va:
                max_va = end
        buf = bytearray(max_va)
        # Map each section
        for sec in self.sections:
            raw = self.data[sec["rawoff"]:sec["rawoff"] + sec["rawsz"]]
            buf[sec["rva"]:sec["rva"] + len(raw)] = raw
        return bytes(buf)


# ===========================================================================
# Architecture resolution
# ===========================================================================
def resolve_pe_arch(pe: PEInfo) -> Tuple[str, str, str]:
    """Return (sla_path, target_string, spec_dir)."""
    from ghidra.sleigh.arch_map import resolve_arch
    proc = "metapc"
    is_be = False  # PE is always little-endian
    info = resolve_arch(proc, pe.bitness, is_be)
    if info is None:
        raise RuntimeError(f"Cannot resolve arch for {proc}/{pe.bitness}")
    sla_path = info["sla_path"]
    target = info["target"]
    spec_dir = os.path.dirname(sla_path)
    return sla_path, target, spec_dir


# ===========================================================================
# IR Snapshot — a lightweight, comparable summary of the IR state
# ===========================================================================
class IRSnapshot:
    """Lightweight summary of a Funcdata or C++ IR dict state."""

    def __init__(self) -> None:
        self.num_blocks: int = 0
        self.num_ops: int = 0
        self.opcode_counts: Counter = Counter()
        self.block_summaries: List[str] = []
        # Canonical text lines for detailed diff
        self.lines: List[str] = []

    @staticmethod
    def from_cpp_dict(ir: Dict[str, Any]) -> IRSnapshot:
        """Build from C++ decompile_staged dumpIr dict."""
        snap = IRSnapshot()
        snap.num_blocks = ir.get("num_blocks", 0)
        snap.num_ops = ir.get("num_ops", 0)

        for block in ir.get("blocks", []):
            idx = block["index"]
            start = block["start"]
            stop = block["stop"]
            succs = block["successors"]
            preds = block["predecessors"]
            nops = block.get("num_ops", len(block.get("ops", [])))
            hdr = (f"BLOCK idx={idx} start=0x{start:x} stop=0x{stop:x} "
                   f"succs={succs} preds={preds} ops={nops}")
            snap.block_summaries.append(hdr)
            snap.lines.append(hdr)

            for op in block.get("ops", []):
                opc = op["opcode"]
                snap.opcode_counts[opc] += 1
                name = opcode_name(opc)
                addr = op["addr"]
                seq = op.get("seq_order", 0)
                out = _fmt_cpp_vn(op.get("output")) if op.get("output") else "---"
                ins = ", ".join(_fmt_cpp_vn(v) for v in op.get("inputs", []))
                line = f"  {name} {out} <- {ins}  @0x{addr:x} #{seq}"
                snap.lines.append(line)
        return snap

    @staticmethod
    def from_python_fd(fd) -> IRSnapshot:
        """Build from a Python Funcdata object."""
        from ghidra.block.block import FlowBlock
        snap = IRSnapshot()
        bblocks = fd.getBasicBlocks()
        snap.num_blocks = bblocks.getSize()

        total_ops = 0
        for i in range(bblocks.getSize()):
            bl = bblocks.getBlock(i)
            idx = bl.getIndex()
            try:
                start = bl.getStart().getOffset()
            except Exception:
                start = 0
            try:
                stop = bl.getStop().getOffset()
            except Exception:
                stop = 0
            succs = [bl.getOut(j).getIndex() for j in range(bl.sizeOut())]
            preds = [bl.getIn(j).getIndex() for j in range(bl.sizeIn())]

            ops = []
            if bl.getType() == FlowBlock.t_basic and hasattr(bl, 'getOpList'):
                ops = bl.getOpList()

            nops = len(ops)
            total_ops += nops
            hdr = (f"BLOCK idx={idx} start=0x{start:x} stop=0x{stop:x} "
                   f"succs={succs} preds={preds} ops={nops}")
            snap.block_summaries.append(hdr)
            snap.lines.append(hdr)

            for op in ops:
                opc = int(op.code())
                snap.opcode_counts[opc] += 1
                name = opcode_name(opc)
                addr_off = op.getAddr().getOffset() if op.getAddr() else 0
                seq = op.getSeqNum().getOrder() if hasattr(op, 'getSeqNum') and op.getSeqNum() else 0
                out_vn = op.getOut()
                out = _fmt_py_vn(out_vn) if out_vn else "---"
                ins = ", ".join(_fmt_py_vn(op.getIn(k)) for k in range(op.numInput()))
                line = f"  {name} {out} <- {ins}  @0x{addr_off:x} #{seq}"
                snap.lines.append(line)

        snap.num_ops = total_ops
        return snap

    def summary_str(self) -> str:
        return f"blocks={self.num_blocks} ops={self.num_ops}"

    def opcode_summary(self) -> str:
        top = self.opcode_counts.most_common(10)
        parts = [f"{opcode_name(opc)}={cnt}" for opc, cnt in top]
        return ", ".join(parts)


def _fmt_cpp_vn(vn: Optional[Dict]) -> str:
    if vn is None:
        return "---"
    return f"{vn['space']}:0x{vn['offset']:x}:{vn['size']}"


def _fmt_py_vn(vn) -> str:
    if vn is None:
        return "---"
    sp = vn.getSpace()
    sp_name = sp.getName() if sp and hasattr(sp, 'getName') else "?"
    return f"{sp_name}:0x{vn.getOffset():x}:{vn.getSize()}"


# ===========================================================================
# C++ engine runner
# ===========================================================================
def run_cpp_staged(sla: str, target: str, spec_dir: str,
                   image: bytes, base: int, entry: int,
                   func_size: int, stage: str) -> Tuple[Optional[IRSnapshot], str, str, float]:
    """Run C++ decompile_staged and return (snapshot, c_code, error, time).

    Returns (None, "", error_msg, time) on failure.
    """
    try:
        from ghidra.sleigh.decompiler_native import DecompilerNative
    except ImportError:
        return None, "", "decompiler_native.pyd not found", 0.0

    dn = DecompilerNative()
    dn.add_spec_path(spec_dir)
    dn.initialize()

    t0 = time.perf_counter()
    try:
        result = dn.decompile_staged(sla, target, image, base, entry, func_size, stage)
    except Exception as e:
        return None, "", str(e), time.perf_counter() - t0
    elapsed = time.perf_counter() - t0

    ir_dict = result.get("ir", {})
    c_code = result.get("c_code", "")
    errors = result.get("errors", "")

    snap = IRSnapshot.from_cpp_dict(ir_dict)
    return snap, c_code, errors, elapsed


# ===========================================================================
# Python engine runner (staged)
# ===========================================================================
def run_py_staged(sla: str, target: str, spec_dir: str,
                  image: bytes, base: int, entry: int,
                  func_size: int, stage: str) -> Tuple[Optional[IRSnapshot], str, str, float]:
    """Run Python decompiler at a specific stage.

    Returns (snapshot, c_code_or_raw, error, time).
    """
    from ghidra.sleigh.decompiler_python import DecompilerPython

    dp = DecompilerPython()
    dp.add_spec_path(spec_dir)
    dp.initialize()

    # Configure stage
    dp.use_python_ir = True
    dp.use_python_flow = True
    dp.use_python_heritage = (stage in ("heritage", "full"))
    dp.use_python_rules = (stage == "full")
    dp.use_python_full_actions = (stage == "full")
    dp.use_python_printc = (stage == "full")

    t0 = time.perf_counter()
    try:
        code = dp.decompile(sla, target, image, base, entry, func_size)
    except Exception as e:
        return None, "", str(e), time.perf_counter() - t0
    elapsed = time.perf_counter() - t0

    errors = dp.get_errors()
    # We can't easily get the IR snapshot from the high-level API
    # since decompile() returns only the code string.
    # For detailed IR comparison we use the instrumented runner below.
    return None, code, errors, elapsed


# ===========================================================================
# Python engine — instrumented per-action runner
# ===========================================================================
class ActionLog:
    """Collects per-action IR summaries during the Python pipeline."""

    def __init__(self) -> None:
        self.entries: List[Dict[str, Any]] = []

    def record(self, name: str, fd, elapsed: float, error: str = "") -> None:
        if error:
            self.entries.append({"name": name, "error": error, "elapsed": elapsed})
            return
        try:
            snap = IRSnapshot.from_python_fd(fd)
            self.entries.append({
                "name": name,
                "blocks": snap.num_blocks,
                "ops": snap.num_ops,
                "opcode_summary": snap.opcode_summary(),
                "elapsed": elapsed,
            })
        except Exception as e:
            self.entries.append({"name": name, "error": f"snapshot: {e}", "elapsed": elapsed})


def run_py_instrumented(sla: str, target: str, spec_dir: str,
                        image: bytes, base: int, entry: int,
                        func_size: int,
                        timeout: float = 30.0) -> Tuple[Optional[IRSnapshot], str, ActionLog, str, float]:
    """Run Python decompiler with per-action instrumentation.

    Returns (final_snapshot, c_code, action_log, errors, total_time).
    """
    from ghidra.sleigh.lifter import Lifter
    from ghidra.sleigh.arch_map import add_sla_search_dir
    from ghidra.arch.archshim import ArchitectureStandalone
    from ghidra.analysis.flowlifter import _split_basic_blocks, _setup_call_specs
    from ghidra.transform.pipeline import _seed_default_return_output
    from ghidra.transform.action import ActionDatabase
    from ghidra.output.emit_helpers import _printc_from_funcdata, _raw_c_from_funcdata

    add_sla_search_dir(spec_dir)
    action_log = ActionLog()
    errors = ""

    t_total_start = time.perf_counter()

    try:
        # 1. Lift
        parts = target.split(":")
        context = {}
        if len(parts) >= 3:
            bitness = int(parts[2])
            if bitness == 32 and "x86" in parts[0].lower():
                context = {"addrsize": 1, "opsize": 1}

        lifter = Lifter(sla, context)
        lifter.set_image(base, image)
        fd = lifter.lift_function(f"func_{entry:x}", entry, func_size)

        # 2. Flow (CFG)
        t0 = time.perf_counter()
        _split_basic_blocks(fd, lifter=lifter)
        action_log.record("flow", fd, time.perf_counter() - t0)

        # 3. Attach architecture
        arch = ArchitectureStandalone(lifter._spc_mgr)
        fd.setArch(arch)
        _setup_call_specs(fd, lifter=lifter)
        _seed_default_return_output(fd, target)

        # 4. Build full action chain
        allacts = ActionDatabase()
        allacts.universalAction(arch)
        allacts.resetDefaults()
        root = allacts.getCurrent()
        if root is None:
            return None, "", action_log, "No current action", time.perf_counter() - t_total_start

        root.reset(fd)

        # Set cooperative deadline for ActionPool inner loop
        from ghidra.transform.action import Action as _Act
        _Act.set_deadline(timeout)

        # 5. Instrument top-level children and run
        try:
            if hasattr(root, '_list') and root._list:
                for act_child in root._list:
                    # Check total elapsed time budget
                    elapsed_total = time.perf_counter() - t_total_start
                    if elapsed_total > timeout:
                        errors += f"TIMEOUT after {elapsed_total:.1f}s\n"
                        break
                    name = act_child.getName()
                    t0 = time.perf_counter()
                    try:
                        act_child.perform(fd)
                        action_log.record(name, fd, time.perf_counter() - t0)
                    except TimeoutError:
                        action_log.record(name, fd, time.perf_counter() - t0, "TIMEOUT")
                        errors += f"Action {name}: TIMEOUT\n"
                        break
                    except Exception as e:
                        action_log.record(name, fd, time.perf_counter() - t0, str(e))
                        errors += f"Action {name}: {e}\n"
                        break
            else:
                t0 = time.perf_counter()
                try:
                    root.perform(fd)
                    action_log.record("root", fd, time.perf_counter() - t0)
                except TimeoutError:
                    action_log.record("root", fd, time.perf_counter() - t0, "TIMEOUT")
                    errors += "Root action: TIMEOUT\n"
                except Exception as e:
                    action_log.record("root", fd, time.perf_counter() - t0, str(e))
                    errors += f"Root action: {e}\n"
        finally:
            _Act.clear_deadline()

        # 6. Final snapshot
        final_snap = IRSnapshot.from_python_fd(fd)

        # 7. C code
        c_code = ""
        try:
            c_code = _printc_from_funcdata(fd)
            if not c_code or not c_code.strip():
                c_code = _raw_c_from_funcdata(fd)
        except Exception as e:
            errors += f"PrintC: {e}\n"
            try:
                c_code = _raw_c_from_funcdata(fd)
            except Exception:
                c_code = "// ERROR generating code\n"

        total_time = time.perf_counter() - t_total_start
        return final_snap, c_code, action_log, errors, total_time

    except Exception as e:
        total_time = time.perf_counter() - t_total_start
        errors += f"Setup: {e}\n{traceback.format_exc()}"
        return None, "", action_log, errors, total_time


# ===========================================================================
# Comparison & reporting
# ===========================================================================
def compare_snapshots(cpp_snap: Optional[IRSnapshot],
                      py_snap: Optional[IRSnapshot]) -> Dict[str, Any]:
    """Compare two IR snapshots and return a diff summary."""
    if cpp_snap is None or py_snap is None:
        return {"status": "SKIP", "reason": "missing snapshot"}

    diff: Dict[str, Any] = {"status": "MATCH"}
    issues = []

    if cpp_snap.num_blocks != py_snap.num_blocks:
        issues.append(f"blocks: C++={cpp_snap.num_blocks} Py={py_snap.num_blocks} "
                       f"(delta={py_snap.num_blocks - cpp_snap.num_blocks:+d})")
    if cpp_snap.num_ops != py_snap.num_ops:
        issues.append(f"ops: C++={cpp_snap.num_ops} Py={py_snap.num_ops} "
                       f"(delta={py_snap.num_ops - cpp_snap.num_ops:+d})")

    # Opcode distribution diff
    all_opcodes = set(cpp_snap.opcode_counts.keys()) | set(py_snap.opcode_counts.keys())
    opc_diffs = []
    for opc in sorted(all_opcodes):
        c = cpp_snap.opcode_counts.get(opc, 0)
        p = py_snap.opcode_counts.get(opc, 0)
        if c != p:
            opc_diffs.append(f"{opcode_name(opc)}: C++={c} Py={p} ({p - c:+d})")
    if opc_diffs:
        issues.append("opcode diffs: " + "; ".join(opc_diffs[:8]))
        if len(opc_diffs) > 8:
            issues[-1] += f" ... (+{len(opc_diffs) - 8} more)"

    if issues:
        diff["status"] = "DIFF"
        diff["issues"] = issues

    return diff


def compare_c_code(cpp_code: str, py_code: str) -> Dict[str, Any]:
    """Compare final C code output."""
    cpp_lines = [l for l in cpp_code.splitlines() if l.strip()]
    py_lines = [l for l in py_code.splitlines() if l.strip()]

    if not cpp_lines and not py_lines:
        return {"status": "EMPTY"}
    if not cpp_lines:
        return {"status": "CPP_EMPTY", "py_lines": len(py_lines)}
    if not py_lines:
        return {"status": "PY_EMPTY", "cpp_lines": len(cpp_lines)}

    # Check if code is identical
    if cpp_code.strip() == py_code.strip():
        return {"status": "MATCH", "lines": len(cpp_lines)}

    return {
        "status": "DIFF",
        "cpp_lines": len(cpp_lines),
        "py_lines": len(py_lines),
    }


# ===========================================================================
# Main comparison for a single function
# ===========================================================================
def compare_function(pe: PEInfo, sla: str, target: str, spec_dir: str,
                     func_addr: int, func_size: int = 0,
                     show_detail: bool = False,
                     show_actions: bool = True,
                     timeout: float = 30.0) -> Dict[str, Any]:
    """Run full comparison for a single function. Returns result dict."""
    image = pe.flat_image()
    base = pe.image_base
    result: Dict[str, Any] = {"addr": func_addr}

    # --- C++ full stage ---
    cpp_snap, cpp_code, cpp_err, cpp_time = run_cpp_staged(
        sla, target, spec_dir, image, base, func_addr, func_size, "full")
    result["cpp"] = {
        "snapshot": cpp_snap, "c_code": cpp_code,
        "error": cpp_err, "time": cpp_time,
    }

    # --- Python instrumented full ---
    py_snap, py_code, action_log, py_err, py_time = run_py_instrumented(
        sla, target, spec_dir, image, base, func_addr, func_size, timeout=timeout)
    result["py"] = {
        "snapshot": py_snap, "c_code": py_code,
        "action_log": action_log, "error": py_err, "time": py_time,
    }

    # --- IR comparison ---
    result["ir_diff"] = compare_snapshots(cpp_snap, py_snap)

    # --- C code comparison ---
    result["code_diff"] = compare_c_code(cpp_code, py_code)

    return result


# ===========================================================================
# Pretty-print report
# ===========================================================================

# ANSI escape codes
_BOLD = "\033[1m"
_RED = "\033[91m"
_GREEN = "\033[92m"
_YELLOW = "\033[93m"
_CYAN = "\033[96m"
_DIM = "\033[2m"
_RESET = "\033[0m"


def print_report(result: Dict[str, Any], show_detail: bool = False,
                 show_actions: bool = True) -> None:
    addr = result["addr"]
    cpp = result["cpp"]
    py = result["py"]
    ir_diff = result["ir_diff"]
    code_diff = result["code_diff"]

    # Header
    print(f"\n{_BOLD}{'='*70}{_RESET}")
    print(f"{_BOLD}  Function 0x{addr:x}{_RESET}")
    print(f"{'='*70}")

    # Errors
    if cpp["error"]:
        print(f"  {_RED}C++ error:{_RESET} {cpp['error'][:200]}")
    if py["error"]:
        print(f"  {_RED}Py  error:{_RESET} {py['error'][:200]}")

    # Timing
    print(f"  {_DIM}C++ time: {cpp['time']:.3f}s  |  Py time: {py['time']:.3f}s{_RESET}")

    # IR comparison
    status = ir_diff["status"]
    if status == "MATCH":
        tag = f"{_GREEN}MATCH{_RESET}"
    elif status == "DIFF":
        tag = f"{_RED}DIFF{_RESET}"
    else:
        tag = f"{_YELLOW}{status}{_RESET}"

    cpp_snap = cpp["snapshot"]
    py_snap = py["snapshot"]
    cpp_summ = cpp_snap.summary_str() if cpp_snap else "N/A"
    py_summ = py_snap.summary_str() if py_snap else "N/A"
    print(f"\n  {_BOLD}IR:{_RESET}  C++: {cpp_summ}  |  Py: {py_summ}  |  [{tag}]")

    if status == "DIFF":
        for issue in ir_diff.get("issues", []):
            print(f"    {_YELLOW}- {issue}{_RESET}")

    # C code comparison
    cs = code_diff["status"]
    if cs == "MATCH":
        ctag = f"{_GREEN}MATCH{_RESET}"
        print(f"  {_BOLD}C code:{_RESET}  {code_diff.get('lines', '?')} lines  [{ctag}]")
    elif cs == "DIFF":
        ctag = f"{_RED}DIFF{_RESET}"
        print(f"  {_BOLD}C code:{_RESET}  C++: {code_diff['cpp_lines']} lines  |  Py: {code_diff['py_lines']} lines  [{ctag}]")
    elif cs == "CPP_EMPTY":
        ctag = f"{_YELLOW}CPP_EMPTY{_RESET}"
        print(f"  {_BOLD}C code:{_RESET}  C++: 0 lines  |  Py: {code_diff['py_lines']} lines  [{ctag}]")
    elif cs == "PY_EMPTY":
        ctag = f"{_YELLOW}PY_EMPTY{_RESET}"
        print(f"  {_BOLD}C code:{_RESET}  C++: {code_diff['cpp_lines']} lines  |  Py: 0 lines  [{ctag}]")
    else:
        print(f"  {_BOLD}C code:{_RESET}  [{_DIM}{cs}{_RESET}]")

    # Per-action Python summary
    if show_actions:
        action_log: ActionLog = py["action_log"]
        if action_log.entries:
            print(f"\n  {_BOLD}Python action trace:{_RESET}")
            prev_blocks = 0
            prev_ops = 0
            for entry in action_log.entries:
                name = entry["name"]
                elapsed = entry.get("elapsed", 0)
                if "error" in entry:
                    print(f"    {_RED}x {name:30s}  ERROR: {entry['error'][:80]}{_RESET}")
                    continue
                blocks = entry.get("blocks", 0)
                ops = entry.get("ops", 0)
                delta_b = blocks - prev_blocks
                delta_o = ops - prev_ops
                delta_str = ""
                if delta_b != 0 or delta_o != 0:
                    delta_str = f"  {_CYAN}dblk={delta_b:+d} dop={delta_o:+d}{_RESET}"
                print(f"    . {name:30s}  blk={blocks:4d} ops={ops:5d}"
                      f"  {_DIM}{elapsed:.3f}s{_RESET}{delta_str}")
                prev_blocks = blocks
                prev_ops = ops

    # Detail: show opcode distribution diff
    if show_detail and cpp_snap and py_snap:
        print(f"\n  {_BOLD}Opcode distribution:{_RESET}")
        all_opc = sorted(set(cpp_snap.opcode_counts.keys()) | set(py_snap.opcode_counts.keys()))
        for opc in all_opc:
            c = cpp_snap.opcode_counts.get(opc, 0)
            p = py_snap.opcode_counts.get(opc, 0)
            name = opcode_name(opc)
            marker = "" if c == p else f"  {_RED}***{_RESET}"
            print(f"    {name:30s}  C++={c:5d}  Py={p:5d}{marker}")

    # Detail: show first N lines of C code diff
    if show_detail:
        cpp_code = cpp.get("c_code", "")
        py_code = py.get("c_code", "")
        if cpp_code.strip():
            print(f"\n  {_BOLD}C++ output (first 30 lines):{_RESET}")
            for line in cpp_code.splitlines()[:30]:
                print(f"    {_DIM}{line}{_RESET}")
        if py_code.strip():
            print(f"\n  {_BOLD}Python output (first 30 lines):{_RESET}")
            for line in py_code.splitlines()[:30]:
                print(f"    {_DIM}{line}{_RESET}")


# ===========================================================================
# Function scanning
# ===========================================================================
def scan_functions(pe: PEInfo, limit: int = 30) -> List[int]:
    """Scan for candidate function addresses in executable sections."""
    candidates = []
    for sec in pe.sections:
        if not (sec["chars"] & 0x20000000):
            continue
        va = pe.image_base + sec["rva"]
        raw = sec["rawoff"]
        sz = min(sec["rawsz"], sec["vsize"])
        data = pe.data[raw:raw + sz]
        if pe.bitness == 32:
            prologues = [b"\x55\x8b\xec", b"\x55\x89\xe5",
                         b"\x83\xec", b"\x56\x57"]
        else:
            prologues = [b"\x55\x48\x89\xe5", b"\x48\x83\xec",
                         b"\x48\x89\x5c\x24", b"\x40\x53\x48\x83\xec"]
        for off in range(0, len(data) - 4):
            for p in prologues:
                if data[off:off + len(p)] == p:
                    candidates.append(va + off)
                    break
            if len(candidates) >= limit:
                break
        if len(candidates) >= limit:
            break
    return candidates[:limit]


# ===========================================================================
# CLI
# ===========================================================================
def main() -> int:
    parser = argparse.ArgumentParser(
        description="Compare C++ and Python decompiler actions on PE functions")
    parser.add_argument("binary", help="Path to PE binary")
    parser.add_argument("addrs", nargs="*", help="Function address(es) in hex")
    parser.add_argument("--scan", action="store_true",
                        help="Scan for candidate functions")
    parser.add_argument("--limit", type=int, default=10,
                        help="Max functions to compare in scan mode (default: 10)")
    parser.add_argument("--detail", action="store_true",
                        help="Show detailed opcode and C-code diff")
    parser.add_argument("--no-actions", action="store_true",
                        help="Hide per-action Python trace")
    parser.add_argument("--no-color", action="store_true",
                        help="Disable ANSI colors")
    parser.add_argument("--timeout", type=float, default=30.0,
                        help="Per-function Python timeout in seconds (default: 30)")
    args = parser.parse_args()

    if args.no_color:
        global _BOLD, _RED, _GREEN, _YELLOW, _CYAN, _DIM, _RESET
        _BOLD = _RED = _GREEN = _YELLOW = _CYAN = _DIM = _RESET = ""

    # Parse PE
    pe = PEInfo(args.binary)
    print(f"\n{_BOLD}GhidraX Action Compare{_RESET}")
    print(f"  File: {os.path.basename(args.binary)}  "
          f"PE{pe.bitness}  ImageBase=0x{pe.image_base:x}")

    # Resolve arch
    sla, target, spec_dir = resolve_pe_arch(pe)
    print(f"  Arch: {target}  SLA: {os.path.basename(sla)}")

    # Collect function addresses
    func_addrs: List[int] = []
    if args.addrs:
        for a in args.addrs:
            func_addrs.append(int(a, 16) if a.startswith("0x") or a.startswith("0X")
                              else int(a, 16))
    elif args.scan:
        func_addrs = scan_functions(pe, args.limit)
        print(f"  Scanned {len(func_addrs)} candidate functions")
    else:
        parser.error("Provide function address(es) or use --scan")

    # Run comparisons
    total = len(func_addrs)
    match_count = 0
    diff_count = 0
    error_count = 0
    show_actions = not args.no_actions

    for i, addr in enumerate(func_addrs):
        print(f"\n{_DIM}[{i+1}/{total}] Comparing 0x{addr:x} ...{_RESET}", flush=True)
        try:
            result = compare_function(pe, sla, target, spec_dir, addr,
                                      show_detail=args.detail,
                                      show_actions=show_actions,
                                      timeout=args.timeout)
            print_report(result, show_detail=args.detail, show_actions=show_actions)

            ir_status = result["ir_diff"]["status"]
            code_status = result["code_diff"]["status"]
            if ir_status == "MATCH" and code_status == "MATCH":
                match_count += 1
            elif "error" in result["cpp"] and result["cpp"]["error"]:
                error_count += 1
            elif "error" in result["py"] and result["py"]["error"]:
                error_count += 1
            else:
                diff_count += 1
        except Exception as e:
            print(f"  {_RED}FATAL: {e}{_RESET}")
            error_count += 1

    # Summary
    print(f"\n{_BOLD}{'='*70}{_RESET}")
    print(f"{_BOLD}  Summary: {total} functions{_RESET}")
    print(f"    {_GREEN}MATCH: {match_count}{_RESET}")
    print(f"    {_RED}DIFF:  {diff_count}{_RESET}")
    print(f"    {_YELLOW}ERROR: {error_count}{_RESET}")
    print()

    return 0 if diff_count == 0 and error_count == 0 else 1


if __name__ == "__main__":
    sys.exit(main())
