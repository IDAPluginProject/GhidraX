"""
PCode IR Logger —带日志的 PCode IR 对比工具 + 震荡检测 / 超时守卫。

用法示例
--------
# 全局开启，写到文件
PCodeIRLogger.enable("decompile_trace.log")

# 或用上下文管理器（自动关闭）
with PCodeIRLogger.session("decompile_trace.log"):
    _run_full_decompile_action(fd)

# 只启用震荡检测（不写完整 log）
PCodeIRLogger.set_oscillation_limit(20)

对应 C++ 参考: coreaction.cc / action.cc (无直接等价，Python 新增调试工具)
"""

from __future__ import annotations

import io
import sys
import time
import threading
from collections import defaultdict
from typing import Dict, List, Optional, Set, Tuple, TYPE_CHECKING

if TYPE_CHECKING:
    from ghidra.analysis.funcdata import Funcdata
    from ghidra.ir.op import PcodeOp

# ---------------------------------------------------------------------------
# Internal opcode name cache
# ---------------------------------------------------------------------------

def _opc_name(opc: int) -> str:
    try:
        from ghidra.core.opcodes import OpCode
        _cache = getattr(_opc_name, '_cache', None)
        if _cache is None:
            _opc_name._cache = {int(v): k for k, v in vars(OpCode).items()
                                if isinstance(v, int) and not k.startswith('_')}
            _cache = _opc_name._cache
        return _cache.get(opc, f"opc_{opc}")
    except Exception:
        return f"opc_{opc}"


def _vn_repr(vn) -> str:
    """Compact single-line varnode representation."""
    if vn is None:
        return "-"
    try:
        spc = vn.getSpace()
        sname = spc.getName() if spc else "?"
        off = vn.getOffset()
        sz = vn.getSize()
        flags = []
        if vn.isInput():
            flags.append("in")
        if vn.isConstant():
            flags.append(f"#{off:#x}")
        flag_s = "," + ",".join(flags) if flags else ""
        return f"{sname}[{off:#x}:{sz}{flag_s}]"
    except Exception:
        return repr(vn)


def _op_repr(op) -> str:
    """Compact single-line PcodeOp representation including output + inputs."""
    if op is None:
        return "<None op>"
    try:
        oname = _opc_name(int(op.code()))
        out = op.getOut()
        out_s = _vn_repr(out) if out else "_"
        ins = [_vn_repr(op.getIn(i)) for i in range(op.numInput())]
        addr = ""
        try:
            seq = op.getSeqNum() if hasattr(op, "getSeqNum") else None
            if seq is not None:
                addr = f"@{seq.getOffset():#x}:{seq.getOrder()}"
        except Exception:
            pass
        return f"{out_s} = {oname}({', '.join(ins)}){addr}"
    except Exception:
        return repr(op)


# ---------------------------------------------------------------------------
# IR Snapshot
# ---------------------------------------------------------------------------

class IRSnapshot:
    """Immutable snapshot of all alive PCode ops in a Funcdata."""

    __slots__ = ("func_name", "ts", "ops")

    def __init__(self, func_name: str, ops: Dict[int, str]) -> None:
        self.func_name = func_name
        self.ts: float = time.perf_counter()
        self.ops: Dict[int, str] = ops  # seq_key → repr_str

    @staticmethod
    def take(data: "Funcdata") -> "IRSnapshot":
        fname = data.getName() if hasattr(data, "getName") else "unknown"
        ops: Dict[int, str] = {}
        try:
            for op in data._obank.beginAlive():
                try:
                    key = id(op)
                    ops[key] = _op_repr(op)
                except Exception:
                    pass
        except Exception:
            pass
        return IRSnapshot(fname, ops)

    def diff(self, after: "IRSnapshot") -> "IRDiff":
        before_set: Set[str] = set(self.ops.values())
        after_set: Set[str] = set(after.ops.values())
        added = sorted(after_set - before_set)
        removed = sorted(before_set - after_set)
        return IRDiff(removed, added, after.ts - self.ts)


class IRDiff:
    """Difference between two IR snapshots."""

    __slots__ = ("removed", "added", "elapsed")

    def __init__(self, removed: List[str], added: List[str], elapsed: float) -> None:
        self.removed = removed
        self.added = added
        self.elapsed = elapsed

    @property
    def has_changes(self) -> bool:
        return bool(self.removed or self.added)

    def format(self, max_lines: int = 40) -> str:
        lines: List[str] = []
        for r in self.removed[:max_lines]:
            lines.append(f"  - {r}")
        for a in self.added[:max_lines]:
            lines.append(f"  + {a}")
        extra_r = max(0, len(self.removed) - max_lines)
        extra_a = max(0, len(self.added) - max_lines)
        if extra_r or extra_a:
            lines.append(f"  ... ({extra_r} more removed, {extra_a} more added)")
        return "\n".join(lines)


# ---------------------------------------------------------------------------
# Oscillation Guard
# ---------------------------------------------------------------------------

def _op_stable_key(op) -> str:
    """Return a stable string key for *op* that survives clearAnalysis() restarts.

    Uses SeqNum (address + order) when available, which is preserved across
    heritage passes.  Falls back to the opcode + input-count fingerprint so
    the guard still works in the absence of sequence numbers.
    """
    try:
        seq = op.getSeqNum() if hasattr(op, "getSeqNum") else None
        if seq is not None:
            off = seq.getOffset() if hasattr(seq, "getOffset") else 0
            order = seq.getOrder() if hasattr(seq, "getOrder") else 0
            return f"{off:#x}:{order}"
    except Exception:
        pass
    # fallback: opcode + number of inputs (not perfect but better than id())
    try:
        return f"opc{int(op.code())}_{op.numInput()}"
    except Exception:
        return str(id(op))


class OscillationGuard:
    """Detects rules that fire repeatedly on the same op (oscillation).

    Uses the op's sequence-number as key (stable across ``clearAnalysis``
    restarts between heritage passes).  When a ``(rule_name, seq_key)`` pair
    exceeds *limit* firings, a warning is emitted; on the next fire an
    ``OscillationError`` is raised, which ``ActionPool._processOp`` converts
    to a skip.
    """

    class OscillationError(RuntimeError):
        pass

    def __init__(self, limit: int = 50) -> None:
        self._limit = limit
        self._counts: Dict[Tuple[str, str], int] = defaultdict(int)
        self._warned: Set[Tuple[str, str]] = set()

    def reset(self) -> None:
        self._counts.clear()

    def is_suppressed(self, rule_name: str, op) -> bool:
        """Return True when this (rule, op) pair should be skipped."""
        seq_key = _op_stable_key(op)
        return self._counts.get((rule_name, seq_key), 0) >= self._limit

    def record(self, rule_name: str, op) -> None:
        """Record one firing of *rule_name* on *op*.  Warns at limit; never raises."""
        seq_key = _op_stable_key(op)
        key: Tuple[str, str] = (rule_name, seq_key)
        self._counts[key] += 1
        n = self._counts[key]
        if n == self._limit:
            op_s = _op_repr(op)
            import warnings
            warnings.warn(
                f"[OscillationGuard] Rule '{rule_name}' suppressed after {n} fires "
                f"on op @ {seq_key}: {op_s}",
                stacklevel=4,
            )


# ---------------------------------------------------------------------------
# PCodeIRLogger  (global singleton)
# ---------------------------------------------------------------------------

class PCodeIRLogger:
    """Global PCode IR logger singleton.

    All state is class-level so it can be toggled from anywhere without
    passing instances around.
    """

    _enabled: bool = False
    _stream: Optional[io.TextIOBase] = None
    _file_path: Optional[str] = None
    _lock: threading.Lock = threading.Lock()
    _oscillation_guard: Optional[OscillationGuard] = None
    _oscillation_limit: int = 50
    _log_ir_diff: bool = True      # write per-rule IR diff to log
    _log_unchanged: bool = False   # also log rules that fired but produced no diff
    _rule_fire_counts: Dict[str, int] = defaultdict(int)  # rule → total fires this func

    # ------------------------------------------------------------------ #
    # Lifecycle
    # ------------------------------------------------------------------ #

    @classmethod
    def enable(cls, path: Optional[str] = None, append: bool = False) -> None:
        """Enable logging.  *path* = None → stderr."""
        with cls._lock:
            if path:
                mode = "a" if append else "w"
                cls._stream = open(path, mode, encoding="utf-8")
                cls._file_path = path
            else:
                cls._stream = sys.stderr
                cls._file_path = None
            cls._enabled = True
            cls._oscillation_guard = OscillationGuard(cls._oscillation_limit)
            cls._rule_fire_counts.clear()
            cls._write_header()

    @classmethod
    def disable(cls) -> None:
        """Disable logging and close file (if any)."""
        with cls._lock:
            cls._enabled = False
            if cls._file_path and cls._stream:
                try:
                    cls._stream.close()
                except Exception:
                    pass
            cls._stream = None
            cls._file_path = None

    @classmethod
    def set_oscillation_limit(cls, limit: int) -> None:
        """Set oscillation detection threshold (independent of full logging)."""
        cls._oscillation_limit = limit
        if cls._oscillation_guard is not None:
            cls._oscillation_guard._limit = limit

    @classmethod
    def reset_for_function(cls, func_name: str) -> None:
        """Reset per-function counters and oscillation state."""
        cls._rule_fire_counts.clear()
        if cls._oscillation_guard is not None:
            cls._oscillation_guard.reset()
        if cls._enabled:
            cls._write(f"\n{'='*70}\nFUNCTION: {func_name}\n{'='*70}\n")

    @classmethod
    def is_enabled(cls) -> bool:
        return cls._enabled

    @classmethod
    def has_oscillation_guard(cls) -> bool:
        return cls._oscillation_guard is not None

    # ------------------------------------------------------------------ #
    # Context manager
    # ------------------------------------------------------------------ #

    class session:
        """Context manager: enable on enter, disable on exit."""
        def __init__(self, path: Optional[str] = None, append: bool = False):
            self._path = path
            self._append = append

        def __enter__(self) -> "PCodeIRLogger.session":
            PCodeIRLogger.enable(self._path, self._append)
            return self

        def __exit__(self, *_):
            PCodeIRLogger.disable()

    # ------------------------------------------------------------------ #
    # Core logging helpers (thread-safe)
    # ------------------------------------------------------------------ #

    @classmethod
    def _write(cls, text: str) -> None:
        try:
            if cls._stream:
                cls._stream.write(text)
                cls._stream.flush()
        except Exception:
            pass

    @classmethod
    def _write_header(cls) -> None:
        ts = time.strftime("%Y-%m-%d %H:%M:%S")
        cls._write(f"# GhidraX PCode IR Log  {ts}\n")
        cls._write(f"# oscillation_limit={cls._oscillation_limit}\n\n")

    # ------------------------------------------------------------------ #
    # Public API used by ActionPool._processOp
    # ------------------------------------------------------------------ #

    @classmethod
    def rule_fired(
        cls,
        rule_name: str,
        op,
        before: Optional["IRSnapshot"],
        after: Optional["IRSnapshot"],
    ) -> None:
        """Called after a rule fires successfully.

        *before* and *after* are snapshots taken around the rule application
        (only when logging is fully enabled).  May be None when only the
        oscillation guard is active.
        """
        # 1. Oscillation guard (always active if set up)
        guard = cls._oscillation_guard
        if guard is not None:
            try:
                guard.record(rule_name, op)
            except OscillationGuard.OscillationError:
                raise  # propagate to ActionPool

        if not cls._enabled:
            return

        # 2. Per-rule fire count
        with cls._lock:
            cls._rule_fire_counts[rule_name] += 1
            fire_no = cls._rule_fire_counts[rule_name]

        # 3. Compute diff
        diff: Optional[IRDiff] = None
        if before is not None and after is not None:
            diff = before.diff(after)

        # 4. Write log entry
        op_s = _op_repr(op)
        header = f"[RULE #{fire_no}] {rule_name}  op=({op_s})"
        if diff is not None and diff.has_changes:
            diff_s = diff.format()
            body = f"{header}\n{diff_s}\n"
        elif cls._log_unchanged or diff is None:
            body = f"{header}  (no IR diff captured)\n"
        else:
            return  # no diff and log_unchanged off → skip

        with cls._lock:
            cls._write(body)

    @classmethod
    def log_timeout(cls, action_name: str, elapsed: float, iter_count: int,
                    top_rules: List[Tuple[str, int]]) -> None:
        """Log a timeout event with statistics."""
        lines = [
            f"\n{'!'*70}",
            f"TIMEOUT in action '{action_name}'",
            f"  elapsed={elapsed:.3f}s  iterations={iter_count}",
            "  top rules by fire count:",
        ]
        for rname, cnt in top_rules[:15]:
            lines.append(f"    {cnt:6d}  {rname}")
        lines.append("!" * 70 + "\n")
        msg = "\n".join(lines)
        with cls._lock:
            cls._write(msg)
        import warnings
        warnings.warn(msg.strip())

    @classmethod
    def log_action_summary(cls, action_name: str, elapsed: float,
                           total_changes: int) -> None:
        """Log a summary after a root action completes."""
        if not cls._enabled:
            return
        lines = [
            f"\n[SUMMARY] action='{action_name}'  "
            f"elapsed={elapsed:.3f}s  changes={total_changes}",
            "  rule fire counts:",
        ]
        with cls._lock:
            sorted_rules = sorted(cls._rule_fire_counts.items(),
                                  key=lambda x: -x[1])
        for rname, cnt in sorted_rules[:20]:
            lines.append(f"    {cnt:6d}  {rname}")
        with cls._lock:
            cls._write("\n".join(lines) + "\n")
