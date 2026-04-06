"""
Pure-Python decompiler driver.

Takes a binary image and function address, produces C-like pseudocode.
All heavy lifting is delegated to the core engine modules:

  - ghidra.sleigh.lifter          → SLEIGH instruction decoding (C++ pyd)
  - ghidra.arch.archshim          → Architecture / calling convention
  - ghidra.analysis.flowlifter    → CFG construction, call specs
  - ghidra.analysis.heritage      → SSA (Heritage)
  - ghidra.transform.pipeline     → Action/Rule optimisation chains
  - ghidra.output.emit_helpers    → C code emission
"""

from __future__ import annotations

import os
import traceback

from ghidra.core.address import Address
from ghidra.core.opcodes import OpCode
from ghidra.analysis.funcdata import Funcdata
from ghidra.sleigh.lifter import Lifter
from ghidra.sleigh.arch_map import add_sla_search_dir, default_context_for_target
from ghidra.arch.archshim import ArchitectureStandalone
from ghidra.arch.loadimage import LoadImageBytes
from ghidra.analysis.flowlifter import (
    _split_basic_blocks,
    _setup_call_specs,
    _inject_tracked_context,
    _run_prerequisite_actions,
)
from ghidra.transform.pipeline import (
    _run_mini_pipeline,
    _run_full_decompile_action,
    _seed_default_return_output,
)
from ghidra.output.emit_helpers import (
    _vn_str,
    _op_str,
    _printc_from_funcdata,
    _raw_c_from_funcdata,
)

# Backward-compatible alias used by tests and scripts
_ArchitectureShim = ArchitectureStandalone


def _context_from_target(target: str) -> dict:
    return default_context_for_target(target)


def _reset_lifter_analysis_state(lifter: Lifter) -> None:
    for attr in ("_jumptables", "_insn_fall_throughs"):
        value = getattr(lifter, attr, None)
        if hasattr(value, "clear"):
            value.clear()
    pending = getattr(lifter, "_unprocessed", None)
    if hasattr(pending, "clear"):
        pending.clear()


def _install_tracked_context(arch: ArchitectureStandalone, target: str, entry: int) -> None:
    parts = target.split(":")
    if len(parts) < 3:
        return
    if parts[0].lower() != "x86":
        return
    try:
        bitness = int(parts[2])
    except ValueError:
        return
    if bitness not in (32, 64):
        return

    from ghidra.core.address import Address
    from ghidra.core.globalcontext import ContextInternal, TrackedContext

    code_space = arch.getDefaultCodeSpace() if hasattr(arch, "getDefaultCodeSpace") else None
    reg_space = arch.getSpaceByName("register") if hasattr(arch, "getSpaceByName") else None
    if code_space is None or reg_space is None:
        return

    ctx = ContextInternal()
    tracked_set = ctx.createSet(Address(code_space, entry), Address(code_space, entry))
    tracked = TrackedContext()
    tracked.loc.space = reg_space
    tracked.loc.offset = 0x20A
    tracked.loc.size = 1
    tracked.val = 0
    tracked_set.append(tracked)
    arch.context = ctx


def _bind_blocks_to_funcdata(fd) -> None:
    bblocks = fd.getBasicBlocks() if hasattr(fd, "getBasicBlocks") else None
    if bblocks is None:
        return
    for bi in range(bblocks.getSize()):
        bb = bblocks.getBlock(bi)
        if hasattr(bb, "_data"):
            bb._data = fd


def _rebind_existing_opcodes(fd) -> None:
    if not hasattr(fd, "beginOpAll"):
        return
    for op in list(fd.beginOpAll()):
        fd.opSetOpcode(op, op.code())


def _restore_unique_base_after_flow(fd, arch, initial_unique_base: int) -> None:
    if not hasattr(fd, "beginOpAll") or not hasattr(arch, "_unique_base"):
        return
    for op in fd.beginOpAll():
        out = op.getOut() if hasattr(op, "getOut") else None
        if out is None:
            continue
        spc = out.getSpace() if hasattr(out, "getSpace") else None
        if spc is None or spc.getName() != "unique":
            continue
        if out.getOffset() >= initial_unique_base:
            return
    arch._unique_base = initial_unique_base


def _build_full_action_ready_funcdata(
    lifter: Lifter,
    arch: ArchitectureStandalone,
    func_name: str,
    target: str,
    entry: int,
    func_size: int,
    *,
    preserve_unresolved_branchind: bool = False,
    initial_unique_base: int | None = None,
):
    _reset_lifter_analysis_state(lifter)
    # Jump-table recovery can run during followFlow(), so the shim must have
    # the default action groups installed before control-flow generation starts.
    if hasattr(arch, "allacts") and arch.allacts is not None:
        arch.allacts.universalAction(arch)
        arch.allacts.resetDefaults()
    code_space = arch.getDefaultCodeSpace()
    if initial_unique_base is None:
        initial_unique_base = arch.getUniqueBase() if hasattr(arch, "getUniqueBase") else 0x10000000
    # Restart rebuilds must reuse the original unique-space baseline.  If we
    # keep the high-water mark from the previous action cycle, raw p-code lifted
    # after restart gets fresh unique offsets that no longer match native Ghidra.
    if hasattr(arch, "_unique_base"):
        arch._unique_base = initial_unique_base
    fd = Funcdata(func_name, func_name, None, Address(code_space, entry), None, func_size)
    fd.setArch(arch)
    fd.followFlow(Address(code_space, 0), Address(code_space, code_space.getHighest()))
    _restore_unique_base_after_flow(fd, arch, initial_unique_base)
    _bind_blocks_to_funcdata(fd)
    return fd


def _restore_rebuilt_funcdata(target_fd, rebuilt_fd) -> None:
    preserved_override = None
    if hasattr(target_fd, "getOverride"):
        try:
            preserved_override = target_fd.getOverride()
        except Exception:
            preserved_override = getattr(target_fd, "_localoverride", None) or getattr(target_fd, "_override", None)
    if preserved_override is None:
        preserved_override = getattr(target_fd, "_localoverride", None) or getattr(target_fd, "_override", None)
    preserved_localmap = getattr(target_fd, "_localmap", None)
    preserved_function_symbol = getattr(target_fd, "_functionSymbol", None)
    preserved_heritage = getattr(target_fd, "_heritage", None)
    preserved_covermerge = getattr(target_fd, "_covermerge", None)

    target_fd.__dict__.clear()
    target_fd.__dict__.update(rebuilt_fd.__dict__)

    if preserved_function_symbol is not None:
        target_fd._functionSymbol = preserved_function_symbol
    if preserved_override is not None:
        target_fd._localoverride = preserved_override
        target_fd._override = preserved_override
    if preserved_heritage is not None and hasattr(preserved_heritage, "clear"):
        preserved_heritage.clear()
        target_fd._heritage = preserved_heritage
    if preserved_covermerge is not None and hasattr(preserved_covermerge, "clear"):
        preserved_covermerge.clear()
        target_fd._covermerge = preserved_covermerge

    if preserved_localmap is not None:
        target_fd._localmap = preserved_localmap
        if hasattr(preserved_localmap, "_fd"):
            preserved_localmap._fd = target_fd
        if hasattr(preserved_localmap, "_name"):
            preserved_localmap._name = target_fd.getName()
        if hasattr(preserved_localmap, "clearUnlocked"):
            preserved_localmap.clearUnlocked()
        if hasattr(preserved_localmap, "resetLocalWindow"):
            preserved_localmap.resetLocalWindow()
    elif getattr(target_fd, "_localmap", None) is not None and hasattr(target_fd._localmap, "_fd"):
        target_fd._localmap._fd = target_fd

    if hasattr(target_fd, "clearActiveOutput"):
        target_fd.clearActiveOutput()
    _bind_blocks_to_funcdata(target_fd)

    target_fd._qlst_map = {}
    for fc in getattr(target_fd, "_qlst", []):
        op = fc.getOp() if hasattr(fc, "getOp") else None
        if op is not None:
            target_fd._qlst_map[id(op)] = fc


def _install_full_action_restart_rebuilder(
    fd,
    arch: ArchitectureStandalone,
    lifter: Lifter,
    target: str,
    func_size: int,
    initial_unique_base: int,
) -> None:
    def _rebuild(target_fd) -> None:
        rebuilt_fd = _build_full_action_ready_funcdata(
            lifter=lifter,
            arch=arch,
            func_name=target_fd.getName(),
            target=target,
            entry=target_fd.getAddress().getOffset(),
            func_size=func_size,
            initial_unique_base=initial_unique_base,
        )
        _restore_rebuilt_funcdata(target_fd, rebuilt_fd)

    if hasattr(arch, "setRestartRebuilder"):
        arch.setRestartRebuilder(_rebuild)


def _prepare_funcdata_for_full_actions(
    sla_path: str,
    target: str,
    image: bytes,
    base_addr: int,
    entry: int,
    func_size: int = 0,
):
    context = _context_from_target(target)
    lifter = Lifter(sla_path, context)
    lifter.set_image(base_addr, image)
    arch = ArchitectureStandalone(lifter._spc_mgr, target=target, sla_path=sla_path)
    if getattr(arch, "loader", None) is None and hasattr(arch, "getDefaultCodeSpace"):
        code_space = arch.getDefaultCodeSpace()
        if code_space is not None:
            arch.loader = LoadImageBytes(image, Address(code_space, base_addr))
    _install_tracked_context(arch, target, entry)
    initial_unique_base = arch.getUniqueBase() if hasattr(arch, "getUniqueBase") else 0x10000000
    fd = _build_full_action_ready_funcdata(
        lifter=lifter,
        arch=arch,
        func_name=f"func_{entry:x}",
        target=target,
        entry=entry,
        func_size=func_size,
        initial_unique_base=initial_unique_base,
    )
    _install_full_action_restart_rebuilder(fd, arch, lifter, target, func_size, initial_unique_base)
    return lifter, arch, fd


def _build_jumptable_prelude_funcdata(
    lifter: Lifter,
    arch: ArchitectureStandalone,
    func_name: str,
    target: str,
    entry: int,
    func_size: int,
):
    return _build_full_action_ready_funcdata(
        lifter=lifter,
        arch=arch,
        func_name=func_name,
        target=target,
        entry=entry,
        func_size=func_size,
        preserve_unresolved_branchind=True,
    )


def _is_indirect_thunk_prelude_candidate(fd, func_size: int) -> bool:
    if func_size <= 0:
        return False
    bblocks = fd.getBasicBlocks() if hasattr(fd, "getBasicBlocks") else None
    if bblocks is None or bblocks.getSize() != 1:
        return False
    bb = bblocks.getBlock(0)
    ops = list(bb.getOpList()) if hasattr(bb, "getOpList") else []
    if len(ops) != 1:
        return False
    return ops[0].code() == OpCode.CPUI_BRANCHIND


class DecompilerPython:
    """Pure-Python decompiler.

    Interface:
        dp = DecompilerPython()
        dp.add_spec_path("specs/")
        dp.initialize()
        code = dp.decompile(sla, target, image, base, entry)
    """

    def __init__(self) -> None:
        self._initialized: bool = False
        self._errors: str = ""
        self._warnings: str = ""

        # Module flags — enable/disable each Python module
        self.use_python_ir: bool = True
        self.use_python_flow: bool = True
        self.use_python_heritage: bool = False
        self.use_python_rules: bool = False
        self.use_python_full_actions: bool = False
        self.use_python_printc: bool = False

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
        """Initialize the decompiler (lazy — actual init per decompile call)."""
        self._initialized = True

    def get_errors(self) -> str:
        return self._errors

    def get_warnings(self) -> str:
        return self._warnings

    # -----------------------------------------------------------------
    # Core entry point
    # -----------------------------------------------------------------
    def decompile(self, sla_path: str, target: str,
                  image: bytes, base_addr: int,
                  entry: int, func_size: int = 0) -> str:
        """Decompile a single function.

        Args:
            sla_path:  Path to the .sla spec file.
            target:    Language id, e.g. ``'x86:LE:64:default'``.
            image:     Raw binary image bytes.
            base_addr: Base address the image is loaded at.
            entry:     Entry-point address of the function.
            func_size: Optional function size hint (0 = auto).

        Returns:
            C-like pseudocode string.
        """
        self._errors = ""
        self._warnings = ""

        try:
            if not self._initialized:
                self.initialize()

            if self.use_python_full_actions:
                _, arch, fd = _prepare_funcdata_for_full_actions(
                    sla_path=sla_path,
                    target=target,
                    image=image,
                    base_addr=base_addr,
                    entry=entry,
                    func_size=func_size,
                )
            else:
                # 1. Lift binary → Python IR (Funcdata)
                context = self._context_from_target(target)
                lifter = Lifter(sla_path, context)
                lifter.set_image(base_addr, image)
                fd = lifter.lift_function(f"func_{entry:x}", entry, func_size)

                # 2. Build CFG (basic blocks, edges)
                if self.use_python_flow:
                    self._safe(lambda: _split_basic_blocks(fd, lifter=lifter), "FlowInfo")

                # 3. Attach architecture shim
                arch = ArchitectureStandalone(lifter._spc_mgr, target=target, sla_path=sla_path)
                fd.setArch(arch)

                # 3b. Create FuncCallSpecs for CALL/CALLIND ops
                self._safe(lambda: _setup_call_specs(fd, lifter=lifter), "CallSpecs")

            # 4. Analysis / optimisation
            ran_full = False
            if self.use_python_full_actions:
                ran_full = self._safe(lambda: _run_full_decompile_action(fd),
                                      "FullActions") is not False

            if not ran_full and self.use_python_heritage:
                self._safe(lambda: fd.opHeritage(), "Heritage")

            if not ran_full and self.use_python_rules:
                self._safe(lambda: _run_mini_pipeline(fd), "Rules")

            for msg in arch.drainMessages():
                self._warnings += f"{msg}\n"

            # 5. Emit C code
            if self.use_python_printc:
                code = self._safe(lambda: _printc_from_funcdata(fd), "PrintC")
                if code and code.strip():
                    return code

            return _raw_c_from_funcdata(fd)

        except Exception as e:
            self._errors += f"Decompile error: {e}\n{traceback.format_exc()}"
            return f"// ERROR: {e}\n"

    # -----------------------------------------------------------------
    # Internal helpers
    # -----------------------------------------------------------------
    @staticmethod
    def _context_from_target(target: str) -> dict:
        return _context_from_target(target)

    def _safe(self, fn, label: str):
        """Run *fn*; on exception append to errors and return ``False``."""
        try:
            return fn()
        except Exception as e:
            self._errors += f"{label} error: {e}\n{traceback.format_exc()}"
            return False
