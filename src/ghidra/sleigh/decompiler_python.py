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

from ghidra.sleigh.lifter import Lifter
from ghidra.sleigh.arch_map import add_sla_search_dir
from ghidra.arch.archshim import ArchitectureStandalone
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

            # 1. Lift binary → Python IR (Funcdata)
            context = self._context_from_target(target)
            lifter = Lifter(sla_path, context)
            lifter.set_image(base_addr, image)
            fd = lifter.lift_function(f"func_{entry:x}", entry, func_size)

            # 2. Build CFG (basic blocks, edges)
            if self.use_python_flow:
                self._safe(lambda: _split_basic_blocks(fd, lifter=lifter), "FlowInfo")

            # 3. Attach architecture shim
            arch = ArchitectureStandalone(lifter._spc_mgr)
            fd.setArch(arch)

            # 4. Analysis / optimisation
            ran_full = False
            if self.use_python_full_actions:
                _seed_default_return_output(fd, target)
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
        parts = target.split(":")
        if len(parts) >= 3:
            bitness = int(parts[2])
            if bitness == 32 and "x86" in parts[0].lower():
                return {"addrsize": 1, "opsize": 1}
        return {}

    def _safe(self, fn, label: str):
        """Run *fn*; on exception append to errors and return ``False``."""
        try:
            return fn()
        except Exception as e:
            self._errors += f"{label} error: {e}\n{traceback.format_exc()}"
            return False
