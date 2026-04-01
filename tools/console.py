#!/usr/bin/env python3
"""
GhidraX Console — Dual-engine decompiler comparison tool.

Usage:
    python console.py <binary> <func_addr> [options]

Examples:
    python console.py examples/cp.exe 0x401000
    python console.py examples/find.exe 0x401000 --py-only
    python console.py examples/cp.exe 0x401000 --heritage --rules --printc
"""

from __future__ import annotations

import argparse
import os
import struct
import sys
import time
from typing import Dict, List, Optional, Tuple

# ---------------------------------------------------------------------------
# Ensure src/ is on sys.path so `import ghidra` works when invoked from tools/
# ---------------------------------------------------------------------------
_TOOLS_DIR = os.path.dirname(os.path.abspath(__file__))
_PROJECT_ROOT = os.path.dirname(_TOOLS_DIR)
_SRC_DIR = os.path.join(_PROJECT_ROOT, "src")
if _SRC_DIR not in sys.path:
    sys.path.insert(0, _SRC_DIR)


# ============================================================================
# Minimal PE parser
# ============================================================================

class PEInfo:
    """Minimal PE header parser — extracts what the decompiler needs."""

    def __init__(self, path: str) -> None:
        self.path: str = path
        self.image_base: int = 0
        self.bitness: int = 32
        self.entry_rva: int = 0
        self.sections: List[Dict] = []
        self.data: bytes = b""
        self._parse()

    def _parse(self) -> None:
        with open(self.path, "rb") as f:
            self.data = f.read()

        # DOS header
        if self.data[:2] != b"MZ":
            raise ValueError(f"Not a PE file: {self.path}")

        pe_off = struct.unpack_from("<I", self.data, 0x3C)[0]
        if self.data[pe_off:pe_off + 4] != b"PE\x00\x00":
            raise ValueError(f"Invalid PE signature at offset 0x{pe_off:X}")

        # COFF header
        coff = pe_off + 4
        _machine = struct.unpack_from("<H", self.data, coff)[0]  # noqa: F841
        num_sections = struct.unpack_from("<H", self.data, coff + 2)[0]
        opt_hdr_size = struct.unpack_from("<H", self.data, coff + 16)[0]

        # Optional header
        opt = coff + 20
        magic = struct.unpack_from("<H", self.data, opt)[0]

        if magic == 0x20B:  # PE32+
            self.bitness = 64
            self.entry_rva = struct.unpack_from("<I", self.data, opt + 16)[0]
            self.image_base = struct.unpack_from("<Q", self.data, opt + 24)[0]
        elif magic == 0x10B:  # PE32
            self.bitness = 32
            self.entry_rva = struct.unpack_from("<I", self.data, opt + 16)[0]
            self.image_base = struct.unpack_from("<I", self.data, opt + 28)[0]
        else:
            raise ValueError(f"Unknown PE optional header magic: 0x{magic:X}")

        # Section headers
        sec_off = opt + opt_hdr_size
        for i in range(num_sections):
            s = sec_off + i * 40
            name = self.data[s:s + 8].rstrip(b"\x00").decode("ascii", errors="replace")
            vsize = struct.unpack_from("<I", self.data, s + 8)[0]
            rva = struct.unpack_from("<I", self.data, s + 12)[0]
            raw_size = struct.unpack_from("<I", self.data, s + 16)[0]
            raw_ptr = struct.unpack_from("<I", self.data, s + 20)[0]
            chars = struct.unpack_from("<I", self.data, s + 36)[0]
            self.sections.append({
                "name": name, "rva": rva, "vsize": vsize,
                "raw_ptr": raw_ptr, "raw_size": raw_size, "chars": chars,
            })

    @property
    def entry_va(self) -> int:
        return self.image_base + self.entry_rva

    def va_to_offset(self, va: int) -> Optional[int]:
        """Convert virtual address to file offset."""
        rva = va - self.image_base
        for sec in self.sections:
            if sec["rva"] <= rva < sec["rva"] + sec["raw_size"]:
                return sec["raw_ptr"] + (rva - sec["rva"])
        return None

    def summary(self) -> str:
        lines = [
            f"  File:       {os.path.basename(self.path)}",
            f"  Format:     PE{'64' if self.bitness == 64 else '32'}",
            f"  ImageBase:  0x{self.image_base:X}",
            f"  EntryPoint: 0x{self.entry_va:X}",
            f"  Sections:   {len(self.sections)}",
        ]
        for sec in self.sections:
            flags = []
            if sec["chars"] & 0x20000000:
                flags.append("X")
            if sec["chars"] & 0x40000000:
                flags.append("R")
            if sec["chars"] & 0x80000000:
                flags.append("W")
            lines.append(
                f"    {sec['name']:<8s}  VA=0x{self.image_base + sec['rva']:X}"
                f"  Size=0x{sec['vsize']:X}  [{','.join(flags)}]"
            )
        return "\n".join(lines)


# ============================================================================
# Architecture resolution
# ============================================================================

def resolve_pe_arch(pe: PEInfo) -> Tuple[str, str, str]:
    """Determine SLA path and target string from PE info.

    Returns:
        (sla_path, target, spec_dir)
    """
    from ghidra.sleigh.arch_map import resolve_arch, add_sla_search_dir

    # Auto-discover specs/ from project root
    specs_proc = os.path.join(_PROJECT_ROOT, "specs", "Processors")
    if os.path.isdir(specs_proc):
        for proc in os.listdir(specs_proc):
            lang_dir = os.path.join(specs_proc, proc, "data", "languages")
            if os.path.isdir(lang_dir):
                add_sla_search_dir(lang_dir)

    info = resolve_arch("metapc", pe.bitness, False)
    return info["sla_path"], info["target"], os.path.dirname(info["sla_path"])


# ============================================================================
# Decompiler runners
# ============================================================================

def run_cpp_decompile(sla: str, target: str, spec_dir: str,
                      image: bytes, base: int, entry: int,
                      func_size: int = 0) -> Tuple[str, float, str]:
    """Run the C++ native decompiler. Returns (code, elapsed_sec, errors)."""
    try:
        from ghidra.sleigh.decompiler_native import DecompilerNative
    except ImportError:
        return ("", 0.0,
                "decompiler_native.pyd not found — run native/build.bat first")

    dn = DecompilerNative()
    dn.add_spec_path(spec_dir)
    dn.initialize()

    t0 = time.perf_counter()
    try:
        code = dn.decompile(sla, target, image, base, entry, func_size)
    except Exception as e:
        elapsed = time.perf_counter() - t0
        return ("", elapsed, f"C++ engine exception: {e}")
    elapsed = time.perf_counter() - t0

    errs = dn.get_errors() or ""
    return (code or "", elapsed, errs)


def run_py_decompile(sla: str, target: str, spec_dir: str,
                     image: bytes, base: int, entry: int,
                     func_size: int = 0,
                     heritage: bool = False, rules: bool = False,
                     full_actions: bool = False,
                     printc: bool = False) -> Tuple[str, float, str]:
    """Run the pure-Python decompiler. Returns (code, elapsed_sec, errors)."""
    from ghidra.sleigh.decompiler_python import DecompilerPython

    dp = DecompilerPython()
    dp.add_spec_path(spec_dir)
    dp.use_python_heritage = heritage
    dp.use_python_rules = rules
    dp.use_python_full_actions = full_actions
    dp.use_python_printc = printc
    dp.initialize()

    t0 = time.perf_counter()
    code = dp.decompile(sla, target, image, base, entry, func_size)
    elapsed = time.perf_counter() - t0

    errs = dp.get_errors() or ""
    warns = dp.get_warnings() or ""
    if warns:
        errs = (errs + "\n" + warns).strip()
    return (code or "", elapsed, errs)


# ============================================================================
# Output formatting
# ============================================================================

_RESET = "\033[0m"
_BOLD = "\033[1m"
_RED = "\033[31m"
_GREEN = "\033[32m"
_YELLOW = "\033[33m"
_CYAN = "\033[36m"
_DIM = "\033[2m"


def _header(title: str) -> str:
    w = 72
    line = "=" * w
    return f"\n{_BOLD}{_CYAN}{line}\n  {title}\n{line}{_RESET}\n"


def _section(title: str) -> str:
    return f"\n{_BOLD}{_YELLOW}--- {title} ---{_RESET}\n"


def _status(ok: bool, msg: str) -> str:
    tag = f"{_GREEN}OK{_RESET}" if ok else f"{_RED}FAIL{_RESET}"
    return f"  [{tag}] {msg}"


def print_result(engine_name: str, code: str, elapsed: float, errors: str) -> None:
    """Pretty-print one engine's result."""
    print(_header(f"{engine_name} Decompiler"))

    # Timing
    print(f"  {_DIM}Time: {elapsed:.3f}s{_RESET}")

    # Errors
    if errors.strip():
        print(f"  {_RED}Errors/Warnings:{_RESET}")
        for line in errors.strip().splitlines():
            print(f"    {_DIM}{line}{_RESET}")

    # Code
    if code.strip():
        print(_section("Output"))
        for i, line in enumerate(code.splitlines(), 1):
            print(f"  {_DIM}{i:4d}{_RESET}  {line}")
        print()
        loc = sum(1 for l in code.splitlines() if l.strip() and not l.strip().startswith("//"))
        print(f"  {_DIM}({loc} lines of code){_RESET}")
    else:
        print(f"\n  {_RED}(no output){_RESET}")

    print()


# ============================================================================
# Scan functions in .text
# ============================================================================

def scan_functions(pe: PEInfo, max_funcs: int = 20) -> List[int]:
    """Naive scan for function prologues in executable sections."""
    funcs = []
    for sec in pe.sections:
        if not (sec["chars"] & 0x20000000):  # IMAGE_SCN_MEM_EXECUTE
            continue
        start = sec["raw_ptr"]
        end = start + sec["raw_size"]
        va_base = pe.image_base + sec["rva"]

        i = start
        while i < end - 2 and len(funcs) < max_funcs:
            b0 = pe.data[i]
            if pe.bitness == 64:
                # sub rsp, imm8 (48 83 EC xx) or push rbp (55)
                if (i + 3 < end and pe.data[i] == 0x48
                        and pe.data[i + 1] == 0x83 and pe.data[i + 2] == 0xEC):
                    funcs.append(va_base + (i - start))
                    i += 4
                    continue
            # push ebp/rbp
            if b0 == 0x55:
                funcs.append(va_base + (i - start))
                i += 1
                continue
            i += 1
    return funcs


# ============================================================================
# Main
# ============================================================================

def main() -> int:
    parser = argparse.ArgumentParser(
        description="GhidraX Console — dual-engine decompiler comparison",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=(
            "Examples:\n"
            "  python console.py ../examples/cp.exe 0x401000\n"
            "  python console.py ../examples/find.exe 0x401000 --heritage --printc\n"
            "  python console.py ../examples/cp.exe --scan\n"
            "  python console.py ../examples/cp.exe 0x401000 --py-only\n"
            "  python console.py ../examples/cp.exe 0x401000 --cpp-only\n"
        ),
    )
    parser.add_argument("binary", help="Path to PE executable")
    parser.add_argument("func_addr", nargs="?", default=None,
                        help="Function virtual address (hex, e.g. 0x401000). "
                             "Omit with --scan to list candidate functions.")
    parser.add_argument("--size", type=lambda x: int(x, 0), default=0,
                        help="Function size hint in bytes (0 = auto)")

    # Engine selection
    eng = parser.add_mutually_exclusive_group()
    eng.add_argument("--cpp-only", action="store_true", help="Run C++ engine only")
    eng.add_argument("--py-only", action="store_true", help="Run Python engine only")

    # Python engine options
    py_grp = parser.add_argument_group("Python engine options")
    py_grp.add_argument("--heritage", action="store_true",
                        help="Enable Python heritage (SSA)")
    py_grp.add_argument("--rules", action="store_true",
                        help="Enable Python optimization rules")
    py_grp.add_argument("--full-actions", action="store_true",
                        help="Enable full Python action chain")
    py_grp.add_argument("--printc", action="store_true",
                        help="Enable Python structured C output")
    py_grp.add_argument("--all-py", action="store_true",
                        help="Enable all Python pipeline stages")

    # Misc
    parser.add_argument("--scan", action="store_true",
                        help="Scan and list candidate function addresses")
    parser.add_argument("--no-color", action="store_true",
                        help="Disable colored output")
    parser.add_argument("--diff", action="store_true",
                        help="Show a simple line-count diff summary")

    args = parser.parse_args()

    # Disable ANSI colors if requested or on dumb terminals
    if args.no_color or not sys.stdout.isatty():
        global _RESET, _BOLD, _RED, _GREEN, _YELLOW, _CYAN, _DIM
        _RESET = _BOLD = _RED = _GREEN = _YELLOW = _CYAN = _DIM = ""

    # --all-py shorthand
    if args.all_py:
        args.heritage = args.rules = args.full_actions = args.printc = True

    # Parse PE
    binary_path = args.binary
    if not os.path.isabs(binary_path):
        binary_path = os.path.abspath(binary_path)

    if not os.path.isfile(binary_path):
        print(f"{_RED}Error: file not found: {binary_path}{_RESET}", file=sys.stderr)
        return 1

    try:
        pe = PEInfo(binary_path)
    except (ValueError, struct.error) as e:
        print(f"{_RED}Error parsing PE: {e}{_RESET}", file=sys.stderr)
        return 1

    print(_header("GhidraX Console"))
    print(pe.summary())
    print()

    # --scan mode
    if args.scan:
        funcs = scan_functions(pe, max_funcs=30)
        if not funcs:
            print(f"  {_YELLOW}No function prologues found.{_RESET}")
        else:
            print(f"  {_BOLD}Candidate functions ({len(funcs)}):{_RESET}")
            for va in funcs:
                print(f"    0x{va:X}")
        return 0

    # Require func_addr for decompilation
    if args.func_addr is None:
        print(f"{_RED}Error: func_addr is required (or use --scan){_RESET}",
              file=sys.stderr)
        return 1

    func_addr = int(args.func_addr, 0)
    func_size = args.size

    print(f"  {_BOLD}Target function:{_RESET} 0x{func_addr:X}")
    if func_size:
        print(f"  {_BOLD}Size hint:{_RESET}       {func_size} bytes")
    print()

    # Resolve architecture
    try:
        sla, target, spec_dir = resolve_pe_arch(pe)
    except (FileNotFoundError, ValueError) as e:
        print(f"{_RED}Architecture error: {e}{_RESET}", file=sys.stderr)
        return 1

    print(_status(True, f"Architecture resolved: {target}"))
    print(_status(True, f"SLA: {os.path.basename(sla)}"))
    print()

    image = pe.data
    base = pe.image_base
    cpp_code = cpp_err = py_code = py_err = ""
    cpp_time = py_time = 0.0

    # --- C++ engine ---
    if not args.py_only:
        print(f"  {_DIM}Running C++ decompiler ...{_RESET}", end="", flush=True)
        cpp_code, cpp_time, cpp_err = run_cpp_decompile(
            sla, target, spec_dir, image, base, func_addr, func_size)
        ok = bool(cpp_code.strip())
        print("\r" + _status(ok, f"C++ decompile done ({cpp_time:.3f}s)"))

    # --- Python engine ---
    if not args.cpp_only:
        flags = []
        if args.heritage:
            flags.append("heritage")
        if args.rules:
            flags.append("rules")
        if args.full_actions:
            flags.append("full-actions")
        if args.printc:
            flags.append("printc")
        flag_str = f" [{', '.join(flags)}]" if flags else " [lift+flow only]"
        print(f"  {_DIM}Running Python decompiler{flag_str} ...{_RESET}",
              end="", flush=True)
        py_code, py_time, py_err = run_py_decompile(
            sla, target, spec_dir, image, base, func_addr, func_size,
            heritage=args.heritage, rules=args.rules,
            full_actions=args.full_actions, printc=args.printc)
        ok = bool(py_code.strip())
        print("\r" + _status(ok, f"Python decompile done ({py_time:.3f}s)  "))

    # --- Print results ---
    if not args.py_only:
        print_result("C++ (Native)", cpp_code, cpp_time, cpp_err)
    if not args.cpp_only:
        print_result("Python", py_code, py_time, py_err)

    # --- Diff summary ---
    if args.diff and not args.cpp_only and not args.py_only:
        cpp_lines = [l for l in cpp_code.splitlines() if l.strip()]
        py_lines = [l for l in py_code.splitlines() if l.strip()]
        print(_section("Diff Summary"))
        print(f"  C++ lines:    {len(cpp_lines)}")
        print(f"  Python lines: {len(py_lines)}")
        if cpp_time > 0:
            print(f"  Speed ratio:  Python is {py_time / cpp_time:.1f}x "
                  f"{'slower' if py_time > cpp_time else 'faster'}")
        print()

    return 0


if __name__ == "__main__":
    sys.exit(main())
