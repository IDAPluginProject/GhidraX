"""Check RETURN input[0] in both C++ and Python for matching functions."""
import sys
sys.path.insert(0, 'python')
sys.path.insert(0, '.')
from tests.test_cpexe_comparison import load_pe
from ghidra.sleigh.decompiler_native import DecompilerNative
from ghidra.sleigh.bridge_validator import _snapshot_from_cpp_dict, _snapshot_from_python_fd
from ghidra.sleigh.decompiler_python import (
    _split_basic_blocks, _setup_call_specs,
    _inject_tracked_context, _run_prerequisite_actions, _ArchitectureShim
)
from ghidra.sleigh.lifter import Lifter
from ghidra.core.opcodes import OpCode

pe = load_pe('bin/cp.exe')
dn = DecompilerNative()
dn.add_spec_path('specs')
dn.initialize()
lifter = Lifter('specs/x86.sla', {'addrsize': 1, 'opsize': 1})
lifter.set_image(pe.image_base, pe.image)

# Pick a matching function (small)
func = 0x404210
cpp_r = dn.decompile_staged(
    'specs/x86.sla', 'x86:LE:32:default',
    pe.image, pe.image_base, func, 0, 'heritage'
)
cpp_snap = _snapshot_from_cpp_dict('heritage', cpp_r)

fd = lifter.lift_function('f', func, 0)
_split_basic_blocks(fd)
arch = _ArchitectureShim(lifter._spc_mgr)
fd.setArch(arch)
_inject_tracked_context(fd, lifter)
_setup_call_specs(fd, lifter)
_run_prerequisite_actions(fd)
fd.opHeritage()
py_snap = _snapshot_from_python_fd('heritage', fd)

# Find RETURN ops in both
print("=== C++ RETURNs ===")
for b in cpp_snap.blocks:
    for op in b.ops:
        if op.opcode == OpCode.CPUI_RETURN:
            inputs = [(i.space, i.offset, i.size) for i in op.inputs]
            print(f"  @0x{op.addr:x}: inputs={inputs}")

print("=== Python RETURNs ===")
for b in py_snap.blocks:
    for op in b.ops:
        if op.opcode == OpCode.CPUI_RETURN:
            inputs = [(i.space, i.offset, i.size) for i in op.inputs]
            print(f"  @0x{op.addr:x}: inputs={inputs}")

# Also check a diff function
func2 = 0x41d720
cpp_r2 = dn.decompile_staged(
    'specs/x86.sla', 'x86:LE:32:default',
    pe.image, pe.image_base, func2, 0, 'heritage'
)
cpp_snap2 = _snapshot_from_cpp_dict('heritage', cpp_r2)

fd2 = lifter.lift_function('f2', func2, 0)
_split_basic_blocks(fd2)
arch2 = _ArchitectureShim(lifter._spc_mgr)
fd2.setArch(arch2)
_inject_tracked_context(fd2, lifter)
_setup_call_specs(fd2, lifter)
_run_prerequisite_actions(fd2)
fd2.opHeritage()
py_snap2 = _snapshot_from_python_fd('heritage', fd2)

print("\n=== C++ RETURNs (0x41d720) ===")
for b in cpp_snap2.blocks:
    for op in b.ops:
        if op.opcode == OpCode.CPUI_RETURN:
            inputs = [(i.space, i.offset, i.size) for i in op.inputs]
            print(f"  @0x{op.addr:x}: inputs={inputs}")

print("=== Python RETURNs (0x41d720) ===")
for b in py_snap2.blocks:
    for op in b.ops:
        if op.opcode == OpCode.CPUI_RETURN:
            inputs = [(i.space, i.offset, i.size) for i in op.inputs]
            print(f"  @0x{op.addr:x}: inputs={inputs}")
