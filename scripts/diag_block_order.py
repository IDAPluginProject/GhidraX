"""Compare block addresses between C++ and Python heritage snapshots."""
import sys, os
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', 'python'))
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..'))

from tests.test_cpexe_comparison import load_pe
from ghidra.sleigh.decompiler_native import DecompilerNative
from ghidra.sleigh.bridge_validator import _snapshot_from_cpp_dict, _snapshot_from_python_fd
from ghidra.sleigh.lifter import Lifter
from ghidra.sleigh.decompiler_python import (
    _split_basic_blocks, _setup_call_specs, _inject_tracked_context,
    _run_prerequisite_actions, _ArchitectureShim,
)

pe = load_pe('bin/cp.exe')
func_addr = 0x4099a0

# C++ heritage
dn = DecompilerNative()
dn.add_spec_path('specs')
dn.initialize()
cpp_result = dn.decompile_staged('specs/x86.sla', 'x86:LE:32:default', 
                                  pe.image, pe.image_base, func_addr, 0, 'heritage')
cpp_snap = _snapshot_from_cpp_dict('heritage', cpp_result)

# Python heritage
lifter = Lifter('specs/x86.sla', {'addrsize': 1, 'opsize': 1})
lifter.set_image(pe.image_base, pe.image)
fd = lifter.lift_function(f'func_{func_addr:x}', func_addr, 0)
_split_basic_blocks(fd)
arch = _ArchitectureShim(lifter._spc_mgr)
fd.setArch(arch)
_inject_tracked_context(fd, lifter)
_setup_call_specs(fd, lifter)
_run_prerequisite_actions(fd)
fd.opHeritage()
py_snap = _snapshot_from_python_fd('heritage', fd)

print(f"Blocks: C++={len(cpp_snap.blocks)} Py={len(py_snap.blocks)}")
print(f"\n{'Idx':>3} {'C++ start':>12} {'C++ stop':>12} {'C++ meqs':>8} | {'Py start':>12} {'Py stop':>12} {'Py meqs':>8} {'Match?':>6}")
for i in range(max(len(cpp_snap.blocks), len(py_snap.blocks))):
    cb = cpp_snap.blocks[i] if i < len(cpp_snap.blocks) else None
    pb = py_snap.blocks[i] if i < len(py_snap.blocks) else None
    
    cpp_start = f"0x{cb.start:x}" if cb else "-"
    cpp_stop = f"0x{cb.stop:x}" if cb else "-"
    cpp_meqs = sum(1 for op in cb.ops if 'CPUI_MULTIEQUAL' in str(op)) if cb else 0
    
    py_start = f"0x{pb.start:x}" if pb else "-"
    py_stop = f"0x{pb.stop:x}" if pb else "-"
    py_meqs = sum(1 for op in pb.ops if 'CPUI_MULTIEQUAL' in str(op)) if pb else 0
    
    addr_match = (cb and pb and cb.start == pb.start) if True else False
    mark = "YES" if addr_match else "NO"
    
    print(f"{i:3d} {cpp_start:>12} {cpp_stop:>12} {cpp_meqs:>8} | {py_start:>12} {py_stop:>12} {py_meqs:>8} {mark:>6}")
