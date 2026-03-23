"""Compare MULTIEQUAL output sets between C++ and Python for a diff function."""
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
func_addr = 0x403490  # first diff function with MULTIEQUAL issue

# C++
dn = DecompilerNative()
dn.add_spec_path('specs')
dn.initialize()
cpp_result = dn.decompile_staged('specs/x86.sla', 'x86:LE:32:default',
                                  pe.image, pe.image_base, func_addr, 0, 'heritage')
cpp_snap = _snapshot_from_cpp_dict('heritage', cpp_result)

# Python
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

# For each block, extract MULTIEQUAL output varnodes as sets
def extract_meq_outputs(snap):
    """Return dict: block_start_addr -> set of MULTIEQUAL output varnode strings."""
    result = {}
    for b in snap.blocks:
        meqs = set()
        for op_str in b.ops:
            s = str(op_str)
            if 'CPUI_MULTIEQUAL' in s:
                # Extract output: everything before ' = CPUI_MULTIEQUAL'
                parts = s.split(' = CPUI_MULTIEQUAL')
                if parts:
                    # Get the varnode part (last space-separated token before =)
                    tokens = parts[0].strip().split()
                    if tokens:
                        meqs.add(tokens[-1])
        result[b.start] = meqs
    return result

cpp_meqs = extract_meq_outputs(cpp_snap)
py_meqs = extract_meq_outputs(py_snap)

# Compare
all_addrs = sorted(set(cpp_meqs.keys()) | set(py_meqs.keys()))
total_only_cpp = 0
total_only_py = 0
for addr in all_addrs:
    cm = cpp_meqs.get(addr, set())
    pm = py_meqs.get(addr, set())
    if cm != pm:
        only_cpp = cm - pm
        only_py = pm - cm
        total_only_cpp += len(only_cpp)
        total_only_py += len(only_py)
        print(f"Block 0x{addr:x}: C++={len(cm)} Py={len(pm)}")
        if only_cpp:
            print(f"  Only C++: {sorted(only_cpp)}")
        if only_py:
            print(f"  Only Py:  {sorted(only_py)}")

print(f"\nTotal MULTIEQUAL outputs only in C++: {total_only_cpp}")
print(f"Total MULTIEQUAL outputs only in Py:  {total_only_py}")
cpp_total = sum(len(v) for v in cpp_meqs.values())
py_total = sum(len(v) for v in py_meqs.values())
print(f"Total MULTIEQUALs: C++={cpp_total} Py={py_total}")
