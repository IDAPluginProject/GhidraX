"""Compare MULTIEQUAL sets (not positions) between C++ and Python."""
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

# Get C++ heritage snapshot
dn = DecompilerNative()
dn.add_spec_path('specs')
dn.initialize()
cpp_result = dn.decompile_staged('specs/x86.sla', 'x86:LE:32:default', 
                                  pe.image, pe.image_base, func_addr, 0, 'heritage')
cpp_snap = _snapshot_from_cpp_dict('heritage', cpp_result)

# Get Python heritage snapshot
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

# Compare MULTIEQUAL sets for block 3
for bi in range(min(len(cpp_snap.blocks), len(py_snap.blocks))):
    cb = cpp_snap.blocks[bi]
    pb = py_snap.blocks[bi]
    
    # Extract MULTIEQUALs from each block
    cpp_meqs = [op for op in cb.ops if 'CPUI_MULTIEQUAL' in str(op)]
    py_meqs = [op for op in pb.ops if 'CPUI_MULTIEQUAL' in str(op)]
    
    if len(cpp_meqs) != len(py_meqs):
        print(f"Block[{bi}]: MULTIEQUAL count C++={len(cpp_meqs)} Py={len(py_meqs)}")
        # Show what each has
        cpp_set = set()
        py_set = set()
        for op in cpp_meqs:
            # Extract output varnode (before '=')
            parts = str(op).split(' = ')
            if len(parts) >= 2:
                # Get just the space/offset/size part
                addr_part = parts[0].split(' ')[-1]  
                cpp_set.add(addr_part)
        for op in py_meqs:
            parts = str(op).split(' = ')
            if len(parts) >= 2:
                addr_part = parts[0].split(' ')[-1]
                py_set.add(addr_part)
        
        only_cpp = cpp_set - py_set
        only_py = py_set - cpp_set
        if only_cpp:
            print(f"  Only in C++: {sorted(only_cpp)}")
        if only_py:
            print(f"  Only in Py:  {sorted(only_py)}")

# Also: count total MULTIEQUALs
cpp_total_meq = sum(1 for b in cpp_snap.blocks for op in b.ops if 'CPUI_MULTIEQUAL' in str(op))
py_total_meq = sum(1 for b in py_snap.blocks for op in b.ops if 'CPUI_MULTIEQUAL' in str(op))
print(f"\nTotal MULTIEQUALs: C++={cpp_total_meq} Py={py_total_meq}")
print(f"Total ops: C++={cpp_snap.total_ops} Py={py_snap.total_ops}")

# Count register vs unique MULTIEQUALs in C++
cpp_reg_meq = sum(1 for b in cpp_snap.blocks for op in b.ops 
                   if 'CPUI_MULTIEQUAL' in str(op) and 'register[' in str(op).split('=')[0])
cpp_uniq_meq = sum(1 for b in cpp_snap.blocks for op in b.ops 
                    if 'CPUI_MULTIEQUAL' in str(op) and 'unique[' in str(op).split('=')[0])
print(f"C++ MULTIEQUALs: register={cpp_reg_meq} unique={cpp_uniq_meq}")
