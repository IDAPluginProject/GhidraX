"""Compare flow-stage (pre-heritage) P-code between C++ and Python for a specific function."""
import sys, os
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', 'python'))
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..'))

from tests.test_cpexe_comparison import load_pe, run_flow_comparison
from ghidra.sleigh.decompiler_native import DecompilerNative

pe = load_pe('bin/cp.exe')
dn = DecompilerNative()
dn.add_spec_path('specs')
dn.initialize()

# Check flow-stage comparison for a function with MULTIEQUAL diffs
func_addr = 0x401080
r = run_flow_comparison(dn, pe, func_addr)
print(f"0x{func_addr:08x}: flow match={r.full_match}, unexpected={r.unexpected_count}")
print(f"  C++={r.cpp_blocks}blk/{r.cpp_ops}ops Py={r.py_blocks}blk/{r.py_ops}ops")
for d in r.diff_details:
    print(f"  {d}")

# Now look at raw P-code for block 3 specifically
# Get C++ flow snapshot
from ghidra.sleigh.bridge_validator import _snapshot_from_cpp_dict, _snapshot_from_python_fd
cpp_result = dn.decompile_staged('specs/x86.sla', 'x86:LE:32:default', pe.image, pe.image_base, func_addr, 0, 'flow')
cpp_snap = _snapshot_from_cpp_dict('flow', cpp_result)

# Get Python flow snapshot 
from ghidra.sleigh.lifter import Lifter
from ghidra.sleigh.decompiler_python import _split_basic_blocks
lifter = Lifter('specs/x86.sla', {'addrsize': 1, 'opsize': 1})
lifter.set_image(pe.image_base, pe.image)
fd = lifter.lift_function(f'func_{func_addr:x}', func_addr, 0)
_split_basic_blocks(fd)
py_snap = _snapshot_from_python_fd('flow', fd)

# Compare block 3 ops
if len(cpp_snap.blocks) > 3 and len(py_snap.blocks) > 3:
    cpp_b3 = cpp_snap.blocks[3]
    py_b3 = py_snap.blocks[3]
    print(f"\n=== Block 3 comparison ===")
    print(f"C++ block 3: start=0x{cpp_b3.start:x} stop=0x{cpp_b3.stop:x} ops={cpp_b3.num_ops}")
    print(f"Py  block 3: start=0x{py_b3.start:x} stop=0x{py_b3.stop:x} ops={py_b3.num_ops}")
    
    # Show first 5 ops from each
    for i in range(min(5, cpp_b3.num_ops)):
        cop = cpp_b3.ops[i]
        print(f"  C++[{i}]: {cop}")
    for i in range(min(5, py_b3.num_ops)):
        pop = py_b3.ops[i]
        print(f"  Py [{i}]: {pop}")

# Check heritage comparison for specific ops
print("\n=== Heritage stage comparison ===")
from tests.test_cpexe_comparison import run_heritage_comparison
r2 = run_heritage_comparison(dn, pe, func_addr)
print(f"heritage match={r2.full_match}, unexpected={r2.unexpected_count}")
for d in r2.diff_details[:10]:
    print(f"  {d}")
