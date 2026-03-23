"""Diagnose which address spaces heritage processes and in what order."""
import sys, os
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', 'python'))
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..'))

from tests.test_cpexe_comparison import load_pe
from ghidra.sleigh.lifter import Lifter
from ghidra.sleigh.decompiler_python import (
    _split_basic_blocks, _setup_call_specs, _inject_tracked_context,
    _run_prerequisite_actions, _ArchitectureShim,
)
from ghidra.core.opcodes import OpCode
from ghidra.analysis.heritage import Heritage

pe = load_pe('bin/cp.exe')
func_addr = 0x401080

lifter = Lifter('specs/x86.sla', {'addrsize': 1, 'opsize': 1})
lifter.set_image(pe.image_base, pe.image)
fd = lifter.lift_function(f'func_{func_addr:x}', func_addr, 0)
_split_basic_blocks(fd)
arch = _ArchitectureShim(lifter._spc_mgr)
fd.setArch(arch)
_inject_tracked_context(fd, lifter)
_setup_call_specs(fd, lifter)
_run_prerequisite_actions(fd)

# Create heritage object
h = Heritage(fd)

print("=== Heritage info list ===")
for i, info in enumerate(h._infolist):
    spc = info.space
    print(f"  [{i}] space={spc.getName()} index={spc.getIndex()} "
          f"heritaged={info.isHeritaged()} delay={info.delay} "
          f"deadcodedelay={info.deadcodedelay}")

# Count varnodes per space before heritage
print("\n=== Varnode counts per space ===")
from collections import Counter
space_counts = Counter()
space_written = Counter()
for vn in fd._vbank.beginLoc():
    spc = vn.getSpace()
    if spc:
        space_counts[spc.getName()] += 1
        if vn.isWritten():
            space_written[spc.getName()] += 1

for name in sorted(space_counts.keys()):
    print(f"  {name}: total={space_counts[name]}, written={space_written[name]}")

# Now run heritage with tracing on the disjoint task list
print("\n=== Running heritage with task list tracing ===")
orig_placeMultiequals = Heritage.placeMultiequals
def traced_placeMultiequals(self):
    print(f"  placeMultiequals: {len(self._disjoint._list)} ranges")
    reg_ranges = 0
    unique_ranges = 0
    for mr in self._disjoint._list:
        spc = mr.addr.getSpace()
        if spc:
            if spc.getName() == 'register':
                reg_ranges += 1
            elif spc.getName() == 'unique':
                unique_ranges += 1
    print(f"    register ranges: {reg_ranges}")
    print(f"    unique ranges: {unique_ranges}")
    # Show first 10 ranges
    for i, mr in enumerate(self._disjoint._list[:20]):
        spc = mr.addr.getSpace()
        print(f"    [{i}] {spc.getName() if spc else '?'}[0x{mr.addr.getOffset():x}:{mr.size}] fl=0x{mr.flags:x}")
    return orig_placeMultiequals(self)
Heritage.placeMultiequals = traced_placeMultiequals

fd.opHeritage()

# Count MULTIEQUALs after heritage
meq_reg = 0
meq_unique = 0
for op in fd._obank.beginAlive():
    if op.code() == OpCode.CPUI_MULTIEQUAL:
        out = op.getOut()
        if out and out.getSpace():
            if out.getSpace().getName() == 'register':
                meq_reg += 1
            elif out.getSpace().getName() == 'unique':
                meq_unique += 1
print(f"\n=== After heritage ===")
print(f"  MULTIEQUAL -> register: {meq_reg}")
print(f"  MULTIEQUAL -> unique: {meq_unique}")
