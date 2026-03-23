"""Deep dive into MULTIEQUAL register vs unique for a specific diff function."""
import sys, os
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', 'python'))
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..'))

from tests.test_cpexe_comparison import load_pe, run_heritage_comparison
from ghidra.sleigh.lifter import Lifter
from ghidra.sleigh.decompiler_python import (
    _split_basic_blocks, _setup_call_specs, _inject_tracked_context,
    _run_prerequisite_actions, _ArchitectureShim,
)
from ghidra.core.opcodes import OpCode
from ghidra.analysis.heritage import Heritage

pe = load_pe('bin/cp.exe')

# Pick a function with MULTIEQUAL register vs unique diffs
func_addr = 0x4099a0

lifter = Lifter('specs/x86.sla', {'addrsize': 1, 'opsize': 1})
lifter.set_image(pe.image_base, pe.image)
fd = lifter.lift_function(f'func_{func_addr:x}', func_addr, 0)
_split_basic_blocks(fd)
arch = _ArchitectureShim(lifter._spc_mgr)
fd.setArch(arch)
_inject_tracked_context(fd, lifter)
_setup_call_specs(fd, lifter)
_run_prerequisite_actions(fd)

# Monkey-patch placeMultiequals to trace
orig_placeMultiequals = Heritage.placeMultiequals
def traced_placeMultiequals(self):
    reg_ranges = []
    unique_ranges = []
    for mr in self._disjoint._list:
        spc = mr.addr.getSpace()
        if spc and spc.getName() == 'register':
            reg_ranges.append(f"register[0x{mr.addr.getOffset():x}:{mr.size}]")
        elif spc and spc.getName() == 'unique':
            unique_ranges.append(f"unique[0x{mr.addr.getOffset():x}:{mr.size}]")
    print(f"placeMultiequals: {len(self._disjoint._list)} ranges")
    print(f"  register ranges ({len(reg_ranges)}):")
    for r in reg_ranges:
        print(f"    {r}")
    print(f"  unique ranges ({len(unique_ranges)}):")
    for r in unique_ranges[:10]:
        print(f"    {r}")
    if len(unique_ranges) > 10:
        print(f"    ... and {len(unique_ranges)-10} more")
    return orig_placeMultiequals(self)
Heritage.placeMultiequals = traced_placeMultiequals

fd.opHeritage()

# Count MULTIEQUALs
meq_reg = {}
meq_unique = {}
for op in fd._obank.beginAlive():
    if op.code() == OpCode.CPUI_MULTIEQUAL:
        out = op.getOut()
        if out and out.getSpace():
            key = f"{out.getSpace().getName()}[0x{out.getOffset():x}:{out.getSize()}]"
            if out.getSpace().getName() == 'register':
                meq_reg[key] = meq_reg.get(key, 0) + 1
            elif out.getSpace().getName() == 'unique':
                meq_unique[key] = meq_unique.get(key, 0) + 1

print(f"\nMULTIEQUAL outputs -> register ({sum(meq_reg.values())} total):")
for k, v in sorted(meq_reg.items()):
    print(f"  {k}: {v}")
print(f"\nMULTIEQUAL outputs -> unique ({sum(meq_unique.values())} total):")
for k, v in sorted(meq_unique.items()):
    print(f"  {k}: {v}")

# Also check flow-stage comparison
from ghidra.sleigh.decompiler_native import DecompilerNative
dn = DecompilerNative()
dn.add_spec_path('specs')
dn.initialize()
from tests.test_cpexe_comparison import run_flow_comparison
r = run_flow_comparison(dn, pe, func_addr)
print(f"\nFlow comparison: match={r.full_match}, unexpected={r.unexpected_count}")
print(f"  C++={r.cpp_blocks}blk/{r.cpp_ops}ops Py={r.py_blocks}blk/{r.py_ops}ops")
