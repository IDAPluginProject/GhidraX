"""Check if space object identity matches between varnodes and architecture."""
import sys, os
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', 'python'))
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..'))

from tests.test_cpexe_comparison import load_pe
from ghidra.sleigh.lifter import Lifter
from ghidra.sleigh.decompiler_python import (
    _split_basic_blocks, _setup_call_specs, _inject_tracked_context,
    _run_prerequisite_actions, _ArchitectureShim,
)
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

# Build heritage info list
h = Heritage(fd)
h.buildInfoList()

# Get the register space from info list
info_reg_space = None
info_unique_space = None
for info in h._infolist:
    if info.space is not None:
        if info.space.getName() == 'register':
            info_reg_space = info.space
        elif info.space.getName() == 'unique':
            info_unique_space = info.space

print(f"Info register space: id={id(info_reg_space)}")
print(f"Info unique space: id={id(info_unique_space)}")

# Check varnode spaces
reg_match = 0
reg_mismatch = 0
unique_match = 0
unique_mismatch = 0

for vn in fd._vbank.beginLoc():
    spc = vn.getSpace()
    if spc is None:
        continue
    if spc.getName() == 'register':
        if spc is info_reg_space:
            reg_match += 1
        else:
            reg_mismatch += 1
            if reg_mismatch <= 3:
                print(f"  MISMATCH register: vn space id={id(spc)}, info space id={id(info_reg_space)}, == {spc == info_reg_space}")
    elif spc.getName() == 'unique':
        if spc is info_unique_space:
            unique_match += 1
        else:
            unique_mismatch += 1
            if unique_mismatch <= 3:
                print(f"  MISMATCH unique: vn space id={id(spc)}, info space id={id(info_unique_space)}, == {spc == info_unique_space}")

print(f"\nRegister: is_match={reg_match}, is_mismatch={reg_mismatch}")
print(f"Unique: is_match={unique_match}, is_mismatch={unique_mismatch}")
