"""Diagnose edge differences for function 0x40b420."""
import sys
sys.path.insert(0, 'python')
sys.path.insert(0, '.')
from tests.test_cpexe_comparison import load_pe
from ghidra.sleigh.decompiler_native import DecompilerNative
from ghidra.sleigh.bridge_validator import _snapshot_from_cpp_dict
from ghidra.core.opcodes import OpCode

pe = load_pe('bin/cp.exe')

# Check bytes at key addresses
base = pe.image_base
for addr in [0x40b441, 0x40b449, 0x40b44b]:
    off = addr - base
    bs = pe.image[off:off+8]
    print(f"@0x{addr:x}: {' '.join(f'{b:02x}' for b in bs)}")

# C++ block details
dn = DecompilerNative()
dn.add_spec_path('specs')
dn.initialize()
cpp_r = dn.decompile_staged(
    'specs/x86.sla', 'x86:LE:32:default',
    pe.image, pe.image_base, 0x40b420, 0, 'heritage'
)
cpp_snap = _snapshot_from_cpp_dict('heritage', cpp_r)
cpp_by_idx = {b.index: b for b in cpp_snap.blocks}

# Show block[3] ops from C++
b3 = cpp_by_idx[3]
print(f"\nC++ block[3]@0x{b3.start:x} stop=0x{b3.stop:x}: succs={b3.successors}")
for op in b3.ops[-5:]:
    inp_str = ', '.join(f"{i.space}[0x{i.offset:x}:{i.size}]" for i in op.inputs)
    out_str = f"{op.output.space}[0x{op.output.offset:x}:{op.output.size}]" if op.output else "-"
    print(f"  @0x{op.addr:x} opc={op.opcode} out={out_str} in=[{inp_str}]")

# Compare index-to-address mapping
from ghidra.sleigh.lifter import Lifter
from ghidra.sleigh.decompiler_python import (
    _split_basic_blocks, _setup_call_specs,
    _inject_tracked_context, _run_prerequisite_actions, _ArchitectureShim
)
lifter = Lifter('specs/x86.sla', {'addrsize': 1, 'opsize': 1})
lifter.set_image(pe.image_base, pe.image)
fd = lifter.lift_function('f', 0x40b420, 0)
_split_basic_blocks(fd)
arch = _ArchitectureShim(lifter._spc_mgr)
fd.setArch(arch)
_inject_tracked_context(fd, lifter)
_setup_call_specs(fd, lifter)
_run_prerequisite_actions(fd)
bg = fd.getBasicBlocks()

print("\n=== Index-to-address comparison ===")
cpp_map = {b.index: b.start for b in cpp_snap.blocks}
py_map = {bg.getBlock(i).getIndex(): bg.getBlock(i).getStart().getOffset()
           for i in range(bg.getSize())}
diffs = 0
for idx in sorted(set(list(cpp_map.keys()) + list(py_map.keys()))):
    ca = cpp_map.get(idx)
    pa = py_map.get(idx)
    if ca != pa:
        diffs += 1
        cs = f"0x{ca:x}" if ca is not None else "None"
        ps = f"0x{pa:x}" if pa is not None else "None"
        print(f"  idx={idx}: C++={cs} Py={ps}")
print(f"Total index diffs: {diffs}/{max(len(cpp_map), len(py_map))}")
