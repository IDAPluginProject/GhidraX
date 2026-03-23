"""Diagnose 0x41b610 self-loop: C++ 2 blocks, Python 1 block."""
import sys, os
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', 'python'))
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..'))

from tests.test_cpexe_comparison import load_pe, SLA_PATH, run_heritage_comparison
from ghidra.sleigh.lifter import Lifter
from ghidra.sleigh.decompiler_python import (
    _split_basic_blocks, _setup_call_specs, _inject_tracked_context,
    _run_prerequisite_actions, _ArchitectureShim,
)
from ghidra.core.opcodes import OpCode

pe = load_pe('bin/cp.exe')
context = {"addrsize": 1, "opsize": 1}
lifter = Lifter(SLA_PATH, context)
lifter.set_image(pe.image_base, pe.image)

# Show p-code
insn = lifter._native.pcode(0x41b610)
print(f"0x41b610 [{insn.length}B]:")
for i, op in enumerate(insn.ops):
    inputs = [f"{inp.space}[0x{inp.offset:x}:{inp.size}]" for inp in op.inputs]
    out = f"{op.output.space}[0x{op.output.offset:x}:{op.output.size}] = " if op.output else ""
    print(f"  [{i}] {out}{OpCode(op.opcode).name}({', '.join(inputs)})")

# Lift and split
fd = lifter.lift_function("test", 0x41b610, 0)
_split_basic_blocks(fd, lifter=lifter)
arch_shim = _ArchitectureShim(lifter._spc_mgr)
fd.setArch(arch_shim)
_inject_tracked_context(fd, lifter)

bblocks = fd.getBasicBlocks()
print(f"\nPython: {bblocks.getSize()} blocks")
for bi in range(bblocks.getSize()):
    bb = bblocks.getBlock(bi)
    ops = bb.getOpList()
    start = ops[0].getSeqNum().getAddr().getOffset() if ops else 0
    print(f"  Block[{bi}] @0x{start:x}: {len(ops)} ops")
    for op in ops:
        print(f"    {op.code().name} @ 0x{op.getSeqNum().getAddr().getOffset():x}")
    succs = [bb.getOut(j) for j in range(bb.sizeOut())]
    succ_ids = []
    for s in succs:
        for bi2 in range(bblocks.getSize()):
            if bblocks.getBlock(bi2) is s:
                succ_ids.append(bi2)
    print(f"    succs: {succ_ids}")

# What does C++ produce?
from ghidra.sleigh.decompiler_native import DecompilerNative
dn = DecompilerNative()
dn.add_spec_path('specs')
dn.initialize()
cpp = dn.decompile_staged(SLA_PATH, 'x86:LE:32:default:windows', pe.image, pe.image_base, 0x41b610, 0, 'heritage')
print(f"\nC++: {cpp['num_blocks']} blocks, {cpp['num_ops']} ops")
if 'blocks' in cpp:
    for b in cpp['blocks']:
        print(f"  Block @0x{b.get('start', 0):x}: {b.get('num_ops', 0)} ops, succs={b.get('succs', [])}")
