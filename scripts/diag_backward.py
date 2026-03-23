"""Check if backward jumps are being followed for 0x40d790."""
import sys
sys.path.insert(0, 'python')
sys.path.insert(0, '.')
from tests.test_cpexe_comparison import load_pe
from ghidra.sleigh.lifter import Lifter
from ghidra.sleigh.decompiler_python import (
    _split_basic_blocks, _setup_call_specs,
    _inject_tracked_context, _run_prerequisite_actions, _ArchitectureShim
)

pe = load_pe('bin/cp.exe')
lifter = Lifter('specs/x86.sla', {'addrsize': 1, 'opsize': 1})
lifter.set_image(pe.image_base, pe.image)

for func in [0x40d790, 0x40d7d0]:
    fd = lifter.lift_function('f', func, 0)
    _split_basic_blocks(fd)
    arch = _ArchitectureShim(lifter._spc_mgr)
    fd.setArch(arch)
    _inject_tracked_context(fd, lifter)
    _setup_call_specs(fd, lifter)
    _run_prerequisite_actions(fd)
    
    bg = fd.getBasicBlocks()
    print(f"\n=== 0x{func:x} ({bg.getSize()} blocks) ===")
    for i in range(bg.getSize()):
        b = bg.getBlock(i)
        addr = b.getStart().getOffset()
        succs = [b.getOut(j).getIndex() for j in range(b.sizeOut())]
        preds = [b.getIn(j).getIndex() for j in range(b.sizeIn())]
        ops = list(b.getOpList())
        print(f"  block[{i}] @0x{addr:x} ops={len(ops)} succs={succs} preds={preds}")
