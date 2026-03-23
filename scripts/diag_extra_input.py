"""Diagnose op ordering at call sites: INT_ADD/LOAD placeholder vs INDIRECT."""
import sys, os
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', 'python'))

from ghidra.sleigh.lifter import Lifter
from ghidra.sleigh.decompiler_python import (
    _split_basic_blocks, _setup_call_specs, _inject_tracked_context,
    _run_prerequisite_actions, _ArchitectureShim,
)
from ghidra.core.opcodes import OpCode

SPEC_DIR = os.path.join(os.path.dirname(__file__), '..', 'specs')
SLA_PATH = os.path.join(SPEC_DIR, 'x86.sla')

sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', 'tests'))
from test_cpexe_comparison import load_pe, BIN_PATH
pe = load_pe(BIN_PATH)
func_addr = pe.functions[0]  # 0x401000

def dump_ops(label, fd, start=0, count=40):
    bb = fd.getBasicBlocks().getBlock(0)
    ops = bb.getOpList()
    print(f"\n=== {label} (ops {start}-{start+count-1} of {len(ops)}) ===")
    for i in range(start, min(start+count, len(ops))):
        op = ops[i]
        ninp = op.numInput()
        inputs = []
        for k in range(ninp):
            v = op.getIn(k)
            if v is not None:
                sn = v.getSpace().getName()
                inputs.append(f"{sn}[0x{v.getAddr().getOffset():x}:{v.getSize()}]")
            else:
                inputs.append("None")
        out = op.getOut()
        out_s = f"{out.getSpace().getName()}[0x{out.getAddr().getOffset():x}:{out.getSize()}]" if out else "void"
        print(f"  [{i:2d}] {out_s} = {op.code().name}({', '.join(inputs)})")

context = {"addrsize": 1, "opsize": 1}
lifter = Lifter(SLA_PATH, context)
lifter.set_image(pe.image_base, pe.image)
fd = lifter.lift_function(f"func_{func_addr:x}", func_addr, 0)
_split_basic_blocks(fd)
arch_shim = _ArchitectureShim(lifter._spc_mgr)
fd.setArch(arch_shim)
_inject_tracked_context(fd, lifter)
_setup_call_specs(fd, lifter)

dump_ops("After setup (before prerequisite actions)", fd, 15, 15)

_run_prerequisite_actions(fd)
dump_ops("After prerequisite actions (before heritage)", fd, 15, 20)

fd.opHeritage()
dump_ops("After Heritage", fd, 15, 25)
