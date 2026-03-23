"""Diagnose REP instruction handling differences."""
import sys, os
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', 'python'))
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..'))

from tests.test_cpexe_comparison import load_pe, SLA_PATH
from ghidra.sleigh.lifter import Lifter
from ghidra.core.opcodes import OpCode

pe = load_pe('bin/cp.exe')
context = {"addrsize": 1, "opsize": 1}
lifter = Lifter(SLA_PATH, context)
lifter.set_image(pe.image_base, pe.image)

# Check instruction at 0x40b4a0 (from 0x40b420 function)
for addr in [0x40b4a0, 0x40d5da, 0x41bbee]:
    try:
        insn = lifter._native.pcode(addr)
        print(f"\n=== 0x{addr:x} length={insn.length} ===")
        for i, op in enumerate(insn.ops):
            inputs = []
            for inp in op.inputs:
                inputs.append(f"{inp.space}[0x{inp.offset:x}:{inp.size}]")
            out = ""
            if op.output:
                out = f"{op.output.space}[0x{op.output.offset:x}:{op.output.size}] = "
            try:
                opc_name = OpCode(op.opcode).name
            except:
                opc_name = f"op{op.opcode}"
            print(f"  [{i}] {out}{opc_name}({', '.join(inputs)})")
    except Exception as e:
        print(f"  Error: {e}")

# Also check 0x41d800 for comparison (the one that works)
print("\n=== 0x41d800 (working example) ===")
insn = lifter._native.pcode(0x41d800)
print(f"  length={insn.length}, {len(insn.ops)} ops")
has_branch = any(op.opcode in (OpCode.CPUI_BRANCH.value, OpCode.CPUI_CBRANCH.value) for op in insn.ops)
print(f"  has BRANCH/CBRANCH: {has_branch}")
