"""Diagnose 0x41b610 self-loop function."""
import sys, os
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', 'python'))
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..'))

from tests.test_cpexe_comparison import load_pe, SLA_PATH
from ghidra.sleigh.lifter import Lifter

pe = load_pe('bin/cp.exe')
context = {"addrsize": 1, "opsize": 1}
lifter = Lifter(SLA_PATH, context)
lifter.set_image(pe.image_base, pe.image)

# Get raw p-code for 0x41b610
insn = lifter._native.pcode(0x41b610)
print(f"Instruction at 0x41b610, length={insn.length}")
from ghidra.core.opcodes import OpCode
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

# Also check the next instruction
next_addr = 0x41b610 + insn.length
print(f"\nNext instruction at 0x{next_addr:x}")
insn2 = lifter._native.pcode(next_addr)
print(f"  length={insn2.length}")
for i, op in enumerate(insn2.ops):
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
