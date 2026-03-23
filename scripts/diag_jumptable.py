"""Diagnose jump table patterns in diff functions."""
import sys, os
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', 'python'))
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..'))

from tests.test_cpexe_comparison import load_pe, SLA_PATH
from ghidra.sleigh.lifter import Lifter
from ghidra.core.opcodes import OpCode
import struct

pe = load_pe('bin/cp.exe')
context = {"addrsize": 1, "opsize": 1}
lifter = Lifter(SLA_PATH, context)
lifter.set_image(pe.image_base, pe.image)

def show_pcode(addr):
    insn = lifter._native.pcode(addr)
    print(f"  0x{addr:x} [{insn.length}B]:")
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
        print(f"    [{i}] {out}{opc_name}({', '.join(inputs)})")
    return insn

# Check jump table functions — find BRANCHIND near block addresses from comparison
jt_funcs = [
    ("0x40a3b0", 0x40a41d),  # Block[6] 10 succs
    ("0x40ff90", 0x40ffbe),  # Block[1] 7 succs
    ("0x41b150", 0x41b170),  # Block[1] 8 succs
    ("0x410390", 0x41401a),  # Block[6] 14 succs
]

for name, start in jt_funcs:
    print(f"\n=== {name} near 0x{start:x} ===")
    addr = start
    for _ in range(8):
        try:
            insn = show_pcode(addr)
        except Exception as e:
            print(f"    Error at 0x{addr:x}: {e}")
            break
        found_branchind = False
        for op in insn.ops:
            if op.opcode == OpCode.CPUI_BRANCHIND.value:
                found_branchind = True
                print(f"    *** BRANCHIND at 0x{addr:x} ***")
                # Show preceding instructions for context
                print(f"\n  Context (3 insns before BRANCHIND):")
                prev = addr
                for j in range(3):
                    prev -= 1
                    # Find instruction start by trying nearby addresses
                    for delta in range(6):
                        try:
                            pi = lifter._native.pcode(prev - delta)
                            if pi.length > 0 and (prev - delta + pi.length > prev):
                                show_pcode(prev - delta)
                                prev = prev - delta
                                break
                        except:
                            pass
        addr += insn.length
        if found_branchind or insn.length == 0:
            break
