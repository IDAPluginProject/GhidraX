"""Diagnose remaining 8 diff functions."""
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

def show_pcode(addr):
    insn = lifter._native.pcode(addr)
    ops_str = []
    for op in insn.ops:
        try:
            name = OpCode(op.opcode).name
        except:
            name = f"op{op.opcode}"
        ops_str.append(name)
    print(f"  0x{addr:x} [{insn.length}B]: {', '.join(ops_str)}")
    return insn

# 0x40a3b0: Block[11] @0x40a488 stop differs (C++=0x40a495, Py=0x40a4a3)
# What's at 0x40a488-0x40a4a3?
print("=== 0x40a3b0: Block[11] @0x40a488 ===")
addr = 0x40a488
for _ in range(10):
    try:
        insn = show_pcode(addr)
        for op in insn.ops:
            if op.opcode in (OpCode.CPUI_BRANCHIND.value, OpCode.CPUI_CALL.value,
                             OpCode.CPUI_BRANCH.value, OpCode.CPUI_CBRANCH.value,
                             OpCode.CPUI_RETURN.value):
                try:
                    name = OpCode(op.opcode).name
                except:
                    name = str(op.opcode)
                inputs = []
                for inp in op.inputs:
                    inputs.append(f"{inp.space}[0x{inp.offset:x}:{inp.size}]")
                print(f"    -> {name}({', '.join(inputs)})")
        addr += insn.length
        if addr > 0x40a4a5:
            break
    except:
        break

# 0x417670: Non-returning call - C++ stops at 0x417682
print("\n=== 0x417670: Non-returning call ===")
addr = 0x417670
for _ in range(15):
    try:
        insn = show_pcode(addr)
        for op in insn.ops:
            if op.opcode == OpCode.CPUI_CALL.value:
                tgt = op.inputs[0] if op.inputs else None
                if tgt:
                    print(f"    -> CALL target: {tgt.space}[0x{tgt.offset:x}]")
        addr += insn.length
        if addr > 0x4176b0:
            break
    except:
        break

# 0x40b420: Block[14] @0x40b4a0 - what causes self-loop?
print("\n=== 0x40b420: Block[14] @0x40b4a0 ===")
addr = 0x40b49a
for _ in range(10):
    try:
        insn = show_pcode(addr)
        for op in insn.ops:
            if op.opcode in (OpCode.CPUI_BRANCH.value, OpCode.CPUI_CBRANCH.value):
                tgt = op.inputs[0] if op.inputs else None
                if tgt:
                    print(f"    -> {OpCode(op.opcode).name} target: {tgt.space}[0x{tgt.offset:x}]")
        addr += insn.length
        if addr > 0x40b4b5:
            break
    except:
        break

# 0x40d3b0: Block[25] @0x40d5da - succ mismatch
print("\n=== 0x40d3b0: Block[25] @0x40d5da ===")
addr = 0x40d5d0
for _ in range(10):
    try:
        insn = show_pcode(addr)
        for op in insn.ops:
            if op.opcode in (OpCode.CPUI_BRANCH.value, OpCode.CPUI_CBRANCH.value):
                tgt = op.inputs[0] if op.inputs else None
                if tgt:
                    print(f"    -> {OpCode(op.opcode).name} target: {tgt.space}[0x{tgt.offset:x}]")
        addr += insn.length
        if addr > 0x40d5f0:
            break
    except:
        break
