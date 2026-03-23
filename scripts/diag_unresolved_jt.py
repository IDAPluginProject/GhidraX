"""Check unresolved BRANCHIND patterns at 0x40a3b0 and 0x40c090."""
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

def show_detail(addr):
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

# Find BRANCHIND near 0x40a41d (block[6] start)
print("=== 0x40a3b0: Block[6] @0x40a41d - BRANCHIND ===")
addr = 0x40a41d
for _ in range(8):
    try:
        insn = show_detail(addr)
        for op in insn.ops:
            if op.opcode == OpCode.CPUI_BRANCHIND.value:
                print(f"    *** BRANCHIND found at 0x{addr:x} ***")
                targets = lifter._try_resolve_jumptable(insn.ops)
                print(f"    Resolution: {targets is not None}")
                if targets:
                    print(f"    Targets: {[f'0x{t:x}' for t in targets[:15]]}")
        addr += insn.length
    except:
        break

# Find BRANCHIND in 0x40c090
print("\n=== 0x40c090: looking for BRANCHIND ===")
# C++ block[19] @0x40c1d0 has succs [22, 28] — might be a CBRANCH, not BRANCHIND
# Let me check more broadly
fd = lifter.lift_function("test_40c090", 0x40c090, 0)
print(f"  jumptables resolved: {len(lifter._jumptables)}")
for a, t in lifter._jumptables.items():
    if 0x40c000 <= a <= 0x40d000:
        print(f"    0x{a:x}: {len(t)} targets")
