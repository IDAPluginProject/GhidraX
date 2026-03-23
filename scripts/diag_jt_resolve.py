"""Test jump table resolution on known functions."""
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

# Test resolution on 0x41b150 (known jump table at 0x41b170)
insn = lifter._native.pcode(0x41b170)
targets = lifter._try_resolve_jumptable(insn.ops)
print(f"0x41b170 resolved: {targets is not None}")
if targets:
    print(f"  {len(targets)} targets: {[f'0x{t:x}' for t in targets]}")

# Test resolution on 0x41401a (known jump table in 0x410390)
insn2 = lifter._native.pcode(0x41401a)
targets2 = lifter._try_resolve_jumptable(insn2.ops)
print(f"\n0x41401a resolved: {targets2 is not None}")
if targets2:
    print(f"  {len(targets2)} targets: {[f'0x{t:x}' for t in targets2[:20]]}")
    if len(targets2) > 20:
        print(f"  ... and {len(targets2)-20} more")

# Now test lift_function to see if jumptables are populated
print("\n--- Testing lift_function for 0x41b150 ---")
fd = lifter.lift_function("test_41b150", 0x41b150, 0x200)
print(f"  jumptables: {len(lifter._jumptables)} resolved")
for addr, tgts in lifter._jumptables.items():
    print(f"    0x{addr:x}: {len(tgts)} targets -> {[f'0x{t:x}' for t in tgts[:10]]}")
