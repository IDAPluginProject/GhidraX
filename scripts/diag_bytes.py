"""Decode raw bytes near overlap points to understand instruction boundaries."""
import sys, os, struct
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', 'python'))
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..'))

from tests.test_cpexe_comparison import load_pe, SLA_PATH
from ghidra.sleigh.lifter import Lifter
from ghidra.core.opcodes import OpCode

pe = load_pe('bin/cp.exe')
context = {"addrsize": 1, "opsize": 1}
lifter = Lifter(SLA_PATH, context)
lifter.set_image(pe.image_base, pe.image)

# Decode instructions linearly from 0x40b490 to 0x40b4b5
print("=== Linear decode from 0x40b490 ===")
addr = 0x40b490
while addr <= 0x40b4b5:
    insn = lifter._native.pcode(addr)
    foff = addr - pe.image_base
    raw = pe.image[foff:foff+insn.length].hex()
    
    ctrl_ops = []
    for op in insn.ops:
        if op.opcode in (OpCode.CPUI_BRANCH.value, OpCode.CPUI_CBRANCH.value,
                         OpCode.CPUI_BRANCHIND.value, OpCode.CPUI_RETURN.value,
                         OpCode.CPUI_CALL.value):
            tgt = op.inputs[0] if op.inputs else None
            tgt_str = f"space={tgt.space},0x{tgt.offset:x}" if tgt else "?"
            ctrl_ops.append(f"{OpCode(op.opcode).name}({tgt_str})")
    
    ctrl = f"  <<< {', '.join(ctrl_ops)}" if ctrl_ops else ""
    print(f"  0x{addr:x} [{insn.length}B] {raw}: {len(insn.ops)} ops{ctrl}")
    addr += insn.length

# Now check: what does SLEIGH produce at 0x40b49f (inside the 7B insn at 0x40b499)?
print("\n=== SLEIGH decode at mid-instruction addresses ===")
for test_addr in [0x40b49f, 0x40b4a0]:
    insn = lifter._native.pcode(test_addr)
    foff = test_addr - pe.image_base
    raw = pe.image[foff:foff+insn.length].hex()
    
    ctrl_ops = []
    all_ops = []
    for op in insn.ops:
        all_ops.append(OpCode(op.opcode).name)
        if op.opcode in (OpCode.CPUI_BRANCH.value, OpCode.CPUI_CBRANCH.value):
            tgt = op.inputs[0] if op.inputs else None
            if tgt:
                ctrl_ops.append(f"{OpCode(op.opcode).name}(space={tgt.space},off=0x{tgt.offset:x})")
    
    print(f"  0x{test_addr:x} [{insn.length}B] {raw}: {len(insn.ops)} ops")
    print(f"    Ops: {', '.join(all_ops)}")
    if ctrl_ops:
        print(f"    Control: {', '.join(ctrl_ops)}")

# Check what the C++ decompiler sees for block[14]
# Use the native decompiler to get the IR
print("\n=== C++ decompile_staged for 0x40b420 ===")
from ghidra.sleigh.decompiler_native import DecompilerNative
cpp = DecompilerNative()
# Find the right target string
result = cpp.decompile_staged(SLA_PATH, "x86:LE:32:default",
                              pe.image, pe.image_base, 0x40b420, 0, "heritage")
ir = result["ir"]
# Find block at 0x40b4a0
for blk_key in sorted(ir.keys()):
    if not blk_key.startswith("block_"):
        continue
    blk = ir[blk_key]
    start = blk.get("start", 0)
    if 0x40b490 <= start <= 0x40b4b0:
        ops = blk.get("ops", {})
        # Get addresses of ops
        addrs = sorted(set(ops[k]["addr"] for k in ops))
        print(f"  {blk_key} @0x{start:x}: {len(ops)} ops, addrs={[f'0x{a:x}' for a in addrs[:10]]}")
