"""Diagnose remaining diff functions."""
import sys, os
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', 'python'))
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..'))

from tests.test_cpexe_comparison import load_pe, SLA_PATH, run_heritage_comparison
from ghidra.sleigh.decompiler_native import DecompilerNative
from ghidra.sleigh.lifter import Lifter

pe = load_pe('bin/cp.exe')
dn = DecompilerNative()
dn.add_spec_path('specs')
dn.initialize()

# Check 0x417670 - Python has 11 blocks vs C++ 2
for func_addr in [0x417670, 0x40b420, 0x40d3b0, 0x41bb70]:
    r = run_heritage_comparison(dn, pe, func_addr)
    if not r.full_match:
        print(f"\n0x{func_addr:x}: C++={r.cpp_blocks}blk/{r.cpp_ops}ops Py={r.py_blocks}blk/{r.py_ops}ops")
        for detail in r.diff_details[:5]:
            print(f"  {detail}")

# Check if 0x417670 has jump tables / BRANCHIND
context = {"addrsize": 1, "opsize": 1}
lifter = Lifter(SLA_PATH, context)
lifter.set_image(pe.image_base, pe.image)

print("\n\n--- P-code for 0x417670 area ---")
addr = 0x417670
for _ in range(20):
    try:
        insn = lifter._native.pcode(addr)
        if insn.length == 0:
            break
        from ghidra.core.opcodes import OpCode
        opcodes = []
        for op in insn.ops:
            try:
                opc_name = OpCode(op.opcode).name
            except:
                opc_name = f"op{op.opcode}"
            opcodes.append(opc_name)
        print(f"  0x{addr:x} [{insn.length}B]: {', '.join(opcodes)}")
        # Check for BRANCHIND
        for op in insn.ops:
            if op.opcode == OpCode.CPUI_BRANCHIND.value:
                print(f"    *** BRANCHIND found ***")
        addr += insn.length
        if addr > 0x4176a0:
            break
    except:
        break
