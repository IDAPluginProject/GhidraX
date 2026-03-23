"""Show raw p-code ops from SLEIGH for instruction at 0x41d800."""
import sys
sys.path.insert(0, 'python')
sys.path.insert(0, '.')
from tests.test_cpexe_comparison import load_pe, SLA_PATH
from ghidra.sleigh.decompiler_native import DecompilerNative

pe = load_pe('bin/cp.exe')
dn = DecompilerNative()
dn.add_spec_path('specs')
dn.initialize()

context = {"addrsize": 1, "opsize": 1}
from ghidra.sleigh.lifter import Lifter
lifter = Lifter(SLA_PATH, context)
lifter.set_image(pe.image_base, pe.image)

# Get raw p-code for instruction at 0x41d800
for addr in [0x41d800, 0x41d801, 0x41d802, 0x41d803, 0x41d804]:
    try:
        insn = lifter._native.pcode(addr)
        if insn.length > 0:
            print(f"\n=== Instruction at 0x{addr:x}, length={insn.length} ===")
            for i, op in enumerate(insn.ops):
                inputs = []
                for inp in op.inputs:
                    inputs.append(f"{inp.space}[0x{inp.offset:x}:{inp.size}]")
                out = ""
                if op.output:
                    out = f"{op.output.space}[0x{op.output.offset:x}:{op.output.size}] = "
                from ghidra.core.opcodes import OpCode
                try:
                    opc_name = OpCode(op.opcode).name
                except:
                    opc_name = f"op{op.opcode}"
                print(f"  [{i}] {out}{opc_name}({', '.join(inputs)})")
    except Exception as e:
        pass
