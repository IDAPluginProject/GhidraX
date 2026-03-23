"""Dump C++ flow + heritage IR around call sites for func 0x401000."""
import sys, os
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', 'python'))
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', 'tests'))

from test_cpexe_comparison import load_pe, BIN_PATH
from ghidra.sleigh.decompiler_native import DecompilerNative
from ghidra.core.opcodes import OpCode

pe = load_pe(BIN_PATH)
func_addr = pe.functions[0]  # 0x401000

SPEC_DIR = os.path.join(os.path.dirname(__file__), '..', 'specs')
SLA_PATH = os.path.join(SPEC_DIR, 'x86.sla')

eng = DecompilerNative()
eng.add_spec_path(SPEC_DIR)
eng.initialize()

def dump_ir(label, result, lo=15, hi=45):
    ir = result.get("ir", {})
    blocks = ir.get("blocks", [])
    print(f"\n=== {label}: {len(blocks)} blocks, {ir.get('num_ops',0)} ops ===")
    for bd in blocks:
        for i, od in enumerate(bd.get("ops", [])):
            if i < lo or i > hi:
                continue
            out_d = od.get("output")
            out_s = "void"
            if out_d:
                out_s = f"{out_d['space']}[0x{out_d['offset']:x}:{out_d['size']}]"
            inputs = []
            for inp in od.get("inputs", []):
                sn = inp['space']
                if sn == 'const' and inp['size'] >= 8:
                    inputs.append(f"const[SPACEID:{inp['size']}]")
                elif sn == 'iop':
                    inputs.append(f"iop[...:{inp['size']}]")
                elif sn == 'fspec':
                    inputs.append(f"fspec[...:{inp['size']}]")
                else:
                    inputs.append(f"{sn}[0x{inp['offset']:x}:{inp['size']}]")
            opc_name = OpCode(od['opcode']).name
            print(f"  [{i:2d}] {out_s} = {opc_name}({', '.join(inputs)})")

r_flow = eng.decompile_staged(SLA_PATH, "x86:LE:32:default", pe.image, pe.image_base, func_addr, 0, "flow")
dump_ir("C++ FLOW (ALL)", r_flow, lo=0, hi=999)

r_her = eng.decompile_staged(SLA_PATH, "x86:LE:32:default", pe.image, pe.image_base, func_addr, 0, "heritage")
dump_ir("C++ HERITAGE (ALL)", r_her, lo=0, hi=999)
