"""Investigate small diff functions: 0x40d790, 0x40d7d0, 0x41b610."""
import sys
sys.path.insert(0, 'python')
sys.path.insert(0, '.')
from tests.test_cpexe_comparison import load_pe
from ghidra.sleigh.decompiler_native import DecompilerNative
from ghidra.sleigh.bridge_validator import _snapshot_from_cpp_dict

pe = load_pe('bin/cp.exe')
dn = DecompilerNative()
dn.add_spec_path('specs')
dn.initialize()

for func in [0x40d790, 0x40d7d0, 0x41b610]:
    cpp_r = dn.decompile_staged(
        'specs/x86.sla', 'x86:LE:32:default',
        pe.image, pe.image_base, func, 0, 'heritage'
    )
    cpp_snap = _snapshot_from_cpp_dict('heritage', cpp_r)
    print(f"\n=== 0x{func:x} ({cpp_snap.num_blocks} blocks, {cpp_snap.num_ops} ops) ===")
    for b in cpp_snap.blocks:
        ops_summary = []
        for op in b.ops[:3]:
            opc_name = str(op.opcode)
            ops_summary.append(f"opc={opc_name}@0x{op.addr:x}")
        if len(b.ops) > 3:
            ops_summary.append(f"...+{len(b.ops)-3} more")
        print(f"  block[{b.index}] @0x{b.start:x}-0x{b.stop:x} "
              f"succs={b.successors} preds={b.predecessors} "
              f"ops({b.num_ops}): {', '.join(ops_summary)}")
