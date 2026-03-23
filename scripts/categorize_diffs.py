"""Categorize remaining diff functions by type."""
import sys, os
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', 'python'))
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..'))

from tests.test_cpexe_comparison import load_pe, run_heritage_comparison
from ghidra.sleigh.decompiler_native import DecompilerNative

pe = load_pe('bin/cp.exe')
dn = DecompilerNative()
dn.add_spec_path('specs')
dn.initialize()

categories = {
    'jump_table': [],
    'block_diff': [],
    'small_diff': [],
    'op_diff': [],
}

for fa in pe.functions:
    r = run_heritage_comparison(dn, pe, fa)
    if r.full_match or r.error:
        continue
    cb, pb = r.cpp_blocks, r.py_blocks
    ratio = max(cb, pb) / max(min(cb, pb), 1)
    if cb != pb and ratio > 2:
        categories['jump_table'].append(r)
    elif cb != pb:
        categories['block_diff'].append(r)
    elif r.unexpected_count <= 5:
        categories['small_diff'].append(r)
    else:
        categories['op_diff'].append(r)

for cat, funcs in categories.items():
    if not funcs:
        continue
    print(f"\n=== {cat} ({len(funcs)} functions) ===")
    for r in funcs:
        print(f"  0x{r.addr:08x}: C++={r.cpp_blocks}blk/{r.cpp_ops}ops "
              f"Py={r.py_blocks}blk/{r.py_ops}ops unexpected={r.unexpected_count}")
        for d in r.diff_details[:2]:
            print(f"    {d}")
