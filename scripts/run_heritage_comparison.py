"""Run heritage comparison on all cp.exe functions and report summary."""
import sys, os
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', 'python'))
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..'))

from tests.test_cpexe_comparison import load_pe, run_heritage_comparison

pe = load_pe('bin/cp.exe')
from ghidra.sleigh.decompiler_native import DecompilerNative
dn = DecompilerNative()
dn.add_spec_path('specs')
dn.initialize()

total = len(pe.functions)
match_count = 0
diff_count = 0
err_count = 0
diff_funcs = []

for i, fa in enumerate(pe.functions):
    r = run_heritage_comparison(dn, pe, fa)
    if r.full_match:
        match_count += 1
    elif r.error:
        err_count += 1
    else:
        diff_count += 1
        diff_funcs.append(r)
    if (i + 1) % 50 == 0:
        print(f"  Progress: {i+1}/{total} (match={match_count})")

print(f"\n{'='*60}")
print(f"Heritage Comparison: cp.exe")
print(f"{'='*60}")
print(f"Total:     {total}")
print(f"Match:     {match_count}/{total} ({100*match_count/total:.1f}%)")
print(f"Diff:      {diff_count}/{total}")
print(f"Error:     {err_count}/{total}")

if diff_funcs:
    print(f"\nDiff functions ({len(diff_funcs)}):")
    for d in diff_funcs[:30]:
        if d.cpp_blocks != d.py_blocks:
            cat = 'BLOCK_DIFF'
        elif d.cpp_ops != d.py_ops:
            cat = f'OP_DIFF(delta={d.py_ops - d.cpp_ops})'
        else:
            cat = 'OTHER'
        print(f"  0x{d.addr:08x}: {cat} C++={d.cpp_blocks}blk/{d.cpp_ops}ops "
              f"Py={d.py_blocks}blk/{d.py_ops}ops "
              f"unexpected={d.unexpected_count}")
        for detail in d.diff_details[:3]:
            print(f"    {detail}")
