"""Categorize the remaining 17 heritage diffs."""
import sys
sys.path.insert(0, 'python')
sys.path.insert(0, '.')
from tests.test_cpexe_comparison import run_heritage_comparison

r = run_heritage_comparison()
diffs = [(e, d) for e, d in sorted(r.items()) if not d.get('match', False)]
print(f"Total diffs: {len(diffs)}\n")

for entry, d in diffs:
    blk_m = d.get('block_count_match', '?')
    op_m = d.get('op_count_match', '?')
    blk_c = d.get('cpp_blocks', '?')
    blk_p = d.get('py_blocks', '?')
    op_c = d.get('cpp_ops', '?')
    op_p = d.get('py_ops', '?')
    details = d.get('details', '')
    
    if blk_c != blk_p:
        cat = 'block_diff'
    elif op_c != op_p:
        delta = op_p - op_c if isinstance(op_c, int) and isinstance(op_p, int) else '?'
        cat = f'op_diff(delta={delta})'
    else:
        cat = 'other'
    
    print(f"0x{entry:x}: {cat}  blk={blk_c}/{blk_p}  ops={op_c}/{op_p}")
