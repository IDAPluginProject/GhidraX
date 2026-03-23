"""Analyze flow comparison report to categorize remaining diffs."""
import re

lines = open(r'd:\BIGAI\pyghidra\flow_comparison_report.txt', encoding='utf-8').readlines()

fspec_only = 0
block_diff = 0
op_diff_only = 0
edge_diff = 0
match_count = 0
other = 0

block_diff_list = []
op_diff_list = []
edge_diff_list = []

for line in lines[2:]:
    line = line.strip()
    if not line or line.startswith('  '):
        continue
    if '[MATCH]' in line:
        match_count += 1
        continue
    if '[ERROR]' in line:
        continue
    if '[DIFF]' not in line and '[EXPECTED]' not in line:
        continue

    parts = line.split()
    addr = parts[0]
    cpp_part = [p for p in parts if p.startswith('C++=')][0]
    py_part = [p for p in parts if p.startswith('Py=')][0]
    cb = int(cpp_part.split('blk')[0].split('=')[1])
    co = int(cpp_part.split('/')[1].replace('ops', ''))
    pb = int(py_part.split('blk')[0].split('=')[1])
    po = int(py_part.split('/')[1].replace('ops', ''))

    unexp = 0
    exp = 0
    for p in parts:
        if p.startswith('unexpected='):
            unexp = int(p.split('=')[1])
        if p.startswith('expected='):
            exp = int(p.split('=')[1])

    if cb != pb:
        block_diff += 1
        block_diff_list.append(
            "%s C++=%dblk/%dops Py=%dblk/%dops" % (addr, cb, co, pb, po))
    elif co != po:
        op_diff_only += 1
        op_diff_list.append(
            "%s C++=%dops Py=%dops unexp=%d" % (addr, co, po, unexp))
    elif unexp == 0 and exp > 0:
        fspec_only += 1
    elif unexp > 0:
        edge_diff += 1
        edge_diff_list.append(
            "%s unexp=%d exp=%d" % (addr, unexp, exp))
    else:
        other += 1

total = match_count + fspec_only + block_diff + op_diff_only + edge_diff + other
print("=== Flow Report Analysis ===")
print("Match:             %d" % match_count)
print("fspec-only:        %d (expected diffs, effectively matching)" % fspec_only)
print("Block count diff:  %d (structural - C++ worklist vs Python linear)" % block_diff)
print("Op count diff:     %d (same blocks, different ops)" % op_diff_only)
print("Edge diff only:    %d (same blk/op counts, edge mismatch)" % edge_diff)
print("Other:             %d" % other)
print("Total:             %d" % total)
print()

if block_diff_list:
    print("Block count diffs (%d):" % len(block_diff_list))
    for d in block_diff_list:
        print("  " + d)
    print()

if op_diff_list:
    print("Op-only diffs (%d):" % len(op_diff_list))
    for d in op_diff_list:
        print("  " + d)
    print()

if edge_diff_list:
    print("Edge diffs (%d):" % len(edge_diff_list))
    for d in edge_diff_list:
        print("  " + d)
