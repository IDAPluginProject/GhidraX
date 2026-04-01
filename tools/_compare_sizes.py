import os
pairs = [
    ('src/ghidra/ir/typeop.py', 'native/typeop.cc', 'native/typeop.hh'),
    ('src/ghidra/ir/op.py', 'native/op.cc', 'native/op.hh'),
    ('src/ghidra/types/datatype.py', 'native/type.cc', 'native/type.hh'),
    ('src/ghidra/analysis/merge.py', 'native/merge.cc', 'native/merge.hh'),
    ('src/ghidra/analysis/funcdata.py', 'native/funcdata.cc', None),
    ('src/ghidra/ir/variable.py', 'native/variable.cc', 'native/variable.hh'),
    ('src/ghidra/ir/varnode.py', 'native/varnode.cc', 'native/varnode.hh'),
    ('src/ghidra/database/database.py', 'native/database.cc', None),
    ('src/ghidra/database/varmap.py', 'native/varmap.cc', None),
    ('src/ghidra/analysis/heritage.py', 'native/heritage.cc', None),
]
print(f"{'Python file':40s} {'Py KB':>7s}  {'C++ file':30s} {'C++ KB':>7s}  {'Ratio':>7s}")
print("-" * 100)
for py, cc, hh in pairs:
    py_sz = os.path.getsize(py) if os.path.exists(py) else 0
    cc_sz = os.path.getsize(cc) if os.path.exists(cc) else 0
    if hh and os.path.exists(hh):
        cc_sz += os.path.getsize(hh)
    ratio = f"{py_sz/cc_sz:.0%}" if cc_sz else "N/A"
    print(f"{py:40s} {py_sz/1024:6.1f}K  {cc:30s} {cc_sz/1024:6.1f}K  {ratio:>7s}")
