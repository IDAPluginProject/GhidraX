"""Check what the full-actions pipeline produces for X86_BRANCH."""
import os, sys
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', 'python'))

from pattern_corpus import X86_BRANCH
from ghidra.sleigh.decompiler_python import DecompilerPython

dp = DecompilerPython()
sla = os.path.join(os.path.dirname(__file__), '..', 'specs', 'x86.sla')
dp.add_spec_path(os.path.dirname(sla))
dp.use_python_full_actions = True
dp.use_python_printc = True

result = dp.decompile(sla, 'x86:LE:32:default', X86_BRANCH, 0x401000, 0x401000, len(X86_BRANCH))
print("=== OUTPUT ===")
print(result)
print("=== ERRORS ===")
print(dp.get_errors())
print("=== CHECKS ===")
print(f"  'if' in result: {'if' in result}")
print(f"  'return' in result.lower(): {'return' in result.lower()}")
