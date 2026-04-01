"""Debug: trace why console still shows flag noise despite fix."""
import sys, os
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', 'src'))
sys.path.insert(0, os.path.dirname(__file__))

from console import PEInfo, resolve_pe_arch
from ghidra.sleigh.lifter import Lifter
from ghidra.analysis.flowlifter import _split_basic_blocks, _setup_call_specs
from ghidra.arch.archshim import ArchitectureStandalone
from ghidra.transform.pipeline import _run_full_decompile_action, _seed_default_return_output
from ghidra.sleigh.decompiler_python import _printc_from_funcdata, _raw_c_from_funcdata

pe = PEInfo(os.path.join(os.path.dirname(__file__), '..', 'examples', 'cp.exe'))
sla, target, spec_dir = resolve_pe_arch(pe)

lifter = Lifter(sla, {'addrsize': 1, 'opsize': 1})
lifter.set_image(pe.image_base, pe.data)

import re, time
from ghidra.transform.action import ActionPool
ActionPool.reset_global_counts()

# Patch bumpDeadcodeDelay to count calls
from ghidra.analysis import heritage as _hmod
_bump_count = [0]
_orig_bump = _hmod.Heritage.bumpDeadcodeDelay
def _patched_bump(self, spc):
    _bump_count[0] += 1
    print(f"  [bumpDeadcodeDelay #{_bump_count[0]}] space={spc.getName()}", flush=True)
    return _orig_bump(self, spc)
_hmod.Heritage.bumpDeadcodeDelay = _patched_bump

entry = 0x402040  # medium function (2139 initial ops, completes)
fd = lifter.lift_function(f"func_{entry:x}", entry, 0)
_split_basic_blocks(fd, lifter=lifter)
arch = ArchitectureStandalone(lifter._spc_mgr)
fd.setArch(arch)
_setup_call_specs(fd, lifter=lifter)
_seed_default_return_output(fd, target)

t0 = time.perf_counter()
print(f"Initial ops: {sum(1 for _ in fd._obank.beginAlive())}")
print("Launching pipeline (30s timeout)...", flush=True)

try:
    _run_full_decompile_action(fd, timeout_seconds=30.0)
    print(f"Pipeline OK  ({time.perf_counter()-t0:.1f}s)")
except Exception as e:
    import traceback as tb
    print(f"Pipeline FAILED: {e}")
    tb.print_exc()

_hmod.Heritage.bumpDeadcodeDelay = _orig_bump  # restore

total = sum(1 for _ in fd._obank.beginAlive())
# Count flag ops in alive ops
reg_spc = None
for i in range(arch.numSpaces()):
    s = arch.getSpace(i)
    if s and s.getName() == 'register':
        reg_spc = s; break
FLAG_OFFSETS = {0x200,0x202,0x206,0x207,0x209,0x20a,0x20b,0x210}
flag_ops = sum(1 for op in fd._obank.beginAlive()
               if op.getOut() is not None and op.getOut().getSpace() is reg_spc
               and op.getOut().getOffset() in FLAG_OFFSETS)

print(f"Total bumpDeadcodeDelay calls: {_bump_count[0]}")
print(f"Alive ops after pipeline: {total}  (flag-writing: {flag_ops})")

top = sorted(ActionPool._global_rule_counts.items(), key=lambda x: -x[1])
print(f"\nTop rules by fire count ({sum(v for _,v in top):,} total fires):")
for name, cnt in top[:15]:
    print(f"  {cnt:10,}  {name}")

# Print decompiled output
print("\n--- PrintC output ---")
try:
    out = _printc_from_funcdata(fd)
    print(out[:4000] if out else "(empty)")
except Exception as e:
    print(f"PrintC FAILED: {e}")
    import traceback as tb2; tb2.print_exc()

print("\n--- Raw C output (fallback) ---")
try:
    raw = _raw_c_from_funcdata(fd)
    print(raw[:2000] if raw else "(empty)")
except Exception as e:
    print(f"Raw C FAILED: {e}")
