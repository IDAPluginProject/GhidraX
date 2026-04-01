"""Quick profiler to identify which actions take the most time."""
import sys, os, time, cProfile, pstats, io
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', 'src'))
sys.path.insert(0, os.path.dirname(__file__))

from console import PEInfo, resolve_pe_arch
from ghidra.sleigh.lifter import Lifter
from ghidra.analysis.flowlifter import _split_basic_blocks, _setup_call_specs
from ghidra.arch.archshim import ArchitectureStandalone
from ghidra.transform.pipeline import _run_full_decompile_action, _seed_default_return_output

pe = PEInfo(os.path.join(os.path.dirname(__file__), '..', 'examples', 'cp.exe'))
sla, target, spec_dir = resolve_pe_arch(pe)
lifter = Lifter(sla, {'addrsize': 1, 'opsize': 1})
lifter.set_image(pe.image_base, pe.data)

entry = 0x402040
fd = lifter.lift_function(f"func_{entry:x}", entry, 0)
_split_basic_blocks(fd, lifter=lifter)
arch = ArchitectureStandalone(lifter._spc_mgr)
fd.setArch(arch)
_setup_call_specs(fd, lifter=lifter)
_seed_default_return_output(fd, target)

pr = cProfile.Profile()
pr.enable()
try:
    _run_full_decompile_action(fd, timeout_seconds=30.0)
except Exception as e:
    print(f"Error: {e}")
pr.disable()

s = io.StringIO()
ps = pstats.Stats(pr, stream=s).sort_stats('cumulative')
ps.print_stats(30)
print(s.getvalue())
