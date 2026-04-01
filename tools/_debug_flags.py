"""Debug: trace why x86 flag varnodes survive dead-code removal."""
import sys, os
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', 'src'))
sys.path.insert(0, os.path.dirname(__file__))

from console import PEInfo, resolve_pe_arch
from ghidra.sleigh.lifter import Lifter
from ghidra.analysis.flowlifter import _split_basic_blocks, _setup_call_specs
from ghidra.arch.archshim import ArchitectureStandalone
from ghidra.transform.pipeline import _run_full_decompile_action, _seed_default_return_output
from ghidra.ir.varnode import Varnode

pe = PEInfo(os.path.join(os.path.dirname(__file__), '..', 'examples', 'cp.exe'))
sla, target, spec_dir = resolve_pe_arch(pe)

lifter = Lifter(sla, {'addrsize': 1, 'opsize': 1})
lifter.set_image(pe.image_base, pe.data)

fd = lifter.lift_function('f_402190', 0x402190, 0)
_split_basic_blocks(fd, lifter=lifter)
arch = ArchitectureStandalone(lifter._spc_mgr)
fd.setArch(arch)
_setup_call_specs(fd, lifter=lifter)
_seed_default_return_output(fd, target)
_run_full_decompile_action(fd, timeout_seconds=10.0)

FLAG_OFFSETS = {0x200, 0x202, 0x206, 0x207, 0x209, 0x20a, 0x20b, 0x210}  # CF PF ZF SF OF AF DF IF

print("\n=== Alive ops after pipeline ===")
reg_spc2 = None
for i in range(arch.numSpaces()):
    s = arch.getSpace(i)
    if s and s.getName() == 'register':
        reg_spc2 = s
        break

total_alive = 0
flag_ops = []
for op in fd._obank.beginAlive():
    total_alive += 1
    out = op.getOut()
    if out is not None and out.getSpace() is reg_spc2:
        if out.getOffset() in FLAG_OFFSETS:
            flag_ops.append(op)

print(f"Total alive ops: {total_alive}")
print(f"Flag-writing alive ops: {len(flag_ops)}")
for op in flag_ops[:5]:
    print(f"  {op}")

FLAG_NAMES = {'CF', 'OF', 'SF', 'ZF', 'PF', 'AF', 'DF', 'IF'}

print("\n=== Live varnodes in register space after full pipeline ===")
reg_spc = None
for i in range(arch.numSpaces()):
    s = arch.getSpace(i)
    if s and s.getName() == 'register':
        reg_spc = s
        break

print(f"{'Name/Addr':<16} {'size':>4}  {'flags':<30}  isAutoLive  isAddrForce  autolive_hold  hasDesc  written")
for vn in fd._vbank.beginLoc():
    if vn.getSpace() is not reg_spc:
        continue

    # Decode flags
    f = vn._flags
    flags_str = []
    if f & Varnode.addrforce:     flags_str.append('addrforce')
    if f & Varnode.autolive_hold: flags_str.append('autolive_hold')
    if f & Varnode.addrtied:      flags_str.append('addrtied')
    if f & Varnode.unaffected:    flags_str.append('unaffected')
    if f & Varnode.directwrite:   flags_str.append('directwrite')
    if f & Varnode.input:         flags_str.append('input')
    if f & Varnode.persist:       flags_str.append('persist')

    off = vn.getOffset()
    print(f"  reg+0x{off:<8x} {vn.getSize():>4}  {','.join(flags_str):<30}"
          f"  {vn.isAutoLive()!s:<10}  {vn.isAddrForce()!s:<11}"
          f"  {vn.isAutoLiveHold()!s:<13}  {not vn.hasNoDescend()!s:<7}"
          f"  {vn.isWritten()}")
