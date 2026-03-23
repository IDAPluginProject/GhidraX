"""Diagnose why MULTIEQUAL outputs go to unique-space instead of register-space."""
import sys, os
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', 'python'))
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..'))

from tests.test_cpexe_comparison import load_pe, run_heritage_comparison
from ghidra.sleigh.lifter import Lifter
from ghidra.sleigh.decompiler_python import (
    _split_basic_blocks, _setup_call_specs, _inject_tracked_context,
    _run_prerequisite_actions, _ArchitectureShim,
)
from ghidra.core.address import Address
from ghidra.core.opcodes import OpCode

pe = load_pe('bin/cp.exe')

# Pick a function with MULTIEQUAL diffs: 0x401080 (26 blocks, many MULTIEQUALs)
func_addr = 0x401080

# Set up Python pipeline
lifter = Lifter('specs/x86.sla', {'addrsize': 1, 'opsize': 1})
lifter.set_image(pe.image_base, pe.image)
fd = lifter.lift_function(f'func_{func_addr:x}', func_addr, 0)
_split_basic_blocks(fd)
arch = _ArchitectureShim(lifter._spc_mgr)
fd.setArch(arch)
_inject_tracked_context(fd, lifter)
_setup_call_specs(fd, lifter)
_run_prerequisite_actions(fd)

# Look at specific register offsets that show up in the diffs
# C++ has: register[0x284:4] (EFLAGS?), register[0x20b:1] (SF), 
#          register[0x207:1] (ZF), register[0x206:1] (CF), register[0x202:1] (OF)
# Python has: unique[0xb900:4], unique[0x57200:4], etc.

# Before heritage: check which varnodes exist in these register locations
reg_space = arch.getSpaceByName('register')
print("=== Checking register varnode usage before heritage ===")
flag_offsets = {
    0x200: 'CF(0x200)', 0x201: 'res1', 0x202: 'PF(0x202)', 0x203: 'res3',
    0x204: 'AF(0x204)', 0x205: 'res5', 0x206: 'ZF(0x206)', 0x207: 'SF(0x207)',
    0x208: 'TF', 0x209: 'IF', 0x20a: 'DF(0x20a)', 0x20b: 'OF(0x20b)',
    0x284: 'eflags(0x284)',
}

# Look for varnodes at flag register offsets
flag_vn_count = 0
for vn in fd._vbank.beginLoc():
    spc = vn.getSpace()
    if spc and spc.getName() == 'register':
        off = vn.getOffset()
        if 0x200 <= off <= 0x20b or off == 0x284:
            flag_vn_count += 1
            if flag_vn_count <= 20:
                nm = flag_offsets.get(off, f'0x{off:x}')
                defop = vn.getDef()
                defstr = f'{defop.code().name}' if defop else 'INPUT'
                print(f"  register[0x{off:x}:{vn.getSize()}] ({nm}) def={defstr}")

print(f"Total flag register varnodes: {flag_vn_count}")

# Look for unique-space varnodes at key addresses from the diffs
print("\n=== Checking unique varnodes at diff addresses ===")
unique_addrs = set()
for vn in fd._vbank.beginLoc():
    spc = vn.getSpace()
    if spc and spc.getName() == 'unique':
        unique_addrs.add(vn.getOffset())

# The key unique addresses from the report: 0xb900, 0x57200, 0x3c900, 0x33e00
for addr in sorted([0xb900, 0x57200, 0x3c900, 0x33e00, 0xcb80, 0x33c00, 0x33b00, 0x33600]):
    if addr in unique_addrs:
        count = sum(1 for vn in fd._vbank.beginLoc() 
                   if vn.getSpace() and vn.getSpace().getName() == 'unique' 
                   and vn.getOffset() == addr)
        # Get first one's def op
        for vn in fd._vbank.beginLoc():
            if vn.getSpace() and vn.getSpace().getName() == 'unique' and vn.getOffset() == addr:
                defop = vn.getDef()
                defstr = f'{defop.code().name}' if defop else 'INPUT'
                print(f"  unique[0x{addr:x}:{vn.getSize()}] count={count} first_def={defstr}")
                break

# Run heritage
print("\n=== Running heritage ===")
fd.opHeritage()

# Check MULTIEQUAL ops after heritage
print("\n=== MULTIEQUAL ops after heritage ===")
meq_count = 0
meq_reg = 0
meq_unique = 0
for op in fd._obank.beginAlive():
    if op.code() == OpCode.CPUI_MULTIEQUAL:
        meq_count += 1
        out = op.getOut()
        if out:
            spc = out.getSpace()
            if spc:
                if spc.getName() == 'register':
                    meq_reg += 1
                elif spc.getName() == 'unique':
                    meq_unique += 1
                    if meq_unique <= 5:
                        print(f"  MULTIEQUAL -> unique[0x{out.getOffset():x}:{out.getSize()}]")

print(f"\nTotal MULTIEQUALs: {meq_count}")
print(f"  -> register: {meq_reg}")
print(f"  -> unique: {meq_unique}")
