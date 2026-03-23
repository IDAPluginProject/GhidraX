"""Diagnose guardCalls for ECX (register[0x4:4]) in a function with missing MULTIEQUALs."""
import sys, os
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', 'python'))
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..'))

from tests.test_cpexe_comparison import load_pe
from ghidra.sleigh.lifter import Lifter
from ghidra.sleigh.decompiler_python import (
    _split_basic_blocks, _setup_call_specs, _inject_tracked_context,
    _run_prerequisite_actions, _ArchitectureShim,
)
from ghidra.core.address import Address
from ghidra.core.opcodes import OpCode
from ghidra.analysis.heritage import Heritage

pe = load_pe('bin/cp.exe')
func_addr = 0x404210  # Function with missing ECX MULTIEQUAL

lifter = Lifter('specs/x86.sla', {'addrsize': 1, 'opsize': 1})
lifter.set_image(pe.image_base, pe.image)
fd = lifter.lift_function(f'func_{func_addr:x}', func_addr, 0)
_split_basic_blocks(fd)
arch = _ArchitectureShim(lifter._spc_mgr)
fd.setArch(arch)
_inject_tracked_context(fd, lifter)
_setup_call_specs(fd, lifter)
_run_prerequisite_actions(fd)

# Check call specs
print(f"Number of calls: {fd.numCalls()}")
for i in range(fd.numCalls()):
    fc = fd.getCallSpecs(i)
    print(f"  Call {i}: op={fc.getOp()}")
    print(f"    isOutputActive: {fc.isOutputActive() if hasattr(fc, 'isOutputActive') else 'N/A'}")
    print(f"    isInputActive: {fc.isInputActive() if hasattr(fc, 'isInputActive') else 'N/A'}")
    
    # Check hasEffect for ECX (register[0x4:4])
    reg_space = lifter._spc_mgr.getSpaceByName("register")
    ecx_addr = Address(reg_space, 0x4)
    esi_addr = Address(reg_space, 0x18)
    
    if hasattr(fc, 'hasEffect'):
        ecx_effect = fc.hasEffect(ecx_addr, 4)
        esi_effect = fc.hasEffect(esi_addr, 4)
        print(f"    hasEffect(ECX): {ecx_effect}")
        print(f"    hasEffect(ESI): {esi_effect}")
    else:
        print(f"    hasEffect: NOT AVAILABLE")

# Now run heritage and check ECX in the disjoint task list
orig_guard = Heritage.guard
ecx_calls_count = [0]
def traced_guard(self, addr, size, new_addr, readvars, writevars, inputvars):
    reg_space = lifter._spc_mgr.getSpaceByName("register")
    if addr.getSpace() is reg_space and addr.getOffset() == 0x4 and size == 4:
        print(f"\nguard(ECX register[0x4:4]):")
        print(f"  new_addr={new_addr}")
        print(f"  readvars={len(readvars)} writevars={len(writevars)} inputvars={len(inputvars)}")
        before_writes = len(writevars)
        result = orig_guard(self, addr, size, new_addr, readvars, writevars, inputvars)
        after_writes = len(writevars)
        print(f"  after guard: writevars grew from {before_writes} to {after_writes}")
        return result
    return orig_guard(self, addr, size, new_addr, readvars, writevars, inputvars)
Heritage.guard = traced_guard

fd.opHeritage()

# Count MULTIEQUALs for ECX
ecx_meqs = 0
for op in fd._obank.beginAlive():
    if op.code() == OpCode.CPUI_MULTIEQUAL:
        out = op.getOut()
        if out and out.getSpace() and out.getSpace().getName() == 'register' and out.getOffset() == 0x4:
            ecx_meqs += 1
print(f"\nECX MULTIEQUALs: {ecx_meqs}")

# Count INDIRECT ops targeting ECX
ecx_indirects = 0
for op in fd._obank.beginAlive():
    if op.code() == OpCode.CPUI_INDIRECT:
        out = op.getOut()
        if out and out.getSpace() and out.getSpace().getName() == 'register' and out.getOffset() == 0x4:
            ecx_indirects += 1
print(f"ECX INDIRECTs: {ecx_indirects}")
