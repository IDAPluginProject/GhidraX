"""Trace which action collapses the branch structure in X86_BRANCH."""
import os, sys
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', 'python'))

from pattern_corpus import X86_BRANCH
from ghidra.core.opcodes import OpCode
from ghidra.transform import action as act_mod

# Monkey-patch Action.apply to trace block count changes
_orig_perform = act_mod.Action.perform
_last_nblocks = [None]
def _traced_perform(self, data):
    nblocks_before = data.getBasicBlocks().getSize()
    meq_before = sum(1 for op in data._obank.beginAlive() if op.code() == OpCode.CPUI_MULTIEQUAL)
    result = _orig_perform(self, data)
    nblocks_after = data.getBasicBlocks().getSize()
    meq_after = sum(1 for op in data._obank.beginAlive() if op.code() == OpCode.CPUI_MULTIEQUAL)
    if nblocks_before != nblocks_after or meq_before != meq_after:
        print(f"  [{self._name}] blocks: {nblocks_before}->{nblocks_after}  MEQ: {meq_before}->{meq_after}")
    return result
act_mod.Action.perform = _traced_perform

from ghidra.sleigh.decompiler_python import (
    _run_full_decompile_action, _printc_from_funcdata,
    _ArchitectureShim, _split_basic_blocks, _seed_default_return_output
)
from ghidra.sleigh.lifter import Lifter

sla = os.path.join(os.path.dirname(__file__), '..', 'specs', 'x86.sla')
context = {"addrsize": 1, "opsize": 1}
lifter = Lifter(sla, context)
lifter.set_image(0x401000, X86_BRANCH)

fd = lifter.lift_function("func_401000", 0x401000, len(X86_BRANCH))
arch_shim = _ArchitectureShim(lifter._spc_mgr)
fd.setArch(arch_shim)
_split_basic_blocks(fd)
_seed_default_return_output(fd, 'x86:LE:32:default')
_run_full_decompile_action(fd)

c = _printc_from_funcdata(fd)
print("\n=== OUTPUT ===")
print(c)
print(f"has 'if': {'if' in c}")
