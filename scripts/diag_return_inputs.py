"""Diagnose why RETURN ops are missing register inputs in Python heritage."""
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

pe = load_pe('bin/cp.exe')
lifter = Lifter('specs/x86.sla', {'addrsize': 1, 'opsize': 1})
lifter.set_image(pe.image_base, pe.image)

fd = lifter.lift_function('func_401000', 0x401000, 0)
_split_basic_blocks(fd)
arch = _ArchitectureShim(lifter._spc_mgr)
fd.setArch(arch)
_inject_tracked_context(fd, lifter)
_setup_call_specs(fd, lifter)
_run_prerequisite_actions(fd)

# Check state before heritage
ao = fd.getActiveOutput()
proto = fd.getFuncProto()
print(f"ActiveOutput: {ao}")
print(f"isOutputLocked: {proto.isOutputLocked()}")
print(f"Proto model: {proto.model}")

if proto.model is not None:
    reg_space = arch.getSpaceByName('register')
    # EAX = register offset 0x0, size 4
    eax_addr = Address(reg_space, 0)
    char_result = proto.characterizeAsOutput(eax_addr, 4)
    print(f"characterizeAsOutput(EAX reg:0x0, size=4): {char_result}")
    # EDX = register offset 0x8, size 4
    edx_addr = Address(reg_space, 0x8)
    char_result2 = proto.characterizeAsOutput(edx_addr, 4)
    print(f"characterizeAsOutput(EDX reg:0x8, size=4): {char_result2}")
    
    # Check model's output ParamList
    if hasattr(proto.model, 'output'):
        out = proto.model.output
        print(f"Model output: {out}")
        if hasattr(out, 'entries'):
            for i, e in enumerate(out.entries):
                print(f"  output entry[{i}]: space={e.space}, offset={e.addressbase}, size={e.size}")

# Count RETURN ops before heritage
ret_count = 0
for op in fd._obank.beginAlive():
    if op.code() == OpCode.CPUI_RETURN:
        ret_count += 1
        print(f"RETURN before heritage: {op.numInput()} inputs")
        for j in range(op.numInput()):
            inv = op.getIn(j)
            print(f"  in[{j}]: {inv.getSpace().getName()}[0x{inv.getOffset():x}:{inv.getSize()}]")

print(f"\nTotal RETURN ops: {ret_count}")

# Monkey-patch guardReturns to trace
import ghidra.analysis.heritage as _hmod
_orig_guardReturns = _hmod.Heritage.guardReturns
def _traced_guardReturns(self, fl, addr, size, write):
    from ghidra.ir.varnode import Varnode as VnCls
    spc_name = addr.getSpace().getName() if hasattr(addr, 'getSpace') and addr.getSpace() else '?'
    active = self._fd.getActiveOutput() if hasattr(self._fd, 'getActiveOutput') else None
    proto = self._fd.getFuncProto() if hasattr(self._fd, 'getFuncProto') else None
    if spc_name == 'register' and addr.getOffset() in (0x0, 0x8):
        print(f"  guardReturns: {spc_name}[0x{addr.getOffset():x}:{size}] fl=0x{fl:x} active={active is not None}")
        if active is not None and proto is not None:
            from ghidra.fspec.fspec import ParamEntry
            char = proto.characterizeAsOutput(addr, size)
            print(f"    characterizeAsOutput -> {char} (no_containment={ParamEntry.no_containment}, contained_by={ParamEntry.contained_by})")
            if char == ParamEntry.contained_by:
                print(f"    -> would call guardReturnsOverlapping")
            elif char != ParamEntry.no_containment:
                print(f"    -> would registerTrial and add inputs")
                # Count RETURN ops
                ret_ops = list(self._fd.beginOp(OpCode.CPUI_RETURN))
                print(f"    -> RETURN ops found: {len(ret_ops)}")
                for op in ret_ops:
                    print(f"       op dead={op.isDead()} halt={op.getHaltType() if hasattr(op,'getHaltType') else '?'} numinput={op.numInput()}")
            else:
                print(f"    -> no_containment, skipping")
        print(f"    persist check: fl & persist = {fl & VnCls.persist}")
    return _orig_guardReturns(self, fl, addr, size, write)
_hmod.Heritage.guardReturns = _traced_guardReturns

# Now run heritage
print("\n--- Running heritage ---")
fd.opHeritage()

# Check RETURN ops after heritage
for op in fd._obank.beginAlive():
    if op.code() == OpCode.CPUI_RETURN:
        print(f"RETURN after heritage: {op.numInput()} inputs")
        for j in range(op.numInput()):
            inv = op.getIn(j)
            print(f"  in[{j}]: {inv.getSpace().getName()}[0x{inv.getOffset():x}:{inv.getSize()}]")
