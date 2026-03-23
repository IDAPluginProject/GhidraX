"""Diagnose RETURN const value differences between C++ and Python."""
import sys
sys.path.insert(0, 'python')
sys.path.insert(0, '.')
from tests.test_cpexe_comparison import load_pe
from ghidra.sleigh.decompiler_native import DecompilerNative
from ghidra.core.opcodes import OpCode

pe = load_pe('bin/cp.exe')
dn = DecompilerNative()
dn.add_spec_path('specs')
dn.initialize()

func = 0x41d720
cpp_r = dn.decompile_staged(
    'specs/x86.sla', 'x86:LE:32:default',
    pe.image, pe.image_base, func, 0, 'heritage'
)
ir = cpp_r.get('ir', {})
print(f"CPUI_RETURN value: {OpCode.CPUI_RETURN}, int={int(OpCode.CPUI_RETURN)}")
opcodes_seen = set()
for bd in ir.get('blocks', []):
    for od in bd.get('ops', []):
        opcodes_seen.add(od.get('opcode'))
        # Look for last op of last block
        if od.get('opcode') == 10:  # CPUI_RETURN
            print(f"  opcode={od['opcode']} @0x{od['addr']:x}")
            for i, inp in enumerate(od.get('inputs', [])):
                print(f"    input[{i}]: space={inp['space']} offset=0x{inp['offset']:x} size={inp['size']}")
print(f"All opcodes: {sorted(opcodes_seen)}")

# Also check Python
from ghidra.sleigh.lifter import Lifter
from ghidra.sleigh.decompiler_python import _split_basic_blocks, _setup_call_specs, _inject_tracked_context, _run_prerequisite_actions, _ArchitectureShim
from ghidra.core.opcodes import OpCode
lifter = Lifter('specs/x86.sla', {'addrsize': 1, 'opsize': 1})
lifter.set_image(pe.image_base, pe.image)
fd = lifter.lift_function('f', func, 0)
_split_basic_blocks(fd)
arch = _ArchitectureShim(lifter._spc_mgr)
fd.setArch(arch)
_inject_tracked_context(fd, lifter)
_setup_call_specs(fd, lifter)
_run_prerequisite_actions(fd)
fd.opHeritage()
bg = fd.getBasicBlocks()
for i in range(bg.getSize()):
    b = bg.getBlock(i)
    for op in b.getOpList():
        if op.code() == OpCode.CPUI_RETURN:
            inp0 = op.getIn(0)
            sname = inp0.getSpace().getName() if inp0 and inp0.getSpace() else 'None'
            off = inp0.getOffset() if inp0 else -1
            sz = inp0.getSize() if inp0 else -1
            print(f"PY RETURN @0x{b.getStart().getOffset():x}: input[0] space={sname} offset=0x{off:x} size={sz}")
