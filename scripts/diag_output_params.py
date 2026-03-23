"""Diagnose output param list entries and MULTIEQUAL register vs unique issue."""
import sys, os
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', 'python'))
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..'))

from ghidra.core.address import Address
from ghidra.sleigh.decompiler_python import _ArchitectureShim
from ghidra.sleigh.lifter import Lifter

lifter = Lifter('specs/x86.sla', {'addrsize': 1, 'opsize': 1})
arch = _ArchitectureShim(lifter._spc_mgr)
model = arch.defaultfp
out = model.output

print("=== Output ParamList entries ===")
print(f"Entries: {len(out.entry)}")
for i, e in enumerate(out.entry):
    spc_name = e.space.getName() if hasattr(e, 'space') and e.space else '?'
    grp = getattr(e, 'group', '?')
    print(f"  entry[{i}]: space={spc_name}, offset=0x{e.addressbase:x}, "
          f"size={e.size}, minsize={e.minsize}, group={grp}")

print("\n=== characterizeAsParam tests ===")
reg_space = arch.getSpaceByName('register')
for name, offset, size in [('EAX', 0x0, 4), ('EDX', 0x8, 4), ('ST0', 0x14, 10),
                             ('XMM0', 0x160, 16), ('AL', 0x0, 1), ('AX', 0x0, 2)]:
    addr = Address(reg_space, offset)
    result = out.characterizeAsParam(addr, size)
    print(f"  {name} (reg:0x{offset:x}, size={size}): characterizeAsParam -> {result}")

# Now check what the C++ cspec says about output
print("\n=== Checking cspec output definition ===")
cspec_path = os.path.join('specs', 'x86win.cspec')
if os.path.exists(cspec_path):
    with open(cspec_path, 'r') as f:
        content = f.read()
    # Find output section
    import re
    output_match = re.search(r'<output[^>]*>(.*?)</output>', content, re.DOTALL)
    if output_match:
        print(f"  Output section:\n{output_match.group(0)[:500]}")
