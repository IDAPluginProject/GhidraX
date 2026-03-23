"""Check non-returning call targets."""
import sys, os, struct
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', 'python'))
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..'))

from tests.test_cpexe_comparison import load_pe, SLA_PATH
from ghidra.sleigh.lifter import Lifter
from ghidra.core.opcodes import OpCode

pe = load_pe('bin/cp.exe')
context = {"addrsize": 1, "opsize": 1}
lifter = Lifter(SLA_PATH, context)
lifter.set_image(pe.image_base, pe.image)

# Check what's at the non-returning call targets
targets = [0x41db60, 0x41db80]
for tgt in targets:
    print(f"\n=== Target 0x{tgt:x} ===")
    addr = tgt
    for _ in range(5):
        try:
            insn = lifter._native.pcode(addr)
            ops_str = []
            for op in insn.ops:
                try:
                    name = OpCode(op.opcode).name
                except:
                    name = f"op{op.opcode}"
                if op.opcode in (OpCode.CPUI_BRANCH.value, OpCode.CPUI_BRANCHIND.value,
                                 OpCode.CPUI_CALL.value, OpCode.CPUI_RETURN.value):
                    inputs = [f"{inp.space}[0x{inp.offset:x}]" for inp in op.inputs]
                    ops_str.append(f"{name}({','.join(inputs)})")
                else:
                    ops_str.append(name)
            print(f"  0x{addr:x} [{insn.length}B]: {', '.join(ops_str)}")
            # Check for indirect branch (thunk pattern: JMP [addr])
            for op in insn.ops:
                if op.opcode == OpCode.CPUI_BRANCHIND.value:
                    print(f"    -> Thunk: indirect jump (JMP [IAT])")
                    # Try to read the IAT entry
                    load_op = None
                    for op2 in insn.ops:
                        if op2.opcode == OpCode.CPUI_LOAD.value and op2.output:
                            load_op = op2
                    if load_op and len(load_op.inputs) >= 2:
                        iat_addr = load_op.inputs[1].offset
                        file_off = iat_addr - pe.image_base
                        if 0 <= file_off < len(pe.image) - 4:
                            iat_val = struct.unpack_from('<I', pe.image, file_off)[0]
                            print(f"    -> IAT at 0x{iat_addr:x} = 0x{iat_val:x}")
            addr += insn.length
        except:
            print(f"  0x{addr:x}: decode error")
            break

# Check PE imports for those IAT entries
print("\n=== PE Imports ===")
if hasattr(pe, 'imports'):
    for imp in pe.imports:
        print(f"  {imp}")
elif hasattr(pe, '_pe'):
    import pefile
    for entry in pe._pe.DIRECTORY_ENTRY_IMPORT:
        for imp in entry.imports:
            if imp.address:
                # Check if this is one of the noreturn functions
                name = imp.name.decode() if imp.name else f"ord{imp.ordinal}"
                if any(n in name.lower() for n in ['exit', 'abort', 'terminate', 'fatal']):
                    print(f"  0x{imp.address:x}: {entry.dll.decode()}!{name}")
