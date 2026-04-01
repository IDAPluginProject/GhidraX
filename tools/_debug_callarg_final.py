"""Debug: run full pipeline on cp.exe func_401000 and emit C output."""
import sys, os, struct
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', 'src'))

from ghidra.sleigh.lifter import Lifter
from ghidra.sleigh.arch_map import add_sla_search_dir, resolve_arch
from ghidra.arch.archshim import ArchitectureStandalone
from ghidra.analysis.flowlifter import _split_basic_blocks, _setup_call_specs
from ghidra.transform.pipeline import _seed_default_return_output
from ghidra.transform.action import ActionDatabase
from ghidra.core.opcodes import OpCode

# Setup
add_sla_search_dir(os.path.join(os.path.dirname(__file__), '..', 'specs', 'Processors', 'x86', 'data', 'languages'))
info = resolve_arch('metapc', 32, False)
lifter = Lifter(info['sla_path'], {'addrsize': 1, 'opsize': 1})
d = open(os.path.join(os.path.dirname(__file__), '..', 'examples', 'cp.exe'), 'rb').read()
pe_off = struct.unpack_from('<I', d, 0x3c)[0]
coff = pe_off + 4
nsec = struct.unpack_from('<H', d, coff + 2)[0]
ohsz = struct.unpack_from('<H', d, coff + 16)[0]
opt = coff + 20
base = struct.unpack_from('<I', d, opt + 28)[0]
sec_start = opt + ohsz
secs = []
for i in range(nsec):
    o = sec_start + i * 40
    rva = struct.unpack_from('<I', d, o + 12)[0]
    vs = struct.unpack_from('<I', d, o + 8)[0]
    rs = struct.unpack_from('<I', d, o + 16)[0]
    ro = struct.unpack_from('<I', d, o + 20)[0]
    secs.append((rva, vs, rs, ro))
max_va = max(r + max(v, rs) for r, v, rs, ro in secs)
buf = bytearray(max_va)
for rva, vs, rs, ro in secs:
    raw = d[ro:ro + rs]
    buf[rva:rva + len(raw)] = raw
lifter.set_image(base, bytes(buf))

fd = lifter.lift_function('func_401000', 0x401000, 0)
_split_basic_blocks(fd, lifter=lifter)
arch = ArchitectureStandalone(lifter._spc_mgr)
fd.setArch(arch)
_setup_call_specs(fd, lifter=lifter)
_seed_default_return_output(fd, info['target'])

# Build and run full pipeline
allacts = ActionDatabase()
allacts.universalAction(arch)
allacts.resetDefaults()
root = allacts.getCurrent()
root.reset(fd)

print("=== Running full pipeline ===")
try:
    root.perform(fd)
    print("Pipeline completed successfully.")
except Exception as e:
    import traceback
    print(f"Pipeline error: {e}")
    traceback.print_exc()

# Summary of final ops
print(f"\n=== Pipeline result ===")
print(f"Flags: {fd._flags:#x}")
print(f"Blocks: {fd.getBasicBlocks().getSize()}")
nops = sum(1 for _ in fd.beginOpAll())
print(f"Total ops: {nops}")

# Count by opcode
from collections import Counter
opc_counts = Counter()
for op in fd.beginOpAll():
    opc_counts[op.code().name] += 1
print("\nOp counts:")
for name, cnt in opc_counts.most_common(20):
    print(f"  {name}: {cnt}")

# Show CALL/CALLIND ops
print("\n=== CALL/CALLIND ops ===")
for op in fd.beginOpAll():
    opc = op.code()
    if opc in (OpCode.CPUI_CALL, OpCode.CPUI_CALLIND):
        ni = op.numInput()
        inputs = []
        for j in range(ni):
            vn = op.getIn(j)
            sn = vn.getSpace().getName() if vn.getSpace() else '?'
            inputs.append(f"{sn}:{vn.getOffset():#x}:{vn.getSize()}")
        print(f"  {opc.name} @{op.getAddr()} inputs=[{', '.join(inputs)}]")

# Try emitting C code
print("\n=== C code emission ===")
try:
    from ghidra.output.emit_helpers import _printc_from_funcdata
    code = _printc_from_funcdata(fd)
    print(code)
except Exception as e:
    import traceback
    print(f"C emission error: {e}")
    traceback.print_exc()
    # Fall back to raw
    try:
        from ghidra.output.emit_helpers import _raw_c_from_funcdata
        print("\n=== Raw fallback ===")
        print(_raw_c_from_funcdata(fd))
    except Exception as e2:
        print(f"Raw emission also failed: {e2}")
