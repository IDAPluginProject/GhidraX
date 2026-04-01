"""Debug script: find where fullloop crashes on cp.exe 0x401180."""
import sys, os, struct, traceback
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', 'src'))

from ghidra.sleigh.lifter import Lifter
from ghidra.sleigh.arch_map import add_sla_search_dir, resolve_arch
from ghidra.arch.archshim import ArchitectureStandalone
from ghidra.analysis.flowlifter import _split_basic_blocks
from ghidra.transform.pipeline import _seed_default_return_output
from ghidra.transform.action import ActionDatabase, Action

# Setup
add_sla_search_dir(os.path.join(os.path.dirname(__file__), '..', 'specs', 'Processors', 'x86', 'data', 'languages'))
info = resolve_arch('metapc', 32, False)
sla, target = info['sla_path'], info['target']

# Build flat PE image
d = open(os.path.join(os.path.dirname(__file__), '..', 'examples', 'cp.exe'), 'rb').read()
pe_off = struct.unpack_from('<I', d, 0x3c)[0]
coff = pe_off + 4
nsec = struct.unpack_from('<H', d, coff + 2)[0]
ohsz = struct.unpack_from('<H', d, coff + 16)[0]
opt = coff + 20
base = struct.unpack_from('<I', d, opt + 28)[0]
sec_start = opt + ohsz
max_va = 0
secs = []
for i in range(nsec):
    o = sec_start + i * 40
    rva = struct.unpack_from('<I', d, o + 12)[0]
    vs = struct.unpack_from('<I', d, o + 8)[0]
    rs = struct.unpack_from('<I', d, o + 16)[0]
    ro = struct.unpack_from('<I', d, o + 20)[0]
    secs.append((rva, vs, rs, ro))
    e = rva + max(vs, rs)
    if e > max_va:
        max_va = e
buf = bytearray(max_va)
for rva, vs, rs, ro in secs:
    raw = d[ro:ro + rs]
    buf[rva:rva + len(raw)] = raw
img = bytes(buf)

# Lift function
lifter = Lifter(sla, {'addrsize': 1, 'opsize': 1})
lifter.set_image(base, img)
fd = lifter.lift_function('func_401080', 0x401080, 0)
_split_basic_blocks(fd, lifter=lifter)
arch = ArchitectureStandalone(lifter._spc_mgr)
fd.setArch(arch)
from ghidra.analysis.flowlifter import _setup_call_specs
_setup_call_specs(fd, lifter=lifter)
_seed_default_return_output(fd, target)

# Build action chain
allacts = ActionDatabase()
allacts.universalAction(arch)
allacts.resetDefaults()
root = allacts.getCurrent()
root.reset(fd)

# Check call specs before actions
print(f"\n--- Pre-action diagnostics ---")
print(f"  numCalls: {fd.numCalls() if hasattr(fd, 'numCalls') else 'N/A'}")
if hasattr(fd, 'numCalls'):
    for ci in range(fd.numCalls()):
        cs = fd.getCallSpecs(ci)
        print(f"  CallSpec[{ci}]: op={cs.getOp().getAddr() if cs else 'None'}")

# Check stack space
ss = arch.getStackSpace()
print(f"  stackSpace: {ss}")
if ss is not None:
    print(f"    type={ss.getType()}, delay={ss.getDelay()}, deadcodeDelay={ss.getDeadcodeDelay()}")
    print(f"    numSpacebase={ss.numSpacebase() if hasattr(ss, 'numSpacebase') else 'N/A'}")
    if hasattr(ss, 'numSpacebase'):
        for si in range(ss.numSpacebase()):
            sb = ss.getSpacebase(si)
            print(f"    spacebase[{si}]: {sb}")

# Check all spaces
print(f"  numSpaces: {arch.numSpaces()}")
for si in range(arch.numSpaces()):
    spc = arch.getSpace(si)
    if spc is not None:
        print(f"    [{si}] {spc.getName()} type={spc.getType()} delay={spc.getDelay()}")

# Check heritage info
if hasattr(fd, '_heritage') and fd._heritage is not None:
    h = fd._heritage
    print(f"  heritage._infolist: {len(h._infolist) if hasattr(h, '_infolist') else 'N/A'}")
    if hasattr(h, '_infolist'):
        for hi, info in enumerate(h._infolist):
            sn = info.space.getName() if info.space else 'None'
            print(f"    [{hi}] {sn} delay={info.delay} heritaged={info.isHeritaged()}")

# Count ops by type before fullloop
from ghidra.core.opcodes import OpCode
op_counts = {}
for op in fd.beginOpAll():
    opc = op.code()
    nm = opc.name if hasattr(opc, 'name') else str(opc)
    op_counts[nm] = op_counts.get(nm, 0) + 1
print(f"  Total ops: {sum(op_counts.values())}")
print(f"  Op breakdown: {dict(sorted(op_counts.items(), key=lambda x: -x[1]))}")

# Run actions up to and including fullloop
for act in root._list:
    nm = act.getName()
    try:
        act.perform(fd)
        if nm == 'fullloop':
            ind_count = sum(1 for op in fd.beginOpAll() if op.code() == OpCode.CPUI_INDIRECT)
            store_count = sum(1 for op in fd.beginOpAll() if op.code() == OpCode.CPUI_STORE)
            load_count = sum(1 for op in fd.beginOpAll() if op.code() == OpCode.CPUI_LOAD)
            sub_count = sum(1 for op in fd.beginOpAll() if op.code() == OpCode.CPUI_INT_SUB)
            total = sum(1 for _ in fd.beginOpAll())
            print(f"OK: {nm}  (total={total}, INDIRECT={ind_count}, STORE={store_count}, LOAD={load_count}, INT_SUB={sub_count})")
            # Dump STORE ops to understand what they look like
            print(f"\n--- STORE ops after fullloop ---")
            for op in fd.beginOpAll():
                if op.code() == OpCode.CPUI_STORE:
                    spc_in = op.getIn(0)
                    spc_from = spc_in.getSpaceFromConst() if hasattr(spc_in, 'getSpaceFromConst') else None
                    ptr_in = op.getIn(1)
                    val_in = op.getIn(2) if op.numInput() > 2 else None
                    ptr_str = f"{ptr_in.getSpace().getName()}:{ptr_in.getOffset():#x}" if ptr_in else "?"
                    if ptr_in.isWritten():
                        defop = ptr_in.getDef()
                        ptr_str += f" (def={defop.code().name})"
                        if defop.code() == OpCode.CPUI_INT_ADD:
                            in0 = defop.getIn(0)
                            in1 = defop.getIn(1)
                            ptr_str += f" [{in0.getSpace().getName()}:{in0.getOffset():#x} sb={in0.isSpacebase()} inp={in0.isInput()}"
                            ptr_str += f" + {in1.getSpace().getName()}:{in1.getOffset():#x} const={in1.isConstant()}]"
                    elif ptr_in.isInput():
                        ptr_str += " (INPUT)"
                    elif ptr_in.isFree():
                        ptr_str += " (FREE)"
                    val_str = f"sz={val_in.getSize()}" if val_in else "?"
                    spc_name = spc_from.getName() if spc_from else "None"
                    print(f"  STORE spc_in={spc_in.getSpace().getName()}:{spc_in.getOffset():#x} fromConst={spc_name} ptr={ptr_str} val={val_str} @ {op.getAddr()}")
                    # Trace the ESP chain for unconverted STOREs
                    if ptr_in.isWritten() and ptr_in.getDef().code() == OpCode.CPUI_INT_ADD:
                        chain_vn = ptr_in.getDef().getIn(0)
                        for step in range(5):
                            if chain_vn is None:
                                break
                            print(f"    chain[{step}]: {chain_vn.getSpace().getName()}:{chain_vn.getOffset():#x} sb={chain_vn.isSpacebase()} inp={chain_vn.isInput()} wr={chain_vn.isWritten()}", end="")
                            if chain_vn.isWritten():
                                d = chain_vn.getDef()
                                print(f" def={d.code().name}", end="")
                                if d.code() == OpCode.CPUI_INT_ADD:
                                    chain_vn = d.getIn(0)
                                elif d.code() == OpCode.CPUI_MULTIEQUAL:
                                    print(f" (MULTI, {d.numInput()} inputs)", end="")
                                    chain_vn = None
                                else:
                                    chain_vn = None
                            else:
                                chain_vn = None
                            print()
            # Check spacebase marking on ESP
            from ghidra.core.address import Address
            reg_spc = arch.getSpace(2)  # register space
            if reg_spc is not None:
                esp_addr = Address(reg_spc, 0x10)
                esp_in = fd.findVarnodeInput(4, esp_addr) if hasattr(fd, 'findVarnodeInput') else None
                if esp_in is not None:
                    print(f"  ESP input: isSpacebase={esp_in.isSpacebase()}, isInput={esp_in.isInput()}, flags={esp_in._flags:#x}")
                else:
                    print(f"  ESP input: NOT FOUND")
                # Check any ESP varnodes for spacebase flag
                for vn in fd._vbank.beginLoc():
                    if vn.getSpace() is reg_spc and vn.getOffset() == 0x10 and vn.getSize() == 4:
                        is_sb = vn.isSpacebase()
                        is_wr = vn.isWritten()
                        print(f"  ESP vn: offset={vn.getOffset():#x} spacebase={is_sb} written={is_wr} input={vn.isInput()}")
                        if is_sb:
                            break
                else:
                    print(f"  No ESP varnode marked as spacebase")
            # Check heritage state
            if hasattr(fd, '_heritage') and fd._heritage is not None:
                h = fd._heritage
                print(f"\n--- Heritage state after fullloop ---")
                print(f"  pass={h._pass}")
                for hi, info in enumerate(h._infolist):
                    sn = info.space.getName() if info.space else 'None'
                    print(f"  [{hi}] {sn} delay={info.delay} heritaged={info.isHeritaged()} loadGuardSearch={info.loadGuardSearch}")
        else:
            print(f"OK: {nm}")
    except Exception as e:
        print(f"FAIL: {nm}: {e}")
        import traceback; traceback.print_exc()
        break
