"""Debug: trace why CALLIND at 0x40100d is missing its arg '1'."""
import sys, os, struct
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', 'src'))

from ghidra.sleigh.lifter import Lifter
from ghidra.sleigh.arch_map import add_sla_search_dir, resolve_arch
from ghidra.arch.archshim import ArchitectureStandalone
from ghidra.analysis.flowlifter import _split_basic_blocks, _setup_call_specs
from ghidra.transform.pipeline import _seed_default_return_output
from ghidra.transform.action import ActionDatabase, Action
from ghidra.core.opcodes import OpCode

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

FUNC = 0x401000
lifter = Lifter(sla, {'addrsize': 1, 'opsize': 1})
lifter.set_image(base, img)
fd = lifter.lift_function(f'func_{FUNC:x}', FUNC, 0)

print("=== Raw ops after lift (before split) ===")
for op in fd.beginOpAll():
    opc = op.code().name
    out = op.getOut()
    out_s = f"{out.getSpace().getName()}:{out.getOffset():#x}:{out.getSize()}" if out else "---"
    ins = []
    for k in range(op.numInput()):
        v = op.getIn(k)
        ins.append(f"{v.getSpace().getName()}:{v.getOffset():#x}:{v.getSize()}")
    print(f"  {opc:25s} {out_s:35s} <- {', '.join(ins)}  @{op.getAddr()}")

_split_basic_blocks(fd, lifter=lifter)
arch = ArchitectureStandalone(lifter._spc_mgr)
fd.setArch(arch)
_setup_call_specs(fd, lifter=lifter)
_seed_default_return_output(fd, target)

print("\n=== After split + call specs ===")
for op in fd.beginOpAll():
    opc = op.code().name
    out = op.getOut()
    out_s = f"{out.getSpace().getName()}:{out.getOffset():#x}:{out.getSize()}" if out else "---"
    ins = []
    for k in range(op.numInput()):
        v = op.getIn(k)
        ins.append(f"{v.getSpace().getName()}:{v.getOffset():#x}:{v.getSize()}")
    extra = ""
    if opc in ('CPUI_CALLIND', 'CPUI_CALL'):
        extra = f"  numInput={op.numInput()}"
    print(f"  {opc:25s} {out_s:35s} <- {', '.join(ins)}  @{op.getAddr()}{extra}")

# Check call specs
print(f"\n=== Call specs ===")
print(f"numCalls: {fd.numCalls()}")
for ci in range(fd.numCalls()):
    cs = fd.getCallSpecs(ci)
    callop = cs.getOp()
    print(f"  CallSpec[{ci}]: op={callop.code().name} @{callop.getAddr()} numInput={callop.numInput()}")
    # Check active param trials
    if hasattr(cs, 'getActiveInput'):
        ap = cs.getActiveInput()
        if ap is not None:
            print(f"    ActiveInput: numTrials={ap.getNumTrials() if hasattr(ap, 'getNumTrials') else '?'}")

# Now run up to fullloop and check the CALLIND state
allacts = ActionDatabase()
allacts.universalAction(arch)
allacts.resetDefaults()
root = allacts.getCurrent()
root.reset(fd)

# Run pre-fullloop actions
for act in root._list:
    nm = act.getName()
    if nm == 'fullloop':
        break
    act.perform(fd)
    # Check CALLIND after each action
    for op in fd.beginOpAll():
        if op.code() == OpCode.CPUI_CALLIND:
            ni = op.numInput()
            ins = [f"{op.getIn(k).getSpace().getName()}:{op.getIn(k).getOffset():#x}:{op.getIn(k).getSize()}" for k in range(ni)]
            print(f"  After {nm:25s}: CALLIND @{op.getAddr()} numInput={ni} inputs=[{', '.join(ins)}]")

# Check active input state for each call
print("\n=== Active param state before fullloop ===")
for ci in range(fd.numCalls()):
    cs = fd.getCallSpecs(ci)
    callop = cs.getOp()
    is_active = cs.isInputActive() if hasattr(cs, 'isInputActive') else 'N/A'
    print(f"  CallSpec[{ci}]: {callop.code().name} @{callop.getAddr()} isInputActive={is_active}")
    if is_active and hasattr(cs, 'getActiveInput'):
        ai = cs.getActiveInput()
        if ai is not None:
            nt = ai.getNumTrials() if hasattr(ai, 'getNumTrials') else '?'
            np = ai.getNumPasses() if hasattr(ai, 'getNumPasses') else '?'
            mp = ai.getMaxPass() if hasattr(ai, 'getMaxPass') else '?'
            fc_check = ai.isFullyChecked() if hasattr(ai, 'isFullyChecked') else '?'
            print(f"    ActiveInput: numTrials={nt} numPasses={np} maxPass={mp} fullyChecked={fc_check}")
            if hasattr(ai, 'getNumTrials') and hasattr(ai, 'getTrial'):
                for ti in range(ai.getNumTrials()):
                    trial = ai.getTrial(ti)
                    addr = trial.getAddress() if hasattr(trial, 'getAddress') else '?'
                    sz = trial.getSize() if hasattr(trial, 'getSize') else '?'
                    slot = trial.getSlot() if hasattr(trial, 'getSlot') else '?'
                    active = trial.isActive() if hasattr(trial, 'isActive') else '?'
                    used = trial.isUsed() if hasattr(trial, 'isUsed') else '?'
                    checked = trial.isChecked() if hasattr(trial, 'isChecked') else '?'
                    print(f"      Trial[{ti}]: addr={addr} sz={sz} slot={slot} active={active} used={used} checked={checked}")
    is_out_active = cs.isOutputActive() if hasattr(cs, 'isOutputActive') else 'N/A'
    print(f"    isOutputActive={is_out_active}")

# Check STORE ops that write to stack (these should become CALLIND args)
print("\n=== Stack writes (potential args) before fullloop ===")
for op in fd.beginOpAll():
    if op.code() == OpCode.CPUI_STORE:
        ins = [f"{op.getIn(k).getSpace().getName()}:{op.getIn(k).getOffset():#x}:{op.getIn(k).getSize()}" for k in range(op.numInput())]
        print(f"  STORE @{op.getAddr()} inputs=[{', '.join(ins)}]")
    if op.code() == OpCode.CPUI_INT_SUB:
        out = op.getOut()
        if out and out.getSpace().getName() == 'register' and out.getOffset() == 0x10:  # ESP
            ins = [f"{op.getIn(k).getSpace().getName()}:{op.getIn(k).getOffset():#x}:{op.getIn(k).getSize()}" for k in range(op.numInput())]
            print(f"  INT_SUB(ESP) @{op.getAddr()} inputs=[{', '.join(ins)}]")

# Run fullloop
print("\n=== Running fullloop ===")
fullloop = None
for act in root._list:
    if act.getName() == 'fullloop':
        fullloop = act
        break
fullloop.reset(fd)
fullloop.perform(fd)

print("\n=== After fullloop: CALLIND state ===")
for op in fd.beginOpAll():
    if op.code() in (OpCode.CPUI_CALLIND, OpCode.CPUI_CALL):
        ni = op.numInput()
        ins = [f"{op.getIn(k).getSpace().getName()}:{op.getIn(k).getOffset():#x}:{op.getIn(k).getSize()}" for k in range(ni)]
        print(f"  {op.code().name} @{op.getAddr()} numInput={ni} inputs=[{', '.join(ins)}]")
