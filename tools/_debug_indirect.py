"""Debug: trace why INDIRECTs are missing after fullloop for 0x401000."""
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

# Lift function 0x401000 (simple: 2 calls + return)
FUNC = 0x401000
lifter = Lifter(sla, {'addrsize': 1, 'opsize': 1})
lifter.set_image(base, img)
fd = lifter.lift_function(f'func_{FUNC:x}', FUNC, 0)
_split_basic_blocks(fd, lifter=lifter)
arch = ArchitectureStandalone(lifter._spc_mgr)
fd.setArch(arch)
_setup_call_specs(fd, lifter=lifter)
_seed_default_return_output(fd, target)

def dump_ops(label):
    counts = {}
    print(f"\n=== {label} ===")
    for op in fd.beginOpAll():
        opc = op.code()
        nm = opc.name if hasattr(opc, 'name') else str(opc)
        counts[nm] = counts.get(nm, 0) + 1
        out = op.getOut()
        out_s = f"{out.getSpace().getName()}:{out.getOffset():#x}:{out.getSize()}" if out else "---"
        ins = []
        for k in range(op.numInput()):
            v = op.getIn(k)
            ins.append(f"{v.getSpace().getName()}:{v.getOffset():#x}:{v.getSize()}")
        print(f"  {nm:25s} {out_s:30s} <- {', '.join(ins)}  @{op.getAddr()}")
    print(f"  Total: {sum(counts.values())}  {dict(sorted(counts.items(), key=lambda x:-x[1]))}")

# Monkey-patch heritage to trace guardCalls
from ghidra.analysis.heritage import Heritage
_orig_guard = Heritage.guard
_orig_guardCalls = Heritage.guardCalls

def _traced_guard(self, addr, size, guardPerformed, read, write, inputvars):
    spc_name = addr.getSpace().getName() if addr.getSpace() else '?'
    print(f"  [guard] {spc_name}:{addr.getOffset():#x} sz={size} guardPerf={guardPerformed} reads={len(read)} writes={len(write)} inputs={len(inputvars)}")
    return _orig_guard(self, addr, size, guardPerformed, read, write, inputvars)

def _traced_guardCalls(self, fl, addr, size, write):
    spc_name = addr.getSpace().getName() if addr.getSpace() else '?'
    ncalls = self._fd.numCalls() if hasattr(self._fd, 'numCalls') else 0
    print(f"    [guardCalls] {spc_name}:{addr.getOffset():#x} sz={size} fl={fl:#x} numCalls={ncalls}")
    write_before = len(write)
    _orig_guardCalls(self, fl, addr, size, write)
    write_after = len(write)
    if write_after > write_before:
        print(f"    [guardCalls] -> created {write_after - write_before} INDIRECT(s)")
    else:
        # Trace why nothing was created
        for i in range(ncalls):
            fc = self._fd.getCallSpecs(i)
            if fc is None:
                print(f"      call[{i}]: fc=None")
                continue
            callOp = fc.getOp()
            effecttype = 'unknown'
            if hasattr(fc, 'hasEffect'):
                transAddr = addr  # simplified
                effecttype = fc.hasEffect(transAddr, size)
            print(f"      call[{i}]: @{callOp.getAddr()} effect={effecttype}")

Heritage.guard = _traced_guard
Heritage.guardCalls = _traced_guardCalls

# Dump initial state
dump_ops("After lift + flow")

# Check call specs
print(f"\n--- Call specs ---")
print(f"  numCalls: {fd.numCalls() if hasattr(fd, 'numCalls') else 'N/A'}")
if hasattr(fd, 'numCalls'):
    for ci in range(fd.numCalls()):
        cs = fd.getCallSpecs(ci)
        print(f"  CallSpec[{ci}]: op=@{cs.getOp().getAddr()} code={cs.getOp().code().name}")

# Run actions one by one
allacts = ActionDatabase()
allacts.universalAction(arch)
allacts.resetDefaults()
root = allacts.getCurrent()
root.reset(fd)

print("\n--- Running pre-fullloop actions ---")
for act in root._list:
    nm = act.getName()
    if nm == 'fullloop':
        break
    act.perform(fd)

# Now manually run fullloop sub-actions to trace INDIRECT removal
fullloop_act = None
for act in root._list:
    if act.getName() == 'fullloop':
        fullloop_act = act
        break

print("\n--- Fullloop sub-actions (mainloop) ---")
# fullloop is an ActionRestartGroup containing a single 'mainloop' ActionGroup
# mainloop contains the actual heritage/rules/deadcode actions
mainloop = fullloop_act._list[0] if fullloop_act._list else None
print(f"fullloop children: {[a.getName() for a in fullloop_act._list]}")
if mainloop and hasattr(mainloop, '_list'):
    print(f"mainloop children: {[a.getName() for a in mainloop._list]}")

# Helper: dump EAX-related ops
def dump_eax_chain(label):
    print(f"\n  --- EAX chain ({label}) ---")
    for op in fd.beginOpAll():
        out = op.getOut()
        is_eax_out = (out and out.getSpace().getName() == 'register' 
                      and out.getOffset() == 0x0 and out.getSize() == 4)
        has_eax_in = False
        for k in range(op.numInput()):
            v = op.getIn(k)
            if (v.getSpace().getName() == 'register' and v.getOffset() == 0x0 
                and v.getSize() == 4):
                has_eax_in = True
                break
        if is_eax_out or has_eax_in or op.code() == OpCode.CPUI_RETURN:
            out_s = f"{out.getSpace().getName()}:{out.getOffset():#x}:{out.getSize()} id={id(out):#x}" if out else "---"
            ins = []
            for k in range(op.numInput()):
                v = op.getIn(k)
                desc_count = sum(1 for _ in v.getDescendants())
                ins.append(f"{v.getSpace().getName()}:{v.getOffset():#x}:{v.getSize()} id={id(v):#x} desc={desc_count}")
            opc = op.code().name
            print(f"    {opc:25s} out=[{out_s}] <- [{'; '.join(ins)}] @{op.getAddr()}")

# Run mainloop's children one by one
mainloop.reset(fd)
had_indirects = False
prev_ind = 0
for sub in mainloop._list:
    sub_nm = sub.getName()
    sub.reset(fd)
    sub.perform(fd)
    ind = sum(1 for op in fd.beginOpAll() if op.code() == OpCode.CPUI_INDIRECT)
    total = sum(1 for _ in fd.beginOpAll())
    eax_ind = sum(1 for op in fd.beginOpAll() 
                  if op.code() == OpCode.CPUI_INDIRECT 
                  and op.getOut() is not None
                  and op.getOut().getSpace().getName() == 'register'
                  and op.getOut().getOffset() == 0x0
                  and op.getOut().getSize() == 4)
    delta = ind - prev_ind
    marker = ""
    if ind > 0 and not had_indirects:
        had_indirects = True
        marker = " *** INDIRECTs CREATED ***"
    elif had_indirects and eax_ind == 0 and prev_ind > 0:
        marker = " *** EAX INDIRECTs GONE ***"
    if delta != 0 or ind > 0 or marker:
        print(f"  {sub_nm:30s}  total={total:4d}  INDIRECT={ind:3d}  EAX_IND={eax_ind}  d={delta:+d}{marker}")
    else:
        print(f"  {sub_nm:30s}  total={total:4d}  INDIRECT={ind:3d}")
    if sub_nm == 'heritage' and ind > 0:
        dump_eax_chain("after heritage")
    if sub_nm == 'deadcode':
        dump_eax_chain("after deadcode")
    if sub_nm == 'stackstall':
        dump_eax_chain("after stackstall")
        # Trace: re-run stackstall's children one by one to find culprit
        # (We already ran stackstall, so this is post-mortem analysis)
    prev_ind = ind

# === Phase 2: Re-run from after deadcode to trace stackstall internals ===
print("\n\n=== PHASE 2: Trace stackstall internals ===")
# Re-setup from scratch to get a clean state up to deadcode
lifter2 = Lifter(sla, {'addrsize': 1, 'opsize': 1})
lifter2.set_image(base, img)
fd2 = lifter2.lift_function(f'func_{FUNC:x}', FUNC, 0)
_split_basic_blocks(fd2, lifter=lifter2)
arch2 = ArchitectureStandalone(lifter2._spc_mgr)
fd2.setArch(arch2)
_setup_call_specs(fd2, lifter=lifter2)
_seed_default_return_output(fd2, target)

allacts2 = ActionDatabase()
allacts2.universalAction(arch2)
allacts2.resetDefaults()
root2 = allacts2.getCurrent()
root2.reset(fd2)

# Run pre-fullloop
for act in root2._list:
    if act.getName() == 'fullloop':
        break
    act.perform(fd2)

# Get mainloop
fullloop2 = None
for act in root2._list:
    if act.getName() == 'fullloop':
        fullloop2 = act
        break
mainloop2 = fullloop2._list[0]
mainloop2.reset(fd2)

# Run mainloop children up to (but not including) stackstall
for sub in mainloop2._list:
    sub_nm = sub.getName()
    sub.reset(fd2)
    if sub_nm == 'stackstall':
        break
    sub.perform(fd2)

def dump_eax_chain_fd(fd_arg, label):
    print(f"\n  --- EAX chain ({label}) ---")
    for op in fd_arg.beginOpAll():
        out = op.getOut()
        is_eax_out = (out and out.getSpace().getName() == 'register' 
                      and out.getOffset() == 0x0 and out.getSize() == 4)
        has_eax_in = False
        for k in range(op.numInput()):
            v = op.getIn(k)
            if (v.getSpace().getName() == 'register' and v.getOffset() == 0x0 
                and v.getSize() == 4):
                has_eax_in = True
                break
        if is_eax_out or has_eax_in or op.code() == OpCode.CPUI_RETURN:
            out_s = f"{out.getSpace().getName()}:{out.getOffset():#x}:{out.getSize()}" if out else "---"
            ins = []
            for k in range(op.numInput()):
                v = op.getIn(k)
                desc_count = sum(1 for _ in v.getDescendants())
                ins.append(f"{v.getSpace().getName()}:{v.getOffset():#x}:{v.getSize()} desc={desc_count}")
            opc = op.code().name
            print(f"    {opc:25s} out=[{out_s}] <- [{'; '.join(ins)}] @{op.getAddr()}")

ind_before = sum(1 for op in fd2.beginOpAll() if op.code() == OpCode.CPUI_INDIRECT)
print(f"Before stackstall: INDIRECT={ind_before}")
for op in fd2.beginOpAll():
    if op.code() == OpCode.CPUI_INDIRECT:
        outvn = op.getOut()
        invn = op.getIn(0)
        iopvn = op.getIn(1)
        indop_ref = getattr(iopvn, '_iop_ref', None)
        print(f"  INDIRECT @{op.getAddr()}")
        print(f"    out: {outvn.getSpace().getName()}:{outvn.getOffset():#x}:{outvn.getSize()} noLocalAlias={outvn.hasNoLocalAlias()}")
        print(f"    in0: {invn.getSpace().getName()}:{invn.getOffset():#x}:{invn.getSize()}")
        print(f"    in1: space_type={iopvn.getSpace().getType() if iopvn.getSpace() else '?'} _iop_ref={indop_ref}")
        print(f"    isIndirectCreation={op.isIndirectCreation()} noIndirectCollapse={op.noIndirectCollapse()}")
        if indop_ref is not None:
            print(f"    blocking op: {indop_ref.code().name} @{indop_ref.getAddr()} isDead={indop_ref.isDead()}")
            print(f"      hasNoLocalAlias check: {outvn.hasNoLocalAlias()}")
            print(f"      isIndirectCreation || noIndirectCollapse: {op.isIndirectCreation() or op.noIndirectCollapse()}")

# Now trace inside stackstall (it's an ActionPool with sub-actions)
stackstall_act = None
for sub in mainloop2._list:
    if sub.getName() == 'stackstall':
        stackstall_act = sub
        break

print(f"stackstall type: {type(stackstall_act).__name__}")
if hasattr(stackstall_act, '_list'):
    print(f"stackstall children: {[a.getName() for a in stackstall_act._list]}")
    stackstall_act.reset(fd2)
    for ssa in stackstall_act._list:
        ssa_nm = ssa.getName()
        ssa.reset(fd2)
        ssa.perform(fd2)
        ind_now = sum(1 for op in fd2.beginOpAll() if op.code() == OpCode.CPUI_INDIRECT)
        eax_now = sum(1 for op in fd2.beginOpAll() 
                      if op.code() == OpCode.CPUI_INDIRECT 
                      and op.getOut() is not None
                      and op.getOut().getSpace().getName() == 'register'
                      and op.getOut().getOffset() == 0x0
                      and op.getOut().getSize() == 4)
        total_now = sum(1 for _ in fd2.beginOpAll())
        print(f"  stackstall.{ssa_nm:25s}  total={total_now:4d}  INDIRECT={ind_now:3d}  EAX_IND={eax_now}")
        if ind_now < ind_before:
            dump_eax_chain_fd(fd2, f"after stackstall.{ssa_nm}")
        ind_before = ind_now

# Restore
Heritage.guard = _orig_guard
Heritage.guardCalls = _orig_guardCalls
