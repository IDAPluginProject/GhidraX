"""Debug: trace stackoffset resolution through fullloop."""
import sys, os, struct
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', 'src'))

from ghidra.sleigh.lifter import Lifter
from ghidra.sleigh.arch_map import add_sla_search_dir, resolve_arch
from ghidra.arch.archshim import ArchitectureStandalone
from ghidra.analysis.flowlifter import _split_basic_blocks, _setup_call_specs
from ghidra.transform.pipeline import _seed_default_return_output
from ghidra.transform.action import ActionDatabase
from ghidra.core.opcodes import OpCode
from ghidra.fspec.fspec import FuncCallSpecs

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

# Monkey-patch resolveSpacebaseRelative to trace
orig_resolve = FuncCallSpecs.resolveSpacebaseRelative
def traced_resolve(self, data, phvn):
    print(f"  [TRACE] resolveSpacebaseRelative called for op @{self.op.getAddr()}")
    if phvn is not None and phvn.isWritten():
        defop = phvn.getDef()
        if defop is not None and defop.numInput() > 0:
            refvn = defop.getIn(0)
            print(f"    refvn: space={refvn.getSpace().getName()} off={refvn.getOffset():#x} isInput={refvn.isInput()}")
    orig_resolve(self, data, phvn)
    print(f"    stackoffset after resolve: {self.stackoffset:#x}")
FuncCallSpecs.resolveSpacebaseRelative = traced_resolve

# Monkey-patch abortSpacebaseRelative to trace
orig_abort = FuncCallSpecs.abortSpacebaseRelative
def traced_abort(self, data):
    print(f"  [TRACE] abortSpacebaseRelative called for op @{self.op.getAddr()}")
    print(f"    stackoffset before abort: {self.stackoffset:#x}")
    orig_abort(self, data)
    print(f"    stackoffset after abort: {self.stackoffset:#x}")
FuncCallSpecs.abortSpacebaseRelative = traced_abort

# Monkey-patch RuleLoadVarnode to trace
from ghidra.transform.rules_pointer import RuleLoadVarnode
orig_apply = RuleLoadVarnode.applyOp
def traced_applyOp(self, op, data):
    out = op.getOut()
    is_ph = out is not None and out.isSpacebasePlaceholder()
    if is_ph:
        print(f"  [TRACE] RuleLoadVarnode.applyOp on placeholder LOAD @{op.getAddr()}")
        spcvn = op.getIn(0)
        offvn = op.getIn(1)
        print(f"    in0(spc): {spcvn.getSpace().getName()}:{spcvn.getOffset():#x}")
        print(f"    in1(off): {offvn.getSpace().getName()}:{offvn.getOffset():#x} written={offvn.isWritten()}")
        if offvn.isWritten():
            defop = offvn.getDef()
            print(f"    in1 def: {defop.code().name} numIn={defop.numInput()}")
            for k in range(defop.numInput()):
                v = defop.getIn(k)
                print(f"      in[{k}]: {v.getSpace().getName()}:{v.getOffset():#x}:{v.getSize()} const={v.isConstant()} input={v.isInput()} spacebase={v.isSpacebase()}")
    res = orig_apply(self, op, data)
    if is_ph:
        print(f"    result={res}")
    return res
RuleLoadVarnode.applyOp = traced_applyOp

# Build pipeline
allacts = ActionDatabase()
allacts.universalAction(arch)
allacts.resetDefaults()
root = allacts.getCurrent()
root.reset(fd)

# Run pre-fullloop
for act in root._list:
    if act.getName() == 'fullloop':
        break
    act.perform(fd)

print("=== Pre-fullloop stackoffset ===")
for ci in range(fd.numCalls()):
    cs = fd.getCallSpecs(ci)
    so = cs.getSpacebaseOffset()
    ps = cs.getStackPlaceholderSlot() if hasattr(cs, 'getStackPlaceholderSlot') else 'N/A'
    print(f"  CallSpec[{ci}] @{cs.getOp().getAddr()}: stackoffset={so:#x} placeholder={ps}")

# Run fullloop
print("\n=== Running fullloop ===")
fullloop = None
for act in root._list:
    if act.getName() == 'fullloop':
        fullloop = act
        break
fullloop.reset(fd)
fullloop.perform(fd)

print("\n=== After fullloop ===")
for ci in range(fd.numCalls()):
    cs = fd.getCallSpecs(ci)
    so = cs.getSpacebaseOffset()
    op = cs.getOp()
    ni = op.numInput()
    ins = [f"{op.getIn(k).getSpace().getName()}:{op.getIn(k).getOffset():#x}:{op.getIn(k).getSize()}" for k in range(ni)]
    print(f"  CallSpec[{ci}] @{op.getAddr()}: stackoffset={so:#x} numInput={ni} inputs=[{', '.join(ins)}]")
    if cs.isInputActive():
        ai = cs.getActiveInput()
        print(f"    numTrials={ai.getNumTrials()} passes={ai.getNumPasses()} maxPass={ai.getMaxPass()}")
