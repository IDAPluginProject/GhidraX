"""Debug: trace RulePropagateCopy and RuleLoadVarnode on placeholder LOAD."""
import sys, os, struct
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', 'src'))

from ghidra.sleigh.lifter import Lifter
from ghidra.sleigh.arch_map import add_sla_search_dir, resolve_arch
from ghidra.arch.archshim import ArchitectureStandalone
from ghidra.analysis.flowlifter import _split_basic_blocks, _setup_call_specs
from ghidra.transform.pipeline import _seed_default_return_output
from ghidra.transform.action import ActionDatabase
from ghidra.core.opcodes import OpCode
from ghidra.ir.varnode import Varnode

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

# Find placeholder LOADs before fullloop
print("=== Placeholder LOADs before fullloop ===")
for op in fd.beginOpAll():
    out = op.getOut()
    if out is not None and out.isSpacebasePlaceholder():
        print(f"  LOAD @{op.getAddr()} out={out.getSpace().getName()}:{out.getOffset():#x}")
        offvn = op.getIn(1)
        print(f"    in1: {offvn.getSpace().getName()}:{offvn.getOffset():#x} written={offvn.isWritten()}")
        if offvn.isWritten():
            defop = offvn.getDef()
            print(f"    in1 def: {defop.code().name}")
            for k in range(defop.numInput()):
                v = defop.getIn(k)
                flags = v._flags
                print(f"      in[{k}]: {v.getSpace().getName()}:{v.getOffset():#x}:{v.getSize()} "
                      f"const={v.isConstant()} input={v.isInput()} spacebase={v.isSpacebase()} "
                      f"insert={(flags & Varnode.insert)!=0} heritageKnown={v.isHeritageKnown()} "
                      f"written={v.isWritten()} flags={flags:#x}")

# Now run fullloop step by step
# Find fullloop action
fullloop = None
for act in root._list:
    if act.getName() == 'fullloop':
        fullloop = act
        break

# Find mainloop inside fullloop
mainloop = None
for act in fullloop._list:
    if act.getName() == 'mainloop':
        mainloop = act
        break

# Monkey-patch RuleLoadVarnode to trace failures
from ghidra.transform.rules_pointer import RuleLoadVarnode
_orig_applyOp = RuleLoadVarnode.applyOp
_orig_checkSpacebase = RuleLoadVarnode.checkSpacebase
_orig_vnSpacebase = RuleLoadVarnode.vnSpacebase
_orig_correctSpacebase = RuleLoadVarnode.correctSpacebase

@staticmethod
def _trace_correctSpacebase(glb, vn, spc):
    if not vn.isSpacebase():
        return None
    if vn.isConstant():
        return spc
    if not vn.isInput():
        return None
    if not hasattr(glb, 'getSpaceBySpacebase'):
        print(f"    correctSpacebase: glb has no getSpaceBySpacebase")
        return None
    assoc = glb.getSpaceBySpacebase(vn.getAddr(), vn.getSize())
    if assoc is None:
        print(f"    correctSpacebase: getSpaceBySpacebase returned None for {vn.getAddr()}:{vn.getSize()}")
        return None
    contain = assoc.getContain() if hasattr(assoc, 'getContain') else None
    if contain is not spc:
        print(f"    correctSpacebase: contain mismatch: contain={contain} spc={spc}")
        if contain is not None:
            print(f"      contain.getName()={contain.getName() if hasattr(contain,'getName') else '?'}")
        if spc is not None:
            print(f"      spc.getName()={spc.getName() if hasattr(spc,'getName') else '?'}")
        return None
    return assoc

@staticmethod
def _trace_checkSpacebase(glb, op):
    offvn = op.getIn(1)
    spcvn = op.getIn(0)
    loadspace = spcvn.getSpaceFromConst() if hasattr(spcvn, 'getSpaceFromConst') else None
    out = op.getOut()
    is_ph = out is not None and out.isSpacebasePlaceholder()
    if not is_ph:
        return _orig_checkSpacebase(glb, op)
    print(f"\n  [TRACE] checkSpacebase for placeholder LOAD @{op.getAddr()}")
    print(f"    spcvn={spcvn.getSpace().getName()}:{spcvn.getOffset():#x}")
    print(f"    loadspace={loadspace}")
    if loadspace is not None and hasattr(loadspace, 'getName'):
        print(f"    loadspace.getName()={loadspace.getName()}")
    if loadspace is None:
        print(f"    FAIL: loadspace is None")
        return None, 0
    if offvn.isConstant():
        return loadspace, offvn.getOffset()
    print(f"    offvn={offvn.getSpace().getName()}:{offvn.getOffset():#x} written={offvn.isWritten()} spacebase={offvn.isSpacebase()}")
    if offvn.isWritten():
        defop = offvn.getDef()
        print(f"    offvn def={defop.code().name}")
        for k in range(defop.numInput()):
            v = defop.getIn(k)
            print(f"      in[{k}]: {v.getSpace().getName()}:{v.getOffset():#x} const={v.isConstant()} input={v.isInput()} spacebase={v.isSpacebase()}")
    # Call vnSpacebase with tracing
    RuleLoadVarnode.correctSpacebase = _trace_correctSpacebase
    result = RuleLoadVarnode.vnSpacebase(glb, offvn, loadspace)
    RuleLoadVarnode.correctSpacebase = _orig_correctSpacebase
    print(f"    vnSpacebase result: {result}")
    return result

RuleLoadVarnode.checkSpacebase = _trace_checkSpacebase

print("\n=== Running mainloop actions one by one ===")
mainloop.reset(fd)
for act in mainloop._list:
    name = act.getName()
    act.reset(fd)
    act.perform(fd)
    print(f"\nAfter {name}:")
    
    # Check placeholder LOADs
    found_ph = False
    for op in fd.beginOpAll():
        out = op.getOut()
        if out is not None and out.isSpacebasePlaceholder():
            found_ph = True
            offvn = op.getIn(1)
            print(f"  placeholder LOAD @{op.getAddr()}: in1={offvn.getSpace().getName()}:{offvn.getOffset():#x} written={offvn.isWritten()}")
            if offvn.isWritten():
                defop = offvn.getDef()
                src = defop.getIn(0) if defop.numInput() > 0 else None
                if src:
                    flags = src._flags
                    print(f"    def={defop.code().name} src={src.getSpace().getName()}:{src.getOffset():#x} "
                          f"input={src.isInput()} spacebase={src.isSpacebase()} "
                          f"insert={(flags & Varnode.insert)!=0} heritageKnown={src.isHeritageKnown()} "
                          f"flags={flags:#x}")
    if not found_ph:
        print("  (no placeholder LOADs remaining)")
    
    # Check call specs  
    for ci in range(fd.numCalls()):
        cs = fd.getCallSpecs(ci)
        so = cs.getSpacebaseOffset()
        op = cs.getOp()
        ni = op.numInput()
        print(f"  CallSpec[{ci}] @{op.getAddr()}: stackoffset={so:#x} numInput={ni}")
    
    if name == 'stackstall':
        # Print INT_ADD details for the placeholder LOAD
        for op in fd.beginOpAll():
            out = op.getOut()
            if out is not None and out.isSpacebasePlaceholder():
                offvn = op.getIn(1)
                if offvn.isWritten():
                    defop = offvn.getDef()
                    print(f"  DETAIL: LOAD @{op.getAddr()} in1 def={defop.code().name}")
                    for k in range(defop.numInput()):
                        v = defop.getIn(k)
                        print(f"    in[{k}]: {v.getSpace().getName()}:{v.getOffset():#x}:{v.getSize()} "
                              f"const={v.isConstant()} input={v.isInput()} spacebase={v.isSpacebase()} "
                              f"insert={(v._flags & Varnode.insert)!=0} flags={v._flags:#x}")
                        if v.isWritten():
                            d3 = v.getDef()
                            print(f"      def: {d3.code().name}")
                            for j in range(d3.numInput()):
                                v2 = d3.getIn(j)
                                print(f"        in[{j}]: {v2.getSpace().getName()}:{v2.getOffset():#x}:{v2.getSize()} "
                                      f"const={v2.isConstant()} input={v2.isInput()} spacebase={v2.isSpacebase()}")
