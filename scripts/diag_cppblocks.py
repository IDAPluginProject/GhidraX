"""Analyze remaining heritage diff functions for fixable patterns."""
import sys, os
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', 'python'))
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..'))

from tests.test_cpexe_comparison import load_pe, SLA_PATH, TARGET
from ghidra.sleigh.decompiler_native import DecompilerNative
from ghidra.sleigh.lifter import Lifter
from ghidra.sleigh.decompiler_python import _split_basic_blocks

pe = load_pe('bin/cp.exe')
cpp = DecompilerNative()
cpp.add_spec_path('specs')
cpp.initialize()

# All remaining diff functions
diff_funcs = [0x40c090, 0x41bb70, 0x40b420, 0x40a3b0, 0x403f00, 0x417670]

for func_addr in diff_funcs:
    print(f"\n{'='*60}")
    print(f"=== 0x{func_addr:x} ===")
    
    # C++ side
    result = cpp.decompile_staged(SLA_PATH, TARGET, pe.image, pe.image_base,
                                  func_addr, 0, "heritage")
    ir = result["ir"]
    cpp_blocks = ir.get("blocks", [])
    
    # Python side
    context = {"addrsize": 1, "opsize": 1}
    lifter = Lifter(SLA_PATH, context)
    lifter.set_image(pe.image_base, pe.image)
    fd = lifter.lift_function("test", func_addr, 0)
    _split_basic_blocks(fd, lifter)
    bblocks = fd.getBasicBlocks()

    # Build maps
    cpp_by_addr = {}
    for b in cpp_blocks:
        cpp_by_addr.setdefault(b["start"], []).append(b)
    
    py_by_addr = {}
    for bi in range(bblocks.getSize()):
        bb = bblocks.getBlock(bi)
        start = bb.getStart().getOffset() if bb.getStart() else 0
        stop = bb.getStop().getOffset() if bb.getStop() else 0
        succs = [bb.getOut(i).getStart().getOffset() for i in range(bb.sizeOut())
                 if bb.getOut(i).getStart()]
        ops = list(bb.getOpList())
        addrs = sorted(set(op.getSeqNum().getAddr().getOffset() for op in ops))
        py_by_addr.setdefault(start, []).append(
            {"start": start, "stop": stop, "succs": succs,
             "num_ops": len(ops), "addrs": addrs})

    cpp_only = sorted(set(cpp_by_addr.keys()) - set(py_by_addr.keys()))
    py_only = sorted(set(py_by_addr.keys()) - set(cpp_by_addr.keys()))
    
    print(f"  C++ {len(cpp_blocks)} blocks, Python {bblocks.getSize()} blocks")
    if cpp_only:
        # Check which C++ only addresses are outside function range
        outside = [a for a in cpp_only if abs(a - func_addr) > 0x1000]
        inside = [a for a in cpp_only if abs(a - func_addr) <= 0x1000]
        if outside:
            print(f"  C++ OUTSIDE blocks: {[hex(a) for a in outside]}")
        if inside:
            print(f"  C++ inside-only blocks: {[hex(a) for a in inside]}")
    if py_only:
        print(f"  Py only blocks: {[hex(a) for a in py_only]}")
    
    # Show first 3 block-level diffs
    diffs_shown = 0
    all_addrs = sorted(set(cpp_by_addr.keys()) & set(py_by_addr.keys()))
    for addr in all_addrs:
        if diffs_shown >= 3:
            break
        cb = cpp_by_addr[addr][0]
        pb = py_by_addr[addr][0]
        cpp_stop = cb["stop"]
        py_stop = pb["stop"]
        cpp_succs = []
        for si in cb.get("successors", []):
            if si < len(cpp_blocks):
                cpp_succs.append(cpp_blocks[si]["start"])
        
        if cpp_stop != py_stop or sorted(cpp_succs) != sorted(pb["succs"]):
            print(f"  DIFF @0x{addr:x}:")
            print(f"    C++ stop=0x{cpp_stop:x} succs={[hex(s) for s in sorted(cpp_succs)]}")
            print(f"    Py  stop=0x{py_stop:x} succs={[hex(s) for s in sorted(pb['succs'])]}")
            diffs_shown += 1
