"""Investigate op_diff pattern — build snapshots directly and compare."""
import sys
sys.path.insert(0, 'python')
sys.path.insert(0, '.')
from tests.test_cpexe_comparison import load_pe, SLA_PATH, TARGET
from ghidra.sleigh.decompiler_native import DecompilerNative
from ghidra.sleigh.bridge_validator import (
    _snapshot_from_cpp_dict, _snapshot_from_python_fd, _compare_snapshots
)
from ghidra.sleigh.lifter import Lifter
from ghidra.sleigh.decompiler_python import (
    _split_basic_blocks, _setup_call_specs, _inject_tracked_context,
    _run_prerequisite_actions, _ArchitectureShim,
)
from ghidra.core.opcodes import OpCode

pe = load_pe('bin/cp.exe')
dn = DecompilerNative()
dn.add_spec_path('specs')
dn.initialize()

for func_addr in [0x41d750]:
    print(f"\n{'='*60}")
    print(f"Function 0x{func_addr:x}")
    
    # C++ snapshot
    cpp_r = dn.decompile_staged(SLA_PATH, TARGET, pe.image, pe.image_base,
                                 func_addr, 0, 'heritage')
    cpp_snap = _snapshot_from_cpp_dict('heritage', cpp_r)
    
    # Python snapshot
    context = {"addrsize": 1, "opsize": 1}
    lifter = Lifter(SLA_PATH, context)
    lifter.set_image(pe.image_base, pe.image)
    fd = lifter.lift_function(f"f_{func_addr:x}", func_addr, 0)
    _split_basic_blocks(fd)
    arch = _ArchitectureShim(lifter._spc_mgr)
    fd.setArch(arch)
    _inject_tracked_context(fd, lifter)
    _setup_call_specs(fd, lifter)
    _run_prerequisite_actions(fd)
    fd.opHeritage()
    py_snap = _snapshot_from_python_fd('heritage', fd)
    
    print(f"  C++: {cpp_snap.num_blocks}blk/{cpp_snap.num_ops}ops")
    print(f"  Py:  {py_snap.num_blocks}blk/{py_snap.num_ops}ops")
    
    # Count total MULTIEQUALs and INDIRECTs
    for label, snap in [("C++", cpp_snap), ("Py", py_snap)]:
        meq = sum(1 for op in snap.all_ops if op.opcode == OpCode.CPUI_MULTIEQUAL.value)
        ind = sum(1 for op in snap.all_ops if op.opcode == OpCode.CPUI_INDIRECT.value)
        cpy = sum(1 for op in snap.all_ops if op.opcode == OpCode.CPUI_COPY.value)
        print(f"  {label} totals: MULTIEQUAL={meq}, INDIRECT={ind}, COPY={cpy}")
    
    # Show blocks at 0x41d800 with their ops
    bg = fd.getBasicBlocks()
    print(f"\n  --- Python blocks at 0x41d800 ---")
    for bi in range(bg.getSize()):
        bl = bg.getBlock(bi)
        addr = bl.getStart().getOffset()
        if addr == 0x41d800 or addr == 0x41d804:
            ops_list = bl.getOpList()
            npred = bl.sizeIn()
            nsucc = bl.sizeOut()
            print(f"  blk[{bi}] @0x{addr:x} preds={npred} succs={nsucc} ops={len(ops_list)}")
            for op in ops_list:
                opc = OpCode(op.code().value) if hasattr(op.code(), 'value') else op.code()
                seq = op.getSeqNum().getOrder()
                print(f"    {opc.name} seq={seq}")
    
    print(f"\n  --- C++ blocks at 0x41d800 ---")
    for b in cpp_snap.blocks:
        if b.start == 0x41d800:
            print(f"  blk[{b.index}] @0x{b.start:x} preds={b.predecessors} succs={b.successors} ops={b.num_ops}")
            for op in b.ops:
                opc = OpCode(op.opcode) if op.opcode < 80 else str(op.opcode)
                print(f"    {opc.name if hasattr(opc,'name') else opc} seq={op.seq_order}")

    # Build address maps (without remapping, just raw)
    cpp_by_addr = {}
    for b in cpp_snap.blocks:
        cpp_by_addr.setdefault(b.start, []).append(b)
    py_by_addr = {}
    for b in py_snap.blocks:
        py_by_addr.setdefault(b.start, []).append(b)
    
    all_addrs = sorted(set(cpp_by_addr) | set(py_by_addr))
    
    for addr in all_addrs:
        c_ops = [op for b in cpp_by_addr.get(addr, []) for op in b.ops]
        p_ops = [op for b in py_by_addr.get(addr, []) for op in b.ops]
        
        if len(c_ops) != len(p_ops):
            print(f"\n  Block @0x{addr:x}: C++={len(c_ops)} ops, Py={len(p_ops)} ops")
            # Show boundary ops
            for label, ops in [("C++", c_ops), ("Py", p_ops)]:
                # Count opcodes
                opc_counts = {}
                for op in ops:
                    name = OpCode(op.opcode).name if op.opcode < 80 else str(op.opcode)
                    opc_counts[name] = opc_counts.get(name, 0) + 1
                diffs_str = ", ".join(f"{k}={v}" for k, v in sorted(opc_counts.items()))
                print(f"    {label}: {diffs_str}")
            # Show which opcodes differ in count
            c_counts = {}
            for op in c_ops:
                name = OpCode(op.opcode).name if op.opcode < 80 else str(op.opcode)
                c_counts[name] = c_counts.get(name, 0) + 1
            p_counts = {}
            for op in p_ops:
                name = OpCode(op.opcode).name if op.opcode < 80 else str(op.opcode)
                p_counts[name] = p_counts.get(name, 0) + 1
            all_opcs = sorted(set(c_counts) | set(p_counts))
            for opc in all_opcs:
                cc = c_counts.get(opc, 0)
                pc = p_counts.get(opc, 0)
                if cc != pc:
                    print(f"    DIFF {opc}: C++={cc} Py={pc} (delta={pc-cc})")
