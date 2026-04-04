"""
Lifter: bridges sleigh_native C++ P-code output into the Python IR framework.

Converts native PcodeResult objects into Funcdata populated with
Python Varnode/PcodeOp/BlockBasic objects, ready for analysis and PrintC output.
"""

from __future__ import annotations

import struct
from collections import deque
from typing import Optional, Dict, List, Tuple

from ghidra.core.address import Address
from ghidra.core.opcodes import OpCode
from ghidra.core.space import (
    AddrSpace, AddrSpaceManager, ConstantSpace, UniqueSpace, OtherSpace,
    IPTR_PROCESSOR, IPTR_CONSTANT, IPTR_INTERNAL, IPTR_IOP, IPTR_FSPEC,
    IPTR_SPACEBASE,
)
from ghidra.ir.varnode import Varnode
from ghidra.ir.op import PcodeOp
from ghidra.block.block import BlockBasic
from ghidra.analysis.funcdata import Funcdata


class _SpacebasePoint:
    """Minimal stand-in for VarnodeData used by getSpacebase()."""
    __slots__ = ('space', 'offset', 'size')
    def __init__(self, space, offset: int, size: int):
        self.space = space
        self.offset = offset
        self.size = size


class _StackSpace(AddrSpace):
    """Minimal stack space (IPTR_SPACEBASE) backed by ESP/RSP.

    C++ creates this from the .cspec <stackpointer> element. We detect
    the correct stack pointer register from the architecture:
      x86-32: ESP at register offset 0x10, size 4
      x86-64: RSP at register offset 0x20, size 8
    """
    def __init__(self, mgr, reg_space, idx: int, flags: int,
                 sp_offset: int = 0x10, sp_size: int = 4,
                 contain_space=None):
        super().__init__(mgr, None, IPTR_SPACEBASE, "stack", False, sp_size, 1, idx,
                         flags, 1, 1)  # delay=1, deadcodedelay=1
        self._reg_space = reg_space
        self._spacebase = _SpacebasePoint(reg_space, sp_offset, sp_size)
        self._contain = contain_space  # RAM space that the stack overlays

    def numSpacebase(self) -> int:
        return 1

    def getSpacebase(self, i: int):
        if i != 0:
            raise IndexError(f"Stack space has only 1 spacebase, got index {i}")
        return self._spacebase

    def getContain(self):
        """Return the address space that this spacebase overlays (RAM)."""
        return self._contain

    def stackGrowsNegative(self) -> bool:
        return True


class Lifter:
    """Lifts machine code to Python IR using the native SLEIGH engine.

    Usage:
        lifter = Lifter(sla_path)
        lifter.set_image(base_addr, code_bytes)
        fd = lifter.lift_function("func_name", entry_addr, size)
        # fd is a Funcdata with Varnodes, PcodeOps, BlockBasic populated
    """

    def __init__(self, sla_path: str, context: Optional[Dict[str, int]] = None) -> None:
        from ghidra.sleigh.sleigh_native import SleighNative
        self._native = SleighNative()
        self._native.load_sla(sla_path)
        if context:
            for k, v in context.items():
                self._native.set_context_default(k, v)

        # Build address space manager from native register info
        self._spc_mgr = AddrSpaceManager()
        self._spc_mgr._native = self._native  # expose for _TranslateShim
        self._spaces: Dict[str, AddrSpace] = {}
        self._setup_spaces()

        # Image data for jump table recovery
        self._image_base: int = 0
        self._image_data: bytes = b''
        # Resolved jump tables: branchind_addr -> [target_addrs]
        self._jumptables: Dict[int, List[int]] = {}  # addr -> [targets]
        self._insn_fall_throughs: Dict[int, int] = {}  # addr -> addr+length
        self._unprocessed: List[int] = []  # out-of-range branch targets (fillinBranchStubs)
        # Known function entries — used by checkContainedCall to skip
        # CALL→BRANCH conversion for real functions (matches C++ fd!=NULL check)
        self._known_functions: set = set()

    def _setup_spaces(self) -> None:
        """Create Python AddrSpace objects matching the native SLEIGH spaces."""
        cs = ConstantSpace(self._spc_mgr)
        self._spc_mgr._insertSpace(cs)
        self._spc_mgr._constantSpace = cs
        self._spaces["const"] = cs

        code_space_name = self._native.get_default_code_space()

        # Detect pointer size from register info: if RSP (8-byte stack pointer)
        # exists, the architecture is 64-bit; otherwise default to 4 (32-bit).
        regs = self._native.get_registers()
        ptr_size = 4
        if 'RSP' in regs and regs['RSP'][2] == 8:
            ptr_size = 8

        idx = 1
        for name in [code_space_name, "register", "unique"]:
            if name == "const":
                continue
            if name == "unique":
                spc = UniqueSpace(self._spc_mgr, None, idx)
                self._spc_mgr._insertSpace(spc)
                self._spc_mgr._uniqueSpace = spc
            else:
                tp = IPTR_PROCESSOR
                flags = AddrSpace.hasphysical | AddrSpace.heritaged | AddrSpace.does_deadcode
                # C++ .sla sets delay=1 for RAM (code/data) space so that
                # Heritage skips it on pass 0.  Register space keeps delay=0.
                dl = 1 if (name == code_space_name) else 0
                # Code space addr_size must match pointer size (8 for x86-64, 4 for x86-32)
                sz = ptr_size if (name == code_space_name) else 4
                spc = AddrSpace(self._spc_mgr, None, tp, name, False, sz, 1, idx, flags, dl, dl)
                self._spc_mgr._insertSpace(spc)
                if name == code_space_name:
                    self._spc_mgr.setDefaultCodeSpace(spc)
                    self._spc_mgr.setDefaultDataSpace(spc)
            self._spaces[name] = spc
            idx += 1

        # Create IOP space for INDIRECT op references (C++ OtherSpace "iop")
        iop_spc = AddrSpace(self._spc_mgr, None, IPTR_IOP, "iop", False, 8, 1, idx, 0, 0, 0)
        self._spc_mgr._insertSpace(iop_spc)
        self._spc_mgr._iopSpace = iop_spc
        self._spaces["iop"] = iop_spc
        idx += 1

        # Create FSPEC space for call-spec references
        fspec_spc = AddrSpace(self._spc_mgr, None, IPTR_FSPEC, "fspec", False, 8, 1, idx, 0, 0, 0)
        self._spc_mgr._insertSpace(fspec_spc)
        self._spc_mgr._fspecSpace = fspec_spc
        self._spaces["fspec"] = fspec_spc
        idx += 1

        # Create stack space (IPTR_SPACEBASE) backed by ESP/RSP.
        # This enables ActionExtraPopSetup to insert INT_ADD ops for
        # stack-pointer adjustment at call sites.
        reg_space = self._spaces.get("register")
        if reg_space is not None:
            stack_flags = AddrSpace.hasphysical | AddrSpace.heritaged | AddrSpace.does_deadcode
            # x86-64: RSP at offset 0x20, size 8; x86-32: ESP at offset 0x10, size 4
            if ptr_size == 8:
                sp_off, sp_sz = 0x20, 8
            else:
                sp_off, sp_sz = 0x10, 4
            ram_space = self._spaces.get("ram")
            stack_spc = _StackSpace(self._spc_mgr, reg_space, idx, stack_flags, sp_off, sp_sz,
                                    contain_space=ram_space)
            self._spc_mgr._insertSpace(stack_spc)
            self._spc_mgr._stackSpace = stack_spc
            self._spaces["stack"] = stack_spc
            idx += 1

    def _get_space(self, name: str) -> AddrSpace:
        """Get or create a Python AddrSpace by name."""
        if name in self._spaces:
            return self._spaces[name]
        # Create on demand
        idx = len(self._spc_mgr._spaces)
        if name == "unique":
            spc = UniqueSpace(self._spc_mgr, None, idx)
            self._spc_mgr._insertSpace(spc)
            self._spc_mgr._uniqueSpace = spc
        else:
            # Non-register IPTR_PROCESSOR spaces default to delay=1
            spc = AddrSpace(self._spc_mgr, None, IPTR_PROCESSOR, name, False, 4, 1, idx,
                            AddrSpace.hasphysical, 1, 1)
            self._spc_mgr._insertSpace(spc)
        self._spaces[name] = spc
        return spc

    def set_image(self, base_addr: int, data: bytes) -> None:
        """Set the binary image to analyze."""
        self._native.set_image(base_addr, data)
        self._image_base = base_addr
        self._image_data = data

    def get_registers(self) -> dict:
        """Get all register definitions from the native engine."""
        return self._native.get_registers()

    def disassemble(self, addr: int):
        """Disassemble a single instruction."""
        return self._native.disassemble(addr)

    def disassemble_range(self, start: int, end: int):
        """Disassemble a range of instructions."""
        return self._native.disassemble_range(start, end)

    def _try_resolve_jumptable(self, ops, all_insns=None, insn_addr: int = 0) -> Optional[List[int]]:
        """Try to resolve jump table targets from BRANCHIND p-code pattern.

        Detects two patterns:

        1) x86-32 direct table::

            tmp1 = INT_MULT(reg, 4)
            tmp2 = INT_ADD(const[table_base], tmp1)
            target = LOAD(space, tmp2)
            BRANCHIND(target)

        2) x86-64 relative offset table::

            tmp1 = INT_MULT(idx, 4)
            tmp2 = INT_ADD(base_reg, tmp1)
            off32 = LOAD(space, tmp2)
            off64 = INT_SEXT(off32)
            target = INT_ADD(off64, base_reg)
            BRANCHIND(target)

        For pattern 2, base_reg is traced backward through prior instructions
        to find its constant value (typically from LEA with RIP-relative addr).

        C++ ref: jumptable.cc JumpTable::recoverModel
        """
        if not self._image_data:
            return None

        # Build output→op map for this instruction's ops
        out_map: Dict[Tuple[str, int], object] = {}
        for op in ops:
            if op.output:
                out_map[(op.output.space, op.output.offset)] = op

        # Find BRANCHIND
        branchind = None
        for op in ops:
            if op.opcode == OpCode.CPUI_BRANCHIND.value:
                branchind = op
                break
        if branchind is None or not branchind.inputs:
            return None

        # --- Pattern 1: direct table (x86-32) ---
        result = self._try_direct_table(out_map, branchind)
        if result is not None:
            return result

        # --- Pattern 2: relative offset table (x86-64) ---
        if all_insns is not None:
            result = self._try_relative_table_traced(all_insns, ops, branchind, insn_addr)
            if result is not None:
                return result

        return None

    def _try_direct_table(self, out_map, branchind) -> Optional[List[int]]:
        """Pattern 1: BRANCHIND(LOAD(INT_ADD(const[base], INT_MULT(reg, sz))))."""
        bi_in = branchind.inputs[0]
        load_op = out_map.get((bi_in.space, bi_in.offset))
        if load_op is None or load_op.opcode != OpCode.CPUI_LOAD.value:
            return None
        if len(load_op.inputs) < 2:
            return None

        addr_vn = load_op.inputs[1]
        add_op = out_map.get((addr_vn.space, addr_vn.offset))
        if add_op is None or add_op.opcode != OpCode.CPUI_INT_ADD.value:
            return None
        if len(add_op.inputs) < 2:
            return None

        # One input should be const (table_base), other from INT_MULT
        table_base = None
        mult_vn = None
        for inp in add_op.inputs:
            if inp.space == "const":
                table_base = inp.offset
            else:
                mult_vn = inp
        if table_base is None or mult_vn is None:
            return None

        mult_op = out_map.get((mult_vn.space, mult_vn.offset))
        if mult_op is None or mult_op.opcode != OpCode.CPUI_INT_MULT.value:
            return None

        entry_size = 0
        for inp in mult_op.inputs:
            if inp.space == "const":
                entry_size = inp.offset
        if entry_size not in (4, 8):
            return None

        return self._read_direct_table(table_base, entry_size)

    def _try_relative_table_traced(self, all_insns, current_ops, branchind,
                                     insn_addr: int = 0) -> Optional[List[int]]:
        """Pattern 2: BRANCHIND(INT_ADD(INT_SEXT(LOAD(...)), base_reg)).

        x86-64 switch tables use 32-bit signed offsets from a base address.
        Uses per-instruction backward tracing to handle register reuse.
        """
        # Build per-instruction output maps sorted by address
        insn_maps: List[Tuple[int, Dict[Tuple[str, int], object]]] = []
        for prev_insn in all_insns:
            omap: Dict[Tuple[str, int], object] = {}
            for op in prev_insn.ops:
                if op.output:
                    omap[(op.output.space, op.output.offset)] = op
            insn_maps.append((prev_insn.addr, omap))
        # Use actual instruction address (not a sentinel)
        branchind_addr = insn_addr if insn_addr != 0 else (
            max((a for a, _ in insn_maps), default=0) + 1)
        # Add current instruction if not already present
        cur_addrs = {a for a, _ in insn_maps}
        if branchind_addr not in cur_addrs:
            cur_map: Dict[Tuple[str, int], object] = {}
            for op in current_ops:
                if op.output:
                    cur_map[(op.output.space, op.output.offset)] = op
            insn_maps.append((branchind_addr, cur_map))
        insn_maps.sort(key=lambda x: x[0])

        # Step 1: find the INT_ADD that defines BRANCHIND's input register
        bi_vn = branchind.inputs[0]
        add_op, add_addr = self._find_writer_before(
            insn_maps, bi_vn.space, bi_vn.offset, branchind_addr)
        if add_op is None or add_op.opcode != OpCode.CPUI_INT_ADD.value:
            return None
        if len(add_op.inputs) < 2:
            return None

        # Step 2: one INT_ADD input should come from INT_SEXT, other is base_reg
        # Trace both inputs from BEFORE the INT_ADD's instruction
        sext_op = None
        base_vn = None
        for inp in add_op.inputs:
            writer, _ = self._find_writer_before(
                insn_maps, inp.space, inp.offset, add_addr)
            if writer is not None and writer.opcode == OpCode.CPUI_INT_SEXT.value:
                sext_op = writer
            else:
                base_vn = inp
        if sext_op is None or base_vn is None:
            return None

        # Step 3: INT_SEXT input should come from LOAD
        load_vn = sext_op.inputs[0]
        # SEXT and LOAD are typically in the same instruction, use intra-insn map
        sext_insn_map = self._find_insn_map_containing(insn_maps, sext_op)
        load_op = sext_insn_map.get((load_vn.space, load_vn.offset)) if sext_insn_map else None
        if load_op is None or load_op.opcode != OpCode.CPUI_LOAD.value:
            return None
        if len(load_op.inputs) < 2:
            return None

        # Step 4: LOAD address = INT_ADD(base_reg, INT_MULT(idx, 4))
        load_addr_vn = load_op.inputs[1]
        load_add = sext_insn_map.get((load_addr_vn.space, load_addr_vn.offset)) if sext_insn_map else None
        if load_add is None or load_add.opcode != OpCode.CPUI_INT_ADD.value:
            return None
        if len(load_add.inputs) < 2:
            return None

        # Identify base_reg and mult in the LOAD address
        load_base_vn = None
        load_mult_vn = None
        for inp in load_add.inputs:
            src = sext_insn_map.get((inp.space, inp.offset)) if sext_insn_map else None
            if src is not None and src.opcode == OpCode.CPUI_INT_MULT.value:
                load_mult_vn = inp
            else:
                load_base_vn = inp
        if load_base_vn is None or load_mult_vn is None:
            return None

        # Verify base_reg consistency (LOAD base == final ADD base)
        if (load_base_vn.space != base_vn.space or
                load_base_vn.offset != base_vn.offset):
            return None

        # Verify INT_MULT has constant 4
        mult_op = sext_insn_map.get((load_mult_vn.space, load_mult_vn.offset)) if sext_insn_map else None
        if mult_op is None or mult_op.opcode != OpCode.CPUI_INT_MULT.value:
            return None
        entry_size = 0
        for inp in mult_op.inputs:
            if inp.space == "const":
                entry_size = inp.offset
        if entry_size != 4:
            return None

        # Step 5: find base_reg constant value by searching backward
        base_val = self._find_register_const_traced(insn_maps, base_vn, add_addr)
        if base_val is None:
            return None

        # Step 6: require a CBRANCH guard bounding the switch index.
        # Without a guard, the BRANCHIND is likely a computed call, not a switch.
        guard_max = self._find_guard_max_entries(all_insns, insn_addr)
        if guard_max is None:
            return None

        targets = self._read_relative_table(base_val, entry_size)
        if targets and guard_max > 0 and len(targets) > guard_max:
            targets = targets[:guard_max]
        return targets

    def _find_guard_max_entries(self, all_insns, branchind_addr: int) -> Optional[int]:
        """Scan backward from BRANCHIND for a CBRANCH guard that bounds the index.

        Returns the max number of table entries (the guard comparison constant),
        or None if no guard is found (meaning this is likely not a bounded switch).
        """
        # Walk backward through decoded instructions before the BRANCHIND,
        # staying within the same basic block (stop at any BRANCH/BRANCHIND/RETURN).
        candidates = [(insn.addr, insn) for insn in all_insns
                      if insn.addr < branchind_addr]
        candidates.sort(key=lambda x: x[0], reverse=True)

        cbranch_idx = -1
        for idx, (addr, insn) in enumerate(candidates[:20]):
            has_terminator = False
            for op in insn.ops:
                if op.opcode == OpCode.CPUI_CBRANCH.value:
                    cbranch_idx = idx
                    break
                if op.opcode in (OpCode.CPUI_BRANCH.value,
                                 OpCode.CPUI_BRANCHIND.value,
                                 OpCode.CPUI_RETURN.value,
                                 OpCode.CPUI_CALL.value):
                    has_terminator = True
            if cbranch_idx >= 0 or has_terminator:
                break

        if cbranch_idx < 0:
            return None  # no guard found

        # Search the CBRANCH insn AND the few instructions BEFORE it
        # (at lower addresses = higher indices in candidates) for
        # INT_LESS / INT_SLESS with a constant.  x86 cmp+ja pattern
        # puts the comparison (cmp) BEFORE the branch (ja).
        search_range = candidates[cbranch_idx:cbranch_idx + 5]
        for _, search_insn in search_range:
            for op2 in search_insn.ops:
                if op2.opcode in (OpCode.CPUI_INT_LESS.value,
                                  OpCode.CPUI_INT_SLESS.value):
                    for inp in op2.inputs:
                        if inp.space == "const" and 1 < inp.offset <= 512:
                            # x86 'cmp eax,N; ja default' → valid indices
                            # are 0..N inclusive → N+1 entries.
                            return inp.offset + 1
        # CBRANCH exists but we couldn't extract a bound;
        # still treat as guarded with a generous cap.
        return 256

    def _find_writer_before(self, insn_maps, space: str, offset: int,
                            before_addr: int) -> Tuple[object, int]:
        """Find the last op writing to (space, offset) in instructions before before_addr."""
        for addr, omap in reversed(insn_maps):
            if addr >= before_addr:
                continue
            op = omap.get((space, offset))
            if op is not None:
                return op, addr
        return None, 0

    def _find_insn_map_containing(self, insn_maps, target_op) -> Optional[dict]:
        """Find the per-instruction output map that contains target_op."""
        for _, omap in insn_maps:
            for op in omap.values():
                if op is target_op:
                    return omap
        return None

    def _find_register_const_traced(self, insn_maps, reg_vn,
                                     before_addr: int) -> Optional[int]:
        """Trace a register backward through instructions to find its constant value."""
        defop, _ = self._find_writer_before(
            insn_maps, reg_vn.space, reg_vn.offset, before_addr)
        if defop is None:
            return None
        if defop.opcode == OpCode.CPUI_COPY.value:
            if defop.inputs and defop.inputs[0].space == "const":
                return defop.inputs[0].offset
        if defop.opcode == OpCode.CPUI_INT_ADD.value:
            if len(defop.inputs) >= 2:
                a, b = defop.inputs[0], defop.inputs[1]
                if a.space == "const" and b.space == "const":
                    return (a.offset + b.offset) & 0xFFFFFFFFFFFFFFFF
        return None


    def _read_direct_table(self, table_base: int, entry_size: int) -> Optional[List[int]]:
        """Read absolute address entries from a direct jump table."""
        image_end = self._image_base + len(self._image_data)
        targets: List[int] = []
        fmt = '<I' if entry_size == 4 else '<Q'
        max_entries = 256

        for i in range(max_entries):
            entry_addr = table_base + i * entry_size
            file_off = entry_addr - self._image_base
            if file_off < 0 or file_off + entry_size > len(self._image_data):
                break
            val = struct.unpack_from(fmt, self._image_data, file_off)[0]
            if val < self._image_base or val >= image_end:
                break
            targets.append(val)

        return targets if targets else None

    def _read_relative_table(self, base: int, entry_size: int) -> Optional[List[int]]:
        """Read signed relative offset entries from a jump table.

        Each entry is a 32-bit signed offset from *base*.
        Target = base + sign_extend(entry).
        """
        image_end = self._image_base + len(self._image_data)
        targets: List[int] = []
        max_entries = 256
        max_offset = 0x80000  # 512KB — reasonable max for intra-function jump

        for i in range(max_entries):
            entry_addr = base + i * entry_size
            file_off = entry_addr - self._image_base
            if file_off < 0 or file_off + entry_size > len(self._image_data):
                break
            raw = struct.unpack_from('<i', self._image_data, file_off)[0]  # signed
            if abs(raw) > max_offset:
                break
            target = (base + raw) & 0xFFFFFFFFFFFFFFFF
            if target < self._image_base or target >= image_end:
                break
            targets.append(target)

        return targets if targets else None

    def lift_function(self, name: str, entry: int, size: int) -> Funcdata:
        """Lift a function starting at entry for size bytes into a Funcdata.

        Uses control-flow-following (worklist) to only lift reachable code,
        matching the C++ FlowInfo behaviour.

        This:
        1. Starts at the entry point and follows branches/fallthroughs
        2. Translates each instruction to P-code via native SLEIGH
        3. Creates Python Varnode/PcodeOp objects
        4. Groups ops into a single basic block (later split by _split_basic_blocks)
        5. Returns a populated Funcdata
        """
        code_spc = self._get_space(self._native.get_default_code_space())
        fd = Funcdata(name, name, None, Address(code_spc, entry), None, size)

        # --- Control-flow-following instruction collection ---
        # C++ uses baddr=0, eaddr=~0 (full address space).  Safety is
        # ensured by only following BRANCH/CBRANCH targets (not CALLs) and
        # BRANCHIND→CALLIND+RETURN termination at indirect jumps.
        # max_instructions mirrors C++ glb->max_instructions.
        max_instructions = 200000
        max_jumptable_targets = 500  # cap total targets to prevent cascading
        total_jt_targets = 0
        function_limit = entry + size if size > 0 else None

        def in_function_bounds(addr: int) -> bool:
            if function_limit is None:
                return True
            return entry <= addr < function_limit

        def enqueue_target(target_addr: int, *, fallthrough: bool = False) -> None:
            if not in_function_bounds(target_addr):
                return
            if fallthrough:
                worklist.appendleft(target_addr)
            else:
                worklist.append(target_addr)

        # C++ FlowInfo processes fall-throughs linearly (immediate) before
        # branch targets (queued in addrlist FIFO).  We simulate this with a
        # deque: fall-throughs → front (left), branch targets → back (right).
        worklist: deque = deque([entry])
        visited: set = set()
        insn_list: List = []  # (addr, native_result) in address order

        while worklist:
            addr = worklist.popleft()
            if not in_function_bounds(addr):
                continue
            if addr in visited:
                continue
            if len(insn_list) >= max_instructions:
                self._unprocessed.append(addr)
                continue
            visited.add(addr)

            try:
                insn = self._native.pcode(addr)
            except Exception:
                continue
            if insn.length <= 0:
                continue

            insn_list.append(insn)
            next_addr = addr + insn.length
            if in_function_bounds(next_addr):
                self._insn_fall_throughs[addr] = next_addr

            # Determine control flow from the last pcode op
            has_branch = False
            has_return = False
            for native_op in insn.ops:
                opc_val = native_op.opcode
                if opc_val == OpCode.CPUI_BRANCH.value:
                    has_branch = True
                    # Target is input[0] → back (branch target)
                    if native_op.inputs:
                        tgt = native_op.inputs[0]
                        if tgt.space != "const":
                            enqueue_target(tgt.offset)
                elif opc_val == OpCode.CPUI_CBRANCH.value:
                    # Branch target → back; fall-through → front
                    if native_op.inputs:
                        tgt = native_op.inputs[0]
                        if tgt.space != "const":
                            enqueue_target(tgt.offset)
                    enqueue_target(next_addr, fallthrough=True)
                elif opc_val == OpCode.CPUI_BRANCHIND.value:
                    has_branch = True
                    # Try to resolve jump table targets → back
                    if total_jt_targets < max_jumptable_targets:
                        targets = self._try_resolve_jumptable(insn.ops, insn_list, addr)
                        if targets:
                            self._jumptables[addr] = targets
                            total_jt_targets += len(targets)
                            for tgt in targets:
                                enqueue_target(tgt)
                elif opc_val == OpCode.CPUI_RETURN.value:
                    has_return = True

            # If no explicit branch/return, fall through → front
            if not has_branch and not has_return:
                enqueue_target(next_addr, fallthrough=True)

        if not insn_list:
            return fd

        # Sort by address to maintain sequential order
        insn_list.sort(key=lambda r: r.addr)

        # Create one basic block for now (later split by _split_basic_blocks)
        bb = fd.getBasicBlocks().newBlockBasic(fd)
        first_addr = insn_list[0].addr
        last_addr = insn_list[-1].addr
        bb.setInitialRange(Address(code_spc, first_addr),
                           Address(code_spc, last_addr))

        # In C++, PcodeEmitFd::dump() always creates fresh Varnodes for
        # both outputs and inputs.  Heritage (SSA construction) then connects
        # free input reads to the correct definitions via the renaming
        # algorithm.  We must do the same: never reuse output varnodes as
        # inputs, so that heritage sees proper free reads and can place
        # MULTIEQUALs at join points for shared addresses.

        def make_vn(space_name: str, offset: int, sz: int) -> Varnode:
            spc = self._get_space(space_name)
            return fd.newVarnode(sz, Address(spc, offset))

        # Convert each native PcodeResult -> Python PcodeOps
        for insn in insn_list:
            for native_op in insn.ops:
                opc = OpCode(native_op.opcode)
                num_in = len(native_op.inputs)
                op = fd.newOp(num_in, Address(code_spc, insn.addr))
                fd.opSetOpcode(op, opc)

                # Output — always fresh varnode
                if native_op.has_output:
                    o = native_op.output
                    out_vn = make_vn(o.space, o.offset, o.size)
                    fd.opSetOutput(op, out_vn)

                # Inputs — always fresh varnode (heritage connects via rename)
                is_load_store = opc in (OpCode.CPUI_LOAD, OpCode.CPUI_STORE)
                start_idx = 0
                if op.isCodeRef() and native_op.inputs:
                    coderef_in = native_op.inputs[0]
                    coderef_addr = Address(self._get_space(coderef_in.space), coderef_in.offset)
                    fd.opSetInput(op, fd.newCodeRef(coderef_addr), 0)
                    start_idx = 1

                for i, inp in enumerate(native_op.inputs[start_idx:], start=start_idx):
                    in_vn = make_vn(inp.space, inp.offset, inp.size)
                    # For LOAD/STORE input 0: tag the space constant with the
                    # actual target space.  The native engine encodes the C++
                    # AddrSpace* pointer as the offset of a const varnode; we
                    # resolve it to the default data space (RAM) since that is
                    # the only space x86 SLEIGH LOAD/STORE ops target.
                    if is_load_store and i == 0 and inp.space == "const":
                        data_spc = self._spc_mgr.getDefaultDataSpace()
                        if data_spc is not None:
                            in_vn.setSpaceFromConst(data_spc)
                    fd.opSetInput(op, in_vn, i)

                fd.opInsertEnd(op, bb)

        return fd

    def pcode_text(self, entry: int, size: int) -> str:
        """Lift a function and return human-readable PCode text.

        Format per instruction:
            0x401000: PUSH EBP
              (register, EBP, 4) = COPY (register, ESP, 4)
              ...
        """
        from ghidra.sleigh.arch_map import get_opcode_name

        native_results = self._native.pcode_range(entry, entry + size)
        if not native_results:
            return f"// No PCode generated for 0x{entry:X} (size={size})\n"

        lines = []
        for insn in native_results:
            # Instruction header: address + assembly
            lines.append(f"  0x{insn.addr:X}: {insn.mnemonic} {insn.body}")
            # PCode ops
            for op in insn.ops:
                opc_name = get_opcode_name(op.opcode)
                # Format output
                if op.has_output:
                    out = self._fmt_varnode(op.output)
                    out_str = f"{out} = "
                else:
                    out_str = ""
                # Format inputs
                ins = ", ".join(self._fmt_varnode(v) for v in op.inputs)
                lines.append(f"    {out_str}{opc_name} {ins}")
            lines.append("")  # blank line between instructions

        return "\n".join(lines)

    def _fmt_varnode(self, vn) -> str:
        """Format a native Varnode for display, resolving register names."""
        if vn.space == "register":
            regname = self._native.get_register_name("register", vn.offset, vn.size)
            if regname:
                return regname
            return f"reg[0x{vn.offset:x}:{vn.size}]"
        elif vn.space == "const":
            return f"0x{vn.offset:x}:{vn.size}"
        elif vn.space == "unique":
            return f"u_0x{vn.offset:x}:{vn.size}"
        else:
            return f"({vn.space}, 0x{vn.offset:x}, {vn.size})"

    def lift_and_print(self, name: str, entry: int, size: int) -> str:
        """Lift a function and generate C-like output. End-to-end pipeline."""
        import io
        from ghidra.output.prettyprint import EmitMarkup
        from ghidra.output.printc import PrintC
        from ghidra.types.cast import CastStrategyC
        from ghidra.types.datatype import TypeFactory
        from ghidra.fspec.fspec import FuncProto, ProtoModel

        fd = self.lift_function(name, entry, size)

        # Set up minimal prototype
        proto = fd.getFuncProto()
        proto.setModel(ProtoModel("__cdecl"))

        # Generate C output
        stream = io.StringIO()
        emit = EmitMarkup(stream)
        printer = PrintC()
        printer.setEmitter(emit)
        tf = TypeFactory()
        tf.setupCoreTypes()
        cs = CastStrategyC()
        cs.setTypeFactory(tf)
        printer.setCastStrategy(cs)

        printer.docFunction(fd)
        return emit.getOutput()
