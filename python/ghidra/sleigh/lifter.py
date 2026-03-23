"""
Lifter: bridges sleigh_native C++ P-code output into the Python IR framework.

Converts native PcodeResult objects into Funcdata populated with
Python Varnode/PcodeOp/BlockBasic objects, ready for analysis and PrintC output.
"""

from __future__ import annotations

import struct
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
    """Minimal stack space (IPTR_SPACEBASE) backed by ESP for x86-32.

    C++ creates this from the .cspec <stackpointer> element. We hardcode
    x86-32 values: ESP at register offset 0x10, size 4, stack grows negative.
    """
    def __init__(self, mgr, reg_space, idx: int, flags: int):
        super().__init__(mgr, None, IPTR_SPACEBASE, "stack", False, 4, 1, idx,
                         flags, 1, 1)  # delay=1, deadcodedelay=1
        self._reg_space = reg_space
        # x86-32: ESP = register[0x10:4]
        self._spacebase = _SpacebasePoint(reg_space, 0x10, 4)

    def numSpacebase(self) -> int:
        return 1

    def getSpacebase(self, i: int):
        if i != 0:
            raise IndexError(f"Stack space has only 1 spacebase, got index {i}")
        return self._spacebase

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
        self._spaces: Dict[str, AddrSpace] = {}
        self._setup_spaces()

        # Image data for jump table recovery
        self._image_base: int = 0
        self._image_data: bytes = b''
        # Resolved jump tables: branchind_addr -> [target_addrs]
        self._jumptables: Dict[int, List[int]] = {}  # addr -> [targets]
        self._insn_fall_throughs: Dict[int, int] = {}  # addr -> addr+length
        self._unprocessed: List[int] = []  # out-of-range branch targets (fillinBranchStubs)

    def _setup_spaces(self) -> None:
        """Create Python AddrSpace objects matching the native SLEIGH spaces."""
        cs = ConstantSpace(self._spc_mgr)
        self._spc_mgr._insertSpace(cs)
        self._spc_mgr._constantSpace = cs
        self._spaces["const"] = cs

        code_space_name = self._native.get_default_code_space()

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
                spc = AddrSpace(self._spc_mgr, None, tp, name, False, 4, 1, idx, flags, dl, dl)
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

        # Create stack space (IPTR_SPACEBASE) backed by ESP for x86-32.
        # This enables ActionExtraPopSetup to insert INT_ADD ops for
        # stack-pointer adjustment at call sites.
        reg_space = self._spaces.get("register")
        if reg_space is not None:
            stack_flags = AddrSpace.hasphysical | AddrSpace.heritaged | AddrSpace.does_deadcode
            stack_spc = _StackSpace(self._spc_mgr, reg_space, idx, stack_flags)
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

    def _try_resolve_jumptable(self, ops) -> Optional[List[int]]:
        """Try to resolve jump table targets from BRANCHIND p-code pattern.

        Detects the common x86 pattern:
            tmp1 = INT_MULT(reg, 4)
            tmp2 = INT_ADD(const[table_base], tmp1)
            target = LOAD(space, tmp2)
            BRANCHIND(target)

        Reads 4-byte LE entries from the image starting at table_base.
        Uses heuristic: entries must be valid code addresses within image.
        Returns list of target addresses or None if pattern not matched.

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

        # Trace: BRANCHIND input ← LOAD ← INT_ADD(const, INT_MULT(reg, 4))
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

        # Verify multiplier is 4 (sizeof pointer for 32-bit)
        entry_size = 0
        for inp in mult_op.inputs:
            if inp.space == "const":
                entry_size = inp.offset
        if entry_size not in (4, 8):
            return None

        # Read table entries from image
        image_end = self._image_base + len(self._image_data)
        targets: List[int] = []
        fmt = '<I' if entry_size == 4 else '<Q'
        max_entries = 512

        for i in range(max_entries):
            entry_addr = table_base + i * entry_size
            file_off = entry_addr - self._image_base
            if file_off < 0 or file_off + entry_size > len(self._image_data):
                break
            val = struct.unpack_from(fmt, self._image_data, file_off)[0]
            # Heuristic: target must be a valid address within the image
            if val < self._image_base or val >= image_end:
                break
            targets.append(val)

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
        # C++ FlowInfo processes fall-throughs linearly (immediate) before
        # branch targets (queued in addrlist FIFO).  We simulate this with a
        # deque: fall-throughs → front (left), branch targets → back (right).
        from collections import deque
        worklist: deque = deque([entry])
        visited: set = set()
        insn_list: List = []  # (addr, native_result) in address order

        while worklist:
            addr = worklist.popleft()
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
                            worklist.append(tgt.offset)
                elif opc_val == OpCode.CPUI_CBRANCH.value:
                    # Branch target → back; fall-through → front
                    if native_op.inputs:
                        tgt = native_op.inputs[0]
                        if tgt.space != "const":
                            worklist.append(tgt.offset)
                    worklist.appendleft(next_addr)
                elif opc_val == OpCode.CPUI_BRANCHIND.value:
                    has_branch = True
                    # Try to resolve jump table targets → back
                    targets = self._try_resolve_jumptable(insn.ops)
                    if targets:
                        self._jumptables[addr] = targets
                        for tgt in targets:
                            worklist.append(tgt)
                elif opc_val == OpCode.CPUI_RETURN.value:
                    has_return = True

            # If no explicit branch/return, fall through → front
            if not has_branch and not has_return:
                worklist.appendleft(next_addr)

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
                op.setOpcodeEnum(opc)

                # Output — always fresh varnode
                if native_op.has_output:
                    o = native_op.output
                    out_vn = make_vn(o.space, o.offset, o.size)
                    fd.opSetOutput(op, out_vn)

                # Inputs — always fresh varnode (heritage connects via rename)
                for i, inp in enumerate(native_op.inputs):
                    in_vn = make_vn(inp.space, inp.offset, inp.size)
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
