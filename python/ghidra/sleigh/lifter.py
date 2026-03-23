"""
Lifter: bridges sleigh_native C++ P-code output into the Python IR framework.

Converts native PcodeResult objects into Funcdata populated with
Python Varnode/PcodeOp/BlockBasic objects, ready for analysis and PrintC output.
"""

from __future__ import annotations

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

    def get_registers(self) -> dict:
        """Get all register definitions from the native engine."""
        return self._native.get_registers()

    def disassemble(self, addr: int):
        """Disassemble a single instruction."""
        return self._native.disassemble(addr)

    def disassemble_range(self, start: int, end: int):
        """Disassemble a range of instructions."""
        return self._native.disassemble_range(start, end)

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
        end_addr = entry + size if size > 0 else entry + 0x10000
        worklist: List[int] = [entry]
        visited: set = set()
        insn_list: List = []  # (addr, native_result) in address order

        while worklist:
            addr = worklist.pop(0)
            if addr in visited:
                continue
            if addr >= end_addr:
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

            # Determine control flow from the last pcode op
            has_branch = False
            has_return = False
            for native_op in insn.ops:
                opc_val = native_op.opcode
                if opc_val == OpCode.CPUI_BRANCH.value:
                    has_branch = True
                    # Target is input[0]
                    if native_op.inputs:
                        tgt = native_op.inputs[0]
                        if tgt.space != "const":
                            worklist.append(tgt.offset)
                elif opc_val == OpCode.CPUI_CBRANCH.value:
                    # Conditional: both target and fallthrough
                    if native_op.inputs:
                        tgt = native_op.inputs[0]
                        if tgt.space != "const":
                            worklist.append(tgt.offset)
                    worklist.append(next_addr)
                elif opc_val == OpCode.CPUI_BRANCHIND.value:
                    has_branch = True
                elif opc_val == OpCode.CPUI_RETURN.value:
                    has_return = True

            # If no explicit branch/return, fall through to next instruction
            if not has_branch and not has_return:
                worklist.append(next_addr)

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
