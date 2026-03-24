"""
Output formatting helpers for PcodeOp / Varnode → human-readable strings,
and lightweight C-like emission from Funcdata.

Moved here from decompiler_python.py to keep that file a thin driver.
"""

from __future__ import annotations

from typing import List, Dict

from ghidra.core.opcodes import OpCode


# =========================================================================
# Register name table for x86 (offset → human-readable name)
# =========================================================================
_X86_32_REG_NAMES: Dict[int, str] = {
    0x00: "EAX", 0x04: "ECX", 0x08: "EDX", 0x0C: "EBX",
    0x10: "ESP", 0x14: "EBP", 0x18: "ESI", 0x1C: "EDI",
    0x200: "CF",
}

_X86_64_REG_NAMES: Dict[int, str] = {
    0x00: "RAX", 0x08: "RCX", 0x10: "RDX", 0x18: "RBX",
    0x20: "RSP", 0x28: "RBP", 0x30: "RSI", 0x38: "RDI",
    0x200: "CF",
}


def _vn_str(vn) -> str:
    """Format a Varnode as a human-readable string."""
    spc = vn.getSpace()
    name = spc.getName()
    off = vn.getAddr().getOffset()
    sz = vn.getSize()

    if name == "const":
        if sz <= 4:
            return f"0x{off & 0xFFFFFFFF:x}"
        return f"0x{off:x}"
    if name == "register":
        # Try to look up a human-readable name
        return f"reg_{off:x}"
    if name == "unique":
        return f"tmp_{off:x}"
    if name == "ram":
        return f"mem[0x{off:x}]"
    return f"{name}[0x{off:x}:{sz}]"


def _op_str(op) -> str:
    """Format a PcodeOp as a C-like statement."""
    opc = op.code()
    out = op.getOut()
    nin = op.numInput()
    ins = [op.getIn(i) for i in range(nin)]
    ins_s = [_vn_str(v) for v in ins if v is not None]

    lhs = _vn_str(out) if out else None

    # Binary ops
    _binop = {
        OpCode.CPUI_INT_ADD: "+", OpCode.CPUI_INT_SUB: "-",
        OpCode.CPUI_INT_MULT: "*", OpCode.CPUI_INT_DIV: "/",
        OpCode.CPUI_INT_SDIV: "s/", OpCode.CPUI_INT_REM: "%",
        OpCode.CPUI_INT_SREM: "s%",
        OpCode.CPUI_INT_AND: "&", OpCode.CPUI_INT_OR: "|",
        OpCode.CPUI_INT_XOR: "^",
        OpCode.CPUI_INT_LEFT: "<<", OpCode.CPUI_INT_RIGHT: ">>",
        OpCode.CPUI_INT_SRIGHT: "s>>",
        OpCode.CPUI_INT_EQUAL: "==", OpCode.CPUI_INT_NOTEQUAL: "!=",
        OpCode.CPUI_INT_LESS: "<", OpCode.CPUI_INT_LESSEQUAL: "<=",
        OpCode.CPUI_INT_SLESS: "s<", OpCode.CPUI_INT_SLESSEQUAL: "s<=",
        OpCode.CPUI_INT_CARRY: "CARRY", OpCode.CPUI_INT_SCARRY: "SCARRY",
        OpCode.CPUI_INT_SBORROW: "SBORROW",
        OpCode.CPUI_BOOL_AND: "&&", OpCode.CPUI_BOOL_OR: "||",
        OpCode.CPUI_BOOL_XOR: "^^",
        OpCode.CPUI_FLOAT_ADD: "f+", OpCode.CPUI_FLOAT_SUB: "f-",
        OpCode.CPUI_FLOAT_MULT: "f*", OpCode.CPUI_FLOAT_DIV: "f/",
        OpCode.CPUI_FLOAT_EQUAL: "f==", OpCode.CPUI_FLOAT_NOTEQUAL: "f!=",
        OpCode.CPUI_FLOAT_LESS: "f<", OpCode.CPUI_FLOAT_LESSEQUAL: "f<=",
        OpCode.CPUI_PIECE: "PIECE",
    }

    # Unary ops
    _unop = {
        OpCode.CPUI_INT_NEGATE: "~", OpCode.CPUI_INT_2COMP: "-",
        OpCode.CPUI_BOOL_NEGATE: "!",
        OpCode.CPUI_FLOAT_NEG: "f-", OpCode.CPUI_FLOAT_ABS: "fabs",
        OpCode.CPUI_FLOAT_SQRT: "fsqrt",
        OpCode.CPUI_POPCOUNT: "POPCOUNT", OpCode.CPUI_LZCOUNT: "LZCOUNT",
    }

    if opc in _binop and len(ins_s) >= 2 and lhs:
        sym = _binop[opc]
        if sym in ("CARRY", "SCARRY", "SBORROW", "PIECE"):
            return f"{lhs} = {sym}({ins_s[0]}, {ins_s[1]})"
        return f"{lhs} = {ins_s[0]} {sym} {ins_s[1]}"

    if opc in _unop and len(ins_s) >= 1 and lhs:
        sym = _unop[opc]
        if sym in ("fabs", "fsqrt", "POPCOUNT", "LZCOUNT"):
            return f"{lhs} = {sym}({ins_s[0]})"
        return f"{lhs} = {sym}{ins_s[0]}"

    if opc == OpCode.CPUI_COPY and lhs and len(ins_s) >= 1:
        return f"{lhs} = {ins_s[0]}"

    if opc == OpCode.CPUI_LOAD and lhs and len(ins_s) >= 2:
        return f"{lhs} = *{ins_s[1]}"

    if opc == OpCode.CPUI_STORE and len(ins_s) >= 3:
        return f"*{ins_s[1]} = {ins_s[2]}"

    if opc == OpCode.CPUI_BRANCH and len(ins_s) >= 1:
        return f"goto {ins_s[0]}"

    if opc == OpCode.CPUI_CBRANCH and len(ins_s) >= 2:
        return f"if ({ins_s[1]}) goto {ins_s[0]}"

    if opc == OpCode.CPUI_BRANCHIND and len(ins_s) >= 1:
        return f"goto *{ins_s[0]}"

    if opc == OpCode.CPUI_CALL and len(ins_s) >= 1:
        args = ", ".join(ins_s[1:])
        return f"CALL {ins_s[0]}({args})"

    if opc == OpCode.CPUI_CALLIND and len(ins_s) >= 1:
        args = ", ".join(ins_s[1:])
        return f"CALLIND *{ins_s[0]}({args})"

    if opc == OpCode.CPUI_RETURN:
        if len(ins_s) >= 2:
            return f"return {ins_s[1]}"
        return "return"

    if opc == OpCode.CPUI_INT_ZEXT and lhs and len(ins_s) >= 1:
        return f"{lhs} = ZEXT({ins_s[0]})"

    if opc == OpCode.CPUI_INT_SEXT and lhs and len(ins_s) >= 1:
        return f"{lhs} = SEXT({ins_s[0]})"

    if opc == OpCode.CPUI_SUBPIECE and lhs and len(ins_s) >= 2:
        return f"{lhs} = SUBPIECE({ins_s[0]}, {ins_s[1]})"

    if opc == OpCode.CPUI_FLOAT_INT2FLOAT and lhs and len(ins_s) >= 1:
        return f"{lhs} = INT2FLOAT({ins_s[0]})"

    if opc == OpCode.CPUI_FLOAT_TRUNC and lhs and len(ins_s) >= 1:
        return f"{lhs} = TRUNC({ins_s[0]})"

    if opc == OpCode.CPUI_FLOAT_NAN and lhs and len(ins_s) >= 1:
        return f"{lhs} = NAN({ins_s[0]})"

    if opc == OpCode.CPUI_FLOAT_FLOAT2FLOAT and lhs and len(ins_s) >= 1:
        return f"{lhs} = FLOAT2FLOAT({ins_s[0]})"

    if opc == OpCode.CPUI_FLOAT_CEIL and lhs and len(ins_s) >= 1:
        return f"{lhs} = CEIL({ins_s[0]})"

    if opc == OpCode.CPUI_FLOAT_FLOOR and lhs and len(ins_s) >= 1:
        return f"{lhs} = FLOOR({ins_s[0]})"

    if opc == OpCode.CPUI_FLOAT_ROUND and lhs and len(ins_s) >= 1:
        return f"{lhs} = ROUND({ins_s[0]})"

    if opc == OpCode.CPUI_PTRADD and lhs and len(ins_s) >= 3:
        return f"{lhs} = PTRADD({ins_s[0]}, {ins_s[1]}, {ins_s[2]})"

    if opc == OpCode.CPUI_PTRSUB and lhs and len(ins_s) >= 2:
        return f"{lhs} = PTRSUB({ins_s[0]}, {ins_s[1]})"

    # Fallback: generic format
    arg_str = ", ".join(ins_s)
    if lhs:
        return f"{lhs} = {opc.name}({arg_str})"
    return f"{opc.name}({arg_str})"


def _printc_from_funcdata(fd) -> str:
    """Generate C pseudocode using the full PrintC emitter in flat mode.

    Uses PrintC's op handlers, RPN stack, register naming, and expression
    emission infrastructure. Falls back to _raw_c_from_funcdata on error.

    Since we don't have block structure recovery or full FuncProto,
    we manually emit the function header and use emitBlockBasic for
    each basic block in flat mode.
    """
    from ghidra.output.prettyprint import EmitMarkup, SyntaxHighlight
    from ghidra.output.printc import PrintC
    from ghidra.output.printlanguage import PrintLanguage

    emit = EmitMarkup()
    printer = PrintC(fd.getArch(), "c-language")
    printer.setEmitter(emit)

    # --- Function header ---
    name = fd.getDisplayName() if hasattr(fd, 'getDisplayName') else fd.getName()
    emit.tagLine()
    emit.print("void", SyntaxHighlight.keyword_color)
    emit.spaces(1)
    emit.tagFuncName(name, SyntaxHighlight.funcname_color, fd, None)
    emit.print("(")
    emit.print("void", SyntaxHighlight.keyword_color)
    emit.print(")")
    emit.tagLine()
    emit.print("{")
    emit.indentlevel += emit.indentincrement

    graph = fd.getStructure()
    if graph.getSize() != 0:
        graph.emit(printer)
    else:
        printer.setMod(PrintLanguage.flat)
        bblocks = fd.getBasicBlocks()
        for bi in range(bblocks.getSize()):
            bb = bblocks.getBlock(bi)
            printer.emitBlockBasic(bb)

    # --- Close function ---
    emit.indentlevel -= emit.indentincrement
    emit.tagLine()
    emit.print("}")
    emit.tagLine()

    return emit.getOutput()


def _raw_c_from_funcdata(fd) -> str:
    """Generate raw C-like pseudocode directly from Python Funcdata.

    This is the Module-1 level output: no analysis, no optimization,
    just a direct translation of PcodeOps to C-like statements.
    Uses pure Python Funcdata/Varnode/PcodeOp/Address/AddrSpace objects.
    """
    lines: List[str] = []
    name = fd.getName()
    addr = fd.getAddress()
    size = fd.getSize()

    bblocks = fd.getBasicBlocks()
    num_blocks = bblocks.getSize()

    lines.append(f"void {name}(void)")
    lines.append("{")

    for bi in range(num_blocks):
        bb = bblocks.getBlock(bi)
        ops = bb.getOpList() if hasattr(bb, 'getOpList') else []

        if num_blocks > 1:
            entry = bb.getEntryAddr() if hasattr(bb, 'getEntryAddr') else None
            label = f"0x{entry.getOffset():x}" if entry and not entry.isInvalid() else f"block_{bi}"
            lines.append(f"  // --- Block {bi} ({label}) ---")

        for op in ops:
            stmt = _op_str(op)
            seq = op.getSeqNum()
            pc = seq.getAddr().getOffset() if seq else 0
            lines.append(f"    {stmt};  // @0x{pc:x}")

    lines.append("}")
    lines.append("")
    return "\n".join(lines)
