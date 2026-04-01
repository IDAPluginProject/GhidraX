"""
Non-zero mask calculation. Corresponds to PcodeOp::getNZMaskLocal() in op.cc.
"""
from ghidra.core.opcodes import OpCode
from ghidra.core.address import (
    calc_mask, pcode_left, pcode_right, sign_extend_sized,
    coveringmask, leastsigbit_set, mostsigbit_set, popcount,
)


_BOOL_OPCS = frozenset((
    OpCode.CPUI_INT_EQUAL, OpCode.CPUI_INT_NOTEQUAL,
    OpCode.CPUI_INT_SLESS, OpCode.CPUI_INT_SLESSEQUAL,
    OpCode.CPUI_INT_LESS, OpCode.CPUI_INT_LESSEQUAL,
    OpCode.CPUI_INT_CARRY, OpCode.CPUI_INT_SCARRY,
    OpCode.CPUI_INT_SBORROW, OpCode.CPUI_BOOL_NEGATE,
    OpCode.CPUI_BOOL_XOR, OpCode.CPUI_BOOL_AND, OpCode.CPUI_BOOL_OR,
    OpCode.CPUI_FLOAT_EQUAL, OpCode.CPUI_FLOAT_NOTEQUAL,
    OpCode.CPUI_FLOAT_LESS, OpCode.CPUI_FLOAT_LESSEQUAL,
    OpCode.CPUI_FLOAT_NAN,
))

_VN_CONSTANT = 0x02  # Varnode.constant flag


def getNZMaskLocal(op, cliploop=True):
    out = op._output
    if out is None: return 0
    size = out._size
    fm = calc_mask(size)
    opc = op._opcode_enum
    ins = op._inrefs
    # Guard: any None input → return full mask (conservative)
    for vn in ins:
        if vn is None:
            return fm
    if opc in _BOOL_OPCS:
        return 1
    if opc in (OpCode.CPUI_COPY, OpCode.CPUI_INT_ZEXT):
        return ins[0]._nzm
    if opc == OpCode.CPUI_INT_SEXT:
        i0 = ins[0]
        return sign_extend_sized(i0._nzm, i0._size, size) & fm
    if opc in (OpCode.CPUI_INT_XOR, OpCode.CPUI_INT_OR):
        r = ins[0]._nzm
        return r | ins[1]._nzm if r != fm else fm
    if opc == OpCode.CPUI_INT_AND:
        r = ins[0]._nzm
        return r & ins[1]._nzm if r != 0 else 0
    if opc == OpCode.CPUI_INT_LEFT:
        i1 = ins[1]
        if not (i1._flags & _VN_CONSTANT): return fm
        sa = int(i1._loc.offset)
        return pcode_left(ins[0]._nzm, sa) & fm
    if opc == OpCode.CPUI_INT_RIGHT:
        i1 = ins[1]
        if not (i1._flags & _VN_CONSTANT): return fm
        sa = int(i1._loc.offset)
        return pcode_right(ins[0]._nzm, sa)
    if opc == OpCode.CPUI_INT_SRIGHT:
        i1 = ins[1]
        if not (i1._flags & _VN_CONSTANT) or size > 8: return fm
        sa = int(i1._loc.offset)
        r = ins[0]._nzm
        if (r & (fm ^ (fm >> 1))) == 0:
            return pcode_right(r, sa)
        return pcode_right(r, sa) | ((fm >> sa) ^ fm)
    if opc == OpCode.CPUI_INT_DIV:
        val = ins[0]._nzm
        r = coveringmask(val)
        i1 = ins[1]
        if i1._flags & _VN_CONSTANT:
            sa = mostsigbit_set(i1._nzm)
            if sa != -1:
                r >>= sa
        return r & fm
    if opc == OpCode.CPUI_INT_REM:
        val = ins[1]._nzm - 1
        return coveringmask(val) & fm
    if opc == OpCode.CPUI_SUBPIECE:
        r = ins[0]._nzm
        s = int(ins[1]._loc.offset)
        return (r >> (8 * s)) & fm if s < 8 else 0
    if opc == OpCode.CPUI_PIECE:
        sa = ins[1]._size
        hi = ins[0]._nzm
        r = (hi << (8 * sa)) if sa < 8 else 0
        return (r | ins[1]._nzm) & fm
    if opc == OpCode.CPUI_INT_ADD:
        r = ins[0]._nzm
        if r != fm:
            r |= ins[1]._nzm
            r |= (r << 1)
            r &= fm
        return r
    if opc == OpCode.CPUI_INT_MULT:
        if size > 8: return fm
        v1 = ins[0]._nzm
        v2 = ins[1]._nzm
        s1 = mostsigbit_set(v1); s2 = mostsigbit_set(v2)
        if s1 == -1 or s2 == -1: return 0
        l1 = leastsigbit_set(v1); l2 = leastsigbit_set(v2)
        sa = l1 + l2
        if sa >= 8 * size: return 0
        t1 = s1 - l1 + 1; t2 = s2 - l2 + 1
        total = t1 + t2 - (1 if t1 == 1 or t2 == 1 else 0)
        r = fm
        if total < 8 * size: r >>= (8 * size - total)
        return (r << sa) & fm
    if opc == OpCode.CPUI_INT_NEGATE:
        return fm
    if opc == OpCode.CPUI_MULTIEQUAL:
        n = len(ins)
        if n == 0: return fm
        r = 0
        for i in range(n):
            if cliploop:
                parent = op._parent
                if parent is not None and i < parent.sizeIn() and parent.isLoopIn(i):
                    continue
            r |= ins[i]._nzm
        return r
    if opc == OpCode.CPUI_INDIRECT:
        return fm
    if opc in (OpCode.CPUI_CALL, OpCode.CPUI_CALLIND, OpCode.CPUI_CPOOLREF):
        return 1 if (op._flags & 0x10000080) else fm  # PcodeOp.calculated_bool | booloutput
    if opc == OpCode.CPUI_POPCOUNT:
        s = popcount(ins[0]._nzm)
        return coveringmask(s) & fm
    if opc == OpCode.CPUI_LZCOUNT:
        return coveringmask(ins[0]._size * 8) & fm
    return fm


_VN_WRITTEN2   = 0x10   # Varnode.written
_VN_CONSTANT2  = 0x02   # Varnode.constant


def calcNZMask(data):
    """Calculate non-zero mask for all Varnodes in the function."""
    for op in list(data._obank.beginAlive()):
        for vn in op._inrefs:
            if vn is None:
                continue
            vn_flags = vn._flags
            if not (vn_flags & _VN_WRITTEN2):
                if vn_flags & _VN_CONSTANT2:
                    vn._nzm = vn._loc.offset
                else:
                    vn._nzm = calc_mask(vn._size)
        out = op._output
        if out is not None:
            out._nzm = getNZMaskLocal(op, True)
