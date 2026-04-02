"""
Corresponds to: ruleaction.hh / ruleaction.cc

1:1 port of Ghidra's transformation Rules.
Each Rule triggers on a specific localized data-flow configuration.
"""

from __future__ import annotations

from typing import Optional, List, TYPE_CHECKING

from ghidra.core.opcodes import OpCode
from ghidra.core.error import LowlevelError
from ghidra.core.address import calc_mask, pcode_left, pcode_right, leastsigbit_set, signbit_negative
from ghidra.transform.action import Rule, ActionGroupList

# Hot-path inline constants (avoids repeated attribute lookups in tight loops)
_CPUI_COPY     = 1        # OpCode.CPUI_COPY
_VN_WRITTEN    = 0x10     # Varnode.written
_VN_CONST      = 0x02     # Varnode.constant
_VN_ANNOT      = 0x04     # Varnode.annotation
_VN_INSERT     = 0x20     # Varnode.insert
_VN_HK         = 0x26     # isHeritageKnown: insert|constant|annotation
_VN_ADDRTIED   = 0x8000   # Varnode.addrtied
_VN_ADDRFORCE  = 0x100000  # Varnode.addrforce
_OP_MARKER_FL  = 0x40     # PcodeOp.marker

if TYPE_CHECKING:
    from ghidra.ir.op import PcodeOp
    from ghidra.ir.varnode import Varnode
    from ghidra.analysis.funcdata import Funcdata


# =========================================================================
# RuleEarlyRemoval
# Get rid of unused PcodeOp objects where output is unused
# =========================================================================

class RuleEarlyRemoval(Rule):
    """Get rid of unused PcodeOp objects where we can guarantee the output is unused."""

    def __init__(self, g: str) -> None:
        super().__init__(g, 0, "earlyremoval")

    def clone(self, grouplist: ActionGroupList) -> Optional[Rule]:
        if not grouplist.contains(self._basegroup):
            return None
        return RuleEarlyRemoval(self._basegroup)

    # This rule applies to all ops (no getOpList override)

    _OP_CALL_OR_INDSRC = 0x404   # PcodeOp.call | PcodeOp.indirect_source
    _VN_AUTOLIVE = 0x40100000   # Varnode.addrforce | Varnode.autolive_hold

    def applyOp(self, op: PcodeOp, data: Funcdata) -> int:
        if op._flags & self._OP_CALL_OR_INDSRC:
            return 0
        vn = op._output
        if vn is None:
            return 0
        if vn._descend:
            return 0
        if vn._flags & self._VN_AUTOLIVE:
            return 0
        spc = vn._loc.base
        if spc is not None and spc.doesDeadcode():
            if not data.deadRemovalAllowedSeen(spc):
                return 0
        data.opDestroy(op)
        return 1


# =========================================================================
# RulePiece2Zext
# concat(#0, W) => zext(W)
# =========================================================================

class RulePiece2Zext(Rule):
    """Concatenation with 0 becomes an extension: V = concat(#0, W) => V = zext(W)"""

    def __init__(self, g: str) -> None:
        super().__init__(g, 0, "piece2zext")

    def clone(self, grouplist):
        if not grouplist.contains(self._basegroup):
            return None
        return RulePiece2Zext(self._basegroup)

    def getOpList(self) -> List[int]:
        return [int(OpCode.CPUI_PIECE)]

    def applyOp(self, op, data) -> int:
        constvn = op.getIn(0)  # Constant must be most significant bits
        if constvn is None or not constvn.isConstant():
            return 0
        if constvn.getOffset() != 0:
            return 0
        data.opRemoveInput(op, 0)
        data.opSetOpcode(op, OpCode.CPUI_INT_ZEXT)
        return 1


# =========================================================================
# RulePiece2Sext
# concat(V s>> #0x1f, V) => sext(V)
# =========================================================================

class RulePiece2Sext(Rule):
    """Concatenation with sign bits becomes extension: concat(V s>> #0x1f, V) => sext(V)"""

    def __init__(self, g: str) -> None:
        super().__init__(g, 0, "piece2sext")

    def clone(self, grouplist):
        if not grouplist.contains(self._basegroup):
            return None
        return RulePiece2Sext(self._basegroup)

    def getOpList(self) -> List[int]:
        return [int(OpCode.CPUI_PIECE)]

    def applyOp(self, op, data) -> int:
        shiftout = op.getIn(0)
        if shiftout is None or not shiftout.isWritten():
            return 0
        shiftop = shiftout.getDef()
        if shiftop.code() != OpCode.CPUI_INT_SRIGHT:
            return 0
        if not shiftop.getIn(1).isConstant():
            return 0
        n = shiftop.getIn(1).getOffset()
        x = shiftop.getIn(0)
        if x is not op.getIn(1):
            return 0
        if n != 8 * x.getSize() - 1:
            return 0
        data.opRemoveInput(op, 0)
        data.opSetOpcode(op, OpCode.CPUI_INT_SEXT)
        return 1


# =========================================================================
# RuleBxor2NotEqual
# V ^^ W => V != W
# =========================================================================

class RuleBxor2NotEqual(Rule):
    """Eliminate BOOL_XOR: V ^^ W => V != W"""

    def __init__(self, g: str) -> None:
        super().__init__(g, 0, "bxor2notequal")

    def clone(self, grouplist):
        if not grouplist.contains(self._basegroup):
            return None
        return RuleBxor2NotEqual(self._basegroup)

    def getOpList(self) -> List[int]:
        return [int(OpCode.CPUI_BOOL_XOR)]

    def applyOp(self, op, data) -> int:
        data.opSetOpcode(op, OpCode.CPUI_INT_NOTEQUAL)
        return 1


# =========================================================================
# RuleOrMask
# V = W | 0xffff => V = 0xffff  (full mask)
# =========================================================================

class RuleOrMask(Rule):
    """Simplify INT_OR with full mask: V = W | 0xffff => V = 0xffff"""

    def __init__(self, g: str) -> None:
        super().__init__(g, 0, "ormask")

    def clone(self, grouplist):
        if not grouplist.contains(self._basegroup):
            return None
        return RuleOrMask(self._basegroup)

    def getOpList(self) -> List[int]:
        return [int(OpCode.CPUI_INT_OR)]

    def applyOp(self, op, data) -> int:
        if op.getOut() is None:
            return 0
        size = op.getOut().getSize()
        if size > 8:
            return 0
        constvn = op.getIn(1)
        if constvn is None or not constvn.isConstant():
            return 0
        val = constvn.getOffset()
        mask = calc_mask(size)
        if (val & mask) != mask:
            return 0
        data.opSetOpcode(op, OpCode.CPUI_COPY)
        data.opSetInput(op, constvn, 0)
        data.opRemoveInput(op, 1)
        return 1


# =========================================================================
# RuleAndMask
# Collapse unnecessary INT_AND
# =========================================================================

class RuleAndMask(Rule):
    """Collapse unnecessary INT_AND."""

    def __init__(self, g: str) -> None:
        super().__init__(g, 0, "andmask")

    def clone(self, grouplist):
        if not grouplist.contains(self._basegroup):
            return None
        return RuleAndMask(self._basegroup)

    def getOpList(self) -> List[int]:
        return [int(OpCode.CPUI_INT_AND)]

    def applyOp(self, op, data) -> int:
        outvn = op.getOut()
        if outvn is None:
            return 0
        size = outvn.getSize()
        if size > 8:
            return 0
        mask1 = op.getIn(0).getNZMask()
        if mask1 == 0:
            andmask = 0
        else:
            mask2 = op.getIn(1).getNZMask()
            andmask = mask1 & mask2

        if andmask == 0:
            vn = data.newConstant(size, 0)
        elif (andmask & outvn.getConsume()) == 0:
            vn = data.newConstant(size, 0)
        elif andmask == mask1:
            if not op.getIn(1).isConstant():
                return 0
            vn = op.getIn(0)
        else:
            return 0
        if not vn.isHeritageKnown():
            return 0
        data.opSetOpcode(op, OpCode.CPUI_COPY)
        data.opRemoveInput(op, 1)
        data.opSetInput(op, vn, 0)
        return 1


# =========================================================================
# RuleOrCollapse
# V | c => c  if NZM(V) | c == c
# =========================================================================

class RuleOrCollapse(Rule):
    """Collapse unnecessary INT_OR: Replace V | c with c, if NZM(V) | c == c."""

    def __init__(self, g: str) -> None:
        super().__init__(g, 0, "orcollapse")

    def clone(self, grouplist):
        if not grouplist.contains(self._basegroup):
            return None
        return RuleOrCollapse(self._basegroup)

    def getOpList(self) -> List[int]:
        return [int(OpCode.CPUI_INT_OR)]

    def applyOp(self, op, data) -> int:
        outvn = op.getOut()
        if outvn is None:
            return 0
        size = outvn.getSize()
        vn = op.getIn(1)
        if vn is None or not vn.isConstant():
            return 0
        if size > 8:
            return 0
        mask = op.getIn(0).getNZMask()
        val = vn.getOffset()
        if (mask | val) != val:
            return 0
        data.opSetOpcode(op, OpCode.CPUI_COPY)
        data.opRemoveInput(op, 0)
        return 1


# =========================================================================
# RuleAndOrLump
# (V & c) & d => V & (c & d)    (also OR, XOR)
# =========================================================================

class RuleAndOrLump(Rule):
    """Collapse constants in logical expressions: (V & c) & d => V & (c & d)"""

    def __init__(self, g: str) -> None:
        super().__init__(g, 0, "andorlump")

    def clone(self, grouplist):
        if not grouplist.contains(self._basegroup):
            return None
        return RuleAndOrLump(self._basegroup)

    def getOpList(self) -> List[int]:
        return [int(OpCode.CPUI_INT_AND), int(OpCode.CPUI_INT_OR), int(OpCode.CPUI_INT_XOR)]

    def applyOp(self, op, data) -> int:
        opc = op.code()
        if not op.getIn(1).isConstant():
            return 0
        vn1 = op.getIn(0)
        if not vn1.isWritten():
            return 0
        op2 = vn1.getDef()
        if op2.code() != opc:
            return 0
        if not op2.getIn(1).isConstant():
            return 0
        basevn = op2.getIn(0)
        if basevn.isFree():
            return 0

        val = op.getIn(1).getOffset()
        val2 = op2.getIn(1).getOffset()
        if opc == OpCode.CPUI_INT_AND:
            val = val & val2
        elif opc == OpCode.CPUI_INT_OR:
            val = val | val2
        elif opc == OpCode.CPUI_INT_XOR:
            val = val ^ val2

        data.opSetInput(op, basevn, 0)
        data.opSetInput(op, data.newConstant(basevn.getSize(), val), 1)
        return 1


# =========================================================================
# RuleNegateIdentity
# V & ~V => #0,  V | ~V => #-1
# =========================================================================

class RuleNegateIdentity(Rule):
    """Apply INT_NEGATE identities: V & ~V => #0, V | ~V => #-1"""

    def __init__(self, g: str) -> None:
        super().__init__(g, 0, "negateidentity")

    def clone(self, grouplist):
        if not grouplist.contains(self._basegroup):
            return None
        return RuleNegateIdentity(self._basegroup)

    def getOpList(self) -> List[int]:
        return [int(OpCode.CPUI_INT_NEGATE)]

    def applyOp(self, op, data) -> int:
        vn = op.getIn(0)
        outVn = op.getOut()
        if outVn is None:
            return 0
        for logicOp in outVn.getDescendants():
            opc = logicOp.code()
            if opc not in (OpCode.CPUI_INT_AND, OpCode.CPUI_INT_OR, OpCode.CPUI_INT_XOR):
                continue
            slot = logicOp.getSlot(outVn)
            if logicOp.getIn(1 - slot) is not vn:
                continue
            value = 0
            if opc != OpCode.CPUI_INT_AND:
                value = calc_mask(vn.getSize())
            data.opSetInput(logicOp, data.newConstant(vn.getSize(), value), 0)
            data.opRemoveInput(logicOp, 1)
            data.opSetOpcode(logicOp, OpCode.CPUI_COPY)
            return 1
        return 0


# =========================================================================
# RuleOrConsume
# V = A | B => V = B  if nzm(A) & consume(V) == 0
# =========================================================================

class RuleOrConsume(Rule):
    """Simplify OR with unconsumed input."""

    def __init__(self, g: str) -> None:
        super().__init__(g, 0, "orconsume")

    def clone(self, grouplist):
        if not grouplist.contains(self._basegroup):
            return None
        return RuleOrConsume(self._basegroup)

    def getOpList(self) -> List[int]:
        return [int(OpCode.CPUI_INT_OR), int(OpCode.CPUI_INT_XOR)]

    def applyOp(self, op, data) -> int:
        outvn = op.getOut()
        if outvn is None:
            return 0
        size = outvn.getSize()
        if size > 8:
            return 0
        consume = outvn.getConsume()
        if (consume & op.getIn(0).getNZMask()) == 0:
            data.opRemoveInput(op, 0)
            data.opSetOpcode(op, OpCode.CPUI_COPY)
            return 1
        elif (consume & op.getIn(1).getNZMask()) == 0:
            data.opRemoveInput(op, 1)
            data.opSetOpcode(op, OpCode.CPUI_COPY)
            return 1
        return 0


# =========================================================================
# RuleTrivialArith
# V + 0 => V, V * 1 => V, V ^ 0 => V, V & -1 => V, V | 0 => V, etc.
# =========================================================================

class RuleTrivialArith(Rule):
    """Simplify ops with identical inputs, matching native RuleTrivialArith."""

    def __init__(self, g: str) -> None:
        super().__init__(g, 0, "trivialarith")

    def clone(self, grouplist):
        if not grouplist.contains(self._basegroup):
            return None
        return RuleTrivialArith(self._basegroup)

    def getOpList(self) -> List[int]:
        return [
            int(OpCode.CPUI_INT_NOTEQUAL), int(OpCode.CPUI_INT_SLESS), int(OpCode.CPUI_INT_LESS),
            int(OpCode.CPUI_BOOL_XOR), int(OpCode.CPUI_BOOL_AND), int(OpCode.CPUI_BOOL_OR),
            int(OpCode.CPUI_INT_EQUAL), int(OpCode.CPUI_INT_SLESSEQUAL), int(OpCode.CPUI_INT_LESSEQUAL),
            int(OpCode.CPUI_INT_XOR), int(OpCode.CPUI_INT_AND), int(OpCode.CPUI_INT_OR),
            int(OpCode.CPUI_FLOAT_EQUAL), int(OpCode.CPUI_FLOAT_NOTEQUAL),
            int(OpCode.CPUI_FLOAT_LESS), int(OpCode.CPUI_FLOAT_LESSEQUAL),
        ]

    def applyOp(self, op, data) -> int:
        if op.numInput() != 2:
            return 0
        in0 = op.getIn(0)
        in1 = op.getIn(1)
        if in0 is None or in1 is None:
            return 0
        if in0 is not in1:
            if not in0.isWritten() or not in1.isWritten():
                return 0
            def0 = in0.getDef()
            def1 = in1.getDef()
            if def0 is None or def1 is None or not def0.isCseMatch(def1):
                return 0

        outvn = op.getOut()
        if outvn is None:
            return 0

        opc = op.code()
        new_vn = None
        if opc in (
            OpCode.CPUI_INT_NOTEQUAL,
            OpCode.CPUI_INT_SLESS,
            OpCode.CPUI_INT_LESS,
            OpCode.CPUI_BOOL_XOR,
            OpCode.CPUI_FLOAT_NOTEQUAL,
            OpCode.CPUI_FLOAT_LESS,
        ):
            new_vn = data.newConstant(1, 0)
        elif opc in (
            OpCode.CPUI_INT_EQUAL,
            OpCode.CPUI_INT_SLESSEQUAL,
            OpCode.CPUI_INT_LESSEQUAL,
            OpCode.CPUI_FLOAT_EQUAL,
            OpCode.CPUI_FLOAT_LESSEQUAL,
        ):
            new_vn = data.newConstant(1, 1)
        elif opc == OpCode.CPUI_INT_XOR:
            new_vn = data.newConstant(outvn.getSize(), 0)
        elif opc not in (
            OpCode.CPUI_BOOL_AND,
            OpCode.CPUI_BOOL_OR,
            OpCode.CPUI_INT_AND,
            OpCode.CPUI_INT_OR,
        ):
            return 0

        data.opSetOpcode(op, OpCode.CPUI_COPY)
        data.opRemoveInput(op, 1)
        if new_vn is not None:
            data.opSetInput(op, new_vn, 0)
        return 1


# =========================================================================
# RuleDoubleSub
# SUBPIECE(SUBPIECE(V, c1), c2) => SUBPIECE(V, c1+c2)
# =========================================================================

class RuleDoubleSub(Rule):
    """Collapse nested SUBPIECE: SUBPIECE(SUBPIECE(V,c1),c2) => SUBPIECE(V,c1+c2)"""

    def __init__(self, g: str) -> None:
        super().__init__(g, 0, "doublesub")

    def clone(self, grouplist):
        if not grouplist.contains(self._basegroup):
            return None
        return RuleDoubleSub(self._basegroup)

    def getOpList(self) -> List[int]:
        return [int(OpCode.CPUI_SUBPIECE)]

    def applyOp(self, op, data) -> int:
        vn = op.getIn(0)
        if not vn.isWritten():
            return 0
        op2 = vn.getDef()
        if op2.code() != OpCode.CPUI_SUBPIECE:
            return 0
        c1 = op2.getIn(1).getOffset()
        c2 = op.getIn(1).getOffset()
        basevn = op2.getIn(0)
        if basevn.isFree():
            return 0
        data.opSetInput(op, basevn, 0)
        data.opSetInput(op, data.newConstant(op.getIn(1).getSize(), c1 + c2), 1)
        return 1


# =========================================================================
# RuleDoubleShift
# (V << c1) << c2 => V << (c1+c2)  or  (V >> c1) >> c2 => V >> (c1+c2)
# =========================================================================

class RuleDoubleShift(Rule):
    """Collapse double shifts: (V << c1) << c2 => V << (c1+c2)"""

    def __init__(self, g: str) -> None:
        super().__init__(g, 0, "doubleshift")

    def clone(self, grouplist):
        if not grouplist.contains(self._basegroup):
            return None
        return RuleDoubleShift(self._basegroup)

    def getOpList(self) -> List[int]:
        return [int(OpCode.CPUI_INT_LEFT), int(OpCode.CPUI_INT_RIGHT)]

    def applyOp(self, op, data) -> int:
        opc = op.code()
        outvn = op.getOut()
        if outvn is None:
            return 0
        if not op.getIn(1).isConstant():
            return 0
        vn = op.getIn(0)
        if not vn.isWritten():
            return 0
        op2 = vn.getDef()
        if op2.code() != opc:
            return 0
        if not op2.getIn(1).isConstant():
            return 0
        c1 = op2.getIn(1).getOffset()
        c2 = op.getIn(1).getOffset()
        basevn = op2.getIn(0)
        if basevn.isFree():
            return 0
        total = c1 + c2
        size_bits = outvn.getSize() * 8
        if total >= size_bits:
            # Shift eliminates all bits
            data.opSetOpcode(op, OpCode.CPUI_COPY)
            data.opSetInput(op, data.newConstant(outvn.getSize(), 0), 0)
            data.opRemoveInput(op, 1)
            return 1
        data.opSetInput(op, basevn, 0)
        data.opSetInput(op, data.newConstant(op.getIn(1).getSize(), total), 1)
        return 1


# =========================================================================
# Collect all rules into a list for registration
# =========================================================================

# =========================================================================
# RuleCollapseConstants
# Fold constant expressions: op(c1, c2) => COPY(result)
# =========================================================================

class RuleCollapseConstants(Rule):
    """Collapse constant expressions: op(c1, c2) => COPY(result)"""

    def __init__(self, g: str) -> None:
        super().__init__(g, 0, "collapseconstants")

    def clone(self, grouplist):
        if not grouplist.contains(self._basegroup):
            return None
        return RuleCollapseConstants(self._basegroup)

    # Applies to all opcodes (no getOpList)

    _VN_CONST = 0x02  # Varnode.constant

    def applyOp(self, op, data) -> int:
        out = op._output
        if out is None or not op.isCollapsible():
            return 0
        opc = op._opcode_enum
        # Skip ops that must not be constant-folded (matches the current stable behavior)
        if opc in (1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 60, 61, 62, 63, 64, 65, 66, 67, 68):
            return 0
        # Need all constant inputs for binary/unary ops
        inrefs = op._inrefs
        numinput = len(inrefs)
        if numinput == 0:
            return 0
        _VC = self._VN_CONST
        # Check all inputs are constant
        for inv in inrefs:
            if inv is None or not (inv._flags & _VC):
                return 0
        marked_input = [False]
        try:
            sizeout = out._size
            result = op.collapse(marked_input)
        except LowlevelError:
            data.opMarkNoCollapse(op)
            return 0
        result &= calc_mask(sizeout)
        newvn = data.newConstant(sizeout, result)
        if marked_input[0]:
            op.collapseConstantSymbol(newvn)
        for i in range(numinput - 1, 0, -1):
            data.opRemoveInput(op, i)
        data.opSetInput(op, newvn, 0)
        data.opSetOpcode(op, OpCode.CPUI_COPY)
        return 1


# =========================================================================
# RulePropagateCopy
# Propagate COPY inputs through the data-flow
# =========================================================================

class RulePropagateCopy(Rule):
    """Propagate the input of a COPY to all the places that read the output."""

    def __init__(self, g: str) -> None:
        super().__init__(g, 0, "propagatecopy")

    def clone(self, grouplist):
        if not grouplist.contains(self._basegroup):
            return None
        return RulePropagateCopy(self._basegroup)

    # Applies to all opcodes (no getOpList)

    def applyOp(self, op, data) -> int:
        if op.isReturnCopy():
            return 0
        op_is_marker = op._flags & _OP_MARKER_FL
        op_out = op.getOut()
        for i, vn in enumerate(op._inrefs):
            if vn is None or not (vn._flags & _VN_WRITTEN):
                continue
            copyop = vn._def
            if copyop._opcode_enum != _CPUI_COPY:
                continue
            invn = copyop._inrefs[0] if copyop._inrefs else None
            if invn is None:
                continue
            if not (invn._flags & _VN_HK):  # isHeritageKnown
                continue
            if invn is vn:
                continue  # Self-defined
            if op_is_marker:
                if invn._flags & _VN_CONST:
                    continue
                if vn._flags & _VN_ADDRFORCE:
                    continue
                if (
                    op_out is not None
                    and (invn._flags & _VN_ADDRTIED)
                    and (op_out._flags & _VN_ADDRTIED)
                    and invn.getAddr() != op_out.getAddr()
                ):
                    continue
            data.opSetInput(op, invn, i)
            return 1
        return 0


# =========================================================================
# Rule2Comp2Mult
# -V => V * -1
# =========================================================================

class Rule2Comp2Mult(Rule):
    """Eliminate INT_2COMP: -V => V * -1"""

    def __init__(self, g: str) -> None:
        super().__init__(g, 0, "2comp2mult")

    def clone(self, grouplist):
        if not grouplist.contains(self._basegroup):
            return None
        return Rule2Comp2Mult(self._basegroup)

    def getOpList(self) -> List[int]:
        return [int(OpCode.CPUI_INT_2COMP)]

    def applyOp(self, op, data) -> int:
        data.opSetOpcode(op, OpCode.CPUI_INT_MULT)
        size = op.getIn(0).getSize()
        negone = data.newConstant(size, calc_mask(size))
        data.opInsertInput(op, negone, 1)
        return 1


# =========================================================================
# RuleSub2Add
# V - W => V + (-W) when W is constant
# =========================================================================

class RuleSub2Add(Rule):
    """Convert subtraction into addition via an explicit multiply-by-minus-one.

    Native Ghidra does not directly negate the constant operand in-place.
    It materializes ``vn * -1`` as a temporary op, rewires the subtraction to
    consume that temporary, then converts the opcode to ``INT_ADD``. The
    temporary immediately feeds the native ``collapseconstants ->
    propagatecopy -> earlyremoval`` chain, which affects action trace counts.
    """

    def __init__(self, g: str) -> None:
        super().__init__(g, 0, "sub2add")

    def clone(self, grouplist):
        if not grouplist.contains(self._basegroup):
            return None
        return RuleSub2Add(self._basegroup)

    def getOpList(self) -> List[int]:
        return [int(OpCode.CPUI_INT_SUB)]

    def applyOp(self, op, data) -> int:
        vn = op.getIn(1)
        if vn is None:
            return 0
        newop = data.newOp(2, op.getAddr())
        data.opSetOpcode(newop, OpCode.CPUI_INT_MULT)
        newvn = data.newUniqueOut(vn.getSize(), newop)
        data.opSetInput(op, newvn, 1)
        data.opSetInput(newop, vn, 0)
        data.opSetInput(newop, data.newConstant(vn.getSize(), calc_mask(vn.getSize())), 1)
        data.opSetOpcode(op, OpCode.CPUI_INT_ADD)
        data.opInsertBefore(newop, op)
        return 1


# =========================================================================
# RuleXorCollapse
# V ^ V => 0
# =========================================================================

class RuleXorCollapse(Rule):
    """Collapse XOR with self: V ^ V => 0"""

    def __init__(self, g: str) -> None:
        super().__init__(g, 0, "xorcollapse")

    def clone(self, grouplist):
        if not grouplist.contains(self._basegroup):
            return None
        return RuleXorCollapse(self._basegroup)

    def getOpList(self) -> List[int]:
        return [int(OpCode.CPUI_INT_XOR)]

    def applyOp(self, op, data) -> int:
        if op.getIn(0) is not op.getIn(1):
            return 0
        outvn = op.getOut()
        if outvn is None:
            return 0
        size = outvn.getSize()
        data.opSetOpcode(op, OpCode.CPUI_COPY)
        data.opSetInput(op, data.newConstant(size, 0), 0)
        data.opRemoveInput(op, 1)
        return 1


# =========================================================================
# RuleZextEliminate
# ZEXT(V) where V is already small enough => COPY(V)
# =========================================================================

class RuleZextEliminate(Rule):
    """Eliminate unnecessary ZEXT when the value already fits."""

    def __init__(self, g: str) -> None:
        super().__init__(g, 0, "zexteliminate")

    def clone(self, grouplist):
        if not grouplist.contains(self._basegroup):
            return None
        return RuleZextEliminate(self._basegroup)

    def getOpList(self) -> List[int]:
        return [int(OpCode.CPUI_INT_ZEXT)]

    def applyOp(self, op, data) -> int:
        vn = op.getIn(0)
        if vn is None:
            return 0
        outvn = op.getOut()
        if outvn is None:
            return 0
        if vn.getSize() >= outvn.getSize():
            data.opSetOpcode(op, OpCode.CPUI_COPY)
            return 1
        # Check if NZ mask fits in smaller size
        nzm = vn.getNZMask()
        if nzm == (nzm & calc_mask(vn.getSize())):
            # Already zero extended naturally
            pass
        return 0


# =========================================================================
# RuleShift2Mult
# V << c => V * (1 << c)
# =========================================================================

class RuleShift2Mult(Rule):
    """Convert left shift by constant to multiply: V << c => V * (1 << c)"""

    def __init__(self, g: str) -> None:
        super().__init__(g, 0, "shift2mult")

    def clone(self, grouplist):
        if not grouplist.contains(self._basegroup):
            return None
        return RuleShift2Mult(self._basegroup)

    def getOpList(self) -> List[int]:
        return [int(OpCode.CPUI_INT_LEFT)]

    def applyOp(self, op, data) -> int:
        outvn = op.getOut()
        if outvn is None:
            return 0
        constvn = op.getIn(1)
        if constvn is None or not constvn.isConstant():
            return 0
        sa = constvn.getOffset()
        if sa >= 32:
            return 0

        # Native only rewrites the shift if the value is participating in an
        # arithmetic expression, either via its defining input or a descendant.
        arithmetic_use = False
        in0 = op.getIn(0)
        arithop = in0.getDef() if in0 is not None and in0.isWritten() else None
        descendants = outvn.getDescendants() if hasattr(outvn, "getDescendants") else []
        for desc in [arithop, *descendants]:
            if desc is None:
                continue
            if desc.code() in (OpCode.CPUI_INT_ADD, OpCode.CPUI_INT_SUB, OpCode.CPUI_INT_MULT):
                arithmetic_use = True
                break
        if not arithmetic_use:
            return 0

        mult_val = 1 << sa
        data.opSetOpcode(op, OpCode.CPUI_INT_MULT)
        data.opSetInput(op, data.newConstant(outvn.getSize(), mult_val), 1)
        return 1


# =========================================================================
# Collect all rules
# =========================================================================

# =========================================================================
# RuleRightShiftAnd
# (V & 0xf000) >> 24 => V >> 24
# =========================================================================

class RuleRightShiftAnd(Rule):
    """Simplify right shift where AND mask becomes unnecessary after shift."""

    def __init__(self, g: str) -> None:
        super().__init__(g, 0, "rightshiftand")

    def clone(self, grouplist):
        if not grouplist.contains(self._basegroup): return None
        return RuleRightShiftAnd(self._basegroup)

    def getOpList(self) -> List[int]:
        return [int(OpCode.CPUI_INT_RIGHT), int(OpCode.CPUI_INT_SRIGHT)]

    def applyOp(self, op, data) -> int:
        constVn = op.getIn(1)
        if not constVn.isConstant(): return 0
        inVn = op.getIn(0)
        if not inVn.isWritten(): return 0
        andOp = inVn.getDef()
        if andOp.code() != OpCode.CPUI_INT_AND: return 0
        maskVn = andOp.getIn(1)
        if not maskVn.isConstant(): return 0
        sa = constVn.getOffset()
        mask = maskVn.getOffset() >> sa
        rootVn = andOp.getIn(0)
        full = calc_mask(rootVn.getSize()) >> sa
        if full != mask: return 0
        if rootVn.isFree(): return 0
        data.opSetInput(op, rootVn, 0)
        return 1


# =========================================================================
# RuleTermOrder
# Reorder commutative ops so constants come last
# =========================================================================

class RuleTermOrder(Rule):
    """Order the inputs to commutative operations: constants always come last."""

    def __init__(self, g: str) -> None:
        super().__init__(g, 0, "termorder")

    def clone(self, grouplist):
        if not grouplist.contains(self._basegroup): return None
        return RuleTermOrder(self._basegroup)

    def getOpList(self) -> List[int]:
        return [
            int(OpCode.CPUI_INT_EQUAL), int(OpCode.CPUI_INT_NOTEQUAL),
            int(OpCode.CPUI_INT_ADD), int(OpCode.CPUI_INT_CARRY),
            int(OpCode.CPUI_INT_SCARRY), int(OpCode.CPUI_INT_XOR),
            int(OpCode.CPUI_INT_AND), int(OpCode.CPUI_INT_OR),
            int(OpCode.CPUI_INT_MULT), int(OpCode.CPUI_BOOL_XOR),
            int(OpCode.CPUI_BOOL_AND), int(OpCode.CPUI_BOOL_OR),
            int(OpCode.CPUI_FLOAT_EQUAL), int(OpCode.CPUI_FLOAT_NOTEQUAL),
            int(OpCode.CPUI_FLOAT_ADD), int(OpCode.CPUI_FLOAT_MULT),
        ]

    def applyOp(self, op, data) -> int:
        vn1 = op.getIn(0)
        vn2 = op.getIn(1)
        if vn1.isConstant() and not vn2.isConstant():
            # Swap inputs
            data.opSetInput(op, vn2, 0)
            data.opSetInput(op, vn1, 1)
            return 1
        return 0


# =========================================================================
# RuleTrivialBool
# CBRANCH with constant condition => BRANCH or NOP
# =========================================================================

class RuleTrivialBool(Rule):
    """Simplify CBRANCH with constant boolean: always-true or always-false."""

    def __init__(self, g: str) -> None:
        super().__init__(g, 0, "trivialbool")

    def clone(self, grouplist):
        if not grouplist.contains(self._basegroup): return None
        return RuleTrivialBool(self._basegroup)

    def getOpList(self) -> List[int]:
        return [int(OpCode.CPUI_CBRANCH)]

    def applyOp(self, op, data) -> int:
        boolVn = op.getIn(1)
        if boolVn is None or not boolVn.isConstant(): return 0
        val = boolVn.getOffset()
        if op.isBooleanFlip():
            val = 1 - val
        if val != 0:
            # Always taken: convert to unconditional BRANCH
            data.opSetOpcode(op, OpCode.CPUI_BRANCH)
            data.opRemoveInput(op, 1)
        else:
            # Never taken: remove the branch
            data.opDestroy(op)
        return 1


# =========================================================================
# RuleIdentityEl
# V + 0 => V, V * 1 => V, V & -1 => V, V | 0 => V, V ^ 0 => V
# (input 0 is identity element)
# =========================================================================

class RuleIdentityEl(Rule):
    """Eliminate identity elements: V op identity => V."""

    def __init__(self, g: str) -> None:
        super().__init__(g, 0, "identityel")

    def clone(self, grouplist):
        if not grouplist.contains(self._basegroup): return None
        return RuleIdentityEl(self._basegroup)

    def getOpList(self) -> List[int]:
        return [
            int(OpCode.CPUI_INT_ADD), int(OpCode.CPUI_INT_SUB),
            int(OpCode.CPUI_INT_XOR), int(OpCode.CPUI_INT_OR),
            int(OpCode.CPUI_INT_AND), int(OpCode.CPUI_INT_MULT),
        ]

    def applyOp(self, op, data) -> int:
        opc = op.code()
        outvn = op.getOut()
        if outvn is None:
            return 0
        # Check if input 0 is the identity element (after TermOrder, constants are in slot 1)
        # But we also need to check slot 0 in case TermOrder hasn't run
        for slot in [0, 1]:
            vn = op.getIn(slot)
            if vn is None or not vn.isConstant(): continue
            val = vn.getOffset()
            size = outvn.getSize()
            mask = calc_mask(size)
            is_identity = False
            if opc in (OpCode.CPUI_INT_ADD, OpCode.CPUI_INT_SUB, OpCode.CPUI_INT_XOR, OpCode.CPUI_INT_OR):
                is_identity = (val == 0)
            elif opc == OpCode.CPUI_INT_AND:
                is_identity = ((val & mask) == mask)
            elif opc == OpCode.CPUI_INT_MULT:
                is_identity = (val == 1)
            if is_identity:
                if opc == OpCode.CPUI_INT_SUB and slot == 0:
                    continue  # 0 - V is not identity
                other = op.getIn(1 - slot)
                data.opSetOpcode(op, OpCode.CPUI_COPY)
                data.opSetInput(op, other, 0)
                data.opRemoveInput(op, 1)
                return 1
        return 0


# =========================================================================
# RuleCarryElim
# carry(V, 0) => false
# =========================================================================

class RuleCarryElim(Rule):
    """Transform carry with zero: carry(V, 0) => false."""

    def __init__(self, g: str) -> None:
        super().__init__(g, 0, "carryelim")

    def clone(self, grouplist):
        if not grouplist.contains(self._basegroup): return None
        return RuleCarryElim(self._basegroup)

    def getOpList(self) -> List[int]:
        return [int(OpCode.CPUI_INT_CARRY)]

    def applyOp(self, op, data) -> int:
        vn2 = op.getIn(1)
        if not vn2.isConstant(): return 0
        if vn2.getOffset() != 0: return 0
        # carry(V, 0) => false
        data.opRemoveInput(op, 1)
        data.opSetInput(op, data.newConstant(1, 0), 0)
        data.opSetOpcode(op, OpCode.CPUI_COPY)
        return 1


# =========================================================================
# RuleSborrow
# sborrow(V, 0) => false
# =========================================================================

class RuleSborrow(Rule):
    """Transform sborrow with zero: sborrow(V, 0) => false."""

    def __init__(self, g: str) -> None:
        super().__init__(g, 0, "sborrow")

    def clone(self, grouplist):
        if not grouplist.contains(self._basegroup): return None
        return RuleSborrow(self._basegroup)

    def getOpList(self) -> List[int]:
        return [int(OpCode.CPUI_INT_SBORROW)]

    def applyOp(self, op, data) -> int:
        vn2 = op.getIn(1)
        if not vn2.isConstant(): return 0
        if vn2.getOffset() != 0: return 0
        data.opRemoveInput(op, 1)
        data.opSetInput(op, data.newConstant(1, 0), 0)
        data.opSetOpcode(op, OpCode.CPUI_COPY)
        return 1


# =========================================================================
# RuleScarry
# scarry(V, 0) => false
# =========================================================================

class RuleScarry(Rule):
    """Transform scarry with zero: scarry(V, 0) => false."""

    def __init__(self, g: str) -> None:
        super().__init__(g, 0, "scarry")

    def clone(self, grouplist):
        if not grouplist.contains(self._basegroup): return None
        return RuleScarry(self._basegroup)

    def getOpList(self) -> List[int]:
        return [int(OpCode.CPUI_INT_SCARRY)]

    def applyOp(self, op, data) -> int:
        vn2 = op.getIn(1)
        if not vn2.isConstant(): return 0
        if vn2.getOffset() != 0: return 0
        data.opRemoveInput(op, 1)
        data.opSetInput(op, data.newConstant(1, 0), 0)
        data.opSetOpcode(op, OpCode.CPUI_COPY)
        return 1


# =========================================================================
# RuleBooleanNegate
# V == false => !V, V == true => V, and NOTEQUAL variants.
# =========================================================================

class RuleBooleanNegate(Rule):
    """Simplify equality/inequality tests against boolean values."""

    def __init__(self, g: str) -> None:
        super().__init__(g, 0, "booleannegate")

    def clone(self, grouplist):
        if not grouplist.contains(self._basegroup): return None
        return RuleBooleanNegate(self._basegroup)

    def getOpList(self) -> List[int]:
        return [int(OpCode.CPUI_INT_NOTEQUAL), int(OpCode.CPUI_INT_EQUAL)]

    def applyOp(self, op, data) -> int:
        opc = op.code()
        constvn = op.getIn(1)
        subbool = op.getIn(0)
        if not constvn.isConstant():
            return 0
        val = constvn.getOffset()
        if val not in (0, 1):
            return 0
        negate = (opc == OpCode.CPUI_INT_NOTEQUAL)
        if val == 0:
            negate = not negate
        if not subbool.isBooleanValue(data.isTypeRecoveryOn()):
            return 0

        data.opRemoveInput(op, 1)
        data.opSetInput(op, subbool, 0)
        if negate:
            data.opSetOpcode(op, OpCode.CPUI_BOOL_NEGATE)
        else:
            data.opSetOpcode(op, OpCode.CPUI_COPY)
        return 1


# =========================================================================
# RuleNotDistribute
# ~(V & W) => ~V | ~W,  ~(V | W) => ~V & ~W  (DeMorgan)
# =========================================================================

class RuleNotDistribute(Rule):
    """Apply DeMorgan's law: ~(V & W) => ~V | ~W."""

    def __init__(self, g: str) -> None:
        super().__init__(g, 0, "notdistribute")

    def clone(self, grouplist):
        if not grouplist.contains(self._basegroup): return None
        return RuleNotDistribute(self._basegroup)

    def getOpList(self) -> List[int]:
        return [int(OpCode.CPUI_INT_NEGATE)]

    def applyOp(self, op, data) -> int:
        compop = op.getIn(0).getDef()
        if compop is None:
            return 0
        opc_in = compop.code()
        if opc_in == OpCode.CPUI_BOOL_AND:
            opc = OpCode.CPUI_BOOL_OR
        elif opc_in == OpCode.CPUI_BOOL_OR:
            opc = OpCode.CPUI_BOOL_AND
        else:
            return 0

        newneg1 = data.newOp(1, op.getAddr())
        newout1 = data.newUniqueOut(1, newneg1)
        data.opSetOpcode(newneg1, OpCode.CPUI_BOOL_NEGATE)
        data.opSetInput(newneg1, compop.getIn(0), 0)
        data.opInsertBefore(newneg1, op)

        newneg2 = data.newOp(1, op.getAddr())
        newout2 = data.newUniqueOut(1, newneg2)
        data.opSetOpcode(newneg2, OpCode.CPUI_BOOL_NEGATE)
        data.opSetInput(newneg2, compop.getIn(1), 0)
        data.opInsertBefore(newneg2, op)

        data.opSetOpcode(op, opc)
        data.opSetInput(op, newout1, 0)
        data.opInsertInput(op, newout2, 1)
        return 1


# =========================================================================
# RuleLogic2Bool
# INT_AND/OR/XOR on booleans => BOOL_AND/OR/XOR
# =========================================================================

class RuleLogic2Bool(Rule):
    """Convert integer logic ops on booleans to boolean ops."""

    def __init__(self, g: str) -> None:
        super().__init__(g, 0, "logic2bool")

    def clone(self, grouplist):
        if not grouplist.contains(self._basegroup): return None
        return RuleLogic2Bool(self._basegroup)

    def getOpList(self) -> List[int]:
        return [int(OpCode.CPUI_INT_AND), int(OpCode.CPUI_INT_OR), int(OpCode.CPUI_INT_XOR)]

    def applyOp(self, op, data) -> int:
        outvn = op.getOut()
        if outvn is None or outvn.getSize() != 1: return 0
        # Check if both inputs produce boolean (1-bit) values
        in0 = op.getIn(0)
        in1 = op.getIn(1)
        if in0 is None or in1 is None: return 0
        # Check NZMask: if both inputs have NZM <= 1, they're boolean
        if (in0.getNZMask() > 1) or (in1.getNZMask() > 1): return 0
        opc = op.code()
        if opc == OpCode.CPUI_INT_AND:
            data.opSetOpcode(op, OpCode.CPUI_BOOL_AND)
        elif opc == OpCode.CPUI_INT_OR:
            data.opSetOpcode(op, OpCode.CPUI_BOOL_OR)
        elif opc == OpCode.CPUI_INT_XOR:
            data.opSetOpcode(op, OpCode.CPUI_BOOL_XOR)
        return 1


# =========================================================================
# RuleAddMultCollapse
# (V + c1) * c2  =>  V * c2 + (c1 * c2) when profitable
# =========================================================================

class RuleAddMultCollapse(Rule):
    """Collapse constants in an additive or multiplicative expression.

    Forms include:
      - ``((V + c) + d)  =>  V + (c+d)``
      - ``((V * c) * d)  =>  V * (c*d)``
      - ``((V + (W + c)) + d)  =>  (W + (c+d)) + V``  (spacebase case)

    C++ ref: ``RuleAddMultCollapse::applyOp`` (ruleaction.cc:4093-4162)
    """

    def __init__(self, g: str) -> None:
        super().__init__(g, 0, "addmultcollapse")

    def clone(self, grouplist):
        if not grouplist.contains(self._basegroup): return None
        return RuleAddMultCollapse(self._basegroup)

    def getOpList(self) -> List[int]:
        return [int(OpCode.CPUI_INT_ADD), int(OpCode.CPUI_INT_MULT)]

    def applyOp(self, op, data) -> int:
        opc = op.code()
        # c[0] is the constant at this level, sub is the other input
        c0 = op.getIn(1)
        if not c0.isConstant():
            return 0
        sub = op.getIn(0)
        if not sub.isWritten():
            return 0
        subop = sub.getDef()
        if subop.code() != opc:
            return 0  # Must be same exact operation
        c1 = subop.getIn(1)
        if not c1.isConstant():
            # Extended form: ((V + (W + c)) + d) => (W + (c+d)) + V
            # Only for INT_ADD with spacebase
            if opc != OpCode.CPUI_INT_ADD:
                return 0
            for i in range(2):
                othervn = subop.getIn(i)
                if othervn.isConstant():
                    continue
                if othervn.isFree():
                    continue
                sub2 = subop.getIn(1 - i)
                if not sub2.isWritten():
                    continue
                baseop = sub2.getDef()
                if baseop.code() != OpCode.CPUI_INT_ADD:
                    continue
                c1inner = baseop.getIn(1)
                if not c1inner.isConstant():
                    continue
                basevn = baseop.getIn(0)
                if not basevn.isSpacebase():
                    continue
                if not basevn.isInput():
                    continue
                # Fold the two constants
                sz = c0.getSize()
                val = (c0.getOffset() + c1inner.getOffset()) & calc_mask(sz)
                newvn = data.newConstant(sz, val)
                newop = data.newOp(2, op.getAddr())
                data.opSetOpcode(newop, OpCode.CPUI_INT_ADD)
                newout = data.newUniqueOut(sz, newop)
                data.opSetInput(newop, basevn, 0)
                data.opSetInput(newop, newvn, 1)
                data.opInsertBefore(newop, op)
                data.opSetInput(op, newout, 0)
                data.opSetInput(op, othervn, 1)
                return 1
            return 0
        # Simple form: ((V op c1) op c0) => V op (c0 op c1)
        sub2 = subop.getIn(0)
        if sub2.isFree():
            return 0
        sz = c0.getSize()
        if opc == OpCode.CPUI_INT_ADD:
            val = (c0.getOffset() + c1.getOffset()) & calc_mask(sz)
        else:  # CPUI_INT_MULT
            val = (c0.getOffset() * c1.getOffset()) & calc_mask(sz)
        newvn = data.newConstant(sz, val)
        data.opSetInput(op, newvn, 1)
        data.opSetInput(op, sub2, 0)
        return 1


# =========================================================================
# Collect all rules
# =========================================================================

# =========================================================================
# RuleLessOne
# V < 1 => V == 0,  V <= 0 => V == 0
# =========================================================================

class RuleLessOne(Rule):
    """Transform INT_LESS of 0 or 1: V < 1 => V == 0, V <= 0 => V == 0."""

    def __init__(self, g: str) -> None:
        super().__init__(g, 0, "lessone")

    def clone(self, grouplist):
        if not grouplist.contains(self._basegroup): return None
        return RuleLessOne(self._basegroup)

    def getOpList(self) -> List[int]:
        return [int(OpCode.CPUI_INT_LESS), int(OpCode.CPUI_INT_LESSEQUAL)]

    def applyOp(self, op, data) -> int:
        constvn = op.getIn(1)
        if not constvn.isConstant(): return 0
        val = constvn.getOffset()
        if op.code() == OpCode.CPUI_INT_LESS and val != 1: return 0
        if op.code() == OpCode.CPUI_INT_LESSEQUAL and val != 0: return 0
        data.opSetOpcode(op, OpCode.CPUI_INT_EQUAL)
        if val != 0:
            data.opSetInput(op, data.newConstant(constvn.getSize(), 0), 1)
        return 1


# =========================================================================
# RuleHighOrderAnd
# (V + c) & 0xfff0 => V + (c & 0xfff0) when V is aligned
# =========================================================================

class RuleHighOrderAnd(Rule):
    """Simplify INT_AND when applied to aligned INT_ADD."""

    def __init__(self, g: str) -> None:
        super().__init__(g, 0, "highorderand")

    def clone(self, grouplist):
        if not grouplist.contains(self._basegroup): return None
        return RuleHighOrderAnd(self._basegroup)

    def getOpList(self) -> List[int]:
        return [int(OpCode.CPUI_INT_AND)]

    def applyOp(self, op, data) -> int:
        cvn1 = op.getIn(1)
        if not cvn1.isConstant(): return 0
        in0 = op.getIn(0)
        if not in0.isWritten(): return 0
        addop = in0.getDef()
        if addop.code() != OpCode.CPUI_INT_ADD: return 0
        val = cvn1.getOffset()
        size = cvn1.getSize()
        # Check val is of form 11110000
        if ((val - 1) | val) != calc_mask(size): return 0
        cvn2 = addop.getIn(1)
        if cvn2.isConstant():
            xalign = addop.getIn(0)
            if xalign.isFree(): return 0
            mask1 = xalign.getNZMask()
            if (mask1 & val) != mask1: return 0
            data.opSetOpcode(op, OpCode.CPUI_INT_ADD)
            data.opSetInput(op, xalign, 0)
            data.opSetInput(op, data.newConstant(size, val & cvn2.getOffset()), 1)
            return 1
        else:
            if addop.getOut().loneDescend() is not op: return 0
            for i in range(2):
                zerovn = addop.getIn(i)
                mask2 = zerovn.getNZMask()
                if (mask2 & val) != mask2:
                    continue
                nonzerovn = addop.getIn(1 - i)
                if not nonzerovn.isWritten():
                    continue
                addop2 = nonzerovn.getDef()
                if addop2.code() != OpCode.CPUI_INT_ADD:
                    continue
                if nonzerovn.loneDescend() is not addop:
                    continue
                cvn2 = addop2.getIn(1)
                if not cvn2.isConstant():
                    continue
                xalign = addop2.getIn(0)
                mask2 = xalign.getNZMask()
                if (mask2 & val) != mask2:
                    continue
                data.opSetInput(addop2, data.newConstant(size, val & cvn2.getOffset()), 1)
                data.opRemoveInput(op, 1)
                data.opSetOpcode(op, OpCode.CPUI_COPY)
                return 1
        return 0


# =========================================================================
# RuleBoolZext
# zext(V) where V is boolean and result used as boolean => COPY(V)
# =========================================================================

class RuleBoolZext(Rule):
    """Simplify ZEXT of boolean value when used as boolean."""

    def __init__(self, g: str) -> None:
        super().__init__(g, 0, "boolzext")

    def clone(self, grouplist):
        if not grouplist.contains(self._basegroup): return None
        return RuleBoolZext(self._basegroup)

    def getOpList(self) -> List[int]:
        return [int(OpCode.CPUI_INT_ZEXT)]

    def applyOp(self, op, data) -> int:
        invn = op.getIn(0)
        if invn is None: return 0
        if invn.getSize() != 1: return 0
        outvn = op.getOut()
        if outvn is None: return 0
        # Check if output is only used in boolean context
        if outvn.getNZMask() > 1: return 0
        # All uses must treat it as boolean
        for desc in outvn.getDescendants():
            if not desc.isBoolOutput() and desc.code() != OpCode.CPUI_CBRANCH:
                return 0
        data.opSetOpcode(op, OpCode.CPUI_COPY)
        return 1


# =========================================================================
# RuleDoubleArithShift
# (V s>> c1) s>> c2 => V s>> (c1+c2)
# =========================================================================

class RuleDoubleArithShift(Rule):
    """Collapse double arithmetic shifts."""

    def __init__(self, g: str) -> None:
        super().__init__(g, 0, "doublearithshift")

    def clone(self, grouplist):
        if not grouplist.contains(self._basegroup): return None
        return RuleDoubleArithShift(self._basegroup)

    def getOpList(self) -> List[int]:
        return [int(OpCode.CPUI_INT_SRIGHT)]

    def applyOp(self, op, data) -> int:
        if not op.getIn(1).isConstant(): return 0
        vn = op.getIn(0)
        if not vn.isWritten(): return 0
        op2 = vn.getDef()
        if op2.code() != OpCode.CPUI_INT_SRIGHT: return 0
        if not op2.getIn(1).isConstant(): return 0
        c1 = op2.getIn(1).getOffset()
        c2 = op.getIn(1).getOffset()
        basevn = op2.getIn(0)
        if basevn.isFree(): return 0
        outvn = op.getOut()
        if outvn is None: return 0
        total = c1 + c2
        size_bits = outvn.getSize() * 8
        if total >= size_bits:
            total = size_bits - 1  # Arithmetic shift saturates
        data.opSetInput(op, basevn, 0)
        data.opSetInput(op, data.newConstant(op.getIn(1).getSize(), total), 1)
        return 1


# =========================================================================
# RuleLeftRight
# (V << c) >> c => V & mask  (zero extension pattern)
# =========================================================================

class RuleLeftRight(Rule):
    """Collapse left-then-right shift: (V << c) >> c => V & mask."""

    def __init__(self, g: str) -> None:
        super().__init__(g, 0, "leftright")

    def clone(self, grouplist):
        if not grouplist.contains(self._basegroup): return None
        return RuleLeftRight(self._basegroup)

    def getOpList(self) -> List[int]:
        return [int(OpCode.CPUI_INT_RIGHT)]

    def applyOp(self, op, data) -> int:
        if not op.getIn(1).isConstant(): return 0
        vn = op.getIn(0)
        if not vn.isWritten(): return 0
        op2 = vn.getDef()
        if op2.code() != OpCode.CPUI_INT_LEFT: return 0
        if not op2.getIn(1).isConstant(): return 0
        sa_right = op.getIn(1).getOffset()
        sa_left = op2.getIn(1).getOffset()
        if sa_right != sa_left: return 0
        basevn = op2.getIn(0)
        if basevn.isFree(): return 0
        outvn = op.getOut()
        if outvn is None: return 0
        size = outvn.getSize()
        mask = calc_mask(size) >> sa_right
        data.opSetOpcode(op, OpCode.CPUI_INT_AND)
        data.opSetInput(op, basevn, 0)
        data.opSetInput(op, data.newConstant(size, mask), 1)
        return 1


def buildDefaultRules(group: str = "analysis") -> List[Rule]:
    """Build the default set of transformation rules.

    Each rule is a 1:1 port of the corresponding C++ Rule class
    from ruleaction.cc.
    """
    return [
        RuleEarlyRemoval(group),
        RuleCollapseConstants(group),
        RulePropagateCopy(group),
        RulePiece2Zext(group),
        RulePiece2Sext(group),
        RuleBxor2NotEqual(group),
        RuleOrMask(group),
        RuleAndMask(group),
        RuleOrCollapse(group),
        RuleAndOrLump(group),
        RuleNegateIdentity(group),
        RuleOrConsume(group),
        RuleTrivialArith(group),
        RuleDoubleSub(group),
        RuleDoubleShift(group),
        Rule2Comp2Mult(group),
        RuleSub2Add(group),
        RuleXorCollapse(group),
        RuleZextEliminate(group),
        RuleShift2Mult(group),
        RuleRightShiftAnd(group),
        RuleTermOrder(group),
        RuleTrivialBool(group),
        RuleIdentityEl(group),
        RuleCarryElim(group),
        RuleSborrow(group),
        RuleScarry(group),
        RuleBooleanNegate(group),
        RuleNotDistribute(group),
        RuleLogic2Bool(group),
        RuleAddMultCollapse(group),
        RuleLessOne(group),
        RuleHighOrderAnd(group),
        RuleBoolZext(group),
        RuleDoubleArithShift(group),
        RuleLeftRight(group),
        RuleAndZext(group),
        RuleAndCompare(group),
        RuleConcatShift(group),
        RuleSignShift(group),
    ]


# =========================================================================
# RuleAndZext
# sext(X) & 0xffff => zext(X),  concat(Y,X) & 0xffff => zext(X)
# =========================================================================

class RuleAndZext(Rule):
    """Convert INT_AND to INT_ZEXT: sext(X) & mask => zext(X)."""

    def __init__(self, g: str) -> None:
        super().__init__(g, 0, "andzext")

    def clone(self, grouplist):
        if not grouplist.contains(self._basegroup): return None
        return RuleAndZext(self._basegroup)

    def getOpList(self) -> List[int]:
        return [int(OpCode.CPUI_INT_AND)]

    def applyOp(self, op, data) -> int:
        cvn1 = op.getIn(1)
        if not cvn1.isConstant(): return 0
        in0 = op.getIn(0)
        if not in0.isWritten(): return 0
        otherop = in0.getDef()
        opc = otherop.code()
        if opc == OpCode.CPUI_INT_SEXT:
            rootvn = otherop.getIn(0)
        elif opc == OpCode.CPUI_PIECE:
            rootvn = otherop.getIn(1)
        else:
            return 0
        mask = calc_mask(rootvn.getSize())
        if mask != cvn1.getOffset(): return 0
        if rootvn.isFree(): return 0
        if rootvn.getSize() > 8: return 0
        data.opSetOpcode(op, OpCode.CPUI_INT_ZEXT)
        data.opRemoveInput(op, 1)
        data.opSetInput(op, rootvn, 0)
        return 1


# =========================================================================
# RuleAndCompare
# zext(V) & c == 0 => V & (c & mask) == 0
# =========================================================================

class RuleAndCompare(Rule):
    """Simplify masked comparison through ZEXT/SUBPIECE."""

    def __init__(self, g: str) -> None:
        super().__init__(g, 0, "andcompare")

    def clone(self, grouplist):
        if not grouplist.contains(self._basegroup): return None
        return RuleAndCompare(self._basegroup)

    def getOpList(self) -> List[int]:
        return [int(OpCode.CPUI_INT_EQUAL), int(OpCode.CPUI_INT_NOTEQUAL)]

    def applyOp(self, op, data) -> int:
        if not op.getIn(1).isConstant(): return 0
        if op.getIn(1).getOffset() != 0: return 0
        andvn = op.getIn(0)
        if not andvn.isWritten(): return 0
        andop = andvn.getDef()
        if andop.code() != OpCode.CPUI_INT_AND: return 0
        if not andop.getIn(1).isConstant(): return 0
        subvn = andop.getIn(0)
        if not subvn.isWritten(): return 0
        subop = subvn.getDef()
        if subop.code() == OpCode.CPUI_INT_ZEXT:
            basevn = subop.getIn(0)
            baseconst = andop.getIn(1).getOffset()
            andconst = baseconst & calc_mask(basevn.getSize())
        elif subop.code() == OpCode.CPUI_SUBPIECE:
            basevn = subop.getIn(0)
            baseconst = andop.getIn(1).getOffset()
            andconst = baseconst << (subop.getIn(1).getOffset() * 8)
        else:
            return 0
        if basevn.isFree(): return 0
        newop = data.newOp(2, andop.getAddr())
        data.opSetOpcode(newop, OpCode.CPUI_INT_AND)
        newout = data.newUniqueOut(basevn.getSize(), newop)
        data.opSetInput(newop, basevn, 0)
        data.opSetInput(newop, data.newConstant(basevn.getSize(), andconst), 1)
        data.opInsertBefore(newop, op)
        data.opSetInput(op, newout, 0)
        data.opSetInput(op, data.newConstant(basevn.getSize(), 0), 1)
        return 1


# =========================================================================
# RuleConcatShift
# concat(V, W) >> c => zext(V) when c == sizeof(W)*8
# =========================================================================

class RuleConcatShift(Rule):
    """Simplify right shift of PIECE: concat(V,W) >> (sizeof(W)*8) => zext(V)."""

    def __init__(self, g: str) -> None:
        super().__init__(g, 0, "concatshift")

    def clone(self, grouplist):
        if not grouplist.contains(self._basegroup): return None
        return RuleConcatShift(self._basegroup)

    def getOpList(self) -> List[int]:
        return [int(OpCode.CPUI_INT_RIGHT)]

    def applyOp(self, op, data) -> int:
        if not op.getIn(1).isConstant(): return 0
        vn = op.getIn(0)
        if not vn.isWritten(): return 0
        pieceop = vn.getDef()
        if pieceop.code() != OpCode.CPUI_PIECE: return 0
        lowvn = pieceop.getIn(1)
        sa = op.getIn(1).getOffset()
        if sa != lowvn.getSize() * 8: return 0
        highvn = pieceop.getIn(0)
        if highvn.isFree(): return 0
        data.opSetOpcode(op, OpCode.CPUI_INT_ZEXT)
        data.opRemoveInput(op, 1)
        data.opSetInput(op, highvn, 0)
        return 1


# =========================================================================
# RuleSignShift
# (V s>> 31) => V < 0 ? -1 : 0, rewrite as: V s>> (size*8 - 1) => signbit extraction
# =========================================================================

class RuleSignShift(Rule):
    """Recognize sign extraction: V s>> (N-1) => V < 0 ? -1 : 0."""

    def __init__(self, g: str) -> None:
        super().__init__(g, 0, "signshift")

    def clone(self, grouplist):
        if not grouplist.contains(self._basegroup): return None
        return RuleSignShift(self._basegroup)

    def getOpList(self) -> List[int]:
        return [int(OpCode.CPUI_INT_SRIGHT)]

    def applyOp(self, op, data) -> int:
        if not op.getIn(1).isConstant(): return 0
        sa = op.getIn(1).getOffset()
        inVn = op.getIn(0)
        size = inVn.getSize()
        if sa != size * 8 - 1: return 0
        if inVn.isFree(): return 0

        doConversion = False
        outVn = op.getOut()
        if outVn is None:
            return 0
        for arithOp in outVn.getDescendants():
            opc = arithOp.code()
            if opc in (OpCode.CPUI_INT_EQUAL, OpCode.CPUI_INT_NOTEQUAL):
                if arithOp.getIn(1).isConstant():
                    doConversion = True
            elif opc in (OpCode.CPUI_INT_ADD, OpCode.CPUI_INT_MULT):
                doConversion = True
            if doConversion:
                break
        if not doConversion:
            return 0
        shiftOp = data.newOp(2, op.getAddr())
        data.opSetOpcode(shiftOp, OpCode.CPUI_INT_SRIGHT)
        uniqueVn = data.newUniqueOut(inVn.getSize(), shiftOp)
        data.opSetInput(op, uniqueVn, 0)
        data.opSetInput(op, data.newConstant(inVn.getSize(), calc_mask(inVn.getSize())), 1)
        data.opSetOpcode(op, OpCode.CPUI_INT_MULT)
        data.opSetInput(shiftOp, inVn, 0)
        data.opSetInput(shiftOp, op.getIn(1), 1)
        data.opInsertBefore(shiftOp, op)
        return 1
