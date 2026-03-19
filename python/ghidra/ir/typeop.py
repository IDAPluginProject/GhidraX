"""
Corresponds to: typeop.hh / typeop.cc

Data-type and behavior information associated with specific p-code op-codes.
"""

from __future__ import annotations
from typing import TYPE_CHECKING, Optional, List
from ghidra.core.opcodes import OpCode
from ghidra.core.opbehavior import OpBehavior
from ghidra.types.datatype import (
    Datatype, TypeFactory, MetaType,
    TYPE_VOID, TYPE_UNKNOWN, TYPE_INT, TYPE_UINT, TYPE_BOOL, TYPE_FLOAT, TYPE_PTR,
)

if TYPE_CHECKING:
    from ghidra.ir.op import PcodeOp
    from ghidra.ir.varnode import Varnode
    from ghidra.core.translate import Translate


class TypeOp:
    """Associate data-type and behavior information with a specific p-code op-code."""

    inherits_sign = 1
    inherits_sign_zero = 2
    shift_op = 4
    arithmetic_op = 8
    logical_op = 0x10
    floatingpoint_op = 0x20

    def __init__(self, tlst: TypeFactory, opc: OpCode, name: str) -> None:
        self.tlst = tlst
        self.opcode = opc
        self.opflags: int = 0
        self.addlflags: int = 0
        self.name = name
        self.behave: Optional[OpBehavior] = None

    def getName(self) -> str:
        return self.name

    def getOpcode(self) -> OpCode:
        return self.opcode

    def getFlags(self) -> int:
        return self.opflags

    def getBehavior(self) -> Optional[OpBehavior]:
        return self.behave

    def isCommutative(self) -> bool:
        from ghidra.ir.op import PcodeOp as PcOp
        return (self.opflags & PcOp.commutative) != 0

    def inheritsSign(self) -> bool:
        return (self.addlflags & TypeOp.inherits_sign) != 0

    def isShiftOp(self) -> bool:
        return (self.addlflags & TypeOp.shift_op) != 0

    def isArithmeticOp(self) -> bool:
        return (self.addlflags & TypeOp.arithmetic_op) != 0

    def isLogicalOp(self) -> bool:
        return (self.addlflags & TypeOp.logical_op) != 0

    def isFloatingPointOp(self) -> bool:
        return (self.addlflags & TypeOp.floatingpoint_op) != 0

    def inheritsSignFirstParamOnly(self) -> bool:
        return (self.addlflags & TypeOp.inherits_sign_zero) != 0

    def evaluateUnary(self, sizeout: int, sizein: int, in1: int) -> int:
        """Emulate the unary op-code on an input value."""
        if self.behave is not None:
            return self.behave.evaluateUnary(sizeout, sizein, in1)
        return 0

    def evaluateBinary(self, sizeout: int, sizein: int, in1: int, in2: int) -> int:
        """Emulate the binary op-code on input values."""
        if self.behave is not None:
            return self.behave.evaluateBinary(sizeout, sizein, in1, in2)
        return 0

    def evaluateTernary(self, sizeout: int, sizein: int, in1: int, in2: int, in3: int) -> int:
        """Emulate the ternary op-code on input values."""
        if self.behave is not None and hasattr(self.behave, 'evaluateTernary'):
            return self.behave.evaluateTernary(sizeout, sizein, in1, in2, in3)
        return 0

    def recoverInputBinary(self, slot: int, sizeout: int, out: int, sizein: int, inp: int) -> int:
        """Reverse the binary op-code, recovering a constant input value."""
        if self.behave is not None and hasattr(self.behave, 'recoverInputBinary'):
            return self.behave.recoverInputBinary(slot, sizeout, out, sizein, inp)
        return 0

    def recoverInputUnary(self, sizeout: int, out: int, sizein: int) -> int:
        """Reverse the unary op-code, recovering a constant input value."""
        if self.behave is not None and hasattr(self.behave, 'recoverInputUnary'):
            return self.behave.recoverInputUnary(sizeout, out, sizein)
        return 0

    def getOutputToken(self, op, castStrategy=None) -> Optional[Datatype]:
        """Find the data-type of the output that would be assigned by a compiler."""
        return self.getOutputLocal(op)

    def getInputCast(self, op, slot: int, castStrategy=None) -> Optional[Datatype]:
        """Find the data-type of the input to a specific PcodeOp."""
        return None  # No cast needed by default

    def propagateType(self, alttype, op, invn, outvn, inslot: int, outslot: int):
        """Propagate an incoming data-type across a specific PcodeOp."""
        return None  # No propagation by default

    def stopsTypePropagation(self) -> bool:
        """Check if this op stops type propagation."""
        return False

    def setMetatypeIn(self, mt) -> None:
        """Override input metatype (used by selectJavaOperators)."""
        pass  # Only meaningful on TypeOpBinary/TypeOpUnary/TypeOpFunc

    def setMetatypeOut(self, mt) -> None:
        """Override output metatype (used by selectJavaOperators)."""
        pass  # Only meaningful on TypeOpBinary/TypeOpUnary/TypeOpFunc

    def setSymbol(self, nm: str) -> None:
        """Override display symbol name."""
        self.name = nm

    @staticmethod
    def floatSignManipulation(op) -> OpCode:
        """Return the floating-point op associated with sign bit manipulation."""
        opc = op.code() if hasattr(op, 'code') else op.getOpcode()
        if opc == OpCode.CPUI_INT_AND:
            cvn = op.getIn(1)
            if cvn is not None and hasattr(cvn, 'isConstant') and cvn.isConstant():
                sz = cvn.getSize()
                mask = (1 << (8 * sz)) - 1
                val = mask >> 1
                if val == cvn.getOffset():
                    return OpCode.CPUI_FLOAT_ABS
        elif opc == OpCode.CPUI_INT_XOR:
            cvn = op.getIn(1)
            if cvn is not None and hasattr(cvn, 'isConstant') and cvn.isConstant():
                sz = cvn.getSize()
                mask = (1 << (8 * sz)) - 1
                val = mask ^ (mask >> 1)
                if val == cvn.getOffset():
                    return OpCode.CPUI_FLOAT_NEG
        return OpCode.CPUI_MAX

    @staticmethod
    def propagateToPointer(t, dt, sz: int, wordsz: int):
        """Propagate a dereferenced data-type up to its pointer through LOAD/STORE.

        Don't create more than a depth of 1 (i.e. ptr->ptr).
        """
        meta = dt.getMetatype() if hasattr(dt, 'getMetatype') else TYPE_UNKNOWN
        if meta == TYPE_PTR:
            dt = t.getBase(dt.getSize(), TYPE_UNKNOWN)
        if hasattr(t, 'getTypePointer'):
            return t.getTypePointer(sz, dt, wordsz)
        return None

    @staticmethod
    def propagateFromPointer(t, dt, sz: int):
        """Propagate a pointer data-type down to its element through LOAD/STORE."""
        if not hasattr(dt, 'getMetatype'):
            return None
        if dt.getMetatype() != TYPE_PTR:
            return None
        if hasattr(dt, 'getPtrTo'):
            ptrto = dt.getPtrTo()
            if hasattr(ptrto, 'isVariableLength') and ptrto.isVariableLength():
                return None
            if ptrto.getSize() == sz:
                return ptrto
        return None

    @staticmethod
    def selectJavaOperators(inst: list, val: bool) -> None:
        """Toggle Java specific aspects of the op-code information."""
        if val:
            inst[int(OpCode.CPUI_INT_ZEXT)].setMetatypeIn(TYPE_UNKNOWN)
            inst[int(OpCode.CPUI_INT_ZEXT)].setMetatypeOut(TYPE_INT)
            inst[int(OpCode.CPUI_INT_NEGATE)].setMetatypeIn(TYPE_INT)
            inst[int(OpCode.CPUI_INT_NEGATE)].setMetatypeOut(TYPE_INT)
            inst[int(OpCode.CPUI_INT_XOR)].setMetatypeIn(TYPE_INT)
            inst[int(OpCode.CPUI_INT_XOR)].setMetatypeOut(TYPE_INT)
            inst[int(OpCode.CPUI_INT_OR)].setMetatypeIn(TYPE_INT)
            inst[int(OpCode.CPUI_INT_OR)].setMetatypeOut(TYPE_INT)
            inst[int(OpCode.CPUI_INT_AND)].setMetatypeIn(TYPE_INT)
            inst[int(OpCode.CPUI_INT_AND)].setMetatypeOut(TYPE_INT)
            inst[int(OpCode.CPUI_INT_RIGHT)].setMetatypeIn(TYPE_INT)
            inst[int(OpCode.CPUI_INT_RIGHT)].setMetatypeOut(TYPE_INT)
            inst[int(OpCode.CPUI_INT_RIGHT)].setSymbol('>>>')
        else:
            inst[int(OpCode.CPUI_INT_ZEXT)].setMetatypeIn(TYPE_UINT)
            inst[int(OpCode.CPUI_INT_ZEXT)].setMetatypeOut(TYPE_UINT)
            inst[int(OpCode.CPUI_INT_NEGATE)].setMetatypeIn(TYPE_UINT)
            inst[int(OpCode.CPUI_INT_NEGATE)].setMetatypeOut(TYPE_UINT)
            inst[int(OpCode.CPUI_INT_XOR)].setMetatypeIn(TYPE_UINT)
            inst[int(OpCode.CPUI_INT_XOR)].setMetatypeOut(TYPE_UINT)
            inst[int(OpCode.CPUI_INT_OR)].setMetatypeIn(TYPE_UINT)
            inst[int(OpCode.CPUI_INT_OR)].setMetatypeOut(TYPE_UINT)
            inst[int(OpCode.CPUI_INT_AND)].setMetatypeIn(TYPE_UINT)
            inst[int(OpCode.CPUI_INT_AND)].setMetatypeOut(TYPE_UINT)
            inst[int(OpCode.CPUI_INT_RIGHT)].setMetatypeIn(TYPE_UINT)
            inst[int(OpCode.CPUI_INT_RIGHT)].setMetatypeOut(TYPE_UINT)
            inst[int(OpCode.CPUI_INT_RIGHT)].setSymbol('>>')

    def getOutputLocal(self, op) -> Optional[Datatype]:
        outvn = op.getOut()
        if outvn is None:
            return self.tlst.getTypeVoid()
        return self.tlst.getBase(outvn.getSize(), TYPE_UNKNOWN)

    def getInputLocal(self, op, slot: int) -> Optional[Datatype]:
        invn = op.getIn(slot)
        if invn is None:
            return self.tlst.getTypeVoid()
        return self.tlst.getBase(invn.getSize(), TYPE_UNKNOWN)

    def getOperatorName(self, op) -> str:
        return self.name

    def push(self, lng, op, readOp=None) -> None:
        """Push this op's expression onto the PrintLanguage RPN stack.

        Dispatches to the correct opXxx handler on the PrintLanguage (PrintC) instance.
        This is the bridge between recurse() and per-opcode emission.
        """
        handler = self._getHandler(lng)
        if handler is not None:
            handler(op)
        else:
            # Fallback: use opFunc-style emission
            if hasattr(lng, 'opFunc'):
                lng.opFunc(op)
            else:
                lng.pushVnExplicit(op.getOut() if op.getOut() is not None else op.getIn(0), op)

    def _getHandler(self, lng):
        """Look up the PrintC handler for this opcode."""
        _HANDLER_MAP = {
            OpCode.CPUI_COPY: 'opCopy',
            OpCode.CPUI_LOAD: 'opLoad',
            OpCode.CPUI_STORE: 'opStore',
            OpCode.CPUI_BRANCH: 'opBranch',
            OpCode.CPUI_CBRANCH: 'opCbranch',
            OpCode.CPUI_BRANCHIND: 'opBranchind',
            OpCode.CPUI_CALL: 'opCall',
            OpCode.CPUI_CALLIND: 'opCallind',
            OpCode.CPUI_CALLOTHER: 'opCallother',
            OpCode.CPUI_RETURN: 'opReturn',
            OpCode.CPUI_INT_EQUAL: 'opIntEqual',
            OpCode.CPUI_INT_NOTEQUAL: 'opIntNotEqual',
            OpCode.CPUI_INT_SLESS: 'opIntSless',
            OpCode.CPUI_INT_SLESSEQUAL: 'opIntSlessEqual',
            OpCode.CPUI_INT_LESS: 'opIntLess',
            OpCode.CPUI_INT_LESSEQUAL: 'opIntLessEqual',
            OpCode.CPUI_INT_ZEXT: 'opIntZext',
            OpCode.CPUI_INT_SEXT: 'opIntSext',
            OpCode.CPUI_INT_ADD: 'opIntAdd',
            OpCode.CPUI_INT_SUB: 'opIntSub',
            OpCode.CPUI_INT_CARRY: 'opIntCarry',
            OpCode.CPUI_INT_SCARRY: 'opIntScarry',
            OpCode.CPUI_INT_SBORROW: 'opIntSborrow',
            OpCode.CPUI_INT_2COMP: 'opInt2Comp',
            OpCode.CPUI_INT_NEGATE: 'opIntNegate',
            OpCode.CPUI_INT_XOR: 'opIntXor',
            OpCode.CPUI_INT_AND: 'opIntAnd',
            OpCode.CPUI_INT_OR: 'opIntOr',
            OpCode.CPUI_INT_LEFT: 'opIntLeft',
            OpCode.CPUI_INT_RIGHT: 'opIntRight',
            OpCode.CPUI_INT_SRIGHT: 'opIntSright',
            OpCode.CPUI_INT_MULT: 'opIntMult',
            OpCode.CPUI_INT_DIV: 'opIntDiv',
            OpCode.CPUI_INT_SDIV: 'opIntSdiv',
            OpCode.CPUI_INT_REM: 'opIntRem',
            OpCode.CPUI_INT_SREM: 'opIntSrem',
            OpCode.CPUI_BOOL_NEGATE: 'opBoolNegate',
            OpCode.CPUI_BOOL_XOR: 'opBoolXor',
            OpCode.CPUI_BOOL_AND: 'opBoolAnd',
            OpCode.CPUI_BOOL_OR: 'opBoolOr',
            OpCode.CPUI_FLOAT_EQUAL: 'opFloatEqual',
            OpCode.CPUI_FLOAT_NOTEQUAL: 'opFloatNotEqual',
            OpCode.CPUI_FLOAT_LESS: 'opFloatLess',
            OpCode.CPUI_FLOAT_LESSEQUAL: 'opFloatLessEqual',
            OpCode.CPUI_FLOAT_NAN: 'opFloatNan',
            OpCode.CPUI_FLOAT_ADD: 'opFloatAdd',
            OpCode.CPUI_FLOAT_DIV: 'opFloatDiv',
            OpCode.CPUI_FLOAT_MULT: 'opFloatMult',
            OpCode.CPUI_FLOAT_SUB: 'opFloatSub',
            OpCode.CPUI_FLOAT_NEG: 'opFloatNeg',
            OpCode.CPUI_FLOAT_ABS: 'opFloatAbs',
            OpCode.CPUI_FLOAT_SQRT: 'opFloatSqrt',
            OpCode.CPUI_FLOAT_INT2FLOAT: 'opFloatInt2Float',
            OpCode.CPUI_FLOAT_FLOAT2FLOAT: 'opFloatFloat2Float',
            OpCode.CPUI_FLOAT_TRUNC: 'opFloatTrunc',
            OpCode.CPUI_FLOAT_CEIL: 'opFloatCeil',
            OpCode.CPUI_FLOAT_FLOOR: 'opFloatFloor',
            OpCode.CPUI_FLOAT_ROUND: 'opFloatRound',
            OpCode.CPUI_MULTIEQUAL: 'opMultiequal',
            OpCode.CPUI_INDIRECT: 'opIndirect',
            OpCode.CPUI_PIECE: 'opPiece',
            OpCode.CPUI_SUBPIECE: 'opSubpiece',
            OpCode.CPUI_CAST: 'opCast',
            OpCode.CPUI_PTRADD: 'opPtradd',
            OpCode.CPUI_PTRSUB: 'opPtrsub',
            OpCode.CPUI_SEGMENTOP: 'opSegmentOp',
            OpCode.CPUI_CPOOLREF: 'opCpoolRefOp',
            OpCode.CPUI_NEW: 'opNewOp',
            OpCode.CPUI_INSERT: 'opInsertOp',
            OpCode.CPUI_EXTRACT: 'opExtractOp',
            OpCode.CPUI_POPCOUNT: 'opPopcountOp',
            OpCode.CPUI_LZCOUNT: 'opLzcountOp',
        }
        name = _HANDLER_MAP.get(self.opcode)
        if name is not None:
            return getattr(lng, name, None)
        return None

    def printRaw(self, op) -> str:
        parts = []
        outvn = op.getOut()
        if outvn is not None:
            parts.append(f"{outvn.printRaw()} = ")
        parts.append(self.name)
        for i in range(op.numInput()):
            invn = op.getIn(i)
            if invn is not None:
                parts.append(f" {invn.printRaw()}")
        return "".join(parts)


class TypeOpBinary(TypeOp):
    """A generic binary operator: two inputs and one output."""

    def __init__(self, tlst, opc, name, metaout, metain):
        super().__init__(tlst, opc, name)
        self.metaout: MetaType = metaout
        self.metain: MetaType = metain

    def setMetatypeIn(self, mt) -> None:
        self.metain = mt

    def setMetatypeOut(self, mt) -> None:
        self.metaout = mt

    def getOutputLocal(self, op):
        outvn = op.getOut()
        if outvn is None:
            return self.tlst.getTypeVoid()
        return self.tlst.getBase(outvn.getSize(), self.metaout)

    def getInputLocal(self, op, slot):
        invn = op.getIn(slot)
        if invn is None:
            return self.tlst.getTypeVoid()
        return self.tlst.getBase(invn.getSize(), self.metain)


class TypeOpUnary(TypeOp):
    """A generic unary operator: one input and one output."""

    def __init__(self, tlst, opc, name, metaout, metain):
        super().__init__(tlst, opc, name)
        self.metaout: MetaType = metaout
        self.metain: MetaType = metain

    def setMetatypeIn(self, mt) -> None:
        self.metain = mt

    def setMetatypeOut(self, mt) -> None:
        self.metaout = mt

    def getOutputLocal(self, op):
        outvn = op.getOut()
        if outvn is None:
            return self.tlst.getTypeVoid()
        return self.tlst.getBase(outvn.getSize(), self.metaout)

    def getInputLocal(self, op, slot):
        invn = op.getIn(slot)
        if invn is None:
            return self.tlst.getTypeVoid()
        return self.tlst.getBase(invn.getSize(), self.metain)


class TypeOpFunc(TypeOp):
    """A generic functional operator."""

    def __init__(self, tlst, opc, name, metaout, metain):
        super().__init__(tlst, opc, name)
        self.metaout: MetaType = metaout
        self.metain: MetaType = metain

    def setMetatypeIn(self, mt) -> None:
        self.metain = mt

    def setMetatypeOut(self, mt) -> None:
        self.metaout = mt

    def getOutputLocal(self, op):
        outvn = op.getOut()
        if outvn is None:
            return self.tlst.getTypeVoid()
        return self.tlst.getBase(outvn.getSize(), self.metaout)

    def getInputLocal(self, op, slot):
        invn = op.getIn(slot)
        if invn is None:
            return self.tlst.getTypeVoid()
        return self.tlst.getBase(invn.getSize(), self.metain)


# =========================================================================
# Concrete TypeOp subclasses for opcodes with special type behavior
# =========================================================================

class TypeOpCopy(TypeOp):
    """CPUI_COPY — propagates type directly through."""
    def __init__(self, tlst):
        super().__init__(tlst, OpCode.CPUI_COPY, "COPY")
    def getInputCast(self, op, slot, castStrategy=None):
        if castStrategy is None: return None
        outvn = op.getOut()
        invn = op.getIn(0)
        if outvn is None or invn is None: return None
        return castStrategy.castStandard(outvn.getHighTypeDefFacing() if hasattr(outvn,'getHighTypeDefFacing') else outvn.getType(),
                                          invn.getHighTypeReadFacing(op) if hasattr(invn,'getHighTypeReadFacing') else invn.getType(),
                                          False, True)
    def getOutputToken(self, op, castStrategy=None):
        invn = op.getIn(0)
        return invn.getHighTypeReadFacing(op) if invn is not None and hasattr(invn,'getHighTypeReadFacing') else None
    def propagateType(self, alttype, op, invn, outvn, inslot, outslot):
        if inslot != -1 and outslot != -1:
            return None  # Must propagate input <-> output
        if hasattr(invn, 'isSpacebase') and invn.isSpacebase():
            if hasattr(self.tlst, 'getArch'):
                spc = self.tlst.getArch().getDefaultDataSpace()
                wordsz = spc.getWordSize() if hasattr(spc, 'getWordSize') else 1
                return self.tlst.getTypePointer(alttype.getSize(), self.tlst.getBase(1, TYPE_UNKNOWN), wordsz)
            return alttype
        return alttype

class TypeOpLoad(TypeOp):
    """CPUI_LOAD — dereference pointer to produce value."""
    def __init__(self, tlst):
        super().__init__(tlst, OpCode.CPUI_LOAD, "LOAD")
        from ghidra.ir.op import PcodeOp as PcOp
        self.opflags = PcOp.special | getattr(PcOp, 'nocollapse', 0)
    def propagateType(self, alttype, op, invn, outvn, inslot, outslot):
        if inslot == 0 or outslot == 0:
            return None  # Don't propagate along space edge
        if hasattr(invn, 'isSpacebase') and invn.isSpacebase():
            return None
        if inslot == -1:  # Propagating output to input (value to ptr)
            spc_vn = op.getIn(0)
            wordsz = 1
            if hasattr(spc_vn, 'getSpaceFromConst'):
                spc = spc_vn.getSpaceFromConst()
                if spc is not None and hasattr(spc, 'getWordSize'):
                    wordsz = spc.getWordSize()
            return TypeOp.propagateToPointer(self.tlst, alttype, outvn.getSize(), wordsz)
        else:
            return TypeOp.propagateFromPointer(self.tlst, alttype, outvn.getSize())

class TypeOpStore(TypeOp):
    """CPUI_STORE — store value through pointer."""
    def __init__(self, tlst):
        super().__init__(tlst, OpCode.CPUI_STORE, "STORE")
        from ghidra.ir.op import PcodeOp as PcOp
        self.opflags = PcOp.special | getattr(PcOp, 'nocollapse', 0)
    def propagateType(self, alttype, op, invn, outvn, inslot, outslot):
        if inslot == 0 or outslot == 0:
            return None
        if hasattr(invn, 'isSpacebase') and invn.isSpacebase():
            return None
        if inslot == 2:  # Propagating value to ptr
            spc_vn = op.getIn(0)
            wordsz = 1
            if hasattr(spc_vn, 'getSpaceFromConst'):
                spc = spc_vn.getSpaceFromConst()
                if spc is not None and hasattr(spc, 'getWordSize'):
                    wordsz = spc.getWordSize()
            return TypeOp.propagateToPointer(self.tlst, alttype, outvn.getSize(), wordsz)
        else:
            return TypeOp.propagateFromPointer(self.tlst, alttype, outvn.getSize())

class TypeOpBranch(TypeOp):
    """CPUI_BRANCH."""
    def __init__(self, tlst):
        super().__init__(tlst, OpCode.CPUI_BRANCH, "BRANCH")
    def getInputLocal(self, op, slot):
        return self.tlst.getTypeVoid()
    def getOutputLocal(self, op):
        return self.tlst.getTypeVoid()

class TypeOpCbranch(TypeOp):
    """CPUI_CBRANCH."""
    def __init__(self, tlst):
        super().__init__(tlst, OpCode.CPUI_CBRANCH, "CBRANCH")
    def getInputLocal(self, op, slot):
        if slot == 1:
            return self.tlst.getBase(1, TYPE_BOOL)
        return self.tlst.getTypeVoid()
    def getOutputLocal(self, op):
        return self.tlst.getTypeVoid()

class TypeOpBranchind(TypeOp):
    """CPUI_BRANCHIND."""
    def __init__(self, tlst):
        super().__init__(tlst, OpCode.CPUI_BRANCHIND, "BRANCHIND")
    def getInputLocal(self, op, slot):
        return self.tlst.getTypeVoid()
    def getOutputLocal(self, op):
        return self.tlst.getTypeVoid()

class TypeOpCall(TypeOp):
    """CPUI_CALL."""
    def __init__(self, tlst):
        super().__init__(tlst, OpCode.CPUI_CALL, "CALL")
    def getInputLocal(self, op, slot):
        return self.tlst.getTypeVoid()
    def getOutputLocal(self, op):
        return self.tlst.getTypeVoid()

class TypeOpCallind(TypeOp):
    """CPUI_CALLIND."""
    def __init__(self, tlst):
        super().__init__(tlst, OpCode.CPUI_CALLIND, "CALLIND")
    def getInputLocal(self, op, slot):
        return self.tlst.getTypeVoid()
    def getOutputLocal(self, op):
        return self.tlst.getTypeVoid()

class TypeOpCallother(TypeOp):
    """CPUI_CALLOTHER."""
    def __init__(self, tlst):
        super().__init__(tlst, OpCode.CPUI_CALLOTHER, "CALLOTHER")
    def getInputLocal(self, op, slot):
        return self.tlst.getTypeVoid()
    def getOutputLocal(self, op):
        return self.tlst.getTypeVoid()

class TypeOpReturn(TypeOp):
    """CPUI_RETURN."""
    def __init__(self, tlst):
        super().__init__(tlst, OpCode.CPUI_RETURN, "RETURN")
    def getInputLocal(self, op, slot):
        return self.tlst.getTypeVoid()
    def getOutputLocal(self, op):
        return self.tlst.getTypeVoid()

class TypeOpIntEqual(TypeOpBinary):
    """CPUI_INT_EQUAL."""
    def __init__(self, tlst):
        super().__init__(tlst, OpCode.CPUI_INT_EQUAL, "==", TYPE_BOOL, TYPE_INT)
        from ghidra.ir.op import PcodeOp as PcOp
        self.opflags = PcOp.binary | PcOp.booloutput | PcOp.commutative
        self.addlflags = TypeOp.inherits_sign
    def propagateType(self, alttype, op, invn, outvn, inslot, outslot):
        return TypeOpIntEqual.propagateAcrossCompare(alttype, self.tlst, invn, outvn, inslot, outslot)
    @staticmethod
    def propagateAcrossCompare(alttype, typegrp, invn, outvn, inslot, outslot):
        """Propagate a data-type across a comparison PcodeOp."""
        if inslot == -1 or outslot == -1:
            return None
        if hasattr(invn, 'isSpacebase') and invn.isSpacebase():
            if hasattr(typegrp, 'getArch'):
                spc = typegrp.getArch().getDefaultDataSpace()
                wordsz = spc.getWordSize() if hasattr(spc, 'getWordSize') else 1
                return typegrp.getTypePointer(alttype.getSize(), typegrp.getBase(1, TYPE_UNKNOWN), wordsz)
        return alttype

class TypeOpIntNotEqual(TypeOpBinary):
    """CPUI_INT_NOTEQUAL."""
    def __init__(self, tlst):
        super().__init__(tlst, OpCode.CPUI_INT_NOTEQUAL, "!=", TYPE_BOOL, TYPE_INT)
        from ghidra.ir.op import PcodeOp as PcOp
        self.opflags = PcOp.binary | PcOp.booloutput | PcOp.commutative
        self.addlflags = TypeOp.inherits_sign
    def propagateType(self, alttype, op, invn, outvn, inslot, outslot):
        return TypeOpIntEqual.propagateAcrossCompare(alttype, self.tlst, invn, outvn, inslot, outslot)

class TypeOpIntSless(TypeOpBinary):
    """CPUI_INT_SLESS."""
    def __init__(self, tlst):
        super().__init__(tlst, OpCode.CPUI_INT_SLESS, "s<", TYPE_BOOL, TYPE_INT)
        from ghidra.ir.op import PcodeOp as PcOp
        self.opflags = PcOp.binary | PcOp.booloutput
        self.addlflags = TypeOp.inherits_sign
    def propagateType(self, alttype, op, invn, outvn, inslot, outslot):
        if inslot == -1 or outslot == -1:
            return None  # Must propagate input <-> input
        if hasattr(alttype, 'getMetatype') and alttype.getMetatype() != TYPE_INT:
            return None  # Only propagate signed things
        return alttype

class TypeOpIntSlessEqual(TypeOpBinary):
    """CPUI_INT_SLESSEQUAL."""
    def __init__(self, tlst):
        super().__init__(tlst, OpCode.CPUI_INT_SLESSEQUAL, "s<=", TYPE_BOOL, TYPE_INT)
        from ghidra.ir.op import PcodeOp as PcOp
        self.opflags = PcOp.binary | PcOp.booloutput
        self.addlflags = TypeOp.inherits_sign
    def propagateType(self, alttype, op, invn, outvn, inslot, outslot):
        if inslot == -1 or outslot == -1:
            return None
        if hasattr(alttype, 'getMetatype') and alttype.getMetatype() != TYPE_INT:
            return None
        return alttype

class TypeOpIntLess(TypeOpBinary):
    """CPUI_INT_LESS."""
    def __init__(self, tlst):
        super().__init__(tlst, OpCode.CPUI_INT_LESS, "<", TYPE_BOOL, TYPE_UINT)
        from ghidra.ir.op import PcodeOp as PcOp
        self.opflags = PcOp.binary | PcOp.booloutput
        self.addlflags = TypeOp.inherits_sign
    def propagateType(self, alttype, op, invn, outvn, inslot, outslot):
        return TypeOpIntEqual.propagateAcrossCompare(alttype, self.tlst, invn, outvn, inslot, outslot)

class TypeOpIntLessEqual(TypeOpBinary):
    """CPUI_INT_LESSEQUAL."""
    def __init__(self, tlst):
        super().__init__(tlst, OpCode.CPUI_INT_LESSEQUAL, "<=", TYPE_BOOL, TYPE_UINT)
        from ghidra.ir.op import PcodeOp as PcOp
        self.opflags = PcOp.binary | PcOp.booloutput
        self.addlflags = TypeOp.inherits_sign
    def propagateType(self, alttype, op, invn, outvn, inslot, outslot):
        return TypeOpIntEqual.propagateAcrossCompare(alttype, self.tlst, invn, outvn, inslot, outslot)

class TypeOpIntZext(TypeOpFunc):
    """CPUI_INT_ZEXT — zero extension."""
    def __init__(self, tlst):
        super().__init__(tlst, OpCode.CPUI_INT_ZEXT, "ZEXT", TYPE_UINT, TYPE_UINT)
        from ghidra.ir.op import PcodeOp as PcOp
        self.opflags = PcOp.unary
    def getOperatorName(self, op) -> str:
        return f"{self.name}{op.getIn(0).getSize()}{op.getOut().getSize()}"
    def getOutputToken(self, op, castStrategy=None):
        return self.tlst.getBase(op.getOut().getSize(), TYPE_UINT) if op.getOut() else None
    def propagateType(self, alttype, op, invn, outvn, inslot, outslot):
        if inslot == 0 and outslot == -1:
            return alttype
        return None

class TypeOpIntSext(TypeOpFunc):
    """CPUI_INT_SEXT — sign extension."""
    def __init__(self, tlst):
        super().__init__(tlst, OpCode.CPUI_INT_SEXT, "SEXT", TYPE_INT, TYPE_INT)
        from ghidra.ir.op import PcodeOp as PcOp
        self.opflags = PcOp.unary
    def getOperatorName(self, op) -> str:
        return f"{self.name}{op.getIn(0).getSize()}{op.getOut().getSize()}"
    def getOutputToken(self, op, castStrategy=None):
        return self.tlst.getBase(op.getOut().getSize(), TYPE_INT) if op.getOut() else None
    def propagateType(self, alttype, op, invn, outvn, inslot, outslot):
        if inslot == 0 and outslot == -1:
            return alttype
        return None

class TypeOpIntAdd(TypeOpBinary):
    """CPUI_INT_ADD — addition, pointer arithmetic."""
    def __init__(self, tlst):
        super().__init__(tlst, OpCode.CPUI_INT_ADD, "+", TYPE_INT, TYPE_INT)
        from ghidra.ir.op import PcodeOp as PcOp
        self.opflags = PcOp.binary | PcOp.commutative
        self.addlflags = TypeOp.arithmetic_op | TypeOp.inherits_sign
    def propagateType(self, alttype, op, invn, outvn, inslot, outslot):
        meta = alttype.getMetatype() if hasattr(alttype, 'getMetatype') else TYPE_UNKNOWN
        if meta != TYPE_PTR:
            if meta != TYPE_INT and meta != TYPE_UINT:
                return None
            if outslot != 1 or not (hasattr(op.getIn(1), 'isConstant') and op.getIn(1).isConstant()):
                return None
        elif inslot != -1 and outslot != -1:
            return None  # Must propagate input <-> output for pointers
        if hasattr(outvn, 'isConstant') and outvn.isConstant() and meta != TYPE_PTR:
            return alttype
        elif inslot == -1:
            return None  # Don't propagate pointer types output->input
        else:
            return TypeOpIntAdd.propagateAddIn2Out(alttype, self.tlst, op, inslot)
    @staticmethod
    def propagateAddIn2Out(alttype, typegrp, op, inslot):
        """Propagate a pointer data-type through an ADD from input to output."""
        if not hasattr(alttype, 'getMetatype') or alttype.getMetatype() != TYPE_PTR:
            return None
        if hasattr(alttype, 'getPtrTo'):
            ptrto = alttype.getPtrTo()
            align = ptrto.getAlignSize() if hasattr(ptrto, 'getAlignSize') else ptrto.getSize()
        else:
            align = 1
        cmd = TypeOpIntAdd.propagateAddPointer(op, inslot, align)
        if cmd == 2:
            return None  # Doesn't look like a good pointer add
        if cmd == 3 or cmd == 0:
            return alttype  # Propagate unchanged
        return alttype  # cmd == 1: propagate with offset
    @staticmethod
    def propagateAddPointer(op, slot: int, sz: int) -> int:
        """Determine how a pointer propagates through ADD/PTRADD/PTRSUB.

        Returns:
          0 = adding zero constant
          1 = adding non-zero constant
          2 = don't propagate
          3 = propagate unchanged (variable index)
        """
        opc = op.code() if hasattr(op, 'code') else op.getOpcode()
        if opc == OpCode.CPUI_PTRADD:
            if slot != 0:
                return 2
            constvn = op.getIn(1)
            if hasattr(constvn, 'isConstant') and constvn.isConstant():
                mult = op.getIn(2).getOffset()
                off = (constvn.getOffset() * mult) & ((1 << (8 * constvn.getSize())) - 1)
                return 0 if off == 0 else 1
            if sz != 0:
                mult = op.getIn(2).getOffset()
                if mult % sz != 0:
                    return 2
            return 3
        if opc == OpCode.CPUI_PTRSUB:
            if slot != 0:
                return 2
            off = op.getIn(1).getOffset()
            return 0 if off == 0 else 1
        if opc == OpCode.CPUI_INT_ADD:
            othervn = op.getIn(1 - slot)
            if not (hasattr(othervn, 'isConstant') and othervn.isConstant()):
                if sz == 1:
                    return 3
                return 2
            off = othervn.getOffset()
            return 0 if off == 0 else 1
        return 2

class TypeOpIntSub(TypeOpBinary):
    """CPUI_INT_SUB — subtraction."""
    def __init__(self, tlst):
        super().__init__(tlst, OpCode.CPUI_INT_SUB, "-", TYPE_INT, TYPE_INT)
        from ghidra.ir.op import PcodeOp as PcOp
        self.opflags = PcOp.binary
        self.addlflags = TypeOp.arithmetic_op | TypeOp.inherits_sign
    def propagateType(self, alttype, op, invn, outvn, inslot, outslot):
        if hasattr(alttype, 'getMetatype') and alttype.getMetatype() == TYPE_PTR:
            if inslot == 0 and outslot == -1:
                return alttype
        return None

class TypeOpIntCarry(TypeOpFunc):
    """CPUI_INT_CARRY."""
    def __init__(self, tlst):
        super().__init__(tlst, OpCode.CPUI_INT_CARRY, "CARRY", TYPE_BOOL, TYPE_UINT)
        from ghidra.ir.op import PcodeOp as PcOp
        self.opflags = PcOp.binary | PcOp.commutative | PcOp.booloutput
        self.addlflags = TypeOp.arithmetic_op
    def getOperatorName(self, op) -> str:
        return f"{self.name}{op.getIn(0).getSize()}"
    def propagateType(self, alttype, op, invn, outvn, inslot, outslot):
        return None

class TypeOpIntScarry(TypeOpFunc):
    """CPUI_INT_SCARRY."""
    def __init__(self, tlst):
        super().__init__(tlst, OpCode.CPUI_INT_SCARRY, "SCARRY", TYPE_BOOL, TYPE_INT)
        from ghidra.ir.op import PcodeOp as PcOp
        self.opflags = PcOp.binary | PcOp.commutative | PcOp.booloutput
        self.addlflags = TypeOp.arithmetic_op
    def getOperatorName(self, op) -> str:
        return f"{self.name}{op.getIn(0).getSize()}"
    def propagateType(self, alttype, op, invn, outvn, inslot, outslot):
        return None

class TypeOpIntSborrow(TypeOpFunc):
    """CPUI_INT_SBORROW."""
    def __init__(self, tlst):
        super().__init__(tlst, OpCode.CPUI_INT_SBORROW, "SBORROW", TYPE_BOOL, TYPE_INT)
        from ghidra.ir.op import PcodeOp as PcOp
        self.opflags = PcOp.binary | PcOp.booloutput
        self.addlflags = TypeOp.arithmetic_op
    def getOperatorName(self, op) -> str:
        return f"{self.name}{op.getIn(0).getSize()}"
    def propagateType(self, alttype, op, invn, outvn, inslot, outslot):
        return None

class TypeOpInt2Comp(TypeOpUnary):
    """CPUI_INT_2COMP — two's complement negate."""
    def __init__(self, tlst):
        super().__init__(tlst, OpCode.CPUI_INT_2COMP, "-", TYPE_INT, TYPE_INT)
    def propagateType(self, alttype, op, invn, outvn, inslot, outslot):
        return alttype if inslot == 0 and outslot == -1 else None

class TypeOpIntNegate(TypeOpUnary):
    """CPUI_INT_NEGATE — bitwise negate."""
    def __init__(self, tlst):
        super().__init__(tlst, OpCode.CPUI_INT_NEGATE, "~", TYPE_UINT, TYPE_UINT)
    def propagateType(self, alttype, op, invn, outvn, inslot, outslot):
        return alttype if inslot == 0 and outslot == -1 else None

class TypeOpIntXor(TypeOpBinary):
    """CPUI_INT_XOR."""
    def __init__(self, tlst):
        super().__init__(tlst, OpCode.CPUI_INT_XOR, "^", TYPE_UINT, TYPE_UINT)
        from ghidra.ir.op import PcodeOp as PcOp
        self.opflags = PcOp.binary | PcOp.commutative
        self.addlflags = TypeOp.logical_op | TypeOp.inherits_sign
    def propagateType(self, alttype, op, invn, outvn, inslot, outslot):
        is_enum = hasattr(alttype, 'isEnumType') and alttype.isEnumType()
        if not is_enum:
            meta = alttype.getMetatype() if hasattr(alttype, 'getMetatype') else TYPE_UNKNOWN
            if meta != TYPE_FLOAT:
                return None
            if TypeOp.floatSignManipulation(op) == OpCode.CPUI_MAX:
                return None
        return alttype

class TypeOpIntAnd(TypeOpBinary):
    """CPUI_INT_AND."""
    def __init__(self, tlst):
        super().__init__(tlst, OpCode.CPUI_INT_AND, "&", TYPE_UINT, TYPE_UINT)
        from ghidra.ir.op import PcodeOp as PcOp
        self.opflags = PcOp.binary | PcOp.commutative
        self.addlflags = TypeOp.logical_op | TypeOp.inherits_sign
    def propagateType(self, alttype, op, invn, outvn, inslot, outslot):
        is_enum = hasattr(alttype, 'isEnumType') and alttype.isEnumType()
        if not is_enum:
            meta = alttype.getMetatype() if hasattr(alttype, 'getMetatype') else TYPE_UNKNOWN
            if meta != TYPE_FLOAT:
                return None
            if TypeOp.floatSignManipulation(op) == OpCode.CPUI_MAX:
                return None
        return alttype

class TypeOpIntOr(TypeOpBinary):
    """CPUI_INT_OR."""
    def __init__(self, tlst):
        super().__init__(tlst, OpCode.CPUI_INT_OR, "|", TYPE_UINT, TYPE_UINT)
        from ghidra.ir.op import PcodeOp as PcOp
        self.opflags = PcOp.binary | PcOp.commutative
        self.addlflags = TypeOp.logical_op | TypeOp.inherits_sign
    def propagateType(self, alttype, op, invn, outvn, inslot, outslot):
        if not (hasattr(alttype, 'isEnumType') and alttype.isEnumType()):
            return None  # Only propagate enums for OR
        return alttype

class TypeOpIntLeft(TypeOpBinary):
    """CPUI_INT_LEFT — left shift."""
    def __init__(self, tlst):
        super().__init__(tlst, OpCode.CPUI_INT_LEFT, "<<", TYPE_INT, TYPE_INT)
        from ghidra.ir.op import PcodeOp as PcOp
        self.opflags = PcOp.binary
        self.addlflags = TypeOp.inherits_sign | TypeOp.inherits_sign_zero | TypeOp.shift_op
    def propagateType(self, alttype, op, invn, outvn, inslot, outslot):
        if inslot == 0 and outslot == -1:
            return alttype
        return None

class TypeOpIntRight(TypeOpBinary):
    """CPUI_INT_RIGHT — logical right shift."""
    def __init__(self, tlst):
        super().__init__(tlst, OpCode.CPUI_INT_RIGHT, ">>", TYPE_UINT, TYPE_UINT)
        from ghidra.ir.op import PcodeOp as PcOp
        self.opflags = PcOp.binary
        self.addlflags = TypeOp.inherits_sign | TypeOp.inherits_sign_zero | TypeOp.shift_op
    def propagateType(self, alttype, op, invn, outvn, inslot, outslot):
        if inslot == 0 and outslot == -1:
            return alttype
        return None

class TypeOpIntSright(TypeOpBinary):
    """CPUI_INT_SRIGHT — arithmetic right shift."""
    def __init__(self, tlst):
        super().__init__(tlst, OpCode.CPUI_INT_SRIGHT, "s>>", TYPE_INT, TYPE_INT)
        from ghidra.ir.op import PcodeOp as PcOp
        self.opflags = PcOp.binary
        self.addlflags = TypeOp.inherits_sign | TypeOp.inherits_sign_zero | TypeOp.shift_op
    def propagateType(self, alttype, op, invn, outvn, inslot, outslot):
        if inslot == 0 and outslot == -1:
            return alttype
        return None

class TypeOpIntMult(TypeOpBinary):
    """CPUI_INT_MULT."""
    def __init__(self, tlst):
        super().__init__(tlst, OpCode.CPUI_INT_MULT, "*", TYPE_INT, TYPE_INT)
    def propagateType(self, alttype, op, invn, outvn, inslot, outslot):
        return None

class TypeOpIntDiv(TypeOpBinary):
    """CPUI_INT_DIV — unsigned division."""
    def __init__(self, tlst):
        super().__init__(tlst, OpCode.CPUI_INT_DIV, "/", TYPE_UINT, TYPE_UINT)
    def propagateType(self, alttype, op, invn, outvn, inslot, outslot):
        return None

class TypeOpIntSdiv(TypeOpBinary):
    """CPUI_INT_SDIV — signed division."""
    def __init__(self, tlst):
        super().__init__(tlst, OpCode.CPUI_INT_SDIV, "s/", TYPE_INT, TYPE_INT)
    def propagateType(self, alttype, op, invn, outvn, inslot, outslot):
        return None

class TypeOpIntRem(TypeOpBinary):
    """CPUI_INT_REM — unsigned remainder."""
    def __init__(self, tlst):
        super().__init__(tlst, OpCode.CPUI_INT_REM, "%", TYPE_UINT, TYPE_UINT)
    def propagateType(self, alttype, op, invn, outvn, inslot, outslot):
        return None

class TypeOpIntSrem(TypeOpBinary):
    """CPUI_INT_SREM — signed remainder."""
    def __init__(self, tlst):
        super().__init__(tlst, OpCode.CPUI_INT_SREM, "s%", TYPE_INT, TYPE_INT)
    def propagateType(self, alttype, op, invn, outvn, inslot, outslot):
        return None

class TypeOpBoolNegate(TypeOpUnary):
    """CPUI_BOOL_NEGATE."""
    def __init__(self, tlst):
        super().__init__(tlst, OpCode.CPUI_BOOL_NEGATE, "!", TYPE_BOOL, TYPE_BOOL)
    def propagateType(self, alttype, op, invn, outvn, inslot, outslot):
        return None

class TypeOpBoolXor(TypeOpBinary):
    """CPUI_BOOL_XOR."""
    def __init__(self, tlst):
        super().__init__(tlst, OpCode.CPUI_BOOL_XOR, "^^", TYPE_BOOL, TYPE_BOOL)
    def propagateType(self, alttype, op, invn, outvn, inslot, outslot):
        return None

class TypeOpBoolAnd(TypeOpBinary):
    """CPUI_BOOL_AND."""
    def __init__(self, tlst):
        super().__init__(tlst, OpCode.CPUI_BOOL_AND, "&&", TYPE_BOOL, TYPE_BOOL)
    def propagateType(self, alttype, op, invn, outvn, inslot, outslot):
        return None

class TypeOpBoolOr(TypeOpBinary):
    """CPUI_BOOL_OR."""
    def __init__(self, tlst):
        super().__init__(tlst, OpCode.CPUI_BOOL_OR, "||", TYPE_BOOL, TYPE_BOOL)
    def propagateType(self, alttype, op, invn, outvn, inslot, outslot):
        return None

class TypeOpFloatEqual(TypeOpBinary):
    """CPUI_FLOAT_EQUAL."""
    def __init__(self, tlst):
        super().__init__(tlst, OpCode.CPUI_FLOAT_EQUAL, "f==", TYPE_BOOL, TYPE_FLOAT)
    def propagateType(self, alttype, op, invn, outvn, inslot, outslot):
        return None

class TypeOpFloatNotEqual(TypeOpBinary):
    """CPUI_FLOAT_NOTEQUAL."""
    def __init__(self, tlst):
        super().__init__(tlst, OpCode.CPUI_FLOAT_NOTEQUAL, "f!=", TYPE_BOOL, TYPE_FLOAT)
    def propagateType(self, alttype, op, invn, outvn, inslot, outslot):
        return None

class TypeOpFloatLess(TypeOpBinary):
    """CPUI_FLOAT_LESS."""
    def __init__(self, tlst):
        super().__init__(tlst, OpCode.CPUI_FLOAT_LESS, "f<", TYPE_BOOL, TYPE_FLOAT)
    def propagateType(self, alttype, op, invn, outvn, inslot, outslot):
        return None

class TypeOpFloatLessEqual(TypeOpBinary):
    """CPUI_FLOAT_LESSEQUAL."""
    def __init__(self, tlst):
        super().__init__(tlst, OpCode.CPUI_FLOAT_LESSEQUAL, "f<=", TYPE_BOOL, TYPE_FLOAT)
    def propagateType(self, alttype, op, invn, outvn, inslot, outslot):
        return None

class TypeOpFloatNan(TypeOpUnary):
    """CPUI_FLOAT_NAN."""
    def __init__(self, tlst):
        super().__init__(tlst, OpCode.CPUI_FLOAT_NAN, "NAN", TYPE_BOOL, TYPE_FLOAT)
    def propagateType(self, alttype, op, invn, outvn, inslot, outslot):
        return None

class TypeOpFloatAdd(TypeOpBinary):
    """CPUI_FLOAT_ADD."""
    def __init__(self, tlst):
        super().__init__(tlst, OpCode.CPUI_FLOAT_ADD, "f+", TYPE_FLOAT, TYPE_FLOAT)
    def propagateType(self, alttype, op, invn, outvn, inslot, outslot):
        return alttype if outslot == -1 else None

class TypeOpFloatDiv(TypeOpBinary):
    """CPUI_FLOAT_DIV."""
    def __init__(self, tlst):
        super().__init__(tlst, OpCode.CPUI_FLOAT_DIV, "f/", TYPE_FLOAT, TYPE_FLOAT)
    def propagateType(self, alttype, op, invn, outvn, inslot, outslot):
        return None

class TypeOpFloatMult(TypeOpBinary):
    """CPUI_FLOAT_MULT."""
    def __init__(self, tlst):
        super().__init__(tlst, OpCode.CPUI_FLOAT_MULT, "f*", TYPE_FLOAT, TYPE_FLOAT)
    def propagateType(self, alttype, op, invn, outvn, inslot, outslot):
        return None

class TypeOpFloatSub(TypeOpBinary):
    """CPUI_FLOAT_SUB."""
    def __init__(self, tlst):
        super().__init__(tlst, OpCode.CPUI_FLOAT_SUB, "f-", TYPE_FLOAT, TYPE_FLOAT)
    def propagateType(self, alttype, op, invn, outvn, inslot, outslot):
        return None

class TypeOpFloatNeg(TypeOpUnary):
    """CPUI_FLOAT_NEG."""
    def __init__(self, tlst):
        super().__init__(tlst, OpCode.CPUI_FLOAT_NEG, "f-", TYPE_FLOAT, TYPE_FLOAT)
    def propagateType(self, alttype, op, invn, outvn, inslot, outslot):
        return alttype if inslot == 0 and outslot == -1 else None

class TypeOpFloatAbs(TypeOpUnary):
    """CPUI_FLOAT_ABS."""
    def __init__(self, tlst):
        super().__init__(tlst, OpCode.CPUI_FLOAT_ABS, "ABS", TYPE_FLOAT, TYPE_FLOAT)
    def propagateType(self, alttype, op, invn, outvn, inslot, outslot):
        return alttype if inslot == 0 and outslot == -1 else None

class TypeOpFloatSqrt(TypeOpUnary):
    """CPUI_FLOAT_SQRT."""
    def __init__(self, tlst):
        super().__init__(tlst, OpCode.CPUI_FLOAT_SQRT, "SQRT", TYPE_FLOAT, TYPE_FLOAT)
    def propagateType(self, alttype, op, invn, outvn, inslot, outslot):
        return None

class TypeOpFloatInt2Float(TypeOpUnary):
    """CPUI_FLOAT_INT2FLOAT."""
    def __init__(self, tlst):
        super().__init__(tlst, OpCode.CPUI_FLOAT_INT2FLOAT, "INT2FLOAT", TYPE_FLOAT, TYPE_INT)
    def propagateType(self, alttype, op, invn, outvn, inslot, outslot):
        return None

class TypeOpFloatFloat2Float(TypeOpUnary):
    """CPUI_FLOAT_FLOAT2FLOAT."""
    def __init__(self, tlst):
        super().__init__(tlst, OpCode.CPUI_FLOAT_FLOAT2FLOAT, "FLOAT2FLOAT", TYPE_FLOAT, TYPE_FLOAT)
    def propagateType(self, alttype, op, invn, outvn, inslot, outslot):
        return None

class TypeOpFloatTrunc(TypeOpUnary):
    """CPUI_FLOAT_TRUNC."""
    def __init__(self, tlst):
        super().__init__(tlst, OpCode.CPUI_FLOAT_TRUNC, "TRUNC", TYPE_INT, TYPE_FLOAT)
    def propagateType(self, alttype, op, invn, outvn, inslot, outslot):
        return None

class TypeOpFloatCeil(TypeOpUnary):
    """CPUI_FLOAT_CEIL."""
    def __init__(self, tlst):
        super().__init__(tlst, OpCode.CPUI_FLOAT_CEIL, "CEIL", TYPE_FLOAT, TYPE_FLOAT)
    def propagateType(self, alttype, op, invn, outvn, inslot, outslot):
        return None

class TypeOpFloatFloor(TypeOpUnary):
    """CPUI_FLOAT_FLOOR."""
    def __init__(self, tlst):
        super().__init__(tlst, OpCode.CPUI_FLOAT_FLOOR, "FLOOR", TYPE_FLOAT, TYPE_FLOAT)
    def propagateType(self, alttype, op, invn, outvn, inslot, outslot):
        return None

class TypeOpFloatRound(TypeOpUnary):
    """CPUI_FLOAT_ROUND."""
    def __init__(self, tlst):
        super().__init__(tlst, OpCode.CPUI_FLOAT_ROUND, "ROUND", TYPE_FLOAT, TYPE_FLOAT)
    def propagateType(self, alttype, op, invn, outvn, inslot, outslot):
        return None

class TypeOpPiece(TypeOpFunc):
    """CPUI_PIECE — concatenation of two values."""
    def __init__(self, tlst):
        super().__init__(tlst, OpCode.CPUI_PIECE, "CONCAT", TYPE_UNKNOWN, TYPE_UNKNOWN)
        from ghidra.ir.op import PcodeOp as PcOp
        self.opflags = PcOp.binary
    def getOperatorName(self, op) -> str:
        return f"{self.name}{op.getIn(0).getSize()}{op.getIn(1).getSize()}"
    def getInputCast(self, op, slot, castStrategy=None):
        return None  # Never need a cast into a PIECE
    def propagateType(self, alttype, op, invn, outvn, inslot, outslot):
        if inslot != -1:
            return None
        return alttype  # Simplified: propagate output type to input

class TypeOpSubpiece(TypeOpFunc):
    """CPUI_SUBPIECE — extraction of sub-value."""
    def __init__(self, tlst):
        super().__init__(tlst, OpCode.CPUI_SUBPIECE, "SUB", TYPE_UNKNOWN, TYPE_UNKNOWN)
        from ghidra.ir.op import PcodeOp as PcOp
        self.opflags = PcOp.binary
    def getOperatorName(self, op) -> str:
        return f"{self.name}{op.getIn(0).getSize()}{op.getOut().getSize()}"
    def getInputCast(self, op, slot, castStrategy=None):
        return None  # Never need a cast into a SUBPIECE
    def propagateType(self, alttype, op, invn, outvn, inslot, outslot):
        if inslot != 0 or outslot != -1:
            return None  # Propagation must be from in0 to out
        while alttype is not None and alttype.getSize() != outvn.getSize():
            if hasattr(alttype, 'getSubType'):
                alttype = alttype.getSubType(0, None)
            else:
                break
        return alttype

class TypeOpCast(TypeOp):
    """CPUI_CAST — explicit type cast."""
    def __init__(self, tlst):
        super().__init__(tlst, OpCode.CPUI_CAST, "CAST")
    def getInputLocal(self, op, slot):
        return self.tlst.getTypeVoid()
    def propagateType(self, alttype, op, invn, outvn, inslot, outslot):
        return None

class TypeOpPtradd(TypeOp):
    """CPUI_PTRADD — pointer + index*size."""
    def __init__(self, tlst):
        super().__init__(tlst, OpCode.CPUI_PTRADD, "+")
        from ghidra.ir.op import PcodeOp as PcOp
        self.opflags = PcOp.ternary | getattr(PcOp, 'nocollapse', 0)
        self.addlflags = TypeOp.arithmetic_op
    def getInputLocal(self, op, slot):
        return self.tlst.getBase(op.getIn(slot).getSize(), TYPE_INT)
    def getOutputLocal(self, op):
        return self.tlst.getBase(op.getOut().getSize(), TYPE_INT)
    def getOutputToken(self, op, castStrategy=None):
        return op.getIn(0).getHighTypeReadFacing(op) if hasattr(op.getIn(0), 'getHighTypeReadFacing') else None
    def propagateType(self, alttype, op, invn, outvn, inslot, outslot):
        if inslot == 2 or outslot == 2:
            return None
        if inslot != -1 and outslot != -1:
            return None  # Must propagate input <-> output
        meta = alttype.getMetatype() if hasattr(alttype, 'getMetatype') else TYPE_UNKNOWN
        if meta != TYPE_PTR:
            return None
        if inslot == -1:
            return None  # Don't propagate pointer output->input
        return TypeOpIntAdd.propagateAddIn2Out(alttype, self.tlst, op, inslot)

class TypeOpPtrsub(TypeOp):
    """CPUI_PTRSUB — pointer + constant offset."""
    def __init__(self, tlst):
        super().__init__(tlst, OpCode.CPUI_PTRSUB, "->")
        from ghidra.ir.op import PcodeOp as PcOp
        self.opflags = PcOp.binary | getattr(PcOp, 'nocollapse', 0)
        self.addlflags = TypeOp.arithmetic_op
    def getOutputLocal(self, op):
        return self.tlst.getBase(op.getOut().getSize(), TYPE_INT)
    def getInputLocal(self, op, slot):
        return self.tlst.getBase(op.getIn(slot).getSize(), TYPE_INT)
    def propagateType(self, alttype, op, invn, outvn, inslot, outslot):
        if inslot != -1 and outslot != -1:
            return None  # Must propagate input <-> output
        meta = alttype.getMetatype() if hasattr(alttype, 'getMetatype') else TYPE_UNKNOWN
        if meta != TYPE_PTR:
            return None
        if inslot == -1:
            return None  # Don't propagate pointer output->input
        return TypeOpIntAdd.propagateAddIn2Out(alttype, self.tlst, op, inslot)

class TypeOpMultiequal(TypeOp):
    """CPUI_MULTIEQUAL — SSA phi-node."""
    def __init__(self, tlst):
        super().__init__(tlst, OpCode.CPUI_MULTIEQUAL, "?")
        from ghidra.ir.op import PcodeOp as PcOp
        self.opflags = PcOp.special | PcOp.marker | getattr(PcOp, 'nocollapse', 0)
    def propagateType(self, alttype, op, invn, outvn, inslot, outslot):
        if inslot != -1 and outslot != -1:
            return None  # Must propagate input <-> output
        if hasattr(invn, 'isSpacebase') and invn.isSpacebase():
            if hasattr(self.tlst, 'getArch'):
                spc = self.tlst.getArch().getDefaultDataSpace()
                wordsz = spc.getWordSize() if hasattr(spc, 'getWordSize') else 1
                return self.tlst.getTypePointer(alttype.getSize(), self.tlst.getBase(1, TYPE_UNKNOWN), wordsz)
        return alttype

class TypeOpIndirect(TypeOp):
    """CPUI_INDIRECT — indirect effect."""
    def __init__(self, tlst):
        super().__init__(tlst, OpCode.CPUI_INDIRECT, "[]")
        from ghidra.ir.op import PcodeOp as PcOp
        self.opflags = PcOp.special | PcOp.marker | getattr(PcOp, 'nocollapse', 0)
    def propagateType(self, alttype, op, invn, outvn, inslot, outslot):
        if hasattr(op, 'isIndirectCreation') and op.isIndirectCreation():
            return None
        if inslot == 1 or outslot == 1:
            return None
        if inslot != -1 and outslot != -1:
            return None  # Must propagate input <-> output
        if hasattr(invn, 'isSpacebase') and invn.isSpacebase():
            if hasattr(self.tlst, 'getArch'):
                spc = self.tlst.getArch().getDefaultDataSpace()
                wordsz = spc.getWordSize() if hasattr(spc, 'getWordSize') else 1
                return self.tlst.getTypePointer(alttype.getSize(), self.tlst.getBase(1, TYPE_UNKNOWN), wordsz)
        return alttype

class TypeOpSegmentOp(TypeOp):
    """CPUI_SEGMENTOP."""
    def __init__(self, tlst):
        super().__init__(tlst, OpCode.CPUI_SEGMENTOP, "SEGMENTOP")
    def getOutputLocal(self, op):
        return self.tlst.getTypeVoid()

class TypeOpCpoolRef(TypeOp):
    """CPUI_CPOOLREF."""
    def __init__(self, tlst):
        super().__init__(tlst, OpCode.CPUI_CPOOLREF, "CPOOLREF")
    def getOutputLocal(self, op):
        return self.tlst.getTypeVoid()

class TypeOpNew(TypeOp):
    """CPUI_NEW."""
    def __init__(self, tlst):
        super().__init__(tlst, OpCode.CPUI_NEW, "NEW")
    def getOutputLocal(self, op):
        return self.tlst.getTypeVoid()

class TypeOpInsert(TypeOpFunc):
    """CPUI_INSERT."""
    def __init__(self, tlst):
        super().__init__(tlst, OpCode.CPUI_INSERT, "INSERT", TYPE_UNKNOWN, TYPE_INT)
        from ghidra.ir.op import PcodeOp as PcOp
        self.opflags = PcOp.ternary
    def getInputLocal(self, op, slot):
        if slot == 0:
            return self.tlst.getBase(op.getIn(slot).getSize(), TYPE_UNKNOWN)
        return super().getInputLocal(op, slot)
    def propagateType(self, alttype, op, invn, outvn, inslot, outslot):
        return None

class TypeOpExtract(TypeOpFunc):
    """CPUI_EXTRACT."""
    def __init__(self, tlst):
        super().__init__(tlst, OpCode.CPUI_EXTRACT, "EXTRACT", TYPE_INT, TYPE_INT)
        from ghidra.ir.op import PcodeOp as PcOp
        self.opflags = PcOp.ternary
    def getInputLocal(self, op, slot):
        if slot == 0:
            return self.tlst.getBase(op.getIn(slot).getSize(), TYPE_UNKNOWN)
        return super().getInputLocal(op, slot)
    def propagateType(self, alttype, op, invn, outvn, inslot, outslot):
        return None

class TypeOpPopcount(TypeOpFunc):
    """CPUI_POPCOUNT."""
    def __init__(self, tlst):
        super().__init__(tlst, OpCode.CPUI_POPCOUNT, "POPCOUNT", TYPE_INT, TYPE_UNKNOWN)
        from ghidra.ir.op import PcodeOp as PcOp
        self.opflags = PcOp.unary
    def propagateType(self, alttype, op, invn, outvn, inslot, outslot):
        return None

class TypeOpLzcount(TypeOpFunc):
    """CPUI_LZCOUNT."""
    def __init__(self, tlst):
        super().__init__(tlst, OpCode.CPUI_LZCOUNT, "LZCOUNT", TYPE_INT, TYPE_UNKNOWN)
        from ghidra.ir.op import PcodeOp as PcOp
        self.opflags = PcOp.unary
    def propagateType(self, alttype, op, invn, outvn, inslot, outslot):
        return None


def registerTypeOps(tlst: TypeFactory, trans=None) -> List[Optional[TypeOp]]:
    """Build all TypeOp objects indexed by OpCode value.

    Corresponds to TypeOp::registerInstructions in typeop.cc.
    Uses specialized subclasses for each opcode.
    """
    inst: List[Optional[TypeOp]] = [None] * int(OpCode.CPUI_MAX)
    behaviors = OpBehavior.registerInstructions(trans)

    def _reg(t: TypeOp) -> None:
        opc_val = int(t.opcode)
        if opc_val < len(behaviors) and behaviors[opc_val]:
            t.behave = behaviors[opc_val]
        inst[opc_val] = t

    _reg(TypeOpCopy(tlst))
    _reg(TypeOpLoad(tlst))
    _reg(TypeOpStore(tlst))
    _reg(TypeOpBranch(tlst))
    _reg(TypeOpCbranch(tlst))
    _reg(TypeOpBranchind(tlst))
    _reg(TypeOpCall(tlst))
    _reg(TypeOpCallind(tlst))
    _reg(TypeOpCallother(tlst))
    _reg(TypeOpReturn(tlst))

    _reg(TypeOpIntEqual(tlst))
    _reg(TypeOpIntNotEqual(tlst))
    _reg(TypeOpIntSless(tlst))
    _reg(TypeOpIntSlessEqual(tlst))
    _reg(TypeOpIntLess(tlst))
    _reg(TypeOpIntLessEqual(tlst))

    _reg(TypeOpIntZext(tlst))
    _reg(TypeOpIntSext(tlst))

    _reg(TypeOpIntAdd(tlst))
    _reg(TypeOpIntSub(tlst))
    _reg(TypeOpIntCarry(tlst))
    _reg(TypeOpIntScarry(tlst))
    _reg(TypeOpIntSborrow(tlst))

    _reg(TypeOpInt2Comp(tlst))
    _reg(TypeOpIntNegate(tlst))

    _reg(TypeOpIntXor(tlst))
    _reg(TypeOpIntAnd(tlst))
    _reg(TypeOpIntOr(tlst))
    _reg(TypeOpIntLeft(tlst))
    _reg(TypeOpIntRight(tlst))
    _reg(TypeOpIntSright(tlst))
    _reg(TypeOpIntMult(tlst))
    _reg(TypeOpIntDiv(tlst))
    _reg(TypeOpIntSdiv(tlst))
    _reg(TypeOpIntRem(tlst))
    _reg(TypeOpIntSrem(tlst))

    _reg(TypeOpBoolNegate(tlst))
    _reg(TypeOpBoolXor(tlst))
    _reg(TypeOpBoolAnd(tlst))
    _reg(TypeOpBoolOr(tlst))

    _reg(TypeOpFloatEqual(tlst))
    _reg(TypeOpFloatNotEqual(tlst))
    _reg(TypeOpFloatLess(tlst))
    _reg(TypeOpFloatLessEqual(tlst))
    _reg(TypeOpFloatNan(tlst))
    _reg(TypeOpFloatAdd(tlst))
    _reg(TypeOpFloatDiv(tlst))
    _reg(TypeOpFloatMult(tlst))
    _reg(TypeOpFloatSub(tlst))
    _reg(TypeOpFloatNeg(tlst))
    _reg(TypeOpFloatAbs(tlst))
    _reg(TypeOpFloatSqrt(tlst))
    _reg(TypeOpFloatInt2Float(tlst))
    _reg(TypeOpFloatFloat2Float(tlst))
    _reg(TypeOpFloatTrunc(tlst))
    _reg(TypeOpFloatCeil(tlst))
    _reg(TypeOpFloatFloor(tlst))
    _reg(TypeOpFloatRound(tlst))

    _reg(TypeOpMultiequal(tlst))
    _reg(TypeOpIndirect(tlst))
    _reg(TypeOpPiece(tlst))
    _reg(TypeOpSubpiece(tlst))
    _reg(TypeOpCast(tlst))
    _reg(TypeOpPtradd(tlst))
    _reg(TypeOpPtrsub(tlst))
    _reg(TypeOpSegmentOp(tlst))
    _reg(TypeOpCpoolRef(tlst))
    _reg(TypeOpNew(tlst))
    _reg(TypeOpInsert(tlst))
    _reg(TypeOpExtract(tlst))
    _reg(TypeOpPopcount(tlst))
    _reg(TypeOpLzcount(tlst))

    return inst
