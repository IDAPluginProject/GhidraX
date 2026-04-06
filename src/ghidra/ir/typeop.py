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
    TYPE_VOID, TYPE_SPACEBASE, TYPE_UNKNOWN, TYPE_INT, TYPE_UINT, TYPE_BOOL, TYPE_FLOAT, TYPE_PTR,
    TYPE_STRUCT, TYPE_UNION, TYPE_ARRAY,
)
from ghidra.core.space import IPTR_FSPEC

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
        if castStrategy is None:
            return None
        vn = op.getIn(slot)
        if vn is None or vn.isAnnotation():
            return None
        reqtype = op.inputTypeLocal(slot) if hasattr(op, "inputTypeLocal") else None
        curtype = vn.getHighTypeReadFacing(op) if hasattr(vn, "getHighTypeReadFacing") else None
        if reqtype is None or curtype is None:
            return None
        return castStrategy.castStandard(reqtype, curtype, False, True)

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
        from ghidra.ir.op import PcodeOp as PcOp
        self.opflags = PcOp.unary | getattr(PcOp, 'nocollapse', 0)
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
    def getInputCast(self, op, slot, castStrategy=None):
        """C++ ref: TypeOpLoad::getInputCast"""
        if slot != 1 or castStrategy is None:
            return None
        reqtype = op.getOut().getHighTypeDefFacing() if hasattr(op.getOut(), 'getHighTypeDefFacing') else None
        if reqtype is None:
            return None
        invn = op.getIn(1)
        curtype = invn.getHighTypeReadFacing(op) if hasattr(invn, 'getHighTypeReadFacing') else None
        if curtype is None:
            return None
        spc_vn = op.getIn(0)
        wordsz = 1
        if hasattr(spc_vn, 'getSpaceFromConst'):
            spc = spc_vn.getSpaceFromConst()
            if spc is not None and hasattr(spc, 'getWordSize'):
                wordsz = spc.getWordSize()
        if curtype.getMetatype() == TYPE_PTR:
            curtype = curtype.getPtrTo() if hasattr(curtype, 'getPtrTo') else curtype
        else:
            return self.tlst.getTypePointer(invn.getSize(), reqtype, wordsz)
        if curtype is not reqtype and curtype.getSize() == reqtype.getSize():
            curmeta = curtype.getMetatype()
            if curmeta != TYPE_STRUCT and curmeta != TYPE_ARRAY and curmeta != TYPE_UNION and curmeta != TYPE_SPACEBASE:
                if not (hasattr(invn, 'isImplied') and invn.isImplied() and
                        hasattr(invn, 'isWritten') and invn.isWritten() and
                        invn.getDef().code() == OpCode.CPUI_CAST):
                    return None  # Postpone cast to output
        reqtype = castStrategy.castStandard(reqtype, curtype, False, True)
        if reqtype is None:
            return None
        return self.tlst.getTypePointer(invn.getSize(), reqtype, wordsz)
    def getOutputToken(self, op, castStrategy=None):
        """C++ ref: TypeOpLoad::getOutputToken"""
        ct = op.getIn(1).getHighTypeReadFacing(op) if hasattr(op.getIn(1), 'getHighTypeReadFacing') else None
        if ct is not None and ct.getMetatype() == TYPE_PTR:
            ptrto = ct.getPtrTo() if hasattr(ct, 'getPtrTo') else None
            if ptrto is not None and ptrto.getSize() == op.getOut().getSize():
                return ptrto
        return op.getOut().getHighTypeDefFacing() if hasattr(op.getOut(), 'getHighTypeDefFacing') else None
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
    def getInputCast(self, op, slot, castStrategy=None):
        """C++ ref: TypeOpStore::getInputCast"""
        if slot == 0 or castStrategy is None:
            return None
        pointerVn = op.getIn(1)
        pointerType = pointerVn.getHighTypeReadFacing(op) if hasattr(pointerVn, 'getHighTypeReadFacing') else None
        if pointerType is None:
            return None
        pointedToType = pointerType
        valueType = op.getIn(2).getHighTypeReadFacing(op) if hasattr(op.getIn(2), 'getHighTypeReadFacing') else None
        if valueType is None:
            return None
        spc_vn = op.getIn(0)
        wordsz = 1
        if hasattr(spc_vn, 'getSpaceFromConst'):
            spc = spc_vn.getSpaceFromConst()
            if spc is not None and hasattr(spc, 'getWordSize'):
                wordsz = spc.getWordSize()
        if pointerType.getMetatype() == TYPE_PTR:
            pointedToType = pointerType.getPtrTo() if hasattr(pointerType, 'getPtrTo') else pointerType
            destSize = pointedToType.getSize()
        else:
            destSize = -1
        if destSize != valueType.getSize():
            if slot == 1:
                return self.tlst.getTypePointer(pointerVn.getSize(), valueType, wordsz)
            else:
                return None
        if slot == 1:
            if hasattr(pointerVn, 'isWritten') and pointerVn.isWritten() and pointerVn.getDef().code() == OpCode.CPUI_CAST:
                if hasattr(pointerVn, 'isImplied') and pointerVn.isImplied():
                    if hasattr(pointerVn, 'loneDescend') and pointerVn.loneDescend() == op:
                        newType = self.tlst.getTypePointer(pointerVn.getSize(), valueType, wordsz)
                        if pointerType is not newType:
                            return newType
            return None
        # slot == 2: cast the value, not the pointer
        return castStrategy.castStandard(pointedToType, valueType, False, True)
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
        from ghidra.ir.op import PcodeOp as PcOp
        self.opflags = PcOp.special | getattr(PcOp, 'branch', 0) | getattr(PcOp, 'coderef', 0) | getattr(PcOp, 'nocollapse', 0)
    def getInputLocal(self, op, slot):
        return self.tlst.getTypeVoid()
    def getOutputLocal(self, op):
        return self.tlst.getTypeVoid()

class TypeOpCbranch(TypeOp):
    """CPUI_CBRANCH."""
    def __init__(self, tlst):
        super().__init__(tlst, OpCode.CPUI_CBRANCH, "CBRANCH")
        from ghidra.ir.op import PcodeOp as PcOp
        self.opflags = PcOp.special | getattr(PcOp, 'branch', 0) | getattr(PcOp, 'coderef', 0) | getattr(PcOp, 'nocollapse', 0)
    def getInputLocal(self, op, slot):
        """C++ ref: TypeOpCbranch::getInputLocal"""
        if slot == 1:
            return self.tlst.getBase(op.getIn(1).getSize(), TYPE_BOOL)
        # slot 0: code pointer
        td = self.tlst.getTypeCode()
        vn0 = op.getIn(0)
        spc = vn0.getSpace() if hasattr(vn0, 'getSpace') else None
        wordsz = spc.getWordSize() if spc is not None and hasattr(spc, 'getWordSize') else 1
        return self.tlst.getTypePointer(vn0.getSize(), td, wordsz)
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
        from ghidra.ir.op import PcodeOp as PcOp
        self.opflags = PcOp.special | getattr(PcOp, 'call', 0) | getattr(PcOp, 'has_callspec', 0) | getattr(PcOp, 'coderef', 0) | getattr(PcOp, 'nocollapse', 0)
    def getInputLocal(self, op, slot):
        """C++ ref: TypeOpCall::getInputLocal"""
        vn = op.getIn(0)
        if slot == 0 or not (hasattr(vn, 'getSpace') and hasattr(vn.getSpace(), 'getType') and vn.getSpace().getType() == IPTR_FSPEC):
            return TypeOp.getInputLocal(self, op, slot)
        try:
            from ghidra.fspec.fspec import FuncCallSpecs
            fc = FuncCallSpecs.getFspecFromConst(vn.getAddr())
            if fc is None:
                return TypeOp.getInputLocal(self, op, slot)
            param = fc.getParam(slot - 1)
            if param is not None:
                if hasattr(param, 'isTypeLocked') and param.isTypeLocked():
                    ct = param.getType()
                    if ct.getMetatype() != TYPE_VOID and ct.getSize() <= op.getIn(slot).getSize():
                        return ct
                elif hasattr(param, 'isThisPointer') and param.isThisPointer():
                    ct = param.getType()
                    if ct.getMetatype() == TYPE_PTR and hasattr(ct, 'getPtrTo') and ct.getPtrTo().getMetatype() == TYPE_STRUCT:
                        return ct
        except Exception:
            pass
        return TypeOp.getInputLocal(self, op, slot)
    def getOutputLocal(self, op):
        """C++ ref: TypeOpCall::getOutputLocal"""
        vn = op.getIn(0)
        if not (hasattr(vn, 'getSpace') and hasattr(vn.getSpace(), 'getType') and vn.getSpace().getType() == IPTR_FSPEC):
            return TypeOp.getOutputLocal(self, op)
        try:
            from ghidra.fspec.fspec import FuncCallSpecs
            fc = FuncCallSpecs.getFspecFromConst(vn.getAddr())
            if fc is None:
                return TypeOp.getOutputLocal(self, op)
            if not fc.isOutputLocked():
                return TypeOp.getOutputLocal(self, op)
            ct = fc.getOutputType()
            if ct.getMetatype() == TYPE_VOID:
                return TypeOp.getOutputLocal(self, op)
            return ct
        except Exception:
            pass
        return TypeOp.getOutputLocal(self, op)

class TypeOpCallind(TypeOp):
    """CPUI_CALLIND."""
    def __init__(self, tlst):
        super().__init__(tlst, OpCode.CPUI_CALLIND, "CALLIND")
        from ghidra.ir.op import PcodeOp as PcOp
        self.opflags = PcOp.special | getattr(PcOp, 'call', 0) | getattr(PcOp, 'has_callspec', 0) | getattr(PcOp, 'nocollapse', 0)
    def getInputLocal(self, op, slot):
        """C++ ref: TypeOpCallind::getInputLocal"""
        if slot == 0:
            td = self.tlst.getTypeCode()
            spc = op.getAddr().getSpace() if hasattr(op, 'getAddr') and hasattr(op.getAddr(), 'getSpace') else None
            wordsz = spc.getWordSize() if spc is not None and hasattr(spc, 'getWordSize') else 1
            return self.tlst.getTypePointer(op.getIn(0).getSize(), td, wordsz)
        try:
            bb = op.getParent() if hasattr(op, 'getParent') else None
            if bb is not None and hasattr(bb, 'getFuncdata'):
                fd = bb.getFuncdata()
                if fd is not None and hasattr(fd, 'getCallSpecs'):
                    fc = fd.getCallSpecs(op)
                    if fc is not None:
                        param = fc.getParam(slot - 1)
                        if param is not None:
                            if hasattr(param, 'isTypeLocked') and param.isTypeLocked():
                                ct = param.getType()
                                if ct.getMetatype() != TYPE_VOID:
                                    return ct
                            elif hasattr(param, 'isThisPointer') and param.isThisPointer():
                                ct = param.getType()
                                if ct.getMetatype() == TYPE_PTR and hasattr(ct, 'getPtrTo') and ct.getPtrTo().getMetatype() == TYPE_STRUCT:
                                    return ct
        except Exception:
            pass
        return TypeOp.getInputLocal(self, op, slot)
    def getOutputLocal(self, op):
        """C++ ref: TypeOpCallind::getOutputLocal"""
        try:
            bb = op.getParent() if hasattr(op, 'getParent') else None
            if bb is not None and hasattr(bb, 'getFuncdata'):
                fd = bb.getFuncdata()
                if fd is not None and hasattr(fd, 'getCallSpecs'):
                    fc = fd.getCallSpecs(op)
                    if fc is not None:
                        if not fc.isOutputLocked():
                            return TypeOp.getOutputLocal(self, op)
                        ct = fc.getOutputType()
                        if ct.getMetatype() == TYPE_VOID:
                            return TypeOp.getOutputLocal(self, op)
                        return ct
        except Exception:
            pass
        return TypeOp.getOutputLocal(self, op)

class TypeOpCallother(TypeOp):
    """CPUI_CALLOTHER."""
    def __init__(self, tlst):
        super().__init__(tlst, OpCode.CPUI_CALLOTHER, "CALLOTHER")
        from ghidra.ir.op import PcodeOp as PcOp
        self.opflags = PcOp.special | getattr(PcOp, 'call', 0) | getattr(PcOp, 'nocollapse', 0)
    def getInputLocal(self, op, slot):
        """C++ ref: TypeOpCallother::getInputLocal"""
        try:
            if hasattr(self.tlst, 'getArch') and self.tlst.getArch() is not None:
                glb = self.tlst.getArch()
                if hasattr(glb, 'userops'):
                    userOp = glb.userops.getOp(int(op.getIn(0).getOffset()))
                    if userOp is not None and hasattr(userOp, 'getInputLocal'):
                        res = userOp.getInputLocal(op, slot)
                        if res is not None:
                            return res
        except Exception:
            pass
        return TypeOp.getInputLocal(self, op, slot)
    def getOutputLocal(self, op):
        """C++ ref: TypeOpCallother::getOutputLocal"""
        try:
            if hasattr(self.tlst, 'getArch') and self.tlst.getArch() is not None:
                glb = self.tlst.getArch()
                if hasattr(glb, 'userops'):
                    userOp = glb.userops.getOp(int(op.getIn(0).getOffset()))
                    if userOp is not None and hasattr(userOp, 'getOutputLocal'):
                        res = userOp.getOutputLocal(op)
                        if res is not None:
                            return res
        except Exception:
            pass
        return TypeOp.getOutputLocal(self, op)

class TypeOpReturn(TypeOp):
    """CPUI_RETURN."""
    def __init__(self, tlst):
        super().__init__(tlst, OpCode.CPUI_RETURN, "RETURN")
        from ghidra.ir.op import PcodeOp as PcOp
        self.opflags = PcOp.special | getattr(PcOp, 'returns', 0) | getattr(PcOp, 'nocollapse', 0) | getattr(PcOp, 'return_copy', 0)
    def getInputLocal(self, op, slot):
        """C++ ref: TypeOpReturn::getInputLocal"""
        if slot == 0:
            return TypeOp.getInputLocal(self, op, slot)
        try:
            bb = op.getParent() if hasattr(op, 'getParent') else None
            if bb is None:
                return TypeOp.getInputLocal(self, op, slot)
            fd = bb.getFuncdata() if hasattr(bb, 'getFuncdata') else None
            if fd is None:
                return TypeOp.getInputLocal(self, op, slot)
            fp = fd.getFuncProto() if hasattr(fd, 'getFuncProto') else None
            if fp is None:
                return TypeOp.getInputLocal(self, op, slot)
            ct = fp.getOutputType()
            if ct.getMetatype() == TYPE_VOID or ct.getSize() != op.getIn(slot).getSize():
                return TypeOp.getInputLocal(self, op, slot)
            return ct
        except Exception:
            pass
        return TypeOp.getInputLocal(self, op, slot)
    def getOutputLocal(self, op):
        return self.tlst.getTypeVoid()

class TypeOpIntEqual(TypeOpBinary):
    """CPUI_INT_EQUAL."""
    def __init__(self, tlst):
        super().__init__(tlst, OpCode.CPUI_INT_EQUAL, "==", TYPE_BOOL, TYPE_INT)
        from ghidra.ir.op import PcodeOp as PcOp
        self.opflags = PcOp.binary | PcOp.booloutput | PcOp.commutative
        self.addlflags = TypeOp.inherits_sign
    def getInputCast(self, op, slot, castStrategy=None):
        if castStrategy is None:
            return None
        reqtype = op.getIn(0).getHighTypeReadFacing(op)
        othertype = op.getIn(1).getHighTypeReadFacing(op)
        if hasattr(othertype, 'typeOrder') and othertype.typeOrder(reqtype) < 0:
            reqtype = othertype
        if castStrategy.checkIntPromotionForCompare(op, slot):
            return reqtype
        othertype = op.getIn(slot).getHighTypeReadFacing(op)
        return castStrategy.castStandard(reqtype, othertype, False, False)
    def propagateType(self, alttype, op, invn, outvn, inslot, outslot):
        return TypeOpIntEqual.propagateAcrossCompare(alttype, self.tlst, invn, outvn, inslot, outslot)
    @staticmethod
    def propagateAcrossCompare(alttype, typegrp, invn, outvn, inslot, outslot):
        """Propagate a data-type across a comparison PcodeOp.

        C++ ref: TypeOpEqual::propagateAcrossCompare
        """
        if inslot == -1 or outslot == -1:
            return None
        if hasattr(invn, 'isSpacebase') and invn.isSpacebase():
            if hasattr(typegrp, 'getArch'):
                spc = typegrp.getArch().getDefaultDataSpace()
                wordsz = spc.getWordSize() if hasattr(spc, 'getWordSize') else 1
                return typegrp.getTypePointer(alttype.getSize(), typegrp.getBase(1, TYPE_UNKNOWN), wordsz)
        elif hasattr(alttype, 'isPointerRel') and alttype.isPointerRel() and not (hasattr(outvn, 'isConstant') and outvn.isConstant()):
            if hasattr(alttype, 'getParent') and hasattr(alttype, 'getByteOffset'):
                parent = alttype.getParent()
                if parent is not None and parent.getMetatype() == TYPE_STRUCT and alttype.getByteOffset() >= 0:
                    return typegrp.getTypePointer(alttype.getSize(), typegrp.getBase(1, TYPE_UNKNOWN),
                                                  alttype.getWordSize() if hasattr(alttype, 'getWordSize') else 1)
        return alttype

class TypeOpIntNotEqual(TypeOpBinary):
    """CPUI_INT_NOTEQUAL."""
    def __init__(self, tlst):
        super().__init__(tlst, OpCode.CPUI_INT_NOTEQUAL, "!=", TYPE_BOOL, TYPE_INT)
        from ghidra.ir.op import PcodeOp as PcOp
        self.opflags = PcOp.binary | PcOp.booloutput | PcOp.commutative
        self.addlflags = TypeOp.inherits_sign
    def getInputCast(self, op, slot, castStrategy=None):
        if castStrategy is None:
            return None
        reqtype = op.getIn(0).getHighTypeReadFacing(op)
        othertype = op.getIn(1).getHighTypeReadFacing(op)
        if hasattr(othertype, 'typeOrder') and othertype.typeOrder(reqtype) < 0:
            reqtype = othertype
        if castStrategy.checkIntPromotionForCompare(op, slot):
            return reqtype
        othertype = op.getIn(slot).getHighTypeReadFacing(op)
        return castStrategy.castStandard(reqtype, othertype, False, False)
    def propagateType(self, alttype, op, invn, outvn, inslot, outslot):
        return TypeOpIntEqual.propagateAcrossCompare(alttype, self.tlst, invn, outvn, inslot, outslot)

class TypeOpIntSless(TypeOpBinary):
    """CPUI_INT_SLESS."""
    def __init__(self, tlst):
        super().__init__(tlst, OpCode.CPUI_INT_SLESS, "s<", TYPE_BOOL, TYPE_INT)
        from ghidra.ir.op import PcodeOp as PcOp
        self.opflags = PcOp.binary | PcOp.booloutput
        self.addlflags = TypeOp.inherits_sign
    def getInputCast(self, op, slot, castStrategy=None):
        if castStrategy is None:
            return None
        reqtype = op.inputTypeLocal(slot)
        if castStrategy.checkIntPromotionForCompare(op, slot):
            return reqtype
        curtype = op.getIn(slot).getHighTypeReadFacing(op)
        return castStrategy.castStandard(reqtype, curtype, True, True)
    def propagateType(self, alttype, op, invn, outvn, inslot, outslot):
        if inslot == -1 or outslot == -1:
            return None
        if hasattr(alttype, 'getMetatype') and alttype.getMetatype() != TYPE_INT:
            return None
        return alttype

class TypeOpIntSlessEqual(TypeOpBinary):
    """CPUI_INT_SLESSEQUAL."""
    def __init__(self, tlst):
        super().__init__(tlst, OpCode.CPUI_INT_SLESSEQUAL, "s<=", TYPE_BOOL, TYPE_INT)
        from ghidra.ir.op import PcodeOp as PcOp
        self.opflags = PcOp.binary | PcOp.booloutput
        self.addlflags = TypeOp.inherits_sign
    def getInputCast(self, op, slot, castStrategy=None):
        if castStrategy is None:
            return None
        reqtype = op.inputTypeLocal(slot)
        if castStrategy.checkIntPromotionForCompare(op, slot):
            return reqtype
        curtype = op.getIn(slot).getHighTypeReadFacing(op)
        return castStrategy.castStandard(reqtype, curtype, True, True)
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
    def getInputCast(self, op, slot, castStrategy=None):
        if castStrategy is None:
            return None
        reqtype = op.inputTypeLocal(slot)
        if castStrategy.checkIntPromotionForCompare(op, slot):
            return reqtype
        curtype = op.getIn(slot).getHighTypeReadFacing(op)
        return castStrategy.castStandard(reqtype, curtype, True, False)
    def propagateType(self, alttype, op, invn, outvn, inslot, outslot):
        return TypeOpIntEqual.propagateAcrossCompare(alttype, self.tlst, invn, outvn, inslot, outslot)

class TypeOpIntLessEqual(TypeOpBinary):
    """CPUI_INT_LESSEQUAL."""
    def __init__(self, tlst):
        super().__init__(tlst, OpCode.CPUI_INT_LESSEQUAL, "<=", TYPE_BOOL, TYPE_UINT)
        from ghidra.ir.op import PcodeOp as PcOp
        self.opflags = PcOp.binary | PcOp.booloutput
        self.addlflags = TypeOp.inherits_sign
    def getInputCast(self, op, slot, castStrategy=None):
        if castStrategy is None:
            return None
        reqtype = op.inputTypeLocal(slot)
        if castStrategy.checkIntPromotionForCompare(op, slot):
            return reqtype
        curtype = op.getIn(slot).getHighTypeReadFacing(op)
        return castStrategy.castStandard(reqtype, curtype, True, False)
    def propagateType(self, alttype, op, invn, outvn, inslot, outslot):
        return TypeOpIntEqual.propagateAcrossCompare(alttype, self.tlst, invn, outvn, inslot, outslot)

class TypeOpIntZext(TypeOpFunc):
    """CPUI_INT_ZEXT — zero extension."""
    def __init__(self, tlst):
        super().__init__(tlst, OpCode.CPUI_INT_ZEXT, "ZEXT", TYPE_UINT, TYPE_UINT)
        from ghidra.ir.op import PcodeOp as PcOp
        self.opflags = PcOp.unary
    def getInputCast(self, op, slot, castStrategy=None):
        if castStrategy is None:
            return None
        reqtype = op.inputTypeLocal(slot)
        if castStrategy.checkIntPromotionForExtension(op):
            return reqtype
        curtype = op.getIn(slot).getHighTypeReadFacing(op)
        return castStrategy.castStandard(reqtype, curtype, True, False)
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
    def getInputCast(self, op, slot, castStrategy=None):
        if castStrategy is None:
            return None
        reqtype = op.inputTypeLocal(slot)
        if castStrategy.checkIntPromotionForExtension(op):
            return reqtype
        curtype = op.getIn(slot).getHighTypeReadFacing(op)
        return castStrategy.castStandard(reqtype, curtype, True, False)
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
    def getOutputToken(self, op, castStrategy=None):
        """C++ ref: TypeOpIntAdd::getOutputToken — use arithmetic typing rules."""
        if castStrategy is not None and hasattr(castStrategy, 'arithmeticOutputStandard'):
            return castStrategy.arithmeticOutputStandard(op)
        return op.outputTypeLocal() if hasattr(op, 'outputTypeLocal') else None
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
    def getOutputToken(self, op, castStrategy=None):
        if castStrategy is not None:
            return castStrategy.arithmeticOutputStandard(op)
        return self.getOutputLocal(op)
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
    def getOutputToken(self, op, castStrategy=None):
        if castStrategy is not None:
            return castStrategy.arithmeticOutputStandard(op)
        return self.getOutputLocal(op)
    def propagateType(self, alttype, op, invn, outvn, inslot, outslot):
        return alttype if inslot == 0 and outslot == -1 else None

class TypeOpIntNegate(TypeOpUnary):
    """CPUI_INT_NEGATE — bitwise negate."""
    def __init__(self, tlst):
        super().__init__(tlst, OpCode.CPUI_INT_NEGATE, "~", TYPE_UINT, TYPE_UINT)
    def getOutputToken(self, op, castStrategy=None):
        if castStrategy is not None:
            return castStrategy.arithmeticOutputStandard(op)
        return self.getOutputLocal(op)
    def propagateType(self, alttype, op, invn, outvn, inslot, outslot):
        return alttype if inslot == 0 and outslot == -1 else None

class TypeOpIntXor(TypeOpBinary):
    """CPUI_INT_XOR."""
    def __init__(self, tlst):
        super().__init__(tlst, OpCode.CPUI_INT_XOR, "^", TYPE_UINT, TYPE_UINT)
        from ghidra.ir.op import PcodeOp as PcOp
        self.opflags = PcOp.binary | PcOp.commutative
        self.addlflags = TypeOp.logical_op | TypeOp.inherits_sign
    def getOutputToken(self, op, castStrategy=None):
        if castStrategy is not None:
            return castStrategy.arithmeticOutputStandard(op)
        return self.getOutputLocal(op)
    def propagateType(self, alttype, op, invn, outvn, inslot, outslot):
        is_enum = hasattr(alttype, 'isEnumType') and alttype.isEnumType()
        if not is_enum:
            meta = alttype.getMetatype() if hasattr(alttype, 'getMetatype') else TYPE_UNKNOWN
            if meta != TYPE_FLOAT:
                return None
            if TypeOp.floatSignManipulation(op) == OpCode.CPUI_MAX:
                return None
        if hasattr(invn, 'isSpacebase') and invn.isSpacebase():
            if hasattr(self.tlst, 'getArch'):
                spc = self.tlst.getArch().getDefaultDataSpace()
                wordsz = spc.getWordSize() if hasattr(spc, 'getWordSize') else 1
                return self.tlst.getTypePointer(alttype.getSize(), self.tlst.getBase(1, TYPE_UNKNOWN), wordsz)
        return alttype

class TypeOpIntAnd(TypeOpBinary):
    """CPUI_INT_AND."""
    def __init__(self, tlst):
        super().__init__(tlst, OpCode.CPUI_INT_AND, "&", TYPE_UINT, TYPE_UINT)
        from ghidra.ir.op import PcodeOp as PcOp
        self.opflags = PcOp.binary | PcOp.commutative
        self.addlflags = TypeOp.logical_op | TypeOp.inherits_sign
    def getOutputToken(self, op, castStrategy=None):
        if castStrategy is not None:
            return castStrategy.arithmeticOutputStandard(op)
        return self.getOutputLocal(op)
    def propagateType(self, alttype, op, invn, outvn, inslot, outslot):
        is_enum = hasattr(alttype, 'isEnumType') and alttype.isEnumType()
        if not is_enum:
            meta = alttype.getMetatype() if hasattr(alttype, 'getMetatype') else TYPE_UNKNOWN
            if meta != TYPE_FLOAT:
                return None
            if TypeOp.floatSignManipulation(op) == OpCode.CPUI_MAX:
                return None
        if hasattr(invn, 'isSpacebase') and invn.isSpacebase():
            if hasattr(self.tlst, 'getArch'):
                spc = self.tlst.getArch().getDefaultDataSpace()
                wordsz = spc.getWordSize() if hasattr(spc, 'getWordSize') else 1
                return self.tlst.getTypePointer(alttype.getSize(), self.tlst.getBase(1, TYPE_UNKNOWN), wordsz)
        return alttype

class TypeOpIntOr(TypeOpBinary):
    """CPUI_INT_OR."""
    def __init__(self, tlst):
        super().__init__(tlst, OpCode.CPUI_INT_OR, "|", TYPE_UINT, TYPE_UINT)
        from ghidra.ir.op import PcodeOp as PcOp
        self.opflags = PcOp.binary | PcOp.commutative
        self.addlflags = TypeOp.logical_op | TypeOp.inherits_sign
    def getOutputToken(self, op, castStrategy=None):
        if castStrategy is not None:
            return castStrategy.arithmeticOutputStandard(op)
        return self.getOutputLocal(op)
    def propagateType(self, alttype, op, invn, outvn, inslot, outslot):
        if not (hasattr(alttype, 'isEnumType') and alttype.isEnumType()):
            return None  # Only propagate enums for OR
        if hasattr(invn, 'isSpacebase') and invn.isSpacebase():
            if hasattr(self.tlst, 'getArch'):
                spc = self.tlst.getArch().getDefaultDataSpace()
                wordsz = spc.getWordSize() if hasattr(spc, 'getWordSize') else 1
                return self.tlst.getTypePointer(alttype.getSize(), self.tlst.getBase(1, TYPE_UNKNOWN), wordsz)
        return alttype

class TypeOpIntLeft(TypeOpBinary):
    """CPUI_INT_LEFT — left shift."""
    def __init__(self, tlst):
        super().__init__(tlst, OpCode.CPUI_INT_LEFT, "<<", TYPE_INT, TYPE_INT)
        from ghidra.ir.op import PcodeOp as PcOp
        self.opflags = PcOp.binary
        self.addlflags = TypeOp.inherits_sign | TypeOp.inherits_sign_zero | TypeOp.shift_op
    def getInputLocal(self, op, slot):
        if slot == 1:
            return self.tlst.getBaseNoChar(op.getIn(1).getSize(), TYPE_INT)
        return super().getInputLocal(op, slot)
    def getOutputToken(self, op, castStrategy=None):
        res1 = op.getIn(0).getHighTypeReadFacing(op) if hasattr(op.getIn(0), 'getHighTypeReadFacing') else None
        if res1 is not None and res1.getMetatype() == TYPE_BOOL:
            res1 = self.tlst.getBase(res1.getSize(), TYPE_INT)
        return res1
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
    def getInputLocal(self, op, slot):
        if slot == 1:
            return self.tlst.getBaseNoChar(op.getIn(1).getSize(), TYPE_INT)
        return super().getInputLocal(op, slot)
    def getInputCast(self, op, slot, castStrategy=None):
        if castStrategy is None:
            return None
        if slot == 0:
            from ghidra.types.cast import IntPromotionCode
            vn = op.getIn(0)
            reqtype = op.inputTypeLocal(slot)
            curtype = vn.getHighTypeReadFacing(op)
            promoType = castStrategy.intPromotionType(vn)
            if promoType != int(IntPromotionCode.NO_PROMOTION) and (promoType & int(IntPromotionCode.UNSIGNED_EXTENSION)) == 0:
                return reqtype
            return castStrategy.castStandard(reqtype, curtype, True, True)
        return super().getInputCast(op, slot, castStrategy)
    def getOutputToken(self, op, castStrategy=None):
        res1 = op.getIn(0).getHighTypeReadFacing(op) if hasattr(op.getIn(0), 'getHighTypeReadFacing') else None
        if res1 is not None and res1.getMetatype() == TYPE_BOOL:
            res1 = self.tlst.getBase(res1.getSize(), TYPE_INT)
        return res1
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
    def getInputLocal(self, op, slot):
        if slot == 1:
            return self.tlst.getBaseNoChar(op.getIn(1).getSize(), TYPE_INT)
        return super().getInputLocal(op, slot)
    def getInputCast(self, op, slot, castStrategy=None):
        if castStrategy is None:
            return None
        if slot == 0:
            from ghidra.types.cast import IntPromotionCode
            vn = op.getIn(0)
            reqtype = op.inputTypeLocal(slot)
            curtype = vn.getHighTypeReadFacing(op)
            promoType = castStrategy.intPromotionType(vn)
            if promoType != int(IntPromotionCode.NO_PROMOTION) and (promoType & int(IntPromotionCode.SIGNED_EXTENSION)) == 0:
                return reqtype
            return castStrategy.castStandard(reqtype, curtype, True, True)
        return super().getInputCast(op, slot, castStrategy)
    def getOutputToken(self, op, castStrategy=None):
        res1 = op.getIn(0).getHighTypeReadFacing(op) if hasattr(op.getIn(0), 'getHighTypeReadFacing') else None
        if res1 is not None and res1.getMetatype() == TYPE_BOOL:
            res1 = self.tlst.getBase(res1.getSize(), TYPE_INT)
        return res1
    def propagateType(self, alttype, op, invn, outvn, inslot, outslot):
        if inslot == 0 and outslot == -1:
            return alttype
        return None

class TypeOpIntMult(TypeOpBinary):
    """CPUI_INT_MULT."""
    def __init__(self, tlst):
        super().__init__(tlst, OpCode.CPUI_INT_MULT, "*", TYPE_INT, TYPE_INT)
    def getOutputToken(self, op, castStrategy=None):
        if castStrategy is not None:
            return castStrategy.arithmeticOutputStandard(op)
        return self.getOutputLocal(op)
    def propagateType(self, alttype, op, invn, outvn, inslot, outslot):
        return None

class TypeOpIntDiv(TypeOpBinary):
    """CPUI_INT_DIV — unsigned division."""
    def __init__(self, tlst):
        super().__init__(tlst, OpCode.CPUI_INT_DIV, "/", TYPE_UINT, TYPE_UINT)
    def getInputCast(self, op, slot, castStrategy=None):
        if castStrategy is None:
            return None
        from ghidra.types.cast import IntPromotionCode
        vn = op.getIn(slot)
        reqtype = op.inputTypeLocal(slot)
        curtype = vn.getHighTypeReadFacing(op)
        promoType = castStrategy.intPromotionType(vn)
        if promoType != int(IntPromotionCode.NO_PROMOTION) and (promoType & int(IntPromotionCode.UNSIGNED_EXTENSION)) == 0:
            return reqtype
        return castStrategy.castStandard(reqtype, curtype, True, True)
    def propagateType(self, alttype, op, invn, outvn, inslot, outslot):
        return None

class TypeOpIntSdiv(TypeOpBinary):
    """CPUI_INT_SDIV — signed division."""
    def __init__(self, tlst):
        super().__init__(tlst, OpCode.CPUI_INT_SDIV, "s/", TYPE_INT, TYPE_INT)
    def getInputCast(self, op, slot, castStrategy=None):
        if castStrategy is None:
            return None
        from ghidra.types.cast import IntPromotionCode
        vn = op.getIn(slot)
        reqtype = op.inputTypeLocal(slot)
        curtype = vn.getHighTypeReadFacing(op)
        promoType = castStrategy.intPromotionType(vn)
        if promoType != int(IntPromotionCode.NO_PROMOTION) and (promoType & int(IntPromotionCode.SIGNED_EXTENSION)) == 0:
            return reqtype
        return castStrategy.castStandard(reqtype, curtype, True, True)
    def propagateType(self, alttype, op, invn, outvn, inslot, outslot):
        return None

class TypeOpIntRem(TypeOpBinary):
    """CPUI_INT_REM — unsigned remainder."""
    def __init__(self, tlst):
        super().__init__(tlst, OpCode.CPUI_INT_REM, "%", TYPE_UINT, TYPE_UINT)
    def getInputCast(self, op, slot, castStrategy=None):
        if castStrategy is None:
            return None
        from ghidra.types.cast import IntPromotionCode
        vn = op.getIn(slot)
        reqtype = op.inputTypeLocal(slot)
        curtype = vn.getHighTypeReadFacing(op)
        promoType = castStrategy.intPromotionType(vn)
        if promoType != int(IntPromotionCode.NO_PROMOTION) and (promoType & int(IntPromotionCode.UNSIGNED_EXTENSION)) == 0:
            return reqtype
        return castStrategy.castStandard(reqtype, curtype, True, True)
    def propagateType(self, alttype, op, invn, outvn, inslot, outslot):
        return None

class TypeOpIntSrem(TypeOpBinary):
    """CPUI_INT_SREM — signed remainder."""
    def __init__(self, tlst):
        super().__init__(tlst, OpCode.CPUI_INT_SREM, "s%", TYPE_INT, TYPE_INT)
    def getInputCast(self, op, slot, castStrategy=None):
        if castStrategy is None:
            return None
        from ghidra.types.cast import IntPromotionCode
        vn = op.getIn(slot)
        reqtype = op.inputTypeLocal(slot)
        curtype = vn.getHighTypeReadFacing(op)
        promoType = castStrategy.intPromotionType(vn)
        if promoType != int(IntPromotionCode.NO_PROMOTION) and (promoType & int(IntPromotionCode.SIGNED_EXTENSION)) == 0:
            return reqtype
        return castStrategy.castStandard(reqtype, curtype, True, True)
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
    def getInputCast(self, op, slot, castStrategy=None):
        if castStrategy is None:
            return None
        if TypeOpFloatInt2Float.absorbZext(op) is not None:
            return None
        vn = op.getIn(slot)
        reqtype = op.inputTypeLocal(slot)
        curtype = vn.getHighTypeReadFacing(op)
        care_uint_int = True
        if vn.getSize() <= 8:
            val = vn.getNZMask() if hasattr(vn, 'getNZMask') else 0
            val >>= (8 * vn.getSize() - 1)
            care_uint_int = (val & 1) != 0
        return castStrategy.castStandard(reqtype, curtype, care_uint_int, True)
    @staticmethod
    def absorbZext(op):
        """Return any INT_ZEXT PcodeOp that the given FLOAT_INT2FLOAT absorbs.

        C++ ref: TypeOpFloatInt2Float::absorbZext
        """
        vn0 = op.getIn(0)
        if hasattr(vn0, 'isWritten') and vn0.isWritten() and hasattr(vn0, 'isImplied') and vn0.isImplied():
            zextOp = vn0.getDef()
            if zextOp.code() == OpCode.CPUI_INT_ZEXT:
                return zextOp
        return None
    @staticmethod
    def preferredZextSize(inSize: int) -> int:
        """Return the preferred extension size for passing unsigned value to FLOAT_INT2FLOAT.

        C++ ref: TypeOpFloatInt2Float::preferredZextSize
        """
        if inSize < 4:
            return 4
        elif inSize < 8:
            return 8
        else:
            return inSize + 1
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
        self.nearPointerSize = 0
        self.farPointerSize = tlst.getSizeOfAltPointer()
        if self.farPointerSize != 0:
            self.nearPointerSize = tlst.getSizeOfPointer()
    def getOperatorName(self, op) -> str:
        return f"{self.name}{op.getIn(0).getSize()}{op.getIn(1).getSize()}"
    def getInputCast(self, op, slot, castStrategy=None):
        return None  # Never need a cast into a PIECE
    def getOutputToken(self, op, castStrategy=None):
        """C++ ref: TypeOpPiece::getOutputToken"""
        vn = op.getOut()
        dt = vn.getHighTypeDefFacing() if hasattr(vn, 'getHighTypeDefFacing') else None
        if dt is not None:
            meta = dt.getMetatype()
            if meta == TYPE_INT or meta == TYPE_UINT:
                return dt
        return self.tlst.getBase(vn.getSize(), TYPE_UINT)
    @staticmethod
    def computeByteOffsetForComposite(op, slot):
        """C++ ref: TypeOpPiece::computeByteOffsetForComposite"""
        inVn0 = op.getIn(0)
        spc = inVn0.getSpace() if hasattr(inVn0, 'getSpace') else None
        if spc is not None and hasattr(spc, 'isBigEndian') and spc.isBigEndian():
            return 0 if slot == 0 else inVn0.getSize()
        else:
            return op.getIn(1).getSize() if slot == 0 else 0
    def propagateType(self, alttype, op, invn, outvn, inslot, outslot):
        if self.nearPointerSize != 0 and alttype.getMetatype() == TYPE_PTR:
            if inslot == 1 and outslot == -1:
                if invn.getSize() == self.nearPointerSize and outvn.getSize() == self.farPointerSize:
                    return self.tlst.resizePointer(alttype, self.farPointerSize)
            elif inslot == -1 and outslot == 1:
                if invn.getSize() == self.farPointerSize and outvn.getSize() == self.nearPointerSize:
                    return self.tlst.resizePointer(alttype, self.nearPointerSize)
            return None
        if inslot != -1:
            return None
        byteOff = TypeOpPiece.computeByteOffsetForComposite(op, outslot)
        while alttype is not None and (byteOff != 0 or alttype.getSize() != outvn.getSize()):
            if hasattr(alttype, 'getSubType'):
                result = alttype.getSubType(byteOff, None)
                if result is None:
                    alttype = None
                    break
                if isinstance(result, tuple):
                    alttype, byteOff = result[0], result[1]
                else:
                    alttype = result
                    byteOff = 0
            else:
                alttype = None
                break
        return alttype

class TypeOpSubpiece(TypeOpFunc):
    """CPUI_SUBPIECE — extraction of sub-value."""
    def __init__(self, tlst):
        super().__init__(tlst, OpCode.CPUI_SUBPIECE, "SUB", TYPE_UNKNOWN, TYPE_UNKNOWN)
        from ghidra.ir.op import PcodeOp as PcOp
        self.opflags = PcOp.binary
        self.nearPointerSize = 0
        self.farPointerSize = tlst.getSizeOfAltPointer()
        if self.farPointerSize != 0:
            self.nearPointerSize = tlst.getSizeOfPointer()
    def getOperatorName(self, op) -> str:
        return f"{self.name}{op.getIn(0).getSize()}{op.getOut().getSize()}"
    def getInputCast(self, op, slot, castStrategy=None):
        return None  # Never need a cast into a SUBPIECE
    def getOutputToken(self, op, castStrategy=None):
        """C++ ref: TypeOpSubpiece::getOutputToken"""
        outvn = op.getOut()
        ct = op.getIn(0).getHighTypeReadFacing(op) if hasattr(op.getIn(0), 'getHighTypeReadFacing') else None
        if ct is not None:
            byteOff = TypeOpSubpiece.computeByteOffsetForComposite(op)
            if hasattr(ct, 'findTruncation'):
                field = ct.findTruncation(byteOff, outvn.getSize(), op, 1, [0])
                if field is not None:
                    if outvn.getSize() == field.type.getSize():
                        return field.type
        dt = outvn.getHighTypeDefFacing() if hasattr(outvn, 'getHighTypeDefFacing') else None
        if dt is not None and dt.getMetatype() != TYPE_UNKNOWN:
            return dt
        return self.tlst.getBase(outvn.getSize(), TYPE_INT)
    @staticmethod
    def computeByteOffsetForComposite(op):
        """C++ ref: TypeOpSubpiece::computeByteOffsetForComposite"""
        outSize = op.getOut().getSize()
        lsb = int(op.getIn(1).getOffset()) if op.numInput() > 1 else 0
        vn = op.getIn(0)
        spc = vn.getSpace() if hasattr(vn, 'getSpace') else None
        if spc is not None and hasattr(spc, 'isBigEndian') and spc.isBigEndian():
            return vn.getSize() - outSize - lsb
        else:
            return lsb
    def propagateType(self, alttype, op, invn, outvn, inslot, outslot):
        if self.nearPointerSize != 0 and alttype.getMetatype() == TYPE_PTR and inslot == -1 and outslot == 0:
            if op.getIn(1).getOffset() != 0:
                return None
            if invn.getSize() == self.nearPointerSize and outvn.getSize() == self.farPointerSize:
                return self.tlst.resizePointer(alttype, self.farPointerSize)
            return None
        if inslot != 0 or outslot != -1:
            return None  # Propagation must be from in0 to out
        byteOff = TypeOpSubpiece.computeByteOffsetForComposite(op)
        meta = alttype.getMetatype()
        if meta == TYPE_UNION or meta == getattr(alttype, 'TYPE_PARTIALUNION', -999):
            if hasattr(alttype, 'resolveTruncation'):
                trunc_off = [byteOff]
                field = alttype.resolveTruncation(byteOff, op, 1, trunc_off)
                byteOff = trunc_off[0]
                alttype = field.type if field is not None else None
        while alttype is not None and (byteOff != 0 or alttype.getSize() != outvn.getSize()):
            if hasattr(alttype, 'getSubType'):
                result = alttype.getSubType(byteOff, None)
                if result is None:
                    alttype = None
                    break
                if isinstance(result, tuple):
                    alttype, byteOff = result[0], result[1]
                else:
                    alttype = result
                    byteOff = 0
            else:
                alttype = None
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
        """C++ ref: TypeOpPtradd::getOutputToken — cast to input data-type."""
        return op.getIn(0).getHighTypeReadFacing(op) if hasattr(op.getIn(0), 'getHighTypeReadFacing') else None
    def getInputCast(self, op, slot, castStrategy=None):
        """C++ ref: TypeOpPtradd::getInputCast"""
        if slot == 0:
            vn0 = op.getIn(0)
            reqtype = vn0.getTypeReadFacing(op) if hasattr(vn0, 'getTypeReadFacing') else None
            curtype = vn0.getHighTypeReadFacing(op) if hasattr(vn0, 'getHighTypeReadFacing') else None
            if reqtype is None or curtype is None:
                return None
            if reqtype.getMetatype() != TYPE_PTR:
                return reqtype
            if curtype.getMetatype() != TYPE_PTR:
                return reqtype
            reqbase = reqtype.getPtrTo() if hasattr(reqtype, 'getPtrTo') else None
            curbase = curtype.getPtrTo() if hasattr(curtype, 'getPtrTo') else None
            if reqbase is not None and curbase is not None:
                if reqbase.getAlignSize() == curbase.getAlignSize():
                    return None
            return reqtype
        return TypeOp.getInputCast(self, op, slot, castStrategy)
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
    def getInputCast(self, op, slot, castStrategy=None):
        """C++ ref: TypeOpPtrsub::getInputCast"""
        if slot == 0:
            vn0 = op.getIn(0)
            reqtype = vn0.getTypeReadFacing(op) if hasattr(vn0, 'getTypeReadFacing') else None
            curtype = vn0.getHighTypeReadFacing(op) if hasattr(vn0, 'getHighTypeReadFacing') else None
            if reqtype is None or curtype is None:
                return None
            if curtype is reqtype:
                return None
            if reqtype.getMetatype() != TYPE_PTR:
                return reqtype
            if curtype.getMetatype() != TYPE_PTR:
                return reqtype
            reqbase = reqtype.getPtrTo() if hasattr(reqtype, 'getPtrTo') else None
            curbase = curtype.getPtrTo() if hasattr(curtype, 'getPtrTo') else None
            if reqbase is not None and curbase is not None:
                from ghidra.types.datatype import TypeArray
                if curbase.getMetatype() == TYPE_ARRAY and reqbase.getMetatype() == TYPE_ARRAY:
                    if isinstance(curbase, TypeArray) and isinstance(reqbase, TypeArray):
                        curbase = curbase.getBase()
                        reqbase = reqbase.getBase()
                while hasattr(reqbase, 'getTypedef') and reqbase.getTypedef() is not None:
                    reqbase = reqbase.getTypedef()
                while hasattr(curbase, 'getTypedef') and curbase.getTypedef() is not None:
                    curbase = curbase.getTypedef()
                if curbase is reqbase:
                    return None
            return reqtype
        return TypeOp.getInputCast(self, op, slot, castStrategy)
    def getOutputToken(self, op, castStrategy=None):
        """C++ ref: TypeOpPtrsub::getOutputToken"""
        ptype = op.getIn(0).getHighTypeReadFacing(op) if hasattr(op.getIn(0), 'getHighTypeReadFacing') else None
        if ptype is not None and ptype.getMetatype() == TYPE_PTR:
            if hasattr(ptype, 'downChain'):
                offset = op.getIn(1).getOffset() if hasattr(op.getIn(1), 'getOffset') else 0
                if hasattr(ptype, 'getWordSize'):
                    from ghidra.core.address import AddrSpace as AddrSpc
                    offset = AddrSpc.addressToByte(offset, ptype.getWordSize()) if hasattr(AddrSpc, 'addressToByte') else offset
                try:
                    rettype = ptype.downChain(offset, None, 0, False, self.tlst)
                    if isinstance(rettype, tuple):
                        rettype = rettype[0]
                    if offset == 0 and rettype is not None:
                        return rettype
                except Exception:
                    pass
            rettype = self.tlst.getBase(1, TYPE_UNKNOWN)
            wordsz = ptype.getWordSize() if hasattr(ptype, 'getWordSize') else 1
            return self.tlst.getTypePointer(op.getOut().getSize(), rettype, wordsz)
        return TypeOp.getOutputToken(self, op, castStrategy)
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
    def getInputLocal(self, op, slot):
        """C++ ref: TypeOpIndirect::getInputLocal"""
        if slot == 0:
            return TypeOp.getInputLocal(self, op, slot)
        # slot 1: code pointer to the affecting op
        ct = self.tlst.getTypeCode()
        try:
            from ghidra.ir.op import PcodeOp as PcOp
            iop = PcOp.getOpFromConst(op.getIn(1).getAddr())
            spc = iop.getAddr().getSpace()
            wordsz = spc.getWordSize() if hasattr(spc, 'getWordSize') else 1
            return self.tlst.getTypePointer(op.getIn(0).getSize(), ct, wordsz)
        except Exception:
            return self.tlst.getTypePointer(op.getIn(0).getSize(), ct, 1)
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
        from ghidra.ir.op import PcodeOp as PcOp
        self.opflags = PcOp.special | getattr(PcOp, 'nocollapse', 0)
    def getOutputToken(self, op, castStrategy=None):
        """C++ ref: TypeOpSegment::getOutputToken — assume type of ptr portion."""
        return op.getIn(2).getHighTypeReadFacing(op) if op.numInput() > 2 and hasattr(op.getIn(2), 'getHighTypeReadFacing') else None
    def getInputCast(self, op, slot, castStrategy=None):
        return None  # Never need a cast for inputs
    def propagateType(self, alttype, op, invn, outvn, inslot, outslot):
        """C++ ref: TypeOpSegment::propagateType — must propagate slot2 <-> output."""
        if inslot == 0 or inslot == 1:
            return None
        if outslot == 0 or outslot == 1:
            return None
        if hasattr(invn, 'isSpacebase') and invn.isSpacebase():
            return None
        if alttype.getMetatype() != TYPE_PTR:
            return None
        return self.tlst.resizePointer(alttype, outvn.getSize())

class TypeOpCpoolRef(TypeOp):
    """CPUI_CPOOLREF."""
    def __init__(self, tlst):
        super().__init__(tlst, OpCode.CPUI_CPOOLREF, "CPOOLREF")
        from ghidra.ir.op import PcodeOp as PcOp
        self.opflags = PcOp.special | getattr(PcOp, 'nocollapse', 0)
        self.cpool = None
        if hasattr(tlst, 'getArch') and tlst.getArch() is not None:
            self.cpool = getattr(tlst.getArch(), 'cpool', None)
    def getInputLocal(self, op, slot):
        """C++ ref: TypeOpCpoolref::getInputLocal."""
        return self.tlst.getBase(op.getIn(slot).getSize(), TYPE_INT)
    def getOutputLocal(self, op):
        """C++ ref: TypeOpCpoolref::getOutputLocal — query cpool for output type."""
        if self.cpool is not None and hasattr(self.cpool, 'getRecord'):
            refs = []
            for i in range(1, op.numInput()):
                refs.append(op.getIn(i).getOffset())
            rec = self.cpool.getRecord(refs)
            if rec is not None:
                if hasattr(rec, 'getTag') and rec.getTag() == getattr(rec, 'instance_of', -1):
                    return self.tlst.getBase(1, TYPE_BOOL)
                if hasattr(rec, 'getType'):
                    return rec.getType()
        return TypeOp.getOutputLocal(self, op)

class TypeOpNew(TypeOp):
    """CPUI_NEW."""
    def __init__(self, tlst):
        super().__init__(tlst, OpCode.CPUI_NEW, "NEW")
        from ghidra.ir.op import PcodeOp as PcOp
        self.opflags = PcOp.special | getattr(PcOp, 'call', 0) | getattr(PcOp, 'nocollapse', 0)
    def propagateType(self, alttype, op, invn, outvn, inslot, outslot):
        """C++ ref: TypeOpNew::propagateType"""
        if inslot != 0 or outslot != -1:
            return None
        vn0 = op.getIn(0)
        if not (hasattr(vn0, 'isWritten') and vn0.isWritten()):
            return None
        if vn0.getDef().code() != OpCode.CPUI_CPOOLREF:
            return None
        return alttype

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
