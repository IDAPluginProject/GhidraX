"""
Corresponds to: cast.hh / cast.cc

API and specific strategies for applying type casts.
"""

from __future__ import annotations

from abc import ABC, abstractmethod
from enum import IntEnum
from typing import TYPE_CHECKING, Optional

from ghidra.types.datatype import (
    Datatype, TypeFactory, MetaType,
    TYPE_VOID, TYPE_UNKNOWN, TYPE_INT, TYPE_UINT, TYPE_BOOL, TYPE_FLOAT,
    TYPE_PTR, TYPE_PTRREL, TYPE_ARRAY, TYPE_STRUCT, TYPE_UNION, TYPE_CODE,
)

if TYPE_CHECKING:
    from ghidra.ir.varnode import Varnode
    from ghidra.ir.op import PcodeOp


class IntPromotionCode(IntEnum):
    """Types of integer promotion."""
    NO_PROMOTION = -1
    UNKNOWN_PROMOTION = 0
    UNSIGNED_EXTENSION = 1
    SIGNED_EXTENSION = 2
    EITHER_EXTENSION = 3


class CastStrategy(ABC):
    """A strategy for applying type casts.

    Makes four kinds of decisions:
      - Do we need a cast operator for a given assignment
      - Does the given conversion need to be represented as a cast
      - Does the given extension/comparison match integer promotion
      - What data-type is produced by integer arithmetic
    """

    def __init__(self) -> None:
        self.tlst: Optional[TypeFactory] = None
        self.promoteSize: int = 4

    def setTypeFactory(self, t: TypeFactory) -> None:
        self.tlst = t
        self.promoteSize = t.getSizeOfInt()

    @abstractmethod
    def localExtensionType(self, vn: Varnode, op: PcodeOp) -> int:
        ...

    @abstractmethod
    def intPromotionType(self, vn: Varnode) -> int:
        ...

    @abstractmethod
    def checkIntPromotionForCompare(self, op: PcodeOp, slot: int) -> bool:
        ...

    @abstractmethod
    def checkIntPromotionForExtension(self, op: PcodeOp) -> bool:
        ...

    @abstractmethod
    def isExtensionCastImplied(self, op: PcodeOp, readOp: Optional[PcodeOp]) -> bool:
        ...

    @abstractmethod
    def castStandard(self, reqtype: Datatype, curtype: Datatype,
                     care_uint_int: bool, care_ptr_uint: bool) -> Optional[Datatype]:
        ...

    @abstractmethod
    def arithmeticOutputStandard(self, op: PcodeOp) -> Datatype:
        ...

    @abstractmethod
    def isSubpieceCast(self, outtype: Datatype, intype: Datatype, offset: int) -> bool:
        ...

    @abstractmethod
    def isSubpieceCastEndian(self, outtype: Datatype, intype: Datatype,
                              offset: int, isbigend: bool) -> bool:
        ...

    @abstractmethod
    def isSextCast(self, outtype: Datatype, intype: Datatype) -> bool:
        ...

    @abstractmethod
    def isZextCast(self, outtype: Datatype, intype: Datatype) -> bool:
        ...

    def markExplicitUnsigned(self, op: PcodeOp, slot: int) -> bool:
        """Check if an integer constant input needs to be marked as explicitly unsigned.

        If the constant input to an inherits-sign operation would otherwise be
        interpreted as signed, mark it for unsigned printing.
        """
        opcode = op.getOpcode() if hasattr(op, 'getOpcode') else None
        if opcode is None:
            return False
        if not opcode.inheritsSign():
            return False
        inheritsFirstOnly = opcode.inheritsSignFirstParamOnly()
        if slot == 1 and inheritsFirstOnly:
            return False
        vn = op.getIn(slot)
        if not vn.isConstant():
            return False
        dt = vn.getHighTypeReadFacing(op) if hasattr(vn, 'getHighTypeReadFacing') else vn.getType()
        if dt is None:
            return False
        meta = dt.getMetatype()
        if meta != TYPE_UINT and meta != TYPE_UNKNOWN:
            return False
        if hasattr(dt, 'isCharPrint') and dt.isCharPrint():
            return False
        if hasattr(dt, 'isEnumType') and dt.isEnumType():
            return False
        if op.numInput() == 2 and not inheritsFirstOnly:
            firstvn = op.getIn(1 - slot)
            fdt = firstvn.getHighTypeReadFacing(op) if hasattr(firstvn, 'getHighTypeReadFacing') else firstvn.getType()
            if fdt is not None:
                fmeta = fdt.getMetatype()
                if fmeta == TYPE_UINT or fmeta == TYPE_UNKNOWN:
                    return False  # Other side will force unsigned
        outvn = op.getOut()
        if outvn is not None:
            if hasattr(outvn, 'isExplicit') and outvn.isExplicit():
                return False
            lone = outvn.loneDescend() if hasattr(outvn, 'loneDescend') else None
            if lone is not None:
                loneopc = lone.getOpcode() if hasattr(lone, 'getOpcode') else None
                if loneopc is not None and not loneopc.inheritsSign():
                    return False
        if hasattr(vn, 'setUnsignedPrint'):
            vn.setUnsignedPrint()
        return True

    def markExplicitLongSize(self, op: PcodeOp, slot: int) -> bool:
        """Check if a constant input to a shift op needs to be marked as explicitly long."""
        opcode = op.getOpcode() if hasattr(op, 'getOpcode') else None
        if opcode is None:
            return False
        if not opcode.isShiftOp():
            return False
        if slot != 0:
            return False
        vn = op.getIn(slot)
        if not vn.isConstant():
            return False
        if vn.getSize() <= self.promoteSize:
            return False
        dt = vn.getType()
        if dt is None:
            return False
        meta = dt.getMetatype()
        if meta != TYPE_UINT and meta != TYPE_INT and meta != TYPE_UNKNOWN:
            return False
        off = vn.getOffset()
        sz = vn.getSize()
        if meta == TYPE_INT:
            sign_bit = 1 << (8 * sz - 1)
            if off & sign_bit:
                off = ((1 << (8 * sz)) - off) & ((1 << (8 * sz)) - 1)
                bit = off.bit_length() - 1 if off else -1
                if bit >= self.promoteSize * 8 - 1:
                    return False
            else:
                bit = off.bit_length() - 1 if off else -1
                if bit >= self.promoteSize * 8:
                    return False
        else:
            bit = off.bit_length() - 1 if off else -1
            if bit >= self.promoteSize * 8:
                return False
        if hasattr(vn, 'setLongPrint'):
            vn.setLongPrint()
        return True

    def caresAboutCharRepresentation(self, vn: Varnode, op: Optional[PcodeOp]) -> bool:
        return False


class CastStrategyC(CastStrategy):
    """Casting strategies specific to the C language."""

    def localExtensionType(self, vn, op):
        tp = vn.getHighTypeReadFacing(op) if hasattr(vn, 'getHighTypeReadFacing') else vn.getType()
        if tp is None:
            return int(IntPromotionCode.UNKNOWN_PROMOTION)
        meta = tp.getMetatype()
        if meta == TYPE_UINT or meta == TYPE_BOOL or meta == TYPE_UNKNOWN:
            natural = int(IntPromotionCode.UNSIGNED_EXTENSION)
        elif meta == TYPE_INT:
            natural = int(IntPromotionCode.SIGNED_EXTENSION)
        else:
            return int(IntPromotionCode.UNKNOWN_PROMOTION)
        if vn.isConstant():
            off = vn.getOffset()
            sign_bit = 1 << (8 * vn.getSize() - 1)
            if not (off & sign_bit):  # High-bit is zero
                return int(IntPromotionCode.EITHER_EXTENSION)
            return natural
        if hasattr(vn, 'isExplicit') and vn.isExplicit():
            return natural
        if not vn.isWritten():
            return int(IntPromotionCode.UNKNOWN_PROMOTION)
        defOp = vn.getDef()
        if hasattr(defOp, 'isBoolOutput') and defOp.isBoolOutput():
            return int(IntPromotionCode.EITHER_EXTENSION)
        from ghidra.core.opcodes import OpCode
        opc = defOp.code()
        if opc in (OpCode.CPUI_CAST, OpCode.CPUI_LOAD) or (hasattr(defOp, 'isCall') and defOp.isCall()):
            return natural
        if opc == OpCode.CPUI_INT_AND:
            tmpvn = defOp.getIn(1)
            if tmpvn.isConstant():
                sign_bit = 1 << (8 * tmpvn.getSize() - 1)
                if not (tmpvn.getOffset() & sign_bit):
                    return int(IntPromotionCode.EITHER_EXTENSION)
                return natural
        return int(IntPromotionCode.UNKNOWN_PROMOTION)

    def intPromotionType(self, vn):
        if vn.getSize() >= self.promoteSize:
            return int(IntPromotionCode.NO_PROMOTION)
        if vn.isConstant():
            lone = vn.loneDescend() if hasattr(vn, 'loneDescend') else None
            return self.localExtensionType(vn, lone)
        if hasattr(vn, 'isExplicit') and vn.isExplicit():
            return int(IntPromotionCode.NO_PROMOTION)
        if not vn.isWritten():
            return int(IntPromotionCode.UNKNOWN_PROMOTION)
        from ghidra.core.opcodes import OpCode
        op = vn.getDef()
        opc = op.code()
        if opc == OpCode.CPUI_INT_AND:
            othervn = op.getIn(1)
            if (self.localExtensionType(othervn, op) & int(IntPromotionCode.UNSIGNED_EXTENSION)) != 0:
                return int(IntPromotionCode.UNSIGNED_EXTENSION)
            othervn = op.getIn(0)
            if (self.localExtensionType(othervn, op) & int(IntPromotionCode.UNSIGNED_EXTENSION)) != 0:
                return int(IntPromotionCode.UNSIGNED_EXTENSION)
        elif opc == OpCode.CPUI_INT_RIGHT:
            othervn = op.getIn(0)
            val = self.localExtensionType(othervn, op)
            if (val & int(IntPromotionCode.UNSIGNED_EXTENSION)) != 0:
                return val
        elif opc == OpCode.CPUI_INT_SRIGHT:
            othervn = op.getIn(0)
            val = self.localExtensionType(othervn, op)
            if (val & int(IntPromotionCode.SIGNED_EXTENSION)) != 0:
                return val
        elif opc in (OpCode.CPUI_INT_XOR, OpCode.CPUI_INT_OR,
                     OpCode.CPUI_INT_DIV, OpCode.CPUI_INT_REM):
            othervn = op.getIn(0)
            if (self.localExtensionType(othervn, op) & int(IntPromotionCode.UNSIGNED_EXTENSION)) == 0:
                return int(IntPromotionCode.UNKNOWN_PROMOTION)
            othervn = op.getIn(1)
            if (self.localExtensionType(othervn, op) & int(IntPromotionCode.UNSIGNED_EXTENSION)) == 0:
                return int(IntPromotionCode.UNKNOWN_PROMOTION)
            return int(IntPromotionCode.UNSIGNED_EXTENSION)
        elif opc in (OpCode.CPUI_INT_SDIV, OpCode.CPUI_INT_SREM):
            othervn = op.getIn(0)
            if (self.localExtensionType(othervn, op) & int(IntPromotionCode.SIGNED_EXTENSION)) == 0:
                return int(IntPromotionCode.UNKNOWN_PROMOTION)
            othervn = op.getIn(1)
            if (self.localExtensionType(othervn, op) & int(IntPromotionCode.SIGNED_EXTENSION)) == 0:
                return int(IntPromotionCode.UNKNOWN_PROMOTION)
            return int(IntPromotionCode.SIGNED_EXTENSION)
        elif opc in (OpCode.CPUI_INT_NEGATE, OpCode.CPUI_INT_2COMP):
            othervn = op.getIn(0)
            if (self.localExtensionType(othervn, op) & int(IntPromotionCode.SIGNED_EXTENSION)) != 0:
                return int(IntPromotionCode.SIGNED_EXTENSION)
        elif opc in (OpCode.CPUI_INT_ADD, OpCode.CPUI_INT_SUB,
                     OpCode.CPUI_INT_LEFT, OpCode.CPUI_INT_MULT):
            pass  # Fall through to UNKNOWN_PROMOTION
        else:
            return int(IntPromotionCode.NO_PROMOTION)
        return int(IntPromotionCode.UNKNOWN_PROMOTION)

    def checkIntPromotionForCompare(self, op, slot):
        vn = op.getIn(slot)
        if vn is None:
            return False
        if vn.getSize() >= self.promoteSize:
            return False
        exttype1 = self.intPromotionType(vn)
        if exttype1 == int(IntPromotionCode.NO_PROMOTION):
            return False
        if exttype1 == int(IntPromotionCode.UNKNOWN_PROMOTION):
            return True  # Promotion with unknown type => need cast
        exttype2 = self.intPromotionType(op.getIn(1 - slot))
        if (exttype1 & exttype2) != 0:
            return False  # Both share a common extension
        if exttype2 == int(IntPromotionCode.NO_PROMOTION):
            return False  # Other side has no promotion; both extended same way
        return True

    def checkIntPromotionForExtension(self, op):
        vn = op.getIn(0)
        if vn is None:
            return False
        if vn.getSize() >= self.promoteSize:
            return False
        exttype = self.intPromotionType(vn)
        if exttype == int(IntPromotionCode.NO_PROMOTION):
            return False
        if exttype == int(IntPromotionCode.UNKNOWN_PROMOTION):
            return True  # Extension with unknown type => need cast
        from ghidra.core.opcodes import OpCode
        if (exttype & int(IntPromotionCode.UNSIGNED_EXTENSION)) != 0 and op.code() == OpCode.CPUI_INT_ZEXT:
            return False
        if (exttype & int(IntPromotionCode.SIGNED_EXTENSION)) != 0 and op.code() == OpCode.CPUI_INT_SEXT:
            return False
        return True  # Promotion doesn't match explicit extension

    def isExtensionCastImplied(self, op, readOp):
        outVn = op.getOut()
        if outVn is None:
            return False
        if hasattr(outVn, 'isExplicit') and outVn.isExplicit():
            return False  # Explicit output — cast is not implied
        # Non-explicit output
        if readOp is None:
            return False
        metatype = None
        odt = outVn.getHighTypeReadFacing(readOp) if hasattr(outVn, 'getHighTypeReadFacing') else outVn.getType()
        if odt is not None:
            metatype = odt.getMetatype()
        from ghidra.core.opcodes import OpCode
        ropc = readOp.code()
        if ropc == OpCode.CPUI_PTRADD:
            pass  # Integer promotion applies
        elif ropc in (OpCode.CPUI_INT_ADD, OpCode.CPUI_INT_SUB,
                      OpCode.CPUI_INT_MULT, OpCode.CPUI_INT_DIV,
                      OpCode.CPUI_INT_AND, OpCode.CPUI_INT_OR,
                      OpCode.CPUI_INT_XOR,
                      OpCode.CPUI_INT_EQUAL, OpCode.CPUI_INT_NOTEQUAL,
                      OpCode.CPUI_INT_LESS, OpCode.CPUI_INT_LESSEQUAL,
                      OpCode.CPUI_INT_SLESS, OpCode.CPUI_INT_SLESSEQUAL):
            slot = readOp.getSlot(outVn) if hasattr(readOp, 'getSlot') else 0
            otherVn = readOp.getIn(1 - slot)
            if otherVn.isConstant():
                if otherVn.getSize() > self.promoteSize:
                    return False  # Big constant — extension must be explicit
            elif not (hasattr(otherVn, 'isExplicit') and otherVn.isExplicit()):
                return False
            if metatype is not None:
                other_dt = otherVn.getHighTypeReadFacing(readOp) if hasattr(otherVn, 'getHighTypeReadFacing') else otherVn.getType()
                if other_dt is not None and other_dt.getMetatype() != metatype:
                    return False
        else:
            return False
        return True  # Everything is integer promotion

    def castStandard(self, reqtype, curtype, care_uint_int, care_ptr_uint):
        if curtype is reqtype:
            return None
        if curtype.getMetatype() == TYPE_VOID:
            return reqtype  # Coming from void (dereferenced pointer) needs cast

        reqbase = reqtype
        curbase = curtype
        isptr = False

        # Unwrap matching pointer chains
        while reqbase.getMetatype() == TYPE_PTR and curbase.getMetatype() == TYPE_PTR:
            reqword = reqbase.getWordSize() if hasattr(reqbase, 'getWordSize') else 0
            curword = curbase.getWordSize() if hasattr(curbase, 'getWordSize') else 0
            if reqword != curword:
                return reqtype
            reqspc = reqbase.getSpace() if hasattr(reqbase, 'getSpace') else None
            curspc = curbase.getSpace() if hasattr(curbase, 'getSpace') else None
            if reqspc != curspc:
                if reqspc is not None and curspc is not None:
                    return reqtype  # Pointers to different address spaces
            reqbase = reqbase.getPtrTo() if hasattr(reqbase, 'getPtrTo') else reqbase
            curbase = curbase.getPtrTo() if hasattr(curbase, 'getPtrTo') else curbase
            care_uint_int = True
            isptr = True

        # Unwrap typedefs
        while hasattr(reqbase, 'getTypedef') and reqbase.getTypedef() is not None:
            reqbase = reqbase.getTypedef()
        while hasattr(curbase, 'getTypedef') and curbase.getTypedef() is not None:
            curbase = curbase.getTypedef()

        if curbase is reqbase:
            return None  # Different typedefs pointing to the same type

        reqmeta = reqbase.getMetatype()
        curmeta = curbase.getMetatype()

        if reqmeta == TYPE_VOID or curmeta == TYPE_VOID:
            return None  # Don't cast to/from void pointer

        if reqbase.getSize() != curbase.getSize():
            if hasattr(reqbase, 'isVariableLength') and reqbase.isVariableLength() and isptr:
                if hasattr(reqbase, 'hasSameVariableBase') and reqbase.hasSameVariableBase(curbase):
                    return None
            return reqtype  # Always cast change in size

        if reqmeta == TYPE_UNKNOWN:
            return None
        elif reqmeta == TYPE_UINT:
            if not care_uint_int:
                if curmeta in (TYPE_UNKNOWN, TYPE_INT, TYPE_UINT, TYPE_BOOL):
                    return None
            else:
                if curmeta in (TYPE_UINT, TYPE_BOOL):
                    return None
                if isptr and curmeta == TYPE_UNKNOWN:
                    return None  # Don't cast pointers to unknown
            if not care_ptr_uint and curmeta == TYPE_PTR:
                return None
        elif reqmeta == TYPE_INT:
            if not care_uint_int:
                if curmeta in (TYPE_UNKNOWN, TYPE_INT, TYPE_UINT, TYPE_BOOL):
                    return None
            else:
                if curmeta in (TYPE_INT, TYPE_BOOL):
                    return None
                if isptr and curmeta == TYPE_UNKNOWN:
                    return None
        elif reqmeta == TYPE_CODE:
            if curmeta == TYPE_CODE:
                # Don't cast between function pointer and generic code pointer
                req_proto = reqbase.getPrototype() if hasattr(reqbase, 'getPrototype') else None
                cur_proto = curbase.getPrototype() if hasattr(curbase, 'getPrototype') else None
                if req_proto is None or cur_proto is None:
                    return None

        return reqtype

    def arithmeticOutputStandard(self, op):
        res1 = op.getIn(0).getHighTypeReadFacing(op) if hasattr(op.getIn(0), 'getHighTypeReadFacing') else op.getIn(0).getType()
        if res1 is None:
            return self.tlst.getBase(1, TYPE_INT)
        if res1.getMetatype() == TYPE_BOOL:
            res1 = self.tlst.getBase(res1.getSize(), TYPE_INT)
        for i in range(1, op.numInput()):
            res2 = op.getIn(i).getHighTypeReadFacing(op) if hasattr(op.getIn(i), 'getHighTypeReadFacing') else op.getIn(i).getType()
            if res2 is None:
                continue
            if res2.getMetatype() == TYPE_BOOL:
                continue
            if hasattr(res2, 'typeOrder') and res2.typeOrder(res1) < 0:
                res1 = res2
        return res1

    def isSubpieceCast(self, outtype, intype, offset):
        if offset != 0:
            return False
        inmeta = intype.getMetatype()
        if inmeta not in (TYPE_INT, TYPE_UINT, TYPE_UNKNOWN, TYPE_PTR):
            return False
        outmeta = outtype.getMetatype()
        if outmeta not in (TYPE_INT, TYPE_UINT, TYPE_UNKNOWN, TYPE_PTR, TYPE_FLOAT):
            return False
        if inmeta == TYPE_PTR:
            if outmeta == TYPE_PTR:
                if outtype.getSize() < intype.getSize():
                    return True  # Far pointer to near pointer
            if outmeta != TYPE_INT and outmeta != TYPE_UINT:
                return False  # Other casts don't make sense for pointers
        return True

    def isSubpieceCastEndian(self, outtype, intype, offset, isbigend):
        tmpoff = offset
        if isbigend:
            tmpoff = intype.getSize() - 1 - offset
        return self.isSubpieceCast(outtype, intype, tmpoff)

    def isSextCast(self, outtype, intype):
        outmeta = outtype.getMetatype()
        if outmeta != TYPE_UINT and outmeta != TYPE_INT:
            return False
        inmeta = intype.getMetatype()
        if inmeta != TYPE_INT and inmeta != TYPE_BOOL:
            return False
        return True

    def isZextCast(self, outtype, intype):
        outmeta = outtype.getMetatype()
        if outmeta != TYPE_UINT and outmeta != TYPE_INT:
            return False
        inmeta = intype.getMetatype()
        if inmeta != TYPE_UINT and inmeta != TYPE_BOOL:
            return False
        return True


class CastStrategyJava(CastStrategyC):
    """Casting strategies specific to the Java language."""

    def castStandard(self, reqtype, curtype, care_uint_int, care_ptr_uint):
        if curtype is reqtype:
            return None
        reqbase = reqtype
        curbase = curtype
        # In Java, any pointer cast is implicit (objects handled by JVM)
        if reqbase.getMetatype() == TYPE_PTR or curbase.getMetatype() == TYPE_PTR:
            return None
        if reqbase.getMetatype() == TYPE_VOID or curbase.getMetatype() == TYPE_VOID:
            return None
        if reqbase.getSize() != curbase.getSize():
            return reqtype  # Always cast change in size

        reqmeta = reqbase.getMetatype()
        curmeta = curbase.getMetatype()

        if reqmeta == TYPE_UNKNOWN:
            return None
        elif reqmeta == TYPE_UINT:
            if not care_uint_int:
                if curmeta in (TYPE_UNKNOWN, TYPE_INT, TYPE_UINT, TYPE_BOOL):
                    return None
            else:
                if curmeta in (TYPE_UINT, TYPE_BOOL):
                    return None
        elif reqmeta == TYPE_INT:
            if not care_uint_int:
                if curmeta in (TYPE_UNKNOWN, TYPE_INT, TYPE_UINT, TYPE_BOOL):
                    return None
            else:
                if curmeta in (TYPE_INT, TYPE_BOOL):
                    return None
        elif reqmeta == TYPE_CODE:
            if curmeta == TYPE_CODE:
                req_proto = reqbase.getPrototype() if hasattr(reqbase, 'getPrototype') else None
                cur_proto = curbase.getPrototype() if hasattr(curbase, 'getPrototype') else None
                if req_proto is None or cur_proto is None:
                    return None

        return reqtype

    def isZextCast(self, outtype, intype):
        outmeta = outtype.getMetatype()
        if outmeta not in (TYPE_INT, TYPE_UINT, TYPE_BOOL):
            return False
        inmeta = intype.getMetatype()
        if inmeta not in (TYPE_INT, TYPE_UINT, TYPE_BOOL):
            return False  # Non-integer types, print functional ZEXT
        if intype.getSize() == 2 and not (hasattr(intype, 'isCharPrint') and intype.isCharPrint()):
            return False  # Cast is not zext for short
        if intype.getSize() == 1 and inmeta == TYPE_INT:
            return False  # Cast is not zext for byte
        if intype.getSize() >= 4:
            return False  # Cast is not zext for int and long
        return True
