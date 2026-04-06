"""
Corresponds to: op.hh / op.cc

The PcodeOp and PcodeOpBank classes.
"""

from __future__ import annotations

from bisect import bisect_left, bisect_right
from typing import TYPE_CHECKING, Optional, List, Dict, Iterator
from ghidra.core.address import Address, SeqNum
from ghidra.core.error import LowlevelError
from ghidra.core.opcodes import OpCode

if TYPE_CHECKING:
    from ghidra.ir.varnode import Varnode
    from ghidra.core.marshal import Encoder, Decoder


_IOP_REF_LOOKUP: Dict[int, "PcodeOp"] = {}
_TYPEOP_FLAG_CACHE: Optional[Dict[int, int]] = None


def _get_typeop_flags_for_opcode(opc: OpCode) -> int:
    """Mirror native PcodeOp::setOpcode(TypeOp*) for enum-only opcode updates.

    Python frequently mutates ops via ``setOpcodeEnum()`` without a live TypeOp
    instance attached. Native still preserves the opcode's behavioral flags
    (booloutput, branch, call, commutative, etc.) because ``setOpcode`` always
    receives a TypeOp. Cache the canonical TypeOp flags once and reuse them so
    enum-only updates don't silently drop rule-visible properties.
    """
    global _TYPEOP_FLAG_CACHE
    cache = _TYPEOP_FLAG_CACHE
    if cache is None:
        from ghidra.ir.typeop import registerTypeOps
        from ghidra.types.datatype import TypeFactory

        typeops = registerTypeOps(TypeFactory(), None)
        cache = {}
        for typeop in typeops:
            if typeop is None:
                continue
            cache[int(typeop.getOpcode())] = int(typeop.getFlags())
        _TYPEOP_FLAG_CACHE = cache
    return cache.get(int(opc), 0)


class PcodeOp:
    """Lowest level operation of the p-code language.

    Only one version of any type of operation exists, and all effects
    are completely explicit. All operations except control flow operations
    have exactly one explicit output.
    """

    # --- Primary flags (uint4 flags) ---
    startbasic       = 1
    branch           = 2
    call             = 4
    returns          = 0x8
    nocollapse       = 0x10
    dead             = 0x20
    marker           = 0x40
    booloutput       = 0x80
    boolean_flip     = 0x100
    fallthru_true    = 0x200
    indirect_source  = 0x400
    coderef          = 0x800
    startmark        = 0x1000
    mark             = 0x2000
    commutative      = 0x4000
    unary            = 0x8000
    binary           = 0x10000
    special          = 0x20000
    ternary          = 0x40000
    return_copy      = 0x80000
    nonprinting      = 0x100000
    halt             = 0x200000
    badinstruction   = 0x400000
    unimplemented    = 0x800000
    noreturn         = 0x1000000
    missing          = 0x2000000
    spacebase_ptr    = 0x4000000
    indirect_creation = 0x8000000
    calculated_bool  = 0x10000000
    has_callspec     = 0x20000000
    ptrflow          = 0x40000000
    indirect_store   = 0x80000000

    # --- Additional flags (uint4 addlflags) ---
    special_prop         = 1
    special_print        = 2
    modified             = 4
    warning              = 8
    incidental_copy      = 0x10
    is_cpool_transformed = 0x20
    stop_type_propagation = 0x40
    hold_output          = 0x80
    concat_root          = 0x100
    no_indirect_collapse = 0x200
    store_unmapped       = 0x400

    # Flags sourced from TypeOp::getFlags() in C++ PcodeOp::setOpcode.
    _TYPEOP_FLAG_MASK = (
        branch | call | coderef | commutative | returns | nocollapse |
        marker | booloutput | unary | binary | ternary | special |
        has_callspec | return_copy
    )

    __slots__ = ('_opcode', '_opcode_enum', '_flags', '_addlflags',
                 '_start', '_parent', '_output', '_inrefs')

    def __init__(self, num_inputs: int, sq: SeqNum) -> None:
        self._opcode = None  # TypeOp reference
        self._opcode_enum: OpCode = OpCode.CPUI_BLANK
        self._flags: int = 0
        self._addlflags: int = 0
        self._start: SeqNum = sq
        self._parent = None  # BlockBasic
        self._output: Optional[Varnode] = None
        self._inrefs: List[Optional[Varnode]] = [None] * num_inputs

    # --- Basic accessors ---

    def numInput(self) -> int:
        return len(self._inrefs)

    def getOut(self) -> Optional[Varnode]:
        return self._output

    def getIn(self, slot: int) -> Optional[Varnode]:
        return self._inrefs[slot]

    def getParent(self):
        """Get the parent basic block."""
        return self._parent

    def getAddr(self) -> Address:
        return self._start.getAddr()

    def getTime(self) -> int:
        return self._start.getTime()

    def getSeqNum(self) -> SeqNum:
        return self._start

    def getSlot(self, vn: Varnode) -> int:
        """Get the slot number of the indicated input varnode."""
        for i, ref in enumerate(self._inrefs):
            if ref is vn:
                return i
        return len(self._inrefs)

    def getEvalType(self) -> int:
        eval_type = self._flags & (PcodeOp.unary | PcodeOp.binary | PcodeOp.special | PcodeOp.ternary)
        if eval_type != 0:
            return eval_type
        behave = self._opcode.behave if self._opcode is not None and hasattr(self._opcode, 'behave') else None
        if behave is None:
            from ghidra.core.opbehavior import OpBehavior
            behaviors = OpBehavior.registerInstructions()
            if int(self._opcode_enum) < len(behaviors):
                behave = behaviors[int(self._opcode_enum)]
        if behave is None:
            return 0
        if behave.isSpecial():
            return PcodeOp.special
        if behave.isUnary():
            return PcodeOp.unary
        if len(self._inrefs) == 3:
            return PcodeOp.ternary
        if len(self._inrefs) == 2:
            return PcodeOp.binary
        return 0

    def getHaltType(self) -> int:
        return self._flags & (PcodeOp.halt | PcodeOp.badinstruction | PcodeOp.unimplemented |
                              PcodeOp.noreturn | PcodeOp.missing)

    def code(self) -> OpCode:
        """Get the opcode id (enum) for this op."""
        return self._opcode_enum

    def getOpcode(self):
        """Get the TypeOp for this op."""
        return self._opcode

    def getOpName(self) -> str:
        if self._opcode is not None:
            return self._opcode.getName()
        from ghidra.core.opcodes import get_opname
        return get_opname(self._opcode_enum)

    # --- Flag queries ---

    def isDead(self) -> bool:
        return (self._flags & PcodeOp.dead) != 0

    def isAssignment(self) -> bool:
        return self._output is not None

    def isCall(self) -> bool:
        return (self._flags & PcodeOp.call) != 0

    def isCallWithoutSpec(self) -> bool:
        return (self._flags & (PcodeOp.call | PcodeOp.has_callspec)) == PcodeOp.call

    def isMarker(self) -> bool:
        return (self._flags & PcodeOp.marker) != 0

    def isIndirectCreation(self) -> bool:
        return (self._flags & PcodeOp.indirect_creation) != 0

    def isIndirectStore(self) -> bool:
        return (self._flags & PcodeOp.indirect_store) != 0

    def notPrinted(self) -> bool:
        return (self._flags & (PcodeOp.marker | PcodeOp.nonprinting | PcodeOp.noreturn)) != 0

    def isBoolOutput(self) -> bool:
        return (self._flags & PcodeOp.booloutput) != 0

    def isBranch(self) -> bool:
        if (self._flags & PcodeOp.branch) != 0:
            return True
        return self._opcode_enum in (
            OpCode.CPUI_BRANCH,
            OpCode.CPUI_CBRANCH,
            OpCode.CPUI_BRANCHIND,
        )

    def isCallOrBranch(self) -> bool:
        if (self._flags & (PcodeOp.branch | PcodeOp.call)) != 0:
            return True
        return self.isBranch() or self.isCall()

    def isFlowBreak(self) -> bool:
        if (self._flags & (PcodeOp.branch | PcodeOp.returns)) != 0:
            return True
        return self.isBranch() or self._opcode_enum == OpCode.CPUI_RETURN

    def isBooleanFlip(self) -> bool:
        return (self._flags & PcodeOp.boolean_flip) != 0

    def isFallthruTrue(self) -> bool:
        return (self._flags & PcodeOp.fallthru_true) != 0

    def isCodeRef(self) -> bool:
        return (self._flags & PcodeOp.coderef) != 0

    def isInstructionStart(self) -> bool:
        return (self._flags & PcodeOp.startmark) != 0

    def isBlockStart(self) -> bool:
        return (self._flags & PcodeOp.startbasic) != 0

    def isModified(self) -> bool:
        return (self._addlflags & PcodeOp.modified) != 0

    def isMark(self) -> bool:
        return (self._flags & PcodeOp.mark) != 0

    def isCommutative(self) -> bool:
        return (self._flags & PcodeOp.commutative) != 0

    def isIndirectSource(self) -> bool:
        return (self._flags & PcodeOp.indirect_source) != 0

    def isPtrFlow(self) -> bool:
        return (self._flags & PcodeOp.ptrflow) != 0

    def isCalculatedBool(self) -> bool:
        return (self._flags & (PcodeOp.calculated_bool | PcodeOp.booloutput)) != 0

    def isReturnCopy(self) -> bool:
        return (self._flags & PcodeOp.return_copy) != 0

    def usesSpacebasePtr(self) -> bool:
        return (self._flags & PcodeOp.spacebase_ptr) != 0

    # --- Flag mutators ---

    def setFlag(self, fl: int) -> None:
        self._flags |= fl

    def clearFlag(self, fl: int) -> None:
        self._flags &= ~fl

    def flipFlag(self, fl: int) -> None:
        self._flags ^= fl

    def setAdditionalFlag(self, fl: int) -> None:
        self._addlflags |= fl

    def clearAdditionalFlag(self, fl: int) -> None:
        self._addlflags &= ~fl

    def setMark(self) -> None:
        self._flags |= PcodeOp.mark

    def clearMark(self) -> None:
        self._flags &= ~PcodeOp.mark

    def setIndirectSource(self) -> None:
        self._flags |= PcodeOp.indirect_source

    def clearIndirectSource(self) -> None:
        self._flags &= ~PcodeOp.indirect_source

    def setPtrFlow(self) -> None:
        self._flags |= PcodeOp.ptrflow

    # --- Structural mutators (Funcdata-level) ---

    def setOpcode(self, t_op) -> None:
        self._flags &= ~PcodeOp._TYPEOP_FLAG_MASK
        self._opcode = t_op
        if t_op is None:
            self._opcode_enum = OpCode.CPUI_BLANK
            return
        self._opcode_enum = t_op.getOpcode()
        if hasattr(t_op, "getFlags"):
            self._flags |= int(t_op.getFlags())

    def setOpcodeEnum(self, opc: OpCode) -> None:
        self._flags &= ~PcodeOp._TYPEOP_FLAG_MASK
        self._opcode = None
        self._opcode_enum = opc
        self._flags |= _get_typeop_flags_for_opcode(opc)

    def setOutput(self, vn: Optional[Varnode]) -> None:
        self._output = vn

    def clearInput(self, slot: int) -> None:
        self._inrefs[slot] = None

    def setInput(self, vn: Varnode, slot: int) -> None:
        self._inrefs[slot] = vn

    def setNumInputs(self, num: int) -> None:
        while len(self._inrefs) < num:
            self._inrefs.append(None)
        while len(self._inrefs) > num:
            self._inrefs.pop()

    def removeInput(self, slot: int) -> None:
        del self._inrefs[slot]

    def insertInput(self, slot: int) -> None:
        self._inrefs.insert(slot, None)

    def setOrder(self, ord_: int) -> None:
        self._start.setOrder(ord_)

    def setParent(self, p) -> None:
        self._parent = p

    # --- Navigation ---

    @staticmethod
    def _get_parent_ops(block) -> list["PcodeOp"] | tuple[()]:
        if block is None:
            return ()
        if hasattr(block, 'getOps'):
            ops = block.getOps()
            if ops is not None:
                return ops
        if hasattr(block, '_op'):
            ops = getattr(block, '_op')
            if ops is not None:
                return ops
        if hasattr(block, 'beginOp'):
            return list(block.beginOp())
        return ()

    def nextOp(self) -> Optional[PcodeOp]:
        """Return the next op in sequence from this op.

        Follows flow into successive blocks during search, so long as there is only one path.
        C++ ref: ``PcodeOp::nextOp``
        """
        p = self._parent
        if p is None:
            return None
        ops = self._get_parent_ops(p)
        found = False
        for op in ops:
            if found:
                return op
            if op is self:
                found = True
        # Reached end of block, follow single-output edges
        while True:
            nout = p.sizeOut() if hasattr(p, 'sizeOut') else 0
            if nout != 1 and nout != 2:
                return None
            p = p.getOut(0) if hasattr(p, 'getOut') else None
            if p is None:
                return None
            ops = self._get_parent_ops(p)
            for op in ops:
                return op
            # Empty block, keep going
        return None

    def previousOp(self) -> Optional[PcodeOp]:
        """Return the previous op within this op's basic block, or None.

        C++ ref: ``PcodeOp::previousOp``
        """
        p = self._parent
        if p is None:
            return None
        prev = None
        ops = self._get_parent_ops(p)
        for op in ops:
            if op is self:
                return prev
            prev = op
        return None

    def compareOrder(self, bop: PcodeOp) -> int:
        """Compare the control-flow order of this and bop.
        Returns -1, 0, or 1.
        """
        if self._parent is not bop._parent:
            si = self._parent.getIndex() if self._parent else -1
            bi = bop._parent.getIndex() if bop._parent else -1
            return -1 if si < bi else (1 if si > bi else 0)
        so = self._start.getOrder()
        bo = bop._start.getOrder()
        if so < bo:
            return -1
        if so > bo:
            return 1
        return 0

    @staticmethod
    def registerOpRef(op: "PcodeOp") -> None:
        _IOP_REF_LOOKUP[id(op)] = op

    @staticmethod
    def getOpFromConst(addr: Address):
        """Retrieve the PcodeOp encoded in an IOP-space address."""
        if addr is None:
            return None
        return _IOP_REF_LOOKUP.get(addr.getOffset())

    def printRaw(self) -> str:
        """Print raw info about this op."""
        parts = []
        if self._output is not None:
            parts.append(f"{self._output.printRaw()} = ")
        parts.append(self.getOpName())
        for i, inp in enumerate(self._inrefs):
            if inp is not None:
                parts.append(f" {inp.printRaw()}")
        return "".join(parts)

    def doesSpecialPrinting(self) -> bool:
        return (self._addlflags & PcodeOp.special_print) != 0

    def doesSpecialPropagation(self) -> bool:
        return (self._addlflags & PcodeOp.special_prop) != 0

    def isIncidentalCopy(self) -> bool:
        return (self._addlflags & PcodeOp.incidental_copy) != 0

    def isCpoolTransformed(self) -> bool:
        return (self._addlflags & PcodeOp.is_cpool_transformed) != 0

    def stopsTypePropagation(self) -> bool:
        return (self._addlflags & PcodeOp.stop_type_propagation) != 0

    def setStopTypePropagation(self) -> None:
        self._addlflags |= PcodeOp.stop_type_propagation

    def clearStopTypePropagation(self) -> None:
        self._addlflags &= ~PcodeOp.stop_type_propagation

    def holdOutput(self) -> bool:
        return (self._addlflags & PcodeOp.hold_output) != 0

    def setHoldOutput(self) -> None:
        self._addlflags |= PcodeOp.hold_output

    def isPartialRoot(self) -> bool:
        return (self._addlflags & PcodeOp.concat_root) != 0

    def setPartialRoot(self) -> None:
        self._addlflags |= PcodeOp.concat_root

    def noIndirectCollapse(self) -> bool:
        return (self._addlflags & PcodeOp.no_indirect_collapse) != 0

    def setNoIndirectCollapse(self) -> None:
        self._addlflags |= PcodeOp.no_indirect_collapse

    def isStoreUnmapped(self) -> bool:
        return (self._addlflags & PcodeOp.store_unmapped) != 0

    def setStoreUnmapped(self) -> None:
        self._addlflags |= PcodeOp.store_unmapped

    def isWarning(self) -> bool:
        return (self._addlflags & PcodeOp.warning) != 0

    def isCollapsible(self) -> bool:
        if (self._flags & PcodeOp.nocollapse) != 0:
            return False
        if self._output is None:
            return False
        if len(self._inrefs) == 0:
            return False
        for inv in self._inrefs:
            if inv is None or not inv.isConstant():
                return False
        if self._output.getSize() > 8:
            return False
        return True

    def isMoveable(self, point) -> bool:
        return not self.isMarker() and not self.isCall()

    def setHaltType(self, flag: int) -> None:
        self._flags = (self._flags & ~(PcodeOp.halt | PcodeOp.badinstruction | PcodeOp.unimplemented | PcodeOp.noreturn | PcodeOp.missing)) | flag

    def getRepeatSlot(self, vn, firstSlot, op) -> int:
        for i in range(firstSlot, len(self._inrefs)):
            if self._inrefs[i] is vn:
                return i
        return -1

    def getCseHash(self) -> int:
        eval_type = self.getEvalType()
        if (eval_type & (PcodeOp.unary | PcodeOp.binary)) == 0:
            return 0
        if self._opcode_enum == OpCode.CPUI_COPY:
            return 0
        outvn = self._output
        if outvn is None:
            return 0
        mask = 0xFFFFFFFFFFFFFFFF
        h = ((outvn.getSize() << 8) | int(self._opcode_enum)) & mask
        for vn in self._inrefs:
            h = ((h << 8) | (h >> 56)) & mask
            if vn is None:
                continue
            if vn.isConstant():
                h ^= vn.getOffset() & mask
            else:
                h ^= vn.getCreateIndex() & mask
        return h

    def isCseMatch(self, other) -> bool:
        if (self.getEvalType() & (PcodeOp.unary | PcodeOp.binary)) == 0:
            return False
        if (other.getEvalType() & (PcodeOp.unary | PcodeOp.binary)) == 0:
            return False
        if self._output is None or other._output is None:
            return False
        if self._output.getSize() != other._output.getSize():
            return False
        if self._opcode_enum != other._opcode_enum:
            return False
        if self._opcode_enum == OpCode.CPUI_COPY:
            return False
        if len(self._inrefs) != len(other._inrefs):
            return False
        for i in range(len(self._inrefs)):
            vn1 = self._inrefs[i]
            vn2 = other._inrefs[i]
            if vn1 is vn2:
                continue
            if (
                vn1 is not None
                and vn2 is not None
                and vn1.isConstant()
                and vn2.isConstant()
                and vn1.getOffset() == vn2.getOffset()
            ):
                continue
            return False
        return True

    def getBasicIter(self):
        return getattr(self, '_basiciter', None)

    def setBasicIter(self, it):
        self._basiciter = it

    def getInsertIter(self):
        return getattr(self, '_insertiter', None)

    def getNZMaskLocal(self, clipsize: int) -> int:
        from ghidra.transform.nzmask import getNZMaskLocal as calc_nzmask_local
        return calc_nzmask_local(self, bool(clipsize))

    def _setMarkedInput(self, markedInput, val: bool) -> None:
        if markedInput is None:
            return
        if isinstance(markedInput, list):
            if markedInput:
                markedInput[0] = val
            else:
                markedInput.append(val)
        elif isinstance(markedInput, dict):
            markedInput['value'] = val
        elif hasattr(markedInput, 'value'):
            markedInput.value = val

    def collapse(self, markedInput=None):
        from ghidra.core.opbehavior import OpBehavior

        vn0 = self.getIn(0)
        outvn = self.getOut()
        if vn0 is None or outvn is None:
            raise LowlevelError("Invalid constant collapse")

        marked = vn0.getSymbolEntry() is not None
        behaviors = OpBehavior.registerInstructions()
        beh = behaviors[int(self._opcode_enum)] if int(self._opcode_enum) < len(behaviors) else None
        if beh is None:
            raise LowlevelError("Invalid constant collapse")

        eval_type = self.getEvalType()
        if eval_type == PcodeOp.unary:
            res = beh.evaluateUnary(outvn.getSize(), vn0.getSize(), vn0.getOffset())
        elif eval_type == PcodeOp.binary:
            vn1 = self.getIn(1)
            if vn1 is None:
                raise LowlevelError("Invalid constant collapse")
            if vn1.getSymbolEntry() is not None:
                marked = True
            res = beh.evaluateBinary(outvn.getSize(), vn0.getSize(), vn0.getOffset(), vn1.getOffset())
        else:
            raise LowlevelError("Invalid constant collapse")

        self._setMarkedInput(markedInput, marked)
        return res

    def executeSimple(self, inputs: list) -> tuple:
        """Execute this op on constant inputs.

        C++ ref: PcodeOp::executeSimple
        Returns (result, evalError).
        """
        evalType = self.getEvalType()
        try:
            if evalType == PcodeOp.unary:
                res = self._opcode.evaluateUnary(
                    self._output.getSize(), self._inrefs[0].getSize(), inputs[0])
            elif evalType == PcodeOp.binary:
                res = self._opcode.evaluateBinary(
                    self._output.getSize(), self._inrefs[0].getSize(), inputs[0], inputs[1])
            elif evalType == PcodeOp.ternary:
                res = self._opcode.evaluateTernary(
                    self._output.getSize(), self._inrefs[0].getSize(), inputs[0], inputs[1], inputs[2])
            else:
                raise Exception("Cannot perform simple execution of " + str(self.code()))
        except Exception:
            return 0, True
        return res, False

    def collapseConstantSymbol(self, vn):
        if vn is None:
            return
        copyVn = None
        opc = self.code()
        if opc == OpCode.CPUI_SUBPIECE:
            if self.getIn(1) is None or self.getIn(1).getOffset() != 0:
                return
            copyVn = self.getIn(0)
        elif opc in (OpCode.CPUI_COPY, OpCode.CPUI_INT_ZEXT, OpCode.CPUI_INT_NEGATE, OpCode.CPUI_INT_2COMP,
                     OpCode.CPUI_INT_LEFT, OpCode.CPUI_INT_RIGHT, OpCode.CPUI_INT_SRIGHT):
            copyVn = self.getIn(0)
        elif opc in (OpCode.CPUI_INT_ADD, OpCode.CPUI_INT_MULT, OpCode.CPUI_INT_AND, OpCode.CPUI_INT_OR, OpCode.CPUI_INT_XOR):
            copyVn = self.getIn(0)
            if copyVn is not None and copyVn.getSymbolEntry() is None:
                copyVn = self.getIn(1)
        else:
            return
        if copyVn is None or copyVn.getSymbolEntry() is None:
            return
        vn.copySymbolIfValid(copyVn)

    def printDebug(self) -> str:
        return self.printRaw()

    def outputTypeLocal(self):
        """Calculate the local output type."""
        if self._opcode is not None and hasattr(self._opcode, 'getOutputLocal'):
            return self._opcode.getOutputLocal(self)
        return None

    def inputTypeLocal(self, slot: int):
        """Calculate the local input type for a given slot."""
        if self._opcode is not None and hasattr(self._opcode, 'getInputLocal'):
            return self._opcode.getInputLocal(self, slot)
        return None

    def target(self):
        """Return starting op for instruction associated with this op.

        Scan backward to find the first op marked as start of instruction.
        C++ ref: ``PcodeOp::target``
        """
        p = self._parent
        if p is None:
            return self
        ops = list(p.getOps()) if hasattr(p, 'getOps') else []
        retop = self
        idx = -1
        for i, op in enumerate(ops):
            if op is self:
                idx = i
                break
        if idx < 0:
            return self
        while idx >= 0:
            retop = ops[idx]
            if retop._flags & PcodeOp.startmark:
                return retop
            idx -= 1
        return retop

    def encode(self, encoder) -> None:
        """Encode a description of this op to stream.

        C++ ref: ``PcodeOp::encode``
        """
        from ghidra.core.marshal import (
            ELEM_OP, ELEM_VOID, ELEM_ADDR, ELEM_IOP, ELEM_SPACEID,
            ATTRIB_CODE, ATTRIB_REF, ATTRIB_VALUE, ATTRIB_NAME,
        )
        from ghidra.core.space import IPTR_IOP, IPTR_CONSTANT
        from ghidra.core.opcodes import OpCode
        encoder.openElement(ELEM_OP)
        encoder.writeSignedInteger(ATTRIB_CODE, int(self._opcode_enum))
        self._start.encode(encoder)
        if self._output is None:
            encoder.openElement(ELEM_VOID)
            encoder.closeElement(ELEM_VOID)
        else:
            encoder.openElement(ELEM_ADDR)
            encoder.writeUnsignedInteger(ATTRIB_REF, self._output.getCreateIndex())
            encoder.closeElement(ELEM_ADDR)
        for i, vn in enumerate(self._inrefs):
            if vn is None:
                encoder.openElement(ELEM_VOID)
                encoder.closeElement(ELEM_VOID)
            elif vn.getSpace() is not None and vn.getSpace().getType() == IPTR_IOP:
                if i == 1 and self._opcode_enum == OpCode.CPUI_INDIRECT:
                    indop = PcodeOp.getOpFromConst(vn.getAddr())
                    if indop is not None:
                        encoder.openElement(ELEM_IOP)
                        encoder.writeUnsignedInteger(ATTRIB_VALUE, indop.getSeqNum().getTime())
                        encoder.closeElement(ELEM_IOP)
                    else:
                        encoder.openElement(ELEM_VOID)
                        encoder.closeElement(ELEM_VOID)
                else:
                    encoder.openElement(ELEM_VOID)
                    encoder.closeElement(ELEM_VOID)
            elif vn.getSpace() is not None and vn.getSpace().getType() == IPTR_CONSTANT:
                if i == 0 and self._opcode_enum in (OpCode.CPUI_STORE, OpCode.CPUI_LOAD):
                    spc = vn.getSpaceFromConst()
                    if spc is not None:
                        encoder.openElement(ELEM_SPACEID)
                        encoder.writeSpace(ATTRIB_NAME, spc)
                        encoder.closeElement(ELEM_SPACEID)
                    else:
                        encoder.openElement(ELEM_ADDR)
                        encoder.writeUnsignedInteger(ATTRIB_REF, vn.getCreateIndex())
                        encoder.closeElement(ELEM_ADDR)
                else:
                    encoder.openElement(ELEM_ADDR)
                    encoder.writeUnsignedInteger(ATTRIB_REF, vn.getCreateIndex())
                    encoder.closeElement(ELEM_ADDR)
            else:
                encoder.openElement(ELEM_ADDR)
                encoder.writeUnsignedInteger(ATTRIB_REF, vn.getCreateIndex())
                encoder.closeElement(ELEM_ADDR)
        encoder.closeElement(ELEM_OP)

    def setAllInput(self, newInputs: list) -> None:
        """Replace all inputs with the given list."""
        self._inrefs = list(newInputs)

    def __repr__(self) -> str:
        return f"PcodeOp({self.getOpName()} @ {self._start})"


# =========================================================================
# PcodeOpBank
# =========================================================================

class PcodeOpBank:
    """Container class for PcodeOps associated with a single function.

    Maintains multiple sorted structures for quick access.
    """

    def __init__(self) -> None:
        self._optree: Dict[SeqNum, PcodeOp] = {}  # Main sequence number sort
        self._deadlist: dict = {}   # id(op) -> op, O(1) membership/removal
        self._alivelist: dict = {}  # id(op) -> op, O(1) membership/removal
        self._storelist: dict = {}  # id(op) -> op
        self._loadlist: dict = {}   # id(op) -> op
        self._returnlist: dict = {} # id(op) -> op
        self._useroplist: dict = {} # id(op) -> op
        self._opcode_idx: dict = {}  # opcode_int -> {id(op): op} for O(1) beginByOpcode
        self._ordered_optree_cache: Optional[List[tuple[SeqNum, PcodeOp]]] = None
        self._ordered_optree_keys: Optional[List[SeqNum]] = None
        self._uniqid: int = 0

    @staticmethod
    def _opcode_key(value) -> Optional[int]:
        if value is None:
            return None
        if hasattr(value, "_opcode_enum"):
            return int(value._opcode_enum)
        if hasattr(value, "getOpcode"):
            return int(value.getOpcode())
        return int(value)

    def clear(self) -> None:
        self._optree.clear()
        self._deadlist.clear()
        self._alivelist.clear()
        self._storelist.clear()
        self._loadlist.clear()
        self._returnlist.clear()
        self._useroplist.clear()
        self._opcode_idx.clear()
        self._invalidateOrderedOptreeCache()

    def clearCodeLists(self) -> None:
        """Clear the opcode-specific code lists.

        C++ ref: PcodeOpBank::clearCodeLists
        """
        self._storelist.clear()
        self._loadlist.clear()
        self._returnlist.clear()
        self._useroplist.clear()

    def clearDead(self) -> None:
        """Remove all dead PcodeOps."""
        self._deadlist.clear()

    def setUniqId(self, val: int) -> None:
        self._uniqid = val

    def getUniqId(self) -> int:
        return self._uniqid

    def empty(self) -> bool:
        return len(self._optree) == 0

    def create(self, inputs: int, addr_or_sq) -> PcodeOp:
        """Create a PcodeOp with a given Address or SeqNum."""
        if isinstance(addr_or_sq, Address):
            sq = SeqNum(addr_or_sq, self._uniqid)
            self._uniqid += 1
        else:
            sq = addr_or_sq
        op = PcodeOp(inputs, sq)
        self._optree[sq] = op
        self._insertOrderedOptreeItem(sq, op)
        self._deadlist[id(op)] = op  # O(1) insert
        op.setFlag(PcodeOp.dead)
        return op

    def destroy(self, op: PcodeOp) -> None:
        """Destroy/retire the given PcodeOp."""
        if not op.isDead():
            raise LowlevelError("Deleting integrated op")
        sq = op.getSeqNum()
        self._optree.pop(sq, None)
        self._removeOrderedOptreeItem(sq, op)
        oid = id(op)
        self._deadlist.pop(oid, None)   # O(1)
        if self._alivelist.pop(oid, None) is not None:
            opc_int = self._opcode_key(op)
            if opc_int is not None:
                bucket = self._opcode_idx.get(opc_int)
                if bucket is not None:
                    bucket.pop(oid, None)
        self._removeFromCodeList(op)

    def destroyDead(self) -> None:
        """Destroy/retire all PcodeOps in the dead list."""
        for op in list(self._deadlist.values()):
            self.destroy(op)

    def markAlive(self, op: PcodeOp) -> None:
        """Mark the given PcodeOp as alive."""
        op.clearFlag(PcodeOp.dead)
        oid = id(op)
        self._deadlist.pop(oid, None)   # O(1)
        if oid not in self._alivelist:  # O(1)
            self._alivelist[oid] = op
            self._addToCodeList(op)
            opc_int = self._opcode_key(op)
            if opc_int is not None:
                bucket = self._opcode_idx.get(opc_int)
                if bucket is None:
                    self._opcode_idx[opc_int] = {oid: op}
                else:
                    bucket[oid] = op

    def markDead(self, op: PcodeOp) -> None:
        """Mark the given PcodeOp as dead."""
        op.setFlag(PcodeOp.dead)
        oid = id(op)
        if self._alivelist.pop(oid, None) is not None:
            opc_int = self._opcode_key(op)
            if opc_int is not None:
                bucket = self._opcode_idx.get(opc_int)
                if bucket is not None:
                    bucket.pop(oid, None)
        self._deadlist[oid] = op        # O(1)
        self._removeFromCodeList(op)

    def _addToCodeList(self, op: PcodeOp) -> None:
        opc = op.code()
        oid = id(op)
        if opc == OpCode.CPUI_STORE:
            self._storelist[oid] = op
        elif opc == OpCode.CPUI_LOAD:
            self._loadlist[oid] = op
        elif opc == OpCode.CPUI_RETURN:
            self._returnlist[oid] = op
        elif opc == OpCode.CPUI_CALLOTHER:
            self._useroplist[oid] = op

    def _removeFromCodeList(self, op: PcodeOp) -> None:
        oid = id(op)
        self._storelist.pop(oid, None)   # O(1)
        self._loadlist.pop(oid, None)    # O(1)
        self._returnlist.pop(oid, None)  # O(1)
        self._useroplist.pop(oid, None)  # O(1)

    def findOp(self, num: SeqNum) -> Optional[PcodeOp]:
        return self._optree.get(num)

    def _invalidateOrderedOptreeCache(self) -> None:
        self._ordered_optree_cache = None
        self._ordered_optree_keys = None

    def _insertOrderedOptreeItem(self, sq: SeqNum, op: PcodeOp) -> None:
        cache = self._ordered_optree_cache
        keys = self._ordered_optree_keys
        if cache is None or keys is None:
            return
        idx = bisect_right(keys, sq)
        keys.insert(idx, sq)
        cache.insert(idx, (sq, op))

    def _removeOrderedOptreeItem(self, sq: SeqNum, op: PcodeOp) -> None:
        cache = self._ordered_optree_cache
        keys = self._ordered_optree_keys
        if cache is None or keys is None:
            return
        idx = bisect_left(keys, sq)
        while idx < len(keys) and keys[idx] == sq:
            if cache[idx][1] is op:
                del keys[idx]
                del cache[idx]
                return
            idx += 1
        # Cache and backing map drifted; fall back to a full rebuild next time.
        self._invalidateOrderedOptreeCache()

    def _orderedOptreeItems(self) -> List[tuple[SeqNum, PcodeOp]]:
        cache = self._ordered_optree_cache
        if cache is None:
            cache = sorted(self._optree.items(), key=lambda item: item[0])
            self._ordered_optree_cache = cache
            self._ordered_optree_keys = [sq for sq, _ in cache]
        return cache

    def firstOp(self) -> Optional[PcodeOp]:
        ordered = self._orderedOptreeItems()
        if not ordered:
            return None
        return ordered[0][1]

    def nextAfter(self, seq: SeqNum) -> Optional[PcodeOp]:
        ordered = self._orderedOptreeItems()
        if not ordered:
            return None
        keys = self._ordered_optree_keys
        if keys is None:
            return None
        idx = bisect_right(keys, seq)
        if idx >= len(ordered):
            return None
        return ordered[idx][1]

    def target(self, addr: Address) -> Optional[PcodeOp]:
        """Find the first executing PcodeOp for a target address."""
        for sq, op in self._orderedOptreeItems():
            if sq.getAddr() == addr:
                return op
        return None

    def beginAll(self) -> Iterator[PcodeOp]:
        return iter(op for _, op in self._orderedOptreeItems())

    def beginAlive(self) -> Iterator[PcodeOp]:
        return iter(self._alivelist.values())

    def beginDead(self) -> Iterator[PcodeOp]:
        return iter(self._deadlist.values())

    def getStoreList(self) -> List[PcodeOp]:
        return list(self._storelist.values())

    def getReturnList(self) -> List[PcodeOp]:
        return list(self._returnlist.values())

    def getLoadList(self) -> List[PcodeOp]:
        return list(self._loadlist.values())

    def getUserOpList(self) -> List[PcodeOp]:
        return list(self._useroplist.values())

    def getDeadList(self) -> List[PcodeOp]:
        """Get all PcodeOps in the dead list."""
        return list(self._deadlist.values())

    def getAliveList(self) -> List[PcodeOp]:
        """Get all PcodeOps in the alive list."""
        return list(self._alivelist.values())

    def endDead(self):
        """End sentinel for dead list iteration."""
        return None

    def endAlive(self):
        """End sentinel for alive list iteration."""
        return None

    def endAll(self):
        """End sentinel for all ops iteration."""
        return None

    def getNextDead(self, op: PcodeOp) -> Optional[PcodeOp]:
        """Get the next op after the given op in the dead list."""
        dead_ops = list(self._deadlist.values())
        try:
            idx = dead_ops.index(op)
            if idx + 1 < len(dead_ops):
                return dead_ops[idx + 1]
        except ValueError:
            pass
        return None

    def changeOpcode(self, op: PcodeOp, newopc) -> None:
        """Change the op-code for the given PcodeOp."""
        oid = id(op)
        if oid in self._alivelist:
            old_opc_int = self._opcode_key(op)
            if old_opc_int is not None:
                bucket = self._opcode_idx.get(old_opc_int)
                if bucket is not None:
                    bucket.pop(oid, None)
        self._removeFromCodeList(op)
        op.setOpcode(newopc)
        self._addToCodeList(op)
        if oid in self._alivelist:
            opc_int = self._opcode_key(newopc if newopc is not None else op)
            if opc_int is None:
                return
            bucket = self._opcode_idx.get(opc_int)
            if bucket is None:
                self._opcode_idx[opc_int] = {oid: op}
            else:
                bucket[oid] = op

    def insertAfterDead(self, op: PcodeOp, prev: PcodeOp) -> None:
        """Insert the given PcodeOp after a point in the dead list."""
        op_id = id(op)
        items = [(oid, dead_op) for oid, dead_op in self._deadlist.items() if oid != op_id]
        insert_idx = len(items)
        for idx, (_, dead_op) in enumerate(items):
            if dead_op is prev:
                insert_idx = idx + 1
                break
        items.insert(insert_idx, (op_id, op))
        self._deadlist = dict(items)

    def moveSequenceDead(self, firstop: PcodeOp, lastop: PcodeOp, prev: PcodeOp) -> None:
        """Move a sequence of PcodeOps in the dead list to after prev."""
        items = list(self._deadlist.items())
        first_idx = next((idx for idx, (_, dead_op) in enumerate(items) if dead_op is firstop), -1)
        last_idx = next((idx for idx, (_, dead_op) in enumerate(items) if dead_op is lastop), -1)
        if first_idx < 0 or last_idx < first_idx:
            return

        seq = items[first_idx:last_idx + 1]
        seq_ids = {oid for oid, _ in seq}
        remaining = [(oid, dead_op) for oid, dead_op in items if oid not in seq_ids]

        insert_idx = len(remaining)
        for idx, (_, dead_op) in enumerate(remaining):
            if dead_op is prev:
                insert_idx = idx + 1
                break

        new_items = remaining[:insert_idx] + seq + remaining[insert_idx:]
        self._deadlist = dict(new_items)

    def markIncidentalCopy(self, firstop: PcodeOp, lastop: PcodeOp) -> None:
        """Mark any COPY ops in the given range as incidental."""
        in_range = False
        for op in self._deadlist:
            if op is firstop:
                in_range = True
            if in_range:
                if op.code() == OpCode.CPUI_COPY:
                    op.setAdditionalFlag(PcodeOp.incidental_copy)
            if op is lastop:
                break

    def fallthru(self, op: PcodeOp) -> Optional[PcodeOp]:
        """Find the PcodeOp considered a fallthru of the given PcodeOp."""
        return self.getNextDead(op)

    def beginByAddr(self, addr: Address) -> List[PcodeOp]:
        """Get all PcodeOps at the given address."""
        return [op for sq, op in self._orderedOptreeItems() if sq.getAddr() == addr]

    def beginByOpcode(self, opc: OpCode) -> List[PcodeOp]:
        """Get all alive PcodeOps with the given opcode."""
        bucket = self._opcode_idx.get(int(opc))
        return list(bucket.values()) if bucket else []


# =========================================================================
# PieceNode
# =========================================================================

class PieceNode:
    """A node in a tree structure of CPUI_PIECE operations.

    If a group of Varnodes are concatenated into a larger structure,
    this object explicitly gathers the PcodeOps and Varnodes.
    """

    def __init__(self, op, sl: int, off: int, leaf: bool) -> None:
        self._pieceOp = op
        self._slot: int = sl
        self._typeOffset: int = off
        self._leaf: bool = leaf

    def isLeaf(self) -> bool:
        return self._leaf

    def getTypeOffset(self) -> int:
        return self._typeOffset

    def getSlot(self) -> int:
        return self._slot

    def getOp(self):
        return self._pieceOp

    def getVarnode(self):
        return self._pieceOp.getIn(self._slot)

    @staticmethod
    def isLeafStatic(rootVn, vn, typeOffset: int) -> bool:
        """Check if vn is a leaf of the CONCAT tree rooted at rootVn."""
        if vn is rootVn:
            return False
        if vn.hasNoDescend():
            return True
        descs = list(vn.beginDescend())
        if len(descs) != 1:
            return True
        return descs[0].code() != OpCode.CPUI_PIECE

    @staticmethod
    def findRoot(vn):
        """Find the root Varnode of a PIECE tree containing vn."""
        while True:
            if vn.hasNoDescend():
                return vn
            descs = list(vn.beginDescend())
            if len(descs) != 1:
                return vn
            op = descs[0]
            if op.code() != OpCode.CPUI_PIECE:
                return vn
            vn = op.getOut()
        return vn

    @staticmethod
    def gatherPieces(stack: list, rootVn, op, baseOffset: int, rootOffset: int) -> None:
        """Gather all pieces in a CPUI_PIECE tree."""
        if op is None or op.code() != OpCode.CPUI_PIECE:
            return
        hiVn = op.getIn(0)  # Most significant
        loVn = op.getIn(1)  # Least significant
        loSize = loVn.getSize()
        # Process low part
        loOff = rootOffset
        if loVn.isWritten() and loVn.getDef().code() == OpCode.CPUI_PIECE:
            PieceNode.gatherPieces(stack, rootVn, loVn.getDef(), baseOffset, loOff)
        else:
            isLeaf = PieceNode.isLeafStatic(rootVn, loVn, loOff)
            stack.append(PieceNode(op, 1, loOff, isLeaf))
        # Process high part
        hiOff = rootOffset + loSize
        if hiVn.isWritten() and hiVn.getDef().code() == OpCode.CPUI_PIECE:
            PieceNode.gatherPieces(stack, rootVn, hiVn.getDef(), baseOffset, hiOff)
        else:
            isLeaf = PieceNode.isLeafStatic(rootVn, hiVn, hiOff)
            stack.append(PieceNode(op, 0, hiOff, isLeaf))
