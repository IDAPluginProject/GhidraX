"""
Corresponds to: unify.hh / unify.cc

Constraint unification system for rule matching in the decompiler.
Provides UnifyDatatype, UnifyState, RHSConstant hierarchy,
TraverseConstraint hierarchy, and the full UnifyConstraint class tree
for matching patterns against the data-flow graph.
"""

from __future__ import annotations

from typing import Dict, List, Optional, TYPE_CHECKING

if TYPE_CHECKING:
    from ghidra.ir.varnode import Varnode
    from ghidra.ir.op import PcodeOp
    from ghidra.block.block import BlockBasic
    from ghidra.analysis.funcdata import Funcdata


# =========================================================================
# UnifyDatatype
# =========================================================================

class UnifyDatatype:
    """A typed slot in the unification state — holds an op, varnode, constant, or block."""

    op_type = 0
    var_type = 1
    const_type = 2
    block_type = 3

    def __init__(self, tp: int = 0) -> None:
        self._type: int = tp
        self._op = None
        self._vn = None
        self._cn: int = 0
        self._bl = None

    def getType(self) -> int:
        return self._type

    def setOp(self, op) -> None:
        self._type = self.op_type
        self._op = op

    def getOp(self):
        return self._op

    def setVarnode(self, vn) -> None:
        self._type = self.var_type
        self._vn = vn

    def getVarnode(self):
        return self._vn

    def setBlock(self, bl) -> None:
        self._type = self.block_type
        self._bl = bl

    def getBlock(self):
        return self._bl

    def setConstant(self, val: int) -> None:
        self._type = self.const_type
        self._cn = val

    def getConstant(self) -> int:
        return self._cn

    def getBaseName(self) -> str:
        _names = {self.op_type: "op", self.var_type: "vn",
                  self.const_type: "cn", self.block_type: "bl"}
        return _names.get(self._type, "unknown")

    def printVarDecl(self, s, idx: int, cprinter) -> None:
        cprinter.printIndent(s)
        _decls = {self.op_type: "PcodeOp *", self.var_type: "Varnode *",
                  self.block_type: "BlockBasic *", self.const_type: "uintb "}
        s.write(_decls.get(self._type, "/* unknown */ "))
        s.write(f"{cprinter.getName(idx)};\n")


# =========================================================================
# RHSConstant hierarchy
# =========================================================================

class RHSConstant:
    """A construction that results in a constant on the right-hand side of an expression."""

    def clone(self) -> RHSConstant:
        raise NotImplementedError

    def getConstant(self, state: UnifyState) -> int:
        raise NotImplementedError

    def writeExpression(self, s, printstate) -> None:
        raise NotImplementedError


class ConstantNamed(RHSConstant):
    """A named constant referencing a slot in the unification state."""

    def __init__(self, constindex: int) -> None:
        self._constindex: int = constindex

    def getId(self) -> int:
        return self._constindex

    def clone(self) -> ConstantNamed:
        return ConstantNamed(self._constindex)

    def getConstant(self, state: UnifyState) -> int:
        return state.data(self._constindex).getConstant()

    def writeExpression(self, s, printstate) -> None:
        s.write(printstate.getName(self._constindex))


class ConstantAbsolute(RHSConstant):
    """An absolute constant value."""

    def __init__(self, val: int = 0) -> None:
        self._val: int = val

    def getVal(self) -> int:
        return self._val

    def clone(self) -> ConstantAbsolute:
        return ConstantAbsolute(self._val)

    def getConstant(self, state: UnifyState) -> int:
        return self._val

    def writeExpression(self, s, printstate) -> None:
        s.write(f"(uintb)0x{self._val & 0xFFFFFFFFFFFFFFFF:x}")


class ConstantNZMask(RHSConstant):
    """A varnode's non-zero mask."""

    def __init__(self, varindex: int) -> None:
        self._varindex: int = varindex

    def clone(self) -> ConstantNZMask:
        return ConstantNZMask(self._varindex)

    def getConstant(self, state: UnifyState) -> int:
        vn = state.data(self._varindex).getVarnode()
        return vn.getNZMask()

    def writeExpression(self, s, printstate) -> None:
        s.write(f"{printstate.getName(self._varindex)}->getNZMask()")


class ConstantConsumed(RHSConstant):
    """A varnode's consume mask."""

    def __init__(self, varindex: int) -> None:
        self._varindex: int = varindex

    def clone(self) -> ConstantConsumed:
        return ConstantConsumed(self._varindex)

    def getConstant(self, state: UnifyState) -> int:
        vn = state.data(self._varindex).getVarnode()
        return vn.getConsume()

    def writeExpression(self, s, printstate) -> None:
        s.write(f"{printstate.getName(self._varindex)}->getConsume()")


class ConstantOffset(RHSConstant):
    """A varnode's offset."""

    def __init__(self, varindex: int) -> None:
        self._varindex: int = varindex

    def clone(self) -> ConstantOffset:
        return ConstantOffset(self._varindex)

    def getConstant(self, state: UnifyState) -> int:
        vn = state.data(self._varindex).getVarnode()
        return vn.getOffset()

    def writeExpression(self, s, printstate) -> None:
        s.write(f"{printstate.getName(self._varindex)}->getOffset()")


class ConstantIsConstant(RHSConstant):
    """TRUE (1) if the varnode is constant, else 0."""

    def __init__(self, varindex: int) -> None:
        self._varindex: int = varindex

    def clone(self) -> ConstantIsConstant:
        return ConstantIsConstant(self._varindex)

    def getConstant(self, state: UnifyState) -> int:
        vn = state.data(self._varindex).getVarnode()
        return 1 if vn.isConstant() else 0

    def writeExpression(self, s, printstate) -> None:
        s.write(f"(uintb){printstate.getName(self._varindex)}->isConstant()")


class ConstantHeritageKnown(RHSConstant):
    """1 if the varnode's heritage is known, else 0."""

    def __init__(self, varindex: int) -> None:
        self._varindex: int = varindex

    def clone(self) -> ConstantHeritageKnown:
        return ConstantHeritageKnown(self._varindex)

    def getConstant(self, state: UnifyState) -> int:
        vn = state.data(self._varindex).getVarnode()
        return 1 if vn.isHeritageKnown() else 0

    def writeExpression(self, s, printstate) -> None:
        s.write(f"(uintb){printstate.getName(self._varindex)}->isHeritageKnown()")


class ConstantVarnodeSize(RHSConstant):
    """A varnode's size as a constant."""

    def __init__(self, varindex: int) -> None:
        self._varindex: int = varindex

    def clone(self) -> ConstantVarnodeSize:
        return ConstantVarnodeSize(self._varindex)

    def getConstant(self, state: UnifyState) -> int:
        vn = state.data(self._varindex).getVarnode()
        return vn.getSize()

    def writeExpression(self, s, printstate) -> None:
        s.write(f"(uintb){printstate.getName(self._varindex)}->getSize()")


class ConstantExpression(RHSConstant):
    """A binary/unary expression combining RHS constants via an OpCode."""

    def __init__(self, expr1: RHSConstant, expr2: Optional[RHSConstant], opc: int) -> None:
        self._expr1: RHSConstant = expr1
        self._expr2: Optional[RHSConstant] = expr2
        self._opc: int = opc

    def clone(self) -> ConstantExpression:
        e2 = self._expr2.clone() if self._expr2 is not None else None
        return ConstantExpression(self._expr1.clone(), e2, self._opc)

    def getConstant(self, state: UnifyState) -> int:
        behavior = state.getBehavior(self._opc)
        if behavior.isSpecial():
            raise RuntimeError("Cannot evaluate special operator in constant expression")
        if behavior.isUnary():
            c1 = self._expr1.getConstant(state)
            return behavior.evaluateUnary(8, 8, c1)
        c1 = self._expr1.getConstant(state)
        c2 = self._expr2.getConstant(state) if self._expr2 else 0
        return behavior.evaluateBinary(8, 8, c1, c2)

    def writeExpression(self, s, printstate) -> None:
        from ghidra.core.pcode import OpCode
        _binops = {
            OpCode.CPUI_INT_ADD: " + ", OpCode.CPUI_INT_SUB: " - ",
            OpCode.CPUI_INT_AND: " & ", OpCode.CPUI_INT_OR: " | ",
            OpCode.CPUI_INT_XOR: " ^ ", OpCode.CPUI_INT_MULT: " * ",
            OpCode.CPUI_INT_DIV: " / ", OpCode.CPUI_INT_EQUAL: " == ",
            OpCode.CPUI_INT_NOTEQUAL: " != ", OpCode.CPUI_INT_LESS: " < ",
            OpCode.CPUI_INT_LESSEQUAL: " <= ",
            OpCode.CPUI_INT_LEFT: " << ", OpCode.CPUI_INT_RIGHT: " >> ",
        }
        name = _binops.get(self._opc)
        if name is not None:
            s.write("(")
            self._expr1.writeExpression(s, printstate)
            s.write(name)
            if self._expr2:
                self._expr2.writeExpression(s, printstate)
            s.write(")")
        else:
            s.write("/* unknown op */")


# =========================================================================
# TraverseConstraint hierarchy
# =========================================================================

class TraverseConstraint:
    """Base class for traversal state during constraint stepping."""

    def __init__(self, uniqid: int) -> None:
        self._uniqid: int = uniqid


class TraverseDescendState(TraverseConstraint):
    """Iterate over all descendants (users) of a varnode."""

    def __init__(self, uniqid: int) -> None:
        super().__init__(uniqid)
        self._onestep: bool = False
        self._iter: Optional[list] = None
        self._pos: int = 0

    def getCurrentOp(self):
        return self._iter[self._pos - 1]

    def initialize(self, vn) -> None:
        self._onestep = False
        self._iter = list(vn.getDescend()) if hasattr(vn, 'getDescend') else []
        self._pos = 0

    def step(self) -> bool:
        if self._onestep:
            pass  # already advanced
        else:
            self._onestep = True
        if self._pos < len(self._iter):
            self._pos += 1
            return True
        return False


class TraverseCountState(TraverseConstraint):
    """Simple counter-based traversal state."""

    def __init__(self, uniqid: int) -> None:
        super().__init__(uniqid)
        self._state: int = -1
        self._endstate: int = 0

    def getState(self) -> int:
        return self._state

    def initialize(self, end: int) -> None:
        self._state = -1
        self._endstate = end

    def step(self) -> bool:
        self._state += 1
        return self._state != self._endstate


class TraverseGroupState(TraverseConstraint):
    """Group traversal state for ConstraintGroup."""

    def __init__(self, uniqid: int) -> None:
        super().__init__(uniqid)
        self._traverselist: List[TraverseConstraint] = []
        self._currentconstraint: int = 0
        self._state: int = -1

    def addTraverse(self, tc: TraverseConstraint) -> None:
        self._traverselist.append(tc)

    def getSubTraverse(self, slot: int) -> TraverseConstraint:
        return self._traverselist[slot]

    def getCurrentIndex(self) -> int:
        return self._currentconstraint

    def setCurrentIndex(self, val: int) -> None:
        self._currentconstraint = val

    def getState(self) -> int:
        return self._state

    def setState(self, val: int) -> None:
        self._state = val


# =========================================================================
# UnifyState
# =========================================================================

class UnifyState:
    """State container for a unification attempt.

    Holds a vector of UnifyDatatype slots and TraverseConstraint objects
    that constraints read/write during pattern matching.
    """

    def __init__(self, container=None) -> None:
        self._container = container
        self._storemap: List[UnifyDatatype] = []
        self._traverselist: List[TraverseConstraint] = []
        self._fd = None
        if container is not None:
            maxn = container.getMaxNum()
            self._storemap = [UnifyDatatype() for _ in range(maxn + 1)]
            container.collectTypes(self._storemap)
            container.buildTraverseState(self)

    def numTraverse(self) -> int:
        return len(self._traverselist)

    def registerTraverseConstraint(self, t: TraverseConstraint) -> None:
        self._traverselist.append(t)

    def data(self, slot: int) -> UnifyDatatype:
        while slot >= len(self._storemap):
            self._storemap.append(UnifyDatatype())
        return self._storemap[slot]

    def getTraverse(self, slot: int) -> TraverseConstraint:
        return self._traverselist[slot]

    def getFunction(self):
        return self._fd

    def setFunction(self, fd) -> None:
        self._fd = fd

    def getBehavior(self, opc: int):
        glb = self._fd.getArch()
        return glb.inst[opc].getBehavior()

    def initializeVarnode(self, idx: int, vn) -> None:
        self._storemap[idx].setVarnode(vn)

    def initializeOp(self, idx: int, op) -> None:
        self._storemap[idx].setOp(op)

    def initialize(self, idx: int, op) -> None:
        """Set up the initial op at the given index for rule matching."""
        self._storemap[idx].setOp(op)

    # Legacy API aliases
    def getData(self, index: int) -> UnifyDatatype:
        return self.data(index)

    def setData(self, index: int, val: UnifyDatatype) -> None:
        while index >= len(self._storemap):
            self._storemap.append(UnifyDatatype())
        self._storemap[index] = val

    def size(self) -> int:
        return len(self._storemap)

    def resize(self, n: int) -> None:
        while len(self._storemap) < n:
            self._storemap.append(UnifyDatatype())
        self._storemap = self._storemap[:n]

    def clear(self) -> None:
        self._storemap.clear()
        self._traverselist.clear()
        self._fd = None


# =========================================================================
# UnifyConstraint (base) and full hierarchy
# =========================================================================

class UnifyConstraint:
    """Base class for constraints used in rule unification."""

    def __init__(self) -> None:
        self._uniqid: int = 0
        self._maxnum: int = -1

    def _copyid(self, other: UnifyConstraint) -> UnifyConstraint:
        self._uniqid = other._uniqid
        self._maxnum = other._maxnum
        return self

    def getId(self) -> int:
        return self._uniqid

    def getMaxNum(self) -> int:
        return self._maxnum

    def clone(self) -> UnifyConstraint:
        raise NotImplementedError

    def initialize(self, state: UnifyState) -> None:
        traverse = state.getTraverse(self._uniqid)
        traverse.initialize(1)

    def step(self, state: UnifyState) -> bool:
        return False

    def buildTraverseState(self, state: UnifyState) -> None:
        if self._uniqid != state.numTraverse():
            raise RuntimeError("Traverse id does not match index")
        state.registerTraverseConstraint(TraverseCountState(self._uniqid))

    def setId(self, id_box: list) -> None:
        self._uniqid = id_box[0]
        id_box[0] += 1

    def collectTypes(self, typelist: List[UnifyDatatype]) -> None:
        pass

    def getBaseIndex(self) -> int:
        return -1

    def print(self, s, printstate=None) -> None:
        pass

    def isDummy(self) -> bool:
        return False

    def removeDummy(self) -> None:
        pass


# -- Dummy constraints (placeholders for type collection) ------------------

class DummyOpConstraint(UnifyConstraint):
    def __init__(self, opindex: int) -> None:
        super().__init__()
        self._opindex = opindex
        self._maxnum = opindex

    def clone(self) -> DummyOpConstraint:
        return DummyOpConstraint(self._opindex)._copyid(self)

    def step(self, state: UnifyState) -> bool:
        return True

    def collectTypes(self, typelist: List[UnifyDatatype]) -> None:
        typelist[self._opindex] = UnifyDatatype(UnifyDatatype.op_type)

    def getBaseIndex(self) -> int:
        return self._opindex

    def isDummy(self) -> bool:
        return True


class DummyVarnodeConstraint(UnifyConstraint):
    def __init__(self, varindex: int) -> None:
        super().__init__()
        self._varindex = varindex
        self._maxnum = varindex

    def clone(self) -> DummyVarnodeConstraint:
        return DummyVarnodeConstraint(self._varindex)._copyid(self)

    def step(self, state: UnifyState) -> bool:
        return True

    def collectTypes(self, typelist: List[UnifyDatatype]) -> None:
        typelist[self._varindex] = UnifyDatatype(UnifyDatatype.var_type)

    def getBaseIndex(self) -> int:
        return self._varindex

    def isDummy(self) -> bool:
        return True


class DummyConstConstraint(UnifyConstraint):
    def __init__(self, constindex: int) -> None:
        super().__init__()
        self._constindex = constindex
        self._maxnum = constindex

    def clone(self) -> DummyConstConstraint:
        return DummyConstConstraint(self._constindex)._copyid(self)

    def step(self, state: UnifyState) -> bool:
        return True

    def collectTypes(self, typelist: List[UnifyDatatype]) -> None:
        typelist[self._constindex] = UnifyDatatype(UnifyDatatype.const_type)

    def getBaseIndex(self) -> int:
        return self._constindex

    def isDummy(self) -> bool:
        return True


# -- Pattern-matching constraints ------------------------------------------

class ConstraintBoolean(UnifyConstraint):
    """Constant expression must evaluate to true (or false)."""

    def __init__(self, istrue: bool, expr: RHSConstant) -> None:
        super().__init__()
        self._istrue = istrue
        self._expr = expr
        self._maxnum = -1

    def clone(self) -> ConstraintBoolean:
        return ConstraintBoolean(self._istrue, self._expr.clone())._copyid(self)

    def step(self, state: UnifyState) -> bool:
        traverse = state.getTraverse(self._uniqid)
        if not traverse.step():
            return False
        val = self._expr.getConstant(state)
        if self._istrue:
            return val != 0
        return val == 0


class ConstraintVarConst(UnifyConstraint):
    """Create a new constant varnode."""

    def __init__(self, varindex: int, expr: RHSConstant, exprsz: Optional[RHSConstant] = None) -> None:
        super().__init__()
        self._varindex = varindex
        self._expr = expr
        self._exprsz = exprsz
        self._maxnum = varindex

    def clone(self) -> ConstraintVarConst:
        newsz = self._exprsz.clone() if self._exprsz else None
        return ConstraintVarConst(self._varindex, self._expr.clone(), newsz)._copyid(self)

    def step(self, state: UnifyState) -> bool:
        traverse = state.getTraverse(self._uniqid)
        if not traverse.step():
            return False
        val = self._expr.getConstant(state)
        fd = state.getFunction()
        sz = int(self._exprsz.getConstant(state)) if self._exprsz else 8
        mask = (1 << (sz * 8)) - 1
        val &= mask
        vn = fd.newConstant(sz, val)
        state.data(self._varindex).setVarnode(vn)
        return True

    def collectTypes(self, typelist: List[UnifyDatatype]) -> None:
        typelist[self._varindex] = UnifyDatatype(UnifyDatatype.var_type)

    def getBaseIndex(self) -> int:
        return self._varindex


class ConstraintNamedExpression(UnifyConstraint):
    """Evaluate an expression and store result in a named constant slot."""

    def __init__(self, constindex: int, expr: RHSConstant) -> None:
        super().__init__()
        self._constindex = constindex
        self._expr = expr
        self._maxnum = constindex

    def clone(self) -> ConstraintNamedExpression:
        return ConstraintNamedExpression(self._constindex, self._expr.clone())._copyid(self)

    def step(self, state: UnifyState) -> bool:
        traverse = state.getTraverse(self._uniqid)
        if not traverse.step():
            return False
        val = self._expr.getConstant(state)
        state.data(self._constindex).setConstant(val)
        return True

    def collectTypes(self, typelist: List[UnifyDatatype]) -> None:
        typelist[self._constindex] = UnifyDatatype(UnifyDatatype.const_type)

    def getBaseIndex(self) -> int:
        return self._constindex


class ConstraintOpCopy(UnifyConstraint):
    """Copy an op reference from one slot to another."""

    def __init__(self, oldopindex: int, newopindex: int) -> None:
        super().__init__()
        self._oldopindex = oldopindex
        self._newopindex = newopindex
        self._maxnum = max(oldopindex, newopindex)

    def clone(self) -> ConstraintOpCopy:
        return ConstraintOpCopy(self._oldopindex, self._newopindex)._copyid(self)

    def step(self, state: UnifyState) -> bool:
        traverse = state.getTraverse(self._uniqid)
        if not traverse.step():
            return False
        op = state.data(self._oldopindex).getOp()
        state.data(self._newopindex).setOp(op)
        return True

    def collectTypes(self, typelist: List[UnifyDatatype]) -> None:
        typelist[self._oldopindex] = UnifyDatatype(UnifyDatatype.op_type)
        typelist[self._newopindex] = UnifyDatatype(UnifyDatatype.op_type)

    def getBaseIndex(self) -> int:
        return self._oldopindex


class ConstraintOpcode(UnifyConstraint):
    """Constraint that matches specific opcode(s) at a slot."""

    def __init__(self, opindex: int, opcodes: List[int]) -> None:
        super().__init__()
        self._opindex = opindex
        self._opcodes = list(opcodes)
        self._maxnum = opindex

    def getOpCodes(self) -> List[int]:
        return self._opcodes

    def clone(self) -> ConstraintOpcode:
        return ConstraintOpcode(self._opindex, self._opcodes)._copyid(self)

    def step(self, state: UnifyState) -> bool:
        traverse = state.getTraverse(self._uniqid)
        if not traverse.step():
            return False
        op = state.data(self._opindex).getOp()
        return op.code() in self._opcodes

    def collectTypes(self, typelist: List[UnifyDatatype]) -> None:
        typelist[self._opindex] = UnifyDatatype(UnifyDatatype.op_type)

    def getBaseIndex(self) -> int:
        return self._opindex


class ConstraintOpCompare(UnifyConstraint):
    """Verify that two ops are the same (or different)."""

    def __init__(self, op1index: int, op2index: int, istrue: bool) -> None:
        super().__init__()
        self._op1index = op1index
        self._op2index = op2index
        self._istrue = istrue
        self._maxnum = max(op1index, op2index)

    def clone(self) -> ConstraintOpCompare:
        return ConstraintOpCompare(self._op1index, self._op2index, self._istrue)._copyid(self)

    def step(self, state: UnifyState) -> bool:
        traverse = state.getTraverse(self._uniqid)
        if not traverse.step():
            return False
        op1 = state.data(self._op1index).getOp()
        op2 = state.data(self._op2index).getOp()
        return (op1 is op2) == self._istrue

    def collectTypes(self, typelist: List[UnifyDatatype]) -> None:
        typelist[self._op1index] = UnifyDatatype(UnifyDatatype.op_type)
        typelist[self._op2index] = UnifyDatatype(UnifyDatatype.op_type)

    def getBaseIndex(self) -> int:
        return self._op1index


class ConstraintOpInput(UnifyConstraint):
    """Move from op to one of its input varnodes (specific slot)."""

    def __init__(self, opindex: int, varnodeindex: int, slot: int) -> None:
        super().__init__()
        self._opindex = opindex
        self._varnodeindex = varnodeindex
        self._slot = slot
        self._maxnum = max(opindex, varnodeindex)

    def clone(self) -> ConstraintOpInput:
        return ConstraintOpInput(self._opindex, self._varnodeindex, self._slot)._copyid(self)

    def step(self, state: UnifyState) -> bool:
        traverse = state.getTraverse(self._uniqid)
        if not traverse.step():
            return False
        op = state.data(self._opindex).getOp()
        vn = op.getIn(self._slot)
        state.data(self._varnodeindex).setVarnode(vn)
        return True

    def collectTypes(self, typelist: List[UnifyDatatype]) -> None:
        typelist[self._opindex] = UnifyDatatype(UnifyDatatype.op_type)
        typelist[self._varnodeindex] = UnifyDatatype(UnifyDatatype.var_type)

    def getBaseIndex(self) -> int:
        return self._varnodeindex


class ConstraintOpInputAny(UnifyConstraint):
    """Move from op to ANY of its input varnodes (iterate over all)."""

    def __init__(self, opindex: int, varnodeindex: int) -> None:
        super().__init__()
        self._opindex = opindex
        self._varnodeindex = varnodeindex
        self._maxnum = max(opindex, varnodeindex)

    def clone(self) -> ConstraintOpInputAny:
        return ConstraintOpInputAny(self._opindex, self._varnodeindex)._copyid(self)

    def initialize(self, state: UnifyState) -> None:
        traverse = state.getTraverse(self._uniqid)
        op = state.data(self._opindex).getOp()
        traverse.initialize(op.numInput())

    def step(self, state: UnifyState) -> bool:
        traverse = state.getTraverse(self._uniqid)
        if not traverse.step():
            return False
        op = state.data(self._opindex).getOp()
        vn = op.getIn(traverse.getState())
        state.data(self._varnodeindex).setVarnode(vn)
        return True

    def collectTypes(self, typelist: List[UnifyDatatype]) -> None:
        typelist[self._opindex] = UnifyDatatype(UnifyDatatype.op_type)
        typelist[self._varnodeindex] = UnifyDatatype(UnifyDatatype.var_type)

    def getBaseIndex(self) -> int:
        return self._varnodeindex


class ConstraintOpOutput(UnifyConstraint):
    """Move from op to its output varnode."""

    def __init__(self, opindex: int, varnodeindex: int) -> None:
        super().__init__()
        self._opindex = opindex
        self._varnodeindex = varnodeindex
        self._maxnum = max(opindex, varnodeindex)

    def clone(self) -> ConstraintOpOutput:
        return ConstraintOpOutput(self._opindex, self._varnodeindex)._copyid(self)

    def step(self, state: UnifyState) -> bool:
        traverse = state.getTraverse(self._uniqid)
        if not traverse.step():
            return False
        op = state.data(self._opindex).getOp()
        vn = op.getOut()
        state.data(self._varnodeindex).setVarnode(vn)
        return True

    def collectTypes(self, typelist: List[UnifyDatatype]) -> None:
        typelist[self._opindex] = UnifyDatatype(UnifyDatatype.op_type)
        typelist[self._varnodeindex] = UnifyDatatype(UnifyDatatype.var_type)

    def getBaseIndex(self) -> int:
        return self._varnodeindex


class ConstraintParamConstVal(UnifyConstraint):
    """Verify that a specific slot of an op is a constant with a specific value."""

    def __init__(self, opindex: int, slot: int, val: int) -> None:
        super().__init__()
        self._opindex = opindex
        self._slot = slot
        self._val = val
        self._maxnum = opindex

    def clone(self) -> ConstraintParamConstVal:
        return ConstraintParamConstVal(self._opindex, self._slot, self._val)._copyid(self)

    def step(self, state: UnifyState) -> bool:
        traverse = state.getTraverse(self._uniqid)
        if not traverse.step():
            return False
        op = state.data(self._opindex).getOp()
        vn = op.getIn(self._slot)
        if not vn.isConstant():
            return False
        mask = (1 << (vn.getSize() * 8)) - 1
        return vn.getOffset() == (self._val & mask)

    def collectTypes(self, typelist: List[UnifyDatatype]) -> None:
        typelist[self._opindex] = UnifyDatatype(UnifyDatatype.op_type)


class ConstraintParamConst(UnifyConstraint):
    """Extract constant value from a specific slot into a named constant."""

    def __init__(self, opindex: int, slot: int, constindex: int) -> None:
        super().__init__()
        self._opindex = opindex
        self._slot = slot
        self._constindex = constindex
        self._maxnum = max(opindex, constindex)

    def clone(self) -> ConstraintParamConst:
        return ConstraintParamConst(self._opindex, self._slot, self._constindex)._copyid(self)

    def step(self, state: UnifyState) -> bool:
        traverse = state.getTraverse(self._uniqid)
        if not traverse.step():
            return False
        op = state.data(self._opindex).getOp()
        vn = op.getIn(self._slot)
        if not vn.isConstant():
            return False
        state.data(self._constindex).setConstant(vn.getOffset())
        return True

    def collectTypes(self, typelist: List[UnifyDatatype]) -> None:
        typelist[self._opindex] = UnifyDatatype(UnifyDatatype.op_type)
        typelist[self._constindex] = UnifyDatatype(UnifyDatatype.const_type)

    def getBaseIndex(self) -> int:
        return self._constindex


class ConstraintVarnodeCopy(UnifyConstraint):
    """Copy a varnode reference from one slot to another."""

    def __init__(self, oldvarindex: int, newvarindex: int) -> None:
        super().__init__()
        self._oldvarindex = oldvarindex
        self._newvarindex = newvarindex
        self._maxnum = max(oldvarindex, newvarindex)

    def clone(self) -> ConstraintVarnodeCopy:
        return ConstraintVarnodeCopy(self._oldvarindex, self._newvarindex)._copyid(self)

    def step(self, state: UnifyState) -> bool:
        traverse = state.getTraverse(self._uniqid)
        if not traverse.step():
            return False
        vn = state.data(self._oldvarindex).getVarnode()
        state.data(self._newvarindex).setVarnode(vn)
        return True

    def collectTypes(self, typelist: List[UnifyDatatype]) -> None:
        typelist[self._oldvarindex] = UnifyDatatype(UnifyDatatype.var_type)
        typelist[self._newvarindex] = UnifyDatatype(UnifyDatatype.var_type)

    def getBaseIndex(self) -> int:
        return self._oldvarindex


class ConstraintVarCompare(UnifyConstraint):
    """Verify that two varnodes are the same (or different)."""

    def __init__(self, var1index: int, var2index: int, istrue: bool) -> None:
        super().__init__()
        self._var1index = var1index
        self._var2index = var2index
        self._istrue = istrue
        self._maxnum = max(var1index, var2index)

    def clone(self) -> ConstraintVarCompare:
        return ConstraintVarCompare(self._var1index, self._var2index, self._istrue)._copyid(self)

    def step(self, state: UnifyState) -> bool:
        traverse = state.getTraverse(self._uniqid)
        if not traverse.step():
            return False
        vn1 = state.data(self._var1index).getVarnode()
        vn2 = state.data(self._var2index).getVarnode()
        return (vn1 is vn2) == self._istrue

    def collectTypes(self, typelist: List[UnifyDatatype]) -> None:
        typelist[self._var1index] = UnifyDatatype(UnifyDatatype.var_type)
        typelist[self._var2index] = UnifyDatatype(UnifyDatatype.var_type)

    def getBaseIndex(self) -> int:
        return self._var1index


class ConstraintDef(UnifyConstraint):
    """Get the defining op of a varnode."""

    def __init__(self, opindex: int, varindex: int) -> None:
        super().__init__()
        self._opindex = opindex
        self._varindex = varindex
        self._maxnum = max(opindex, varindex)

    def clone(self) -> ConstraintDef:
        return ConstraintDef(self._opindex, self._varindex)._copyid(self)

    def step(self, state: UnifyState) -> bool:
        traverse = state.getTraverse(self._uniqid)
        if not traverse.step():
            return False
        vn = state.data(self._varindex).getVarnode()
        if not vn.isWritten():
            return False
        op = vn.getDef()
        state.data(self._opindex).setOp(op)
        return True

    def collectTypes(self, typelist: List[UnifyDatatype]) -> None:
        typelist[self._opindex] = UnifyDatatype(UnifyDatatype.op_type)
        typelist[self._varindex] = UnifyDatatype(UnifyDatatype.var_type)

    def getBaseIndex(self) -> int:
        return self._opindex


class ConstraintDescend(UnifyConstraint):
    """Iterate over all ops that read a varnode."""

    def __init__(self, opindex: int, varindex: int) -> None:
        super().__init__()
        self._opindex = opindex
        self._varindex = varindex
        self._maxnum = max(opindex, varindex)

    def clone(self) -> ConstraintDescend:
        return ConstraintDescend(self._opindex, self._varindex)._copyid(self)

    def buildTraverseState(self, state: UnifyState) -> None:
        if self._uniqid != state.numTraverse():
            raise RuntimeError("Traverse id does not match index")
        state.registerTraverseConstraint(TraverseDescendState(self._uniqid))

    def initialize(self, state: UnifyState) -> None:
        traverse = state.getTraverse(self._uniqid)
        vn = state.data(self._varindex).getVarnode()
        traverse.initialize(vn)

    def step(self, state: UnifyState) -> bool:
        traverse = state.getTraverse(self._uniqid)
        if not traverse.step():
            return False
        op = traverse.getCurrentOp()
        state.data(self._opindex).setOp(op)
        return True

    def collectTypes(self, typelist: List[UnifyDatatype]) -> None:
        typelist[self._opindex] = UnifyDatatype(UnifyDatatype.op_type)
        typelist[self._varindex] = UnifyDatatype(UnifyDatatype.var_type)

    def getBaseIndex(self) -> int:
        return self._opindex


class ConstraintLoneDescend(UnifyConstraint):
    """The varnode must have exactly one descendant op."""

    def __init__(self, opindex: int, varindex: int) -> None:
        super().__init__()
        self._opindex = opindex
        self._varindex = varindex
        self._maxnum = max(opindex, varindex)

    def clone(self) -> ConstraintLoneDescend:
        return ConstraintLoneDescend(self._opindex, self._varindex)._copyid(self)

    def step(self, state: UnifyState) -> bool:
        traverse = state.getTraverse(self._uniqid)
        if not traverse.step():
            return False
        vn = state.data(self._varindex).getVarnode()
        res = vn.loneDescend()
        if res is None:
            return False
        state.data(self._opindex).setOp(res)
        return True

    def collectTypes(self, typelist: List[UnifyDatatype]) -> None:
        typelist[self._opindex] = UnifyDatatype(UnifyDatatype.op_type)
        typelist[self._varindex] = UnifyDatatype(UnifyDatatype.var_type)

    def getBaseIndex(self) -> int:
        return self._opindex


class ConstraintOtherInput(UnifyConstraint):
    """For a binary op, given one input, get the other."""

    def __init__(self, opindex: int, varindex_in: int, varindex_out: int) -> None:
        super().__init__()
        self._opindex = opindex
        self._varindex_in = varindex_in
        self._varindex_out = varindex_out
        self._maxnum = max(opindex, varindex_in, varindex_out)

    def clone(self) -> ConstraintOtherInput:
        return ConstraintOtherInput(self._opindex, self._varindex_in, self._varindex_out)._copyid(self)

    def step(self, state: UnifyState) -> bool:
        traverse = state.getTraverse(self._uniqid)
        if not traverse.step():
            return False
        op = state.data(self._opindex).getOp()
        vn = state.data(self._varindex_in).getVarnode()
        res = op.getIn(1 - op.getSlot(vn))
        state.data(self._varindex_out).setVarnode(res)
        return True

    def collectTypes(self, typelist: List[UnifyDatatype]) -> None:
        typelist[self._opindex] = UnifyDatatype(UnifyDatatype.op_type)
        typelist[self._varindex_in] = UnifyDatatype(UnifyDatatype.var_type)
        typelist[self._varindex_out] = UnifyDatatype(UnifyDatatype.var_type)

    def getBaseIndex(self) -> int:
        return self._varindex_out


class ConstraintConstCompare(UnifyConstraint):
    """Compare two named constants using a boolean operation."""

    def __init__(self, const1index: int, const2index: int, opc: int) -> None:
        super().__init__()
        self._const1index = const1index
        self._const2index = const2index
        self._opc = opc
        self._maxnum = max(const1index, const2index)

    def clone(self) -> ConstraintConstCompare:
        return ConstraintConstCompare(self._const1index, self._const2index, self._opc)._copyid(self)

    def step(self, state: UnifyState) -> bool:
        traverse = state.getTraverse(self._uniqid)
        if not traverse.step():
            return False
        c1 = state.data(self._const1index).getConstant()
        c2 = state.data(self._const2index).getConstant()
        behavior = state.getBehavior(self._opc)
        res = behavior.evaluateBinary(1, 8, c1, c2)
        return res != 0

    def collectTypes(self, typelist: List[UnifyDatatype]) -> None:
        typelist[self._const1index] = UnifyDatatype(UnifyDatatype.const_type)
        typelist[self._const2index] = UnifyDatatype(UnifyDatatype.const_type)

    def getBaseIndex(self) -> int:
        return self._const1index


# -- Composite constraints -------------------------------------------------

class ConstraintGroup(UnifyConstraint):
    """All sub-constraints must match (AND). Tested first to last."""

    def __init__(self) -> None:
        super().__init__()
        self._constraintlist: List[UnifyConstraint] = []

    def getConstraint(self, slot: int) -> UnifyConstraint:
        return self._constraintlist[slot]

    def addConstraint(self, c: UnifyConstraint) -> None:
        self._constraintlist.append(c)
        if c.getMaxNum() > self._maxnum:
            self._maxnum = c.getMaxNum()

    def numConstraints(self) -> int:
        return len(self._constraintlist)

    def deleteConstraint(self, slot: int) -> None:
        del self._constraintlist[slot]

    def mergeIn(self, b: ConstraintGroup) -> None:
        for c in b._constraintlist:
            self.addConstraint(c)
        b._constraintlist.clear()

    def clone(self) -> ConstraintGroup:
        res = ConstraintGroup()
        for c in self._constraintlist:
            res._constraintlist.append(c.clone())
        res._copyid(self)
        return res

    def initialize(self, state: UnifyState) -> None:
        traverse = state.getTraverse(self._uniqid)
        traverse.setState(-1)

    def step(self, state: UnifyState) -> bool:
        traverse = state.getTraverse(self._uniqid)
        maxn = len(self._constraintlist)
        while True:
            stateint = traverse.getState()
            subindex = traverse.getCurrentIndex()
            if stateint == 0:
                subconstraint = self._constraintlist[subindex]
                if subconstraint.step(state):
                    traverse.setState(1)
                    subindex += 1
                    traverse.setCurrentIndex(subindex)
                else:
                    subindex -= 1
                    if subindex < 0:
                        return False
                    traverse.setCurrentIndex(subindex)
                    traverse.setState(0)
            elif stateint == 1:
                subconstraint = self._constraintlist[subindex]
                subconstraint.initialize(state)
                traverse.setState(0)
            else:
                traverse.setCurrentIndex(0)
                subindex = 0
                subconstraint = self._constraintlist[0]
                subconstraint.initialize(state)
                traverse.setState(0)
            if subindex >= maxn:
                break
        subindex -= 1
        traverse.setCurrentIndex(subindex)
        traverse.setState(0)
        return True

    def collectTypes(self, typelist: List[UnifyDatatype]) -> None:
        for c in self._constraintlist:
            c.collectTypes(typelist)

    def buildTraverseState(self, state: UnifyState) -> None:
        if self._uniqid != state.numTraverse():
            raise RuntimeError("Traverse id does not match index")
        basetrav = TraverseGroupState(self._uniqid)
        state.registerTraverseConstraint(basetrav)
        for sub in self._constraintlist:
            sub.buildTraverseState(state)
            subtrav = state.getTraverse(sub.getId())
            basetrav.addTraverse(subtrav)

    def setId(self, id_box: list) -> None:
        super().setId(id_box)
        for c in self._constraintlist:
            c.setId(id_box)

    def getBaseIndex(self) -> int:
        if self._constraintlist:
            return self._constraintlist[-1].getBaseIndex()
        return -1

    def print(self, s, printstate=None) -> None:
        for c in self._constraintlist:
            c.print(s, printstate)

    def removeDummy(self) -> None:
        newlist = []
        for c in self._constraintlist:
            if c.isDummy():
                pass
            else:
                c.removeDummy()
                newlist.append(c)
        self._constraintlist = newlist


class ConstraintOr(ConstraintGroup):
    """Exactly one sub-constraint needs to be true (OR)."""

    def clone(self) -> ConstraintOr:
        res = ConstraintOr()
        for c in self._constraintlist:
            res._constraintlist.append(c.clone())
        res._copyid(self)
        return res

    def initialize(self, state: UnifyState) -> None:
        traverse = state.getTraverse(self._uniqid)
        traverse.initialize(len(self._constraintlist))

    def step(self, state: UnifyState) -> bool:
        traverse = state.getTraverse(self._uniqid)
        stateind = traverse.getState()
        if stateind == -1:
            if not traverse.step():
                return False
            stateind = traverse.getState()
            cur = self.getConstraint(stateind)
            cur.initialize(state)
        else:
            cur = self.getConstraint(stateind)
        while True:
            if cur.step(state):
                return True
            if not traverse.step():
                break
            stateind = traverse.getState()
            cur = self.getConstraint(stateind)
            cur.initialize(state)
        return False

    def buildTraverseState(self, state: UnifyState) -> None:
        if self._uniqid != state.numTraverse():
            raise RuntimeError("Traverse id does not match index in or")
        state.registerTraverseConstraint(TraverseCountState(self._uniqid))
        for sub in self._constraintlist:
            sub.buildTraverseState(state)

    def getBaseIndex(self) -> int:
        return -1


# -- Action constraints (always step exactly once, return True) ------------

class ConstraintNewOp(UnifyConstraint):
    """Create a new PcodeOp and insert it relative to an existing op."""

    def __init__(self, newopindex: int, oldopindex: int, opc: int,
                 insertafter: bool, numparams: int) -> None:
        super().__init__()
        self._newopindex = newopindex
        self._oldopindex = oldopindex
        self._opc = opc
        self._insertafter = insertafter
        self._numparams = numparams
        self._maxnum = max(newopindex, oldopindex)

    def clone(self) -> ConstraintNewOp:
        return ConstraintNewOp(self._newopindex, self._oldopindex, self._opc,
                               self._insertafter, self._numparams)._copyid(self)

    def step(self, state: UnifyState) -> bool:
        traverse = state.getTraverse(self._uniqid)
        if not traverse.step():
            return False
        fd = state.getFunction()
        op = state.data(self._oldopindex).getOp()
        newop = fd.newOp(self._numparams, op.getAddr())
        fd.opSetOpcode(newop, self._opc)
        if self._insertafter:
            fd.opInsertAfter(newop, op)
        else:
            fd.opInsertBefore(newop, op)
        state.data(self._newopindex).setOp(newop)
        return True

    def collectTypes(self, typelist: List[UnifyDatatype]) -> None:
        typelist[self._newopindex] = UnifyDatatype(UnifyDatatype.op_type)
        typelist[self._oldopindex] = UnifyDatatype(UnifyDatatype.op_type)

    def getBaseIndex(self) -> int:
        return self._newopindex


class ConstraintNewUniqueOut(UnifyConstraint):
    """Create a new unique output varnode for an op."""

    def __init__(self, opindex: int, newvarindex: int, sizevarindex: int) -> None:
        super().__init__()
        self._opindex = opindex
        self._newvarindex = newvarindex
        self._sizevarindex = sizevarindex
        self._maxnum = max(opindex, newvarindex)
        if sizevarindex > self._maxnum:
            self._maxnum = sizevarindex

    def clone(self) -> ConstraintNewUniqueOut:
        return ConstraintNewUniqueOut(self._opindex, self._newvarindex, self._sizevarindex)._copyid(self)

    def step(self, state: UnifyState) -> bool:
        traverse = state.getTraverse(self._uniqid)
        if not traverse.step():
            return False
        fd = state.getFunction()
        op = state.data(self._opindex).getOp()
        if self._sizevarindex < 0:
            sz = -self._sizevarindex
        else:
            sizevn = state.data(self._sizevarindex).getVarnode()
            sz = sizevn.getSize()
        newvn = fd.newUniqueOut(sz, op)
        state.data(self._newvarindex).setVarnode(newvn)
        return True

    def collectTypes(self, typelist: List[UnifyDatatype]) -> None:
        typelist[self._opindex] = UnifyDatatype(UnifyDatatype.op_type)
        typelist[self._newvarindex] = UnifyDatatype(UnifyDatatype.var_type)
        if self._sizevarindex >= 0:
            typelist[self._sizevarindex] = UnifyDatatype(UnifyDatatype.var_type)

    def getBaseIndex(self) -> int:
        return self._newvarindex


class ConstraintSetInput(UnifyConstraint):
    """Set an input of an op to a varnode."""

    def __init__(self, opindex: int, slot: RHSConstant, varindex: int) -> None:
        super().__init__()
        self._opindex = opindex
        self._slot = slot
        self._varindex = varindex
        self._maxnum = max(opindex, varindex)

    def clone(self) -> ConstraintSetInput:
        return ConstraintSetInput(self._opindex, self._slot.clone(), self._varindex)._copyid(self)

    def step(self, state: UnifyState) -> bool:
        traverse = state.getTraverse(self._uniqid)
        if not traverse.step():
            return False
        fd = state.getFunction()
        op = state.data(self._opindex).getOp()
        vn = state.data(self._varindex).getVarnode()
        slt = int(self._slot.getConstant(state))
        fd.opSetInput(op, vn, slt)
        return True

    def collectTypes(self, typelist: List[UnifyDatatype]) -> None:
        typelist[self._opindex] = UnifyDatatype(UnifyDatatype.op_type)
        typelist[self._varindex] = UnifyDatatype(UnifyDatatype.var_type)

    def getBaseIndex(self) -> int:
        return self._varindex


class ConstraintSetInputConstVal(UnifyConstraint):
    """Set an input of an op to a new constant varnode."""

    def __init__(self, opindex: int, slot: RHSConstant, val: RHSConstant,
                 exprsz: Optional[RHSConstant] = None) -> None:
        super().__init__()
        self._opindex = opindex
        self._slot = slot
        self._val = val
        self._exprsz = exprsz
        self._maxnum = opindex

    def clone(self) -> ConstraintSetInputConstVal:
        newsz = self._exprsz.clone() if self._exprsz else None
        return ConstraintSetInputConstVal(
            self._opindex, self._slot.clone(), self._val.clone(), newsz)._copyid(self)

    def step(self, state: UnifyState) -> bool:
        traverse = state.getTraverse(self._uniqid)
        if not traverse.step():
            return False
        fd = state.getFunction()
        op = state.data(self._opindex).getOp()
        ourconst = self._val.getConstant(state)
        sz = int(self._exprsz.getConstant(state)) if self._exprsz else 8
        slt = int(self._slot.getConstant(state))
        mask = (1 << (sz * 8)) - 1
        fd.opSetInput(op, fd.newConstant(sz, ourconst & mask), slt)
        return True

    def collectTypes(self, typelist: List[UnifyDatatype]) -> None:
        typelist[self._opindex] = UnifyDatatype(UnifyDatatype.op_type)


class ConstraintRemoveInput(UnifyConstraint):
    """Remove an input from an op."""

    def __init__(self, opindex: int, slot: RHSConstant) -> None:
        super().__init__()
        self._opindex = opindex
        self._slot = slot
        self._maxnum = opindex

    def clone(self) -> ConstraintRemoveInput:
        return ConstraintRemoveInput(self._opindex, self._slot.clone())._copyid(self)

    def step(self, state: UnifyState) -> bool:
        traverse = state.getTraverse(self._uniqid)
        if not traverse.step():
            return False
        fd = state.getFunction()
        op = state.data(self._opindex).getOp()
        slt = int(self._slot.getConstant(state))
        fd.opRemoveInput(op, slt)
        return True

    def collectTypes(self, typelist: List[UnifyDatatype]) -> None:
        typelist[self._opindex] = UnifyDatatype(UnifyDatatype.op_type)

    def getBaseIndex(self) -> int:
        return self._opindex


class ConstraintSetOpcode(UnifyConstraint):
    """Change the opcode of an op."""

    def __init__(self, opindex: int, opc: int) -> None:
        super().__init__()
        self._opindex = opindex
        self._opc = opc
        self._maxnum = opindex

    def clone(self) -> ConstraintSetOpcode:
        return ConstraintSetOpcode(self._opindex, self._opc)._copyid(self)

    def step(self, state: UnifyState) -> bool:
        traverse = state.getTraverse(self._uniqid)
        if not traverse.step():
            return False
        fd = state.getFunction()
        op = state.data(self._opindex).getOp()
        fd.opSetOpcode(op, self._opc)
        return True

    def collectTypes(self, typelist: List[UnifyDatatype]) -> None:
        typelist[self._opindex] = UnifyDatatype(UnifyDatatype.op_type)

    def getBaseIndex(self) -> int:
        return self._opindex


# =========================================================================
# UnifyCPrinter
# =========================================================================

class UnifyCPrinter:
    """Generates C code from a constraint group (for rule compilation)."""

    def __init__(self) -> None:
        self._storemap: List[UnifyDatatype] = []
        self._namemap: List[str] = []
        self._depth: int = 0
        self._printingtype: int = 0
        self._classname: str = ""
        self._opparam: int = -1
        self._opcodelist: List[int] = []
        self._grp: Optional[ConstraintGroup] = None

    def getDepth(self) -> int:
        return self._depth

    def incDepth(self) -> None:
        self._depth += 1

    def decDepth(self) -> None:
        self._depth -= 1

    def printIndent(self, s) -> None:
        s.write("  " * (self._depth + 1))

    def printAbort(self, s) -> None:
        self._depth += 1
        self.printIndent(s)
        if self._depth > 1:
            s.write("continue;")
        elif self._printingtype == 0:
            s.write("return 0;")
        else:
            s.write("return false;")
        self._depth -= 1
        s.write("\n")

    def popDepth(self, s, newdepth: int) -> None:
        while self._depth != newdepth:
            self._depth -= 1
            self.printIndent(s)
            s.write("}\n")

    def getName(self, idx: int) -> str:
        if idx < len(self._namemap):
            return self._namemap[idx]
        return f"unk{idx}"

    def _initializeBase(self, g: ConstraintGroup) -> None:
        self._grp = g
        self._depth = 0
        self._namemap.clear()
        self._storemap.clear()
        self._opparam = -1
        self._opcodelist.clear()
        maxop = g.getMaxNum()
        self._storemap = [UnifyDatatype() for _ in range(maxop + 1)]
        g.collectTypes(self._storemap)
        for i in range(maxop + 1):
            self._namemap.append(f"{self._storemap[i].getBaseName()}{i}")

    def initializeRuleAction(self, g: ConstraintGroup, opparam: int, oplist: List[int]) -> None:
        self._initializeBase(g)
        self._printingtype = 0
        self._classname = "DummyRule"
        self._opparam = opparam
        self._opcodelist = list(oplist)

    def initializeBasic(self, g: ConstraintGroup) -> None:
        self._initializeBase(g)
        self._printingtype = 1
        self._opparam = -1

    def setClassName(self, nm: str) -> None:
        self._classname = nm

    def addNames(self, nmmap: Dict[str, int]) -> None:
        for name, slot in nmmap.items():
            if slot >= len(self._namemap):
                raise RuntimeError("Name indices do not match constraint")
            self._namemap[slot] = name

    def printVarDecls(self, s) -> None:
        for i in range(len(self._namemap)):
            if i == self._opparam:
                continue
            self._storemap[i].printVarDecl(s, i, self)
        if self._namemap:
            s.write("\n")

    def print(self, s) -> None:
        if self._grp is None:
            return
        if self._printingtype == 0:
            self.printVarDecls(s)
            self._grp.print(s, self)
            self.printIndent(s)
            s.write("return 1;\n")
            if self._depth != 0:
                self.popDepth(s, 0)
                self.printIndent(s)
                s.write("return 0;\n")
            s.write("}\n")
        elif self._printingtype == 1:
            self.printVarDecls(s)
            self._grp.print(s, self)
            self.printIndent(s)
            s.write("return true;\n")
            if self._depth != 0:
                self.popDepth(s, 0)
                self.printIndent(s)
                s.write("return false;\n")
            s.write("}\n")
