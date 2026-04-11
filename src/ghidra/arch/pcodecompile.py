"""
Corresponds to: pcodecompile.hh / pcodecompile.cc

P-code snippet compiler.  In the C++ implementation this uses SLEIGH
grammar to compile p-code syntax into ConstructTpl/OpTpl/VarnodeTpl
templates.  Per the project architecture, the actual SLEIGH compilation
stays in the native C++ module (sleigh_native.pyd).

This module provides:
  - Location: source location tracking (filename + line number)
  - ExprTree: a flattened expression tree of p-code ops (Python-side stub)
  - PcodeCompile: abstract base for p-code compilation (Python-side stub)

These stubs enable type-checking and interface compatibility for pure-Python
modules that reference pcodecompile types, while actual compilation is
delegated to the native SLEIGH engine.
"""

from __future__ import annotations

from abc import ABC, abstractmethod
from copy import copy
from typing import Any, Optional, List, TYPE_CHECKING

from ghidra.core.error import LowlevelError
from ghidra.core.opcodes import OpCode
from ghidra.core.space import IPTR_CONSTANT, IPTR_INTERNAL
from ghidra.sleigh.sleighbase import SleighSymbol, VarnodeSymbol

if TYPE_CHECKING:
    from ghidra.core.space import AddrSpace


# =========================================================================
# Location
# =========================================================================

class Location:
    """Source location for error reporting during p-code compilation."""

    def __init__(self, filename: str = "", lineno: int = 0) -> None:
        self.filename: str = filename
        self.lineno: int = lineno

    def getFilename(self) -> str:
        return self.filename

    def getLineno(self) -> int:
        return self.lineno

    def format(self) -> str:
        return f"{self.filename}:{self.lineno}"

    def __repr__(self) -> str:
        return f"Location({self.filename!r}, {self.lineno})"


class SleighError(LowlevelError):
    pass


# =========================================================================
# StarQuality
# =========================================================================

class StarQuality:
    """Dereference qualifier for load/store operations."""

    def __init__(self, space_id: Any = 0, size: int = 0) -> None:
        self.id = space_id
        self.size: int = size


class ConstTpl:
    """Minimal Python analogue of ghidra::ConstTpl for p-code template helpers."""

    real = 0
    handle = 1
    j_start = 2
    j_next = 3
    j_next2 = 4
    j_curspace = 5
    j_curspace_size = 6
    spaceid = 7
    j_relative = 8
    j_flowref = 9
    j_flowref_size = 10
    j_flowdest = 11
    j_flowdest_size = 12

    v_space = 0
    v_offset = 1
    v_size = 2
    v_offset_plus = 3

    def __init__(self, *args) -> None:
        self.type = ConstTpl.real
        self.spaceid = None
        self.handle_index = 0
        self.value_real = 0
        self.select = ConstTpl.v_space

        if len(args) == 0:
            return
        if len(args) == 1:
            arg = args[0]
            if isinstance(arg, ConstTpl):
                self.type = arg.type
                self.spaceid = arg.spaceid
                self.handle_index = arg.handle_index
                self.value_real = arg.value_real
                self.select = arg.select
            else:
                self.type = ConstTpl.spaceid
                self.spaceid = arg
            return
        if len(args) == 2:
            tp, val = args
            self.type = tp
            if tp == ConstTpl.spaceid:
                self.spaceid = val
            elif tp == ConstTpl.handle:
                self.handle_index = int(val)
            else:
                self.value_real = int(val)
            return
        if len(args) in (3, 4):
            _, handle_index, select, *rest = args
            self.type = ConstTpl.handle
            self.handle_index = int(handle_index)
            self.select = select
            self.value_real = int(rest[0]) if rest else 0
            return
        raise TypeError("ConstTpl constructor does not match native overloads")

    def getReal(self) -> int:
        return self.value_real

    def getSpace(self):
        return self.spaceid

    def getHandleIndex(self) -> int:
        return self.handle_index

    def getType(self) -> int:
        return self.type

    def getSelect(self) -> int:
        return self.select

    def isConstSpace(self) -> bool:
        return self.type == ConstTpl.spaceid and self.spaceid.getType() == IPTR_CONSTANT

    def isUniqueSpace(self) -> bool:
        return self.type == ConstTpl.spaceid and self.spaceid.getType() == IPTR_INTERNAL

    def isZero(self) -> bool:
        return self.type == ConstTpl.real and self.value_real == 0

    def clone(self) -> "ConstTpl":
        return ConstTpl(self)

    def __eq__(self, other: object) -> bool:
        if not isinstance(other, ConstTpl):
            return NotImplemented
        return (
            self.type == other.type
            and self.spaceid is other.spaceid
            and self.handle_index == other.handle_index
            and self.value_real == other.value_real
            and self.select == other.select
        )


class VarnodeTpl:
    """Minimal Python analogue of ghidra::VarnodeTpl."""

    def __init__(self, *args) -> None:
        self.space = ConstTpl()
        self.offset = ConstTpl()
        self.size = ConstTpl()
        self.unnamed_flag = False

        if len(args) == 0:
            return
        if len(args) == 1 and isinstance(args[0], VarnodeTpl):
            vn = args[0]
            self.space = vn.space.clone()
            self.offset = vn.offset.clone()
            self.size = vn.size.clone()
            self.unnamed_flag = vn.unnamed_flag
            return
        if len(args) == 2:
            hand, zerosize = args
            self.space = ConstTpl(ConstTpl.handle, hand, ConstTpl.v_space)
            self.offset = ConstTpl(ConstTpl.handle, hand, ConstTpl.v_offset)
            self.size = ConstTpl(ConstTpl.handle, hand, ConstTpl.v_size)
            if zerosize:
                self.size = ConstTpl(ConstTpl.real, 0)
            return
        if len(args) == 3:
            sp, off, sz = args
            self.space = ConstTpl(sp)
            self.offset = ConstTpl(off)
            self.size = ConstTpl(sz)
            return
        raise TypeError("VarnodeTpl constructor does not match native overloads")

    def getSpace(self) -> ConstTpl:
        return self.space

    def getOffset(self) -> ConstTpl:
        return self.offset

    def getSize(self) -> ConstTpl:
        return self.size

    def isZeroSize(self) -> bool:
        return self.size.isZero()

    def setOffset(self, const_val: int) -> None:
        self.offset = ConstTpl(ConstTpl.real, const_val)

    def setRelative(self, const_val: int) -> None:
        self.offset = ConstTpl(ConstTpl.j_relative, const_val)

    def setSize(self, sz: ConstTpl) -> None:
        self.size = ConstTpl(sz)

    def isUnnamed(self) -> bool:
        return self.unnamed_flag

    def setUnnamed(self, val: bool) -> None:
        self.unnamed_flag = val

    def isLocalTemp(self) -> bool:
        if self.space.getType() != ConstTpl.spaceid:
            return False
        return self.space.getSpace().getType() == IPTR_INTERNAL

    def isRelative(self) -> bool:
        return self.offset.getType() == ConstTpl.j_relative

    def clone(self) -> "VarnodeTpl":
        return VarnodeTpl(self)

    def __eq__(self, other: object) -> bool:
        if not isinstance(other, VarnodeTpl):
            return NotImplemented
        return (
            self.space == other.space
            and self.offset == other.offset
            and self.size == other.size
            and self.unnamed_flag == other.unnamed_flag
        )


class OpTpl:
    """Minimal Python analogue of ghidra::OpTpl."""

    def __init__(self, oc: Optional[int | OpCode] = None) -> None:
        self.output: Optional[VarnodeTpl] = None
        self.opcode: Optional[OpCode] = None
        self.input: List[VarnodeTpl] = []
        if oc is not None:
            self.opcode = oc if isinstance(oc, OpCode) else OpCode(oc)

    def getOut(self) -> Optional[VarnodeTpl]:
        return self.output

    def numInput(self) -> int:
        return len(self.input)

    def getIn(self, i: int) -> VarnodeTpl:
        return self.input[i]

    def getOpcode(self) -> Optional[OpCode]:
        return self.opcode

    def isZeroSize(self) -> bool:
        if self.output is not None and self.output.isZeroSize():
            return True
        return any(vn.isZeroSize() for vn in self.input)

    def setOpcode(self, opcode: int | OpCode) -> None:
        self.opcode = opcode if isinstance(opcode, OpCode) else OpCode(opcode)

    def setOutput(self, vt: VarnodeTpl) -> None:
        self.output = vt

    def clearOutput(self) -> None:
        self.output = None

    def addInput(self, vt: VarnodeTpl) -> None:
        self.input.append(vt)

    def setInput(self, vt: VarnodeTpl, slot: int) -> None:
        self.input[slot] = vt


class LabelSymbol(SleighSymbol):
    """Minimal Python analogue of ghidra::LabelSymbol."""

    def __init__(self, nm: str, index: int) -> None:
        super().__init__(nm, SleighSymbol.label_symbol)
        self.index = index
        self.refcount = 0
        self.isplaced = False

    def getIndex(self) -> int:
        return self.index

    def incrementRefCount(self) -> None:
        self.refcount += 1

    def getRefCount(self) -> int:
        return self.refcount

    def setPlaced(self) -> None:
        self.isplaced = True

    def isPlaced(self) -> bool:
        return self.isplaced


# =========================================================================
# ExprTree
# =========================================================================


def _clone_like_cpp(obj):
    if obj is None:
        return None
    if hasattr(obj, "clone"):
        return obj.clone()
    try:
        return type(obj)(obj)
    except Exception:
        return copy(obj)


class _SyntheticCopyOp:
    def __init__(self) -> None:
        self.opcode = OpCode.CPUI_COPY
        self._inputs: List[Any] = []
        self._output = None

    def addInput(self, vn) -> None:
        self._inputs.append(vn)

    def setOutput(self, outvn) -> None:
        self._output = outvn

    def clearOutput(self) -> None:
        self._output = None

    def getOut(self):
        return self._output

class ExprTree:
    """A flattened expression tree of p-code template ops.

    In C++ this holds a list of OpTpl* and an output VarnodeTpl*.
    This Python stub provides the interface for code that needs to
    build or manipulate expression trees; actual construction is done
    by the native SLEIGH compiler.
    """

    def __init__(self, obj=None) -> None:
        self.ops: Optional[List] = None
        self.outvn = None
        if obj is None:
            return
        self.ops = []
        if hasattr(obj, "getOut"):
            self.ops.append(obj)
            outvn = obj.getOut()
            self.outvn = _clone_like_cpp(outvn) if outvn is not None else None
        else:
            self.outvn = obj

    def __del__(self) -> None:
        if self.ops is not None:
            self.ops.clear()
            self.ops = None
        self.outvn = None

    def setOutput(self, newout) -> None:
        if self.outvn is None:
            raise SleighError("Expression has no output")
        if self.outvn.isUnnamed():
            op = self.ops[-1]
            op.clearOutput()
            op.setOutput(newout)
        else:
            op = _SyntheticCopyOp()
            op.addInput(self.outvn)
            op.setOutput(newout)
            self.ops.append(op)
        self.outvn = _clone_like_cpp(newout)

    def getOut(self):
        return self.outvn

    def getSize(self):
        return self.outvn.getSize()

    @staticmethod
    def appendParams(op, params: List[ExprTree]) -> List:
        """Flatten parameter expressions and append op."""
        res: List = []
        for p in params:
            if p.ops is not None:
                res.extend(p.ops)
                p.ops.clear()
                p.ops = None
            op.addInput(p.outvn)
            p.outvn = None
        params.clear()
        res.append(op)
        return res

    @staticmethod
    def toVector(expr: ExprTree) -> List:
        """Extract the op list from an expression tree."""
        res = expr.ops
        expr.ops = None
        expr.outvn = None
        return res


# =========================================================================
# PcodeCompile (abstract base)
# =========================================================================

class PcodeCompile(ABC):
    """Abstract base for p-code compilation from SLEIGH syntax.

    Concrete implementations exist in:
      - C++ native: PcodeSnippet (in pcodeparse.cc) used by PcodeInjectLibrarySleigh
      - Python: not implemented (SLEIGH compilation stays native)

    This stub provides the interface contract so that Python code can
    reference the compiler type and its helper methods.
    """

    def __init__(self) -> None:
        self._defaultspace: Optional[AddrSpace] = None
        self._constantspace: Optional[AddrSpace] = None
        self._uniqspace: Optional[AddrSpace] = None
        self._local_labelcount: int = 0
        self._enforceLocalKey: bool = False

    def __del__(self) -> None:
        pass

    def resetLabelCount(self) -> None:
        self._local_labelcount = 0

    def setDefaultSpace(self, spc: AddrSpace) -> None:
        self._defaultspace = spc

    def setConstantSpace(self, spc: AddrSpace) -> None:
        self._constantspace = spc

    def setUniqueSpace(self, spc: AddrSpace) -> None:
        self._uniqspace = spc

    def setEnforceLocalKey(self, val: bool) -> None:
        self._enforceLocalKey = val

    def getDefaultSpace(self) -> Optional[AddrSpace]:
        return self._defaultspace

    def getConstantSpace(self) -> Optional[AddrSpace]:
        return self._constantspace

    @staticmethod
    def force_size(vt: VarnodeTpl, size: ConstTpl, ops: List[OpTpl]) -> None:
        """Fill a zero-size varnode, propagating the size across matching local temporaries."""
        if vt.getSize().getType() != ConstTpl.real or vt.getSize().getReal() != 0:
            return

        vt.setSize(size)
        if not vt.isLocalTemp():
            return

        for op in ops:
            outvn = op.getOut()
            if outvn is not None and outvn.isLocalTemp() and outvn.getOffset() == vt.getOffset():
                if (
                    size.getType() == ConstTpl.real
                    and outvn.getSize().getType() == ConstTpl.real
                    and outvn.getSize().getReal() != 0
                    and outvn.getSize().getReal() != size.getReal()
                ):
                    raise SleighError("Localtemp size mismatch")
                outvn.setSize(size)
            for slot in range(op.numInput()):
                invn = op.getIn(slot)
                if invn.isLocalTemp() and invn.getOffset() == vt.getOffset():
                    if (
                        size.getType() == ConstTpl.real
                        and invn.getSize().getType() == ConstTpl.real
                        and invn.getSize().getReal() != 0
                        and invn.getSize().getReal() != size.getReal()
                    ):
                        raise SleighError("Localtemp size mismatch")
                    invn.setSize(size)

    @staticmethod
    def matchSize(j: int, op: OpTpl, inputonly: bool, ops: List[OpTpl]) -> None:
        """Try to fill a zero-size varnode in *op* by matching another varnode's size."""
        vt = op.getOut() if j == -1 else op.getIn(j)
        match = None
        if not inputonly:
            outvn = op.getOut()
            if outvn is not None and not outvn.isZeroSize():
                match = outvn
        for slot in range(op.numInput()):
            if match is not None:
                break
            invn = op.getIn(slot)
            if invn.isZeroSize():
                continue
            match = invn
        if match is not None:
            PcodeCompile.force_size(vt, match.getSize(), ops)

    @staticmethod
    def fillinZero(op: OpTpl, ops: List[OpTpl]) -> None:
        """Try to infer zero-size varnodes for a single op."""
        same_size_ops = {
            OpCode.CPUI_COPY,
            OpCode.CPUI_INT_ADD,
            OpCode.CPUI_INT_SUB,
            OpCode.CPUI_INT_2COMP,
            OpCode.CPUI_INT_NEGATE,
            OpCode.CPUI_INT_XOR,
            OpCode.CPUI_INT_AND,
            OpCode.CPUI_INT_OR,
            OpCode.CPUI_INT_MULT,
            OpCode.CPUI_INT_DIV,
            OpCode.CPUI_INT_SDIV,
            OpCode.CPUI_INT_REM,
            OpCode.CPUI_INT_SREM,
            OpCode.CPUI_FLOAT_ADD,
            OpCode.CPUI_FLOAT_DIV,
            OpCode.CPUI_FLOAT_MULT,
            OpCode.CPUI_FLOAT_SUB,
            OpCode.CPUI_FLOAT_NEG,
            OpCode.CPUI_FLOAT_ABS,
            OpCode.CPUI_FLOAT_SQRT,
            OpCode.CPUI_FLOAT_CEIL,
            OpCode.CPUI_FLOAT_FLOOR,
            OpCode.CPUI_FLOAT_ROUND,
        }
        bool_out_ops = {
            OpCode.CPUI_INT_EQUAL,
            OpCode.CPUI_INT_NOTEQUAL,
            OpCode.CPUI_INT_SLESS,
            OpCode.CPUI_INT_SLESSEQUAL,
            OpCode.CPUI_INT_LESS,
            OpCode.CPUI_INT_LESSEQUAL,
            OpCode.CPUI_INT_CARRY,
            OpCode.CPUI_INT_SCARRY,
            OpCode.CPUI_INT_SBORROW,
            OpCode.CPUI_FLOAT_EQUAL,
            OpCode.CPUI_FLOAT_NOTEQUAL,
            OpCode.CPUI_FLOAT_LESS,
            OpCode.CPUI_FLOAT_LESSEQUAL,
            OpCode.CPUI_FLOAT_NAN,
            OpCode.CPUI_BOOL_NEGATE,
            OpCode.CPUI_BOOL_XOR,
            OpCode.CPUI_BOOL_AND,
            OpCode.CPUI_BOOL_OR,
        }

        opcode = op.getOpcode()
        if opcode in same_size_ops:
            outvn = op.getOut()
            if outvn is not None and outvn.isZeroSize():
                PcodeCompile.matchSize(-1, op, False, ops)
            for slot in range(op.numInput()):
                if op.getIn(slot).isZeroSize():
                    PcodeCompile.matchSize(slot, op, False, ops)
            return

        if opcode in bool_out_ops:
            if op.getOut().isZeroSize():
                PcodeCompile.force_size(op.getOut(), ConstTpl(ConstTpl.real, 1), ops)
            for slot in range(op.numInput()):
                if op.getIn(slot).isZeroSize():
                    PcodeCompile.matchSize(slot, op, True, ops)
            return

        if opcode in {OpCode.CPUI_INT_LEFT, OpCode.CPUI_INT_RIGHT, OpCode.CPUI_INT_SRIGHT}:
            if op.getOut().isZeroSize():
                if not op.getIn(0).isZeroSize():
                    PcodeCompile.force_size(op.getOut(), op.getIn(0).getSize(), ops)
            elif op.getIn(0).isZeroSize():
                PcodeCompile.force_size(op.getIn(0), op.getOut().getSize(), ops)
            if op.getIn(1).isZeroSize():
                PcodeCompile.force_size(op.getIn(1), ConstTpl(ConstTpl.real, 4), ops)
            return

        if opcode == OpCode.CPUI_SUBPIECE:
            if op.getIn(1).isZeroSize():
                PcodeCompile.force_size(op.getIn(1), ConstTpl(ConstTpl.real, 4), ops)
            return

        if opcode == OpCode.CPUI_CPOOLREF:
            if op.getOut().isZeroSize() and not op.getIn(0).isZeroSize():
                PcodeCompile.force_size(op.getOut(), op.getIn(0).getSize(), ops)
            if op.getIn(0).isZeroSize() and not op.getOut().isZeroSize():
                PcodeCompile.force_size(op.getIn(0), op.getOut().getSize(), ops)
            for slot in range(1, op.numInput()):
                if op.getIn(slot).isZeroSize():
                    PcodeCompile.force_size(op.getIn(slot), ConstTpl(ConstTpl.real, 8), ops)

    @abstractmethod
    def allocateTemp(self) -> int:
        """Allocate a new unique temporary offset."""
        ...

    @abstractmethod
    def addSymbol(self, sym) -> None:
        """Add a symbol to the local scope."""
        ...

    @abstractmethod
    def getLocation(self, sym) -> Optional[Location]:
        """Get the source location associated with a symbol."""
        ...

    @abstractmethod
    def reportError(self, loc: Optional[Location], msg: str) -> None:
        """Report an error during compilation."""
        ...

    @abstractmethod
    def reportWarning(self, loc: Optional[Location], msg: str) -> None:
        """Report a warning during compilation."""
        ...

    # --- Factory methods (stubs matching C++ interface) ---

    def buildTemporary(self):
        """Build a temporary varnode with zero size."""
        res = VarnodeTpl(
            ConstTpl(self._uniqspace),
            ConstTpl(ConstTpl.real, self.allocateTemp()),
            ConstTpl(ConstTpl.real, 0),
        )
        res.setUnnamed(True)
        return res

    def defineLabel(self, name: str) -> LabelSymbol:
        """Create and register a local label symbol."""
        labsym = LabelSymbol(name, self._local_labelcount)
        self._local_labelcount += 1
        self.addSymbol(labsym)
        return labsym

    def placeLabel(self, sym: LabelSymbol) -> List[OpTpl]:
        """Create the placeholder op that marks a label location."""
        if sym.isPlaced():
            self.reportError(self.getLocation(sym), f"Label '{sym.getName()}' is placed more than once")
        sym.setPlaced()
        op = OpTpl(OpCode.CPUI_PTRADD)
        idvn = VarnodeTpl(
            ConstTpl(self._constantspace),
            ConstTpl(ConstTpl.real, sym.getIndex()),
            ConstTpl(ConstTpl.real, 4),
        )
        op.addInput(idvn)
        return [op]

    def newOutput(self, usesLocalKey: bool, rhs: ExprTree, varname: str, size: int = 0) -> List[OpTpl]:
        """Create a named temporary and attach it as the output of *rhs*."""
        tmpvn = self.buildTemporary()
        if size != 0:
            tmpvn.setSize(ConstTpl(ConstTpl.real, size))
        elif rhs.getSize().getType() == ConstTpl.real and rhs.getSize().getReal() != 0:
            tmpvn.setSize(rhs.getSize())
        rhs.setOutput(tmpvn)
        sym = VarnodeSymbol(varname)
        sym.setFixedVarnode(tmpvn.getSpace().getSpace(), tmpvn.getOffset().getReal(), tmpvn.getSize().getReal())
        self.addSymbol(sym)
        if (not usesLocalKey) and self._enforceLocalKey:
            self.reportError(self.getLocation(sym), f"Must use 'local' keyword to define symbol '{varname}'")
        return ExprTree.toVector(rhs)

    def newLocalDefinition(self, varname: str, size: int = 0) -> None:
        """Create a named temporary without emitting p-code."""
        sym = VarnodeSymbol(varname)
        sym.setFixedVarnode(self._uniqspace, self.allocateTemp(), size)
        self.addSymbol(sym)

    def createOp(self, opc: int, *args):
        """Create a new expression with the given opcode."""
        if len(args) == 1:
            vn = args[0]
            outvn = self.buildTemporary()
            op = OpTpl(opc)
            op.addInput(vn.outvn)
            op.setOutput(outvn)
            vn.ops.append(op)
            vn.outvn = VarnodeTpl(outvn)
            return vn
        if len(args) == 2:
            vn1, vn2 = args
            outvn = self.buildTemporary()
            vn1.ops.extend(vn2.ops)
            vn2.ops.clear()
            op = OpTpl(opc)
            op.addInput(vn1.outvn)
            op.addInput(vn2.outvn)
            vn2.outvn = None
            op.setOutput(outvn)
            vn1.ops.append(op)
            vn1.outvn = VarnodeTpl(outvn)
            vn2.ops = None
            return vn1
        raise TypeError("createOp matches unary and binary native overloads only")

    def createOpOut(self, outvn: VarnodeTpl, opc: int, vn1: ExprTree, vn2: ExprTree) -> ExprTree:
        """Create an op with explicit output and two inputs."""
        vn1.ops.extend(vn2.ops)
        vn2.ops.clear()
        op = OpTpl(opc)
        op.addInput(vn1.outvn)
        op.addInput(vn2.outvn)
        vn2.outvn = None
        op.setOutput(outvn)
        vn1.ops.append(op)
        vn1.outvn = VarnodeTpl(outvn)
        vn2.ops = None
        return vn1

    def createOpOutUnary(self, outvn: VarnodeTpl, opc: int, vn: ExprTree) -> ExprTree:
        """Create an op with explicit output and one input."""
        op = OpTpl(opc)
        op.addInput(vn.outvn)
        op.setOutput(outvn)
        vn.ops.append(op)
        vn.outvn = VarnodeTpl(outvn)
        return vn

    def createOpNoOut(self, opc: int, *args):
        """Create a new expression (no output) with the given opcode."""
        if len(args) == 1:
            vn = args[0]
            op = OpTpl(opc)
            op.addInput(vn.outvn)
            vn.outvn = None
            res = vn.ops
            vn.ops = None
            res.append(op)
            return res
        if len(args) == 2:
            vn1, vn2 = args
            res = vn1.ops
            vn1.ops = None
            res.extend(vn2.ops)
            vn2.ops.clear()
            op = OpTpl(opc)
            op.addInput(vn1.outvn)
            vn1.outvn = None
            op.addInput(vn2.outvn)
            vn2.outvn = None
            res.append(op)
            vn2.ops = None
            return res
        raise TypeError("createOpNoOut matches unary and binary native overloads only")

    def createOpConst(self, opc: int, val: int) -> List[OpTpl]:
        """Create a no-output op that takes a constant input."""
        vn = VarnodeTpl(
            ConstTpl(self._constantspace),
            ConstTpl(ConstTpl.real, val),
            ConstTpl(ConstTpl.real, 4),
        )
        op = OpTpl(opc)
        op.addInput(vn)
        return [op]

    def createLoad(self, qual: StarQuality, ptr: ExprTree) -> ExprTree:
        """Create a load expression."""
        outvn = self.buildTemporary()
        op = OpTpl(OpCode.CPUI_LOAD)
        space_id = ConstTpl(qual.id) if isinstance(qual.id, ConstTpl) else ConstTpl(ConstTpl.real, qual.id)
        spcvn = VarnodeTpl(
            ConstTpl(self._constantspace),
            space_id,
            ConstTpl(ConstTpl.real, 8),
        )
        op.addInput(spcvn)
        op.addInput(ptr.outvn)
        op.setOutput(outvn)
        ptr.ops.append(op)
        if qual.size > 0:
            self.force_size(outvn, ConstTpl(ConstTpl.real, qual.size), ptr.ops)
        ptr.outvn = VarnodeTpl(outvn)
        return ptr

    def createStore(self, qual: StarQuality, ptr: ExprTree, val: ExprTree) -> List:
        """Create a store operation."""
        res = ptr.ops
        ptr.ops = None
        res.extend(val.ops)
        val.ops.clear()
        op = OpTpl(OpCode.CPUI_STORE)
        space_id = ConstTpl(qual.id) if isinstance(qual.id, ConstTpl) else ConstTpl(ConstTpl.real, qual.id)
        spcvn = VarnodeTpl(
            ConstTpl(self._constantspace),
            space_id,
            ConstTpl(ConstTpl.real, 8),
        )
        op.addInput(spcvn)
        op.addInput(ptr.outvn)
        op.addInput(val.outvn)
        res.append(op)
        self.force_size(val.outvn, ConstTpl(ConstTpl.real, qual.size), res)
        ptr.outvn = None
        val.outvn = None
        val.ops = None
        return res

    def createUserOp(self, sym, param: List[ExprTree]) -> ExprTree:
        """Create a user-defined p-code op with an output temporary."""
        outvn = self.buildTemporary()
        res = ExprTree()
        res.ops = self.createUserOpNoOut(sym, param)
        res.ops[-1].setOutput(outvn)
        res.outvn = VarnodeTpl(outvn)
        return res

    def createUserOpNoOut(self, sym, param: List[ExprTree]) -> List[OpTpl]:
        """Create a user-defined p-code op without an output varnode."""
        op = OpTpl(OpCode.CPUI_CALLOTHER)
        vn = VarnodeTpl(
            ConstTpl(self._constantspace),
            ConstTpl(ConstTpl.real, sym.getIndex()),
            ConstTpl(ConstTpl.real, 4),
        )
        op.addInput(vn)
        return ExprTree.appendParams(op, param)

    def createVariadic(self, opc: int, param: List[ExprTree]) -> ExprTree:
        """Create a variadic op with a temporary output."""
        outvn = self.buildTemporary()
        res = ExprTree()
        op = OpTpl(opc)
        res.ops = ExprTree.appendParams(op, param)
        res.ops[-1].setOutput(outvn)
        res.outvn = VarnodeTpl(outvn)
        return res

    def appendOp(self, opc: int, res: ExprTree, constval: int, constsz: int) -> None:
        """Append an op that combines the current expression output with a constant."""
        op = OpTpl(opc)
        constvn = VarnodeTpl(
            ConstTpl(self._constantspace),
            ConstTpl(ConstTpl.real, constval),
            ConstTpl(ConstTpl.real, constsz),
        )
        outvn = self.buildTemporary()
        op.addInput(res.outvn)
        op.addInput(constvn)
        op.setOutput(outvn)
        res.ops.append(op)
        res.outvn = VarnodeTpl(outvn)

    def buildTruncatedVarnode(self, basevn: VarnodeTpl, bitoffset: int, numbits: int) -> Optional[VarnodeTpl]:
        """Build a truncated view of a varnode using ConstTpl mechanics where possible."""
        byteoffset = bitoffset // 8
        numbytes = numbits // 8
        fullsz = 0
        if basevn.getSize().getType() == ConstTpl.real:
            fullsz = basevn.getSize().getReal()
            if fullsz == 0:
                return None
            if byteoffset + numbytes > fullsz:
                raise SleighError("Requested bit range out of bounds")

        if (bitoffset % 8) != 0 or (numbits % 8) != 0:
            return None

        offset_type = basevn.getOffset().getType()
        if offset_type not in (ConstTpl.real, ConstTpl.handle):
            return None

        if offset_type == ConstTpl.handle:
            specialoff = ConstTpl(ConstTpl.handle, basevn.getOffset().getHandleIndex(), ConstTpl.v_offset_plus, byteoffset)
        else:
            if basevn.getSize().getType() != ConstTpl.real:
                raise SleighError("Could not construct requested bit range")
            if self._defaultspace is not None and self._defaultspace.isBigEndian():
                plus = fullsz - (byteoffset + numbytes)
            else:
                plus = byteoffset
            specialoff = ConstTpl(ConstTpl.real, basevn.getOffset().getReal() + plus)
        return VarnodeTpl(basevn.getSpace(), specialoff, ConstTpl(ConstTpl.real, numbytes))

    def assignBitRange(self, vn: VarnodeTpl, bitoffset: int, numbits: int, rhs: ExprTree) -> List[OpTpl]:
        """Assign an expression into a bitrange within a varnode."""
        errmsg = ""
        if numbits == 0:
            errmsg = "Size of bitrange is zero"
        smallsize = (numbits + 7) // 8
        shiftneeded = bitoffset != 0
        zextneeded = True
        mask = 0
        if numbits > 0:
            mask = ~((((2 << (numbits - 1)) - 1) << bitoffset))

        if vn.getSize().getType() == ConstTpl.real:
            symsize = vn.getSize().getReal()
            if symsize > 0:
                zextneeded = symsize > smallsize
            symsize *= 8
            if bitoffset >= symsize or bitoffset + numbits > symsize:
                errmsg = "Assigned bitrange is bad"
            elif bitoffset == 0 and numbits == symsize:
                errmsg = "Assigning to bitrange is superfluous"

        if errmsg:
            self.reportError(None, errmsg)
            resops = rhs.ops
            rhs.ops = None
            rhs.outvn = None
            return resops

        self.force_size(rhs.outvn, ConstTpl(ConstTpl.real, smallsize), rhs.ops)

        finalout = self.buildTruncatedVarnode(vn, bitoffset, numbits)
        if finalout is not None:
            res = self.createOpOutUnary(finalout, OpCode.CPUI_COPY, rhs)
        else:
            if bitoffset + numbits > 64:
                errmsg = "Assigned bitrange extends past first 64 bits"
            res = ExprTree(vn)
            self.appendOp(OpCode.CPUI_INT_AND, res, mask, 0)
            if zextneeded:
                self.createOp(OpCode.CPUI_INT_ZEXT, rhs)
            if shiftneeded:
                self.appendOp(OpCode.CPUI_INT_LEFT, rhs, bitoffset, 4)
            finalout = VarnodeTpl(vn)
            res = self.createOpOut(finalout, OpCode.CPUI_INT_OR, res, rhs)

        if errmsg:
            self.reportError(None, errmsg)
        resops = res.ops
        res.ops = None
        res.outvn = None
        return resops

    def createBitRange(self, sym, bitoffset: int, numbits: int) -> ExprTree:
        """Create an expression computing a bitrange of a symbol."""
        errmsg = ""
        if numbits == 0:
            errmsg = "Size of bitrange is zero"
        vn = sym.getVarnode()
        finalsize = (numbits + 7) // 8
        truncshift = 0
        maskneeded = (numbits % 8) != 0
        truncneeded = True

        if not errmsg and bitoffset == 0 and not maskneeded:
            if vn.getSpace().getType() == ConstTpl.handle and vn.isZeroSize():
                vn.setSize(ConstTpl(ConstTpl.real, finalsize))
                return ExprTree(vn)

        if not errmsg:
            truncvn = self.buildTruncatedVarnode(vn, bitoffset, numbits)
            if truncvn is not None:
                return ExprTree(truncvn)

        if vn.getSize().getType() == ConstTpl.real:
            insize = vn.getSize().getReal()
            if insize > 0:
                truncneeded = finalsize < insize
                insize *= 8
                if bitoffset >= insize or bitoffset + numbits > insize:
                    errmsg = "Bitrange is bad"
                if maskneeded and (bitoffset + numbits) == insize:
                    maskneeded = False

        mask = 0
        if numbits > 0:
            mask = (2 << (numbits - 1)) - 1

        if truncneeded and ((bitoffset % 8) == 0):
            truncshift = bitoffset // 8
            bitoffset = 0

        if bitoffset == 0 and (not truncneeded) and (not maskneeded):
            errmsg = "Superfluous bitrange"

        if maskneeded and finalsize > 8:
            errmsg = f"Illegal masked bitrange producing varnode larger than 64 bits: {sym.getName()}"

        res = ExprTree(vn)
        if errmsg:
            self.reportError(self.getLocation(sym), errmsg)
            return res

        if bitoffset != 0:
            self.appendOp(OpCode.CPUI_INT_RIGHT, res, bitoffset, 4)
        if truncneeded:
            self.appendOp(OpCode.CPUI_SUBPIECE, res, truncshift, 4)
        if maskneeded:
            self.appendOp(OpCode.CPUI_INT_AND, res, mask, finalsize)
        self.force_size(res.outvn, ConstTpl(ConstTpl.real, finalsize), res.ops)
        return res

    def addressOf(self, var: VarnodeTpl, size: int) -> VarnodeTpl:
        """Produce a constant varnode holding the address portion of *var*."""
        if size == 0 and var.getSpace().getType() == ConstTpl.spaceid:
            size = var.getSpace().getSpace().getAddrSize()
        if var.getOffset().getType() == ConstTpl.real and var.getSpace().getType() == ConstTpl.spaceid:
            spc = var.getSpace().getSpace()
            off = spc.byteToAddress(var.getOffset().getReal(), spc.getWordSize())
            return VarnodeTpl(
                ConstTpl(self._constantspace),
                ConstTpl(ConstTpl.real, off),
                ConstTpl(ConstTpl.real, size),
            )
        return VarnodeTpl(
            ConstTpl(self._constantspace),
            var.getOffset(),
            ConstTpl(ConstTpl.real, size),
        )

    @staticmethod
    def propagateSize(ct) -> bool:
        """Fill in zero-size varnodes in a ConstructTpl. Returns True if all resolved."""
        opvec = ct.getOpvec()
        zerovec: List[OpTpl] = []
        for op in opvec:
            if op.isZeroSize():
                PcodeCompile.fillinZero(op, opvec)
                if op.isZeroSize():
                    zerovec.append(op)
        lastsize = len(zerovec) + 1
        while len(zerovec) < lastsize:
            lastsize = len(zerovec)
            zerovec2: List[OpTpl] = []
            for op in zerovec:
                PcodeCompile.fillinZero(op, opvec)
                if op.isZeroSize():
                    zerovec2.append(op)
            zerovec = zerovec2
        return lastsize == 0
