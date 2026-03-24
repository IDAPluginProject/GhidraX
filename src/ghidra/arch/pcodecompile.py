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
from typing import Optional, List, TYPE_CHECKING

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


# =========================================================================
# StarQuality
# =========================================================================

class StarQuality:
    """Dereference qualifier for load/store operations."""

    def __init__(self, space_id: int = 0, size: int = 0) -> None:
        self.id: int = space_id
        self.size: int = size


# =========================================================================
# ExprTree
# =========================================================================

class ExprTree:
    """A flattened expression tree of p-code template ops.

    In C++ this holds a list of OpTpl* and an output VarnodeTpl*.
    This Python stub provides the interface for code that needs to
    build or manipulate expression trees; actual construction is done
    by the native SLEIGH compiler.
    """

    def __init__(self, outvn=None) -> None:
        self.ops: List = []
        self.outvn = outvn

    def setOutput(self, newout) -> None:
        self.outvn = newout

    def getOut(self):
        return self.outvn

    @staticmethod
    def appendParams(op, params: List[ExprTree]) -> List:
        """Flatten parameter expressions and append op."""
        res: List = []
        for p in params:
            res.extend(p.ops)
            p.ops.clear()
            if hasattr(op, 'addInput'):
                op.addInput(p.outvn)
            p.outvn = None
        res.append(op)
        return res

    @staticmethod
    def toVector(expr: ExprTree) -> List:
        """Extract the op list from an expression tree."""
        res = expr.ops
        expr.ops = []
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
        raise NotImplementedError("buildTemporary requires native SLEIGH engine")

    def createOp(self, opc: int, *args):
        """Create a new expression with the given opcode."""
        raise NotImplementedError("createOp requires native SLEIGH engine")

    def createOpNoOut(self, opc: int, *args):
        """Create a new expression (no output) with the given opcode."""
        raise NotImplementedError("createOpNoOut requires native SLEIGH engine")

    def createLoad(self, qual: StarQuality, ptr: ExprTree) -> ExprTree:
        """Create a load expression."""
        raise NotImplementedError("createLoad requires native SLEIGH engine")

    def createStore(self, qual: StarQuality, ptr: ExprTree, val: ExprTree) -> List:
        """Create a store operation."""
        raise NotImplementedError("createStore requires native SLEIGH engine")

    @staticmethod
    def propagateSize(ct) -> bool:
        """Fill in zero-size varnodes in a ConstructTpl. Returns True if all resolved."""
        raise NotImplementedError("propagateSize requires native SLEIGH engine")
