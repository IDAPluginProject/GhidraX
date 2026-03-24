"""
Corresponds to: printjava.hh / printjava.cc

Java language code emitter. Builds on PrintC, overriding specific behaviors
for Java semantics: array handling, instanceof, constant pool references,
Unicode escaping, and type printing adjustments.
"""

from __future__ import annotations

from typing import TYPE_CHECKING

from ghidra.output.printlanguage import (
    PrintLanguageCapability, OpToken,
    Atom, syntax, vartoken, typetoken, blanktoken,
)
from ghidra.output.prettyprint import EmitMarkup
from ghidra.output.printc import PrintC, _tok
from ghidra.types.cast import CastStrategyJava

if TYPE_CHECKING:
    from ghidra.ir.op import PcodeOp
    from ghidra.ir.varnode import Varnode
    from ghidra.types.datatype import Datatype
    from ghidra.analysis.funcdata import Funcdata


# Type metatype constants (mirror ghidra.types.datatype)
TYPE_PTR = 10
TYPE_INT = 8
TYPE_UINT = 3
TYPE_BOOL = 1
TYPE_FLOAT = 9
TYPE_CODE = 13


class PrintJava(PrintC):
    """The Java-language token emitter.

    Builds heavily on PrintC. Most operator tokens, function prototypes,
    and code structuring are shared. Java-specific behaviors include:
    - constant pool handling via opCpoolRefOp()
    - array type detection and [0] syntax
    - instanceof operator
    - Java-specific type printing (unwrap pointer chains)
    - Unicode escape printing
    """

    # Java-specific operator token
    instanceof = _tok("instanceof", "", 2, 60, True, OpToken.binary, 1, 0)

    def __init__(self, glb=None, nm: str = "java-language") -> None:
        super().__init__(glb, nm)
        self._resetDefaultsPrintJava()
        self.nullToken = "null"
        self._castStrategy = CastStrategyJava()

    def resetDefaults(self) -> None:
        """Reset all defaults including Java-specific ones."""
        super().resetDefaults()
        self._resetDefaultsPrintJava()

    def _resetDefaultsPrintJava(self) -> None:
        """Set options specific to Java."""
        self.option_NULL = True
        self.option_convention = False
        self._mods |= PrintC.hide_thisparam

    def docFunction(self, fd) -> None:
        """Print a function, pushing parent class scope if needed."""
        singletonFunction = False
        if self._curscope is None:
            singletonFunction = True
            scope_local = fd.getScopeLocal() if hasattr(fd, 'getScopeLocal') else None
            if scope_local is not None and hasattr(scope_local, 'getParent'):
                self.pushScope(scope_local.getParent())
        super().docFunction(fd)
        if singletonFunction:
            self.popScope()

    def pushTypeStart(self, ct, noident: bool) -> None:
        """Print a data-type up to the identifier.

        Unwraps pointer chains to find the root type and counts
        array wrappers for Java array syntax.
        """
        arrayCount = 0
        while True:
            meta = ct.getMetatype() if hasattr(ct, 'getMetatype') else -1
            if meta == TYPE_PTR:
                if self._isArrayType(ct):
                    arrayCount += 1
                ct = ct.getPtrTo() if hasattr(ct, 'getPtrTo') else ct
            elif hasattr(ct, 'getName') and ct.getName():
                break
            else:
                if self._glb is not None and hasattr(self._glb, 'types'):
                    ct = self._glb.types.getTypeVoid()
                break

        tok = self.type_expr_space if not noident else self.type_expr_nospace
        self.pushOp(tok, None)
        for _ in range(arrayCount):
            self.pushOp(self.subscript, None)

        name = ""
        if hasattr(ct, 'getName'):
            name = ct.getName()
        if not name:
            name = self.genericTypeName(ct) if hasattr(self, 'genericTypeName') else "unknown"
            self.pushAtom(Atom(name, typetoken, EmitMarkup.type_color, ct))
        else:
            display = ct.getDisplayName() if hasattr(ct, 'getDisplayName') else name
            self.pushAtom(Atom(display, typetoken, EmitMarkup.type_color, ct))

        for _ in range(arrayCount):
            self.pushAtom(Atom("", blanktoken, EmitMarkup.no_color))

    def pushTypeEnd(self, ct) -> None:
        """No-op for Java — array brackets are handled in pushTypeStart."""

    def adjustTypeOperators(self) -> None:
        """Adjust operator tokens for Java semantics."""
        self.scope.print1 = "."
        self.shift_right.print1 = ">>>"

    def doEmitWideCharPrefix(self, *args) -> bool:
        """Java doesn't use wide character prefix."""
        return False

    @staticmethod
    def _isArrayType(ct) -> bool:
        """Determine if data-type references a Java array object.

        Java arrays are pointer-to-primitive or pointer-to-pointer types.
        Pointer-to-unsigned is a class reference (not array), unless char.
        """
        meta = ct.getMetatype() if hasattr(ct, 'getMetatype') else -1
        if meta != TYPE_PTR:
            return False
        inner = ct.getPtrTo() if hasattr(ct, 'getPtrTo') else None
        if inner is None:
            return False
        inner_meta = inner.getMetatype() if hasattr(inner, 'getMetatype') else -1
        if inner_meta == TYPE_UINT:
            return hasattr(inner, 'isCharPrint') and inner.isCharPrint()
        return inner_meta in (TYPE_INT, TYPE_BOOL, TYPE_FLOAT, TYPE_PTR)

    @staticmethod
    def _needZeroArray(vn) -> bool:
        """Determine if a dereferenced pointer needs [0] syntax."""
        if not PrintJava._isArrayType(vn.getType()):
            return False
        if hasattr(vn, 'isExplicit') and vn.isExplicit():
            return True
        if hasattr(vn, 'isWritten') and not vn.isWritten():
            return True
        opc = vn.getDef().code()
        from ghidra.core.opcodes import OpCode
        if opc in (OpCode.CPUI_PTRADD, OpCode.CPUI_PTRSUB, OpCode.CPUI_CPOOLREF):
            return False
        return True

    def _printUnicode(self, s, onechar: int) -> None:
        """Print a unicode character with Java escape sequences."""
        special = {0: "\\0", 8: "\\b", 9: "\\t", 10: "\\n",
                   12: "\\f", 13: "\\r", 92: "\\\\", 34: '\\"', 39: "\\'"}
        if onechar in special:
            s.write(special[onechar])
            return
        if onechar < 0x20 or onechar > 0x7e:
            if onechar < 65536:
                s.write(f"\\u{onechar:04x}")
            else:
                s.write(f"\\u{onechar:08x}")
            return
        s.write(chr(onechar))

    def opLoad(self, op) -> None:
        """Handle LOAD with Java array [0] syntax."""
        m = self._mods | self.print_load_value
        printArrayRef = self._needZeroArray(op.getIn(1))
        if printArrayRef:
            self.pushOp(self.subscript, op)
        self.pushVn(op.getIn(1), op, m)
        if printArrayRef:
            self.push_integer(0, 4, False, syntax, None, op)

    def opStore(self, op) -> None:
        """Handle STORE with Java array [0] syntax."""
        m = self._mods | self.print_store_value
        self.pushOp(self.assignment, op)
        if self._needZeroArray(op.getIn(1)):
            self.pushOp(self.subscript, op)
            self.pushVn(op.getIn(1), op, m)
            self.push_integer(0, 4, False, syntax, None, op)
            self.pushVn(op.getIn(2), op, self._mods)
        else:
            self.pushVn(op.getIn(2), op, self._mods)
            self.pushVn(op.getIn(1), op, m)

    def opCallind(self, op) -> None:
        """Handle indirect calls with Java 'this' hiding."""
        self.pushOp(self.function_call, op)
        fd = op.getParent().getFuncdata()
        fc = fd.getCallSpecs(op) if hasattr(fd, 'getCallSpecs') else None
        if fc is None:
            from ghidra.core.error import LowlevelError
            raise LowlevelError("Missing indirect function callspec")
        skip = self.getHiddenThisSlot(op, fc) if hasattr(self, 'getHiddenThisSlot') else -1
        count = op.numInput() - 1
        count -= 0 if skip < 0 else 1
        if count > 1:
            self.pushVn(op.getIn(0), op, self._mods)
            for _ in range(count - 1):
                self.pushOp(self.comma, op)
            for i in range(op.numInput() - 1, 0, -1):
                if i == skip:
                    continue
                self.pushVn(op.getIn(i), op, self._mods)
        elif count == 1:
            if skip == 1:
                self.pushVn(op.getIn(2), op, self._mods)
            else:
                self.pushVn(op.getIn(1), op, self._mods)
            self.pushVn(op.getIn(0), op, self._mods)
        else:
            self.pushVn(op.getIn(0), op, self._mods)
            self.pushAtom(Atom("", blanktoken, EmitMarkup.no_color))

    def opCpoolRefOp(self, op) -> None:
        """Handle constant pool references."""
        outvn = op.getOut()
        vn0 = op.getIn(0)
        refs = []
        for i in range(1, op.numInput()):
            refs.append(op.getIn(i).getOffset())

        rec = None
        if self._glb is not None and hasattr(self._glb, 'cpool') and self._glb.cpool is not None:
            rec = self._glb.cpool.getRecord(refs)

        if rec is None:
            self.pushAtom(Atom("UNKNOWNREF", syntax, EmitMarkup.const_color, op, outvn))
            return

        tag = rec.getTag()
        if tag == "string_literal":
            data = rec.getByteData() if hasattr(rec, 'getByteData') else b""
            length = min(len(data), 2048)
            text = '"' + data[:length].decode('utf-8', errors='replace')
            if length < len(data):
                text += '..."'
            else:
                text += '"'
            self.pushAtom(Atom(text, vartoken, EmitMarkup.const_color, op, outvn))
        elif tag == "class_reference":
            self.pushAtom(Atom(rec.getToken(), vartoken, EmitMarkup.type_color, op, outvn))
        elif tag == "instance_of":
            dt = rec.getType()
            while hasattr(dt, 'getMetatype') and dt.getMetatype() == TYPE_PTR:
                dt = dt.getPtrTo()
            self.pushOp(self.instanceof, op)
            self.pushVn(vn0, op, self._mods)
            display = dt.getDisplayName() if hasattr(dt, 'getDisplayName') else str(dt)
            self.pushAtom(Atom(display, syntax, EmitMarkup.type_color, op, outvn))
        else:
            ct = rec.getType() if hasattr(rec, 'getType') else None
            color = EmitMarkup.var_color
            if ct is not None and hasattr(ct, 'getMetatype') and ct.getMetatype() == TYPE_PTR:
                inner = ct.getPtrTo() if hasattr(ct, 'getPtrTo') else None
                if inner is not None and hasattr(inner, 'getMetatype') and inner.getMetatype() == TYPE_CODE:
                    color = EmitMarkup.funcname_color
            if hasattr(vn0, 'isConstant') and vn0.isConstant():
                self.pushAtom(Atom(rec.getToken(), vartoken, color, op, outvn))
            else:
                self.pushOp(self.object_member, op)
                self.pushVn(vn0, op, self._mods)
                self.pushAtom(Atom(rec.getToken(), syntax, color, op, outvn))


# =========================================================================
# PrintJavaCapability
# =========================================================================

class PrintJavaCapability(PrintLanguageCapability):
    """Factory for the java-language back-end."""

    def __init__(self) -> None:
        super().__init__("java-language", False)

    def buildLanguage(self, glb):
        return PrintJava(glb, self.name)


# Register the capability (singleton pattern matching C++)
printJavaCapability = PrintJavaCapability()
printJavaCapability.initialize()
