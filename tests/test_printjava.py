"""Tests for ghidra.output.printjava — Java language emitter."""
from __future__ import annotations

import io
import pytest

from ghidra.output.printjava import (
    PrintJava, PrintJavaCapability, printJavaCapability,
    TYPE_PTR, TYPE_INT, TYPE_UINT, TYPE_BOOL, TYPE_FLOAT, TYPE_CODE,
)
from ghidra.output.printlanguage import PrintLanguageCapability
from ghidra.output.printc import PrintC
from ghidra.types.cast import CastStrategyJava


# ---------------------------------------------------------------------------
# Helpers / Fakes
# ---------------------------------------------------------------------------

class FakeDatatype:
    def __init__(self, name="int", meta=TYPE_INT, ptr_to=None, char_print=False, display=None):
        self._name = name
        self._meta = meta
        self._ptr_to = ptr_to
        self._char_print = char_print
        self._display = display or name

    def getName(self):
        return self._name

    def getDisplayName(self):
        return self._display

    def getMetatype(self):
        return self._meta

    def getPtrTo(self):
        return self._ptr_to

    def isCharPrint(self):
        return self._char_print


class FakeVarnode:
    def __init__(self, dt=None, explicit=False, written=True, def_op=None, offset=0, const=False):
        self._type = dt or FakeDatatype()
        self._explicit = explicit
        self._written = written
        self._def = def_op
        self._offset = offset
        self._const = const

    def getType(self):
        return self._type

    def isExplicit(self):
        return self._explicit

    def isWritten(self):
        return self._written

    def getDef(self):
        return self._def

    def getOffset(self):
        return self._offset

    def isConstant(self):
        return self._const


# ---------------------------------------------------------------------------
# PrintJava basics
# ---------------------------------------------------------------------------

class TestPrintJavaConstruction:
    def test_inherits_printc(self):
        pj = PrintJava()
        assert isinstance(pj, PrintC)

    def test_name(self):
        pj = PrintJava()
        assert pj.getName() == "java-language"

    def test_null_token(self):
        pj = PrintJava()
        assert pj.nullToken == "null"

    def test_cast_strategy_java(self):
        pj = PrintJava()
        assert isinstance(pj._castStrategy, CastStrategyJava)

    def test_defaults_set(self):
        pj = PrintJava()
        assert pj.option_NULL is True
        assert pj.option_convention is False

    def test_reset_defaults(self):
        pj = PrintJava()
        pj.option_NULL = False
        pj.option_convention = True
        pj.resetDefaults()
        assert pj.option_NULL is True
        assert pj.option_convention is False

    def test_wide_char_prefix(self):
        pj = PrintJava()
        assert pj.doEmitWideCharPrefix() is False


# ---------------------------------------------------------------------------
# _isArrayType
# ---------------------------------------------------------------------------

class TestIsArrayType:
    def test_non_pointer_is_false(self):
        dt = FakeDatatype(meta=TYPE_INT)
        assert PrintJava._isArrayType(dt) is False

    def test_ptr_to_int_is_array(self):
        inner = FakeDatatype(meta=TYPE_INT)
        dt = FakeDatatype(meta=TYPE_PTR, ptr_to=inner)
        assert PrintJava._isArrayType(dt) is True

    def test_ptr_to_bool_is_array(self):
        inner = FakeDatatype(meta=TYPE_BOOL)
        dt = FakeDatatype(meta=TYPE_PTR, ptr_to=inner)
        assert PrintJava._isArrayType(dt) is True

    def test_ptr_to_float_is_array(self):
        inner = FakeDatatype(meta=TYPE_FLOAT)
        dt = FakeDatatype(meta=TYPE_PTR, ptr_to=inner)
        assert PrintJava._isArrayType(dt) is True

    def test_ptr_to_ptr_is_array(self):
        inner = FakeDatatype(meta=TYPE_PTR)
        dt = FakeDatatype(meta=TYPE_PTR, ptr_to=inner)
        assert PrintJava._isArrayType(dt) is True

    def test_ptr_to_uint_not_array(self):
        inner = FakeDatatype(meta=TYPE_UINT, char_print=False)
        dt = FakeDatatype(meta=TYPE_PTR, ptr_to=inner)
        assert PrintJava._isArrayType(dt) is False

    def test_ptr_to_char_uint_is_array(self):
        inner = FakeDatatype(meta=TYPE_UINT, char_print=True)
        dt = FakeDatatype(meta=TYPE_PTR, ptr_to=inner)
        assert PrintJava._isArrayType(dt) is True


# ---------------------------------------------------------------------------
# _printUnicode
# ---------------------------------------------------------------------------

class TestPrintUnicode:
    def test_special_chars(self):
        pj = PrintJava()
        cases = {
            0: "\\0", 8: "\\b", 9: "\\t", 10: "\\n",
            12: "\\f", 13: "\\r", 92: "\\\\", 34: '\\"', 39: "\\'"
        }
        for code, expected in cases.items():
            buf = io.StringIO()
            pj._printUnicode(buf, code)
            assert buf.getvalue() == expected, f"Failed for code {code}"

    def test_normal_ascii(self):
        pj = PrintJava()
        buf = io.StringIO()
        pj._printUnicode(buf, ord('A'))
        assert buf.getvalue() == "A"

    def test_unicode_escape_short(self):
        pj = PrintJava()
        buf = io.StringIO()
        pj._printUnicode(buf, 0x01)
        assert buf.getvalue() == "\\u0001"

    def test_unicode_escape_long(self):
        pj = PrintJava()
        buf = io.StringIO()
        pj._printUnicode(buf, 0x10000)
        assert buf.getvalue() == "\\u00010000"


# ---------------------------------------------------------------------------
# adjustTypeOperators
# ---------------------------------------------------------------------------

class TestAdjustTypeOperators:
    def test_scope_becomes_dot(self):
        pj = PrintJava()
        pj.adjustTypeOperators()
        assert pj.scope.print1 == "."

    def test_shift_right_becomes_unsigned(self):
        pj = PrintJava()
        pj.adjustTypeOperators()
        assert pj.shift_right.print1 == ">>>"


# ---------------------------------------------------------------------------
# pushTypeEnd
# ---------------------------------------------------------------------------

class TestPushTypeEnd:
    def test_noop(self):
        pj = PrintJava()
        dt = FakeDatatype()
        pj.pushTypeEnd(dt)  # Should not raise


# ---------------------------------------------------------------------------
# PrintJavaCapability
# ---------------------------------------------------------------------------

class TestPrintJavaCapability:
    def test_name(self):
        cap = PrintJavaCapability()
        assert cap.getName() == "java-language"

    def test_not_default(self):
        cap = PrintJavaCapability()
        assert cap.isdefault is False

    def test_build_language(self):
        cap = PrintJavaCapability()
        lang = cap.buildLanguage(None)
        assert isinstance(lang, PrintJava)
        assert lang.getName() == "java-language"

    def test_singleton_registered(self):
        assert printJavaCapability is not None
        assert isinstance(printJavaCapability, PrintJavaCapability)

    def test_findable(self):
        found = PrintLanguageCapability.findCapability("java-language")
        assert found is not None
        assert found.getName() == "java-language"

    def test_is_capability(self):
        assert isinstance(printJavaCapability, PrintLanguageCapability)
