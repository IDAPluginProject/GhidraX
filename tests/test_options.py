"""Tests for ghidra.arch.options -- OptionDatabase + ArchOption classes."""
from __future__ import annotations

import pytest

from ghidra.core.error import LowlevelError
from ghidra.arch.options import (
    ArchOption, OptionDatabase,
    OptionExtraPop, OptionForLoops, OptionInferConstPtr,
    OptionAliasBlock, OptionMaxInstruction, OptionJumpTableMax,
    OptionNanIgnore, OptionReadOnly, OptionSetAction,
    OptionNullPrinting, OptionInPlaceOps, OptionConventionPrinting,
    OptionNoCastPrinting, OptionHideExtensions,
    OptionMaxLineWidth, OptionIndentIncrement,
    OptionSplitDatatypes,
)


# ---------------------------------------------------------------------------
# Minimal stubs
# ---------------------------------------------------------------------------

class _FakePrint:
    def __init__(self):
        self.option_NULL = False
        self.option_inplace_ops = False
        self.option_convention = False
        self.option_nocasts = False
        self.option_hide_exts = False

    def getEmitter(self):
        return _FakeEmitter()

    def setLineCommentIndent(self, val):
        self._comment_indent = val

    def setCommentDelimeter(self, o, c, b):
        pass

    def setIntegerFormat(self, f):
        pass

    def setNamespaceStrategy(self, s):
        pass

    def setHeaderComment(self, t):
        pass

    def setInstructionComment(self, t):
        pass


class _FakeEmitter:
    def __init__(self):
        self._max = 0
        self._indent = 0

    def setMaxLineSize(self, v):
        self._max = v

    def setIndentIncrement(self, v):
        self._indent = v


class _FakeAllActs:
    def __init__(self):
        self._current = "decompile"

    def setCurrent(self, name):
        self._current = name

    def getCurrent(self):
        return None


class _FakeGlb:
    def __init__(self):
        self.extra_pop = 0
        self.infer_pointers = False
        self.analyze_for_loops = False
        self.alias_block_level = 0
        self.max_instructions = 100000
        self.max_jumptable_size = 1024
        self.nan_ignore_all = False
        self.nan_ignore_compare = False
        self.readonlypropagate = False
        self.split_datatype_config = 0
        self.print_ = _FakePrint()
        self.allacts = _FakeAllActs()


# ---------------------------------------------------------------------------
# ArchOption.onOrOff
# ---------------------------------------------------------------------------

class TestOnOrOff:
    @pytest.mark.parametrize("val", ["on", "yes", "true", "1", "ON", "True"])
    def test_on_values(self, val):
        assert ArchOption.onOrOff(val) is True

    @pytest.mark.parametrize("val", ["off", "no", "false", "0", "OFF", "False"])
    def test_off_values(self, val):
        assert ArchOption.onOrOff(val) is False

    def test_invalid_raises(self):
        with pytest.raises(LowlevelError):
            ArchOption.onOrOff("maybe")


# ---------------------------------------------------------------------------
# OptionDatabase
# ---------------------------------------------------------------------------

class TestOptionDatabase:
    def test_construction_registers_defaults(self):
        db = OptionDatabase(_FakeGlb())
        assert len(db._optionmap) > 20

    def test_set_known_option(self):
        glb = _FakeGlb()
        db = OptionDatabase(glb)
        result = db.set("extrapop", "8")
        assert "set" in result.lower() or "pop" in result.lower()
        assert glb.extra_pop == 8

    def test_set_unknown_raises(self):
        db = OptionDatabase(_FakeGlb())
        with pytest.raises(LowlevelError):
            db.set("nonexistent_option_xyz")

    def test_register_custom_option(self):
        class MyOpt(ArchOption):
            def __init__(self):
                super().__init__()
                self.name = "myopt"

            def apply(self, glb, p1="", p2="", p3=""):
                return "applied"

        db = OptionDatabase(_FakeGlb())
        db.registerOption(MyOpt())
        result = db.set("myopt")
        assert result == "applied"


# ---------------------------------------------------------------------------
# Concrete option tests
# ---------------------------------------------------------------------------

class TestOptionExtraPop:
    def test_numeric(self):
        glb = _FakeGlb()
        opt = OptionExtraPop()
        opt.apply(glb, "16")
        assert glb.extra_pop == 16

    def test_unknown(self):
        glb = _FakeGlb()
        opt = OptionExtraPop()
        opt.apply(glb, "unknown")
        assert glb.extra_pop == -1

    def test_bad_value(self):
        glb = _FakeGlb()
        opt = OptionExtraPop()
        with pytest.raises(LowlevelError):
            opt.apply(glb, "abc")


class TestOptionForLoops:
    def test_on(self):
        glb = _FakeGlb()
        OptionForLoops().apply(glb, "on")
        assert glb.analyze_for_loops is True

    def test_off(self):
        glb = _FakeGlb()
        glb.analyze_for_loops = True
        OptionForLoops().apply(glb, "off")
        assert glb.analyze_for_loops is False


class TestOptionInferConstPtr:
    def test_on(self):
        glb = _FakeGlb()
        OptionInferConstPtr().apply(glb, "on")
        assert glb.infer_pointers is True


class TestOptionAliasBlock:
    @pytest.mark.parametrize("val,expected", [("none", 0), ("stack", 1), ("register", 2), ("all", 3)])
    def test_valid_levels(self, val, expected):
        glb = _FakeGlb()
        OptionAliasBlock().apply(glb, val)
        assert glb.alias_block_level == expected

    def test_invalid_level(self):
        glb = _FakeGlb()
        with pytest.raises(LowlevelError):
            OptionAliasBlock().apply(glb, "invalid")


class TestOptionMaxInstruction:
    def test_valid(self):
        glb = _FakeGlb()
        OptionMaxInstruction().apply(glb, "5000")
        assert glb.max_instructions == 5000

    def test_invalid(self):
        glb = _FakeGlb()
        with pytest.raises(LowlevelError):
            OptionMaxInstruction().apply(glb, "abc")


class TestOptionJumpTableMax:
    def test_valid(self):
        glb = _FakeGlb()
        OptionJumpTableMax().apply(glb, "2048")
        assert glb.max_jumptable_size == 2048


class TestOptionNanIgnore:
    def test_all(self):
        glb = _FakeGlb()
        OptionNanIgnore().apply(glb, "all")
        assert glb.nan_ignore_all is True
        assert glb.nan_ignore_compare is True

    def test_compare(self):
        glb = _FakeGlb()
        OptionNanIgnore().apply(glb, "compare")
        assert glb.nan_ignore_compare is True

    def test_none(self):
        glb = _FakeGlb()
        glb.nan_ignore_all = True
        glb.nan_ignore_compare = True
        OptionNanIgnore().apply(glb, "none")
        assert glb.nan_ignore_all is False
        assert glb.nan_ignore_compare is False


class TestOptionReadOnly:
    def test_on(self):
        glb = _FakeGlb()
        OptionReadOnly().apply(glb, "on")
        assert glb.readonlypropagate is True


class TestOptionPrintFlags:
    def test_null_printing(self):
        glb = _FakeGlb()
        OptionNullPrinting().apply(glb, "on")
        assert glb.print_.option_NULL is True

    def test_inplace_ops(self):
        glb = _FakeGlb()
        OptionInPlaceOps().apply(glb, "on")
        assert glb.print_.option_inplace_ops is True

    def test_convention_printing(self):
        glb = _FakeGlb()
        OptionConventionPrinting().apply(glb, "on")
        assert glb.print_.option_convention is True

    def test_nocast_printing(self):
        glb = _FakeGlb()
        OptionNoCastPrinting().apply(glb, "on")
        assert glb.print_.option_nocasts is True

    def test_hide_extensions(self):
        glb = _FakeGlb()
        OptionHideExtensions().apply(glb, "on")
        assert glb.print_.option_hide_exts is True


class TestOptionSplitDatatypes:
    def test_struct_on(self):
        glb = _FakeGlb()
        OptionSplitDatatypes().apply(glb, "struct", "on")
        assert glb.split_datatype_config & 1

    def test_array_on(self):
        glb = _FakeGlb()
        OptionSplitDatatypes().apply(glb, "array", "on")
        assert glb.split_datatype_config & 2

    def test_pointer_off(self):
        glb = _FakeGlb()
        glb.split_datatype_config = 7
        OptionSplitDatatypes().apply(glb, "pointer", "off")
        assert not (glb.split_datatype_config & 4)


class TestOptionSetAction:
    def test_apply(self):
        glb = _FakeGlb()
        result = OptionSetAction().apply(glb, "normalize")
        assert "normalize" in result
