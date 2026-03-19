"""Tests for ghidra.arch.pcodecompile -- Location, StarQuality, ExprTree, PcodeCompile."""
from __future__ import annotations

import pytest

from ghidra.arch.pcodecompile import (
    Location, StarQuality, ExprTree, PcodeCompile,
)


# ---------------------------------------------------------------------------
# Location
# ---------------------------------------------------------------------------

class TestLocation:
    def test_defaults(self):
        loc = Location()
        assert loc.getFilename() == ""
        assert loc.getLineno() == 0

    def test_with_values(self):
        loc = Location("test.sla", 42)
        assert loc.getFilename() == "test.sla"
        assert loc.getLineno() == 42

    def test_format(self):
        loc = Location("foo.sla", 10)
        assert loc.format() == "foo.sla:10"

    def test_repr(self):
        loc = Location("a.sla", 5)
        assert "a.sla" in repr(loc)
        assert "5" in repr(loc)


# ---------------------------------------------------------------------------
# StarQuality
# ---------------------------------------------------------------------------

class TestStarQuality:
    def test_defaults(self):
        sq = StarQuality()
        assert sq.id == 0
        assert sq.size == 0

    def test_with_values(self):
        sq = StarQuality(space_id=3, size=4)
        assert sq.id == 3
        assert sq.size == 4


# ---------------------------------------------------------------------------
# ExprTree
# ---------------------------------------------------------------------------

class TestExprTree:
    def test_defaults(self):
        et = ExprTree()
        assert et.ops == []
        assert et.outvn is None

    def test_with_output(self):
        et = ExprTree(outvn="my_vn")
        assert et.getOut() == "my_vn"

    def test_set_output(self):
        et = ExprTree()
        et.setOutput("new_out")
        assert et.getOut() == "new_out"

    def test_to_vector(self):
        et = ExprTree()
        et.ops = ["op1", "op2"]
        result = ExprTree.toVector(et)
        assert result == ["op1", "op2"]
        assert et.ops == []

    def test_append_params(self):
        class FakeOp:
            def __init__(self):
                self.inputs = []
            def addInput(self, vn):
                self.inputs.append(vn)

        p1 = ExprTree(outvn="v1")
        p1.ops = ["a"]
        p2 = ExprTree(outvn="v2")
        p2.ops = ["b"]

        op = FakeOp()
        result = ExprTree.appendParams(op, [p1, p2])
        assert result == ["a", "b", op]
        assert op.inputs == ["v1", "v2"]
        assert p1.outvn is None
        assert p2.outvn is None


# ---------------------------------------------------------------------------
# PcodeCompile (abstract, test via concrete subclass)
# ---------------------------------------------------------------------------

class _ConcretePcodeCompile(PcodeCompile):
    """Minimal concrete subclass for testing the ABC."""
    def __init__(self):
        super().__init__()
        self._temp_counter = 0x1000
        self._symbols = []
        self._errors = []
        self._warnings = []

    def allocateTemp(self) -> int:
        val = self._temp_counter
        self._temp_counter += 4
        return val

    def addSymbol(self, sym) -> None:
        self._symbols.append(sym)

    def getLocation(self, sym):
        return Location("test", 0)

    def reportError(self, loc, msg: str) -> None:
        self._errors.append(msg)

    def reportWarning(self, loc, msg: str) -> None:
        self._warnings.append(msg)


class TestPcodeCompile:
    def test_defaults(self):
        pc = _ConcretePcodeCompile()
        assert pc.getDefaultSpace() is None
        assert pc.getConstantSpace() is None
        assert pc._local_labelcount == 0
        assert pc._enforceLocalKey is False

    def test_set_spaces(self):
        pc = _ConcretePcodeCompile()
        pc.setDefaultSpace("ram")
        pc.setConstantSpace("const")
        pc.setUniqueSpace("unique")
        assert pc.getDefaultSpace() == "ram"
        assert pc.getConstantSpace() == "const"

    def test_reset_label_count(self):
        pc = _ConcretePcodeCompile()
        pc._local_labelcount = 5
        pc.resetLabelCount()
        assert pc._local_labelcount == 0

    def test_enforce_local_key(self):
        pc = _ConcretePcodeCompile()
        pc.setEnforceLocalKey(True)
        assert pc._enforceLocalKey is True

    def test_allocate_temp(self):
        pc = _ConcretePcodeCompile()
        t1 = pc.allocateTemp()
        t2 = pc.allocateTemp()
        assert t1 == 0x1000
        assert t2 == 0x1004

    def test_add_symbol(self):
        pc = _ConcretePcodeCompile()
        pc.addSymbol("sym1")
        assert "sym1" in pc._symbols

    def test_report_error(self):
        pc = _ConcretePcodeCompile()
        pc.reportError(None, "bad thing")
        assert "bad thing" in pc._errors

    def test_report_warning(self):
        pc = _ConcretePcodeCompile()
        pc.reportWarning(None, "watch out")
        assert "watch out" in pc._warnings

    def test_build_temporary_raises(self):
        pc = _ConcretePcodeCompile()
        with pytest.raises(NotImplementedError):
            pc.buildTemporary()

    def test_create_op_raises(self):
        pc = _ConcretePcodeCompile()
        with pytest.raises(NotImplementedError):
            pc.createOp(1)

    def test_create_load_raises(self):
        pc = _ConcretePcodeCompile()
        with pytest.raises(NotImplementedError):
            pc.createLoad(StarQuality(), ExprTree())

    def test_create_store_raises(self):
        pc = _ConcretePcodeCompile()
        with pytest.raises(NotImplementedError):
            pc.createStore(StarQuality(), ExprTree(), ExprTree())

    def test_propagate_size_raises(self):
        with pytest.raises(NotImplementedError):
            PcodeCompile.propagateSize(None)
