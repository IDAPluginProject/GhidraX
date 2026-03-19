"""Tests for ghidra.core.globalcontext -- ContextBitRange + ContextInternal."""
from __future__ import annotations

from ghidra.core.space import AddrSpace
from ghidra.core.address import Address
from ghidra.core.globalcontext import ContextBitRange, ContextInternal


def _spc(name="ram", index=0, size=4):
    return AddrSpace(name=name, size=size, ind=index)


def _addr(offset, spc=None):
    if spc is None:
        spc = _spc()
    return Address(spc, offset)


# ---------------------------------------------------------------------------
# ContextBitRange
# ---------------------------------------------------------------------------

class TestContextBitRange:
    def test_single_bit(self):
        cbr = ContextBitRange(0, 0)
        vec = [0]
        cbr.setValue(vec, 1)
        assert cbr.getValue(vec) == 1
        cbr.setValue(vec, 0)
        assert cbr.getValue(vec) == 0

    def test_multi_bit_same_word(self):
        cbr = ContextBitRange(4, 7)
        vec = [0]
        cbr.setValue(vec, 0xF)
        assert cbr.getValue(vec) == 0xF
        cbr.setValue(vec, 0x5)
        assert cbr.getValue(vec) == 0x5

    def test_high_bits(self):
        cbr = ContextBitRange(0, 3)
        vec = [0]
        cbr.setValue(vec, 0xA)
        assert cbr.getValue(vec) == 0xA

    def test_auto_extend_vec(self):
        cbr = ContextBitRange(32, 35)
        vec = []
        cbr.setValue(vec, 0xC)
        assert len(vec) >= 2
        assert cbr.getValue(vec) == 0xC

    def test_get_from_short_vec(self):
        cbr = ContextBitRange(64, 67)
        vec = [0]
        assert cbr.getValue(vec) == 0

    def test_preserves_other_bits(self):
        cbr = ContextBitRange(4, 7)
        vec = [0xFFFFFFFF]
        cbr.setValue(vec, 0)
        assert cbr.getValue(vec) == 0
        other = ContextBitRange(0, 3)
        assert other.getValue(vec) == 0xF


# ---------------------------------------------------------------------------
# ContextInternal
# ---------------------------------------------------------------------------

class TestContextInternal:
    def test_register_and_get_variable(self):
        ctx = ContextInternal()
        ctx.registerVariable("mode", 0, 1)
        cbr = ctx.getVariable("mode")
        assert cbr is not None
        assert ctx.getVariable("nonexist") is None

    def test_set_and_get_default(self):
        ctx = ContextInternal()
        ctx.registerVariable("mode", 0, 3)
        ctx.setVariableDefault("mode", 5)
        assert ctx.getDefaultValue("mode") == 5

    def test_default_value_zero(self):
        ctx = ContextInternal()
        ctx.registerVariable("x", 0, 7)
        assert ctx.getDefaultValue("x") == 0

    def test_set_variable_at_address(self):
        ctx = ContextInternal()
        ctx.registerVariable("thumb", 0, 0)
        spc = _spc()
        addr1 = Address(spc, 0x1000)
        addr2 = Address(spc, 0x2000)
        ctx.setVariable("thumb", addr1, 1)
        blob1 = ctx.getContext(addr1)
        blob2 = ctx.getContext(addr2)
        cbr = ctx.getVariable("thumb")
        assert cbr.getValue(blob1) == 1
        assert cbr.getValue(blob2) == 0

    def test_multiple_variables(self):
        ctx = ContextInternal()
        ctx.registerVariable("a", 0, 3)
        ctx.registerVariable("b", 4, 7)
        ctx.setVariableDefault("a", 0xC)
        ctx.setVariableDefault("b", 0x3)
        assert ctx.getDefaultValue("a") == 0xC
        assert ctx.getDefaultValue("b") == 0x3

    def test_get_tracked_set_empty(self):
        ctx = ContextInternal()
        spc = _spc()
        assert ctx.getTrackedSet(Address(spc, 0)) == []

    def test_set_variable_region(self):
        ctx = ContextInternal()
        ctx.registerVariable("v", 0, 3)
        spc = _spc()
        a1 = Address(spc, 0x100)
        a2 = Address(spc, 0x200)
        ctx.setVariableRegion("v", a1, a2, 7)
        blob = ctx.getContext(a1)
        cbr = ctx.getVariable("v")
        assert cbr.getValue(blob) == 7

    def test_context_isolation(self):
        ctx = ContextInternal()
        ctx.registerVariable("m", 0, 7)
        spc = _spc()
        addr_a = Address(spc, 0x10)
        addr_b = Address(spc, 0x20)
        ctx.setVariable("m", addr_a, 0xAB)
        ctx.setVariable("m", addr_b, 0xCD)
        cbr = ctx.getVariable("m")
        assert cbr.getValue(ctx.getContext(addr_a)) == 0xAB
        assert cbr.getValue(ctx.getContext(addr_b)) == 0xCD
