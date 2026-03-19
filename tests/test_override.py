"""Tests for ghidra.arch.override — Override system."""
from __future__ import annotations

import io
import pytest

from ghidra.core.space import AddrSpace
from ghidra.core.address import Address
from ghidra.arch.override import Override


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _make_space(name: str = "ram", index: int = 0, size: int = 4) -> AddrSpace:
    return AddrSpace(name=name, size=size, ind=index)


def _make_addr(offset: int, spc: AddrSpace | None = None) -> Address:
    if spc is None:
        spc = _make_space()
    return Address(spc, offset)


# ---------------------------------------------------------------------------
# Type conversion
# ---------------------------------------------------------------------------

class TestTypeConversion:
    def test_type_to_string_all(self):
        assert Override.typeToString(Override.NONE) == "none"
        assert Override.typeToString(Override.BRANCH) == "branch"
        assert Override.typeToString(Override.CALL) == "call"
        assert Override.typeToString(Override.CALL_RETURN) == "callreturn"
        assert Override.typeToString(Override.RETURN) == "return"
        assert Override.typeToString(99) == "unknown"

    def test_string_to_type_all(self):
        assert Override.stringToType("none") == Override.NONE
        assert Override.stringToType("branch") == Override.BRANCH
        assert Override.stringToType("call") == Override.CALL
        assert Override.stringToType("callreturn") == Override.CALL_RETURN
        assert Override.stringToType("return") == Override.RETURN
        assert Override.stringToType("BRANCH") == Override.BRANCH  # case insensitive
        assert Override.stringToType("unknown_xyz") == Override.NONE

    def test_roundtrip(self):
        for tp in (Override.NONE, Override.BRANCH, Override.CALL, Override.CALL_RETURN, Override.RETURN):
            assert Override.stringToType(Override.typeToString(tp)) == tp


# ---------------------------------------------------------------------------
# ForceGoto
# ---------------------------------------------------------------------------

class TestForceGoto:
    def test_insert_and_get(self):
        ov = Override()
        spc = _make_space()
        target = Address(spc, 0x1000)
        dest = Address(spc, 0x2000)
        ov.insertForceGoto(target, dest)
        assert ov.getForceGoto(target) is dest

    def test_get_missing(self):
        ov = Override()
        spc = _make_space()
        assert ov.getForceGoto(Address(spc, 0x9999)) is None

    def test_overwrite(self):
        ov = Override()
        spc = _make_space()
        target = Address(spc, 0x1000)
        ov.insertForceGoto(target, Address(spc, 0x2000))
        new_dest = Address(spc, 0x3000)
        ov.insertForceGoto(target, new_dest)
        assert ov.getForceGoto(target) is new_dest


# ---------------------------------------------------------------------------
# DeadcodeDelay
# ---------------------------------------------------------------------------

class TestDeadcodeDelay:
    def test_insert_and_has(self):
        ov = Override()
        spc = _make_space("ram", index=2)
        ov.insertDeadcodeDelay(spc, 3)
        assert ov.hasDeadcodeDelay(spc) is True
        assert ov.getDeadcodeDelay(spc) == 3

    def test_no_delay(self):
        ov = Override()
        spc = _make_space("ram", index=0)
        assert ov.hasDeadcodeDelay(spc) is False
        assert ov.getDeadcodeDelay(spc) == 0

    def test_multiple_spaces(self):
        ov = Override()
        s0 = _make_space("ram", index=0)
        s1 = _make_space("register", index=1)
        ov.insertDeadcodeDelay(s0, 2)
        ov.insertDeadcodeDelay(s1, 5)
        assert ov.getDeadcodeDelay(s0) == 2
        assert ov.getDeadcodeDelay(s1) == 5


# ---------------------------------------------------------------------------
# IndirectOverride
# ---------------------------------------------------------------------------

class TestIndirectOverride:
    def test_insert_and_get(self):
        ov = Override()
        spc = _make_space()
        cp = Address(spc, 0x400)
        dc = Address(spc, 0x800)
        ov.insertIndirectOverride(cp, dc)
        assert ov.getIndirectOverride(cp) is dc

    def test_get_missing(self):
        ov = Override()
        spc = _make_space()
        assert ov.getIndirectOverride(Address(spc, 0x123)) is None


# ---------------------------------------------------------------------------
# ProtoOverride
# ---------------------------------------------------------------------------

class TestProtoOverride:
    def test_insert_and_get(self):
        ov = Override()
        spc = _make_space()
        cp = Address(spc, 0x500)
        proto = object()  # placeholder
        ov.insertProtoOverride(cp, proto)
        assert ov.getProtoOverride(cp) is proto

    def test_get_missing(self):
        ov = Override()
        spc = _make_space()
        assert ov.getProtoOverride(Address(spc, 0xABC)) is None


# ---------------------------------------------------------------------------
# MultistageJump
# ---------------------------------------------------------------------------

class TestMultistageJump:
    def test_insert_and_query(self):
        ov = Override()
        spc = _make_space()
        a = Address(spc, 0x100)
        ov.insertMultistageJump(a)
        assert ov.queryMultistageJumptable(a) is True

    def test_query_missing(self):
        ov = Override()
        spc = _make_space()
        assert ov.queryMultistageJumptable(Address(spc, 0x999)) is False


# ---------------------------------------------------------------------------
# FlowOverride
# ---------------------------------------------------------------------------

class TestFlowOverride:
    def test_insert_and_get(self):
        ov = Override()
        spc = _make_space()
        a = Address(spc, 0x200)
        ov.insertFlowOverride(a, Override.CALL)
        assert ov.hasFlowOverride() is True
        assert ov.getFlowOverride(a) == Override.CALL

    def test_insert_none_removes(self):
        ov = Override()
        spc = _make_space()
        a = Address(spc, 0x200)
        ov.insertFlowOverride(a, Override.BRANCH)
        ov.insertFlowOverride(a, Override.NONE)
        assert ov.hasFlowOverride() is False
        assert ov.getFlowOverride(a) == Override.NONE

    def test_get_missing(self):
        ov = Override()
        spc = _make_space()
        assert ov.getFlowOverride(Address(spc, 0x300)) == Override.NONE

    def test_has_flow_empty(self):
        ov = Override()
        assert ov.hasFlowOverride() is False


# ---------------------------------------------------------------------------
# Clear
# ---------------------------------------------------------------------------

class TestClear:
    def test_clear_all(self):
        ov = Override()
        spc = _make_space()
        ov.insertForceGoto(Address(spc, 1), Address(spc, 2))
        ov.insertDeadcodeDelay(spc, 3)
        ov.insertIndirectOverride(Address(spc, 4), Address(spc, 5))
        ov.insertProtoOverride(Address(spc, 6), object())
        ov.insertMultistageJump(Address(spc, 7))
        ov.insertFlowOverride(Address(spc, 8), Override.RETURN)
        ov.clear()
        assert ov.getForceGoto(Address(spc, 1)) is None
        assert ov.hasDeadcodeDelay(spc) is False
        assert ov.getIndirectOverride(Address(spc, 4)) is None
        assert ov.getProtoOverride(Address(spc, 6)) is None
        assert ov.queryMultistageJumptable(Address(spc, 7)) is False
        assert ov.hasFlowOverride() is False


# ---------------------------------------------------------------------------
# PrintRaw
# ---------------------------------------------------------------------------

class TestPrintRaw:
    def test_printraw_forcegoto(self):
        ov = Override()
        spc = _make_space()
        ov.insertForceGoto(Address(spc, 0x100), Address(spc, 0x200))
        buf = io.StringIO()
        ov.printRaw(buf)
        assert "forcegoto" in buf.getvalue()

    def test_printraw_flow(self):
        ov = Override()
        spc = _make_space()
        ov.insertFlowOverride(Address(spc, 0x300), Override.BRANCH)
        buf = io.StringIO()
        ov.printRaw(buf)
        assert "branch" in buf.getvalue()


# ---------------------------------------------------------------------------
# GenerateOverrideMessages
# ---------------------------------------------------------------------------

class TestGenerateMessages:
    def test_deadcode_message(self):
        ov = Override()
        spc = _make_space("ram", index=0)
        ov.insertDeadcodeDelay(spc, 2)
        msgs = ov.generateOverrideMessages()
        assert len(msgs) >= 1
        assert "deadcode" in msgs[0].lower()

    def test_empty_messages(self):
        ov = Override()
        msgs = ov.generateOverrideMessages()
        assert msgs == []
