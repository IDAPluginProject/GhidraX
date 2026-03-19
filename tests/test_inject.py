"""Tests for ghidra.arch.inject -- InjectPayload + PcodeInjectLibrary."""
from __future__ import annotations

from ghidra.arch.inject import (
    InjectPayload, InjectPayloadSleigh, InjectContext, PcodeInjectLibrary,
)


class TestInjectPayload:
    def test_defaults(self):
        p = InjectPayload()
        assert p.getName() == ""
        assert p.getType() == 0
        assert p.getParamShift() == 0
        assert p.isDynamic() is False
        assert p.isIncidentalCopy() is False

    def test_named(self):
        p = InjectPayload("myfixup", InjectPayload.CALLFIXUP_TYPE)
        assert p.getName() == "myfixup"
        assert p.getType() == InjectPayload.CALLFIXUP_TYPE

    def test_type_constants(self):
        assert InjectPayload.CALLFIXUP_TYPE == 1
        assert InjectPayload.CALLOTHERFIXUP_TYPE == 2
        assert InjectPayload.CALLMECHANISM_TYPE == 3
        assert InjectPayload.EXECUTABLEPCODE_TYPE == 4


class TestInjectPayloadSleigh:
    def test_construction(self):
        p = InjectPayloadSleigh("src.sla", "fix1", InjectPayload.CALLFIXUP_TYPE)
        assert p.getSource() == "src.sla"
        assert p.getName() == "fix1"
        assert p.getType() == InjectPayload.CALLFIXUP_TYPE

    def test_print_template(self):
        import io
        p = InjectPayloadSleigh()
        p.parsestring = "EAX = 0;"
        buf = io.StringIO()
        p.printTemplate(buf)
        assert buf.getvalue() == "EAX = 0;"


class TestInjectContext:
    def test_defaults(self):
        ctx = InjectContext()
        assert ctx.inputlist == []
        assert ctx.output == []

    def test_clear(self):
        ctx = InjectContext()
        ctx.inputlist.append("a")
        ctx.output.append("b")
        ctx.clear()
        assert ctx.inputlist == []
        assert ctx.output == []


class TestPcodeInjectLibrary:
    def test_empty(self):
        lib = PcodeInjectLibrary()
        assert lib.numPayloads() == 0
        assert lib.getPayload(0) is None
        assert lib.getPayloadByName("x") is None
        assert lib.getPayloadId("x") == -1

    def test_register_callfixup(self):
        lib = PcodeInjectLibrary()
        p = InjectPayload("fix1", InjectPayload.CALLFIXUP_TYPE)
        idx = lib.registerPayload(p)
        assert idx == 0
        assert lib.numPayloads() == 1
        assert lib.getPayload(idx) is p
        assert lib.getPayloadByName("fix1") is p
        assert lib.getPayloadId("fix1") == 0
        assert lib.getCallFixupId("fix1") == 0
        assert lib.hasCallFixup("fix1") is True
        assert lib.hasCallFixup("nope") is False

    def test_register_callother_fixup(self):
        lib = PcodeInjectLibrary()
        p = InjectPayload("other1", InjectPayload.CALLOTHERFIXUP_TYPE)
        idx = lib.registerPayload(p)
        assert lib.getCallOtherFixupId("other1") == idx
        assert lib.hasCallOtherFixup("other1") is True

    def test_register_callmechanism(self):
        lib = PcodeInjectLibrary()
        p = InjectPayload("mech1", InjectPayload.CALLMECHANISM_TYPE)
        idx = lib.registerPayload(p)
        assert lib.getCallMechanismId("mech1") == idx

    def test_register_exe_pcode(self):
        lib = PcodeInjectLibrary()
        p = InjectPayload("exe1", InjectPayload.EXECUTABLEPCODE_TYPE)
        idx = lib.registerPayload(p)
        assert lib.getExePcodeId("exe1") == idx
        assert lib.getExePcodePayload("exe1") is p
        assert lib.getExePcodePayload("nope") is None

    def test_multiple_payloads(self):
        lib = PcodeInjectLibrary()
        p0 = InjectPayload("a", InjectPayload.CALLFIXUP_TYPE)
        p1 = InjectPayload("b", InjectPayload.CALLOTHERFIXUP_TYPE)
        p2 = InjectPayload("c", InjectPayload.EXECUTABLEPCODE_TYPE)
        i0 = lib.registerPayload(p0)
        i1 = lib.registerPayload(p1)
        i2 = lib.registerPayload(p2)
        assert lib.numPayloads() == 3
        assert lib.getPayload(i0) is p0
        assert lib.getPayload(i1) is p1
        assert lib.getPayload(i2) is p2

    def test_manual_call_fixup(self):
        lib = PcodeInjectLibrary()
        idx = lib.manualCallFixup("myfunc", "out", ["in1"], "EAX=0;")
        assert idx >= 0
        assert lib.hasCallFixup("myfunc") is True

    def test_manual_callother_fixup(self):
        lib = PcodeInjectLibrary()
        idx = lib.manualCallOtherFixup("myother", "out", ["in1"], "EAX=0;")
        assert idx >= 0
        assert lib.hasCallOtherFixup("myother") is True

    def test_get_payload_out_of_range(self):
        lib = PcodeInjectLibrary()
        assert lib.getPayload(-1) is None
        assert lib.getPayload(100) is None
