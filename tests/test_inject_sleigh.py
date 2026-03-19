"""Tests for ghidra.arch.inject_sleigh -- InjectContextSleigh, InjectPayloadCallfixup,
InjectPayloadCallother, ExecutablePcodeSleigh, InjectPayloadDynamic, PcodeInjectLibrarySleigh."""
from __future__ import annotations

import io
import xml.etree.ElementTree as ET

import pytest

from ghidra.core.error import LowlevelError
from ghidra.arch.inject import InjectPayload, InjectPayloadSleigh, InjectContext
from ghidra.arch.inject_sleigh import (
    InjectContextSleigh,
    InjectPayloadCallfixup,
    InjectPayloadCallother,
    ExecutablePcodeSleigh,
    InjectPayloadDynamic,
    PcodeInjectLibrarySleigh,
)


# ---------------------------------------------------------------------------
# InjectContextSleigh
# ---------------------------------------------------------------------------

class TestInjectContextSleigh:
    def test_defaults(self):
        ctx = InjectContextSleigh()
        assert ctx.cacher is None
        assert ctx.pos is None
        assert ctx.glb is None
        assert ctx.inputlist == []
        assert ctx.output == []

    def test_inherits_inject_context(self):
        ctx = InjectContextSleigh()
        assert isinstance(ctx, InjectContext)

    def test_clear(self):
        ctx = InjectContextSleigh()
        ctx.inputlist.append("a")
        ctx.output.append("b")
        ctx.clear()
        assert ctx.inputlist == []
        assert ctx.output == []


# ---------------------------------------------------------------------------
# InjectPayloadCallfixup
# ---------------------------------------------------------------------------

CALLFIXUP_XML = """
<callfixup name="myfix">
    <target name="malloc"/>
    <target name="calloc"/>
    <pcode>
        <body>EAX = 0;</body>
    </pcode>
</callfixup>
"""

class TestInjectPayloadCallfixup:
    def test_defaults(self):
        p = InjectPayloadCallfixup("src")
        assert p.getName() == "unknown"
        assert p.getType() == InjectPayload.CALLFIXUP_TYPE
        assert p.getSource() == "src"
        assert p.targetSymbolNames == []

    def test_decode_xml(self):
        el = ET.fromstring(CALLFIXUP_XML.strip())
        p = InjectPayloadCallfixup("test_source")
        p.decode(el)
        assert p.getName() == "myfix"
        assert p.getType() == InjectPayload.CALLFIXUP_TYPE
        assert "malloc" in p.getTargetSymbolNames()
        assert "calloc" in p.getTargetSymbolNames()
        assert p.parsestring == "EAX = 0;"

    def test_decode_missing_body_non_dynamic(self):
        xml = """<callfixup name="bad">
            <pcode></pcode>
        </callfixup>"""
        el = ET.fromstring(xml)
        p = InjectPayloadCallfixup("src")
        with pytest.raises(LowlevelError, match="Missing <body>"):
            p.decode(el)

    def test_decode_dynamic_no_body(self):
        xml = """<callfixup name="dynfix">
            <pcode dynamic="true"></pcode>
        </callfixup>"""
        el = ET.fromstring(xml)
        p = InjectPayloadCallfixup("src")
        p.decode(el)
        assert p.isDynamic() is True
        assert p.parsestring == ""

    def test_inherits(self):
        p = InjectPayloadCallfixup()
        assert isinstance(p, InjectPayloadSleigh)
        assert isinstance(p, InjectPayload)


# ---------------------------------------------------------------------------
# InjectPayloadCallother
# ---------------------------------------------------------------------------

CALLOTHER_XML = """
<callotherfixup targetop="myop">
    <pcode>
        <body>output = input0 + input1;</body>
    </pcode>
</callotherfixup>
"""

class TestInjectPayloadCallother:
    def test_defaults(self):
        p = InjectPayloadCallother("src")
        assert p.getName() == "unknown"
        assert p.getType() == InjectPayload.CALLOTHERFIXUP_TYPE

    def test_decode_xml(self):
        el = ET.fromstring(CALLOTHER_XML.strip())
        p = InjectPayloadCallother("test_source")
        p.decode(el)
        assert p.getName() == "myop"
        assert p.parsestring == "output = input0 + input1;"

    def test_decode_missing_pcode(self):
        xml = """<callotherfixup targetop="bad"></callotherfixup>"""
        el = ET.fromstring(xml)
        p = InjectPayloadCallother("src")
        with pytest.raises(LowlevelError, match="does not contain"):
            p.decode(el)


# ---------------------------------------------------------------------------
# ExecutablePcodeSleigh
# ---------------------------------------------------------------------------

class TestExecutablePcodeSleigh:
    def test_defaults(self):
        ep = ExecutablePcodeSleigh(None, "src", "script1")
        assert ep.getName() == "script1"
        assert ep.getType() == InjectPayload.EXECUTABLEPCODE_TYPE
        assert ep.getSource() == "src"

    def test_decode_xml(self):
        xml = """<pcode><body>EAX = EBX;</body></pcode>"""
        el = ET.fromstring(xml)
        ep = ExecutablePcodeSleigh(None, "src", "test")
        ep.decode(el)
        assert ep.parsestring == "EAX = EBX;"

    def test_print_template_no_tpl(self):
        ep = ExecutablePcodeSleigh(None, "src", "test")
        ep.parsestring = "x = y;"
        buf = io.StringIO()
        ep.printTemplate(buf)
        assert buf.getvalue() == "x = y;"


# ---------------------------------------------------------------------------
# InjectPayloadDynamic
# ---------------------------------------------------------------------------

class TestInjectPayloadDynamic:
    def test_defaults(self):
        dp = InjectPayloadDynamic()
        assert dp.isDynamic() is True
        assert dp.getSource() == "dynamic"

    def test_from_base(self):
        base = InjectPayload("base_name", InjectPayload.CALLFIXUP_TYPE)
        base.paramshift = 3
        dp = InjectPayloadDynamic(None, base)
        assert dp.getName() == "base_name"
        assert dp.getType() == InjectPayload.CALLFIXUP_TYPE
        assert dp.paramshift == 3
        assert dp.isDynamic() is True

    def test_decode_raises(self):
        dp = InjectPayloadDynamic()
        with pytest.raises(LowlevelError, match="not supported"):
            dp.decode(None)

    def test_print_template(self):
        dp = InjectPayloadDynamic()
        buf = io.StringIO()
        dp.printTemplate(buf)
        assert buf.getvalue() == "dynamic"

    def test_inject_missing(self):
        dp = InjectPayloadDynamic()

        class _FakeCtx:
            class _Addr:
                def getOffset(self):
                    return 0x1000
            baseaddr = _Addr()

        with pytest.raises(LowlevelError, match="Missing dynamic inject"):
            dp.inject(_FakeCtx(), None)


# ---------------------------------------------------------------------------
# PcodeInjectLibrarySleigh
# ---------------------------------------------------------------------------

class TestPcodeInjectLibrarySleigh:
    def test_defaults(self):
        lib = PcodeInjectLibrarySleigh()
        assert lib.numPayloads() == 0
        assert lib._glb is None

    def test_allocate_callfixup(self):
        lib = PcodeInjectLibrarySleigh()
        idx = lib.allocateInject("src", "fix1", InjectPayload.CALLFIXUP_TYPE)
        assert idx == 0
        p = lib.getPayload(idx)
        assert isinstance(p, InjectPayloadCallfixup)

    def test_allocate_callother(self):
        lib = PcodeInjectLibrarySleigh()
        idx = lib.allocateInject("src", "other1", InjectPayload.CALLOTHERFIXUP_TYPE)
        p = lib.getPayload(idx)
        assert isinstance(p, InjectPayloadCallother)

    def test_allocate_executable(self):
        lib = PcodeInjectLibrarySleigh()
        idx = lib.allocateInject("src", "exec1", InjectPayload.EXECUTABLEPCODE_TYPE)
        p = lib.getPayload(idx)
        assert isinstance(p, ExecutablePcodeSleigh)

    def test_allocate_generic(self):
        lib = PcodeInjectLibrarySleigh()
        idx = lib.allocateInject("src", "gen1", InjectPayload.CALLMECHANISM_TYPE)
        p = lib.getPayload(idx)
        assert isinstance(p, InjectPayloadSleigh)

    def test_manual_call_fixup(self):
        lib = PcodeInjectLibrarySleigh()
        idx = lib.manualCallFixup("myfunc", "EAX = 0;")
        p = lib.getPayload(idx)
        assert p is not None
        assert p.getType() == InjectPayload.CALLFIXUP_TYPE

    def test_manual_callother_fixup(self):
        lib = PcodeInjectLibrarySleigh()
        idx = lib.manualCallOtherFixup("myop", "out", ["in0", "in1"], "out = in0;")
        p = lib.getPayload(idx)
        assert p is not None
        assert p.getType() == InjectPayload.CALLOTHERFIXUP_TYPE

    def test_get_cached_context(self):
        lib = PcodeInjectLibrarySleigh()
        ctx = lib.getCachedContext()
        assert isinstance(ctx, InjectContextSleigh)

    def test_get_behaviors_no_arch(self):
        lib = PcodeInjectLibrarySleigh()
        assert lib.getBehaviors() == []

    def test_register_dynamic_inject(self):
        lib = PcodeInjectLibrarySleigh()
        idx = lib.allocateInject("src", "dyn", InjectPayload.CALLFIXUP_TYPE)
        p = lib.getPayload(idx)
        p.dynamic = True
        lib.registerInject(idx)
        # After registration, dynamic payload is replaced
        p2 = lib.getPayload(idx)
        assert isinstance(p2, InjectPayloadDynamic)
