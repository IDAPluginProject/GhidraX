"""Tests for ghidra.console.codedata — code/data analysis module."""
from __future__ import annotations

import io
import pytest

from ghidra.console.interface import (
    IfaceData, IfaceCommand, IfaceCapability, IfaceStatus,
    IfaceParseError, IfaceExecutionError,
)
from ghidra.console.codedata import (
    CodeUnit, DisassemblyResult, AddrLink, TargetHit, TargetFeature,
    DisassemblyEngine, CodeDataAnalysis,
    IfaceCodeDataCapability, IfaceCodeDataCommand,
    IfcCodeDataInit, IfcCodeDataTarget, IfcCodeDataRun,
    IfcCodeDataDumpModelHits, IfcCodeDataDumpCrossRefs,
    IfcCodeDataDumpStarts, IfcCodeDataDumpUnlinked,
    IfcCodeDataDumpTargetHits,
)


# ---------------------------------------------------------------------------
# CodeUnit
# ---------------------------------------------------------------------------

class TestCodeUnit:
    def test_defaults(self):
        cu = CodeUnit()
        assert cu.flags == 0
        assert cu.size == 0

    def test_flags(self):
        cu = CodeUnit(CodeUnit.fallthru | CodeUnit.jump, 4)
        assert cu.flags & CodeUnit.fallthru
        assert cu.flags & CodeUnit.jump
        assert cu.size == 4

    def test_flag_constants(self):
        assert CodeUnit.fallthru == 1
        assert CodeUnit.jump == 2
        assert CodeUnit.call == 4
        assert CodeUnit.notcode == 8
        assert CodeUnit.hit_by_fallthru == 16
        assert CodeUnit.hit_by_jump == 32
        assert CodeUnit.hit_by_call == 64
        assert CodeUnit.errantstart == 128
        assert CodeUnit.targethit == 256
        assert CodeUnit.thunkhit == 512


# ---------------------------------------------------------------------------
# DisassemblyResult
# ---------------------------------------------------------------------------

class TestDisassemblyResult:
    def test_defaults(self):
        r = DisassemblyResult()
        assert r.success is False
        assert r.length == 0
        assert r.flags == 0
        assert r.jumpaddress is None
        assert r.targethit == 0


# ---------------------------------------------------------------------------
# AddrLink
# ---------------------------------------------------------------------------

class TestAddrLink:
    def test_equality(self):
        a = AddrLink(10, 20)
        b = AddrLink(10, 20)
        assert a == b

    def test_inequality(self):
        a = AddrLink(10, 20)
        b = AddrLink(10, 30)
        assert a != b

    def test_ordering(self):
        a = AddrLink(10, 20)
        b = AddrLink(20, 10)
        assert a < b

    def test_ordering_same_a(self):
        a = AddrLink(10, 20)
        b = AddrLink(10, 30)
        assert a < b

    def test_hash(self):
        a = AddrLink(10, 20)
        b = AddrLink(10, 20)
        assert hash(a) == hash(b)

    def test_none_b(self):
        a = AddrLink(10)
        assert a.b is None
        b = AddrLink(10, 5)
        assert a < b


# ---------------------------------------------------------------------------
# TargetHit
# ---------------------------------------------------------------------------

class TestTargetHit:
    def test_fields(self):
        th = TargetHit(0x1000, 0x2000, 0x3000, 1)
        assert th.funcstart == 0x1000
        assert th.codeaddr == 0x2000
        assert th.thunkaddr == 0x3000
        assert th.mask == 1

    def test_ordering(self):
        a = TargetHit(0x1000, 0x2000, 0x3000, 1)
        b = TargetHit(0x2000, 0x1000, 0x3000, 1)
        assert a < b


# ---------------------------------------------------------------------------
# TargetFeature
# ---------------------------------------------------------------------------

class TestTargetFeature:
    def test_defaults(self):
        tf = TargetFeature()
        assert tf.name == ""
        assert tf.featuremask == 0

    def test_fields(self):
        tf = TargetFeature("printf", 0x1)
        assert tf.name == "printf"
        assert tf.featuremask == 0x1


# ---------------------------------------------------------------------------
# DisassemblyEngine
# ---------------------------------------------------------------------------

class TestDisassemblyEngine:
    def test_init(self):
        de = DisassemblyEngine()
        assert de._trans is None

    def test_disassemble_no_trans(self):
        de = DisassemblyEngine()
        res = DisassemblyResult()
        de.disassemble(0x1000, res)
        assert res.success is False

    def test_add_target(self):
        de = DisassemblyEngine()
        de.addTarget(0x4000)
        assert 0x4000 in de._targetoffsets


# ---------------------------------------------------------------------------
# CodeDataAnalysis
# ---------------------------------------------------------------------------

class TestCodeDataAnalysis:
    def test_is_iface_data(self):
        cda = CodeDataAnalysis()
        assert isinstance(cda, IfaceData)

    def test_defaults(self):
        cda = CodeDataAnalysis()
        assert cda.alignment == 1
        assert cda.glb is None
        assert len(cda.codeunit) == 0
        assert len(cda.targets) == 0

    def test_init_with_none(self):
        cda = CodeDataAnalysis()
        cda.init(None)
        assert cda.glb is None

    def test_add_target(self):
        cda = CodeDataAnalysis()
        cda.addTarget("printf", 0x4000, 1)
        assert cda.getNumTargets() == 1
        assert 0x4000 in cda.targets

    def test_clear_hit_by(self):
        cda = CodeDataAnalysis()
        cu = CodeUnit(CodeUnit.hit_by_fallthru | CodeUnit.hit_by_jump, 2)
        cda.codeunit[0x1000] = cu
        cda.clearHitBy()
        assert (cu.flags & CodeUnit.hit_by_fallthru) == 0
        assert (cu.flags & CodeUnit.hit_by_jump) == 0

    def test_mark_fallthru_hits(self):
        cda = CodeDataAnalysis()
        cu1 = CodeUnit(CodeUnit.fallthru, 2)
        cu2 = CodeUnit(0, 2)
        cda.codeunit[100] = cu1
        cda.codeunit[102] = cu2
        cda.markFallthruHits()
        assert cu2.flags & CodeUnit.hit_by_fallthru

    def test_mark_cross_hits(self):
        cda = CodeDataAnalysis()
        cu = CodeUnit(0, 2)
        cda.codeunit[0x2000] = cu
        link = AddrLink(0x2000, 0x1000)
        cda.tofrom_crossref[link] = CodeUnit.call
        cda.markCrossHits()
        assert cu.flags & CodeUnit.hit_by_call

    def test_find_unlinked(self):
        cda = CodeDataAnalysis()
        cu1 = CodeUnit(0, 2)  # No hit_by flags
        cu2 = CodeUnit(CodeUnit.hit_by_call, 2)
        cda.codeunit[0x1000] = cu1
        cda.codeunit[0x2000] = cu2
        cda.findUnlinked()
        assert 0x1000 in cda.unlinkedstarts
        assert 0x2000 not in cda.unlinkedstarts

    def test_dump_cross_refs(self):
        cda = CodeDataAnalysis()
        link = AddrLink(0x1000, 0x2000)
        cda.fromto_crossref[link] = CodeUnit.call
        buf = io.StringIO()
        cda.dumpCrossRefs(buf)
        out = buf.getvalue()
        assert "0x1000" in out
        assert "0x2000" in out
        assert "call" in out

    def test_dump_function_starts(self):
        cda = CodeDataAnalysis()
        link = AddrLink(0x5000, 0x1000)
        cda.tofrom_crossref[link] = CodeUnit.call
        buf = io.StringIO()
        cda.dumpFunctionStarts(buf)
        assert "0x5000" in buf.getvalue()

    def test_dump_unlinked(self):
        cda = CodeDataAnalysis()
        cda.unlinkedstarts.append(0x3000)
        buf = io.StringIO()
        cda.dumpUnlinked(buf)
        assert "0x3000" in buf.getvalue()

    def test_dump_target_hits(self):
        cda = CodeDataAnalysis()
        cda.targets[0x4000] = TargetFeature("exit", 1)
        cda.targethits.append(TargetHit(0x1000, 0x2000, 0x4000, 1))
        buf = io.StringIO()
        cda.dumpTargetHits(buf)
        out = buf.getvalue()
        assert "exit" in out


# ---------------------------------------------------------------------------
# IfaceCodeDataCommand
# ---------------------------------------------------------------------------

class TestIfaceCodeDataCommand:
    def test_module(self):
        cmd = IfcCodeDataInit()
        assert cmd.getModule() == "codedata"

    def test_create_data(self):
        cmd = IfcCodeDataInit()
        data = cmd.createData()
        assert isinstance(data, CodeDataAnalysis)


# ---------------------------------------------------------------------------
# IfcCodeDataTarget
# ---------------------------------------------------------------------------

class TestIfcCodeDataTarget:
    def test_no_name_raises(self):
        cmd = IfcCodeDataTarget()
        cmd.codedata = CodeDataAnalysis()
        with pytest.raises(IfaceParseError, match="Missing system call"):
            cmd.execute("")


# ---------------------------------------------------------------------------
# IfcCodeDataDump commands
# ---------------------------------------------------------------------------

class TestDumpCommands:
    def test_dump_model_hits(self):
        cmd = IfcCodeDataDumpModelHits()
        cmd.codedata = CodeDataAnalysis()
        buf = io.StringIO()

        class FakeStatus:
            fileoptr = buf
        cmd.status = FakeStatus()
        cmd.execute("")  # Should not raise

    def test_dump_crossrefs(self):
        cmd = IfcCodeDataDumpCrossRefs()
        cmd.codedata = CodeDataAnalysis()
        buf = io.StringIO()

        class FakeStatus:
            fileoptr = buf
        cmd.status = FakeStatus()
        cmd.execute("")

    def test_dump_starts(self):
        cmd = IfcCodeDataDumpStarts()
        cmd.codedata = CodeDataAnalysis()
        buf = io.StringIO()

        class FakeStatus:
            fileoptr = buf
        cmd.status = FakeStatus()
        cmd.execute("")

    def test_dump_unlinked(self):
        cmd = IfcCodeDataDumpUnlinked()
        cmd.codedata = CodeDataAnalysis()
        buf = io.StringIO()

        class FakeStatus:
            fileoptr = buf
        cmd.status = FakeStatus()
        cmd.execute("")

    def test_dump_targethits(self):
        cmd = IfcCodeDataDumpTargetHits()
        cmd.codedata = CodeDataAnalysis()
        buf = io.StringIO()

        class FakeStatus:
            fileoptr = buf
        cmd.status = FakeStatus()
        cmd.execute("")

    def test_no_codedata_raises(self):
        cmd = IfcCodeDataDumpModelHits()
        cmd.codedata = None
        with pytest.raises(IfaceExecutionError, match="No code data"):
            cmd.execute("")


# ---------------------------------------------------------------------------
# IfaceCodeDataCapability
# ---------------------------------------------------------------------------

class TestIfaceCodeDataCapability:
    def test_singleton(self):
        cap1 = IfaceCodeDataCapability.getInstance()
        cap2 = IfaceCodeDataCapability.getInstance()
        assert cap1 is cap2

    def test_name(self):
        cap = IfaceCodeDataCapability.getInstance()
        assert cap.getName() == "codedata"

    def test_is_capability(self):
        cap = IfaceCodeDataCapability()
        assert isinstance(cap, IfaceCapability)
