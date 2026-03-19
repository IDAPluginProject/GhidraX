"""End-to-end integration tests for Phase 1 arch modules.

Verifies that:
- SleighArchitecture + RawBinaryArchitecture + XmlArchitecture class hierarchies work
- PcodeInjectLibrarySleigh integrates with architecture objects
- RawBinaryArchitecture can load a real binary and expose it via its loader
- Architecture capability registry works across all three capability types
- Full arch → loader → decompiler pipeline wiring (using existing DecompilerPython)
"""
from __future__ import annotations

import io
import os
import tempfile

import pytest

from ghidra.arch.architecture import Architecture, ArchitectureCapability
from ghidra.arch.sleigh_arch import (
    SleighArchitecture, SleighArchitectureCapability,
    FileManage, LanguageDescription, CompilerTag,
)
from ghidra.arch.inject_sleigh import (
    PcodeInjectLibrarySleigh, InjectPayloadCallfixup,
    InjectPayloadCallother, ExecutablePcodeSleigh, InjectPayloadDynamic,
)
from ghidra.arch.pcodecompile import Location, ExprTree, PcodeCompile
from ghidra.arch.raw_arch import (
    RawBinaryArchitecture, RawBinaryArchitectureCapability, RawLoadImage,
)
from ghidra.arch.xml_arch import (
    XmlArchitecture, XmlArchitectureCapability,
)
from ghidra.arch.inject import InjectPayload
from ghidra.core.error import LowlevelError


# ---------------------------------------------------------------------------
# Hierarchy / isinstance checks
# ---------------------------------------------------------------------------

class TestClassHierarchy:
    """Verify the full inheritance chain for all arch types."""

    def test_raw_binary_is_sleigh_is_architecture(self):
        arch = RawBinaryArchitecture("f", "t")
        assert isinstance(arch, SleighArchitecture)
        assert isinstance(arch, Architecture)

    def test_xml_is_sleigh_is_architecture(self):
        arch = XmlArchitecture("f", "t")
        assert isinstance(arch, SleighArchitecture)
        assert isinstance(arch, Architecture)

    def test_capabilities_are_architecture_capability(self):
        assert isinstance(SleighArchitectureCapability(), ArchitectureCapability)
        assert isinstance(RawBinaryArchitectureCapability(), ArchitectureCapability)
        assert isinstance(XmlArchitectureCapability(), ArchitectureCapability)

    def test_capability_names_are_distinct(self):
        names = {
            SleighArchitectureCapability().getName(),
            RawBinaryArchitectureCapability().getName(),
            XmlArchitectureCapability().getName(),
        }
        assert len(names) == 3
        assert "sleigh" in names
        assert "raw" in names
        assert "xml" in names


# ---------------------------------------------------------------------------
# Capability dispatch
# ---------------------------------------------------------------------------

class TestCapabilityDispatch:
    """Verify that each capability builds the correct architecture type."""

    def test_sleigh_builds_sleigh(self):
        cap = SleighArchitectureCapability()
        a = cap.buildArchitecture("f.bin", "x86:LE:64:default")
        assert type(a) is SleighArchitecture

    def test_raw_builds_raw(self):
        cap = RawBinaryArchitectureCapability()
        a = cap.buildArchitecture("f.bin", "x86:LE:64:default")
        assert type(a) is RawBinaryArchitecture

    def test_xml_builds_xml(self):
        cap = XmlArchitectureCapability()
        a = cap.buildArchitecture("f.xml", "x86:LE:64:default")
        assert type(a) is XmlArchitecture


# ---------------------------------------------------------------------------
# RawBinaryArchitecture full load pipeline
# ---------------------------------------------------------------------------

class TestRawBinaryPipeline:
    """Test that RawBinaryArchitecture can load a binary and read bytes."""

    def test_load_and_read_bytes(self, tmp_path):
        code = b"\x55\x89\xE5\x31\xC0\x5D\xC3"  # push ebp; mov ebp,esp; xor eax,eax; pop ebp; ret
        binfile = tmp_path / "func.bin"
        binfile.write_bytes(code)

        arch = RawBinaryArchitecture(str(binfile), "x86:LE:32:default")
        arch.buildLoader()

        assert arch.loader is not None
        buf = bytearray(len(code))

        class Addr:
            def getOffset(self):
                return 0
        arch.loader.loadFill(buf, len(code), Addr())
        assert bytes(buf) == code

    def test_adjustvma_affects_reads(self, tmp_path):
        code = b"\xCC\xCC\xCC"
        binfile = tmp_path / "int3.bin"
        binfile.write_bytes(code)

        arch = RawBinaryArchitecture(str(binfile), "x86:LE:32:default")
        arch.adjustvma = 0x400000
        arch.buildLoader()

        buf = bytearray(1)

        class Addr:
            def __init__(self, off):
                self._off = off
            def getOffset(self):
                return self._off

        arch.loader.loadFill(buf, 1, Addr(0x400001))
        assert buf[0] == 0xCC

        arch.loader.loadFill(buf, 1, Addr(0))
        assert buf[0] == 0  # outside range


# ---------------------------------------------------------------------------
# PcodeInjectLibrarySleigh integration with arch
# ---------------------------------------------------------------------------

class TestInjectLibraryWithArch:
    """Test that PcodeInjectLibrarySleigh works with architecture objects."""

    def test_create_with_raw_arch(self, tmp_path):
        binfile = tmp_path / "test.bin"
        binfile.write_bytes(b"\x90")
        arch = RawBinaryArchitecture(str(binfile), "x86:LE:32:default")
        lib = PcodeInjectLibrarySleigh(arch)
        assert lib._glb is arch
        ctx = lib.getCachedContext()
        assert ctx.glb is arch

    def test_allocate_and_retrieve(self):
        arch = SleighArchitecture("f", "t")
        lib = PcodeInjectLibrarySleigh(arch)

        idx_fix = lib.allocateInject("src", "fix1", InjectPayload.CALLFIXUP_TYPE)
        idx_other = lib.allocateInject("src", "other1", InjectPayload.CALLOTHERFIXUP_TYPE)
        idx_exec = lib.allocateInject("src", "exec1", InjectPayload.EXECUTABLEPCODE_TYPE)

        assert isinstance(lib.getPayload(idx_fix), InjectPayloadCallfixup)
        assert isinstance(lib.getPayload(idx_other), InjectPayloadCallother)
        assert isinstance(lib.getPayload(idx_exec), ExecutablePcodeSleigh)
        assert lib.numPayloads() == 3

    def test_manual_fixup_roundtrip(self):
        arch = SleighArchitecture("f", "t")
        lib = PcodeInjectLibrarySleigh(arch)
        idx = lib.manualCallFixup("myfix", "EAX = 0;")
        p = lib.getPayload(idx)
        assert p is not None
        assert p.getType() == InjectPayload.CALLFIXUP_TYPE

    def test_dynamic_replacement(self):
        arch = SleighArchitecture("f", "t")
        lib = PcodeInjectLibrarySleigh(arch)
        idx = lib.allocateInject("src", "dyn", InjectPayload.CALLFIXUP_TYPE)
        lib.getPayload(idx).dynamic = True
        lib.registerInject(idx)
        assert isinstance(lib.getPayload(idx), InjectPayloadDynamic)


# ---------------------------------------------------------------------------
# SleighArchitecture ldefs resolution end-to-end
# ---------------------------------------------------------------------------

class TestSleighArchLdefsResolution:
    """Full ldefs → resolve → architecture integration."""

    @pytest.fixture(autouse=True)
    def _reset(self):
        saved_desc = list(SleighArchitecture._descriptions)
        saved_loaded = SleighArchitecture._descriptions_loaded
        saved_paths = list(SleighArchitecture.specpaths._paths)
        SleighArchitecture._descriptions = []
        SleighArchitecture._descriptions_loaded = False
        SleighArchitecture.specpaths = FileManage()
        yield
        SleighArchitecture._descriptions = saved_desc
        SleighArchitecture._descriptions_loaded = saved_loaded
        SleighArchitecture.specpaths = FileManage()
        for p in saved_paths:
            SleighArchitecture.specpaths.addDir2Path(p)

    def test_full_flow(self, tmp_path):
        """Write ldefs → scan → resolve → check archid."""
        ldefs = """<?xml version="1.0" encoding="UTF-8"?>
<language_definitions>
    <language processor="x86" endian="little" size="32"
             variant="default" version="2.14"
             slafile="x86.sla" processorspec="x86.pspec"
             id="x86:LE:32:default">
        <description>Intel/AMD 32-bit x86</description>
        <compiler name="gcc" spec="x86gcc.cspec" id="gcc"/>
        <compiler name="Visual Studio" spec="x86win.cspec" id="windows"/>
    </language>
</language_definitions>"""
        (tmp_path / "x86.ldefs").write_text(ldefs)
        SleighArchitecture.specpaths.addDir2Path(str(tmp_path))
        SleighArchitecture.collectSpecFiles()

        descs = SleighArchitecture.getDescriptions()
        assert len(descs) == 1
        assert descs[0].getProcessor() == "x86"
        assert descs[0].getSize() == 32

        # Create a RawBinaryArchitecture and resolve
        arch = RawBinaryArchitecture("test.bin", "x86:LE:32:default")
        arch.resolveArchitecture()
        assert arch._languageindex == 0
        assert "x86:LE:32:default" in arch.archid

        # Verify compiler resolution
        lang = descs[0]
        gcc = lang.getCompiler("gcc")
        assert gcc.getId() == "gcc"
        win = lang.getCompiler("windows")
        assert win.getId() == "windows"
        fallback = lang.getCompiler("nonexistent")
        assert fallback.getId() == "gcc"  # first compiler as fallback

    def test_multiple_architectures(self, tmp_path):
        ldefs = """<?xml version="1.0" encoding="UTF-8"?>
<language_definitions>
    <language processor="x86" endian="little" size="32"
             variant="default" version="2.14"
             slafile="x86.sla" processorspec="x86.pspec"
             id="x86:LE:32:default">
        <compiler name="gcc" spec="x86gcc.cspec" id="default"/>
    </language>
    <language processor="ARM" endian="little" size="32"
             variant="v7" version="1.0"
             slafile="ARM7_le.sla" processorspec="ARM7.pspec"
             id="ARM:LE:32:v7">
        <compiler name="gcc" spec="armgcc.cspec" id="default"/>
    </language>
</language_definitions>"""
        (tmp_path / "multi.ldefs").write_text(ldefs)
        SleighArchitecture.specpaths.addDir2Path(str(tmp_path))
        SleighArchitecture.collectSpecFiles()

        assert len(SleighArchitecture.getDescriptions()) == 2

        arch_x86 = RawBinaryArchitecture("test.bin", "x86:LE:32:default")
        arch_x86.resolveArchitecture()
        assert arch_x86._languageindex == 0

        arch_arm = RawBinaryArchitecture("test.bin", "ARM:LE:32:v7")
        arch_arm.resolveArchitecture()
        assert arch_arm._languageindex == 1


# ---------------------------------------------------------------------------
# XmlArchitectureCapability file detection
# ---------------------------------------------------------------------------

class TestXmlFileDetection:
    def test_detects_binaryimage(self, tmp_path):
        xmlfile = tmp_path / "img.xml"
        xmlfile.write_text('<binaryimage arch="x86:LE:32:default"></binaryimage>')
        cap = XmlArchitectureCapability()
        assert cap.isFileMatch(str(xmlfile)) is True

    def test_rejects_raw_binary(self, tmp_path):
        binfile = tmp_path / "raw.bin"
        binfile.write_bytes(b"\x00\x01\x02\x03")
        cap = XmlArchitectureCapability()
        assert cap.isFileMatch(str(binfile)) is False

    def test_raw_always_matches(self, tmp_path):
        binfile = tmp_path / "any.dat"
        binfile.write_bytes(b"\xFF")
        cap = RawBinaryArchitectureCapability()
        assert cap.isFileMatch(str(binfile)) is True


# ---------------------------------------------------------------------------
# Cross-module: Location + ExprTree used by inject pipeline
# ---------------------------------------------------------------------------

class TestCrossModuleTypes:
    """Ensure types from pcodecompile and inject can be used together."""

    def test_location_in_error_reporting(self):
        loc = Location("test.cspec", 42)
        assert loc.format() == "test.cspec:42"

    def test_expr_tree_basic_ops(self):
        et = ExprTree(outvn="v0")
        et.ops = ["op1", "op2"]
        vec = ExprTree.toVector(et)
        assert vec == ["op1", "op2"]

    def test_inject_payload_source_tracking(self):
        p = InjectPayloadCallfixup("test.cspec")
        assert p.getSource() == "test.cspec"
        assert p.getType() == InjectPayload.CALLFIXUP_TYPE


# ---------------------------------------------------------------------------
# DecompilerPython integration (if available)
# ---------------------------------------------------------------------------

class TestDecompilerPythonIntegration:
    """Test that the arch modules integrate with the existing DecompilerPython."""

    def test_raw_arch_with_decompiler(self, tmp_path):
        """Verify RawBinaryArchitecture can be constructed alongside DecompilerPython."""
        try:
            from ghidra.sleigh.decompiler_python import DecompilerPython
        except ImportError:
            pytest.skip("DecompilerPython not available")

        code = b"\x55\x89\xE5\x31\xC0\x5D\xC3"
        binfile = tmp_path / "func.bin"
        binfile.write_bytes(code)

        # Verify both objects can coexist
        arch = RawBinaryArchitecture(str(binfile), "x86:LE:32:default")
        arch.buildLoader()
        assert arch.loader is not None

        # DecompilerPython uses its own pipeline internally
        dp = DecompilerPython()
        assert dp is not None

    def test_inject_library_standalone(self):
        """Verify inject library can be used without full architecture init."""
        lib = PcodeInjectLibrarySleigh()
        idx = lib.manualCallFixup("nop_func", "")
        p = lib.getPayload(idx)
        assert p is not None
