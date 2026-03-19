"""Tests for ghidra.arch.sleigh_arch -- CompilerTag, LanguageDescription, SleighArchitecture, FileManage."""
from __future__ import annotations

import io
import os
import tempfile
import xml.etree.ElementTree as ET

import pytest

from ghidra.arch.sleigh_arch import (
    CompilerTag, LanguageDescription, FileManage,
    SleighArchitecture, SleighArchitectureCapability,
)
from ghidra.core.error import LowlevelError


# ---------------------------------------------------------------------------
# CompilerTag
# ---------------------------------------------------------------------------

class TestCompilerTag:
    def test_defaults(self):
        ct = CompilerTag()
        assert ct.getName() == ""
        assert ct.getSpec() == ""
        assert ct.getId() == ""

    def test_decode(self):
        xml = '<compiler name="gcc" spec="x86gcc.cspec" id="gcc"/>'
        el = ET.fromstring(xml)
        ct = CompilerTag()
        ct.decode(el)
        assert ct.getName() == "gcc"
        assert ct.getSpec() == "x86gcc.cspec"
        assert ct.getId() == "gcc"

    def test_repr(self):
        ct = CompilerTag()
        ct.id = "msvc"
        ct.spec = "x86win.cspec"
        assert "msvc" in repr(ct)


# ---------------------------------------------------------------------------
# LanguageDescription
# ---------------------------------------------------------------------------

SAMPLE_LDEFS_LANGUAGE = """
<language processor="x86" endian="little" size="64"
         variant="default" version="2.14"
         slafile="x86-64.sla" processorspec="x86-64.pspec"
         id="x86:LE:64:default">
    <description>Intel/AMD 64-bit x86</description>
    <compiler name="gcc" spec="x86-64-gcc.cspec" id="gcc"/>
    <compiler name="Visual Studio" spec="x86-64-win.cspec" id="windows"/>
</language>
"""

class TestLanguageDescription:
    def _make(self) -> LanguageDescription:
        el = ET.fromstring(SAMPLE_LDEFS_LANGUAGE.strip())
        ld = LanguageDescription()
        ld.decode(el)
        return ld

    def test_basic_fields(self):
        ld = self._make()
        assert ld.getProcessor() == "x86"
        assert ld.isBigEndian() is False
        assert ld.getSize() == 64
        assert ld.getVariant() == "default"
        assert ld.getVersion() == "2.14"
        assert ld.getSlaFile() == "x86-64.sla"
        assert ld.getProcessorSpec() == "x86-64.pspec"
        assert ld.getId() == "x86:LE:64:default"
        assert "Intel" in ld.getDescription()
        assert ld.isDeprecated() is False

    def test_compilers(self):
        ld = self._make()
        assert ld.numCompilers() == 2
        assert ld.getCompilerByIndex(0).getId() == "gcc"
        assert ld.getCompilerByIndex(1).getId() == "windows"

    def test_get_compiler_by_name(self):
        ld = self._make()
        assert ld.getCompiler("gcc").getId() == "gcc"
        assert ld.getCompiler("windows").getId() == "windows"

    def test_get_compiler_fallback_default(self):
        xml = """<language processor="test" endian="little" size="32"
                    variant="default" version="1" slafile="t.sla"
                    processorspec="t.pspec" id="test:LE:32:default">
                    <compiler name="Default" spec="d.cspec" id="default"/>
                    <compiler name="Other" spec="o.cspec" id="other"/>
                 </language>"""
        el = ET.fromstring(xml)
        ld = LanguageDescription()
        ld.decode(el)
        # Requesting non-existent compiler should fall back to "default"
        ct = ld.getCompiler("nonexistent")
        assert ct.getId() == "default"

    def test_get_compiler_fallback_first(self):
        ld = self._make()
        # No "default" id, falls back to first
        ct = ld.getCompiler("nonexistent")
        assert ct.getId() == "gcc"

    def test_deprecated(self):
        xml = """<language processor="old" endian="big" size="32"
                    variant="v1" version="1" slafile="old.sla"
                    processorspec="old.pspec" id="old:BE:32:v1"
                    deprecated="true">
                    <compiler name="gcc" spec="old.cspec" id="gcc"/>
                 </language>"""
        el = ET.fromstring(xml)
        ld = LanguageDescription()
        ld.decode(el)
        assert ld.isDeprecated() is True
        assert ld.isBigEndian() is True

    def test_truncations(self):
        xml = """<language processor="test" endian="little" size="32"
                    variant="default" version="1" slafile="t.sla"
                    processorspec="t.pspec" id="test:LE:32:default">
                    <truncate_space space="ram" size="3"/>
                    <compiler name="gcc" spec="t.cspec" id="gcc"/>
                 </language>"""
        el = ET.fromstring(xml)
        ld = LanguageDescription()
        ld.decode(el)
        assert ld.numTruncations() == 1
        assert ld.getTruncation(0)["space"] == "ram"
        assert ld.getTruncation(0)["size"] == 3

    def test_repr(self):
        ld = self._make()
        assert "x86" in repr(ld)


# ---------------------------------------------------------------------------
# FileManage
# ---------------------------------------------------------------------------

class TestFileManage:
    def test_add_dir(self):
        fm = FileManage()
        fm.addDir2Path("/a")
        fm.addDir2Path("/a")  # duplicate
        assert fm._paths == ["/a"]

    def test_find_file(self, tmp_path):
        fm = FileManage()
        fm.addDir2Path(str(tmp_path))
        (tmp_path / "hello.txt").write_text("hi")
        assert fm.findFile("hello.txt") is not None
        assert fm.findFile("nope.txt") is None

    def test_match_list(self, tmp_path):
        fm = FileManage()
        fm.addDir2Path(str(tmp_path))
        (tmp_path / "a.ldefs").write_text("<x/>")
        (tmp_path / "b.txt").write_text("nope")
        results = fm.matchList(".ldefs", recursive=False)
        assert len(results) == 1
        assert results[0].endswith("a.ldefs")

    def test_scan_directory_recursive(self, tmp_path):
        target = tmp_path / "a" / "b" / "target"
        target.mkdir(parents=True)
        results = FileManage.scanDirectoryRecursive("target", str(tmp_path), 3)
        assert len(results) == 1
        assert results[0].endswith("target")

    def test_directory_list(self, tmp_path):
        (tmp_path / "sub1").mkdir()
        (tmp_path / "sub2").mkdir()
        (tmp_path / "file.txt").write_text("x")
        results = FileManage.directoryList(str(tmp_path))
        assert len(results) == 2


# ---------------------------------------------------------------------------
# SleighArchitecture - normalization statics
# ---------------------------------------------------------------------------

class TestNormalization:
    def test_normalize_processor(self):
        assert SleighArchitecture.normalizeProcessor("i386") == "x86"
        assert SleighArchitecture.normalizeProcessor("arm") == "arm"

    def test_normalize_endian(self):
        assert SleighArchitecture.normalizeEndian("big") == "BE"
        assert SleighArchitecture.normalizeEndian("little") == "LE"
        assert SleighArchitecture.normalizeEndian("LE") == "LE"

    def test_normalize_size(self):
        assert SleighArchitecture.normalizeSize("64bit") == "64"
        assert SleighArchitecture.normalizeSize("32-bit") == "32"
        assert SleighArchitecture.normalizeSize("16") == "16"

    def test_normalize_architecture_4_parts(self):
        result = SleighArchitecture.normalizeArchitecture("x86:LE:64:default")
        assert result == "x86:LE:64:default:default"

    def test_normalize_architecture_5_parts(self):
        result = SleighArchitecture.normalizeArchitecture("x86:LE:64:default:gcc")
        assert result == "x86:LE:64:default:gcc"

    def test_normalize_architecture_bad(self):
        with pytest.raises(LowlevelError):
            SleighArchitecture.normalizeArchitecture("x86:LE")

    def test_normalize_architecture_with_386(self):
        result = SleighArchitecture.normalizeArchitecture("i386:little:32bit:default")
        assert result == "x86:LE:32:default:default"


# ---------------------------------------------------------------------------
# SleighArchitecture - construction and ldefs loading
# ---------------------------------------------------------------------------

class TestSleighArchitectureConstruction:
    def test_defaults(self):
        sa = SleighArchitecture()
        assert sa.getFilename() == ""
        assert sa.getTarget() == ""
        assert sa._languageindex == -1

    def test_with_args(self):
        errs = io.StringIO()
        sa = SleighArchitecture("test.bin", "x86:LE:64:default", errs)
        assert sa.getFilename() == "test.bin"
        assert sa.getTarget() == "x86:LE:64:default"
        sa.printMessage("hello")
        assert "hello" in errs.getvalue()


class TestSleighArchitectureLdefs:
    """Test ldefs loading with a temporary .ldefs file."""

    @pytest.fixture(autouse=True)
    def _reset_descriptions(self):
        """Ensure clean static state for each test."""
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

    def test_load_language_description(self, tmp_path):
        ldefs_content = """<?xml version="1.0" encoding="UTF-8"?>
<language_definitions>
    <language processor="x86" endian="little" size="64"
             variant="default" version="2.14"
             slafile="x86-64.sla" processorspec="x86-64.pspec"
             id="x86:LE:64:default">
        <description>Intel 64-bit</description>
        <compiler name="gcc" spec="x86gcc.cspec" id="gcc"/>
    </language>
    <language processor="ARM" endian="little" size="32"
             variant="v8" version="1.0"
             slafile="ARM8_le.sla" processorspec="ARM8.pspec"
             id="ARM:LE:32:v8">
        <description>ARM v8 LE</description>
        <compiler name="gcc" spec="armgcc.cspec" id="default"/>
    </language>
</language_definitions>"""
        ldefs_file = tmp_path / "test.ldefs"
        ldefs_file.write_text(ldefs_content)

        SleighArchitecture.loadLanguageDescription(str(ldefs_file))
        assert len(SleighArchitecture._descriptions) == 2
        assert SleighArchitecture._descriptions[0].getId() == "x86:LE:64:default"
        assert SleighArchitecture._descriptions[1].getId() == "ARM:LE:32:v8"

    def test_load_bad_file(self, tmp_path):
        bad_file = tmp_path / "bad.ldefs"
        bad_file.write_text("NOT XML AT ALL <<<>>>")
        errs = io.StringIO()
        SleighArchitecture.loadLanguageDescription(str(bad_file), errs)
        assert "WARNING" in errs.getvalue()
        assert len(SleighArchitecture._descriptions) == 0

    def test_collect_spec_files(self, tmp_path):
        ldefs_content = """<?xml version="1.0" encoding="UTF-8"?>
<language_definitions>
    <language processor="TEST" endian="little" size="32"
             variant="default" version="1"
             slafile="test.sla" processorspec="test.pspec"
             id="TEST:LE:32:default">
        <compiler name="gcc" spec="test.cspec" id="default"/>
    </language>
</language_definitions>"""
        (tmp_path / "test.ldefs").write_text(ldefs_content)
        SleighArchitecture.specpaths.addDir2Path(str(tmp_path))
        SleighArchitecture.collectSpecFiles()
        assert len(SleighArchitecture._descriptions) == 1
        assert SleighArchitecture._descriptions[0].getProcessor() == "TEST"

    def test_collect_spec_files_only_once(self, tmp_path):
        ldefs_content = """<?xml version="1.0" encoding="UTF-8"?>
<language_definitions>
    <language processor="T" endian="little" size="32"
             variant="d" version="1" slafile="t.sla"
             processorspec="t.pspec" id="T:LE:32:d">
        <compiler name="gcc" spec="t.cspec" id="default"/>
    </language>
</language_definitions>"""
        (tmp_path / "once.ldefs").write_text(ldefs_content)
        SleighArchitecture.specpaths.addDir2Path(str(tmp_path))
        SleighArchitecture.collectSpecFiles()
        count1 = len(SleighArchitecture._descriptions)
        SleighArchitecture.collectSpecFiles()
        assert len(SleighArchitecture._descriptions) == count1

    def test_resolve_architecture(self, tmp_path):
        ldefs_content = """<?xml version="1.0" encoding="UTF-8"?>
<language_definitions>
    <language processor="x86" endian="little" size="64"
             variant="default" version="2.14"
             slafile="x86-64.sla" processorspec="x86-64.pspec"
             id="x86:LE:64:default">
        <compiler name="gcc" spec="x86gcc.cspec" id="gcc"/>
    </language>
</language_definitions>"""
        (tmp_path / "x86.ldefs").write_text(ldefs_content)
        SleighArchitecture.specpaths.addDir2Path(str(tmp_path))
        SleighArchitecture.collectSpecFiles()

        sa = SleighArchitecture("test.bin", "x86:LE:64:default")
        sa.resolveArchitecture()
        assert sa._languageindex == 0
        assert sa.archid == "x86:LE:64:default:default"

    def test_resolve_architecture_not_found(self, tmp_path):
        SleighArchitecture.specpaths.addDir2Path(str(tmp_path))
        SleighArchitecture._descriptions_loaded = True  # skip file scan

        sa = SleighArchitecture("test.bin", "NONEXIST:LE:32:default")
        with pytest.raises(LowlevelError, match="No sleigh specification"):
            sa.resolveArchitecture()

    def test_shutdown(self, tmp_path):
        SleighArchitecture._descriptions.append(LanguageDescription())
        SleighArchitecture._descriptions_loaded = True
        SleighArchitecture.shutdown()
        assert len(SleighArchitecture._descriptions) == 0
        assert SleighArchitecture._descriptions_loaded is False


# ---------------------------------------------------------------------------
# SleighArchitectureCapability
# ---------------------------------------------------------------------------

class TestSleighArchitectureCapability:
    def test_name(self):
        cap = SleighArchitectureCapability()
        assert cap.getName() == "sleigh"

    def test_build(self):
        cap = SleighArchitectureCapability()
        sa = cap.buildArchitecture("test.bin", "x86:LE:64:default")
        assert isinstance(sa, SleighArchitecture)
        assert sa.getFilename() == "test.bin"

    def test_is_file_match(self):
        cap = SleighArchitectureCapability()
        assert cap.isFileMatch("anything.bin") is True

    def test_is_xml_match(self):
        cap = SleighArchitectureCapability()
        assert cap.isXmlMatch(None) is False
