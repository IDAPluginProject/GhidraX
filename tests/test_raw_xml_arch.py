"""Tests for ghidra.arch.raw_arch and ghidra.arch.xml_arch."""
from __future__ import annotations

import io
import os
import tempfile

import pytest

from ghidra.core.error import LowlevelError
from ghidra.arch.raw_arch import (
    RawLoadImage, RawBinaryArchitecture, RawBinaryArchitectureCapability,
)
from ghidra.arch.xml_arch import (
    XmlArchitecture, XmlArchitectureCapability,
)
from ghidra.arch.sleigh_arch import SleighArchitecture
from ghidra.arch.architecture import ArchitectureCapability


# ---------------------------------------------------------------------------
# RawLoadImage
# ---------------------------------------------------------------------------

class TestRawLoadImage:
    def test_open_and_load(self, tmp_path):
        binfile = tmp_path / "test.bin"
        binfile.write_bytes(b"\x90\x90\xCC\xC3")
        ldr = RawLoadImage(str(binfile))
        ldr.open()
        assert ldr.getArchType() == "raw"
        assert ldr.getFileName() == str(binfile)

    def test_open_nonexistent(self):
        ldr = RawLoadImage("/nonexistent/file.bin")
        with pytest.raises(LowlevelError, match="Unable to open"):
            ldr.open()

    def test_load_fill(self, tmp_path):
        binfile = tmp_path / "test.bin"
        binfile.write_bytes(b"\x01\x02\x03\x04")
        ldr = RawLoadImage(str(binfile))
        ldr.open()

        class FakeAddr:
            def getOffset(self):
                return 1
        buf = bytearray(2)
        ldr.loadFill(buf, 2, FakeAddr())
        assert buf == bytearray(b"\x02\x03")

    def test_load_fill_out_of_bounds(self, tmp_path):
        binfile = tmp_path / "test.bin"
        binfile.write_bytes(b"\x01\x02")
        ldr = RawLoadImage(str(binfile))
        ldr.open()

        class FakeAddr:
            def getOffset(self):
                return 1
        buf = bytearray(4)
        ldr.loadFill(buf, 4, FakeAddr())
        assert buf[0] == 0x02
        assert buf[1] == 0  # out of bounds, padded

    def test_adjust_vma(self, tmp_path):
        binfile = tmp_path / "test.bin"
        binfile.write_bytes(b"\xAA\xBB\xCC")
        ldr = RawLoadImage(str(binfile))
        ldr.open()
        ldr.adjustVma(0x1000)

        class FakeAddr:
            def getOffset(self):
                return 0x1001
        buf = bytearray(1)
        ldr.loadFill(buf, 1, FakeAddr())
        assert buf[0] == 0xBB

    def test_attach_to_space(self):
        ldr = RawLoadImage("test")
        ldr.attachToSpace("ram_space")
        assert ldr._space == "ram_space"


# ---------------------------------------------------------------------------
# RawBinaryArchitectureCapability
# ---------------------------------------------------------------------------

class TestRawBinaryArchitectureCapability:
    def test_name(self):
        cap = RawBinaryArchitectureCapability()
        assert cap.getName() == "raw"

    def test_is_file_match(self):
        cap = RawBinaryArchitectureCapability()
        assert cap.isFileMatch("anything.bin") is True

    def test_is_xml_match_none(self):
        cap = RawBinaryArchitectureCapability()
        assert cap.isXmlMatch(None) is False

    def test_is_xml_match_raw_savefile(self):
        import xml.etree.ElementTree as ET
        doc = ET.fromstring("<raw_savefile/>")
        cap = RawBinaryArchitectureCapability()
        assert cap.isXmlMatch(doc) is True

    def test_is_xml_match_other(self):
        import xml.etree.ElementTree as ET
        doc = ET.fromstring("<other/>")
        cap = RawBinaryArchitectureCapability()
        assert cap.isXmlMatch(doc) is False

    def test_build_architecture(self):
        cap = RawBinaryArchitectureCapability()
        arch = cap.buildArchitecture("test.bin", "x86:LE:64:default")
        assert isinstance(arch, RawBinaryArchitecture)
        assert isinstance(arch, SleighArchitecture)

    def test_inherits(self):
        cap = RawBinaryArchitectureCapability()
        assert isinstance(cap, ArchitectureCapability)


# ---------------------------------------------------------------------------
# RawBinaryArchitecture
# ---------------------------------------------------------------------------

class TestRawBinaryArchitecture:
    def test_defaults(self):
        arch = RawBinaryArchitecture()
        assert arch.adjustvma == 0
        assert arch.getFilename() == ""

    def test_with_args(self):
        errs = io.StringIO()
        arch = RawBinaryArchitecture("test.bin", "x86:LE:32:default", errs)
        assert arch.getFilename() == "test.bin"
        assert arch.getTarget() == "x86:LE:32:default"
        assert arch.adjustvma == 0

    def test_build_loader(self, tmp_path):
        binfile = tmp_path / "test.bin"
        binfile.write_bytes(b"\x90\xC3")
        arch = RawBinaryArchitecture(str(binfile), "x86:LE:32:default")
        arch.buildLoader()
        assert arch.loader is not None
        assert isinstance(arch.loader, RawLoadImage)

    def test_build_loader_nonexistent(self):
        arch = RawBinaryArchitecture("/nonexistent.bin", "x86:LE:32:default")
        with pytest.raises(LowlevelError):
            arch.buildLoader()

    def test_inherits_sleigh(self):
        arch = RawBinaryArchitecture()
        assert isinstance(arch, SleighArchitecture)


# ---------------------------------------------------------------------------
# XmlArchitectureCapability
# ---------------------------------------------------------------------------

class TestXmlArchitectureCapability:
    def test_name(self):
        cap = XmlArchitectureCapability()
        assert cap.getName() == "xml"

    def test_is_file_match_xml(self, tmp_path):
        xmlfile = tmp_path / "test.xml"
        xmlfile.write_text('<binaryimage arch="x86"></binaryimage>')
        cap = XmlArchitectureCapability()
        assert cap.isFileMatch(str(xmlfile)) is True

    def test_is_file_match_raw(self, tmp_path):
        binfile = tmp_path / "test.bin"
        binfile.write_bytes(b"\x90\xC3")
        cap = XmlArchitectureCapability()
        assert cap.isFileMatch(str(binfile)) is False

    def test_is_file_match_nonexistent(self):
        cap = XmlArchitectureCapability()
        assert cap.isFileMatch("/nonexistent") is False

    def test_is_xml_match(self):
        import xml.etree.ElementTree as ET
        doc = ET.fromstring("<xml_savefile/>")
        cap = XmlArchitectureCapability()
        assert cap.isXmlMatch(doc) is True

    def test_is_xml_match_other(self):
        import xml.etree.ElementTree as ET
        doc = ET.fromstring("<other/>")
        cap = XmlArchitectureCapability()
        assert cap.isXmlMatch(doc) is False

    def test_build_architecture(self):
        cap = XmlArchitectureCapability()
        arch = cap.buildArchitecture("test.xml", "x86:LE:64:default")
        assert isinstance(arch, XmlArchitecture)
        assert isinstance(arch, SleighArchitecture)

    def test_inherits(self):
        cap = XmlArchitectureCapability()
        assert isinstance(cap, ArchitectureCapability)


# ---------------------------------------------------------------------------
# XmlArchitecture
# ---------------------------------------------------------------------------

class TestXmlArchitecture:
    def test_defaults(self):
        arch = XmlArchitecture()
        assert arch.adjustvma == 0
        assert arch.getFilename() == ""

    def test_with_args(self):
        errs = io.StringIO()
        arch = XmlArchitecture("test.xml", "x86:LE:32:default", errs)
        assert arch.getFilename() == "test.xml"
        assert arch.getTarget() == "x86:LE:32:default"

    def test_inherits_sleigh(self):
        arch = XmlArchitecture()
        assert isinstance(arch, SleighArchitecture)

    def test_restore_xml_no_store(self):
        arch = XmlArchitecture()
        # Should return without error when store is None
        arch.restoreXml(None)

    def test_restore_xml_missing_tag(self):
        arch = XmlArchitecture()

        class FakeStore:
            def getTag(self, name):
                return None

        with pytest.raises(LowlevelError, match="Could not find xml_savefile"):
            arch.restoreXml(FakeStore())
