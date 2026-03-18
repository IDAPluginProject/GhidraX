"""Tests for ghidra.arch.loadimage_xml — Python port of loadimage_xml.cc."""
from __future__ import annotations

import sys, os
import pytest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', 'python'))

from ghidra.core.address import Address
from ghidra.core.space import AddrSpace
from ghidra.arch.loadimage import LoadImageFunc, DataUnavailError
from ghidra.arch.loadimage_xml import LoadImageXml


# =========================================================================
# Shared fixtures
# =========================================================================

_SPACE = AddrSpace(name="ram", size=8, ind=1)


def _addr(offset: int) -> Address:
    return Address(_SPACE, offset)


# =========================================================================
# Basic construction
# =========================================================================

class TestBasicConstruction:
    def test_empty_image(self):
        img = LoadImageXml(filename="test.bin", archtype="x86")
        assert img.getArchType() == "x86"
        assert img.getFileName() == "test.bin"

    def test_add_chunk(self):
        img = LoadImageXml()
        img.addChunk(_addr(0x1000), b"\x90\x90\x90")
        buf = bytearray(3)
        img.loadFill(buf, 3, _addr(0x1000))
        assert buf == bytearray(b"\x90\x90\x90")

    def test_add_symbol(self):
        img = LoadImageXml()
        img.addSymbol(_addr(0x1000), "main")
        img.openSymbols()
        rec = LoadImageFunc()
        assert img.getNextSymbol(rec) is True
        assert rec.name == "main"
        assert rec.address == _addr(0x1000)
        assert img.getNextSymbol(rec) is False


# =========================================================================
# loadFill
# =========================================================================

class TestLoadFill:
    def test_exact_chunk(self):
        img = LoadImageXml()
        data = bytes(range(16))
        img.addChunk(_addr(0x2000), data)
        buf = bytearray(16)
        img.loadFill(buf, 16, _addr(0x2000))
        assert buf == bytearray(data)

    def test_partial_read(self):
        img = LoadImageXml()
        img.addChunk(_addr(0x2000), bytes(range(16)))
        buf = bytearray(4)
        img.loadFill(buf, 4, _addr(0x2004))
        assert buf == bytearray([4, 5, 6, 7])

    def test_unmapped_raises(self):
        img = LoadImageXml()
        img.addChunk(_addr(0x2000), b"\x00" * 4)
        buf = bytearray(4)
        with pytest.raises(DataUnavailError):
            img.loadFill(buf, 4, _addr(0x9000))

    def test_read_past_end_raises(self):
        img = LoadImageXml()
        img.addChunk(_addr(0x2000), b"\x00" * 4)
        buf = bytearray(8)
        with pytest.raises(DataUnavailError):
            img.loadFill(buf, 8, _addr(0x2000))

    def test_contiguous_chunks(self):
        img = LoadImageXml()
        img.addChunk(_addr(0x1000), b"\xAA" * 4)
        img.addChunk(_addr(0x1004), b"\xBB" * 4)
        buf = bytearray(8)
        img.loadFill(buf, 8, _addr(0x1000))
        assert buf == bytearray(b"\xAA\xAA\xAA\xAA\xBB\xBB\xBB\xBB")


# =========================================================================
# Symbols
# =========================================================================

class TestSymbols:
    def test_multiple_symbols(self):
        img = LoadImageXml()
        img.addSymbol(_addr(0x1000), "main")
        img.addSymbol(_addr(0x2000), "helper")
        img.openSymbols()
        names = []
        rec = LoadImageFunc()
        while img.getNextSymbol(rec):
            names.append(rec.name)
        assert "main" in names
        assert "helper" in names
        assert len(names) == 2

    def test_no_symbols(self):
        img = LoadImageXml()
        img.openSymbols()
        rec = LoadImageFunc()
        assert img.getNextSymbol(rec) is False


# =========================================================================
# Readonly
# =========================================================================

class TestReadonly:
    def test_readonly_chunk(self):
        img = LoadImageXml()
        img.addChunk(_addr(0x1000), b"\x00" * 16, readonly=True)
        img.addChunk(_addr(0x2000), b"\x00" * 16, readonly=False)
        assert _addr(0x1000) in img._readonlyset
        assert _addr(0x2000) not in img._readonlyset


# =========================================================================
# Padding
# =========================================================================

class TestPadding:
    def test_pad_adds_zeros(self):
        img = LoadImageXml()
        img.addChunk(_addr(0x1000), b"\x90" * 4)
        img.pad()
        # After padding, should be able to read past the original chunk
        buf = bytearray(4)
        img.loadFill(buf, 4, _addr(0x1004))
        assert buf == bytearray(4)  # zeros

    def test_pad_empty_image(self):
        img = LoadImageXml()
        img.pad()  # should not crash


# =========================================================================
# Clear
# =========================================================================

class TestClear:
    def test_clear(self):
        img = LoadImageXml(filename="test", archtype="x86")
        img.addChunk(_addr(0x1000), b"\x90")
        img.addSymbol(_addr(0x1000), "main")
        img.clear()
        assert img.getArchType() == ""
        buf = bytearray(1)
        with pytest.raises(DataUnavailError):
            img.loadFill(buf, 1, _addr(0x1000))


# =========================================================================
# fromHexChunk convenience
# =========================================================================

class TestFromHexChunk:
    def test_basic(self):
        img = LoadImageXml.fromHexChunk(_SPACE, 0x1000, "9090cc")
        assert img.getArchType() == "x86"
        buf = bytearray(3)
        img.loadFill(buf, 3, _addr(0x1000))
        assert buf == bytearray(b"\x90\x90\xcc")

    def test_with_whitespace(self):
        img = LoadImageXml.fromHexChunk(_SPACE, 0x1000, "90 90\ncc")
        buf = bytearray(3)
        img.loadFill(buf, 3, _addr(0x1000))
        assert buf == bytearray(b"\x90\x90\xcc")


# =========================================================================
# AdjustVma
# =========================================================================

class TestAdjustVma:
    def test_adjust(self):
        img = LoadImageXml()
        img.addChunk(_addr(0x1000), b"\xAA\xBB")
        img.addSymbol(_addr(0x1000), "main")
        img.adjustVma(0x100)
        # Original address should fail
        buf = bytearray(2)
        with pytest.raises(DataUnavailError):
            img.loadFill(buf, 2, _addr(0x1000))
        # New address should work
        img.loadFill(buf, 2, _addr(0x1100))
        assert buf == bytearray(b"\xAA\xBB")


if __name__ == '__main__':
    pytest.main([__file__, '-v'])
