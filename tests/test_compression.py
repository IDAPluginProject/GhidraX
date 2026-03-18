"""Tests for ghidra.core.compression — Python port of compression.cc and crc32.cc."""
from __future__ import annotations

import sys, os, zlib
import pytest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', 'python'))

from ghidra.core.compression import (
    crc32tab, crc_update, crc32_bytes,
    Compress, Decompress,
    compress, decompress,
)
from ghidra.core.error import LowlevelError


# =========================================================================
# CRC32 table
# =========================================================================

class TestCRC32Table:
    def test_table_length(self):
        assert len(crc32tab) == 256

    def test_first_entry(self):
        assert crc32tab[0] == 0

    def test_known_entries(self):
        assert crc32tab[1] == 0x77073096
        assert crc32tab[2] == 0xEE0E612C

    def test_all_entries_32bit(self):
        for v in crc32tab:
            assert 0 <= v <= 0xFFFFFFFF


# =========================================================================
# crc_update
# =========================================================================

class TestCRCUpdate:
    def test_zero_input(self):
        result = crc_update(0, 0)
        assert result == crc32tab[0]

    def test_single_byte(self):
        result = crc_update(0xFFFFFFFF, 0x41)  # 'A'
        expected = crc32tab[(0xFFFFFFFF ^ 0x41) & 0xFF] ^ (0xFFFFFFFF >> 8)
        assert result == (expected & 0xFFFFFFFF)

    def test_chained(self):
        reg = 0xFFFFFFFF
        for b in b"Hello":
            reg = crc_update(reg, b)
        assert isinstance(reg, int)
        assert 0 <= reg <= 0xFFFFFFFF


# =========================================================================
# crc32_bytes
# =========================================================================

class TestCRC32Bytes:
    def test_empty(self):
        result = crc32_bytes(b"")
        assert result == 0  # CRC of empty = 0 with init=0

    def test_matches_zlib(self):
        data = b"Hello, World!"
        our_crc = crc32_bytes(data) & 0xFFFFFFFF
        zlib_crc = zlib.crc32(data) & 0xFFFFFFFF
        assert our_crc == zlib_crc

    def test_known_value(self):
        data = b"123456789"
        crc = crc32_bytes(data) & 0xFFFFFFFF
        assert crc == 0xCBF43926  # Standard CRC-32 test vector

    def test_large_data(self):
        data = b"\x00" * 10000
        our_crc = crc32_bytes(data) & 0xFFFFFFFF
        zlib_crc = zlib.crc32(data) & 0xFFFFFFFF
        assert our_crc == zlib_crc


# =========================================================================
# Compress
# =========================================================================

class TestCompress:
    def test_basic_compress(self):
        c = Compress(level=6)
        data = b"AAAAAAAAAA" * 100
        c.input(data)
        out, avail = c.deflate(4096, finish=True)
        assert len(out) > 0
        assert len(out) < len(data)  # Should compress well

    def test_default_level(self):
        c = Compress()  # level=-1 (default)
        c.input(b"test data")
        out, _ = c.deflate(4096, finish=True)
        assert len(out) > 0

    def test_invalid_level(self):
        with pytest.raises(LowlevelError):
            Compress(level=10)

    def test_no_compression(self):
        c = Compress(level=0)
        c.input(b"small")
        out, _ = c.deflate(4096, finish=True)
        assert len(out) > 0


# =========================================================================
# Decompress
# =========================================================================

class TestDecompress:
    def test_basic_decompress(self):
        original = b"Hello World! " * 50
        compressed = zlib.compress(original)
        d = Decompress()
        d.input(compressed)
        out, _ = d.inflate(len(original) + 100)
        assert out == original
        assert d.isFinished()

    def test_initially_not_finished(self):
        d = Decompress()
        assert not d.isFinished()

    def test_bad_data(self):
        d = Decompress()
        d.input(b"\x00\x01\x02\x03")
        with pytest.raises(LowlevelError):
            d.inflate(4096)


# =========================================================================
# Roundtrip
# =========================================================================

class TestRoundtrip:
    def test_compress_decompress(self):
        original = b"The quick brown fox jumps over the lazy dog" * 10
        compressed = compress(original)
        restored = decompress(compressed)
        assert restored == original

    def test_empty_roundtrip(self):
        compressed = compress(b"")
        restored = decompress(compressed)
        assert restored == b""

    def test_binary_roundtrip(self):
        original = bytes(range(256)) * 4
        compressed = compress(original, level=9)
        restored = decompress(compressed)
        assert restored == original

    def test_class_roundtrip(self):
        original = b"ABCDEFGH" * 100
        c = Compress(level=6)
        c.input(original)
        compressed, _ = c.deflate(8192, finish=True)

        d = Decompress()
        d.input(compressed)
        restored, _ = d.inflate(len(original) + 100)
        assert restored == original


if __name__ == '__main__':
    pytest.main([__file__, '-v'])
