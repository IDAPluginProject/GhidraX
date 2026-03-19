"""Tests for ghidra.core.crc32 — CRC32 table and update function."""
from __future__ import annotations

from ghidra.core.crc32 import crc32tab, crc_update


class TestCrc32Tab:
    def test_table_length(self):
        assert len(crc32tab) == 256

    def test_first_entry_zero(self):
        assert crc32tab[0] == 0

    def test_known_entry_1(self):
        assert crc32tab[1] == 0x77073096

    def test_known_entry_255(self):
        assert crc32tab[255] == 0x2d02ef8d

    def test_all_entries_are_int(self):
        for v in crc32tab:
            assert isinstance(v, int)

    def test_all_entries_fit_32bit(self):
        for v in crc32tab:
            assert 0 <= v <= 0xFFFFFFFF


class TestCrcUpdate:
    def test_zero_reg_zero_val(self):
        result = crc_update(0, 0)
        assert result == 0

    def test_zero_reg_val_1(self):
        result = crc_update(0, 1)
        assert result == crc32tab[1]

    def test_deterministic(self):
        a = crc_update(0xDEADBEEF, 0x42)
        b = crc_update(0xDEADBEEF, 0x42)
        assert a == b

    def test_different_val_different_result(self):
        a = crc_update(0, 0x10)
        b = crc_update(0, 0x20)
        assert a != b

    def test_chain_bytes(self):
        reg = 0
        for byte in b"hello":
            reg = crc_update(reg, byte)
        assert isinstance(reg, int)
        assert reg != 0

    def test_result_fits_32bit(self):
        reg = crc_update(0xFFFFFFFF, 0xFF)
        assert 0 <= reg <= 0xFFFFFFFF
