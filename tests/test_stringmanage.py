"""Tests for ghidra.database.stringmanage -- StringData, StringManager, StringManagerUnicode."""
from __future__ import annotations

from ghidra.database.stringmanage import StringData, StringManager, StringManagerUnicode
from ghidra.core.address import Address
from ghidra.core.space import AddrSpace


def _spc():
    return AddrSpace(name="ram", size=4)


def _addr(off):
    return Address(_spc(), off)


# ---------------------------------------------------------------------------
# StringData
# ---------------------------------------------------------------------------

class TestStringData:
    def test_defaults(self):
        sd = StringData()
        assert sd.isTruncated is False
        assert sd.byteData == b""

    def test_set_fields(self):
        sd = StringData()
        sd.isTruncated = True
        sd.byteData = b"hello"
        assert sd.isTruncated is True
        assert sd.byteData == b"hello"


# ---------------------------------------------------------------------------
# StringManager static helpers
# ---------------------------------------------------------------------------

class TestStringManagerHelpers:
    def test_has_char_terminator_1byte(self):
        assert StringManager.hasCharTerminator(b"abc\x00", 4, 1) is True
        assert StringManager.hasCharTerminator(b"abcd", 4, 1) is False

    def test_has_char_terminator_2byte(self):
        buf = b"a\x00\x00\x00"
        assert StringManager.hasCharTerminator(buf, 4, 2) is True
        buf2 = b"a\x01b\x01"
        assert StringManager.hasCharTerminator(buf2, 4, 2) is False

    def test_write_utf8_ascii(self):
        result = StringManager.writeUtf8(0x41)
        assert result == b"A"

    def test_write_utf8_multibyte(self):
        result = StringManager.writeUtf8(0x4E2D)  # 中
        assert result == "中".encode("utf-8")

    def test_get_codepoint_1byte(self):
        cp, consumed = StringManager.getCodepoint(b"\x41", 1, False)
        assert cp == 0x41
        assert consumed == 1

    def test_get_codepoint_2byte_le(self):
        cp, consumed = StringManager.getCodepoint(b"\x41\x00", 2, False)
        assert cp == 0x41
        assert consumed == 2

    def test_get_codepoint_2byte_be(self):
        cp, consumed = StringManager.getCodepoint(b"\x00\x41", 2, True)
        assert cp == 0x41
        assert consumed == 2

    def test_get_codepoint_4byte_le(self):
        cp, consumed = StringManager.getCodepoint(b"\x41\x00\x00\x00", 4, False)
        assert cp == 0x41
        assert consumed == 4

    def test_get_codepoint_4byte_be(self):
        cp, consumed = StringManager.getCodepoint(b"\x00\x00\x00\x41", 4, True)
        assert cp == 0x41
        assert consumed == 4

    def test_max_chars(self):
        sm = StringManagerUnicode(glb=None, max_chars=100)
        assert sm.getMaxChars() == 100
        sm.setMaxChars(500)
        assert sm.getMaxChars() == 500


# ---------------------------------------------------------------------------
# StringManagerUnicode (no glb)
# ---------------------------------------------------------------------------

class TestStringManagerUnicode:
    def test_no_glb_returns_empty(self):
        sm = StringManagerUnicode(glb=None)
        data, trunc = sm.getStringData(_addr(0x1000), type("FakeType", (), {"getSize": lambda self: 1})())
        assert data == b""
        assert trunc is False

    def test_is_utf8(self):
        sm = StringManagerUnicode(glb=None)
        assert sm.isUTF8() is True

    def test_get_glb(self):
        sm = StringManagerUnicode(glb=None)
        assert sm.getGlb() is None

    def test_read_string_no_glb(self):
        sm = StringManagerUnicode(glb=None)
        assert sm.readString(_addr(0x1000), type("FakeType", (), {"getSize": lambda self: 1})()) is None

    def test_clear(self):
        sm = StringManagerUnicode(glb=None)
        sm.clear()  # Should not raise
