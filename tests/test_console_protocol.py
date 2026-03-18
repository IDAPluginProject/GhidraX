"""Tests for the Ghidra binary protocol layer and command dispatch."""

from __future__ import annotations

import io
import pytest

from ghidra.console.protocol import (
    JavaError,
    read_to_any_burst, read_string_stream, read_bool_stream,
    write_string_stream, read_all_response,
    send_query_open, send_query_close,
    send_cmd_response_open, send_cmd_response_close,
    send_int_open, send_int_close,
    send_warning_open, send_warning_close,
    pass_java_exception, read_bytes_response,
    BURST_COMMAND_OPEN, BURST_COMMAND_CLOSE,
    BURST_QUERY_OPEN, BURST_QUERY_CLOSE,
    BURST_CMD_RESP_OPEN, BURST_CMD_RESP_CLOSE,
    BURST_QUERY_RESP_OPEN, BURST_QUERY_RESP_CLOSE,
    BURST_EXCEPTION_OPEN, BURST_EXCEPTION_CLOSE,
    BURST_BYTE_OPEN, BURST_BYTE_CLOSE,
    BURST_STRING_OPEN, BURST_STRING_CLOSE,
    BURST_WARNING_OPEN, BURST_WARNING_CLOSE,
)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _burst(code: int) -> bytes:
    """Build a 4-byte alignment burst with the given code."""
    return b"\x00\x00\x01" + bytes([code])


def _string_frame(s: str) -> bytes:
    """Wrap a string in string-open / string-close bursts."""
    return _burst(BURST_STRING_OPEN) + s.encode("utf-8") + _burst(BURST_STRING_CLOSE)


# =========================================================================
# Test burst reading
# =========================================================================

class TestReadToAnyBurst:
    def test_simple_burst(self):
        data = _burst(BURST_COMMAND_OPEN)
        sin = io.BytesIO(data)
        assert read_to_any_burst(sin) == BURST_COMMAND_OPEN

    def test_burst_with_leading_zeros(self):
        data = b"\x00\x00\x00\x00\x00\x01" + bytes([BURST_QUERY_OPEN])
        sin = io.BytesIO(data)
        assert read_to_any_burst(sin) == BURST_QUERY_OPEN

    def test_multiple_bursts(self):
        data = _burst(BURST_CMD_RESP_OPEN) + _burst(BURST_CMD_RESP_CLOSE)
        sin = io.BytesIO(data)
        assert read_to_any_burst(sin) == BURST_CMD_RESP_OPEN
        assert read_to_any_burst(sin) == BURST_CMD_RESP_CLOSE


# =========================================================================
# Test string stream read/write
# =========================================================================

class TestStringStream:
    def test_read_string(self):
        data = _string_frame("hello")
        sin = io.BytesIO(data)
        assert read_string_stream(sin) == "hello"

    def test_read_empty_string(self):
        data = _string_frame("")
        sin = io.BytesIO(data)
        assert read_string_stream(sin) == ""

    def test_read_unicode_string(self):
        data = _string_frame("日本語テスト")
        sin = io.BytesIO(data)
        assert read_string_stream(sin) == "日本語テスト"

    def test_write_string(self):
        sout = io.BytesIO()
        write_string_stream(sout, "test")
        result = sout.getvalue()
        assert result == b"\x00\x00\x01\x0etest\x00\x00\x01\x0f"

    def test_roundtrip(self):
        sout = io.BytesIO()
        write_string_stream(sout, "roundtrip")
        sin = io.BytesIO(sout.getvalue())
        assert read_string_stream(sin) == "roundtrip"


# =========================================================================
# Test bool stream
# =========================================================================

class TestBoolStream:
    def test_read_true(self):
        data = _burst(BURST_STRING_OPEN) + b"t" + _burst(BURST_STRING_CLOSE)
        sin = io.BytesIO(data)
        assert read_bool_stream(sin) is True

    def test_read_false(self):
        data = _burst(BURST_STRING_OPEN) + b"f" + _burst(BURST_STRING_CLOSE)
        sin = io.BytesIO(data)
        assert read_bool_stream(sin) is False


# =========================================================================
# Test query response reading
# =========================================================================

class TestReadAllResponse:
    def test_empty_response(self):
        data = (_burst(BURST_QUERY_RESP_OPEN) +
                _burst(BURST_QUERY_RESP_CLOSE))
        sin = io.BytesIO(data)
        assert read_all_response(sin) is None

    def test_string_response(self):
        data = (_burst(BURST_QUERY_RESP_OPEN) +
                _string_frame("<addr space=\"ram\" offset=\"0x401000\"/>") +
                _burst(BURST_QUERY_RESP_CLOSE))
        sin = io.BytesIO(data)
        result = read_all_response(sin)
        assert result is not None
        assert b"ram" in result
        assert b"0x401000" in result

    def test_exception_response(self):
        data = (_burst(BURST_EXCEPTION_OPEN) +
                _string_frame("java.lang.Exception") +
                _string_frame("Something failed") +
                _burst(BURST_EXCEPTION_CLOSE))
        sin = io.BytesIO(data)
        with pytest.raises(JavaError) as exc_info:
            read_all_response(sin)
        assert "Something failed" in str(exc_info.value)


# =========================================================================
# Test bytes response
# =========================================================================

class TestBytesResponse:
    def test_read_bytes(self):
        # Encode 3 bytes: 0xDE, 0xAD, 0xBE using A+nibble pairs
        encoded = b""
        for byte_val in [0xDE, 0xAD, 0xBE]:
            hi = byte_val >> 4
            lo = byte_val & 0xF
            encoded += bytes([ord('A') + hi, ord('A') + lo])

        data = (_burst(BURST_QUERY_RESP_OPEN) +
                _burst(BURST_BYTE_OPEN) +
                encoded +
                _burst(BURST_BYTE_CLOSE) +
                _burst(BURST_QUERY_RESP_CLOSE))
        sin = io.BytesIO(data)
        result = read_bytes_response(sin, 3)
        assert result == bytes([0xDE, 0xAD, 0xBE])

    def test_no_bytes_available(self):
        data = (_burst(BURST_QUERY_RESP_OPEN) +
                _burst(BURST_QUERY_RESP_CLOSE))
        sin = io.BytesIO(data)
        result = read_bytes_response(sin, 4)
        assert result is None


# =========================================================================
# Test exception passing
# =========================================================================

class TestPassJavaException:
    def test_exception_encoding(self):
        sout = io.BytesIO()
        pass_java_exception(sout, "decompiler", "test error")
        result = sout.getvalue()
        assert b"\x00\x00\x01\x0a" in result  # exception open
        assert b"decompiler" in result
        assert b"test error" in result
        assert b"\x00\x00\x01\x0b" in result  # exception close


# =========================================================================
# Test burst write helpers
# =========================================================================

class TestBurstWrites:
    def test_query_open(self):
        sout = io.BytesIO()
        send_query_open(sout)
        assert sout.getvalue() == _burst(BURST_QUERY_OPEN)

    def test_query_close(self):
        sout = io.BytesIO()
        send_query_close(sout)
        assert sout.getvalue() == _burst(BURST_QUERY_CLOSE)

    def test_cmd_response_open(self):
        sout = io.BytesIO()
        send_cmd_response_open(sout)
        assert sout.getvalue() == _burst(BURST_CMD_RESP_OPEN)

    def test_cmd_response_close(self):
        sout = io.BytesIO()
        send_cmd_response_close(sout)
        assert sout.getvalue() == _burst(BURST_CMD_RESP_CLOSE)

    def test_int_open_close(self):
        sout = io.BytesIO()
        send_int_open(sout)
        sout.write(b"42")
        send_int_close(sout)
        assert sout.getvalue() == _burst(BURST_STRING_OPEN) + b"42" + _burst(BURST_STRING_CLOSE)

    def test_warning_open_close(self):
        sout = io.BytesIO()
        send_warning_open(sout)
        sout.write(b"some warning")
        send_warning_close(sout)
        assert sout.getvalue() == _burst(BURST_WARNING_OPEN) + b"some warning" + _burst(BURST_WARNING_CLOSE)


# =========================================================================
# Test JavaError
# =========================================================================

class TestJavaError:
    def test_java_error_attributes(self):
        err = JavaError("decompiler", "Some error occurred")
        assert err.type == "decompiler"
        assert str(err) == "Some error occurred"
        assert isinstance(err, Exception)


# =========================================================================
# Test ArchitectureGhidra static methods
# =========================================================================

class TestArchitectureGhidraStatic:
    def test_is_dynamic_symbol_name_true(self):
        from ghidra.console.ghidra_arch import ArchitectureGhidra
        assert ArchitectureGhidra.isDynamicSymbolName("FUN_00401000") is True
        assert ArchitectureGhidra.isDynamicSymbolName("DAT_00402000") is True

    def test_is_dynamic_symbol_name_false(self):
        from ghidra.console.ghidra_arch import ArchitectureGhidra
        assert ArchitectureGhidra.isDynamicSymbolName("main") is False
        assert ArchitectureGhidra.isDynamicSymbolName("short") is False
        assert ArchitectureGhidra.isDynamicSymbolName("ABC_0000") is False
        assert ArchitectureGhidra.isDynamicSymbolName("FUN_") is False


# =========================================================================
# Test command map build
# =========================================================================

class TestCommandMap:
    def test_build_command_map(self):
        from ghidra.console.ghidra_process import build_command_map
        sin = io.BytesIO()
        sout = io.BytesIO()
        cmap = build_command_map(sin, sout)
        assert "registerProgram" in cmap
        assert "deregisterProgram" in cmap
        assert "flushNative" in cmap
        assert "decompileAt" in cmap
        assert "structureGraph" in cmap
        assert "setAction" in cmap
        assert "setOptions" in cmap
        assert len(cmap) == 7


# =========================================================================
# Test protocol constants
# =========================================================================

class TestProtocolConstants:
    def test_burst_codes(self):
        assert BURST_COMMAND_OPEN == 2
        assert BURST_COMMAND_CLOSE == 3
        assert BURST_QUERY_OPEN == 4
        assert BURST_QUERY_CLOSE == 5
        assert BURST_CMD_RESP_OPEN == 6
        assert BURST_CMD_RESP_CLOSE == 7
        assert BURST_QUERY_RESP_OPEN == 8
        assert BURST_QUERY_RESP_CLOSE == 9
        assert BURST_EXCEPTION_OPEN == 0xA
        assert BURST_EXCEPTION_CLOSE == 0xB
        assert BURST_BYTE_OPEN == 0xC
        assert BURST_BYTE_CLOSE == 0xD
        assert BURST_STRING_OPEN == 0xE
        assert BURST_STRING_CLOSE == 0xF
        assert BURST_WARNING_OPEN == 0x10
        assert BURST_WARNING_CLOSE == 0x11


# =========================================================================
# Test XML escape helper
# =========================================================================

class TestXmlEscape:
    def test_xml_escape(self):
        from ghidra.console.ghidra_arch import _xml_escape
        assert _xml_escape("hello") == "hello"
        assert _xml_escape("<test>") == "&lt;test&gt;"
        assert _xml_escape('key="val"') == 'key=&quot;val&quot;'
        assert _xml_escape("a&b") == "a&amp;b"

    def test_encode_addr(self):
        from ghidra.console.ghidra_arch import _encode_addr
        from ghidra.core.address import Address
        addr = Address(None, 0x401000)
        xml = _encode_addr(addr)
        assert "0x401000" in xml


# =========================================================================
# Test console entry module importability
# =========================================================================

class TestConsoleMainImport:
    def test_import(self):
        from ghidra.console import consolemain
        assert hasattr(consolemain, 'main')
        assert callable(consolemain.main)
