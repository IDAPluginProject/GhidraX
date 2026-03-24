"""
Corresponds to: ghidra_arch.cc (protocol methods) + ghidra_process.cc (framing)

Binary protocol for communication between the Ghidra client (Java GUI) and the
decompiler process.  All data is framed by "alignment bursts":

    [0x00...] 0x01 <code>

where <code> identifies the message type:

    Code  Open/Close  Meaning
    ----  ----------  -------
     2       open     Command
     3       close    Command
     4       open     Query
     5       close    Query
     6       open     Command response
     7       close    Command response
     8       open     Query response
     9       close    Query response
     0xa     open     Exception
     0xb     close    Exception
     0xc     open     Byte stream
     0xd     close    Byte stream
     0xe     open     String stream
     0xf     close    String stream

Protocol flow:
  1. Ghidra sends a command
  2. [Decompiler may send query → Ghidra sends query response] (0+ times)
  3. Decompiler sends command response
"""

from __future__ import annotations

import sys
from typing import BinaryIO, Optional

from ghidra.core.error import LowlevelError


# ---------------------------------------------------------------------------
# Burst type constants
# ---------------------------------------------------------------------------

BURST_COMMAND_OPEN = 2
BURST_COMMAND_CLOSE = 3
BURST_QUERY_OPEN = 4
BURST_QUERY_CLOSE = 5
BURST_CMD_RESP_OPEN = 6
BURST_CMD_RESP_CLOSE = 7
BURST_QUERY_RESP_OPEN = 8
BURST_QUERY_RESP_CLOSE = 9
BURST_EXCEPTION_OPEN = 0xA
BURST_EXCEPTION_CLOSE = 0xB
BURST_BYTE_OPEN = 0xC
BURST_BYTE_CLOSE = 0xD
BURST_STRING_OPEN = 0xE
BURST_STRING_CLOSE = 0xF
BURST_WARNING_OPEN = 0x10
BURST_WARNING_CLOSE = 0x11


# ---------------------------------------------------------------------------
# JavaError — mirrors the C++ JavaError struct
# ---------------------------------------------------------------------------

class JavaError(LowlevelError):
    """Exception mirroring a Ghidra Java-side exception."""

    def __init__(self, tp: str, message: str) -> None:
        super().__init__(message)
        self.type: str = tp


# ---------------------------------------------------------------------------
# Low-level framing helpers
# ---------------------------------------------------------------------------

def read_to_any_burst(sin: BinaryIO) -> int:
    """Read past zero-padding until an alignment burst is found.

    A burst is one or more 0x00 bytes followed by 0x01, then a code byte.
    Returns the code byte (2–15).  Exits the process if the pipe is closed.

    C++ ref: ``ArchitectureGhidra::readToAnyBurst``
    """
    while True:
        # Skip non-zero bytes (shouldn't normally happen in well-formed streams)
        c = _read_byte(sin)
        while c > 0:
            c = _read_byte(sin)
        # Now c <= 0.  Consume all zeros.
        while c == 0:
            c = _read_byte(sin)
        if c == 1:
            code = _read_byte(sin)
            return code
        if c < 0:
            sys.exit(1)


def read_string_stream(sin: BinaryIO) -> str:
    """Read a string delimited by string-open (0x0E) and string-close (0x0F) bursts.

    C++ ref: ``ArchitectureGhidra::readStringStream(istream&, string&)``
    """
    burst = read_to_any_burst(sin)
    if burst != BURST_STRING_OPEN:
        raise JavaError("alignment", "Expecting string")
    parts: list[bytes] = []
    c = _read_byte(sin)
    while c > 0:
        parts.append(bytes([c]))
        c = _read_byte(sin)
    # Consume trailing zeros
    while c == 0:
        c = _read_byte(sin)
    if c == 1:
        code = _read_byte(sin)
        if code == BURST_STRING_CLOSE:
            return b"".join(parts).decode("utf-8", errors="replace")
    if c < 0:
        sys.exit(1)
    raise JavaError("alignment", "Expecting string terminator")


def read_string_stream_raw(sin: BinaryIO) -> bytes:
    """Read raw bytes from a string stream (no UTF-8 decode)."""
    burst = read_to_any_burst(sin)
    if burst != BURST_STRING_OPEN:
        raise JavaError("alignment", "Expecting string")
    parts: list[bytes] = []
    c = _read_byte(sin)
    while c > 0:
        parts.append(bytes([c]))
        c = _read_byte(sin)
    while c == 0:
        c = _read_byte(sin)
    if c == 1:
        code = _read_byte(sin)
        if code == BURST_STRING_CLOSE:
            return b"".join(parts)
    if c < 0:
        sys.exit(1)
    raise JavaError("alignment", "Expecting string terminator")


def read_bool_stream(sin: BinaryIO) -> bool:
    """Read a boolean ('t' or 'f') from a string stream.

    C++ ref: ``ArchitectureGhidra::readBoolStream``
    """
    burst = read_to_any_burst(sin)
    if burst != BURST_STRING_OPEN:
        raise JavaError("alignment", "Expecting string")
    c = _read_byte(sin)
    result = (c == ord('t'))
    c = _read_byte(sin)
    while c == 0:
        c = _read_byte(sin)
    if c == 1:
        code = _read_byte(sin)
        if code == BURST_STRING_CLOSE:
            return result
    if c < 0:
        sys.exit(1)
    raise JavaError("alignment", "Expecting string terminator")


def write_string_stream(sout: BinaryIO, msg: str) -> None:
    """Write a string wrapped in string-open / string-close bursts.

    C++ ref: ``ArchitectureGhidra::writeStringStream``
    """
    sout.write(b"\x00\x00\x01\x0e")
    sout.write(msg.encode("utf-8"))
    sout.write(b"\x00\x00\x01\x0f")


def write_string_stream_bytes(sout: BinaryIO, data: bytes) -> None:
    """Write raw bytes wrapped in string-open / string-close bursts."""
    sout.write(b"\x00\x00\x01\x0e")
    sout.write(data)
    sout.write(b"\x00\x00\x01\x0f")


def read_to_response(sin: BinaryIO) -> None:
    """Consume the query-response-open burst.  Handle exception bursts.

    C++ ref: ``ArchitectureGhidra::readToResponse``
    """
    burst = read_to_any_burst(sin)
    if burst == BURST_QUERY_RESP_OPEN:
        return
    if burst == BURST_EXCEPTION_OPEN:
        excepttype = read_string_stream(sin)
        message = read_string_stream(sin)
        _burst = read_to_any_burst(sin)  # exception terminator
        raise JavaError(excepttype, message)
    raise JavaError("alignment", "Expecting query response")


def read_response_end(sin: BinaryIO) -> None:
    """Consume the query-response-close burst.

    C++ ref: ``ArchitectureGhidra::readResponseEnd``
    """
    burst = read_to_any_burst(sin)
    if burst != BURST_QUERY_RESP_CLOSE:
        raise JavaError("alignment", "Expecting end of query response")


def read_all_response(sin: BinaryIO) -> Optional[bytes]:
    """Read a full query response as raw bytes.

    Returns the raw string content if a string stream was present, else None.

    C++ ref: ``ArchitectureGhidra::readAll``
    """
    read_to_response(sin)
    burst = read_to_any_burst(sin)
    if burst == BURST_STRING_OPEN:
        parts: list[bytes] = []
        c = _read_byte(sin)
        while c > 0:
            parts.append(bytes([c]))
            c = _read_byte(sin)
        while c == 0:
            c = _read_byte(sin)
        if c == 1:
            code = _read_byte(sin)
            if code != BURST_STRING_CLOSE:
                raise JavaError("alignment", "Expecting XML string end")
        elif c < 0:
            sys.exit(1)
        read_response_end(sin)
        return b"".join(parts)
    if (burst & 1) == 1:
        # Odd burst = close, meaning empty response
        return None
    raise JavaError("alignment", "Expecting string or end of query response")


def pass_java_exception(sout: BinaryIO, tp: str, msg: str) -> None:
    """Send an exception message to the Ghidra client.

    C++ ref: ``ArchitectureGhidra::passJavaException``
    """
    sout.write(b"\x00\x00\x01\x0a")
    write_string_stream(sout, tp)
    write_string_stream(sout, msg)
    sout.write(b"\x00\x00\x01\x0b")


# ---------------------------------------------------------------------------
# Query helpers (decompiler → Ghidra)
# ---------------------------------------------------------------------------

def send_query_open(sout: BinaryIO) -> None:
    """Write the query-open burst."""
    sout.write(b"\x00\x00\x01\x04")


def send_query_close(sout: BinaryIO) -> None:
    """Write the query-close burst."""
    sout.write(b"\x00\x00\x01\x05")


def send_cmd_response_open(sout: BinaryIO) -> None:
    """Write the command-response-open burst."""
    sout.write(b"\x00\x00\x01\x06")


def send_cmd_response_close(sout: BinaryIO) -> None:
    """Write the command-response-close burst."""
    sout.write(b"\x00\x00\x01\x07")


def send_int_open(sout: BinaryIO) -> None:
    """Write the integer/id-open burst (0x0e)."""
    sout.write(b"\x00\x00\x01\x0e")


def send_int_close(sout: BinaryIO) -> None:
    """Write the integer/id-close burst (0x0f)."""
    sout.write(b"\x00\x00\x01\x0f")


def send_warning_open(sout: BinaryIO) -> None:
    """Write the warning-open burst (0x10)."""
    sout.write(b"\x00\x00\x01\x10")


def send_warning_close(sout: BinaryIO) -> None:
    """Write the warning-close burst (0x11)."""
    sout.write(b"\x00\x00\x01\x11")


def read_bytes_response(sin: BinaryIO, size: int) -> Optional[bytes]:
    """Read a bytes response from a query (hex-encoded A+nibble pairs).

    C++ ref: ``ArchitectureGhidra::getBytes``
    """
    read_to_response(sin)
    burst = read_to_any_burst(sin)
    if burst == BURST_BYTE_OPEN:
        dblbuf = sin.read(size * 2)
        result = bytearray(size)
        for i in range(size):
            hi = dblbuf[i * 2] - ord('A')
            lo = dblbuf[i * 2 + 1] - ord('A')
            result[i] = (hi << 4) | lo
        end_burst = read_to_any_burst(sin)
        if end_burst != BURST_BYTE_CLOSE:
            raise JavaError("alignment", "Expecting byte alignment end")
        read_response_end(sin)
        return bytes(result)
    if (burst & 1) == 1:
        return None  # No data available
    raise JavaError("alignment", "Expecting bytes or end of query response")


# ---------------------------------------------------------------------------
# Internal helpers
# ---------------------------------------------------------------------------

def _read_byte(sin: BinaryIO) -> int:
    """Read a single byte. Returns -1 on EOF."""
    b = sin.read(1)
    if not b:
        return -1
    return b[0]
