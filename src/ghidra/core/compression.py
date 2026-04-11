"""
Compression and CRC32 utilities.
Corresponds to compression.hh/cc and crc32.hh/cc.

Python uses stdlib zlib which provides both deflate/inflate and CRC32.
"""
from __future__ import annotations

from typing import Optional
import zlib
from ghidra.core.error import LowlevelError

# =========================================================================
# CRC32 — matches crc32.hh crc_update()
# =========================================================================

# The C++ crc32tab[] is the standard CRC-32/ISO-HDLC table.
# Python's zlib.crc32 uses the same polynomial, so we delegate to it
# for full-buffer CRC. For the byte-at-a-time crc_update used internally
# by Ghidra (e.g. in hashing), we replicate the exact C++ inline:
#   crc32tab[(reg ^ val) & 0xff] ^ (reg >> 8)

# Pre-build the table identically to the C++ static array
crc32tab: list[int] = []
for _i in range(256):
    _crc = _i
    for _ in range(8):
        if _crc & 1:
            _crc = 0xEDB88320 ^ (_crc >> 1)
        else:
            _crc >>= 1
    crc32tab.append(_crc & 0xFFFFFFFF)


def crc_update(reg: int, val: int) -> int:
    """Feed 8 bits into a CRC register (matches C++ crc_update inline)."""
    return crc32tab[(reg ^ val) & 0xFF] ^ ((reg >> 8) & 0x00FFFFFF)


def crc32_bytes(data: bytes, initial: int = 0) -> int:
    """Compute CRC-32 over a byte buffer using the Ghidra-compatible table."""
    reg = initial ^ 0xFFFFFFFF
    for b in data:
        reg = crc32tab[(reg ^ b) & 0xFF] ^ ((reg >> 8) & 0x00FFFFFF)
    return reg ^ 0xFFFFFFFF


# =========================================================================
# Compress — matches compression.hh Compress class
# =========================================================================

class Compress:
    """Wrapper for the deflate algorithm (mirrors C++ Compress class)."""

    def __init__(self, level: int = -1) -> None:
        try:
            self._compobj = zlib.compressobj(level)
        except (ValueError, zlib.error) as exc:
            raise LowlevelError("Could not initialize deflate stream state") from exc
        self._pending_input = b""
        self._pending_output = bytearray()
        self._finished = False

    def __del__(self) -> None:
        self._compobj = None
        self._pending_input = b""
        pending_output = getattr(self, "_pending_output", None)
        if pending_output is not None:
            pending_output.clear()

    def input(self, buffer, sz: Optional[int] = None) -> None:
        """Provide the next sequence of bytes to compress."""
        self._pending_input = _coerce_input(buffer, sz)

    def _produce_output(self, finish: bool) -> None:
        if self._finished:
            if self._pending_input:
                raise LowlevelError("Error compressing stream")
            return
        try:
            produced = self._compobj.compress(self._pending_input)
            self._pending_input = b""
            if finish:
                produced += self._compobj.flush()
                self._finished = True
        except (ValueError, zlib.error) as exc:
            raise LowlevelError("Error compressing stream") from exc
        if produced:
            self._pending_output.extend(produced)

    def _deflate_into(self, out_view: memoryview, sz: int, finish: bool) -> int:
        self._produce_output(finish)
        written = min(sz, len(self._pending_output))
        if written:
            out_view[:written] = self._pending_output[:written]
            del self._pending_output[:written]
        return sz - written

    def deflate(self, buffer, sz: Optional[int] = None, finish: bool = False):
        """Deflate pending input into a caller-provided buffer.

        Native surface: ``deflate(buffer, sz, finish) -> avail_out``.
        Compatibility surface: ``deflate(sz, finish=False) -> (bytes, avail_out)``.
        """
        if isinstance(buffer, int) and sz is None:
            max_out = buffer
            out = bytearray(max_out)
            avail_out = self._deflate_into(memoryview(out), max_out, finish)
            return bytes(out[: max_out - avail_out]), avail_out

        if sz is None:
            raise TypeError("deflate() missing required output size")
        out_view = _coerce_output(buffer, sz)
        return self._deflate_into(out_view, sz, finish)


# =========================================================================
# Decompress — matches compression.hh Decompress class
# =========================================================================

class Decompress:
    """Wrapper for the inflate algorithm (mirrors C++ Decompress class)."""

    def __init__(self) -> None:
        try:
            self._decompobj = zlib.decompressobj()
        except zlib.error as exc:
            raise LowlevelError("Could not initialize inflate stream state") from exc
        self._pending_input = b""
        self._finished = False

    def __del__(self) -> None:
        self._decompobj = None
        self._pending_input = b""

    def input(self, buffer, sz: Optional[int] = None) -> None:
        """Provide the next sequence of compressed bytes."""
        self._pending_input = _coerce_input(buffer, sz)

    def isFinished(self) -> bool:
        return self._finished

    def _inflate_into(self, out_view: memoryview, sz: int) -> int:
        try:
            out = self._decompobj.decompress(self._pending_input, sz)
        except zlib.error as exc:
            raise LowlevelError("Error decompressing stream") from exc
        written = len(out)
        if written:
            out_view[:written] = out
        tail = self._decompobj.unconsumed_tail
        if tail:
            self._pending_input = tail
        else:
            self._pending_input = self._decompobj.unused_data
        if self._decompobj.eof:
            self._finished = True
        return sz - written

    def inflate(self, buffer, sz: Optional[int] = None):
        """Inflate pending input into a caller-provided buffer.

        Native surface: ``inflate(buffer, sz) -> avail_out``.
        Compatibility surface: ``inflate(sz) -> (bytes, avail_out)``.
        """
        if isinstance(buffer, int) and sz is None:
            max_out = buffer
            out = bytearray(max_out)
            avail_out = self._inflate_into(memoryview(out), max_out)
            return bytes(out[: max_out - avail_out]), avail_out

        if sz is None:
            raise TypeError("inflate() missing required output size")
        out_view = _coerce_output(buffer, sz)
        return self._inflate_into(out_view, sz)


class CompressBuffer:
    """Buffered stream filter that compresses bytes to a backing stream."""

    IN_BUFFER_SIZE = 4096
    OUT_BUFFER_SIZE = 4096

    def __init__(self, s, level: int) -> None:
        self.outStream = s
        self.inBuffer = bytearray(self.IN_BUFFER_SIZE)
        self.outBuffer = bytearray(self.OUT_BUFFER_SIZE)
        self.compressor = Compress(level)
        self._in_count = 0

    def __del__(self) -> None:
        self.inBuffer = bytearray()
        self.outBuffer = bytearray()

    def flushInput(self, lastBuffer: bool) -> None:
        length = self._in_count
        self.compressor.input(self.inBuffer, length)
        while True:
            out_avail = self.compressor.deflate(self.outBuffer, self.OUT_BUFFER_SIZE, lastBuffer)
            self.outStream.write(self.outBuffer[: self.OUT_BUFFER_SIZE - out_avail])
            if out_avail != 0:
                break
        self._in_count = 0

    def overflow(self, c: int) -> int:
        if c != -1:
            if self._in_count >= self.IN_BUFFER_SIZE:
                self.flushInput(False)
            self.inBuffer[self._in_count] = c & 0xFF
            self._in_count += 1
        self.flushInput(False)
        return c

    def sync(self) -> int:
        self.flushInput(True)
        return 0

    def write(self, data: bytes) -> int:
        view = memoryview(data).cast("B")
        offset = 0
        total = len(view)
        while offset < total:
            if self._in_count == self.IN_BUFFER_SIZE:
                self.flushInput(False)
            chunk = min(self.IN_BUFFER_SIZE - self._in_count, total - offset)
            self.inBuffer[self._in_count : self._in_count + chunk] = view[offset : offset + chunk]
            self._in_count += chunk
            offset += chunk
        return total

    def flush(self) -> None:
        self.sync()


# =========================================================================
# Convenience: compress / decompress entire buffers
# =========================================================================

def compress(data: bytes, level: int = -1) -> bytes:
    """Compress data using deflate (convenience wrapper)."""
    return zlib.compress(data, level)


def decompress(data: bytes) -> bytes:
    """Decompress deflate-compressed data (convenience wrapper)."""
    return zlib.decompress(data)


def _coerce_input(buffer, sz: Optional[int]) -> bytes:
    if isinstance(buffer, memoryview):
        data = buffer.cast("B")
        return data[:sz].tobytes() if sz is not None else data.tobytes()
    raw = bytes(buffer)
    return raw[:sz] if sz is not None else raw


def _coerce_output(buffer, sz: int) -> memoryview:
    view = memoryview(buffer)
    if view.readonly:
        raise TypeError("output buffer must be writable")
    if view.format != "B":
        view = view.cast("B")
    if len(view) < sz:
        raise ValueError("output buffer too small")
    return view[:sz]
