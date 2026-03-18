"""
Compression and CRC32 utilities.
Corresponds to compression.hh/cc and crc32.hh/cc.

Python uses stdlib zlib which provides both deflate/inflate and CRC32.
"""
from __future__ import annotations

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
        if level < -1 or level > 9:
            raise LowlevelError("Invalid compression level")
        self._level: int = level
        self._compobj = zlib.compressobj(level)
        self._pending: bytes = b""

    def input(self, data: bytes) -> None:
        """Provide the next sequence of bytes to compress."""
        self._pending = data

    def deflate(self, max_out: int, finish: bool = False) -> tuple[bytes, int]:
        """Deflate pending input.

        Returns (compressed_bytes, avail_out) where avail_out is
        how many output bytes were NOT used (mirrors C++ return).
        """
        if finish:
            out = self._compobj.compress(self._pending)
            out += self._compobj.flush()
        else:
            out = self._compobj.compress(self._pending)
        self._pending = b""
        if len(out) > max_out:
            out = out[:max_out]
        return out, max_out - len(out)


# =========================================================================
# Decompress — matches compression.hh Decompress class
# =========================================================================

class Decompress:
    """Wrapper for the inflate algorithm (mirrors C++ Decompress class)."""

    def __init__(self) -> None:
        self._decompobj = zlib.decompressobj()
        self._pending: bytes = b""
        self._finished: bool = False

    def input(self, data: bytes) -> None:
        """Provide the next sequence of compressed bytes."""
        self._pending = data

    def isFinished(self) -> bool:
        return self._finished

    def inflate(self, max_out: int) -> tuple[bytes, int]:
        """Inflate pending input.

        Returns (decompressed_bytes, avail_out).
        """
        try:
            out = self._decompobj.decompress(self._pending, max_out)
        except zlib.error as e:
            raise LowlevelError(f"Error decompressing stream: {e}") from e
        self._pending = b""
        if self._decompobj.eof:
            self._finished = True
        return out, max_out - len(out)


# =========================================================================
# Convenience: compress / decompress entire buffers
# =========================================================================

def compress(data: bytes, level: int = -1) -> bytes:
    """Compress data using deflate (convenience wrapper)."""
    return zlib.compress(data, level)


def decompress(data: bytes) -> bytes:
    """Decompress deflate-compressed data (convenience wrapper)."""
    return zlib.decompress(data)
