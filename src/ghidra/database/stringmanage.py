"""
Corresponds to: stringmanage.hh / stringmanage.cc

Classes for decoding and storing string data.
"""

from __future__ import annotations

from abc import abstractmethod
from io import BytesIO
from typing import Dict, List, Optional

from ghidra.core.address import Address, mostsigbit_set
from ghidra.core.crc32 import crc_update
from ghidra.core.error import LowlevelError
from ghidra.types.datatype import Datatype, TYPE_INT


class StringData:
    """String data (a sequence of bytes) stored by StringManager."""

    def __init__(self) -> None:
        self.isTruncated: bool = False
        self.byteData: bytes = b""


class StringManager:
    """Storage for decoding and storing strings associated with an address."""

    def __init__(self, max_chars: int = 256) -> None:
        self._stringMap: Dict[Address, StringData] = {}
        self.maximumChars: int = max_chars

    def __del__(self) -> None:
        self.clear()

    def clear(self) -> None:
        self._stringMap.clear()

    @staticmethod
    def _format_get_string_data_result(
        byte_data: bytes,
        is_truncated: bool,
        isTrunc: Optional[List[bool]] = None,
    ):
        if isinstance(isTrunc, list):
            if isTrunc:
                isTrunc[0] = is_truncated
            else:
                isTrunc.append(is_truncated)
            return byte_data
        return byte_data, is_truncated

    @staticmethod
    def _unpack_get_string_data_result(result) -> tuple[bytes, bool]:
        if isinstance(result, tuple):
            return result
        return result, False

    @abstractmethod
    def getStringData(
        self,
        addr: Address,
        charType: Datatype,
        isTrunc: Optional[List[bool]] = None,
    ):
        """Retrieve string data at the given address as UTF8 bytes."""
        ...

    def getString(self, addr: Address, charType=None) -> Optional[str]:
        """Get a quoted string representation at the given address."""
        if charType is None:
            charType = Datatype(1, 1, TYPE_INT)
            charType.name = "char"
        data, _ = self._unpack_get_string_data_result(self.getStringData(addr, charType))
        if not data:
            return None
        try:
            s = data.decode("utf-8", errors="replace")
            if s.endswith("\x00"):
                s = s[:-1]
            return (
                '"'
                + s.replace("\\", "\\\\")
                .replace('"', '\\"')
                .replace("\n", "\\n")
                .replace("\r", "\\r")
                .replace("\t", "\\t")
                + '"'
            )
        except Exception:
            return None

    def writeUnicode(
        self,
        s,
        buffer: bytes | bytearray,
        size: int,
        charsize: int,
        bigend: bool,
    ) -> bool:
        i = 0
        count = 0
        skip = [charsize]
        while i < size:
            codepoint = self.getCodepoint(buffer[i:], charsize, bigend, skip)
            if codepoint < 0:
                return False
            if codepoint == 0:
                break
            self.writeUtf8(s, codepoint)
            i += skip[0]
            count += 1
            if count >= self.maximumChars:
                break
        return True

    def assignStringData(
        self,
        data: StringData,
        buf: bytes | bytearray,
        size: int,
        charsize: int,
        numChars: int,
        bigend: bool,
    ) -> None:
        if charsize == 1 and numChars < self.maximumChars:
            data.byteData = bytes(buf[:size])
        else:
            s = BytesIO()
            if not self.writeUnicode(s, buf, size, charsize, bigend):
                return
            data.byteData = s.getvalue() + b"\x00"
        data.isTruncated = numChars >= self.maximumChars

    @staticmethod
    def calcInternalHash(addr: Address, buf: bytes | bytearray, size: int) -> int:
        reg = 0x7B7C66A9
        for i in range(size):
            reg = crc_update(reg, buf[i]) & 0xFFFFFFFF
        res = addr.getOffset()
        res ^= reg << 32
        return res & 0xFFFFFFFFFFFFFFFF

    def isString(self, addr: Address, charType: Datatype) -> bool:
        isTrunc: List[bool] = []
        buffer = self.getStringData(addr, charType, isTrunc)
        return len(buffer) != 0

    def registerInternalStringData(
        self,
        addr: Address,
        buf: bytes | bytearray,
        size: int,
        charType: Datatype,
    ) -> int:
        charsize = charType.getSize()
        numChars = self.checkCharacters(buf, size, charsize, addr.isBigEndian())
        if numChars < 0:
            return 0
        hash_val = self.calcInternalHash(addr, buf, size)
        const_addr = addr.getSpace().getManager().getConstant(hash_val)
        string_data = self._stringMap.setdefault(const_addr, StringData())
        string_data.byteData = b""
        string_data.isTruncated = False
        self.assignStringData(string_data, buf, size, charsize, numChars, addr.isBigEndian())
        return hash_val

    def setMaxChars(self, val: int) -> None:
        self.maximumChars = val

    def getMaxChars(self) -> int:
        return self.maximumChars

    def encode(self, encoder) -> None:
        from ghidra.core.marshal import (
            ATTRIB_CONTENT,
            ATTRIB_TRUNC,
            ELEM_BYTES,
            ELEM_STRING,
            ELEM_STRINGMANAGE,
        )

        encoder.openElement(ELEM_STRINGMANAGE)
        for addr in sorted(self._stringMap.keys()):
            encoder.openElement(ELEM_STRING)
            addr.encode(encoder)
            string_data = self._stringMap[addr]
            encoder.openElement(ELEM_BYTES)
            encoder.writeBool(ATTRIB_TRUNC, string_data.isTruncated)
            pieces = ["\n"]
            for i, val in enumerate(string_data.byteData):
                pieces.append(f"{val:02x}")
                if i % 20 == 19:
                    pieces.append("\n  ")
            pieces.append("\n")
            encoder.writeString(ATTRIB_CONTENT, "".join(pieces))
            encoder.closeElement(ELEM_BYTES)
            encoder.closeElement(ELEM_STRING)
        encoder.closeElement(ELEM_STRINGMANAGE)

    def decode(self, decoder) -> None:
        from ghidra.core.marshal import (
            ATTRIB_CONTENT,
            ATTRIB_TRUNC,
            ELEM_BYTES,
            ELEM_STRING,
            ELEM_STRINGMANAGE,
        )

        elemId = decoder.openElement(ELEM_STRINGMANAGE)
        while True:
            subId = decoder.openElement()
            if subId != ELEM_STRING.id:
                break
            addr = Address.decode(decoder)
            string_data = self._stringMap.setdefault(addr, StringData())
            subId2 = decoder.openElement(ELEM_BYTES)
            string_data.isTruncated = decoder.readBool(ATTRIB_TRUNC)
            content = decoder.readString(ATTRIB_CONTENT)
            hexchars: List[str] = []
            byteseq: List[int] = []
            for ch in content:
                if ch.isspace():
                    continue
                hexchars.append(ch)
                if len(hexchars) == 2:
                    byteseq.append(int("".join(hexchars), 16))
                    hexchars.clear()
            string_data.byteData = bytes(byteseq)
            decoder.closeElement(subId2)
            decoder.closeElement(subId)
        decoder.closeElement(elemId)

    def testForString(self, addr: Address, charType: Datatype, buf: bytes, sz: int) -> bool:
        """Quick test if the given data could be a string."""
        if sz < 1:
            return False
        charsize = charType.getSize() if hasattr(charType, "getSize") else 1
        return self.hasCharTerminator(buf, sz, charsize)

    def getCharType(self, size: int):
        """Get the character data-type for the given element size."""
        return None

    @staticmethod
    def hasCharTerminator(buffer: bytes | bytearray, size: int, charsize: int) -> bool:
        for i in range(0, size, charsize):
            is_terminator = True
            for j in range(charsize):
                if i + j >= len(buffer) or buffer[i + j] != 0:
                    is_terminator = False
                    break
            if is_terminator:
                return True
        return False

    @staticmethod
    def readUtf16(buf: bytes | bytearray, bigend: bool) -> int:
        if bigend:
            codepoint = buf[0]
            codepoint <<= 8
            codepoint += buf[1]
        else:
            codepoint = buf[1]
            codepoint <<= 8
            codepoint += buf[0]
        return codepoint

    @staticmethod
    def writeUtf8(s, codepoint: int) -> None:
        if codepoint < 0:
            raise LowlevelError("Negative unicode codepoint")
        if codepoint < 128:
            s.write(bytes([codepoint]))
            return
        bits = mostsigbit_set(codepoint) + 1
        if bits > 21:
            raise LowlevelError("Bad unicode codepoint")
        if bits < 12:
            data = bytes(
                [
                    0xC0 ^ ((codepoint >> 6) & 0x1F),
                    0x80 ^ (codepoint & 0x3F),
                ]
            )
        elif bits < 17:
            data = bytes(
                [
                    0xE0 ^ ((codepoint >> 12) & 0xF),
                    0x80 ^ ((codepoint >> 6) & 0x3F),
                    0x80 ^ (codepoint & 0x3F),
                ]
            )
        else:
            data = bytes(
                [
                    0xF0 ^ ((codepoint >> 18) & 7),
                    0x80 ^ ((codepoint >> 12) & 0x3F),
                    0x80 ^ ((codepoint >> 6) & 0x3F),
                    0x80 ^ (codepoint & 0x3F),
                ]
            )
        s.write(data)

    @staticmethod
    def checkCharacters(
        buf: bytes | bytearray,
        size: int,
        charsize: int,
        bigend: bool,
    ) -> int:
        if buf is None:
            return -1
        i = 0
        count = 0
        skip = [charsize]
        while i < size:
            codepoint = StringManager.getCodepoint(buf[i:], charsize, bigend, skip)
            if codepoint < 0:
                return -1
            if codepoint == 0:
                break
            count += 1
            i += skip[0]
        return count

    @staticmethod
    def getCodepoint(
        buf: bytes | bytearray,
        charsize: int,
        bigend: bool,
        skip: Optional[List[int]] = None,
    ):
        codepoint = -1
        sk = 0
        if charsize == 2:
            if len(buf) < 2:
                return -1 if isinstance(skip, list) else (-1, 0)
            codepoint = StringManager.readUtf16(buf, bigend)
            sk = 2
            if 0xD800 <= codepoint <= 0xDBFF:
                if len(buf) < 4:
                    return -1 if isinstance(skip, list) else (-1, 0)
                trail = StringManager.readUtf16(buf[2:], bigend)
                sk += 2
                if trail < 0xDC00 or trail > 0xDFFF:
                    return -1 if isinstance(skip, list) else (-1, 0)
                codepoint = (codepoint << 10) + trail + (0x10000 - (0xD800 << 10) - 0xDC00)
            elif 0xDC00 <= codepoint <= 0xDFFF:
                return -1 if isinstance(skip, list) else (-1, 0)
        elif charsize == 1:
            if len(buf) < 1:
                return -1 if isinstance(skip, list) else (-1, 0)
            val = buf[0]
            if (val & 0x80) == 0:
                codepoint = val
                sk = 1
            elif (val & 0xE0) == 0xC0:
                if len(buf) < 2:
                    return -1 if isinstance(skip, list) else (-1, 0)
                val2 = buf[1]
                sk = 2
                if (val2 & 0xC0) != 0x80:
                    return -1 if isinstance(skip, list) else (-1, 0)
                codepoint = ((val & 0x1F) << 6) | (val2 & 0x3F)
            elif (val & 0xF0) == 0xE0:
                if len(buf) < 3:
                    return -1 if isinstance(skip, list) else (-1, 0)
                val2 = buf[1]
                val3 = buf[2]
                sk = 3
                if (val2 & 0xC0) != 0x80 or (val3 & 0xC0) != 0x80:
                    return -1 if isinstance(skip, list) else (-1, 0)
                codepoint = ((val & 0xF) << 12) | ((val2 & 0x3F) << 6) | (val3 & 0x3F)
            elif (val & 0xF8) == 0xF0:
                if len(buf) < 4:
                    return -1 if isinstance(skip, list) else (-1, 0)
                val2 = buf[1]
                val3 = buf[2]
                val4 = buf[3]
                sk = 4
                if (val2 & 0xC0) != 0x80 or (val3 & 0xC0) != 0x80 or (val4 & 0xC0) != 0x80:
                    return -1 if isinstance(skip, list) else (-1, 0)
                codepoint = ((val & 7) << 18) | ((val2 & 0x3F) << 12) | ((val3 & 0x3F) << 6) | (val4 & 0x3F)
            else:
                return -1 if isinstance(skip, list) else (-1, 0)
        elif charsize == 4:
            if len(buf) < 4:
                return -1 if isinstance(skip, list) else (-1, 0)
            sk = 4
            if bigend:
                codepoint = (buf[0] << 24) + (buf[1] << 16) + (buf[2] << 8) + buf[3]
            else:
                codepoint = (buf[3] << 24) + (buf[2] << 16) + (buf[1] << 8) + buf[0]
        else:
            return -1 if isinstance(skip, list) else (-1, 0)

        if codepoint >= 0xD800:
            if codepoint > 0x10FFFF:
                return -1 if isinstance(skip, list) else (-1, 0)
            if codepoint <= 0xDFFF:
                return -1 if isinstance(skip, list) else (-1, 0)

        if isinstance(skip, list):
            if skip:
                skip[0] = sk
            else:
                skip.append(sk)
            return codepoint
        return codepoint, sk


class StringManagerUnicode(StringManager):
    """An implementation that understands terminated unicode strings."""

    def __init__(self, glb=None, max_chars: int = 256) -> None:
        super().__init__(max_chars)
        self.glb = glb
        self.testBuffer: Optional[bytearray] = bytearray(max_chars)

    def __del__(self) -> None:
        self.testBuffer = None

    def getStringData(
        self,
        addr: Address,
        charType: Datatype,
        isTrunc: Optional[List[bool]] = None,
    ):
        cached = self._stringMap.get(addr)
        if cached is not None:
            return self._format_get_string_data_result(cached.byteData, cached.isTruncated, isTrunc)

        string_data = self._stringMap.setdefault(addr, StringData())
        string_data.byteData = b""
        string_data.isTruncated = False

        if charType.isOpaqueString():
            return self._format_get_string_data_result(string_data.byteData, string_data.isTruncated, isTrunc)

        curBufferSize = 0
        charsize = charType.getSize()
        foundTerminator = False

        from ghidra.arch.loadimage import DataUnavailError

        try:
            while not foundTerminator:
                amount = 32
                newBufferSize = curBufferSize + amount
                if newBufferSize > self.maximumChars:
                    newBufferSize = self.maximumChars
                    amount = newBufferSize - curBufferSize
                    if amount == 0:
                        return self._format_get_string_data_result(string_data.byteData, string_data.isTruncated, isTrunc)
                if self.testBuffer is None or len(self.testBuffer) < self.maximumChars:
                    self.testBuffer = bytearray(self.maximumChars)
                chunk = bytearray(amount)
                self.glb.loader.loadFill(chunk, amount, addr + curBufferSize)
                self.testBuffer[curBufferSize:curBufferSize + amount] = chunk
                foundTerminator = self.hasCharTerminator(chunk, amount, charsize)
                curBufferSize = newBufferSize
        except DataUnavailError:
            return self._format_get_string_data_result(string_data.byteData, string_data.isTruncated, isTrunc)

        numChars = self.checkCharacters(
            self.testBuffer[:curBufferSize],
            curBufferSize,
            charsize,
            addr.isBigEndian(),
        )
        if numChars < 0:
            return self._format_get_string_data_result(string_data.byteData, string_data.isTruncated, isTrunc)
        self.assignStringData(
            string_data,
            self.testBuffer,
            curBufferSize,
            charsize,
            numChars,
            addr.isBigEndian(),
        )
        return self._format_get_string_data_result(string_data.byteData, string_data.isTruncated, isTrunc)

    def _isBigEndian(self) -> bool:
        if self.glb is not None and hasattr(self.glb, "translate") and self.glb.translate is not None:
            return self.glb.translate.isBigEndian() if hasattr(self.glb.translate, "isBigEndian") else False
        return False

    def isUTF8(self) -> bool:
        return True

    def getGlb(self):
        return self.glb

    def readString(self, addr: Address, charType: Datatype) -> Optional[str]:
        """Read a string from the load image, returning None if not a string."""
        data, _ = self._unpack_get_string_data_result(self.getStringData(addr, charType))
        if not data:
            return None
        try:
            return data.decode("utf-8", errors="replace")
        except Exception:
            return None
