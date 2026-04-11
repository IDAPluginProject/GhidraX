"""
LoadImageXml: Implementation of LoadImage using XML-encoded binary data.
Corresponds to loadimage_xml.hh / loadimage_xml.cc.

Stores binary image chunks, symbols, and readonly regions parsed from
an XML <binaryimage> element.
"""
from __future__ import annotations

from typing import Dict, Optional, Set, TYPE_CHECKING

from ghidra.core.address import Address
from ghidra.core.error import LowlevelError
from ghidra.core.space import AddrSpace
from ghidra.core.xml import DecoderError
from ghidra.core.marshal import (
    ATTRIB_ARCH, ATTRIB_NAME, ATTRIB_READONLY, ATTRIB_CONTENT,
    ELEM_BINARYIMAGE, ELEM_BYTECHUNK, ELEM_SYMBOL,
    Encoder,
)
from ghidra.arch.loadimage import LoadImage, LoadImageFunc, DataUnavailError

if TYPE_CHECKING:
    from ghidra.core.space import AddrSpace, AddrSpaceManager


class LoadImageXml(LoadImage):
    """LoadImage backed by XML-encoded byte chunks and symbols.

    The XML format uses a <binaryimage> root with <bytechunk> children
    containing hex-encoded byte data and optional <symbol> children.
    """

    def __init__(self, filename: str, rootel) -> None:
        super().__init__(filename)
        self._archtype: str = ""
        self._manage: Optional[AddrSpaceManager] = None
        self._rootel = rootel
        self._chunks: Dict[Address, bytearray] = {}
        self._readonlyset: Set[Address] = set()
        self._addrtosymbol: Dict[Address, str] = {}
        self._symbol_iter: Optional[list] = None
        self._symbol_pos: int = 0

        if rootel.getName() != "binaryimage":
            raise LowlevelError("Missing binaryimage tag in " + filename)
        self._archtype = rootel.getAttributeValue("arch")

    # ------------------------------------------------------------------
    # Construction helpers
    # ------------------------------------------------------------------

    def addChunk(self, addr: Address, data: bytes, readonly: bool = False) -> None:
        """Add a byte chunk at the given address."""
        self._chunks[addr] = bytearray(data)
        if readonly:
            self._readonlyset.add(addr)

    def addSymbol(self, addr: Address, name: str) -> None:
        """Add a symbol at the given address."""
        self._addrtosymbol[addr] = name

    def open(self, manage: AddrSpaceManager) -> None:
        """Set the address space manager and parse any stored XML root."""
        self._manage = manage
        self._archtype = self._rootel.getAttributeValue("arch")

        for child in self._rootel.getChildren():
            tag = child.getName()
            base = manage.getSpaceByName(child.getAttributeValue("space"))
            offset = int(child.getAttributeValue("offset"), 0)
            addr = Address(base, offset)

            if tag == "symbol":
                self._addrtosymbol[addr] = child.getAttributeValue("name")
                continue

            if tag != "bytechunk":
                raise LowlevelError("Unknown LoadImageXml tag")

            chunk = self._chunks.setdefault(addr, bytearray())
            chunk.clear()
            try:
                readonly = child.getAttributeValue("readonly").lower() == "true"
            except DecoderError:
                readonly = False
            if readonly:
                self._readonlyset.add(addr)

            chunk.extend(bytes.fromhex(child.getAttributeValue("content")))

        self.pad()

    def clear(self) -> None:
        """Clear all caches."""
        self._archtype = ""
        self._manage = None
        self._chunks.clear()
        self._addrtosymbol.clear()
        self._symbol_iter = None
        self._symbol_pos = 0

    # ------------------------------------------------------------------
    # Padding — mirrors C++ pad() logic
    # ------------------------------------------------------------------

    def pad(self) -> None:
        """Ensure every chunk is followed by at least 512 bytes of zero pad.

        Also removes completely redundant (fully overlapping) chunks.
        """
        if not self._chunks:
            return

        # Sort chunks by address for sequential processing
        sorted_addrs = sorted(self._chunks.keys())

        # Remove completely redundant chunks
        i = 0
        while i < len(sorted_addrs) - 1:
            cur = sorted_addrs[i]
            nxt = sorted_addrs[i + 1]
            if cur.getSpace() is nxt.getSpace():
                end_cur = cur.getOffset() + len(self._chunks[cur]) - 1
                end_nxt = nxt.getOffset() + len(self._chunks[nxt]) - 1
                if end_cur >= end_nxt:
                    del self._chunks[nxt]
                    sorted_addrs.pop(i + 1)
                    continue
            i += 1

        # Add zero padding after each chunk
        sorted_addrs = sorted(self._chunks.keys())
        pad_chunks: Dict[Address, bytearray] = {}

        for idx, addr in enumerate(sorted_addrs):
            chunk = self._chunks[addr]
            endaddr = addr + len(chunk)
            if endaddr < addr:
                continue

            maxsize = 512
            space = endaddr.getSpace()
            room = space.getHighest() - endaddr.getOffset() + 1
            if maxsize > room:
                maxsize = int(room)

            # Check if next chunk is in the same space and close
            if idx + 1 < len(sorted_addrs):
                nxt = sorted_addrs[idx + 1]
                if nxt.getSpace() is endaddr.getSpace():
                    if endaddr.getOffset() >= nxt.getOffset():
                        continue
                    gap = nxt.getOffset() - endaddr.getOffset()
                    if maxsize > gap:
                        maxsize = int(gap)

            if maxsize > 0:
                pad_chunks[endaddr] = bytearray(maxsize)

        # Merge pad chunks
        for addr, data in pad_chunks.items():
            vec = self._chunks.setdefault(addr, bytearray())
            vec.extend(data)

    # ------------------------------------------------------------------
    # LoadImage interface
    # ------------------------------------------------------------------

    def loadFill(self, buf: bytearray, size: int, addr: Address) -> None:
        """Load *size* bytes at *addr* into *buf*."""
        curaddr = addr
        remaining = size
        buf_pos = 0
        emptyhit = False

        # Find chunks that could contain our data
        # Sort chunks and find the last one <= curaddr
        sorted_items = sorted(self._chunks.items(), key=lambda x: x[0])

        chunk_idx = -1
        for i, (caddr, _) in enumerate(sorted_items):
            if caddr <= curaddr:
                chunk_idx = i
            else:
                break

        if chunk_idx < 0:
            chunk_idx = 0

        while remaining > 0 and chunk_idx < len(sorted_items):
            caddr, cdata = sorted_items[chunk_idx]
            chnksize = len(cdata)

            # Calculate overlap
            over = self._overlap(curaddr, caddr, chnksize)
            if over != -1:
                available = chnksize - over
                if available > remaining:
                    available = remaining
                buf[buf_pos:buf_pos + available] = cdata[over:over + available]
                buf_pos += available
                remaining -= available
                curaddr = Address(curaddr.getSpace(),
                                  curaddr.getOffset() + available)
                chunk_idx += 1
            else:
                emptyhit = True
                break

        if remaining > 0 or emptyhit:
            raise DataUnavailError(f"Bytes at {curaddr.printRaw()} are not mapped")

    @staticmethod
    def _overlap(addr: Address, chunk_addr: Address, chunk_size: int) -> int:
        """Check if addr overlaps with the chunk. Returns byte offset or -1."""
        if addr.getSpace() is not chunk_addr.getSpace():
            return -1
        off = addr.getOffset() - chunk_addr.getOffset()
        if off < 0 or off >= chunk_size:
            return -1
        return int(off)

    def getArchType(self) -> str:
        return self._archtype

    def openSymbols(self) -> None:
        self._symbol_iter = list(self._addrtosymbol.items())
        self._symbol_pos = 0

    def getNextSymbol(self, record: LoadImageFunc) -> bool:
        if self._symbol_iter is None or self._symbol_pos >= len(self._symbol_iter):
            return False
        addr, name = self._symbol_iter[self._symbol_pos]
        record.address = addr
        record.name = name
        self._symbol_pos += 1
        return True

    def getReadonly(self, rnglist) -> None:
        """Fill rnglist with readonly address ranges."""
        for addr, data in self._chunks.items():
            if addr in self._readonlyset:
                start = addr.getOffset()
                stop = start + len(data) - 1
                rnglist.insertRange(addr.getSpace(), start, stop)

    def adjustVma(self, adjust: int) -> None:
        """Adjust all addresses by the given amount."""
        new_chunks: Dict[Address, bytearray] = {}
        for addr, data in self._chunks.items():
            spc = addr.getSpace()
            off = AddrSpace.addressToByte(adjust, spc.getWordSize())
            new_chunks[addr + off] = data
        self._chunks = new_chunks

        new_symbols: Dict[Address, str] = {}
        for addr, name in self._addrtosymbol.items():
            spc = addr.getSpace()
            off = AddrSpace.addressToByte(adjust, spc.getWordSize())
            new_symbols[addr + off] = name
        self._addrtosymbol = new_symbols

    # ------------------------------------------------------------------
    # Serialization
    # ------------------------------------------------------------------

    def encode(self, encoder: Encoder) -> None:
        """Encode the image to a stream."""
        encoder.openElement(ELEM_BINARYIMAGE)
        encoder.writeString(ATTRIB_ARCH, self._archtype)

        for addr in sorted(self._chunks.keys()):
            data = self._chunks[addr]
            if not data:
                continue
            encoder.openElement(ELEM_BYTECHUNK)
            addr.getSpace().encodeAttributes(encoder, addr.getOffset())
            if addr in self._readonlyset:
                encoder.writeBool(ATTRIB_READONLY, True)
            hex_str = '\n'
            for i, b in enumerate(data):
                hex_str += f'{b:02x}'
                if i % 20 == 19:
                    hex_str += '\n'
            hex_str += '\n'
            encoder.writeString(ATTRIB_CONTENT, hex_str)
            encoder.closeElement(ELEM_BYTECHUNK)

        for addr in sorted(self._addrtosymbol.keys()):
            name = self._addrtosymbol[addr]
            encoder.openElement(ELEM_SYMBOL)
            addr.getSpace().encodeAttributes(encoder, addr.getOffset())
            encoder.writeString(ATTRIB_NAME, name)
            encoder.closeElement(ELEM_SYMBOL)

        encoder.closeElement(ELEM_BINARYIMAGE)

    def __del__(self) -> None:
        self.clear()

    # ------------------------------------------------------------------
    # Convenience: build from hex string
    # ------------------------------------------------------------------

    @staticmethod
    def fromHexChunk(space: AddrSpace, offset: int,
                     hex_data: str, archtype: str = "x86") -> LoadImageXml:
        """Create a LoadImageXml from a hex string at the given address."""
        cleaned = hex_data.replace('\n', '').replace(' ', '')
        data = bytes.fromhex(cleaned)
        addr = Address(space, offset)
        img = LoadImageXml.__new__(LoadImageXml)
        LoadImage.__init__(img, "memory")
        img._archtype = archtype
        img._manage = None
        img._rootel = None
        img._chunks = {}
        img._readonlyset = set()
        img._addrtosymbol = {}
        img._symbol_iter = None
        img._symbol_pos = 0
        img.addChunk(addr, data)
        return img
