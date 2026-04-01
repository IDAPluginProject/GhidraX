"""
Corresponds to: memstate.hh / memstate.cc

Classes for a pcode machine state that can be operated on by the emulator.
"""

from __future__ import annotations

from typing import Optional, Dict, List

from ghidra.core.space import AddrSpace, IPTR_CONSTANT
from ghidra.core.address import Address, calc_mask
from ghidra.core.error import LowlevelError


class MemoryBank:
    """A byte-addressable bank of memory for a specific address space.

    C++ ref: MemoryBank
    The bank operates on aligned words internally via find()/insert() which
    subclasses override.  Higher-level getValue/setValue/getChunk/setChunk
    break requests into aligned word accesses.
    """

    def __init__(self, spc: AddrSpace, ws: int = 1, ps: int = 4096) -> None:
        self._space: AddrSpace = spc
        self._wordsize: int = ws
        self._pagesize: int = ps

    def getSpace(self) -> AddrSpace:
        return self._space

    def getWordSize(self) -> int:
        return self._wordsize

    def getPageSize(self) -> int:
        return self._pagesize

    # -- static helpers (C++ ref: MemoryBank::constructValue / deconstructValue) --

    @staticmethod
    def constructValue(data: bytes, size: int, bigendian: bool) -> int:
        """Decode *size* bytes from *data* into an integer."""
        res = 0
        if bigendian:
            for i in range(size):
                res = (res << 8) | (data[i] & 0xFF)
        else:
            for i in range(size - 1, -1, -1):
                res = (res << 8) | (data[i] & 0xFF)
        return res

    @staticmethod
    def deconstructValue(val: int, size: int, bigendian: bool) -> bytes:
        """Encode an integer into *size* bytes."""
        buf = bytearray(size)
        if bigendian:
            for i in range(size - 1, -1, -1):
                buf[i] = val & 0xFF
                val >>= 8
        else:
            for i in range(size):
                buf[i] = val & 0xFF
                val >>= 8
        return bytes(buf)

    # -- virtual word-level access (override in subclasses) --

    def find(self, addr: int) -> int:
        """Retrieve a single aligned word.  Default returns 0."""
        return 0

    def insert(self, addr: int, val: int) -> None:
        """Write a single aligned word.  Default is no-op."""
        pass

    # -- page-level access (C++ ref: MemoryBank::getPage / setPage) --

    def getPage(self, addr: int, res: bytearray, skip: int, size: int) -> None:
        """Retrieve bytes from a single page.

        C++ ref: MemoryBank::getPage
        Default implementation iterates using find().
        """
        big = self._space.isBigEndian()
        ptraddr = addr + skip
        endaddr = ptraddr + size
        ws = self._wordsize
        startalign = ptraddr & ~(ws - 1)
        endalign = endaddr & ~(ws - 1)
        if (endaddr & (ws - 1)) != 0:
            endalign += ws

        pos = 0
        while startalign != endalign:
            curval = self.find(startalign)
            raw = self.deconstructValue(curval, ws, big)
            sz = ws
            start = 0
            if startalign < ptraddr:
                start = ptraddr - startalign
                sz = ws - start
            if startalign + ws > endaddr:
                sz -= (startalign + ws - endaddr)
            res[pos:pos + sz] = raw[start:start + sz]
            pos += sz
            startalign += ws

    def setPage(self, addr: int, val: bytes, skip: int, size: int) -> None:
        """Write bytes into a single page.

        C++ ref: MemoryBank::setPage
        Default implementation iterates using find()/insert().
        """
        big = self._space.isBigEndian()
        ptraddr = addr + skip
        endaddr = ptraddr + size
        ws = self._wordsize
        startalign = ptraddr & ~(ws - 1)
        endalign = endaddr & ~(ws - 1)
        if (endaddr & (ws - 1)) != 0:
            endalign += ws

        vpos = 0
        while startalign != endalign:
            sz = ws
            start = 0
            if startalign < ptraddr:
                start = ptraddr - startalign
                sz = ws - start
            if startalign + ws > endaddr:
                sz -= (startalign + ws - endaddr)
            if sz != ws:
                curval = self.find(startalign)
                raw = bytearray(self.deconstructValue(curval, ws, big))
                raw[start:start + sz] = val[vpos:vpos + sz]
                newval = self.constructValue(bytes(raw), ws, big)
            else:
                newval = self.constructValue(val[vpos:vpos + ws], ws, big)
            self.insert(startalign, newval)
            vpos += sz
            startalign += ws

    # -- high-level value access (C++ ref: MemoryBank::setValue / getValue) --

    def setValue(self, offset: int, size: int, val: int) -> None:
        """Write a value at an arbitrary offset.

        C++ ref: MemoryBank::setValue
        """
        ws = self._wordsize
        alignmask = ws - 1
        ind = offset & ~alignmask
        skip = offset & alignmask
        size1 = ws - skip

        if size > size1:
            size2 = size - size1
            val1 = self.find(ind)
            val2 = self.find(ind + ws)
            gap = ws - size2
        else:
            if size == ws:
                self.insert(ind, val)
                return
            val1 = self.find(ind)
            val2 = 0
            gap = size1 - size
            size1 = size
            size2 = 0

        skip_bits = skip * 8
        gap_bits = gap * 8

        if self._space.isBigEndian():
            if size2 == 0:
                val1 &= ~(calc_mask(size1) << gap_bits)
                val1 |= val << gap_bits
                self.insert(ind, val1)
            else:
                val1 &= (~0) << (8 * size1)
                val1 |= val >> (8 * size2)
                self.insert(ind, val1)
                val2 &= (~0) >> (8 * size2)
                val2 |= val << gap_bits
                self.insert(ind + ws, val2)
        else:
            if size2 == 0:
                val1 &= ~(calc_mask(size1) << skip_bits)
                val1 |= val << skip_bits
                self.insert(ind, val1)
            else:
                val1 &= (~0) >> (8 * size1)
                val1 |= val << skip_bits
                self.insert(ind, val1)
                val2 &= (~0) << (8 * size2)
                val2 |= val >> (8 * size1)
                self.insert(ind + ws, val2)

    def getValue(self, offset: int, size: int) -> int:
        """Read a value from an arbitrary offset.

        C++ ref: MemoryBank::getValue
        """
        ws = self._wordsize
        alignmask = ws - 1
        ind = offset & ~alignmask
        skip = offset & alignmask
        size1 = ws - skip

        if size > size1:
            size2 = size - size1
            val1 = self.find(ind)
            val2 = self.find(ind + ws)
            gap = ws - size2
        else:
            val1 = self.find(ind)
            if size == ws:
                return val1
            gap = size1 - size
            size1 = size
            size2 = 0
            val2 = 0

        if self._space.isBigEndian():
            if size2 == 0:
                res = val1 >> (8 * gap)
            else:
                res = (val1 << (8 * size2)) | (val2 >> (8 * gap))
        else:
            if size2 == 0:
                res = val1 >> (skip * 8)
            else:
                res = (val1 >> (skip * 8)) | (val2 << (size1 * 8))

        res &= calc_mask(size)
        return res

    def setChunk(self, offset: int, size: int, val: bytes) -> None:
        """Write a sequence of bytes.

        C++ ref: MemoryBank::setChunk
        """
        pagemask = self._pagesize - 1
        count = 0
        pos = 0
        while count < size:
            cursize = self._pagesize
            offalign = offset & ~pagemask
            skip = 0
            if offalign != offset:
                skip = offset - offalign
                cursize -= skip
            if size - count < cursize:
                cursize = size - count
            self.setPage(offalign, val[pos:pos + cursize], skip, cursize)
            count += cursize
            offset += cursize
            pos += cursize

    def getChunk(self, offset: int, size: int) -> bytes:
        """Read a sequence of bytes.

        C++ ref: MemoryBank::getChunk
        """
        pagemask = self._pagesize - 1
        res = bytearray(size)
        count = 0
        rpos = 0
        while count < size:
            cursize = self._pagesize
            offalign = offset & ~pagemask
            skip = 0
            if offalign != offset:
                skip = offset - offalign
                cursize -= skip
            if size - count < cursize:
                cursize = size - count
            tmp = bytearray(cursize)
            self.getPage(offalign, tmp, skip, cursize)
            res[rpos:rpos + cursize] = tmp
            count += cursize
            offset += cursize
            rpos += cursize
        return bytes(res)

    def clear(self) -> None:
        pass


class MemoryImage(MemoryBank):
    """A read-only memory bank backed by a LoadImage.

    C++ ref: MemoryImage
    """

    def __init__(self, spc: AddrSpace, ws: int, ps: int, loader) -> None:
        super().__init__(spc, ws, ps)
        self._loader = loader

    def find(self, addr: int) -> int:
        """Retrieve an aligned word from the load image.

        C++ ref: MemoryImage::find
        """
        spc = self.getSpace()
        ws = self.getWordSize()
        buf = bytearray(ws)
        try:
            self._loader.loadFill(buf, ws, Address(spc, addr))
        except Exception:
            return 0
        return self.constructValue(bytes(buf), ws, spc.isBigEndian())

    def getPage(self, addr: int, res: bytearray, skip: int, size: int) -> None:
        """Retrieve a page from the load image.

        C++ ref: MemoryImage::getPage
        """
        spc = self.getSpace()
        try:
            tmp = bytearray(size)
            self._loader.loadFill(tmp, size, Address(spc, addr + skip))
            res[:size] = tmp
        except Exception:
            for i in range(size):
                res[i] = 0


class MemoryPageOverlay(MemoryBank):
    """A read/write memory bank overlaying another bank with cached pages.

    C++ ref: MemoryPageOverlay
    """

    def __init__(self, spc: AddrSpace, ws: int, ps: int,
                 underlie: Optional[MemoryBank] = None) -> None:
        super().__init__(spc, ws, ps)
        self._underlie: Optional[MemoryBank] = underlie
        self._pages: Dict[int, bytearray] = {}

    def insert(self, addr: int, val: int) -> None:
        """C++ ref: MemoryPageOverlay::insert"""
        ps = self.getPageSize()
        pageaddr = addr & ~(ps - 1)

        if pageaddr in self._pages:
            pageptr = self._pages[pageaddr]
        else:
            pageptr = bytearray(ps)
            self._pages[pageaddr] = pageptr
            if self._underlie is not None:
                self._underlie.getPage(pageaddr, pageptr, 0, ps)

        pageoffset = addr & (ps - 1)
        raw = self.deconstructValue(val, self.getWordSize(), self.getSpace().isBigEndian())
        pageptr[pageoffset:pageoffset + self.getWordSize()] = raw

    def find(self, addr: int) -> int:
        """C++ ref: MemoryPageOverlay::find"""
        ps = self.getPageSize()
        pageaddr = addr & ~(ps - 1)

        if pageaddr not in self._pages:
            if self._underlie is None:
                return 0
            return self._underlie.find(addr)

        pageptr = self._pages[pageaddr]
        pageoffset = addr & (ps - 1)
        ws = self.getWordSize()
        return self.constructValue(bytes(pageptr[pageoffset:pageoffset + ws]),
                                   ws, self.getSpace().isBigEndian())

    def getPage(self, addr: int, res: bytearray, skip: int, size: int) -> None:
        """C++ ref: MemoryPageOverlay::getPage"""
        if addr not in self._pages:
            if self._underlie is None:
                for i in range(size):
                    res[i] = 0
                return
            self._underlie.getPage(addr, res, skip, size)
            return
        pageptr = self._pages[addr]
        res[:size] = pageptr[skip:skip + size]

    def setPage(self, addr: int, val: bytes, skip: int, size: int) -> None:
        """C++ ref: MemoryPageOverlay::setPage"""
        ps = self.getPageSize()
        if addr not in self._pages:
            pageptr = bytearray(ps)
            self._pages[addr] = pageptr
            if size != ps:
                if self._underlie is not None:
                    self._underlie.getPage(addr, pageptr, 0, ps)
        else:
            pageptr = self._pages[addr]
        pageptr[skip:skip + size] = val[:size]

    def clear(self) -> None:
        self._pages.clear()


class MemoryHashOverlay(MemoryBank):
    """A memory bank using a hash table overlay for unique-space emulation.

    C++ ref: MemoryHashOverlay
    """
    _SENTINEL: int = 0xBADBEEF

    def __init__(self, spc: AddrSpace, ws: int, ps: int,
                 hashsize: int, underlie: Optional[MemoryBank] = None) -> None:
        super().__init__(spc, ws, ps)
        self._underlie: Optional[MemoryBank] = underlie
        self._address: List[int] = [self._SENTINEL] * hashsize
        self._value: List[int] = [0] * hashsize
        self._collideskip: int = 1023
        tmp = ws - 1
        self._alignshift: int = 0
        while tmp != 0:
            self._alignshift += 1
            tmp >>= 1

    def insert(self, addr: int, val: int) -> None:
        """C++ ref: MemoryHashOverlay::insert"""
        sz = len(self._address)
        offset = ((addr >> self._alignshift) % sz)
        for _ in range(sz):
            if self._address[offset] == addr:
                self._value[offset] = val
                return
            elif self._address[offset] == self._SENTINEL:
                self._address[offset] = addr
                self._value[offset] = val
                return
            offset = (offset + self._collideskip) % sz
        raise LowlevelError("Memory state hash_table is full")

    def find(self, addr: int) -> int:
        """C++ ref: MemoryHashOverlay::find"""
        sz = len(self._address)
        offset = ((addr >> self._alignshift) % sz)
        for _ in range(sz):
            if self._address[offset] == addr:
                return self._value[offset]
            elif self._address[offset] == self._SENTINEL:
                break
            offset = (offset + self._collideskip) % sz
        if self._underlie is None:
            return 0
        return self._underlie.find(addr)

    def clear(self) -> None:
        for i in range(len(self._address)):
            self._address[i] = self._SENTINEL
            self._value[i] = 0


class MemoryState:
    """All memory state needed by a pcode emulator.

    Manages a set of MemoryBanks, one per address space.

    C++ ref: MemoryState
    """

    def __init__(self, trans) -> None:
        self._trans = trans  # Translate
        self._banks: Dict[int, MemoryBank] = {}

    def setMemoryBank(self, bank: MemoryBank) -> None:
        """C++ ref: MemoryState::setMemoryBank"""
        self._banks[bank.getSpace().getIndex()] = bank

    def getMemoryBank(self, spc: AddrSpace) -> Optional[MemoryBank]:
        """C++ ref: MemoryState::getMemoryBank"""
        return self._banks.get(spc.getIndex())

    def _ensureBank(self, spc: AddrSpace) -> MemoryBank:
        bank = self._banks.get(spc.getIndex())
        if bank is None:
            bank = MemoryBank(spc)
            self._banks[spc.getIndex()] = bank
        return bank

    def setValue(self, spc_or_name, offset_or_val=None, size: int = 0, val: int = 0) -> None:
        """Write a value. Supports both (spc, off, size, val) and (name, val) forms.

        C++ ref: MemoryState::setValue
        """
        if isinstance(spc_or_name, str):
            nm = spc_or_name
            cval = offset_or_val
            vdata = self._trans.getRegister(nm)
            self.setValue(vdata.space, vdata.offset, vdata.size, cval)
            return
        spc = spc_or_name
        offset = offset_or_val
        if spc.getType() == IPTR_CONSTANT:
            return
        bank = self._ensureBank(spc)
        bank.setValue(offset, size, val)

    def getValue(self, spc_or_name, offset: int = 0, size: int = 0) -> int:
        """Read a value. Supports both (spc, off, size) and (name) forms.

        C++ ref: MemoryState::getValue
        """
        if isinstance(spc_or_name, str):
            nm = spc_or_name
            vdata = self._trans.getRegister(nm)
            return self.getValue(vdata.space, vdata.offset, vdata.size)
        spc = spc_or_name
        if spc.getType() == IPTR_CONSTANT:
            return offset
        bank = self._banks.get(spc.getIndex())
        if bank is None:
            return 0
        return bank.getValue(offset, size)

    def getChunk(self, spc: AddrSpace, offset: int, size: int) -> bytes:
        """Read a range of bytes from the state.

        C++ ref: MemoryState::getChunk
        """
        bank = self.getMemoryBank(spc)
        if bank is None:
            raise LowlevelError(f"Getting chunk from unmapped memory space: {spc.getName()}")
        return bank.getChunk(offset, size)

    def setChunk(self, spc: AddrSpace, offset: int, val: bytes) -> None:
        """Write a range of bytes to the state.

        C++ ref: MemoryState::setChunk
        """
        bank = self._ensureBank(spc)
        bank.setChunk(offset, len(val), val)

    def setVarnodeValue(self, vn_space: AddrSpace, vn_offset: int, vn_size: int, val: int) -> None:
        self.setValue(vn_space, vn_offset, vn_size, val)

    def getVarnodeValue(self, vn_space: AddrSpace, vn_offset: int, vn_size: int) -> int:
        return self.getValue(vn_space, vn_offset, vn_size)

    def clear(self) -> None:
        for bank in self._banks.values():
            bank.clear()
