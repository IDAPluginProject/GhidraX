"""Tests for ghidra.emulate.emulateutil – Python port of emulateutil.cc."""
from __future__ import annotations

import pytest
import sys, os

sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', 'python'))

from ghidra.core.address import Address, calc_mask
from ghidra.core.error import LowlevelError
from ghidra.core.opcodes import OpCode
from ghidra.core.pcoderaw import VarnodeData, PcodeOpRaw
from ghidra.core.opbehavior import OpBehavior
from ghidra.core.space import AddrSpace, IPTR_CONSTANT, IPTR_INTERNAL, IPTR_PROCESSOR
from ghidra.emulate.emulateutil import (
    EmulatePcodeOp, EmulateSnippet, PcodeEmitCache, _load_image_value,
)


# =========================================================================
# Helpers – minimal stubs
# =========================================================================

def _make_space(name: str = "ram", size: int = 4, stype: int = IPTR_PROCESSOR,
                big_endian: bool = False) -> AddrSpace:
    spc = AddrSpace.__new__(AddrSpace)
    spc._name = name
    spc._size = size
    spc._wordsize = 1
    spc._index = 1
    spc._type = stype
    spc._flags = AddrSpace.big_endian if big_endian else 0
    spc._delay = 0
    spc._deadcodedelay = 0
    return spc


def _make_const_space() -> AddrSpace:
    return _make_space("const", 8, IPTR_CONSTANT)


def _make_unique_space() -> AddrSpace:
    return _make_space("unique", 4, IPTR_INTERNAL)


class StubLoadImage:
    """Minimal load image that returns zeros."""
    def __init__(self, data: bytes = b'\x00' * 256):
        self._data = data

    def loadFill(self, buf, sz, addr):
        off = addr.getOffset()
        for i in range(min(sz, len(buf))):
            idx = off + i
            if 0 <= idx < len(self._data):
                buf[i] = self._data[idx]
            else:
                buf[i] = 0


class StubArch:
    """Minimal Architecture stub."""
    def __init__(self, loader=None):
        self.loader = loader or StubLoadImage()


# =========================================================================
# Concrete EmulatePcodeOp for testing
# =========================================================================

class ConcreteEmulatePcodeOp(EmulatePcodeOp):
    """Concrete subclass for testing – stores values in a dict."""

    def __init__(self, glb):
        super().__init__(glb)
        self._values = {}  # (space_index, offset) -> value
        self._op_sequence = []  # list of PcodeOp-like objects
        self._pos = 0

    def getVarnodeValue(self, vn):
        spc = vn.getSpace()
        if spc is not None and spc.getType() == IPTR_CONSTANT:
            return vn.getOffset() & calc_mask(vn.getSize())
        key = (spc.getIndex() if spc else 0, vn.getOffset())
        return self._values.get(key, 0)

    def setVarnodeValue(self, vn, val):
        spc = vn.getSpace()
        if spc is not None and spc.getType() == IPTR_CONSTANT:
            return
        key = (spc.getIndex() if spc else 0, vn.getOffset())
        self._values[key] = val & calc_mask(vn.getSize())

    def fallthruOp(self):
        self._pos += 1
        if self._pos >= len(self._op_sequence):
            self.emu_halted = True
            return
        self.lastOp = self.currentOp
        self.setCurrentOp(self._op_sequence[self._pos])

    def executeBranch(self):
        self.emu_halted = True  # simplified

    def executeBranchind(self):
        self.emu_halted = True

    def executeCall(self):
        self.fallthruOp()

    def executeCallind(self):
        self.fallthruOp()

    def executeCallother(self):
        self.fallthruOp()

    def loadSequence(self, ops):
        self._op_sequence = ops
        self._pos = 0
        if ops:
            self.setCurrentOp(ops[0])
            self.emu_halted = False


# Minimal PcodeOp-like and Varnode-like stubs for EmulatePcodeOp tests

class StubVarnode:
    def __init__(self, space, offset, size):
        self._space = space
        self._offset = offset
        self._size = size

    def getSpace(self):
        return self._space

    def getOffset(self):
        return self._offset

    def getSize(self):
        return self._size

    def getSpaceFromConst(self):
        return self._space


# Build the behavior table once for all tests
_BEHAVIORS = OpBehavior.registerInstructions(None)


class StubTypeOp:
    def __init__(self, behave):
        self._behave = behave

    def getBehavior(self):
        return self._behave


class StubPcodeOp:
    def __init__(self, opcode_enum, inputs, output=None, addr=None):
        self._opcode_enum = opcode_enum
        self._inputs = inputs
        self._output = output
        self._addr = addr or Address()
        idx = int(opcode_enum)
        behave = _BEHAVIORS[idx] if idx < len(_BEHAVIORS) else None
        self._typeop = StubTypeOp(behave)
        self._flags = 0

    def getOpcode(self):
        return self._typeop

    def getIn(self, i):
        return self._inputs[i]

    def getOut(self):
        return self._output

    def getAddr(self):
        return self._addr

    def isBooleanFlip(self):
        return (self._flags & 0x20) != 0  # PcodeOp.boolean_flip

    def getParent(self):
        return None


# =========================================================================
# Tests – _load_image_value
# =========================================================================

class TestLoadImageValue:
    def test_little_endian(self):
        data = bytes([0x78, 0x56, 0x34, 0x12]) + b'\x00' * 252
        loader = StubLoadImage(data)
        spc = _make_space(big_endian=False)
        val = _load_image_value(loader, spc, 0, 4)
        assert val == 0x12345678

    def test_big_endian(self):
        data = bytes([0x12, 0x34, 0x56, 0x78]) + b'\x00' * 252
        loader = StubLoadImage(data)
        spc = _make_space(big_endian=True)
        val = _load_image_value(loader, spc, 0, 4)
        assert val == 0x12345678


# =========================================================================
# Tests – EmulatePcodeOp
# =========================================================================

class TestEmulatePcodeOp:
    def setup_method(self):
        self.arch = StubArch()
        self.emu = ConcreteEmulatePcodeOp(self.arch)
        self.ram = _make_space()
        self.const_spc = _make_const_space()
        self.uniq = _make_unique_space()

    def test_init(self):
        assert self.emu.currentOp is None
        assert self.emu.emu_halted is True
        assert self.emu.glb is self.arch

    def test_execute_copy(self):
        src = StubVarnode(self.ram, 0x10, 4)
        dst = StubVarnode(self.ram, 0x20, 4)
        self.emu._values[(self.ram.getIndex(), 0x10)] = 0xDEADBEEF
        op = StubPcodeOp(OpCode.CPUI_COPY, [src], dst)
        self.emu.loadSequence([op])
        self.emu.executeCurrentOp()
        assert self.emu._values.get((self.ram.getIndex(), 0x20)) == 0xDEADBEEF

    def test_execute_int_add(self):
        a = StubVarnode(self.ram, 0, 4)
        b = StubVarnode(self.ram, 4, 4)
        out = StubVarnode(self.ram, 8, 4)
        self.emu._values[(self.ram.getIndex(), 0)] = 10
        self.emu._values[(self.ram.getIndex(), 4)] = 20
        op = StubPcodeOp(OpCode.CPUI_INT_ADD, [a, b], out)
        self.emu.loadSequence([op])
        self.emu.executeCurrentOp()
        assert self.emu._values.get((self.ram.getIndex(), 8)) == 30

    def test_execute_int_sub(self):
        a = StubVarnode(self.ram, 0, 4)
        b = StubVarnode(self.ram, 4, 4)
        out = StubVarnode(self.ram, 8, 4)
        self.emu._values[(self.ram.getIndex(), 0)] = 100
        self.emu._values[(self.ram.getIndex(), 4)] = 30
        op = StubPcodeOp(OpCode.CPUI_INT_SUB, [a, b], out)
        self.emu.loadSequence([op])
        self.emu.executeCurrentOp()
        assert self.emu._values.get((self.ram.getIndex(), 8)) == 70

    def test_execute_int_and(self):
        a = StubVarnode(self.ram, 0, 4)
        b = StubVarnode(self.ram, 4, 4)
        out = StubVarnode(self.ram, 8, 4)
        self.emu._values[(self.ram.getIndex(), 0)] = 0xFF00
        self.emu._values[(self.ram.getIndex(), 4)] = 0x0FF0
        op = StubPcodeOp(OpCode.CPUI_INT_AND, [a, b], out)
        self.emu.loadSequence([op])
        self.emu.executeCurrentOp()
        assert self.emu._values.get((self.ram.getIndex(), 8)) == 0x0F00

    def test_execute_int_negate(self):
        a = StubVarnode(self.ram, 0, 4)
        out = StubVarnode(self.ram, 4, 4)
        self.emu._values[(self.ram.getIndex(), 0)] = 1
        op = StubPcodeOp(OpCode.CPUI_INT_NEGATE, [a], out)
        self.emu.loadSequence([op])
        self.emu.executeCurrentOp()
        assert self.emu._values.get((self.ram.getIndex(), 4)) == 0xFFFFFFFE

    def test_execute_store_noop(self):
        """executeStore is a no-op in EmulatePcodeOp."""
        spc_vn = StubVarnode(self.const_spc, self.ram.getIndex(), 4)
        off_vn = StubVarnode(self.ram, 0, 4)
        data_vn = StubVarnode(self.ram, 4, 4)
        op = StubPcodeOp(OpCode.CPUI_STORE, [spc_vn, off_vn, data_vn])
        self.emu.loadSequence([op])
        self.emu.executeCurrentOp()
        # No crash = pass

    def test_execute_sequence(self):
        """Multiple ops in sequence."""
        a = StubVarnode(self.ram, 0, 4)
        b = StubVarnode(self.const_spc, 5, 4)
        out1 = StubVarnode(self.ram, 8, 4)
        out2 = StubVarnode(self.ram, 12, 4)
        self.emu._values[(self.ram.getIndex(), 0)] = 10
        op1 = StubPcodeOp(OpCode.CPUI_INT_ADD, [a, b], out1)
        c = StubVarnode(self.const_spc, 3, 4)
        op2 = StubPcodeOp(OpCode.CPUI_INT_ADD, [out1, c], out2)
        self.emu.loadSequence([op1, op2])
        self.emu.executeCurrentOp()  # 10 + 5 = 15
        assert not self.emu.emu_halted
        self.emu.executeCurrentOp()  # 15 + 3 = 18
        assert self.emu._values.get((self.ram.getIndex(), 12)) == 18

    def test_halt_after_last_op(self):
        a = StubVarnode(self.ram, 0, 4)
        out = StubVarnode(self.ram, 4, 4)
        op = StubPcodeOp(OpCode.CPUI_COPY, [a], out)
        self.emu.loadSequence([op])
        self.emu.executeCurrentOp()
        assert self.emu.emu_halted

    def test_execute_indirect_as_copy(self):
        a = StubVarnode(self.ram, 0, 4)
        ind = StubVarnode(self.const_spc, 0, 4)
        out = StubVarnode(self.ram, 4, 4)
        self.emu._values[(self.ram.getIndex(), 0)] = 42
        op = StubPcodeOp(OpCode.CPUI_INDIRECT, [a, ind], out)
        self.emu.loadSequence([op])
        self.emu.executeCurrentOp()
        assert self.emu._values.get((self.ram.getIndex(), 4)) == 42

    def test_get_execute_address(self):
        spc = _make_space()
        a = StubVarnode(spc, 0, 4)
        out = StubVarnode(spc, 4, 4)
        op = StubPcodeOp(OpCode.CPUI_COPY, [a], out, addr=Address(spc, 0x401000))
        self.emu.loadSequence([op])
        assert self.emu.getExecuteAddress().getOffset() == 0x401000


# =========================================================================
# Tests – PcodeEmitCache
# =========================================================================

class TestPcodeEmitCache:
    def test_dump_basic(self):
        opcache = []
        varcache = []
        inst = OpBehavior.registerInstructions(None)
        emitter = PcodeEmitCache(opcache, varcache, inst, 0x100)

        spc = _make_space()
        addr = Address(spc, 0x1000)
        outvn = VarnodeData()
        outvn.space = _make_unique_space()
        outvn.offset = 0x200
        outvn.size = 4
        in0 = VarnodeData()
        in0.space = spc
        in0.offset = 0
        in0.size = 4
        in1 = VarnodeData()
        in1.space = spc
        in1.offset = 4
        in1.size = 4

        emitter.dump(addr, OpCode.CPUI_INT_ADD, outvn, [in0, in1], 2)
        assert len(opcache) == 1
        assert len(varcache) == 3  # 1 out + 2 in
        assert opcache[0].numInput() == 2
        assert opcache[0].getOutput() is not None
        assert opcache[0].getOutput().offset == 0x200

    def test_dump_no_output(self):
        opcache = []
        varcache = []
        inst = OpBehavior.registerInstructions(None)
        emitter = PcodeEmitCache(opcache, varcache, inst, 0)

        spc = _make_space()
        addr = Address(spc, 0)
        in0 = VarnodeData()
        in0.space = spc
        in0.offset = 0
        in0.size = 4

        emitter.dump(addr, OpCode.CPUI_BRANCH, None, [in0], 1)
        assert len(opcache) == 1
        assert opcache[0].getOutput() is None
        assert opcache[0].numInput() == 1


# =========================================================================
# Tests – EmulateSnippet
# =========================================================================

class TestEmulateSnippet:
    def setup_method(self):
        self.arch = StubArch()
        self.ram = _make_space()
        self.const_spc = _make_const_space()
        self.uniq = _make_unique_space()
        self.inst = OpBehavior.registerInstructions(None)

    def _build_snippet(self, ops_data):
        """Build an EmulateSnippet from a list of (opc, out_vn, [in_vns])."""
        emu = EmulateSnippet(self.arch)
        emitter = emu.buildEmitter(self.inst, 0x1000)
        addr = Address(self.ram, 0)
        for opc, outvn, invns in ops_data:
            emitter.dump(addr, opc, outvn, invns, len(invns))
        return emu

    def _vn(self, space, offset, size):
        vn = VarnodeData()
        vn.space = space
        vn.offset = offset
        vn.size = size
        return vn

    def test_simple_add(self):
        """Add two constants into a temp, then retrieve result."""
        t0 = self._vn(self.uniq, 0x100, 4)
        c5 = self._vn(self.const_spc, 5, 4)
        c3 = self._vn(self.const_spc, 3, 4)
        t1 = self._vn(self.uniq, 0x104, 4)

        emu = self._build_snippet([
            (OpCode.CPUI_INT_ADD, t0, [c5, c3]),  # t0 = 5 + 3 = 8
            (OpCode.CPUI_COPY, t1, [t0]),           # t1 = t0 = 8
        ])
        emu.resetMemory()
        while not emu.emu_halted:
            emu.executeCurrentOp()
        assert emu.getTempValue(0x104) == 8

    def test_simple_sub(self):
        t0 = self._vn(self.uniq, 0x100, 4)
        c10 = self._vn(self.const_spc, 10, 4)
        c3 = self._vn(self.const_spc, 3, 4)
        emu = self._build_snippet([
            (OpCode.CPUI_INT_SUB, t0, [c10, c3]),
        ])
        emu.resetMemory()
        while not emu.emu_halted:
            emu.executeCurrentOp()
        assert emu.getTempValue(0x100) == 7

    def test_chained_ops(self):
        """Chain multiple operations."""
        t0 = self._vn(self.uniq, 0x100, 4)
        t1 = self._vn(self.uniq, 0x104, 4)
        c2 = self._vn(self.const_spc, 2, 4)
        c3 = self._vn(self.const_spc, 3, 4)
        c4 = self._vn(self.const_spc, 4, 4)

        emu = self._build_snippet([
            (OpCode.CPUI_INT_ADD, t0, [c2, c3]),     # t0 = 5
            (OpCode.CPUI_INT_MULT, t1, [t0, c4]),    # t1 = 5 * 4 = 20
        ])
        emu.resetMemory()
        while not emu.emu_halted:
            emu.executeCurrentOp()
        assert emu.getTempValue(0x104) == 20

    def test_branch_forward(self):
        """BRANCH with positive relative offset."""
        t0 = self._vn(self.uniq, 0x100, 4)
        c42 = self._vn(self.const_spc, 42, 4)
        c99 = self._vn(self.const_spc, 99, 4)
        branch_target = self._vn(self.const_spc, 2, 4)  # skip 2 ops forward

        emu = self._build_snippet([
            (OpCode.CPUI_BRANCH, None, [branch_target]),  # op0: branch to op2
            (OpCode.CPUI_COPY, t0, [c99]),                # op1: skipped
            (OpCode.CPUI_COPY, t0, [c42]),                # op2: executed
        ])
        emu.resetMemory()
        while not emu.emu_halted:
            emu.executeCurrentOp()
        assert emu.getTempValue(0x100) == 42

    def test_cbranch_taken(self):
        """CBRANCH when condition is true."""
        t0 = self._vn(self.uniq, 0x100, 4)
        c1 = self._vn(self.const_spc, 1, 4)
        c42 = self._vn(self.const_spc, 42, 4)
        c99 = self._vn(self.const_spc, 99, 4)
        branch_target = self._vn(self.const_spc, 2, 4)

        emu = self._build_snippet([
            (OpCode.CPUI_CBRANCH, None, [branch_target, c1]),  # cond=1, taken
            (OpCode.CPUI_COPY, t0, [c99]),                     # skipped
            (OpCode.CPUI_COPY, t0, [c42]),                     # executed
        ])
        emu.resetMemory()
        while not emu.emu_halted:
            emu.executeCurrentOp()
        assert emu.getTempValue(0x100) == 42

    def test_cbranch_not_taken(self):
        """CBRANCH when condition is false."""
        t0 = self._vn(self.uniq, 0x100, 4)
        c0 = self._vn(self.const_spc, 0, 4)
        c42 = self._vn(self.const_spc, 42, 4)
        c99 = self._vn(self.const_spc, 99, 4)
        branch_target = self._vn(self.const_spc, 2, 4)

        emu = self._build_snippet([
            (OpCode.CPUI_CBRANCH, None, [branch_target, c0]),  # cond=0, not taken
            (OpCode.CPUI_COPY, t0, [c99]),                     # executed
            (OpCode.CPUI_COPY, t0, [c42]),                     # also executed
        ])
        emu.resetMemory()
        while not emu.emu_halted:
            emu.executeCurrentOp()
        assert emu.getTempValue(0x100) == 42  # last write wins

    def test_halts_at_end(self):
        t0 = self._vn(self.uniq, 0x100, 4)
        c1 = self._vn(self.const_spc, 1, 4)
        emu = self._build_snippet([
            (OpCode.CPUI_COPY, t0, [c1]),
        ])
        emu.resetMemory()
        assert not emu.emu_halted
        emu.executeCurrentOp()
        assert emu.emu_halted

    def test_reset_memory(self):
        t0 = self._vn(self.uniq, 0x100, 4)
        c5 = self._vn(self.const_spc, 5, 4)
        emu = self._build_snippet([
            (OpCode.CPUI_COPY, t0, [c5]),
        ])
        emu.resetMemory()
        emu.executeCurrentOp()
        assert emu.getTempValue(0x100) == 5
        emu.resetMemory()
        assert emu.getTempValue(0x100) == 0  # cleared

    def test_read_before_write_error(self):
        t0 = self._vn(self.uniq, 0x100, 4)
        t1 = self._vn(self.uniq, 0x999, 4)  # never written
        emu = self._build_snippet([
            (OpCode.CPUI_COPY, t0, [t1]),
        ])
        emu.resetMemory()
        with pytest.raises(LowlevelError, match="Read before write"):
            emu.executeCurrentOp()

    def test_illegal_store(self):
        spc_vn = self._vn(self.const_spc, 1, 4)
        off_vn = self._vn(self.const_spc, 0, 4)
        data_vn = self._vn(self.const_spc, 0, 4)
        emu = self._build_snippet([
            (OpCode.CPUI_STORE, None, [spc_vn, off_vn, data_vn]),
        ])
        emu.resetMemory()
        with pytest.raises(LowlevelError, match="Illegal"):
            emu.executeCurrentOp()

    def test_illegal_call(self):
        target = self._vn(self.const_spc, 0x1000, 4)
        emu = self._build_snippet([
            (OpCode.CPUI_CALL, None, [target]),
        ])
        emu.resetMemory()
        with pytest.raises(LowlevelError, match="Illegal"):
            emu.executeCurrentOp()

    def test_check_for_legal_code_valid(self):
        t0 = self._vn(self.uniq, 0x100, 4)
        c1 = self._vn(self.const_spc, 1, 4)
        emu = self._build_snippet([
            (OpCode.CPUI_COPY, t0, [c1]),
        ])
        assert emu.checkForLegalCode()

    def test_check_for_legal_code_store_illegal(self):
        spc_vn = self._vn(self.const_spc, 1, 4)
        off_vn = self._vn(self.const_spc, 0, 4)
        data_vn = self._vn(self.const_spc, 0, 4)
        emu = self._build_snippet([
            (OpCode.CPUI_STORE, None, [spc_vn, off_vn, data_vn]),
        ])
        assert not emu.checkForLegalCode()

    def test_check_for_legal_code_register_read_illegal(self):
        """Reading from processor space is illegal in snippets."""
        t0 = self._vn(self.uniq, 0x100, 4)
        reg = self._vn(self.ram, 0, 4)  # processor space
        emu = self._build_snippet([
            (OpCode.CPUI_COPY, t0, [reg]),
        ])
        assert not emu.checkForLegalCode()

    def test_check_for_legal_code_write_to_register_illegal(self):
        """Writing to processor space is illegal in snippets."""
        reg = self._vn(self.ram, 0, 4)
        c1 = self._vn(self.const_spc, 1, 4)
        emu = self._build_snippet([
            (OpCode.CPUI_COPY, reg, [c1]),
        ])
        assert not emu.checkForLegalCode()

    def test_set_and_get_varnode_value(self):
        emu = EmulateSnippet(self.arch)
        emu.setVarnodeValue(0x100, 0xBEEF)
        assert emu.getTempValue(0x100) == 0xBEEF

    def test_get_arch(self):
        emu = EmulateSnippet(self.arch)
        assert emu.getArch() is self.arch

    def test_get_varnode_value_constant(self):
        emu = EmulateSnippet(self.arch)
        vn = self._vn(self.const_spc, 42, 4)
        assert emu.getVarnodeValue(vn) == 42


# =========================================================================
# Tests – EmulateSnippet load from image
# =========================================================================

class TestEmulateSnippetLoad:
    def test_load_from_image(self):
        data = b'\x00' * 0x100 + bytes([0x78, 0x56, 0x34, 0x12]) + b'\x00' * 152
        ram = _make_space(big_endian=False)
        const_spc = _make_const_space()
        uniq = _make_unique_space()
        arch = StubArch(StubLoadImage(data))
        inst = OpBehavior.registerInstructions(None)

        emu = EmulateSnippet(arch)
        # Set up space resolver so LOAD can find the target space
        spaces = {ram.getIndex(): ram}
        emu._spaceResolver = lambda idx: spaces.get(idx)

        emitter = emu.buildEmitter(inst, 0x1000)
        addr = Address(ram, 0)

        spc_vn = VarnodeData()
        spc_vn.space = const_spc
        spc_vn.offset = ram.getIndex()
        spc_vn.size = 4

        off_vn = VarnodeData()
        off_vn.space = const_spc
        off_vn.offset = 0x100
        off_vn.size = 4

        out_vn = VarnodeData()
        out_vn.space = uniq
        out_vn.offset = 0x200
        out_vn.size = 4

        emitter.dump(addr, OpCode.CPUI_LOAD, out_vn, [spc_vn, off_vn], 2)
        emu.resetMemory()
        emu.executeCurrentOp()
        assert emu.getTempValue(0x200) == 0x12345678


if __name__ == '__main__':
    pytest.main([__file__, '-v'])
