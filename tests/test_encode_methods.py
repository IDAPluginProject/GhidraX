"""Tests for encode methods: Varnode, PcodeOp, HighVariable, BlockEdge, Funcdata."""

import sys
import os
import io
import pytest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "python"))

from ghidra.core.marshal import (
    PackedDecode, PackedEncode,
    ELEM_ADDR, ELEM_VOID, ELEM_OP, ELEM_IOP, ELEM_SPACEID, ELEM_SEQNUM,
    ELEM_HIGH, ELEM_FUNCTION, ELEM_AST, ELEM_VARNODES,
    ELEM_BLOCK, ELEM_BLOCKEDGE, ELEM_HIGHLIST,
    ATTRIB_SPACE, ATTRIB_OFFSET, ATTRIB_SIZE, ATTRIB_REF,
    ATTRIB_GRP, ATTRIB_PERSISTS, ATTRIB_ADDRTIED, ATTRIB_UNAFF,
    ATTRIB_INPUT, ATTRIB_VOLATILE, ATTRIB_CODE, ATTRIB_VALUE,
    ATTRIB_NAME, ATTRIB_REPREF, ATTRIB_CLASS, ATTRIB_TYPELOCK,
    ATTRIB_SYMREF, ATTRIB_ID, ATTRIB_NOCODE, ATTRIB_INDEX,
)
from ghidra.core.address import Address, SeqNum
from ghidra.core.space import AddrSpace, IPTR_PROCESSOR, IPTR_CONSTANT, IPTR_IOP
from ghidra.core.opcodes import OpCode
from ghidra.ir.varnode import Varnode, VarnodeBank
from ghidra.ir.op import PcodeOp
from ghidra.ir.variable import HighVariable
from ghidra.block.block import BlockBasic, BlockGraph, BlockEdge


def _make_space(name="ram", tp=IPTR_PROCESSOR, idx=0, addrsize=4, wordsize=1):
    """Create a minimal AddrSpace for testing."""
    spc = AddrSpace.__new__(AddrSpace)
    spc._name = name
    spc._type = tp
    spc._index = idx
    spc._addrsize = addrsize
    spc._wordsize = wordsize
    spc._highest = (1 << (addrsize * 8)) - 1
    spc._pointerLowerBound = 0x100
    spc._pointerUpperBound = spc._highest
    spc._delay = 1
    spc._deadcodedelay = 2
    spc._shortcut = ' '
    spc._flags = 0
    return spc


def _make_const_space():
    """Create a constant space for testing."""
    return _make_space("const", IPTR_CONSTANT, 1)


def _make_iop_space():
    """Create an IOP space for testing."""
    return _make_space("iop", IPTR_IOP, 2)


def _decode(enc):
    """Create a decoder from an encoder's output."""
    dec = PackedDecode()
    dec.ingestBytes(enc.getBytes())
    return dec


# =========================================================================
# Varnode.encode tests
# =========================================================================

class TestVarnodeEncode:
    """Test Varnode.encode() produces correct packed format."""

    def test_basic_varnode_encode(self):
        """A simple varnode encodes addr element with space/offset/size + ref."""
        spc = _make_space("ram")
        addr = Address(spc, 0x1000)
        vn = Varnode.__new__(Varnode)
        vn._loc = addr
        vn._size = 4
        vn._create_index = 7
        vn._mergegroup = 0
        vn._flags = 0
        vn._addlflags = 0

        enc = PackedEncode()
        vn.encode(enc)
        dec = _decode(enc)

        eid = dec.openElement(ELEM_ADDR)
        assert dec.readString(ATTRIB_SPACE) == "ram"
        assert dec.readUnsignedInteger(ATTRIB_OFFSET) == 0x1000
        assert dec.readSignedInteger(ATTRIB_SIZE) == 4
        assert dec.readUnsignedInteger(ATTRIB_REF) == 7
        dec.closeElement(eid)

    def test_varnode_with_mergegroup(self):
        """Varnode with non-zero mergegroup writes grp attribute."""
        spc = _make_space("ram")
        vn = Varnode.__new__(Varnode)
        vn._loc = Address(spc, 0x2000)
        vn._size = 2
        vn._create_index = 3
        vn._mergegroup = 5
        vn._flags = 0
        vn._addlflags = 0

        enc = PackedEncode()
        vn.encode(enc)
        dec = _decode(enc)

        eid = dec.openElement(ELEM_ADDR)
        assert dec.readUnsignedInteger(ATTRIB_REF) == 3
        assert dec.readSignedInteger(ATTRIB_GRP) == 5
        dec.closeElement(eid)

    def test_varnode_with_flags(self):
        """Varnode flags (persist, addrtied, unaff, input, volatile) encode as bool attrs."""
        spc = _make_space("ram")
        vn = Varnode.__new__(Varnode)
        vn._loc = Address(spc, 0x100)
        vn._size = 1
        vn._create_index = 0
        vn._mergegroup = 0
        vn._flags = Varnode.persist | Varnode.addrtied | Varnode.insert | Varnode.unaffected
        vn._addlflags = 0

        enc = PackedEncode()
        vn.encode(enc)
        dec = _decode(enc)

        eid = dec.openElement(ELEM_ADDR)
        found = set()
        while True:
            aid = dec.getNextAttributeId()
            if aid == 0:
                break
            if aid == ATTRIB_PERSISTS.id:
                assert dec.readBool() is True
                found.add('persist')
            elif aid == ATTRIB_ADDRTIED.id:
                assert dec.readBool() is True
                found.add('addrtied')
            elif aid == ATTRIB_UNAFF.id:
                assert dec.readBool() is True
                found.add('unaff')
        assert {'persist', 'addrtied', 'unaff'}.issubset(found)
        dec.closeElement(eid)

    def test_varnode_input_flag(self):
        """Varnode with input flag."""
        spc = _make_space("ram")
        vn = Varnode.__new__(Varnode)
        vn._loc = Address(spc, 0x100)
        vn._size = 4
        vn._create_index = 10
        vn._mergegroup = 0
        vn._flags = Varnode.input
        vn._addlflags = 0

        enc = PackedEncode()
        vn.encode(enc)
        dec = _decode(enc)

        eid = dec.openElement(ELEM_ADDR)
        found_input = False
        while True:
            aid = dec.getNextAttributeId()
            if aid == 0:
                break
            if aid == ATTRIB_INPUT.id:
                assert dec.readBool() is True
                found_input = True
        assert found_input
        dec.closeElement(eid)


# =========================================================================
# PcodeOp.encode tests
# =========================================================================

class TestPcodeOpEncode:
    """Test PcodeOp.encode() produces correct packed format."""

    def _make_op(self, opcode, addr, output=None, inputs=None):
        """Build a minimal PcodeOp for testing."""
        op = PcodeOp.__new__(PcodeOp)
        op._opcode_enum = opcode
        op._start = SeqNum(addr, 0)
        op._output = output
        op._inrefs = inputs if inputs is not None else []
        op._flags = 0
        op._addlflags = 0
        op._parent = None
        op._opcode = None
        return op

    def _make_vn(self, spc, offset, size, idx):
        vn = Varnode.__new__(Varnode)
        vn._loc = Address(spc, offset)
        vn._size = size
        vn._create_index = idx
        vn._mergegroup = 0
        vn._flags = 0
        vn._addlflags = 0
        return vn

    def test_op_with_void_output(self):
        """Op with no output encodes <void> element for output."""
        spc = _make_space("ram")
        op = self._make_op(OpCode.CPUI_STORE, Address(spc, 0x1000))

        enc = PackedEncode()
        op.encode(enc)
        dec = _decode(enc)

        eid = dec.openElement(ELEM_OP)
        code_val = dec.readSignedInteger(ATTRIB_CODE)
        assert code_val == int(OpCode.CPUI_STORE)
        # SeqNum element
        sid = dec.openElement(ELEM_SEQNUM)
        dec.closeElement(sid)
        # void output
        vid = dec.openElement(ELEM_VOID)
        dec.closeElement(vid)
        dec.closeElement(eid)

    def test_op_with_output_ref(self):
        """Op with output encodes <addr ref=N> for output."""
        spc = _make_space("ram")
        out_vn = self._make_vn(spc, 0x2000, 4, 42)
        op = self._make_op(OpCode.CPUI_COPY, Address(spc, 0x1000), output=out_vn)

        enc = PackedEncode()
        op.encode(enc)
        dec = _decode(enc)

        eid = dec.openElement(ELEM_OP)
        dec.readSignedInteger(ATTRIB_CODE)
        # SeqNum
        sid = dec.openElement(ELEM_SEQNUM)
        dec.closeElement(sid)
        # output addr ref
        aid = dec.openElement(ELEM_ADDR)
        assert dec.readUnsignedInteger(ATTRIB_REF) == 42
        dec.closeElement(aid)
        dec.closeElement(eid)

    def test_op_with_input_refs(self):
        """Op with regular input varnodes encodes <addr ref=N> for each."""
        spc = _make_space("ram")
        in0 = self._make_vn(spc, 0x100, 4, 10)
        in1 = self._make_vn(spc, 0x200, 4, 11)
        op = self._make_op(OpCode.CPUI_INT_ADD, Address(spc, 0x1000),
                           output=self._make_vn(spc, 0x300, 4, 12),
                           inputs=[in0, in1])

        enc = PackedEncode()
        op.encode(enc)
        dec = _decode(enc)

        eid = dec.openElement(ELEM_OP)
        dec.readSignedInteger(ATTRIB_CODE)
        # SeqNum
        sid = dec.openElement(ELEM_SEQNUM)
        dec.closeElement(sid)
        # output
        a0 = dec.openElement(ELEM_ADDR)
        assert dec.readUnsignedInteger(ATTRIB_REF) == 12
        dec.closeElement(a0)
        # input 0
        a1 = dec.openElement(ELEM_ADDR)
        assert dec.readUnsignedInteger(ATTRIB_REF) == 10
        dec.closeElement(a1)
        # input 1
        a2 = dec.openElement(ELEM_ADDR)
        assert dec.readUnsignedInteger(ATTRIB_REF) == 11
        dec.closeElement(a2)
        dec.closeElement(eid)

    def test_op_null_input_encodes_void(self):
        """Null input varnode encodes as <void>."""
        spc = _make_space("ram")
        op = self._make_op(OpCode.CPUI_COPY, Address(spc, 0x1000),
                           inputs=[None])

        enc = PackedEncode()
        op.encode(enc)
        dec = _decode(enc)

        eid = dec.openElement(ELEM_OP)
        dec.readSignedInteger(ATTRIB_CODE)
        sid = dec.openElement(ELEM_SEQNUM)
        dec.closeElement(sid)
        # void output
        v1 = dec.openElement(ELEM_VOID)
        dec.closeElement(v1)
        # void input (from None)
        v2 = dec.openElement(ELEM_VOID)
        dec.closeElement(v2)
        dec.closeElement(eid)

    def test_op_constant_input_addr_ref(self):
        """Constant input (non-LOAD/STORE) encodes as <addr ref=N>."""
        cspc = _make_const_space()
        rspc = _make_space("ram")
        const_vn = self._make_vn(cspc, 0x42, 4, 99)
        op = self._make_op(OpCode.CPUI_INT_ADD, Address(rspc, 0x1000),
                           output=self._make_vn(rspc, 0x300, 4, 5),
                           inputs=[self._make_vn(rspc, 0x100, 4, 6), const_vn])

        enc = PackedEncode()
        op.encode(enc)
        dec = _decode(enc)

        eid = dec.openElement(ELEM_OP)
        dec.readSignedInteger(ATTRIB_CODE)
        sid = dec.openElement(ELEM_SEQNUM)
        dec.closeElement(sid)
        # output
        a0 = dec.openElement(ELEM_ADDR)
        dec.closeElement(a0)
        # input 0 (ram)
        a1 = dec.openElement(ELEM_ADDR)
        dec.closeElement(a1)
        # input 1 (constant) - should be <addr ref=99>
        a2 = dec.openElement(ELEM_ADDR)
        assert dec.readUnsignedInteger(ATTRIB_REF) == 99
        dec.closeElement(a2)
        dec.closeElement(eid)


# =========================================================================
# HighVariable.encode tests
# =========================================================================

class TestHighVariableEncode:
    """Test HighVariable.encode() produces correct packed format."""

    def _make_vn(self, spc, offset, size, idx, flags=0):
        vn = Varnode.__new__(Varnode)
        vn._loc = Address(spc, offset)
        vn._size = size
        vn._create_index = idx
        vn._mergegroup = 0
        vn._flags = flags
        vn._addlflags = 0
        vn._high = None
        vn._mapentry = None
        vn._def = None
        vn._descend = []
        vn._consumed = 0
        return vn

    def test_basic_high_encode(self):
        """HighVariable encodes <high> with repref, class, and instance addr refs."""
        spc = _make_space("ram")
        vn = self._make_vn(spc, 0x100, 4, 20)
        high = HighVariable(vn)
        high._highflags = 0
        high._nameRepresentative = vn
        high._flags = 0

        enc = PackedEncode()
        high.encode(enc)
        dec = _decode(enc)

        eid = dec.openElement(ELEM_HIGH)
        repref = dec.readUnsignedInteger(ATTRIB_REPREF)
        assert repref == 20
        cls = dec.readString(ATTRIB_CLASS)
        assert cls == "other"
        # instance <addr ref=20>
        aid = dec.openElement(ELEM_ADDR)
        assert dec.readUnsignedInteger(ATTRIB_REF) == 20
        dec.closeElement(aid)
        dec.closeElement(eid)

    def test_high_constant_class(self):
        """HighVariable with constant flag encodes class='constant'."""
        spc = _make_space("ram")
        vn = self._make_vn(spc, 0x100, 4, 30, flags=Varnode.constant)
        high = HighVariable(vn)
        high._highflags = 0
        high._nameRepresentative = vn
        high._flags = Varnode.constant

        enc = PackedEncode()
        high.encode(enc)
        dec = _decode(enc)

        eid = dec.openElement(ELEM_HIGH)
        dec.readUnsignedInteger(ATTRIB_REPREF)
        cls = dec.readString(ATTRIB_CLASS)
        assert cls == "constant"
        # consume instance addr
        aid = dec.openElement(ELEM_ADDR)
        dec.closeElement(aid)
        dec.closeElement(eid)

    def test_high_persist_addrtied_class(self):
        """HighVariable with persist+addrtied encodes class='global'."""
        spc = _make_space("ram")
        vn = self._make_vn(spc, 0x100, 4, 40, flags=Varnode.persist | Varnode.addrtied)
        high = HighVariable(vn)
        high._highflags = 0
        high._nameRepresentative = vn
        high._flags = Varnode.persist | Varnode.addrtied

        enc = PackedEncode()
        high.encode(enc)
        dec = _decode(enc)

        eid = dec.openElement(ELEM_HIGH)
        dec.readUnsignedInteger(ATTRIB_REPREF)
        cls = dec.readString(ATTRIB_CLASS)
        assert cls == "global"
        # consume instance addr
        aid = dec.openElement(ELEM_ADDR)
        dec.closeElement(aid)
        dec.closeElement(eid)

    def test_high_multiple_instances(self):
        """HighVariable with multiple instances encodes all addr refs."""
        spc = _make_space("ram")
        vn1 = self._make_vn(spc, 0x100, 4, 50)
        vn2 = self._make_vn(spc, 0x200, 4, 51)

        high = HighVariable(vn1)
        # Manually add second instance
        high._inst.append(vn2)
        vn2._high = high
        high._highflags = 0
        high._nameRepresentative = vn1
        high._flags = 0

        enc = PackedEncode()
        high.encode(enc)
        dec = _decode(enc)

        eid = dec.openElement(ELEM_HIGH)
        dec.readUnsignedInteger(ATTRIB_REPREF)
        dec.readString(ATTRIB_CLASS)
        # Two instance refs
        a1 = dec.openElement(ELEM_ADDR)
        ref1 = dec.readUnsignedInteger(ATTRIB_REF)
        dec.closeElement(a1)
        a2 = dec.openElement(ELEM_ADDR)
        ref2 = dec.readUnsignedInteger(ATTRIB_REF)
        dec.closeElement(a2)
        assert {ref1, ref2} == {50, 51}
        dec.closeElement(eid)


# =========================================================================
# BlockEdge.encode tests
# =========================================================================

class TestBlockEdgeEncode:
    """Test BlockEdge.encode() produces correct packed format."""

    def test_edge_encode(self):
        """BlockEdge encodes <edge> with end and rev attributes."""
        from ghidra.block.block import ELEM_EDGE, ATTRIB_END, ATTRIB_REV
        target = BlockBasic()
        target._index = 3
        edge = BlockEdge(target, 0, 2)

        enc = PackedEncode()
        edge.encode(enc)
        dec = _decode(enc)

        eid = dec.openElement(ELEM_EDGE)
        assert dec.readSignedInteger(ATTRIB_END) == 3
        assert dec.readSignedInteger(ATTRIB_REV) == 2
        dec.closeElement(eid)


# =========================================================================
# Funcdata.encode tests (integration)
# =========================================================================

class TestFuncdataEncode:
    """Test Funcdata encode methods with a lifted function."""

    def _build_simple_funcdata(self):
        """Build a minimal Funcdata with one block and one COPY op."""
        from ghidra.analysis.funcdata import Funcdata
        from ghidra.fspec.fspec import FuncProto

        spc = _make_space("ram")

        # Minimal architecture shim
        class _Arch:
            def numSpaces(self): return 1
            def getSpace(self, i): return spc if i == 0 else None
            def getConstantSpace(self): return _make_const_space()
            def getUniqueSpace(self): return None
            def getDefaultCodeSpace(self): return spc
            def getDefaultDataSpace(self): return spc
            def getStackSpace(self): return None
            def getIopSpace(self): return _make_iop_space()
            def printMessage(self, msg): pass

        arch = _Arch()
        fd = Funcdata.__new__(Funcdata)
        fd._glb = arch
        fd.name = "test_func"
        fd.size = 10
        fd.baseaddr = Address(spc, 0x1000)
        fd._flags = 0
        fd._clean_up_index = 0
        fd._high_level_index = 0
        fd._cast_phase_index = 0
        fd._vbank = VarnodeBank()
        fd._obank = None
        fd._bblocks = BlockGraph()
        fd._sblocks = BlockGraph()
        fd._localmap = None
        fd._functionSymbol = None
        fd.funcp = FuncProto.__new__(FuncProto)
        fd.funcp._model = None
        fd.funcp._store = None
        fd.funcp._effectlist = []
        fd.funcp._likelytrash = []
        fd.funcp._internalstorage = []
        fd.funcp._flags = 0
        fd.funcp._injectid = -1
        fd.funcp._returnBytesConsumed = 0

        # Create a varnode
        vn_addr = Address(spc, 0x100)
        vn = fd._vbank.create(4, vn_addr)

        # Create a basic block
        bb = BlockBasic()
        bb._index = 0
        fd._bblocks.addBlock(bb)

        # Create a PcodeOp
        op = PcodeOp.__new__(PcodeOp)
        op._opcode_enum = OpCode.CPUI_COPY
        op._start = SeqNum(Address(spc, 0x1000), 0)
        op._output = None
        op._inrefs = []
        op._flags = 0
        op._addlflags = 0
        op._parent = bb
        op._opcode = None
        bb.addOp(op)

        return fd, spc, vn, bb, op

    def test_encode_tree_structure(self):
        """encodeTree produces <ast> with <varnodes> and <block> elements."""
        fd, spc, vn, bb, op = self._build_simple_funcdata()

        enc = PackedEncode()
        fd.encodeTree(enc)
        dec = _decode(enc)

        # <ast>
        ast_id = dec.openElement(ELEM_AST)
        # <varnodes>
        vn_id = dec.openElement(ELEM_VARNODES)
        # Should have the varnode encoded inside
        addr_id = dec.openElement(ELEM_ADDR)
        assert dec.readString(ATTRIB_SPACE) == "ram"
        assert dec.readUnsignedInteger(ATTRIB_OFFSET) == 0x100
        dec.closeElement(addr_id)
        dec.closeElement(vn_id)

        # <block index=0> — contains encodeBody (rangelist) + ops
        from ghidra.core.marshal import ELEM_RANGELIST
        blk_id = dec.openElement(ELEM_BLOCK)
        assert dec.readSignedInteger(ATTRIB_INDEX) == 0
        # block body: rangelist from BlockBasic.encodeBody
        rl_id = dec.openElement(ELEM_RANGELIST)
        dec.closeElement(rl_id)
        # Then the op inside the block
        op_id = dec.openElement(ELEM_OP)
        assert dec.readSignedInteger(ATTRIB_CODE) == int(OpCode.CPUI_COPY)
        dec.closeElementSkipping(op_id)
        dec.closeElement(blk_id)

        dec.closeElement(ast_id)

    def test_encode_high_when_not_high_on(self):
        """encodeHigh does nothing when high-level is not on."""
        fd, *_ = self._build_simple_funcdata()

        enc = PackedEncode()
        fd.encodeHigh(enc)
        # Should produce no output since highlevel_on flag is not set
        data = enc.getBytes()
        assert len(data) == 0

    def test_encode_jumptable_when_empty(self):
        """encodeJumpTable does nothing when no jump tables."""
        fd, *_ = self._build_simple_funcdata()

        enc = PackedEncode()
        fd.encodeJumpTable(enc)
        data = enc.getBytes()
        assert len(data) == 0

    def test_encode_function_structure(self):
        """Funcdata.encode() produces <function> with name, size, addr."""
        fd, *_ = self._build_simple_funcdata()

        enc = PackedEncode()
        fd.encode(enc, uid=0, savetree=False)
        dec = _decode(enc)

        fid = dec.openElement(ELEM_FUNCTION)
        assert dec.readString(ATTRIB_NAME) == "test_func"
        assert dec.readSignedInteger(ATTRIB_SIZE) == 10
        # Address element for baseaddr
        addr_id = dec.openElement(ELEM_ADDR)
        assert dec.readString(ATTRIB_SPACE) == "ram"
        assert dec.readUnsignedInteger(ATTRIB_OFFSET) == 0x1000
        dec.closeElement(addr_id)
        dec.closeElementSkipping(fid)

    def test_encode_function_with_id(self):
        """Funcdata.encode() with uid writes ATTRIB_ID."""
        fd, *_ = self._build_simple_funcdata()

        enc = PackedEncode()
        fd.encode(enc, uid=12345, savetree=False)
        dec = _decode(enc)

        fid = dec.openElement(ELEM_FUNCTION)
        assert dec.readUnsignedInteger(ATTRIB_ID) == 12345
        assert dec.readString(ATTRIB_NAME) == "test_func"
        dec.closeElementSkipping(fid)

    def test_encode_function_with_savetree(self):
        """Funcdata.encode() with savetree=True includes AST."""
        fd, *_ = self._build_simple_funcdata()

        enc = PackedEncode()
        fd.encode(enc, savetree=True)
        dec = _decode(enc)

        fid = dec.openElement(ELEM_FUNCTION)
        dec.readString(ATTRIB_NAME)
        dec.readSignedInteger(ATTRIB_SIZE)
        # baseaddr
        a0 = dec.openElement(ELEM_ADDR)
        dec.closeElement(a0)
        # AST should follow
        ast_id = dec.openElement(ELEM_AST)
        assert ast_id is not None
        dec.closeElementSkipping(ast_id)
        dec.closeElementSkipping(fid)

    def test_encodeVarnode_iterates(self):
        """encodeVarnode encodes each varnode in the iterable."""
        fd, spc, *_ = self._build_simple_funcdata()

        vn1 = Varnode.__new__(Varnode)
        vn1._loc = Address(spc, 0x10)
        vn1._size = 4
        vn1._create_index = 100
        vn1._mergegroup = 0
        vn1._flags = 0
        vn1._addlflags = 0

        vn2 = Varnode.__new__(Varnode)
        vn2._loc = Address(spc, 0x20)
        vn2._size = 2
        vn2._create_index = 101
        vn2._mergegroup = 0
        vn2._flags = 0
        vn2._addlflags = 0

        enc = PackedEncode()
        fd.encodeVarnode(enc, [vn1, vn2])
        dec = _decode(enc)

        a1 = dec.openElement(ELEM_ADDR)
        assert dec.readUnsignedInteger(ATTRIB_REF) == 100
        dec.closeElement(a1)
        a2 = dec.openElement(ELEM_ADDR)
        assert dec.readUnsignedInteger(ATTRIB_REF) == 101
        dec.closeElement(a2)


# =========================================================================
# Marshal constant ID correctness tests
# =========================================================================

class TestMarshalConstants:
    """Verify that critical marshal.py constants match C++ IDs."""

    def test_common_attrib_ids(self):
        assert ATTRIB_NAME.id == 14
        assert ATTRIB_SIZE.id == 19
        assert ATTRIB_SPACE.id == 20
        assert ATTRIB_OFFSET.id == 16
        assert ATTRIB_REF.id == 18
        assert ATTRIB_VALUE.id == 25
        assert ATTRIB_ID.id == 9
        assert ATTRIB_CODE.id == 43
        assert ATTRIB_INDEX.id == 10

    def test_varnode_attrib_ids(self):
        assert ATTRIB_ADDRTIED.id == 30
        assert ATTRIB_GRP.id == 31
        assert ATTRIB_INPUT.id == 32
        assert ATTRIB_PERSISTS.id == 33
        assert ATTRIB_UNAFF.id == 34

    def test_variable_attrib_ids(self):
        assert ATTRIB_REPREF.id == 67
        assert ATTRIB_SYMREF.id == 68
        assert ATTRIB_CLASS.id == 66

    def test_common_elem_ids(self):
        assert ELEM_ADDR.id == 11
        assert ELEM_VOID.id == 10
        assert ELEM_OP.id == 27
        assert ELEM_SPACEID.id == 30
        assert ELEM_HIGH.id == 82
        assert ELEM_FUNCTION.id == 116

    def test_funcdata_elem_ids(self):
        assert ELEM_AST.id == 115
        assert ELEM_VARNODES.id == 119
        assert ELEM_HIGHLIST.id == 117

    def test_translate_attrib_ids(self):
        from ghidra.core.marshal import (
            ATTRIB_CONTAIN, ATTRIB_DEFAULTSPACE, ATTRIB_UNIQBASE,
        )
        assert ATTRIB_CONTAIN.id == 44
        assert ATTRIB_DEFAULTSPACE.id == 45
        assert ATTRIB_UNIQBASE.id == 46

    def test_space_attrib_ids(self):
        from ghidra.core.marshal import (
            ATTRIB_BASE, ATTRIB_DEADCODEDELAY, ATTRIB_DELAY,
            ATTRIB_LOGICALSIZE, ATTRIB_PHYSICAL, ATTRIB_PIECE,
        )
        assert ATTRIB_BASE.id == 89
        assert ATTRIB_DEADCODEDELAY.id == 90
        assert ATTRIB_DELAY.id == 91
        assert ATTRIB_LOGICALSIZE.id == 92
        assert ATTRIB_PHYSICAL.id == 93
        assert ATTRIB_PIECE.id == 94

    def test_database_attrib_ids(self):
        from ghidra.core.marshal import ATTRIB_CAT, ATTRIB_FIELD, ATTRIB_MERGE
        assert ATTRIB_CAT.id == 61
        assert ATTRIB_FIELD.id == 62
        assert ATTRIB_MERGE.id == 63

    def test_block_attrib_ids(self):
        from ghidra.core.marshal import (
            ATTRIB_ALTINDEX, ATTRIB_DEPTH, ATTRIB_END, ATTRIB_OPCODE, ATTRIB_REV,
        )
        assert ATTRIB_ALTINDEX.id == 75
        assert ATTRIB_DEPTH.id == 76
        assert ATTRIB_END.id == 77
        assert ATTRIB_OPCODE.id == 78
        assert ATTRIB_REV.id == 79

    def test_translate_elem_ids(self):
        from ghidra.core.marshal import (
            ELEM_SLEIGH, ELEM_SPACE, ELEM_SPACES,
            ELEM_SPACE_BASE, ELEM_SPACE_OTHER, ELEM_SPACE_OVERLAY,
            ELEM_SPACE_UNIQUE, ELEM_TRUNCATE_SPACE,
        )
        assert ELEM_SLEIGH.id == 28
        assert ELEM_SPACE.id == 29
        assert ELEM_SPACES.id == 31
        assert ELEM_SPACE_BASE.id == 32
        assert ELEM_SPACE_OTHER.id == 33
        assert ELEM_SPACE_OVERLAY.id == 34
        assert ELEM_SPACE_UNIQUE.id == 35
        assert ELEM_TRUNCATE_SPACE.id == 36

    def test_context_elem_ids(self):
        from ghidra.core.marshal import (
            ELEM_TRACKED_POINTSET, ELEM_TRACKED_SET, ELEM_SET,
        )
        assert ELEM_TRACKED_POINTSET.id == 125
        assert ELEM_TRACKED_SET.id == 126
        assert ELEM_SET.id == 124

    def test_op_elem_ids(self):
        from ghidra.core.marshal import ELEM_IOP, ELEM_UNIMPL
        assert ELEM_IOP.id == 113
        assert ELEM_UNIMPL.id == 114

    def test_block_elem_ids(self):
        from ghidra.core.marshal import ELEM_BHEAD, ELEM_BLOCK, ELEM_BLOCKEDGE, ELEM_EDGE
        assert ELEM_BHEAD.id == 102
        assert ELEM_BLOCK.id == 103
        assert ELEM_BLOCKEDGE.id == 104
        assert ELEM_EDGE.id == 105

    def test_funcdata_nocode_id(self):
        assert ATTRIB_NOCODE.id == 84
