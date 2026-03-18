"""
Integration test: Verify that Lifter converts sleigh_native output into
pure Python IR objects (Funcdata, Varnode, PcodeOp, Address, AddrSpace).

This is the critical migration validation — proves the pure Python classes
are actually used in a real lifting pipeline, not just unit-tested in isolation.
"""

import sys
import os
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', 'python'))

import pytest
from ghidra.sleigh.arch_map import resolve_arch, find_sla
from pattern_corpus import X86_NOP_RET, X86_SIMPLE_FUNC, X86_ADD_ARGS

# Skip all tests if sleigh_native is not available
try:
    from ghidra.sleigh.lifter import Lifter
    HAS_SLEIGH = True
except ImportError:
    HAS_SLEIGH = False

pytestmark = pytest.mark.skipif(not HAS_SLEIGH, reason="sleigh_native not available")


@pytest.fixture(scope="module")
def x86_lifter():
    """Create an x86-32 Lifter."""
    info = resolve_arch("metapc", 32, False)
    lifter = Lifter(info["sla_path"], info["context"])
    return lifter


class TestLifterCreatessPythonIR:
    """Verify that the Lifter produces pure Python IR objects, not C++ wrappers."""

    def test_lifter_returns_funcdata(self, x86_lifter):
        """Lifter.lift_function must return a Python Funcdata."""
        from ghidra.analysis.funcdata import Funcdata
        x86_lifter.set_image(0x401000, X86_NOP_RET)
        fd = x86_lifter.lift_function("nop_ret", 0x401000, len(X86_NOP_RET))
        assert isinstance(fd, Funcdata), f"Expected Funcdata, got {type(fd)}"

    def test_funcdata_has_python_address(self, x86_lifter):
        """Funcdata.getAddress() must return a Python Address."""
        from ghidra.core.address import Address
        x86_lifter.set_image(0x401000, X86_NOP_RET)
        fd = x86_lifter.lift_function("nop_ret", 0x401000, len(X86_NOP_RET))
        addr = fd.getAddress()
        assert isinstance(addr, Address), f"Expected Address, got {type(addr)}"
        assert addr.getOffset() == 0x401000

    def test_funcdata_address_has_python_addrspace(self, x86_lifter):
        """Address.getSpace() must return a Python AddrSpace."""
        from ghidra.core.space import AddrSpace
        x86_lifter.set_image(0x401000, X86_NOP_RET)
        fd = x86_lifter.lift_function("nop_ret", 0x401000, len(X86_NOP_RET))
        spc = fd.getAddress().getSpace()
        assert isinstance(spc, AddrSpace), f"Expected AddrSpace, got {type(spc)}"

    def test_funcdata_has_python_varnodes(self, x86_lifter):
        """All Varnodes in the VarnodeBank must be pure Python Varnode objects."""
        from ghidra.ir.varnode import Varnode
        x86_lifter.set_image(0x401000, X86_SIMPLE_FUNC)
        fd = x86_lifter.lift_function("simple", 0x401000, len(X86_SIMPLE_FUNC))
        vbank = fd.getVarnodeBank()
        count = 0
        for vn in vbank.beginDef():
            assert isinstance(vn, Varnode), f"Expected Varnode, got {type(vn)}"
            count += 1
        assert count > 0, "VarnodeBank should have defined varnodes"

    def test_funcdata_has_python_pcodeops(self, x86_lifter):
        """All PcodeOps in the PcodeOpBank must be pure Python PcodeOp objects."""
        from ghidra.ir.op import PcodeOp
        x86_lifter.set_image(0x401000, X86_SIMPLE_FUNC)
        fd = x86_lifter.lift_function("simple", 0x401000, len(X86_SIMPLE_FUNC))
        obank = fd.getOpBank()
        alive = list(obank.beginAlive())
        assert len(alive) > 0, "Should have alive PcodeOps"
        for op in alive:
            assert isinstance(op, PcodeOp), f"Expected PcodeOp, got {type(op)}"

    def test_pcodeop_has_python_seqnum(self, x86_lifter):
        """PcodeOp.getSeqNum() must return a Python SeqNum."""
        from ghidra.core.address import SeqNum
        x86_lifter.set_image(0x401000, X86_SIMPLE_FUNC)
        fd = x86_lifter.lift_function("simple", 0x401000, len(X86_SIMPLE_FUNC))
        obank = fd.getOpBank()
        for op in obank.beginAlive():
            sq = op.getSeqNum()
            assert isinstance(sq, SeqNum), f"Expected SeqNum, got {type(sq)}"
            break  # check at least one

    def test_pcodeop_inputs_are_python_varnodes(self, x86_lifter):
        """PcodeOp inputs must be pure Python Varnode objects."""
        from ghidra.ir.varnode import Varnode
        x86_lifter.set_image(0x401000, X86_SIMPLE_FUNC)
        fd = x86_lifter.lift_function("simple", 0x401000, len(X86_SIMPLE_FUNC))
        checked = 0
        for op in fd.getOpBank().beginAlive():
            for i in range(op.numInput()):
                vn = op.getIn(i)
                if vn is not None:
                    assert isinstance(vn, Varnode), f"Input {i} not Varnode: {type(vn)}"
                    checked += 1
        assert checked > 0

    def test_pcodeop_output_is_python_varnode(self, x86_lifter):
        """PcodeOp output must be a pure Python Varnode."""
        from ghidra.ir.varnode import Varnode
        x86_lifter.set_image(0x401000, X86_SIMPLE_FUNC)
        fd = x86_lifter.lift_function("simple", 0x401000, len(X86_SIMPLE_FUNC))
        checked = 0
        for op in fd.getOpBank().beginAlive():
            out = op.getOut()
            if out is not None:
                assert isinstance(out, Varnode), f"Output not Varnode: {type(out)}"
                checked += 1
        assert checked > 0

    def test_varnode_address_is_python(self, x86_lifter):
        """Varnode.getAddr() must return a Python Address."""
        from ghidra.core.address import Address
        x86_lifter.set_image(0x401000, X86_SIMPLE_FUNC)
        fd = x86_lifter.lift_function("simple", 0x401000, len(X86_SIMPLE_FUNC))
        for op in fd.getOpBank().beginAlive():
            for i in range(op.numInput()):
                vn = op.getIn(i)
                if vn is not None:
                    addr = vn.getAddr()
                    assert isinstance(addr, Address), f"Varnode addr not Address: {type(addr)}"
                    return
        pytest.fail("No varnodes found to check")


class TestLifterContentCorrectness:
    """Verify the lifted IR content is reasonable for known x86 code."""

    def test_nop_ret_ops(self, x86_lifter):
        """NOP+RET should produce at least a RETURN op."""
        from ghidra.core.opcodes import OpCode
        x86_lifter.set_image(0x401000, X86_NOP_RET)
        fd = x86_lifter.lift_function("nop_ret", 0x401000, len(X86_NOP_RET))
        opcodes = [op.code() for op in fd.getOpBank().beginAlive()]
        # NOPs produce COPY ops in SLEIGH, RET produces RETURN
        assert OpCode.CPUI_RETURN in opcodes, f"Expected RETURN in {opcodes}"

    def test_simple_func_has_copy_ops(self, x86_lifter):
        """push ebp; mov ebp,esp should produce COPY operations."""
        from ghidra.core.opcodes import OpCode
        x86_lifter.set_image(0x401000, X86_SIMPLE_FUNC)
        fd = x86_lifter.lift_function("simple", 0x401000, len(X86_SIMPLE_FUNC))
        opcodes = [op.code() for op in fd.getOpBank().beginAlive()]
        assert OpCode.CPUI_COPY in opcodes, f"Expected COPY in {opcodes}"

    def test_simple_func_has_int_xor(self, x86_lifter):
        """xor eax,eax should produce INT_XOR or INT_AND."""
        from ghidra.core.opcodes import OpCode
        x86_lifter.set_image(0x401000, X86_SIMPLE_FUNC)
        fd = x86_lifter.lift_function("simple", 0x401000, len(X86_SIMPLE_FUNC))
        opcodes = set(op.code() for op in fd.getOpBank().beginAlive())
        # xor eax,eax -> CPUI_INT_XOR
        assert OpCode.CPUI_INT_XOR in opcodes, f"Expected INT_XOR in {opcodes}"

    def test_add_args_has_int_add(self, x86_lifter):
        """add eax, [ebp+0xc] should produce INT_ADD."""
        from ghidra.core.opcodes import OpCode
        x86_lifter.set_image(0x401000, X86_ADD_ARGS)
        fd = x86_lifter.lift_function("add_args", 0x401000, len(X86_ADD_ARGS))
        opcodes = set(op.code() for op in fd.getOpBank().beginAlive())
        assert OpCode.CPUI_INT_ADD in opcodes, f"Expected INT_ADD in {opcodes}"

    def test_add_args_has_load(self, x86_lifter):
        """mov eax, [ebp+8] should produce LOAD."""
        from ghidra.core.opcodes import OpCode
        x86_lifter.set_image(0x401000, X86_ADD_ARGS)
        fd = x86_lifter.lift_function("add_args", 0x401000, len(X86_ADD_ARGS))
        opcodes = set(op.code() for op in fd.getOpBank().beginAlive())
        assert OpCode.CPUI_LOAD in opcodes, f"Expected LOAD in {opcodes}"

    def test_funcdata_name(self, x86_lifter):
        x86_lifter.set_image(0x401000, X86_SIMPLE_FUNC)
        fd = x86_lifter.lift_function("my_func", 0x401000, len(X86_SIMPLE_FUNC))
        assert fd.getName() == "my_func"

    def test_funcdata_size(self, x86_lifter):
        x86_lifter.set_image(0x401000, X86_SIMPLE_FUNC)
        fd = x86_lifter.lift_function("simple", 0x401000, len(X86_SIMPLE_FUNC))
        assert fd.getSize() == len(X86_SIMPLE_FUNC)


class TestLifterSpaces:
    """Verify address spaces are pure Python and correct."""

    def test_register_space_exists(self, x86_lifter):
        """Lifted code should reference 'register' space for register varnodes."""
        x86_lifter.set_image(0x401000, X86_SIMPLE_FUNC)
        fd = x86_lifter.lift_function("simple", 0x401000, len(X86_SIMPLE_FUNC))
        space_names = set()
        for op in fd.getOpBank().beginAlive():
            for i in range(op.numInput()):
                vn = op.getIn(i)
                if vn is not None:
                    space_names.add(vn.getSpace().getName())
            out = op.getOut()
            if out is not None:
                space_names.add(out.getSpace().getName())
        # Should see register, const, and possibly unique spaces
        assert "register" in space_names or "unique" in space_names, \
            f"Expected register/unique space, got {space_names}"

    def test_const_space_for_immediates(self, x86_lifter):
        """Immediate values should be in 'const' space."""
        x86_lifter.set_image(0x401000, X86_ADD_ARGS)
        fd = x86_lifter.lift_function("add_args", 0x401000, len(X86_ADD_ARGS))
        found_const = False
        for op in fd.getOpBank().beginAlive():
            for i in range(op.numInput()):
                vn = op.getIn(i)
                if vn is not None and vn.getSpace().getName() == "const":
                    found_const = True
                    break
            if found_const:
                break
        assert found_const, "Should find constant-space varnodes for immediates"


class TestPcodeTextOutput:
    """Verify the text-based PCode output works with the Python pipeline."""

    def test_pcode_text_not_empty(self, x86_lifter):
        x86_lifter.set_image(0x401000, X86_SIMPLE_FUNC)
        text = x86_lifter.pcode_text(0x401000, len(X86_SIMPLE_FUNC))
        assert len(text) > 0
        assert "COPY" in text or "INT_" in text or "STORE" in text

    def test_pcode_text_shows_addresses(self, x86_lifter):
        x86_lifter.set_image(0x401000, X86_SIMPLE_FUNC)
        text = x86_lifter.pcode_text(0x401000, len(X86_SIMPLE_FUNC))
        assert "0x401000" in text or "0x401000" in text.lower()
