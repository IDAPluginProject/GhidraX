"""
Test: Verify DecompilerPython provides the same interface as DecompilerNative
and produces output using pure Python IR objects.
"""

import sys
import os
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', 'python'))

import pytest
from ghidra.sleigh.arch_map import resolve_arch
from pattern_corpus import X86_SIMPLE, X86_ADD_ARGS

try:
    from ghidra.sleigh.decompiler_python import DecompilerPython, _ArchitectureShim
    HAS_SLEIGH = True
except ImportError:
    HAS_SLEIGH = False

pytestmark = pytest.mark.skipif(not HAS_SLEIGH, reason="sleigh_native not available")

X86_ADD = X86_ADD_ARGS


@pytest.fixture(scope="module")
def arch_info():
    return resolve_arch("metapc", 32, False)


@pytest.fixture(scope="module")
def decomp():
    d = DecompilerPython()
    d.initialize()
    return d


class TestDecompilerPythonInterface:
    """Verify DecompilerPython has the same interface as DecompilerNative."""

    def test_has_add_spec_path(self, decomp):
        assert hasattr(decomp, 'add_spec_path')
        assert callable(decomp.add_spec_path)

    def test_has_add_ghidra_root(self, decomp):
        assert hasattr(decomp, 'add_ghidra_root')
        assert callable(decomp.add_ghidra_root)

    def test_has_initialize(self, decomp):
        assert hasattr(decomp, 'initialize')
        assert callable(decomp.initialize)

    def test_has_decompile(self, decomp):
        assert hasattr(decomp, 'decompile')
        assert callable(decomp.decompile)

    def test_has_get_errors(self, decomp):
        assert hasattr(decomp, 'get_errors')
        assert callable(decomp.get_errors)

    def test_decompile_returns_string(self, decomp, arch_info):
        result = decomp.decompile(
            arch_info["sla_path"], arch_info["target"],
            X86_SIMPLE, 0x401000, 0x401000, len(X86_SIMPLE)
        )
        assert isinstance(result, str)

    def test_get_errors_returns_string(self, decomp):
        assert isinstance(decomp.get_errors(), str)


class TestDecompilerPythonOutput:
    """Verify the output contains expected content from pure Python IR."""

    def test_output_not_empty(self, decomp, arch_info):
        result = decomp.decompile(
            arch_info["sla_path"], arch_info["target"],
            X86_SIMPLE, 0x401000, 0x401000, len(X86_SIMPLE)
        )
        assert len(result.strip()) > 0

    def test_output_has_function_declaration(self, decomp, arch_info):
        result = decomp.decompile(
            arch_info["sla_path"], arch_info["target"],
            X86_SIMPLE, 0x401000, 0x401000, len(X86_SIMPLE)
        )
        assert "void func_401000" in result

    def test_output_has_return(self, decomp, arch_info):
        result = decomp.decompile(
            arch_info["sla_path"], arch_info["target"],
            X86_SIMPLE, 0x401000, 0x401000, len(X86_SIMPLE)
        )
        assert "return" in result

    def test_output_has_xor(self, decomp, arch_info):
        """xor eax, eax should produce ^ operator."""
        result = decomp.decompile(
            arch_info["sla_path"], arch_info["target"],
            X86_SIMPLE, 0x401000, 0x401000, len(X86_SIMPLE)
        )
        assert "^" in result

    def test_output_has_add(self, decomp, arch_info):
        """add instruction should produce + operator."""
        result = decomp.decompile(
            arch_info["sla_path"], arch_info["target"],
            X86_ADD, 0x401000, 0x401000, len(X86_ADD)
        )
        assert "+" in result

    def test_output_has_load(self, decomp, arch_info):
        """mov eax, [ebp+8] should produce load (dereference)."""
        result = decomp.decompile(
            arch_info["sla_path"], arch_info["target"],
            X86_ADD, 0x401000, 0x401000, len(X86_ADD)
        )
        assert "*" in result

    def test_output_has_pipeline_header(self, decomp, arch_info):
        """Output should indicate the Python pipeline is active."""
        result = decomp.decompile(
            arch_info["sla_path"], arch_info["target"],
            X86_SIMPLE, 0x401000, 0x401000, len(X86_SIMPLE)
        )
        assert "Python" in result
        assert "SLEIGH" in result

    def test_output_has_address_comments(self, decomp, arch_info):
        """Each statement should have an address comment."""
        result = decomp.decompile(
            arch_info["sla_path"], arch_info["target"],
            X86_SIMPLE, 0x401000, 0x401000, len(X86_SIMPLE)
        )
        assert "@0x401000" in result


class TestDecompilerPythonModuleFlags:
    """Verify module enable/disable flags work."""

    def test_default_flags(self):
        d = DecompilerPython()
        assert d.use_python_ir is True
        assert d.use_python_flow is True
        assert d.use_python_heritage is False
        assert d.use_python_rules is False
        assert d.use_python_printc is False

    def test_modules_header_reflects_state(self, decomp, arch_info):
        """The output header should show which modules are active."""
        result = decomp.decompile(
            arch_info["sla_path"], arch_info["target"],
            X86_SIMPLE, 0x401000, 0x401000, len(X86_SIMPLE)
        )
        assert "[IR(Python)]" in result
        assert "[FlowInfo(-)]" in result


class TestDecompilerPythonUsesRealPythonClasses:
    """Verify internally the pure Python classes are used, not C++ wrappers."""

    def test_internally_creates_python_funcdata(self, arch_info):
        """The Lifter internally produces Python Funcdata."""
        from ghidra.sleigh.lifter import Lifter
        from ghidra.analysis.funcdata import Funcdata

        lifter = Lifter(arch_info["sla_path"], arch_info["context"])
        lifter.set_image(0x401000, X86_SIMPLE)
        fd = lifter.lift_function("test", 0x401000, len(X86_SIMPLE))
        assert isinstance(fd, Funcdata)

    def test_internally_creates_python_varnodes(self, arch_info):
        from ghidra.sleigh.lifter import Lifter
        from ghidra.ir.varnode import Varnode

        lifter = Lifter(arch_info["sla_path"], arch_info["context"])
        lifter.set_image(0x401000, X86_SIMPLE)
        fd = lifter.lift_function("test", 0x401000, len(X86_SIMPLE))
        for vn in fd.getVarnodeBank().beginDef():
            assert isinstance(vn, Varnode)
            return
        pytest.fail("No varnodes found")

    def test_internally_creates_python_pcodeops(self, arch_info):
        from ghidra.sleigh.lifter import Lifter
        from ghidra.ir.op import PcodeOp

        lifter = Lifter(arch_info["sla_path"], arch_info["context"])
        lifter.set_image(0x401000, X86_SIMPLE)
        fd = lifter.lift_function("test", 0x401000, len(X86_SIMPLE))
        for op in fd.getOpBank().beginAlive():
            assert isinstance(op, PcodeOp)
            return
        pytest.fail("No PcodeOps found")

    def test_internally_creates_python_addresses(self, arch_info):
        from ghidra.sleigh.lifter import Lifter
        from ghidra.core.address import Address

        lifter = Lifter(arch_info["sla_path"], arch_info["context"])
        lifter.set_image(0x401000, X86_SIMPLE)
        fd = lifter.lift_function("test", 0x401000, len(X86_SIMPLE))
        assert isinstance(fd.getAddress(), Address)

    def test_internally_creates_python_addrspaces(self, arch_info):
        from ghidra.sleigh.lifter import Lifter
        from ghidra.core.space import AddrSpace

        lifter = Lifter(arch_info["sla_path"], arch_info["context"])
        lifter.set_image(0x401000, X86_SIMPLE)
        fd = lifter.lift_function("test", 0x401000, len(X86_SIMPLE))
        assert isinstance(fd.getAddress().getSpace(), AddrSpace)


class TestArchitectureShimContract:
    def test_shim_exposes_expected_defaults(self, arch_info):
        from ghidra.sleigh.lifter import Lifter

        lifter = Lifter(arch_info["sla_path"], arch_info["context"])
        shim = _ArchitectureShim(lifter._spc_mgr)

        assert shim.context is None
        assert shim.cpool is None
        assert shim.analyze_for_loops is False
        assert shim.nan_ignore_all is False
        assert shim.types is not None
        assert shim.types.getTypeVoid() is not None
        assert shim.types.getSizeOfPointer() == shim.getDefaultCodeSpace().getAddrSize()

    def test_shim_proxies_core_spaces(self, arch_info):
        from ghidra.sleigh.lifter import Lifter

        lifter = Lifter(arch_info["sla_path"], arch_info["context"])
        shim = _ArchitectureShim(lifter._spc_mgr)

        assert shim.numSpaces() == lifter._spc_mgr.numSpaces()
        assert shim.getSpace(0) is lifter._spc_mgr.getSpaceByIndex(0)
        assert shim.getConstantSpace() is lifter._spc_mgr._constantSpace
        assert shim.getUniqueSpace() is lifter._spc_mgr._uniqueSpace
        assert shim.getDefaultCodeSpace() is lifter._spc_mgr._defaultCodeSpace
        assert shim.getDefaultDataSpace() is lifter._spc_mgr._defaultDataSpace

    def test_shim_collects_and_drains_messages(self, arch_info):
        from ghidra.sleigh.lifter import Lifter

        lifter = Lifter(arch_info["sla_path"], arch_info["context"])
        shim = _ArchitectureShim(lifter._spc_mgr)

        shim.printMessage("alpha")
        shim.printMessage("beta")

        assert shim.getMessages() == ["alpha", "beta"]
        assert shim.drainMessages() == ["alpha", "beta"]
        assert shim.getMessages() == []
