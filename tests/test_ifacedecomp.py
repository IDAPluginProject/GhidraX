"""Tests for ghidra.console.ifacedecomp — decompiler CLI commands."""
from __future__ import annotations

import io

import pytest

from ghidra.console.interface import (
    IfaceStatus, IfaceData, IfaceCommand, IfaceCapability,
    IfaceParseError, IfaceExecutionError,
)
from ghidra.console.ifacedecomp import (
    IfaceDecompCapability, IfaceDecompData, IfaceDecompCommand,
    IfaceAssemblyEmit,
    IfcComment, IfcSource, IfcOption, IfcAdjustVma,
    IfcFuncload, IfcCleararch, IfcReadSymbols,
    IfcDecompile, IfcContinue,
    IfcPrintCStruct, IfcPrintCFlat, IfcPrintCGlobals,
    IfcPrintSpaces, IfcListaction, IfcListprototypes,
    IfcPrintLanguage, IfcProduceC, IfcProducePrototypes,
    IfcParseLine, IfcParseFile,
    IfcMapaddress, IfcMaphash, IfcMapParam, IfcMapReturn,
    IfcMapfunction, IfcMapexternalref, IfcMaplabel,
    IfcRename, IfcRetype, IfcRemove, IfcIsolate,
    IfcCallGraphBuild, IfcCallGraphBuildQuick,
    IfcLoadTestFile, IfcListTestCommands, IfcExecuteTestCommand,
    execute, mainloop,
)
from ghidra.console.ifaceterm import IfaceTerm


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

class SimpleStatus(IfaceStatus):
    """Minimal IfaceStatus for testing."""
    def __init__(self):
        self._buf = io.StringIO()
        super().__init__("> ", self._buf)
        self._lines = []

    def feed(self, *lines):
        self._lines = list(lines)

    def readLine(self) -> str:
        if self._lines:
            return self._lines.pop(0)
        return ""

    def isStreamFinished(self) -> bool:
        return not self._lines

    def getOutput(self) -> str:
        return self._buf.getvalue()


# ---------------------------------------------------------------------------
# IfaceDecompData
# ---------------------------------------------------------------------------

class TestIfaceDecompData:
    def test_defaults(self):
        d = IfaceDecompData()
        assert d.fd is None
        assert d.conf is None
        assert d.cgraph is None
        assert isinstance(d, IfaceData)

    def test_clear_architecture(self):
        d = IfaceDecompData()
        d.conf = "fake_arch"
        d.fd = "fake_fd"
        d.clearArchitecture()
        assert d.conf is None
        assert d.fd is None

    def test_abort_function_none(self):
        d = IfaceDecompData()
        buf = io.StringIO()
        d.abortFunction(buf)  # should not raise
        assert buf.getvalue() == ""

    def test_abort_function_with_fd(self):
        d = IfaceDecompData()

        class FakeFd:
            def getName(self):
                return "myfunc"

        class FakeConf:
            def clearAnalysis(self, fd):
                pass

        d.fd = FakeFd()
        d.conf = FakeConf()
        buf = io.StringIO()
        d.abortFunction(buf)
        assert "myfunc" in buf.getvalue()
        assert d.fd is None

    def test_allocate_callgraph(self):
        d = IfaceDecompData()
        d.allocateCallGraph()
        # Placeholder — just verifies no crash


# ---------------------------------------------------------------------------
# IfaceDecompCommand
# ---------------------------------------------------------------------------

class TestIfaceDecompCommand:
    def test_module_name(self):
        cmd = IfcComment()
        assert cmd.getModule() == "decompile"

    def test_create_data(self):
        cmd = IfcComment()
        data = cmd.createData()
        assert isinstance(data, IfaceDecompData)

    def test_setData(self):
        status = SimpleStatus()
        data = IfaceDecompData()
        cmd = IfcComment()
        cmd.setData(status, data)
        assert cmd.status is status
        assert cmd.dcp is data

    def test_iterate_no_arch_raises(self):
        cmd = IfcComment()
        cmd.dcp = IfaceDecompData()
        with pytest.raises(IfaceExecutionError, match="No architecture"):
            cmd.iterateFunctionsAddrOrder()

    def test_iterate_leaf_no_callgraph_raises(self):
        cmd = IfcComment()
        cmd.dcp = IfaceDecompData()
        cmd.dcp.conf = "fake"
        with pytest.raises(IfaceExecutionError, match="No callgraph"):
            cmd.iterateFunctionsLeafOrder()


# ---------------------------------------------------------------------------
# IfaceAssemblyEmit
# ---------------------------------------------------------------------------

class TestIfaceAssemblyEmit:
    def test_dump(self):
        buf = io.StringIO()
        emit = IfaceAssemblyEmit(buf, 10)

        class FakeAddr:
            def __str__(self):
                return "0x401000"
        emit.dump(FakeAddr(), "NOP", "")
        out = buf.getvalue()
        assert "0x401000" in out
        assert "NOP" in out

    def test_dump_with_padding(self):
        buf = io.StringIO()
        emit = IfaceAssemblyEmit(buf, 15)
        emit.dump("addr", "MOV", "EAX, EBX")
        out = buf.getvalue()
        assert "MOV" in out
        assert "EAX, EBX" in out


# ---------------------------------------------------------------------------
# IfcComment
# ---------------------------------------------------------------------------

class TestIfcComment:
    def test_execute_does_nothing(self):
        cmd = IfcComment()
        cmd.execute("anything here")  # Should not raise


# ---------------------------------------------------------------------------
# IfcSource
# ---------------------------------------------------------------------------

class TestIfcSource:
    def test_no_filename_raises(self):
        cmd = IfcSource()
        cmd.status = SimpleStatus()
        with pytest.raises(IfaceParseError, match="No filename"):
            cmd.execute("")

    def test_pushes_script(self):
        status = SimpleStatus()
        cmd = IfcSource()
        cmd.status = status
        # SimpleStatus.pushScript just stores the prompt, doesn't open files
        cmd.execute("somefile.txt")
        assert status.getNumInputStreamSize() == 1


# ---------------------------------------------------------------------------
# IfcOption
# ---------------------------------------------------------------------------

class TestIfcOption:
    def test_no_arch_raises(self):
        cmd = IfcOption()
        cmd.dcp = IfaceDecompData()
        with pytest.raises(IfaceExecutionError, match="No load image"):
            cmd.execute("someoption")

    def test_no_option_name_raises(self):
        cmd = IfcOption()
        cmd.dcp = IfaceDecompData()
        cmd.dcp.conf = "fake"
        with pytest.raises(IfaceParseError, match="Missing option"):
            cmd.execute("")

    def test_too_many_params_raises(self):
        cmd = IfcOption()
        cmd.dcp = IfaceDecompData()
        cmd.dcp.conf = "fake"
        with pytest.raises(IfaceParseError, match="Too many"):
            cmd.execute("opt p1 p2 p3 p4")


# ---------------------------------------------------------------------------
# IfcAdjustVma
# ---------------------------------------------------------------------------

class TestIfcAdjustVma:
    def test_no_arch_raises(self):
        cmd = IfcAdjustVma()
        cmd.dcp = IfaceDecompData()
        with pytest.raises(IfaceExecutionError, match="No load image"):
            cmd.execute("0x1000")

    def test_no_param_raises(self):
        cmd = IfcAdjustVma()
        cmd.dcp = IfaceDecompData()
        cmd.dcp.conf = "fake"
        with pytest.raises(IfaceParseError, match="No adjustment"):
            cmd.execute("")

    def test_zero_raises(self):
        cmd = IfcAdjustVma()
        cmd.dcp = IfaceDecompData()
        cmd.dcp.conf = "fake"
        with pytest.raises(IfaceParseError, match="No adjustment"):
            cmd.execute("0")

    def test_adjusts_loader(self):
        cmd = IfcAdjustVma()
        cmd.dcp = IfaceDecompData()

        class FakeLoader:
            adjusted = 0
            def adjustVma(self, val):
                self.adjusted = val

        class FakeConf:
            loader = FakeLoader()

        cmd.dcp.conf = FakeConf()
        cmd.execute("0x1000")
        assert cmd.dcp.conf.loader.adjusted == 0x1000


# ---------------------------------------------------------------------------
# IfcCleararch
# ---------------------------------------------------------------------------

class TestIfcCleararch:
    def test_clears(self):
        cmd = IfcCleararch()
        cmd.dcp = IfaceDecompData()
        cmd.dcp.conf = "fake"
        cmd.dcp.fd = "fake"
        cmd.execute("")
        assert cmd.dcp.conf is None
        assert cmd.dcp.fd is None


# ---------------------------------------------------------------------------
# IfcDecompile
# ---------------------------------------------------------------------------

class TestIfcDecompile:
    def test_no_function_raises(self):
        cmd = IfcDecompile()
        cmd.dcp = IfaceDecompData()
        with pytest.raises(IfaceExecutionError, match="No function"):
            cmd.execute("")

    def test_no_code_prints_message(self):
        cmd = IfcDecompile()
        cmd.dcp = IfaceDecompData()

        class FakeFd:
            def hasNoCode(self):
                return True
            def getName(self):
                return "stub"

        cmd.dcp.fd = FakeFd()
        cmd.dcp.conf = "fake"
        buf = io.StringIO()
        cmd.status = SimpleStatus()
        cmd.status.optr = buf
        cmd.execute("")
        assert "No code for stub" in buf.getvalue()


# ---------------------------------------------------------------------------
# IfcPrintLanguage
# ---------------------------------------------------------------------------

class TestIfcPrintLanguage:
    def test_no_arch_raises(self):
        cmd = IfcPrintLanguage()
        cmd.dcp = IfaceDecompData()
        with pytest.raises(IfaceExecutionError, match="No load image"):
            cmd.execute("c-language")

    def test_no_lang_raises(self):
        cmd = IfcPrintLanguage()
        cmd.dcp = IfaceDecompData()
        cmd.dcp.conf = "fake"
        with pytest.raises(IfaceParseError, match="No language"):
            cmd.execute("")


# ---------------------------------------------------------------------------
# IfcFuncload
# ---------------------------------------------------------------------------

class TestIfcFuncload:
    def test_no_arch_raises(self):
        cmd = IfcFuncload()
        cmd.dcp = IfaceDecompData()
        with pytest.raises(IfaceExecutionError, match="No image"):
            cmd.execute("main")

    def test_no_name_raises(self):
        cmd = IfcFuncload()
        cmd.dcp = IfaceDecompData()
        cmd.dcp.conf = "fake"
        with pytest.raises(IfaceParseError, match="Missing function"):
            cmd.execute("")


# ---------------------------------------------------------------------------
# Stub commands raise IfaceExecutionError
# ---------------------------------------------------------------------------

class TestStubCommands:
    """Verify stub commands raise IfaceExecutionError with 'not yet implemented'."""

    @pytest.mark.parametrize("cls", [
        IfcParseLine, IfcParseFile,
        IfcMapaddress, IfcMaphash, IfcMapParam, IfcMapReturn,
        IfcMapfunction, IfcMapexternalref, IfcMaplabel,
        IfcRename, IfcRetype, IfcRemove, IfcIsolate,
        IfcCallGraphBuild, IfcCallGraphBuildQuick,
        IfcLoadTestFile, IfcListTestCommands, IfcExecuteTestCommand,
    ])
    def test_stub_raises(self, cls):
        cmd = cls()
        cmd.dcp = IfaceDecompData()
        cmd.dcp.conf = "fake"
        cmd.dcp.fd = "fake"
        with pytest.raises(IfaceExecutionError, match="not yet implemented"):
            cmd.execute("args")


# ---------------------------------------------------------------------------
# IfaceDecompCapability
# ---------------------------------------------------------------------------

class TestIfaceDecompCapability:
    def test_singleton(self):
        cap1 = IfaceDecompCapability.getInstance()
        cap2 = IfaceDecompCapability.getInstance()
        assert cap1 is cap2

    def test_name(self):
        cap = IfaceDecompCapability.getInstance()
        assert cap.getName() == "decomp"

    def test_is_capability(self):
        cap = IfaceDecompCapability()
        assert isinstance(cap, IfaceCapability)

    def test_register_commands(self):
        status = SimpleStatus()
        cap = IfaceDecompCapability()
        cap.registerCommands(status)
        # Should have registered many commands
        assert len(status._comlist) > 50


# ---------------------------------------------------------------------------
# Integration: IfaceTerm + DecompCapability
# ---------------------------------------------------------------------------

class TestIfaceTermIntegration:
    def test_comment_command(self):
        inp = io.StringIO("// this is a comment\nquit\n")
        out = io.StringIO()
        term = IfaceTerm("> ", inp, out)
        cap = IfaceDecompCapability()
        cap.registerCommands(term)
        term.mainloop()
        assert term.done

    def test_quit_command(self):
        inp = io.StringIO("quit\n")
        out = io.StringIO()
        term = IfaceTerm("> ", inp, out)
        cap = IfaceDecompCapability()
        cap.registerCommands(term)
        term.mainloop()
        assert term.done

    def test_clear_architecture(self):
        inp = io.StringIO("clear architecture\nquit\n")
        out = io.StringIO()
        term = IfaceTerm("> ", inp, out)
        cap = IfaceDecompCapability()
        cap.registerCommands(term)
        term.mainloop()
        assert term.done

    def test_decompile_no_func_errors(self):
        inp = io.StringIO("decompile\nquit\n")
        out = io.StringIO()
        term = IfaceTerm("> ", inp, out)
        cap = IfaceDecompCapability()
        cap.registerCommands(term)
        term.mainloop()
        assert "ERROR" in out.getvalue() or "No function" in out.getvalue()


# ---------------------------------------------------------------------------
# execute() and mainloop() helpers
# ---------------------------------------------------------------------------

class TestExecuteAndMainloop:
    def test_execute_error_handling(self):
        status = SimpleStatus()
        cap = IfaceDecompCapability()
        cap.registerCommands(status)
        dcp = status.getData("decompile")
        status.feed("decompile")  # No function loaded → error
        execute(status, dcp)
        assert "ERROR" in status.getOutput() or "No function" in status.getOutput()

    def test_mainloop_quit(self):
        status = SimpleStatus()
        cap = IfaceDecompCapability()
        cap.registerCommands(status)
        status.feed("quit")
        mainloop(status)
        assert status.done
