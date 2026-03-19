"""Tests for ghidra.console.analyzesigs — console commands for signature analysis."""
from __future__ import annotations

import io
import pytest

from ghidra.analysis.signature import SigManager, GraphSigManager
from ghidra.console.analyzesigs import (
    IfcSignatureSettings,
    IfcPrintSignatures,
    IfcSaveSignatures,
    IfcSaveAllSignatures,
    IfcProduceSignatures,
    IfaceAnalyzeSigsCapability,
)
from ghidra.console.interface import IfaceParseError, IfaceExecutionError


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

class FakeOptr:
    def __init__(self):
        self.buf = io.StringIO()

    def write(self, s):
        self.buf.write(s)


class FakeStatus:
    def __init__(self):
        self.optr = FakeOptr()
        self.fileoptr = FakeOptr()

    def registerCom(self, cmd, *words):
        pass


class FakeFuncdata:
    def __init__(self, name="test_func", complete=True, has_code=True):
        self._name = name
        self._complete = complete
        self._has_code = has_code

    def getName(self):
        return self._name

    def isProcComplete(self):
        return self._complete

    def hasNoCode(self):
        return not self._has_code


class FakeDcp:
    def __init__(self, fd=None, conf=None):
        self.fd = fd
        self.conf = conf


# ---------------------------------------------------------------------------
# IfcSignatureSettings
# ---------------------------------------------------------------------------

class TestIfcSignatureSettings:
    def test_set_valid(self):
        old = SigManager.getSettings()
        try:
            cmd = IfcSignatureSettings()
            cmd.status = FakeStatus()
            cmd.execute("0x5")
            assert SigManager.getSettings() == 5
        finally:
            SigManager.setSettings(old)

    def test_empty_raises(self):
        cmd = IfcSignatureSettings()
        with pytest.raises(IfaceParseError):
            cmd.execute("")

    def test_zero_raises(self):
        cmd = IfcSignatureSettings()
        with pytest.raises(IfaceParseError):
            cmd.execute("0")

    def test_invalid_raises(self):
        cmd = IfcSignatureSettings()
        with pytest.raises(IfaceParseError):
            cmd.execute("not_a_number")


# ---------------------------------------------------------------------------
# IfcPrintSignatures
# ---------------------------------------------------------------------------

class TestIfcPrintSignatures:
    def test_no_function_raises(self):
        cmd = IfcPrintSignatures()
        cmd.dcp = FakeDcp()
        with pytest.raises(IfaceExecutionError, match="No function"):
            cmd.execute("")

    def test_not_complete_raises(self):
        cmd = IfcPrintSignatures()
        cmd.dcp = FakeDcp(fd=FakeFuncdata(complete=False))
        with pytest.raises(IfaceExecutionError, match="not been fully"):
            cmd.execute("")


# ---------------------------------------------------------------------------
# IfcSaveSignatures
# ---------------------------------------------------------------------------

class TestIfcSaveSignatures:
    def test_no_function_raises(self):
        cmd = IfcSaveSignatures()
        cmd.dcp = FakeDcp()
        with pytest.raises(IfaceExecutionError, match="No function"):
            cmd.execute("")

    def test_no_filename_raises(self):
        cmd = IfcSaveSignatures()
        cmd.dcp = FakeDcp(fd=FakeFuncdata())
        with pytest.raises(IfaceExecutionError, match="Need name"):
            cmd.execute("")


# ---------------------------------------------------------------------------
# IfcSaveAllSignatures
# ---------------------------------------------------------------------------

class TestIfcSaveAllSignatures:
    def test_no_arch_raises(self):
        cmd = IfcSaveAllSignatures()
        cmd.dcp = FakeDcp()
        with pytest.raises(IfaceExecutionError, match="No architecture"):
            cmd.execute("")

    def test_iteration_callback_no_code(self):
        cmd = IfcSaveAllSignatures()
        cmd._smanage = GraphSigManager()
        cmd.iterationCallback(FakeFuncdata(has_code=False))
        # Should just return without error

    def test_iteration_callback_none(self):
        cmd = IfcSaveAllSignatures()
        cmd._smanage = GraphSigManager()
        cmd.iterationCallback(None)


# ---------------------------------------------------------------------------
# IfcProduceSignatures
# ---------------------------------------------------------------------------

class TestIfcProduceSignatures:
    def test_is_subclass(self):
        assert issubclass(IfcProduceSignatures, IfcSaveAllSignatures)

    def test_iteration_callback_no_code(self):
        cmd = IfcProduceSignatures()
        cmd._smanage = GraphSigManager()
        cmd.iterationCallback(FakeFuncdata(has_code=False))


# ---------------------------------------------------------------------------
# IfaceAnalyzeSigsCapability
# ---------------------------------------------------------------------------

class TestIfaceAnalyzeSigsCapability:
    def test_singleton(self):
        a = IfaceAnalyzeSigsCapability.getInstance()
        b = IfaceAnalyzeSigsCapability.getInstance()
        assert a is b

    def test_name(self):
        cap = IfaceAnalyzeSigsCapability.getInstance()
        assert cap.name == "analyzesigs"

    def test_register_commands(self):
        cap = IfaceAnalyzeSigsCapability()
        status = FakeStatus()
        cap.registerCommands(status)
        # Should not raise
