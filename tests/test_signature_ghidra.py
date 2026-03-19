"""Tests for ghidra.console.signature_ghidra — Ghidra protocol signature commands."""
from __future__ import annotations

import io
import pytest

from ghidra.analysis.signature import SigManager, GraphSigManager
from ghidra.console.signature_ghidra import (
    SignaturesAt, GetSignatureSettings, SetSignatureSettings,
    GhidraSignatureCapability,
)


# ---------------------------------------------------------------------------
# SignaturesAt
# ---------------------------------------------------------------------------

class TestSignaturesAt:
    def test_default_not_debug(self):
        cmd = SignaturesAt(debug=False)
        assert cmd._debug is False

    def test_debug_mode(self):
        cmd = SignaturesAt(debug=True)
        assert cmd._debug is True

    def test_rawAction_no_ghidra_raises(self):
        cmd = SignaturesAt()
        cmd.ghidra = None
        cmd._addr = None
        from ghidra.core.error import LowlevelError
        with pytest.raises(LowlevelError, match="Bad address"):
            cmd.rawAction()


# ---------------------------------------------------------------------------
# GetSignatureSettings
# ---------------------------------------------------------------------------

class TestGetSignatureSettings:
    def test_rawAction_writes_xml(self):
        cmd = GetSignatureSettings()
        buf = io.BytesIO()
        cmd._sout = buf
        cmd.rawAction()
        output = buf.getvalue()
        assert b"sigsettings" in output
        assert b"major" in output
        assert b"minor" in output
        assert b"settings" in output


# ---------------------------------------------------------------------------
# SetSignatureSettings
# ---------------------------------------------------------------------------

class TestSetSignatureSettings:
    def test_valid_settings(self):
        old = SigManager.getSettings()
        try:
            cmd = SetSignatureSettings()
            cmd._settings = 0x3
            buf = io.BytesIO()
            cmd._sout = buf
            cmd.rawAction()
            assert SigManager.getSettings() == 0x3
        finally:
            SigManager.setSettings(old)

    def test_response_t(self):
        old = SigManager.getSettings()
        try:
            cmd = SetSignatureSettings()
            cmd._settings = 0x1
            buf = io.BytesIO()
            cmd._sout = buf
            cmd.rawAction()
            assert b"t" in buf.getvalue()
        finally:
            SigManager.setSettings(old)


# ---------------------------------------------------------------------------
# GhidraSignatureCapability
# ---------------------------------------------------------------------------

class TestGhidraSignatureCapability:
    def test_singleton(self):
        a = GhidraSignatureCapability.getInstance()
        b = GhidraSignatureCapability.getInstance()
        assert a is b

    def test_name(self):
        cap = GhidraSignatureCapability.getInstance()
        assert cap.name == "signature"

    def test_initialize_returns_commands(self):
        cap = GhidraSignatureCapability()
        cmds = cap.initialize()
        assert "generateSignatures" in cmds
        assert "debugSignatures" in cmds
        assert "getSignatureSettings" in cmds
        assert "setSignatureSettings" in cmds

    def test_generate_is_not_debug(self):
        cap = GhidraSignatureCapability()
        cmds = cap.initialize()
        assert cmds["generateSignatures"]._debug is False

    def test_debug_is_debug(self):
        cap = GhidraSignatureCapability()
        cmds = cap.initialize()
        assert cmds["debugSignatures"]._debug is True
