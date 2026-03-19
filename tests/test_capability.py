"""Tests for ghidra.core.capability -- CapabilityPoint registration."""
from __future__ import annotations

from ghidra.core.capability import CapabilityPoint


class _TestCap(CapabilityPoint):
    initialized = False

    def initialize(self) -> None:
        _TestCap.initialized = True


class _TestCap2(CapabilityPoint):
    initialized = False

    def initialize(self) -> None:
        _TestCap2.initialized = True


class TestCapabilityPoint:
    def setup_method(self):
        CapabilityPoint.clearAll()
        _TestCap.initialized = False
        _TestCap2.initialized = False

    def test_register_on_construction(self):
        cap = _TestCap()
        assert cap in CapabilityPoint.getRegistered()

    def test_initialize_all(self):
        _TestCap()
        _TestCap2()
        assert len(CapabilityPoint.getRegistered()) == 2
        CapabilityPoint.initializeAll()
        assert _TestCap.initialized is True
        assert _TestCap2.initialized is True
        assert len(CapabilityPoint.getRegistered()) == 0

    def test_clear_all(self):
        _TestCap()
        assert len(CapabilityPoint.getRegistered()) == 1
        CapabilityPoint.clearAll()
        assert len(CapabilityPoint.getRegistered()) == 0

    def test_get_registered_returns_copy(self):
        _TestCap()
        reg = CapabilityPoint.getRegistered()
        reg.clear()
        assert len(CapabilityPoint.getRegistered()) == 1

    def test_initialize_all_clears_registry(self):
        _TestCap()
        CapabilityPoint.initializeAll()
        assert len(CapabilityPoint.getRegistered()) == 0
        CapabilityPoint.initializeAll()  # second call is no-op
