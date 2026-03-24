"""
Infrastructure for discovering code extensions to the decompiler.
Corresponds to capability.hh / capability.cc.

In C++ this uses static initializers to auto-register extensions.
In Python we use a class-level registry list with explicit registration.
"""
from __future__ import annotations

from abc import abstractmethod
from typing import ClassVar, List


class CapabilityPoint:
    """Base class for automatically registering extension points.

    Subclasses override initialize() and create a singleton instance.
    All registered capabilities can be initialized at once via initializeAll().
    """

    _registry: ClassVar[List[CapabilityPoint]] = []

    def __init__(self) -> None:
        CapabilityPoint._registry.append(self)

    @abstractmethod
    def initialize(self) -> None:
        """Complete initialization of an extension point."""
        ...

    @staticmethod
    def initializeAll() -> None:
        """Finish initialization for all registered extension points."""
        for cap in list(CapabilityPoint._registry):
            cap.initialize()
        CapabilityPoint._registry.clear()

    @staticmethod
    def getRegistered() -> List[CapabilityPoint]:
        """Return the current list of registered capabilities."""
        return list(CapabilityPoint._registry)

    @staticmethod
    def clearAll() -> None:
        """Clear all registered capabilities (for testing)."""
        CapabilityPoint._registry.clear()
