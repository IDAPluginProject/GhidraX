"""
Infrastructure for discovering code extensions to the decompiler.
Corresponds to capability.hh / capability.cc.

In C++ this uses static initializers to auto-register extensions.
In Python we use a class-level registry list with explicit registration.
"""
from __future__ import annotations

from abc import ABC, abstractmethod
from typing import ClassVar, List


class CapabilityPoint(ABC):
    """Base class for automatically registering extension points.

    Subclasses override initialize() and create a singleton instance.
    All registered capabilities can be initialized at once via initializeAll().
    """

    _registry: ClassVar[List[CapabilityPoint]] = []

    @staticmethod
    def getList() -> List[CapabilityPoint]:
        """Return the live registry of capability singletons."""
        return CapabilityPoint._registry

    def __init__(self) -> None:
        CapabilityPoint.getList().append(self)

    def __del__(self) -> None:
        """Mirror the native empty destructor surface."""
        return None

    @abstractmethod
    def initialize(self) -> None:
        """Complete initialization of an extension point."""
        ...

    @staticmethod
    def initializeAll() -> None:
        """Finish initialization for all registered extension points."""
        registry = CapabilityPoint.getList()
        index = 0
        while index < len(registry):
            registry[index].initialize()
            index += 1
        registry.clear()

    @staticmethod
    def getRegistered() -> List[CapabilityPoint]:
        """Return the current list of registered capabilities."""
        return list(CapabilityPoint.getList())

    @staticmethod
    def clearAll() -> None:
        """Clear all registered capabilities (for testing)."""
        CapabilityPoint.getList().clear()
