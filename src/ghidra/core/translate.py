"""
Corresponds to: translate.hh / translate.cc

Classes for disassembly and pcode generation.
Includes the Translate abstract base class, PcodeEmit, and AssemblyEmit.
"""

from __future__ import annotations

from abc import ABC, abstractmethod
from enum import IntEnum
from typing import TYPE_CHECKING, Optional, Dict, List

from ghidra.core.error import LowlevelError, UnimplError, BadDataError
from ghidra.core.opcodes import OpCode
from ghidra.core.address import Address
from ghidra.core.pcoderaw import VarnodeData
from ghidra.core.float_format import FloatFormat
from ghidra.core.space import (
    AddrSpace, AddrSpaceManager, ConstantSpace, UniqueSpace, JoinSpace, OtherSpace,
    IPTR_CONSTANT, IPTR_PROCESSOR, IPTR_INTERNAL, IPTR_JOIN,
)
from ghidra.core.marshal import (
    Encoder, Decoder, ElementId, AttributeId,
    ATTRIB_NAME, ATTRIB_SIZE, ATTRIB_SPACE, ATTRIB_DEFAULTSPACE, ATTRIB_UNIQBASE,
    ELEM_SPACE, ELEM_SPACES, ELEM_SPACE_BASE, ELEM_SPACE_UNIQUE,
    ELEM_SPACE_OTHER, ELEM_SPACE_OVERLAY, ELEM_TRUNCATE_SPACE,
)

if TYPE_CHECKING:
    from ghidra.core.xml import DocumentStorage


# =========================================================================
# TruncationTag
# =========================================================================


class UniqueLayout(IntEnum):
    RUNTIME_BOOLEAN_INVERT = 0
    RUNTIME_RETURN_LOCATION = 0x80
    RUNTIME_BITRANGE_EA = 0x100
    INJECT = 0x200
    ANALYSIS = 0x10000000

class TruncationTag:
    """Object for describing how a space should be truncated."""

    def __init__(self) -> None:
        self.spaceName: str = ""
        self.size: int = 0

    def decode(self, decoder: Decoder) -> None:
        elem_id = decoder.openElement(ELEM_TRUNCATE_SPACE)
        self.spaceName = decoder.readString(ATTRIB_SPACE)
        self.size = decoder.readUnsignedInteger(ATTRIB_SIZE)
        decoder.closeElement(elem_id)

    def getName(self) -> str:
        return self.spaceName

    def getSize(self) -> int:
        return self.size


# =========================================================================
# PcodeEmit
# =========================================================================

class PcodeEmit(ABC):
    """Abstract class for emitting pcode to an application.

    Translation engines pass back the generated pcode for an
    instruction to the application using this class.
    """

    @abstractmethod
    def dump(self, addr: Address, opc: OpCode,
             outvar: Optional[VarnodeData],
             vars_: List[VarnodeData], isize: int) -> None:
        """The main pcode emit method.

        A single pcode instruction is returned to the application
        via this method.
        """
        ...

    def decodeOp(self, addr: Address, decoder: Decoder) -> None:
        """Decode a single <op> element and forward it to dump()."""
        from ghidra.core.marshal import ATTRIB_SIZE, ELEM_OP
        from ghidra.core.pcoderaw import PcodeOpRaw

        elem_id = decoder.openElement(ELEM_OP)
        isize = decoder.readSignedInteger(ATTRIB_SIZE)
        invar = [VarnodeData() for _ in range(isize)]
        outvar = [VarnodeData()]
        opcode = PcodeOpRaw.decode(decoder, invar, outvar)
        decoder.closeElement(elem_id)
        self.dump(addr, opcode, outvar[0], invar, isize)


# =========================================================================
# AssemblyEmit
# =========================================================================

class AssemblyEmit(ABC):
    """Abstract class for emitting disassembly to an application."""

    @abstractmethod
    def dump(self, addr: Address, mnem: str, body: str) -> None:
        """The main disassembly emitting method."""
        ...


# =========================================================================
# AddressResolver
# =========================================================================

class AddressResolver(ABC):
    """Abstract class for converting native constants to addresses."""

    @abstractmethod
    def resolve(self, val: int, sz: int, point: Address) -> tuple[Address, int]:
        """Resolve a native constant to an address.

        Returns (resolved_address, full_encoding).
        """
        ...


# =========================================================================
# Translate
# =========================================================================

class Translate(AddrSpaceManager, ABC):
    """Abstract base for translation engines (disassembler + pcode generator).

    Corresponds to the Translate class in translate.hh.
    Manages address spaces and provides methods for translating
    machine instructions into p-code.
    """

    def __init__(self) -> None:
        super().__init__()
        self._floatformats: Dict[int, FloatFormat] = {}
        self._alignment: int = 1
        self._target_endian: bool = False
        self._unique_base: int = 0

    # --- Float format management ---

    def setBigEndian(self, val: bool) -> None:
        self._target_endian = val

    def setDefaultFloatFormats(self) -> None:
        if not self._floatformats:
            self._floatformats[4] = FloatFormat(4)
            self._floatformats[8] = FloatFormat(8)

    def getFloatFormat(self, size: int) -> FloatFormat | None:
        """Get the floating-point format for a given byte size."""
        return self._floatformats.get(size)

    def setFloatFormat(self, size: int, fmt: FloatFormat) -> None:
        self._floatformats[size] = fmt

    # --- Properties ---

    def getAlignment(self) -> int:
        return self._alignment

    def isBigEndian(self) -> bool:
        return self._target_endian

    def getUniqueBase(self) -> int:
        return self._unique_base

    def setUniqueBase(self, val: int) -> None:
        if val > self._unique_base:
            self._unique_base = val

    def getUniqueStart(self, layout: int) -> int:
        """Get the starting offset for the unique space."""
        if layout != UniqueLayout.ANALYSIS:
            return int(layout) + self._unique_base
        return int(layout)

    @abstractmethod
    def initialize(self, store: DocumentStorage) -> None:
        """Initialize the translator from a document store."""
        ...

    def registerContext(self, name: str, sbit: int, ebit: int) -> None:
        """Register a named context variable.

        The base Translate surface matches the native default no-op.
        """
        return None

    def setContextDefault(self, name: str, val: int) -> None:
        """Set the default value for a context variable.

        The base Translate surface matches the native default no-op.
        """
        return None

    def allowContextSet(self, val: bool) -> None:
        """Toggle whether translation is allowed to affect context.

        The base Translate surface matches the native default no-op.
        """
        return None

    @abstractmethod
    def getRegister(self, nm: str) -> VarnodeData:
        """Get the location of a register by name."""
        ...

    @abstractmethod
    def getRegisterName(self, base: AddrSpace, off: int, size: int) -> str:
        """Get the name of the smallest containing register."""
        ...

    @abstractmethod
    def getExactRegisterName(self, base: AddrSpace, off: int, size: int) -> str:
        """Get the name of a register with an exact location and size."""
        ...

    @abstractmethod
    def getAllRegisters(self) -> Dict[VarnodeData, str]:
        """Get all register definitions."""
        ...

    @abstractmethod
    def getUserOpNames(self) -> List[str]:
        """Get the list of user-defined pcode op names."""
        ...

    @abstractmethod
    def instructionLength(self, addr: Address) -> int:
        """Get the length of a machine instruction in bytes."""
        ...

    @abstractmethod
    def oneInstruction(self, emit: PcodeEmit, addr: Address) -> int:
        """Transform a single machine instruction into pcode.

        Returns the length of the machine instruction in bytes.
        """
        ...

    @abstractmethod
    def printAssembly(self, emit: AssemblyEmit, addr: Address) -> int:
        """Disassemble a single machine instruction.

        Returns the length of the machine instruction in bytes.
        """
        ...
