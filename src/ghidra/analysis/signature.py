"""
Corresponds to: signature.hh / signature.cc

Classes for generating feature vectors representing individual functions.
Provides Signature, SignatureEntry, BlockSignatureEntry, VarnodeSignature,
BlockSignature, CopySignature, SigManager, and GraphSigManager.
"""

from __future__ import annotations

from typing import Dict, List, Optional, TYPE_CHECKING

if TYPE_CHECKING:
    from ghidra.ir.varnode import Varnode
    from ghidra.ir.op import PcodeOp
    from ghidra.block.block import BlockBasic
    from ghidra.analysis.funcdata import Funcdata


# Type alias
hashword = int  # uint8 in C++


# =========================================================================
# Signature
# =========================================================================

class Signature:
    """A feature describing some aspect of a function or other unit of code.

    The underlying representation is a 32-bit hash of the information
    representing the feature.
    """

    def __init__(self, h: hashword = 0) -> None:
        self._sig: int = h & 0xFFFFFFFF

    def getHash(self) -> int:
        """Get the underlying 32-bit hash of the feature."""
        return self._sig

    def compare(self, op2: Signature) -> int:
        """Compare two features."""
        if self._sig < op2._sig:
            return -1
        if self._sig > op2._sig:
            return 1
        return 0

    def printOrigin(self, s) -> None:
        """Print a brief description of this feature."""
        s.write(f"0x{self._sig:08x}")

    def print(self, s) -> None:
        """Print the feature hash and a brief description."""
        s.write(f"0x{self._sig:08x} ")
        self.printOrigin(s)
        s.write("\n")

    def encode(self, encoder) -> None:
        """Encode this feature to the given stream."""
        if encoder is not None and hasattr(encoder, 'openElement'):
            encoder.openElement("sig")
            encoder.writeUnsignedInteger("hash", self._sig)
            encoder.closeElement("sig")

    def decode(self, decoder) -> None:
        """Restore this feature from the given stream."""
        if decoder is not None and hasattr(decoder, 'readUnsignedInteger'):
            self._sig = decoder.readUnsignedInteger("hash") & 0xFFFFFFFF

    @staticmethod
    def comparePtr(a: Signature, b: Signature) -> bool:
        """Compare two Signature pointers via their underlying hash values."""
        return a._sig < b._sig


# =========================================================================
# VarnodeSignature
# =========================================================================

class VarnodeSignature(Signature):
    """A feature representing a portion of the data-flow graph rooted at a Varnode."""

    def __init__(self, vn=None, h: hashword = 0) -> None:
        super().__init__(h)
        self._vn = vn

    def getVarnode(self):
        return self._vn

    def encode(self, encoder) -> None:
        if encoder is not None and hasattr(encoder, 'openElement'):
            encoder.openElement("varsig")
            encoder.writeUnsignedInteger("hash", self.getHash())
            encoder.closeElement("varsig")

    def printOrigin(self, s) -> None:
        if self._vn is not None and hasattr(self._vn, 'printRaw'):
            self._vn.printRaw(s)
        else:
            super().printOrigin(s)


# =========================================================================
# BlockSignature
# =========================================================================

class BlockSignature(Signature):
    """A feature rooted in a basic block.

    Form 1: local control-flow info only.
    Form 2: combines two operations in sequence within the block.
    """

    def __init__(self, bl=None, h: hashword = 0, op1=None, op2=None) -> None:
        super().__init__(h)
        self._bl = bl
        self._op1 = op1
        self._op2 = op2

    def getBlock(self):
        return self._bl

    def encode(self, encoder) -> None:
        if encoder is not None and hasattr(encoder, 'openElement'):
            encoder.openElement("blocksig")
            encoder.writeUnsignedInteger("hash", self.getHash())
            encoder.closeElement("blocksig")

    def printOrigin(self, s) -> None:
        if self._bl is not None and hasattr(self._bl, 'printHeader'):
            self._bl.printHeader(s)
        else:
            super().printOrigin(s)


# =========================================================================
# CopySignature
# =========================================================================

class CopySignature(Signature):
    """A feature representing 1 or more stand-alone copies in a basic block."""

    def __init__(self, bl=None, h: hashword = 0) -> None:
        super().__init__(h)
        self._bl = bl

    def getBlock(self):
        return self._bl

    def encode(self, encoder) -> None:
        if encoder is not None and hasattr(encoder, 'openElement'):
            encoder.openElement("copysig")
            encoder.writeUnsignedInteger("hash", self.getHash())
            encoder.closeElement("copysig")

    def printOrigin(self, s) -> None:
        if self._bl is not None and hasattr(self._bl, 'printHeader'):
            self._bl.printHeader(s)
        else:
            s.write("copy ")
            super().printOrigin(s)


# =========================================================================
# SignatureEntry
# =========================================================================

class SignatureEntry:
    """A node for data-flow feature generation.

    Rooted at a specific Varnode; iteratively hashes information about
    the Varnode and its nearest neighbors through the data-flow graph edges.
    """

    # Flags
    SIG_NODE_TERMINAL = 0x1
    SIG_NODE_COMMUTATIVE = 0x2
    SIG_NODE_NOT_EMITTED = 0x4
    SIG_NODE_STANDALONE = 0x8
    VISITED = 0x10
    MARKER_ROOT = 0x20

    def __init__(self, vn=None, modifiers: int = 0) -> None:
        self._vn = vn
        self._flags: int = 0
        self._hash: List[hashword] = [0, 0]  # current and previous
        self._op = None  # effective defining PcodeOp
        self._startvn: int = 0
        self._inSize: int = 0
        self._index: int = 0
        self._shadow: Optional[SignatureEntry] = None

        if vn is not None:
            self._initFromVarnode(vn, modifiers)

    def _initFromVarnode(self, vn, modifiers: int) -> None:
        """Initialize from a Varnode (mirrors C++ constructor logic)."""
        self._vn = vn
        if not hasattr(vn, 'isWritten') or not vn.isWritten():
            self._flags |= self.SIG_NODE_TERMINAL
            self._op = None
            self._startvn = 0
            self._inSize = 0
        else:
            defop = vn.getDef()
            self._op = defop
            if hasattr(defop, 'code'):
                from ghidra.core.opcodes import OpCode
                opc = defop.code()
                if opc in (OpCode.CPUI_INT_ADD, OpCode.CPUI_INT_MULT,
                           OpCode.CPUI_INT_AND, OpCode.CPUI_INT_OR,
                           OpCode.CPUI_INT_XOR, OpCode.CPUI_BOOL_AND,
                           OpCode.CPUI_BOOL_OR, OpCode.CPUI_BOOL_XOR,
                           OpCode.CPUI_INT_EQUAL, OpCode.CPUI_INT_NOTEQUAL,
                           OpCode.CPUI_FLOAT_ADD, OpCode.CPUI_FLOAT_MULT,
                           OpCode.CPUI_FLOAT_EQUAL, OpCode.CPUI_FLOAT_NOTEQUAL):
                    self._flags |= self.SIG_NODE_COMMUTATIVE
            self._startvn = 0
            self._inSize = defop.numInput() if hasattr(defop, 'numInput') else 0

    @staticmethod
    def createVirtual(ind: int) -> SignatureEntry:
        """Construct a virtual node with a given index."""
        entry = SignatureEntry()
        entry._index = ind
        entry._flags = SignatureEntry.SIG_NODE_TERMINAL
        return entry

    def isTerminal(self) -> bool:
        return (self._flags & self.SIG_NODE_TERMINAL) != 0

    def isNotEmitted(self) -> bool:
        return (self._flags & self.SIG_NODE_NOT_EMITTED) != 0

    def isCommutative(self) -> bool:
        return (self._flags & self.SIG_NODE_COMMUTATIVE) != 0

    def isStandaloneCopy(self) -> bool:
        return (self._flags & self.SIG_NODE_STANDALONE) != 0

    def isVisited(self) -> bool:
        return (self._flags & self.VISITED) != 0

    def setVisited(self) -> None:
        self._flags |= self.VISITED

    def numInputs(self) -> int:
        return self._inSize

    def getVarnode(self):
        return self._vn

    def getHash(self) -> hashword:
        return self._hash[0]

    def flip(self) -> None:
        """Store hash from previous iteration, prepare for next."""
        self._hash[1] = self._hash[0]

    def localHash(self, modifiers: int) -> None:
        """Compute an initial hash based on local Varnode properties."""
        h: hashword = 0
        if self._vn is not None:
            if hasattr(self._vn, 'getSize'):
                h = self.hashSize(self._vn, modifiers)
            if self._op is not None and hasattr(self._op, 'code'):
                h ^= self._op.code() * 0x9e3779b9
        self._hash[0] = h & 0xFFFFFFFFFFFFFFFF

    def hashIn(self, neigh: List[SignatureEntry]) -> None:
        """Hash info from neighboring nodes into this."""
        h = self._hash[0]
        for i, n in enumerate(neigh):
            contrib = n._hash[1]
            contrib = ((contrib << (5 + i)) | (contrib >> (59 - i))) & 0xFFFFFFFFFFFFFFFF
            h ^= contrib
        self._hash[0] = h & 0xFFFFFFFFFFFFFFFF

    @staticmethod
    def hashSize(vn, modifiers: int) -> hashword:
        """Calculate a hash describing the size of a Varnode."""
        val = vn.getSize() if hasattr(vn, 'getSize') else 4
        if (modifiers & 0x1) != 0:  # SIG_COLLAPSE_SIZE
            if val > 4:
                val = 4
        return (val ^ (val << 7) ^ (val << 14) ^ (val << 21)) & 0xFFFFFFFFFFFFFFFF


# =========================================================================
# BlockSignatureEntry
# =========================================================================

class BlockSignatureEntry:
    """A node for control-flow feature generation.

    Rooted at a specific basic block; iteratively hashes information
    about the block and its nearest neighbors.
    """

    def __init__(self, bl=None) -> None:
        self._bl = bl
        self._hash: List[hashword] = [0, 0]

    def getBlock(self):
        return self._bl

    def getHash(self) -> hashword:
        return self._hash[0]

    def flip(self) -> None:
        self._hash[1] = self._hash[0]

    def localHash(self, modifiers: int) -> None:
        """Compute initial hash from local block properties."""
        h: hashword = 0
        if self._bl is not None:
            if hasattr(self._bl, 'sizeIn'):
                h ^= self._bl.sizeIn() * 0x12345678
            if hasattr(self._bl, 'sizeOut'):
                h ^= self._bl.sizeOut() * 0x87654321
        self._hash[0] = h & 0xFFFFFFFFFFFFFFFF

    def hashIn(self, neigh: List[BlockSignatureEntry]) -> None:
        """Hash info from neighboring blocks."""
        h = self._hash[0]
        for i, n in enumerate(neigh):
            contrib = n._hash[1]
            contrib = ((contrib << (5 + i)) | (contrib >> (59 - i))) & 0xFFFFFFFFFFFFFFFF
            h ^= contrib
        self._hash[0] = h & 0xFFFFFFFFFFFFFFFF


# =========================================================================
# SigManager
# =========================================================================

class SigManager:
    """Container for collecting a set of features for a single function.

    Handles configuring signature generation, establishing the function,
    generating features, and outputting the results.
    """

    _settings: int = 0

    def __init__(self) -> None:
        self._sigs: List[Signature] = []
        self._fd = None

    def clear(self) -> None:
        """Clear all current Signature/feature resources."""
        self._sigs.clear()
        self._fd = None

    def setCurrentFunction(self, fd) -> None:
        """Set the function used for (future) feature generation."""
        self._sigs.clear()
        self._fd = fd

    def addSignature(self, sig: Signature) -> None:
        """Add a new feature to the manager."""
        self._sigs.append(sig)

    def numSignatures(self) -> int:
        return len(self._sigs)

    def getSignature(self, i: int) -> Signature:
        return self._sigs[i]

    def getSignatureVector(self) -> List[int]:
        """Get the feature vector as a simple list of hashes."""
        return [s.getHash() for s in self._sigs]

    def getOverallHash(self) -> hashword:
        """Combine all feature hashes into one overall hash."""
        h: hashword = 0
        for s in self._sigs:
            val = s.getHash()
            h = ((h << 1) | (h >> 63)) & 0xFFFFFFFFFFFFFFFF
            h ^= val
        return h

    def sortByHash(self) -> None:
        """Sort all current features by hash."""
        self._sigs.sort(key=lambda s: s.getHash())

    def print(self, s) -> None:
        """Print a brief description of all features."""
        for sig in self._sigs:
            sig.print(s)

    def encode(self, encoder) -> None:
        """Encode all current features to a stream."""
        if encoder is not None and hasattr(encoder, 'openElement'):
            encoder.openElement("signatures")
            for sig in self._sigs:
                sig.encode(encoder)
            encoder.closeElement("signatures")

    @classmethod
    def getSettings(cls) -> int:
        return cls._settings

    @classmethod
    def setSettings(cls, newvalue: int) -> None:
        cls._settings = newvalue

    def generate(self) -> None:
        """Generate all features for the current function. Override in subclasses."""
        raise NotImplementedError("SigManager.generate must be overridden")

    def initializeFromStream(self, s) -> None:
        """Read configuration from a stream. Override in subclasses."""
        raise NotImplementedError("SigManager.initializeFromStream must be overridden")


# =========================================================================
# GraphSigManager
# =========================================================================

class GraphSigManager(SigManager):
    """Manager for generating Signatures on function data-flow and control-flow.

    Feature types: VarnodeSignature, BlockSignature, CopySignature.
    """

    # Settings
    SIG_COLLAPSE_SIZE = 0x1
    SIG_COLLAPSE_INDNOISE = 0x2
    SIG_DONOTUSE_CONST = 0x10
    SIG_DONOTUSE_INPUT = 0x20
    SIG_DONOTUSE_PERSIST = 0x40

    def __init__(self) -> None:
        super().__init__()
        self._sigmods: int = 0
        self._maxiter: int = 7
        self._maxblockiter: int = 3
        self._maxvarnode: int = 10000
        self._sigmap: Dict[int, SignatureEntry] = {}
        self._blockmap: Dict[int, BlockSignatureEntry] = {}

    def clear(self) -> None:
        super().clear()
        self._sigmap.clear()
        self._blockmap.clear()

    def setMaxIteration(self, val: int) -> None:
        self._maxiter = val

    def setMaxBlockIteration(self, val: int) -> None:
        self._maxblockiter = val

    def setMaxVarnode(self, val: int) -> None:
        self._maxvarnode = val

    def setCurrentFunction(self, fd) -> None:
        super().setCurrentFunction(fd)
        self._sigmap.clear()
        self._blockmap.clear()

    def initializeFromStream(self, s) -> None:
        """Read configuration — placeholder."""
        pass

    def generate(self) -> None:
        """Generate all features for the current function.

        This is a simplified version; the full C++ implementation walks
        the data-flow and control-flow graphs with iterative hashing.
        """
        if self._fd is None:
            return
        # Placeholder — full implementation would:
        # 1. Build SignatureEntry overlay for each Varnode
        # 2. Build BlockSignatureEntry overlay for each block
        # 3. Iterate hash propagation
        # 4. Collect VarnodeSignature, BlockSignature, CopySignature features

    @staticmethod
    def testSettings(val: int) -> bool:
        """Test for valid signature generation settings."""
        return True
