"""
Corresponds to: signature.hh / signature.cc

Classes for generating feature vectors representing individual functions.
Provides Signature, SignatureEntry, BlockSignatureEntry, VarnodeSignature,
BlockSignature, CopySignature, SigManager, and GraphSigManager.
"""

from __future__ import annotations

import re
from typing import Dict, List, Optional, TYPE_CHECKING

from ghidra.core.crc32 import crc_update
from ghidra.core.error import LowlevelError
from ghidra.core.marshal import ATTRIB_INDEX, AttributeId, ElementId

if TYPE_CHECKING:
    from ghidra.ir.varnode import Varnode
    from ghidra.ir.op import PcodeOp
    from ghidra.block.block import BlockBasic
    from ghidra.analysis.funcdata import Funcdata


# Type alias
hashword = int  # uint8 in C++

ATTRIB_BADDATA = AttributeId("baddata", 145)
ATTRIB_HASH = AttributeId("hash", 146)
ATTRIB_UNIMPL = AttributeId("unimpl", 147)
ELEM_BLOCKSIG = ElementId("blocksig", 258)
ELEM_CALL = ElementId("call", 259)
ELEM_GENSIG = ElementId("gensig", 260)
ELEM_COPYSIG = ElementId("copysig", 263)
ELEM_SIG = ElementId("sig", 265)
ELEM_SIGNATUREDESC = ElementId("signaturedesc", 266)
ELEM_SIGNATURES = ElementId("signatures", 267)
ELEM_VARSIG = ElementId("varsig", 269)
_AUTO_BASE_INT_RE = re.compile(r"\s*([+-]?(?:0[xX][0-9a-fA-F]+|0[bB][01]+|0[oO][0-7]+|0[0-7]*|[1-9][0-9]*|0))")


def hash_mixin(val1: hashword, val2: hashword) -> hashword:
    hashhi = (val1 >> 32) & 0xFFFFFFFF
    hashlo = val1 & 0xFFFFFFFF
    cur = val2 & 0xFFFFFFFFFFFFFFFF
    for _ in range(8):
        tmphi = hashhi
        tmplo = cur & 0xFFFFFFFF
        cur >>= 8
        hashhi = crc_update(hashhi, tmplo) & 0xFFFFFFFF
        hashlo = crc_update(hashlo, tmphi) & 0xFFFFFFFF
    return ((hashhi << 32) | hashlo) & 0xFFFFFFFFFFFFFFFF


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

    def __del__(self) -> None:
        pass

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
        s.write("*")
        self.printOrigin(s)
        s.write(f" = 0x{self._sig:08x}\n")

    def encode(self, encoder) -> None:
        """Encode this feature to the given stream."""
        encoder.openElement(ELEM_GENSIG)
        encoder.writeUnsignedInteger(ATTRIB_HASH, self.getHash())
        encoder.closeElement(ELEM_GENSIG)

    def decode(self, decoder) -> None:
        """Restore this feature from the given stream."""
        elem_id = decoder.openElement(ELEM_GENSIG)
        self._sig = decoder.readUnsignedInteger(ATTRIB_HASH) & 0xFFFFFFFF
        decoder.closeElement(elem_id)

    @staticmethod
    def comparePtr(a: Signature, b: Signature) -> bool:
        """Compare two Signature pointers via their underlying hash values."""
        return a._sig < b._sig


# =========================================================================
# VarnodeSignature
# =========================================================================

class VarnodeSignature(Signature):
    """A feature representing a portion of the data-flow graph rooted at a Varnode."""

    def __init__(self, vn, h: hashword) -> None:
        super().__init__(h)
        self._vn = vn

    def getVarnode(self):
        return self._vn

    def encode(self, encoder) -> None:
        encoder.openElement(ELEM_VARSIG)
        encoder.writeUnsignedInteger(ATTRIB_HASH, self.getHash())
        self._vn.encode(encoder)
        if self._vn.isWritten():
            self._vn.getDef().encode(encoder)
        encoder.closeElement(ELEM_VARSIG)

    def printOrigin(self, s) -> None:
        self._vn.printRaw(s)


# =========================================================================
# BlockSignature
# =========================================================================

class BlockSignature(Signature):
    """A feature rooted in a basic block.

    Form 1: local control-flow info only.
    Form 2: combines two operations in sequence within the block.
    """

    def __init__(self, bl, h: hashword, op1, op2) -> None:
        super().__init__(h)
        self._bl = bl
        self._op1 = op1
        self._op2 = op2

    def getBlock(self):
        return self._bl

    def encode(self, encoder) -> None:
        encoder.openElement(ELEM_BLOCKSIG)
        encoder.writeUnsignedInteger(ATTRIB_HASH, self.getHash())
        encoder.writeSignedInteger(ATTRIB_INDEX, self._bl.getIndex())
        self._bl.getStart().encode(encoder)
        if self._op2 is not None:
            self._op2.encode(encoder)
        if self._op1 is not None:
            self._op1.encode(encoder)
        encoder.closeElement(ELEM_BLOCKSIG)

    def printOrigin(self, s) -> None:
        self._bl.printHeader(s)


# =========================================================================
# CopySignature
# =========================================================================

class CopySignature(Signature):
    """A feature representing 1 or more stand-alone copies in a basic block."""

    def __init__(self, bl, h: hashword) -> None:
        super().__init__(h)
        self._bl = bl

    def getBlock(self):
        return self._bl

    def encode(self, encoder) -> None:
        if encoder is not None and hasattr(encoder, 'openElement'):
            encoder.openElement(ELEM_COPYSIG)
            encoder.writeUnsignedInteger(ATTRIB_HASH, self.getHash())
            encoder.writeSignedInteger(ATTRIB_INDEX, self._bl.getIndex())
            encoder.closeElement(ELEM_COPYSIG)

    def printOrigin(self, s) -> None:
        if self._bl is not None and hasattr(self._bl, 'printHeader'):
            s.write("Copies in ")
            self._bl.printHeader(s)
        else:
            s.write("Copies in ")
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
        self._index: int = -1
        self._shadow: Optional[SignatureEntry] = None

        if isinstance(vn, int):
            self._vn = None
            self._op = None
            self._inSize = 0
            self._flags = 0
            self._shadow = None
            self._index = vn
            self._startvn = 0
        elif vn is not None:
            self._initFromVarnode(vn, modifiers)

    def _initFromVarnode(self, vn, modifiers: int) -> None:
        """Initialize from a Varnode (mirrors C++ constructor logic)."""
        from ghidra.core.opcodes import OpCode

        self._vn = vn
        self._op = vn.getDef()
        self._inSize = 0
        self._flags = 0
        self._shadow = None
        self._index = -1

        if self._op is None:
            self._flags |= self.SIG_NODE_TERMINAL
            return

        self._startvn = 0
        self._inSize = self._op.numInput()
        opc = self._op.code()
        if opc == OpCode.CPUI_COPY:
            if self.testStandaloneCopy(vn):
                self._flags |= self.SIG_NODE_STANDALONE
        elif opc == OpCode.CPUI_INDIRECT:
            self._inSize -= 1
            if self.testStandaloneCopy(vn):
                self._flags |= self.SIG_NODE_STANDALONE
        elif opc == OpCode.CPUI_MULTIEQUAL:
            self._flags |= self.SIG_NODE_COMMUTATIVE
        elif opc in (
            OpCode.CPUI_CALL,
            OpCode.CPUI_CALLIND,
            OpCode.CPUI_CALLOTHER,
            OpCode.CPUI_STORE,
            OpCode.CPUI_LOAD,
        ):
            self._startvn = 1
            self._inSize -= 1
        elif opc in (
            OpCode.CPUI_INT_LEFT,
            OpCode.CPUI_INT_RIGHT,
            OpCode.CPUI_INT_SRIGHT,
            OpCode.CPUI_SUBPIECE,
        ):
            if self._op.getIn(1).isConstant():
                self._inSize = 1
        elif opc == OpCode.CPUI_CPOOLREF:
            self._inSize = 0
        elif self._op.isCommutative():
            self._flags |= self.SIG_NODE_COMMUTATIVE

    @staticmethod
    def createVirtual(ind: int) -> SignatureEntry:
        """Construct a virtual node with a given index."""
        return SignatureEntry(ind)

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

    def markerSizeIn(self) -> int:
        if (self._flags & self.MARKER_ROOT) != 0:
            return 1
        return self.numInputs()

    @staticmethod
    def mapToEntry(vn, sigMap):
        return sigMap[vn.getCreateIndex()]

    @staticmethod
    def mapToEntryCollapse(vn, sigMap):
        res = SignatureEntry.mapToEntry(vn, sigMap)
        if res._shadow is None:
            return res
        return res._shadow

    def getMarkerIn(self, i: int, vRoot, sigMap):
        if (self._flags & self.MARKER_ROOT) != 0:
            return vRoot
        return self.mapToEntry(self._op.getIn(i + self._startvn), sigMap)

    def getIn(self, i: int, sigMap):
        return self.mapToEntryCollapse(self._op.getIn(i + self._startvn), sigMap)

    def calculateShadow(self, sigMap) -> None:
        from ghidra.core.opcodes import OpCode

        shadow_vn = self._vn
        while True:
            op = shadow_vn.getDef()
            if op is None:
                break
            opc = op.code()
            if opc != OpCode.CPUI_COPY and opc != OpCode.CPUI_INDIRECT and opc != OpCode.CPUI_CAST:
                break
            shadow_vn = op.getIn(0)
        if shadow_vn is not self._vn:
            self._shadow = self.mapToEntry(shadow_vn, sigMap)

    def standaloneCopyHash(self, modifiers: int) -> None:
        val = self.hashSize(self._vn, modifiers)
        val ^= 0xAF29E23B
        if self._vn.isPersist():
            val ^= 0x55055055
        invn = self._vn.getDef().getIn(0)
        if invn.isConstant():
            if (modifiers & GraphSigManager.SIG_DONOTUSE_CONST) == 0:
                val ^= self._vn.getOffset()
            else:
                val ^= 0xA0A0A0A0
        elif invn.isPersist():
            val ^= 0xD7651EC3
        val &= 0xFFFFFFFFFFFFFFFF
        self._hash[0] = val
        self._hash[1] = val

    @staticmethod
    def testStandaloneCopy(vn) -> bool:
        op = vn.getDef()
        invn = op.getIn(0)
        if invn.isWritten():
            return False
        if invn.getAddr() == vn.getAddr():
            return False

        from ghidra.core.opcodes import OpCode

        if vn.isPersist() and op.code() == OpCode.CPUI_INDIRECT:
            return True
        desc_iter = vn.beginDescend()
        desc_op = next(desc_iter, None)
        if desc_op is None:
            return True
        if next(desc_iter, None) is not None:
            return False
        opc = desc_op.code()
        if vn.isPersist() and opc == OpCode.CPUI_INDIRECT:
            return True
        if opc != OpCode.CPUI_COPY and opc != OpCode.CPUI_INDIRECT:
            return False
        return desc_op.getOut().hasNoDescend()

    @staticmethod
    def noisePostOrder(rootlist, postOrder, sigMap) -> None:
        from ghidra.core.opcodes import OpCode

        stack = []
        for entry in rootlist:
            stack.append((entry, entry._vn.beginDescend()))
            entry.setVisited()
            while stack:
                cur_entry, cur_iter = stack[-1]
                op = next(cur_iter, None)
                if op is None:
                    stack.pop()
                    cur_entry._index = len(postOrder)
                    postOrder.append(cur_entry)
                    continue
                if op.isMarker() or op.code() == OpCode.CPUI_COPY:
                    child_entry = SignatureEntry.mapToEntry(op.getOut(), sigMap)
                    if not child_entry.isVisited():
                        child_entry.setVisited()
                        stack.append((child_entry, child_entry._vn.beginDescend()))

    @staticmethod
    def noiseDominator(postOrder, sigMap) -> None:
        b = virtualRoot = postOrder[-1]
        b._shadow = b
        changed = True
        new_idom = None
        while changed:
            changed = False
            for i in range(len(postOrder) - 2, -1, -1):
                b = postOrder[i]
                if b._shadow != postOrder[-1]:
                    size_in = b.markerSizeIn()
                    j = 0
                    while j < size_in:
                        new_idom = b.getMarkerIn(j, virtualRoot, sigMap)
                        if new_idom._shadow is not None:
                            break
                        j += 1
                    j += 1
                    while j < size_in:
                        rho = b.getMarkerIn(j, virtualRoot, sigMap)
                        if rho._shadow is not None:
                            finger1 = rho._index
                            finger2 = new_idom._index
                            while finger1 != finger2:
                                while finger1 < finger2:
                                    finger1 = postOrder[finger1]._shadow._index
                                while finger2 < finger1:
                                    finger2 = postOrder[finger2]._shadow._index
                            new_idom = postOrder[finger1]
                        j += 1
                    if b._shadow != new_idom:
                        b._shadow = new_idom
                        changed = True

    @staticmethod
    def removeNoise(sigMap) -> None:
        from ghidra.core.opcodes import OpCode

        rootlist = []
        postOrder = []

        for entry in sigMap.values():
            vn = entry._vn
            if vn.isInput() or vn.isConstant():
                rootlist.append(entry)
                entry._flags |= SignatureEntry.MARKER_ROOT
            elif vn.isWritten():
                op = vn.getDef()
                if (not op.isMarker()) and op.code() != OpCode.CPUI_COPY:
                    rootlist.append(entry)
                    entry._flags |= SignatureEntry.MARKER_ROOT

        SignatureEntry.noisePostOrder(rootlist, postOrder, sigMap)
        virtualRoot = SignatureEntry.createVirtual(len(postOrder))
        postOrder.append(virtualRoot)
        for entry in rootlist:
            entry._shadow = virtualRoot

        SignatureEntry.noiseDominator(postOrder, sigMap)
        postOrder.pop()

        for entry in postOrder:
            if entry._shadow is virtualRoot:
                entry._shadow = None

        for entry in postOrder:
            base = entry
            while base._shadow is not None:
                base = base._shadow
            while entry._shadow is not None:
                tmp = entry
                entry = entry._shadow
                tmp._shadow = base

    def getVarnode(self):
        return self._vn

    def getHash(self) -> hashword:
        return self._hash[0]

    def getOpHash(self, modifiers: int) -> hashword:
        """Get a hash encoding the effective defining opcode."""
        if self._op is None:
            return 0
        from ghidra.core.opcodes import OpCode

        opc = self._op.code()
        ophash: hashword = int(opc)
        if opc == OpCode.CPUI_CPOOLREF:
            ophash = (ophash + 0xFEEDFACE) ^ self._op.getIn(self._op.numInput() - 1).getOffset()
        return ophash

    def flip(self) -> None:
        """Store hash from previous iteration, prepare for next."""
        self._hash[1] = self._hash[0]

    def localHash(self, modifiers: int) -> None:
        if self._vn.isAnnotation():
            localhash = 0xB7B7B7B7
            self._flags |= self.SIG_NODE_NOT_EMITTED | self.SIG_NODE_TERMINAL
            self._hash[0] = localhash
            self._hash[1] = localhash
            return
        if self._shadow is not None:
            self._flags |= self.SIG_NODE_NOT_EMITTED
            if self.isStandaloneCopy():
                self.standaloneCopyHash(modifiers)
            return

        localhash = self.hashSize(self._vn, modifiers)

        if not self._vn.isWritten():
            self._flags |= self.SIG_NODE_NOT_EMITTED
        ophash = self.getOpHash(modifiers)

        if self._vn.isConstant():
            if (modifiers & GraphSigManager.SIG_DONOTUSE_CONST) == 0:
                localhash ^= self._vn.getOffset()
            else:
                localhash ^= 0xA0A0A0A0
        if (modifiers & GraphSigManager.SIG_DONOTUSE_PERSIST) == 0:
            if self._vn.isPersist() and self._vn.isInput():
                localhash ^= 0x55055055
        if self._vn.isInput():
            localhash ^= 0x10101
        if ophash != 0:
            localhash ^= ophash ^ (ophash << 9) ^ (ophash << 18)

        localhash &= 0xFFFFFFFFFFFFFFFF
        self._hash[0] = localhash
        self._hash[1] = localhash

    def hashIn(self, neigh: List[SignatureEntry]) -> None:
        curhash = self._hash[1]
        if self.isCommutative():
            accum = 0
            for entry in neigh:
                tmphash = hash_mixin(curhash, entry._hash[1])
                accum = (accum + tmphash) & 0xFFFFFFFFFFFFFFFF
            curhash = hash_mixin(curhash, accum)
        else:
            for entry in neigh:
                curhash = hash_mixin(curhash, entry._hash[1])
        self._hash[0] = curhash & 0xFFFFFFFFFFFFFFFF

    @staticmethod
    def hashSize(vn, modifiers: int) -> hashword:
        """Calculate a hash describing the size of a Varnode."""
        val = vn.getSize() if hasattr(vn, 'getSize') else 4
        if (modifiers & 0x1) != 0:  # SIG_COLLAPSE_SIZE
            if val > 4:
                val = 4
        return (val ^ (val << 7) ^ (val << 14) ^ (val << 21)) & 0xFFFFFFFFFFFFFFFF

    def verifyNoiseRemoval(self, sigMap) -> None:
        from ghidra.core.error import LowlevelError
        from ghidra.core.opcodes import OpCode

        if self._shadow is None:
            if not self._vn.isWritten():
                return
            op = self._vn.getDef()
            opc = op.code()
            if opc == OpCode.CPUI_COPY or opc == OpCode.CPUI_INDIRECT:
                raise LowlevelError("Node should be shadowed but isnt")
            return
        if not self._vn.isWritten():
            raise LowlevelError("Shadowed node has no input")
        op = self._vn.getDef()
        opc = op.code()
        if opc == OpCode.CPUI_COPY or opc == OpCode.CPUI_INDIRECT:
            invn = op.getIn(0)
            inEntry = sigMap[invn.getCreateIndex()]
            if inEntry._shadow is None:
                if self._shadow is not inEntry:
                    raise LowlevelError("Shadow does not match terminator")
            elif inEntry._shadow is not self._shadow:
                raise LowlevelError("Shadow mismatch between varnode and COPY/INDIRECT input")
        elif opc == OpCode.CPUI_MULTIEQUAL:
            for i in range(op.numInput()):
                invn = op.getIn(i)
                inEntry = sigMap[invn.getCreateIndex()]
                if inEntry._shadow is None:
                    if self._shadow is not inEntry:
                        raise LowlevelError("Shadow does not match multi terminator")
                elif inEntry._shadow is not self._shadow:
                    raise LowlevelError("Shadow mismatch between varnode and MULTIEQUAL input")
        else:
            raise LowlevelError("Shadowing varnode not written by COPY/INDIRECT/MULTIEQUAL")

    @staticmethod
    def verifyAllNoiseRemoval(sigMap) -> None:
        for index in sorted(sigMap.keys()):
            sigMap[index].verifyNoiseRemoval(sigMap)


# =========================================================================
# BlockSignatureEntry
# =========================================================================

class BlockSignatureEntry:
    """A node for control-flow feature generation.

    Rooted at a specific basic block; iteratively hashes information
    about the block and its nearest neighbors.
    """

    def __init__(self, bl) -> None:
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
        localhash = self._bl.sizeIn()
        localhash <<= 8
        localhash |= self._bl.sizeOut()
        self._hash[0] = localhash & 0xFFFFFFFFFFFFFFFF

    def hashIn(self, neigh: List[BlockSignatureEntry]) -> None:
        """Hash info from neighboring blocks."""
        curhash = self._hash[1]
        accum = 0xBAFABACA
        for i, entry in enumerate(neigh):
            tmphash = hash_mixin(curhash, entry._hash[1])
            if entry._bl.sizeOut() == 2:
                if self._bl.getInRevIndex(i) == 0:
                    tmphash = hash_mixin(tmphash, 0x777 ^ 0x7ABC7ABC)
                else:
                    tmphash = hash_mixin(tmphash, 0x777)
            accum = (accum + tmphash) & 0xFFFFFFFFFFFFFFFF
        self._hash[0] = hash_mixin(curhash, accum)


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

    def __del__(self) -> None:
        self.clearSignatures()

    def clearSignatures(self) -> None:
        """Clear any Signature objects specifically."""
        self._sigs.clear()

    def clear(self) -> None:
        """Clear all current Signature/feature resources."""
        self.clearSignatures()

    def setCurrentFunction(self, fd) -> None:
        """Set the function used for (future) feature generation."""
        self._fd = fd

    def addSignature(self, sig: Signature) -> None:
        """Add a new feature to the manager."""
        self._sigs.append(sig)

    def numSignatures(self) -> int:
        return len(self._sigs)

    def getSignature(self, i: int) -> Signature:
        return self._sigs[i]

    def getSignatureVector(self, feature: List[int]) -> None:
        """Get the feature vector as a simple list of hashes."""
        feature[:] = [sig.getHash() for sig in self._sigs]
        feature.sort()

    def getOverallHash(self) -> hashword:
        """Combine all feature hashes into one overall hash."""
        feature: List[int] = []
        self.getSignatureVector(feature)
        pool: hashword = 0x12349876ABACAB
        for item in feature:
            pool = hash_mixin(pool, item)
        return pool

    def sortByHash(self) -> None:
        """Sort all current features by hash."""
        self._sigs.sort(key=lambda s: s.getHash())

    def print(self, s) -> None:
        """Print a brief description of all features."""
        for sig in self._sigs:
            sig.print(s)

    def encode(self, encoder) -> None:
        """Encode all current features to a stream."""
        encoder.openElement(ELEM_SIGNATUREDESC)
        for sig in self._sigs:
            sig.encode(encoder)
        encoder.closeElement(ELEM_SIGNATUREDESC)

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
        setting = SigManager.getSettings()
        if not self.testSettings(setting):
            raise LowlevelError("Bad signature settings")
        self._sigmods: int = setting >> 2
        self._maxiter: int = 3
        self._maxblockiter: int = 1
        self._maxvarnode: int = 0
        self._sigmap: Dict[int, SignatureEntry] = {}
        self._blockmap: Dict[int, BlockSignatureEntry] = {}

    def __del__(self) -> None:
        if hasattr(self, "_sigmap"):
            self.varnodeClear()

    def clear(self) -> None:
        self.varnodeClear()
        self.blockClear()
        super().clear()

    def setMaxIteration(self, val: int) -> None:
        self._maxiter = val

    def setMaxBlockIteration(self, val: int) -> None:
        self._maxblockiter = val

    def setMaxVarnode(self, val: int) -> None:
        self._maxvarnode = val

    def setCurrentFunction(self, fd) -> None:
        super().setCurrentFunction(fd)
        size = fd.numVarnodes()
        if self._maxvarnode != 0 and size > self._maxvarnode:
            raise LowlevelError(f"{fd.getName()} exceeds size threshold for generating signatures")

        for vn in fd.beginLoc():
            entry = SignatureEntry(vn, self._sigmods)
            self._sigmap[vn.getCreateIndex()] = entry

        if (self._sigmods & self.SIG_COLLAPSE_INDNOISE) != 0:
            SignatureEntry.removeNoise(self._sigmap)
        else:
            for key in sorted(self._sigmap):
                self._sigmap[key].calculateShadow(self._sigmap)

        for key in sorted(self._sigmap):
            self._sigmap[key].localHash(self._sigmods)

    def flipVarnodes(self) -> None:
        for key in sorted(self._sigmap):
            self._sigmap[key].flip()

    def flipBlocks(self) -> None:
        for key in sorted(self._blockmap):
            self._blockmap[key].flip()

    def signatureIterate(self) -> None:
        self.flipVarnodes()
        for key in sorted(self._sigmap):
            entry = self._sigmap[key]
            if entry.isNotEmitted():
                continue
            if entry.isTerminal():
                continue
            neigh: List[SignatureEntry] = []
            for i in range(entry.numInputs()):
                vnentry = entry.getIn(i, self._sigmap)
                neigh.append(vnentry)
            entry.hashIn(neigh)

    def signatureBlockIterate(self) -> None:
        self.flipBlocks()
        for key in sorted(self._blockmap):
            entry = self._blockmap[key]
            bl = entry.getBlock()
            neigh: List[BlockSignatureEntry] = []
            for i in range(bl.sizeIn()):
                inbl = bl.getIn(i)
                inentry = self._blockmap[inbl.getIndex()]
                neigh.append(inentry)
            entry.hashIn(neigh)

    def collectVarnodeSigs(self) -> None:
        for key in sorted(self._sigmap):
            entry = self._sigmap[key]
            if entry.isNotEmitted():
                continue
            vsig = VarnodeSignature(entry.getVarnode(), entry.getHash())
            self.addSignature(vsig)

    def collectBlockSigs(self) -> None:
        from ghidra.core.opcodes import OpCode

        mask = 0xFFFFFFFFFFFFFFFF
        for key in sorted(self._blockmap):
            entry = self._blockmap[key]
            bl = entry.getBlock()

            lastop = None
            lasthash: hashword = 0
            callhash: hashword = 0
            copyhash: hashword = 0
            for op in bl.beginOp():
                startind = 0
                stopind = 0
                opcode = op.code()
                if opcode == OpCode.CPUI_CALL:
                    callhash = ((callhash + 100001) * 0x78ABBF) & mask
                    startind = 1
                    stopind = op.numInput()
                elif opcode == OpCode.CPUI_CALLIND:
                    callhash = ((callhash + 123451) * 0x78ABBF) & mask
                    startind = 1
                    stopind = op.numInput()
                elif opcode == OpCode.CPUI_CALLOTHER:
                    startind = 1
                    stopind = op.numInput()
                elif opcode == OpCode.CPUI_STORE:
                    startind = 1
                    stopind = op.numInput()
                elif opcode == OpCode.CPUI_CBRANCH:
                    startind = 1
                    stopind = 2
                elif opcode == OpCode.CPUI_BRANCHIND:
                    startind = 0
                    stopind = 1
                elif opcode == OpCode.CPUI_RETURN:
                    startind = 1
                    stopind = op.numInput()
                elif opcode == OpCode.CPUI_INDIRECT or opcode == OpCode.CPUI_COPY:
                    outEntry = SignatureEntry.mapToEntry(op.getOut(), self._sigmap)
                    if outEntry.isStandaloneCopy():
                        copyhash = (copyhash + outEntry.getHash()) & mask
                    continue

                outvn = op.getOut()
                if stopind == 0 and (outvn is None or not outvn.hasNoDescend()):
                    continue
                if outvn is not None:
                    outEntry = SignatureEntry.mapToEntry(outvn, self._sigmap)
                    if outEntry.isNotEmitted():
                        continue
                    val = outEntry.getHash()
                else:
                    val = int(opcode)
                    val = (val ^ (val << 9) ^ (val << 18)) & mask
                    accum: hashword = 0
                    for i in range(startind, stopind):
                        vn = op.getIn(i)
                        tmphash = hash_mixin(val, SignatureEntry.mapToEntryCollapse(vn, self._sigmap).getHash())
                        accum = (accum + tmphash) & mask
                    val ^= accum
                if lastop is None:
                    finalhash = hash_mixin(val, entry.getHash())
                else:
                    finalhash = hash_mixin(val, lasthash)
                self.addSignature(BlockSignature(bl, finalhash, lastop, op))
                lastop = op
                lasthash = val

            finalhash = hash_mixin(entry.getHash(), 0x9B1C5F)
            if callhash != 0:
                finalhash = hash_mixin(finalhash, callhash)
            self.addSignature(BlockSignature(bl, finalhash, None, None))
            if copyhash != 0:
                copyhash = hash_mixin(copyhash, 0xA2DE3C)
                self.addSignature(CopySignature(bl, copyhash))

    def varnodeClear(self) -> None:
        self._sigmap.clear()

    def blockClear(self) -> None:
        self._blockmap.clear()

    def initializeBlocks(self) -> None:
        blockgraph = self._fd.getBasicBlocks()
        for i in range(blockgraph.getSize()):
            bl = blockgraph.getBlock(i)
            entry = BlockSignatureEntry(bl)
            self._blockmap[bl.getIndex()] = entry
            entry.localHash(self._sigmods)

    def initializeFromStream(self, s) -> None:
        mymaxiter = -1
        if isinstance(s, str):
            text = s
            match = _AUTO_BASE_INT_RE.match(text)
            consumed = match.end() if match is not None else len(text) - len(text.lstrip())
        else:
            start = s.tell() if hasattr(s, "tell") else None
            text = s.read() if hasattr(s, "read") else str(s)
            match = _AUTO_BASE_INT_RE.match(text)
            consumed = match.end() if match is not None else len(text) - len(text.lstrip())
            if start is not None and hasattr(s, "seek"):
                s.seek(start + consumed)

        if match is not None:
            token = match.group(1)
            try:
                if re.fullmatch(r"[+-]?0[0-7]+", token) and not re.fullmatch(r"[+-]?0", token):
                    mymaxiter = int(token, 8)
                else:
                    mymaxiter = int(token, 0)
            except ValueError:
                mymaxiter = -1
        if mymaxiter != -1:
            self._maxiter = mymaxiter

    def generate(self) -> None:
        minusone = self._maxiter - 1
        firsthalf = int(minusone / 2)
        secondhalf = minusone - firsthalf

        self.signatureIterate()
        for _ in range(firsthalf):
            self.signatureIterate()

        if self._maxblockiter >= 0:
            self.initializeBlocks()
            for _ in range(self._maxblockiter):
                self.signatureBlockIterate()
            self.collectBlockSigs()
            self.blockClear()

        for _ in range(secondhalf):
            self.signatureIterate()

        self.collectVarnodeSigs()
        self.varnodeClear()

    @staticmethod
    def testSettings(val: int) -> bool:
        """Test for valid signature generation settings."""
        if val == 0:
            return False
        mask = (
            GraphSigManager.SIG_COLLAPSE_SIZE
            | GraphSigManager.SIG_DONOTUSE_CONST
            | GraphSigManager.SIG_DONOTUSE_INPUT
            | GraphSigManager.SIG_DONOTUSE_PERSIST
            | GraphSigManager.SIG_COLLAPSE_INDNOISE
        )
        mask = (mask << 2) | 1
        return (val & ~mask) == 0
