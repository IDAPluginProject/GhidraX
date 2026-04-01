"""
Corresponds to: variable.hh / variable.cc

Definitions for high-level variables (HighVariable, VariableGroup, VariablePiece).
"""

from __future__ import annotations

from typing import TYPE_CHECKING, Optional, List, Set

from ghidra.ir.cover import Cover

if TYPE_CHECKING:
    from ghidra.ir.varnode import Varnode

# ---------------------------------------------------------------------------
# Pre-cached Varnode flag constants — avoids repeated sys.modules lookup
# inside every hot flag-checking method (called millions of times per run).
# ---------------------------------------------------------------------------
_VN_MARK            = 0x01
_VN_CONSTANT        = 0x02
_VN_INPUT           = 0x08
_VN_IMPLIED         = 0x40
_VN_TYPELOCK        = 0x100
_VN_NAMELOCK        = 0x200
_VN_PERSIST         = 0x4000
_VN_ADDRTIED        = 0x8000
_VN_UNAFFECTED      = 0x10000
_VN_SPACEBASE       = 0x20000
_VN_INDIRECT_CREATE = 0x400000
_VN_MAPPED          = 0x200000
_VN_PROTO_PARTIAL   = 0x80000000
_HV_FLAGSDIRTY      = 1    # HighVariable.flagsdirty
_HV_COVERDIRTY      = 8    # HighVariable.coverdirty
_HV_SYMBOLDIRTY     = 0x10 # HighVariable.symboldirty
_HV_TYPEDIRTY       = 4    # HighVariable.typedirty
_HV_COVER_MASK      = 0x408  # coverdirty | extendcoverdirty (for isCoverDirty)
_VN_WRITTEN         = 0x10   # Varnode.written flag (def op assigned)
_CPUI_COPY          = 1      # OpCode.CPUI_COPY integer value
_ADDRSPACE_BIG_ENDIAN = 1    # AddrSpace.big_endian flag bit
# Mask of flags that block speculative merging when set on a HighVariable.
# If (flags & _SPEC_OK_BLOCKERS)==0 AND _symbol is None → _spec_ok=True.
_SPEC_OK_BLOCKERS   = (0x08 | 0x4000 | 0x8000 |   # INPUT|PERSIST|ADDRTIED
                       0x400000 |                  # INDIRECT_CREATE
                       0x80000000 |                # PROTO_PARTIAL
                       0x200)                      # NAMELOCK


class VariableGroup:
    """A collection of HighVariable objects that overlap.

    For a set of HighVariable objects that mutually overlap, a VariableGroup
    is a central access point for information about the intersections.
    """

    def __init__(self) -> None:
        self._pieceSet: List[VariablePiece] = []
        self._size: int = 0
        self._symbolOffset: int = 0

    def empty(self) -> bool:
        return len(self._pieceSet) == 0

    def addPiece(self, piece: VariablePiece) -> None:
        piece._group = self
        if piece in self._pieceSet:
            raise RuntimeError("Duplicate VariablePiece")
        self._pieceSet.append(piece)
        pieceMax = piece._groupOffset + piece._size
        if pieceMax > self._size:
            self._size = pieceMax

    def removePiece(self, piece: VariablePiece) -> None:
        try:
            self._pieceSet.remove(piece)
        except ValueError:
            pass

    def adjustOffsets(self, amt: int) -> None:
        for p in self._pieceSet:
            p._groupOffset += amt
        self._size += amt

    def getSize(self) -> int:
        return self._size

    def setSymbolOffset(self, val: int) -> None:
        self._symbolOffset = val

    def getSymbolOffset(self) -> int:
        return self._symbolOffset

    def combineGroups(self, op2: VariableGroup) -> None:
        """Combine given VariableGroup into this."""
        for p in list(op2._pieceSet):
            p.transferGroup(self)


class VariablePiece:
    """Information about how a HighVariable fits into a larger group or Symbol.

    Describes overlaps and how they affect the HighVariable Cover.
    """

    def __init__(self, high: HighVariable, offset: int,
                 grp_high: Optional[HighVariable] = None) -> None:
        self._high: HighVariable = high
        self._groupOffset: int = offset
        self._size: int = 0
        self._intersection: List[VariablePiece] = []
        self._cover: Cover = Cover()

        if grp_high is not None and grp_high._piece is not None:
            self._group = grp_high._piece._group
        else:
            self._group = VariableGroup()
        self._group.addPiece(self)

        # Calculate size from the HighVariable's instances
        if high._inst:
            self._size = high._inst[0].getSize()

    def getHigh(self) -> HighVariable:
        return self._high

    def getGroup(self) -> VariableGroup:
        return self._group

    def getOffset(self) -> int:
        return self._groupOffset

    def getSize(self) -> int:
        return self._size

    def getCover(self) -> Cover:
        return self._cover

    def numIntersection(self) -> int:
        return len(self._intersection)

    def getIntersection(self, i: int) -> VariablePiece:
        return self._intersection[i]

    def setHigh(self, newHigh: HighVariable) -> None:
        self._high = newHigh

    def transferGroup(self, newGroup: VariableGroup) -> None:
        oldGroup = self._group
        oldGroup.removePiece(self)
        newGroup.addPiece(self)

    def markIntersectionDirty(self) -> None:
        """Mark all pieces in the group as needing intersection recalculation."""
        for p in self._group._pieceSet:
            p._high._highflags |= (HighVariable.intersectdirty | HighVariable.extendcoverdirty)

    def markExtendCoverDirty(self) -> None:
        """Mark all intersecting pieces as having a dirty extended cover."""
        if (self._high._highflags & HighVariable.intersectdirty) != 0:
            return
        for p in self._intersection:
            p._high._highflags |= HighVariable.extendcoverdirty
        self._high._highflags |= HighVariable.extendcoverdirty

    def updateIntersections(self) -> None:
        """Calculate intersections with other pieces in the group."""
        if (self._high._highflags & HighVariable.intersectdirty) == 0:
            return
        endOffset = self._groupOffset + self._size
        self._intersection.clear()
        for p in self._group._pieceSet:
            if p is self:
                continue
            if endOffset <= p._groupOffset:
                continue
            otherEnd = p._groupOffset + p._size
            if self._groupOffset >= otherEnd:
                continue
            self._intersection.append(p)
        self._high._highflags &= ~HighVariable.intersectdirty

    def updateCover(self) -> None:
        """Calculate extended cover based on intersections."""
        if (self._high._highflags & (HighVariable.coverdirty | HighVariable.extendcoverdirty)) == 0:
            return
        self._high._updateInternalCover()
        self._cover = Cover()
        self._cover.merge(self._high._internalCover)
        for p in self._intersection:
            h = p._high
            h._updateInternalCover()
            self._cover.merge(h._internalCover)
        self._high._highflags &= ~HighVariable.extendcoverdirty

    def mergeGroups(self, op2: VariablePiece, mergePairs: list) -> None:
        """Combine two VariableGroups, returning HighVariable pairs to merge."""
        diff = self._groupOffset - op2._groupOffset
        if diff > 0:
            op2._group.adjustOffsets(diff)
        elif diff < 0:
            self._group.adjustOffsets(-diff)
        for piece in list(op2._group._pieceSet):
            # Check if there's a matching piece in self's group
            match = None
            for sp in self._group._pieceSet:
                if sp._groupOffset == piece._groupOffset and sp._size == piece._size:
                    match = sp
                    break
            if match is not None:
                mergePairs.append(match._high)
                mergePairs.append(piece._high)
                piece._high._piece = None
                op2._group.removePiece(piece)
            else:
                piece.transferGroup(self._group)


class HighVariable:
    """A high-level variable modeled as a list of low-level variables, each written once.

    In SSA form, a Varnode is written at most once. A high-level variable
    may be written multiple times, modeled as a list of Varnode objects
    where each holds the value for different parts of the code.
    """

    # Dirtiness flags
    flagsdirty       = 1
    namerepdirty     = 2
    typedirty        = 4
    coverdirty       = 8
    symboldirty      = 0x10
    copy_in1         = 0x20
    copy_in2         = 0x40
    type_finalized   = 0x80
    unmerged         = 0x100
    intersectdirty   = 0x200
    extendcoverdirty = 0x400

    __slots__ = (
        '_inst', '_numMergeClasses', '_highflags', '_flags', '_spec_ok',
        '_type', '_nameRepresentative', '_internalCover', '_piece',
        '_symbol', '_symboloffset',
    )

    def __init__(self, vn: Varnode) -> None:
        self._inst: List[Varnode] = [vn]
        self._numMergeClasses: int = 1
        self._highflags: int = (HighVariable.flagsdirty | HighVariable.namerepdirty |
                                HighVariable.typedirty | HighVariable.coverdirty)
        self._flags: int = 0
        self._spec_ok: bool = False  # True when no speculative-merge blockers are set
        self._type = None  # Datatype
        self._nameRepresentative: Optional[Varnode] = None
        self._internalCover: Cover = Cover()
        self._piece: Optional[VariablePiece] = None
        self._symbol = None  # Symbol
        self._symboloffset: int = -1

        vn.setHigh(self, self._numMergeClasses - 1)
        if vn.getSymbolEntry() is not None:
            self.setSymbol(vn)

    # --- Accessors ---

    def getType(self):
        if self._highflags & _HV_TYPEDIRTY:
            self._updateType()
        return self._type

    def getCover(self) -> Cover:
        if self._highflags & _HV_COVERDIRTY:
            self._updateCover()
        if self._piece is not None:
            return self._piece.getCover()
        return self._internalCover

    def getSymbol(self):
        if self._highflags & _HV_SYMBOLDIRTY:
            self._updateSymbol()
        return self._symbol

    def getSymbolOffset(self) -> int:
        return self._symboloffset

    def numInstances(self) -> int:
        return len(self._inst)

    def getInstance(self, i: int) -> Varnode:
        return self._inst[i]

    def getNumMergeClasses(self) -> int:
        return self._numMergeClasses

    # --- Flag queries ---

    def isMapped(self) -> bool:
        if self._highflags & _HV_FLAGSDIRTY: self._updateFlags()
        return bool(self._flags & _VN_MAPPED)

    def isPersist(self) -> bool:
        if self._highflags & _HV_FLAGSDIRTY: self._updateFlags()
        return bool(self._flags & _VN_PERSIST)

    def isAddrTied(self) -> bool:
        if self._highflags & _HV_FLAGSDIRTY: self._updateFlags()
        return bool(self._flags & _VN_ADDRTIED)

    def isInput(self) -> bool:
        if self._highflags & _HV_FLAGSDIRTY: self._updateFlags()
        return bool(self._flags & _VN_INPUT)

    def isUnaffected(self) -> bool:
        if self._highflags & _HV_FLAGSDIRTY: self._updateFlags()
        return bool(self._flags & _VN_UNAFFECTED)

    def isConstant(self) -> bool:
        if self._highflags & _HV_FLAGSDIRTY: self._updateFlags()
        return bool(self._flags & _VN_CONSTANT)

    def isTypeLock(self) -> bool:
        if self._highflags & _HV_FLAGSDIRTY: self._updateFlags()
        return bool(self._flags & _VN_TYPELOCK)

    def isNameLock(self) -> bool:
        if self._highflags & _HV_FLAGSDIRTY: self._updateFlags()
        return bool(self._flags & _VN_NAMELOCK)

    def isImplied(self) -> bool:
        if self._highflags & _HV_FLAGSDIRTY: self._updateFlags()
        return bool(self._flags & _VN_IMPLIED)

    def isSpacebase(self) -> bool:
        if self._highflags & _HV_FLAGSDIRTY: self._updateFlags()
        return bool(self._flags & _VN_SPACEBASE)

    def isExtraOut(self) -> bool:
        if self._highflags & _HV_FLAGSDIRTY: self._updateFlags()
        return (self._flags & (_VN_INDIRECT_CREATE | _VN_ADDRTIED)) == _VN_INDIRECT_CREATE

    def isProtoPartial(self) -> bool:
        if self._highflags & _HV_FLAGSDIRTY: self._updateFlags()
        return bool(self._flags & _VN_PROTO_PARTIAL)

    def setMark(self) -> None:
        self._flags |= _VN_MARK

    def clearMark(self) -> None:
        self._flags &= ~_VN_MARK

    def isMark(self) -> bool:
        return bool(self._flags & _VN_MARK)

    def isUnmerged(self) -> bool:
        return (self._highflags & HighVariable.unmerged) != 0

    def isSameGroup(self, op2: HighVariable) -> bool:
        """Test if this and op2 are pieces of the same symbol."""
        if self._piece is None or op2._piece is None:
            return False
        return self._piece.getGroup() is op2._piece.getGroup()

    def hasCover(self) -> bool:
        """Determine if this HighVariable has an associated cover."""
        self._updateFlags()
        from ghidra.ir.varnode import Varnode as VN
        return (self._flags & (VN.constant | VN.annotation | VN.insert)) == VN.insert

    def isUnattached(self) -> bool:
        return len(self._inst) == 0

    # --- Dirty management ---

    def flagsDirty(self) -> None:
        self._highflags |= (HighVariable.flagsdirty | HighVariable.namerepdirty)

    def coverDirty(self) -> None:
        self._highflags |= HighVariable.coverdirty
        if self._piece is not None:
            self._piece.markExtendCoverDirty()

    def typeDirty(self) -> None:
        self._highflags |= HighVariable.typedirty

    def symbolDirty(self) -> None:
        self._highflags |= HighVariable.symboldirty

    def setUnmerged(self) -> None:
        self._highflags |= HighVariable.unmerged

    def setCopyIn1(self) -> None:
        self._highflags |= HighVariable.copy_in1

    def setCopyIn2(self) -> None:
        self._highflags |= HighVariable.copy_in2

    def clearCopyIns(self) -> None:
        self._highflags &= ~(HighVariable.copy_in1 | HighVariable.copy_in2)

    def hasCopyIn1(self) -> bool:
        return (self._highflags & HighVariable.copy_in1) != 0

    def hasCopyIn2(self) -> bool:
        return (self._highflags & HighVariable.copy_in2) != 0

    def isCoverDirty(self) -> bool:
        return (self._highflags & (HighVariable.coverdirty | HighVariable.extendcoverdirty)) != 0

    # --- Representative / naming methods ---

    def getNameRepresentative(self) -> 'Varnode':
        """Return the Varnode best suited to provide a name.

        C++ ref: ``HighVariable::getNameRepresentative`` in variable.cc
        """
        if (self._highflags & HighVariable.namerepdirty) == 0:
            if self._nameRepresentative is not None:
                return self._nameRepresentative
        self._highflags &= ~HighVariable.namerepdirty
        if not self._inst:
            return self._nameRepresentative
        rep = self._inst[0]
        for vn in self._inst[1:]:
            if HighVariable.compareName(rep, vn):
                rep = vn
        self._nameRepresentative = rep
        return rep

    def getTypeRepresentative(self) -> 'Varnode':
        """Return the Varnode best suited to determine the data-type.

        C++ ref: ``HighVariable::getTypeRepresentative`` in variable.cc
        """
        if not self._inst:
            return None
        rep = self._inst[0]
        for vn in self._inst[1:]:
            if rep.isTypeLock() != vn.isTypeLock():
                if vn.isTypeLock():
                    rep = vn
            else:
                rtype = rep.getType()
                vtype = vn.getType()
                if rtype is not None and vtype is not None and hasattr(vtype, 'typeOrderBool'):
                    if vtype.typeOrderBool(rtype) < 0:
                        rep = vn
        return rep

    def getInputVarnode(self) -> 'Varnode':
        """Return the input Varnode member (must exist).

        C++ ref: ``HighVariable::getInputVarnode`` in variable.cc
        """
        for vn in self._inst:
            if vn.isInput():
                return vn
        raise RuntimeError("HighVariable has no input member")

    def hasName(self) -> bool:
        """Determine if this variable can have a name.

        Returns False for implied varnodes, non-coverable varnodes,
        and certain unaffected inputs like the stack pointer.

        C++ ref: ``HighVariable::hasName`` in variable.cc
        """
        indirectonly = True
        for vn in self._inst:
            if not vn.hasCover():
                if len(self._inst) > 1:
                    raise RuntimeError("Non-coverable varnode has been merged")
                return False
            if vn.isImplied():
                if len(self._inst) > 1:
                    raise RuntimeError("Implied varnode has been merged")
                return False
            if not (hasattr(vn, 'isIndirectOnly') and vn.isIndirectOnly()):
                indirectonly = False
        if self.isUnaffected():
            if not self.isInput():
                return False
            if indirectonly:
                return False
            try:
                vn = self.getInputVarnode()
            except RuntimeError:
                return False
            if not (hasattr(vn, 'isIllegalInput') and vn.isIllegalInput()):
                if vn.isSpacebase():
                    return False
        return True

    # --- Internal update methods ---

    def updateFlags(self) -> None:
        """Public alias for flag update (matches C++ public method)."""
        self._updateFlags()

    def _updateFlags(self) -> None:
        if (self._highflags & HighVariable.flagsdirty) == 0:
            return
        from ghidra.ir.varnode import Varnode as VN
        fl = 0
        for vn in self._inst:
            fl |= vn.getFlags()
        self._flags &= (VN.mark | VN.typelock)
        self._flags |= fl & ~(VN.mark | VN.directwrite | VN.typelock)
        self._highflags &= ~HighVariable.flagsdirty
        self._spec_ok = (self._flags & _SPEC_OK_BLOCKERS) == 0 and self._symbol is None

    def _updateType(self) -> None:
        if (self._highflags & HighVariable.typedirty) == 0:
            return
        self._highflags &= ~HighVariable.typedirty
        if (self._highflags & HighVariable.type_finalized) != 0:
            return
        from ghidra.ir.varnode import Varnode as VN
        vn = self.getTypeRepresentative()
        if vn is None:
            return
        self._type = vn.getType()
        self.stripType()
        self._flags &= ~VN.typelock
        if vn.isTypeLock():
            self._flags |= VN.typelock

    def _updateInternalCover(self) -> None:
        """(Re)derive the internal cover from member Varnodes."""
        if (self._highflags & HighVariable.coverdirty) == 0:
            return
        self._internalCover.clear()
        if self._inst and self._inst[0].hasCover():
            for vn in self._inst:
                c = vn.getCover()
                if c is not None:
                    self._internalCover.merge(c)
        self._highflags &= ~HighVariable.coverdirty

    def _updateCover(self) -> None:
        if self._piece is None:
            self._updateInternalCover()
        else:
            self._piece.updateIntersections()
            self._piece.updateCover()

    # --- Merge operations ---

    def remove(self, vn: Varnode) -> None:
        """Remove a member Varnode from this."""
        for i, v in enumerate(self._inst):
            if v is vn:
                self._inst.pop(i)
                self._highflags |= (HighVariable.flagsdirty | HighVariable.namerepdirty |
                                    HighVariable.coverdirty | HighVariable.typedirty)
                if vn.getSymbolEntry() is not None:
                    self._highflags |= HighVariable.symboldirty
                if self._piece is not None:
                    self._piece.markExtendCoverDirty()
                return

    def mergeInternal(self, tv2: HighVariable, isspeculative: bool = False) -> None:
        """Merge another HighVariable into this."""
        self._highflags |= (HighVariable.flagsdirty | HighVariable.namerepdirty | HighVariable.typedirty)
        if tv2._symbol is not None:
            if (tv2._highflags & HighVariable.symboldirty) == 0:
                self._symbol = tv2._symbol
                self._symboloffset = tv2._symboloffset
                self._highflags &= ~HighVariable.symboldirty
        if isspeculative:
            for vn in tv2._inst:
                vn.setHigh(self, vn.getMergeGroup() + self._numMergeClasses)
            self._numMergeClasses += tv2._numMergeClasses
        else:
            if self._numMergeClasses != 1 or tv2._numMergeClasses != 1:
                raise RuntimeError("Non-speculative merge after speculative merges")
            for vn in tv2._inst:
                vn.setHigh(self, vn.getMergeGroup())
        merged = sorted(self._inst + tv2._inst, key=lambda v: v.getAddr())
        self._inst = merged
        tv2._inst.clear()
        if ((self._highflags & HighVariable.coverdirty) == 0 and
                (tv2._highflags & HighVariable.coverdirty) == 0):
            self._internalCover.merge(tv2._internalCover)
        else:
            self._highflags |= HighVariable.coverdirty

    def setSymbol(self, vn: Varnode) -> None:
        """Update Symbol information for this from the given member Varnode."""
        self._spec_ok = False  # symbol assigned → disable fast-path
        entry = vn.getSymbolEntry()
        if entry is None:
            return
        sym = entry.getSymbol() if hasattr(entry, 'getSymbol') else None
        if self._symbol is not None and sym is not None and self._symbol is not sym:
            if (self._highflags & HighVariable.symboldirty) == 0:
                raise RuntimeError("Symbols assigned to the same variable")
        if sym is not None:
            self._symbol = sym
        if vn.isProtoPartial() and self._piece is not None:
            self._symboloffset = self._piece.getOffset() + self._piece.getGroup().getSymbolOffset()
        elif hasattr(entry, 'isDynamic') and entry.isDynamic():
            self._symboloffset = -1
        elif (self._symbol is not None and hasattr(self._symbol, 'getType') and
              self._symbol.getType() is not None and
              hasattr(entry, 'getAddr') and
              self._symbol.getType().getSize() == vn.getSize() and
              entry.getAddr() == vn.getAddr() and
              not (hasattr(entry, 'isPiece') and entry.isPiece())):
            self._symboloffset = -1
        else:
            symtype = self._symbol.getType() if (self._symbol and hasattr(self._symbol, 'getType')) else None
            symsize = symtype.getSize() if symtype is not None else 0
            if hasattr(vn, 'getAddr') and hasattr(entry, 'getAddr') and hasattr(entry, 'getOffset'):
                self._symboloffset = vn.getAddr().overlapJoin(
                    0, entry.getAddr(), symsize
                ) + entry.getOffset()
            else:
                self._symboloffset = -1
        if (self._type is not None and hasattr(self._type, 'getMetatype') and
                self._type.getMetatype() == 'TYPE_PARTIALUNION'):
            self._highflags |= HighVariable.typedirty
        self._highflags &= ~HighVariable.symboldirty

    def setSymbolReference(self, sym, off: int) -> None:
        self._symbol = sym
        self._symboloffset = off
        self._highflags &= ~HighVariable.symboldirty
        if sym is not None:
            self._spec_ok = False

    def merge(self, tv2: HighVariable, testCache=None, isspeculative: bool = False) -> None:
        """Merge with another HighVariable taking into account groups."""
        if tv2 is self:
            return
        if testCache is not None and hasattr(testCache, 'moveIntersectTests'):
            testCache.moveIntersectTests(self, tv2)
        if self._piece is None and tv2._piece is None:
            self.mergeInternal(tv2, isspeculative)
            return
        if tv2._piece is None:
            self._piece.markExtendCoverDirty()
            self.mergeInternal(tv2, isspeculative)
            return
        if self._piece is None:
            self.transferPiece(tv2)
            self._piece.markExtendCoverDirty()
            self.mergeInternal(tv2, isspeculative)
            return
        if isspeculative:
            raise RuntimeError("Trying speculatively merge variables in separate groups")
        mergePairs = []
        self._piece.mergeGroups(tv2._piece, mergePairs)
        for i in range(0, len(mergePairs), 2):
            high1 = mergePairs[i]
            high2 = mergePairs[i + 1]
            if testCache is not None and hasattr(testCache, 'moveIntersectTests'):
                testCache.moveIntersectTests(high1, high2)
            high1.mergeInternal(high2, isspeculative)
        self._piece.markIntersectionDirty()

    def transferPiece(self, tv2: HighVariable) -> None:
        """Transfer ownership of another's VariablePiece to this."""
        self._piece = tv2._piece
        tv2._piece = None
        self._piece.setHigh(self)
        self._highflags |= (tv2._highflags & (HighVariable.intersectdirty | HighVariable.extendcoverdirty))
        tv2._highflags &= ~(HighVariable.intersectdirty | HighVariable.extendcoverdirty)

    def updateCover(self) -> None:
        """Public method to force cover update."""
        self._updateCover()

    def updateInternalCover(self) -> None:
        """(Re)derive the internal cover from member Varnodes."""
        self._updateInternalCover()

    def getSymbolEntry(self):
        """Get the SymbolEntry mapping to this or None."""
        for vn in self._inst:
            entry = vn.getSymbolEntry()
            if entry is not None:
                if hasattr(entry, 'getSymbol') and entry.getSymbol() is self._symbol:
                    return entry
        return None

    def finalizeDatatype(self, typeFactory=None) -> None:
        """Set a final data-type matching the associated Symbol."""
        self._highflags |= HighVariable.type_finalized

    def establishGroupSymbolOffset(self) -> None:
        """Transfer symbol offset of this to the VariableGroup."""
        group = self._piece.getGroup()
        off = self._symboloffset
        if off < 0:
            off = 0
        off -= self._piece.getOffset()
        if off < 0:
            raise RuntimeError("Symbol offset is incompatible with VariableGroup")
        group.setSymbolOffset(off)

    def stripType(self) -> None:
        """Take the stripped form of the current data-type."""
        if self._type is None or not hasattr(self._type, 'hasStripped'):
            return
        if not self._type.hasStripped():
            return
        meta = self._type.getMetatype() if hasattr(self._type, 'getMetatype') else None
        if meta in ('TYPE_PARTIALUNION', 'TYPE_PARTIALSTRUCT'):
            if self._symbol is not None and self._symboloffset != -1:
                submeta = self._symbol.getType().getMetatype() if hasattr(self._symbol, 'getType') else None
                if submeta in ('TYPE_STRUCT', 'TYPE_UNION'):
                    return
        elif hasattr(self._type, 'isEnumType') and self._type.isEnumType():
            if len(self._inst) == 1 and self._inst[0].isConstant():
                return
        if hasattr(self._type, 'getStripped'):
            self._type = self._type.getStripped()

    def _updateSymbol(self) -> None:
        """(Re)derive the Symbol and offset from member Varnodes."""
        if (self._highflags & HighVariable.symboldirty) == 0:
            return
        self._highflags &= ~HighVariable.symboldirty
        self._symbol = None
        for vn in self._inst:
            if vn.getSymbolEntry() is not None:
                self.setSymbol(vn)
                return

    def encode(self, encoder) -> None:
        """Encode this variable to stream as a <high> element.

        C++ ref: ``HighVariable::encode``
        """
        from ghidra.core.marshal import (
            ELEM_HIGH, ELEM_ADDR, ATTRIB_REPREF, ATTRIB_CLASS,
            ATTRIB_TYPELOCK, ATTRIB_SYMREF, ATTRIB_OFFSET, ATTRIB_REF,
        )
        from ghidra.database.database import Symbol
        vn = self.getNameRepresentative()
        encoder.openElement(ELEM_HIGH)
        encoder.writeUnsignedInteger(ATTRIB_REPREF, vn.getCreateIndex())
        if self.isSpacebase() or self.isImplied():
            encoder.writeString(ATTRIB_CLASS, "other")
        elif self.isPersist() and self.isAddrTied():
            encoder.writeString(ATTRIB_CLASS, "global")
        elif self.isConstant():
            encoder.writeString(ATTRIB_CLASS, "constant")
        elif not self.isPersist() and self._symbol is not None:
            cat = self._symbol.getCategory() if hasattr(self._symbol, 'getCategory') else -1
            if cat == Symbol.function_parameter:
                encoder.writeString(ATTRIB_CLASS, "param")
            elif hasattr(self._symbol, 'getScope') and self._symbol.getScope().isGlobal():
                encoder.writeString(ATTRIB_CLASS, "global")
            else:
                encoder.writeString(ATTRIB_CLASS, "local")
        else:
            encoder.writeString(ATTRIB_CLASS, "other")
        if self.isTypeLock():
            encoder.writeBool(ATTRIB_TYPELOCK, True)
        if self._symbol is not None:
            if hasattr(self._symbol, 'getId'):
                encoder.writeUnsignedInteger(ATTRIB_SYMREF, self._symbol.getId())
            if self._symboloffset >= 0:
                encoder.writeSignedInteger(ATTRIB_OFFSET, self._symboloffset)
        tp = self.getType()
        if tp is not None and hasattr(tp, 'encodeRef'):
            tp.encodeRef(encoder)
        for inst_vn in self._inst:
            encoder.openElement(ELEM_ADDR)
            encoder.writeUnsignedInteger(ATTRIB_REF, inst_vn.getCreateIndex())
            encoder.closeElement(ELEM_ADDR)
        encoder.closeElement(ELEM_HIGH)

    @staticmethod
    def compareName(vn1, vn2) -> bool:
        """Return True if vn2's name would override vn1's."""
        if vn1.isNameLock():
            return False
        if vn2.isNameLock():
            return True
        if vn1.isUnaffected() != vn2.isUnaffected():
            return vn2.isUnaffected()
        if vn1.isPersist() != vn2.isPersist():
            return vn2.isPersist()
        if vn1.isInput() != vn2.isInput():
            return vn2.isInput()
        if vn1.isAddrTied() != vn2.isAddrTied():
            return vn2.isAddrTied()
        if vn1.isProtoPartial() != vn2.isProtoPartial():
            return vn2.isProtoPartial()
        spc1 = vn1.getSpace()
        spc2 = vn2.getSpace()
        if spc1 is not None and spc2 is not None:
            t1 = spc1.getType() if hasattr(spc1, 'getType') else None
            t2 = spc2.getType() if hasattr(spc2, 'getType') else None
            IPTR_INTERNAL = 'IPTR_INTERNAL'
            if t1 != IPTR_INTERNAL and t2 == IPTR_INTERNAL:
                return False
            if t1 == IPTR_INTERNAL and t2 != IPTR_INTERNAL:
                return True
        if vn1.isWritten() != vn2.isWritten():
            return vn2.isWritten()
        if not vn1.isWritten():
            return False
        t1 = vn1.getDef().getTime() if hasattr(vn1.getDef(), 'getTime') else 0
        t2 = vn2.getDef().getTime() if hasattr(vn2.getDef(), 'getTime') else 0
        if t1 != t2:
            return t2 < t1
        return False

    @staticmethod
    def compareJustLoc(a, b) -> bool:
        """Compare based on storage location."""
        return a.getAddr() < b.getAddr()

    @staticmethod
    def markExpression(vn, highList: list) -> int:
        """Mark and collect variables in expression using iterative DFS."""
        from ghidra.core.expression import PcodeOpNode
        from ghidra.core.opcodes import OpCode
        high = vn.getHigh()
        high.setMark()
        highList.append(high)
        retVal = 0
        if not vn.isWritten():
            return retVal
        path = []
        op = vn.getDef()
        if op.isCall():
            retVal |= 1
        if op.code() == OpCode.CPUI_LOAD:
            retVal |= 2
        path.append(PcodeOpNode(op, 0))
        while path:
            node = path[-1]
            if node.op.numInput() <= node.slot:
                path.pop()
                continue
            curVn = node.op.getIn(node.slot)
            node.slot += 1
            if curVn.isAnnotation():
                continue
            if hasattr(curVn, 'isExplicit') and curVn.isExplicit():
                h = curVn.getHigh()
                if h.isMark():
                    continue
                h.setMark()
                highList.append(h)
                continue
            if not curVn.isWritten():
                continue
            op = curVn.getDef()
            if op.isCall():
                retVal |= 1
            if op.code() == OpCode.CPUI_LOAD:
                retVal |= 2
            path.append(PcodeOpNode(op, 0))
        return retVal

    # --- Query helpers ---

    def getTiedVarnode(self) -> Optional[Varnode]:
        """Find the first address-tied member Varnode."""
        for vn in self._inst:
            if vn.isAddrTied():
                return vn
        raise RuntimeError("Could not find address-tied varnode")

    def groupWith(self, off: int, hi2: HighVariable) -> None:
        """Put this and another HighVariable in the same intersection group."""
        if self._piece is None and hi2._piece is None:
            hi2._piece = VariablePiece(hi2, 0)
            self._piece = VariablePiece(self, off, hi2)
            hi2._piece.markIntersectionDirty()
            return
        if self._piece is None:
            if (hi2._highflags & HighVariable.intersectdirty) == 0:
                hi2._piece.markIntersectionDirty()
            self._highflags |= (HighVariable.intersectdirty | HighVariable.extendcoverdirty)
            off += hi2._piece.getOffset()
            self._piece = VariablePiece(self, off, hi2)
        elif hi2._piece is None:
            hi2Off = self._piece.getOffset() - off
            if hi2Off < 0:
                self._piece.getGroup().adjustOffsets(-hi2Off)
                hi2Off = 0
            if (self._highflags & HighVariable.intersectdirty) == 0:
                self._piece.markIntersectionDirty()
            hi2._highflags |= (HighVariable.intersectdirty | HighVariable.extendcoverdirty)
            hi2._piece = VariablePiece(hi2, hi2Off, self)
        else:
            offDiff = hi2._piece.getOffset() + off - self._piece.getOffset()
            if offDiff != 0:
                self._piece.getGroup().adjustOffsets(offDiff)
            hi2._piece.getGroup().combineGroups(self._piece.getGroup())
            hi2._piece.markIntersectionDirty()

    def printInfo(self) -> str:
        """Print information about this HighVariable."""
        self._updateType()
        parts = []
        if self._symbol is None:
            parts.append("Variable: UNNAMED\n")
        else:
            name = self._symbol.getName() if hasattr(self._symbol, 'getName') else str(self._symbol)
            s = f"Variable: {name}"
            if self._symboloffset != -1:
                s += "(partial)"
            parts.append(s + "\n")
        parts.append(f"Type: {self._type}\n\n")
        for vn in self._inst:
            mg = vn.getMergeGroup() if hasattr(vn, 'getMergeGroup') else 0
            parts.append(f"{mg}: ")
            if hasattr(vn, 'printInfo'):
                parts.append(str(vn.printInfo()))
            parts.append("\n")
        return "".join(parts)

    def printCover(self) -> str:
        if (self._highflags & HighVariable.coverdirty) == 0:
            return str(self._internalCover)
        return "Cover dirty"

    def instanceIndex(self, vn) -> int:
        """Find the index of a specific Varnode member."""
        for i, v in enumerate(self._inst):
            if v is vn:
                return i
        return -1

    def verifyCover(self) -> None:
        """Check that there are no internal Cover intersections (debug)."""
        accumCover = Cover()
        for i, vn in enumerate(self._inst):
            c = vn.getCover()
            if c is not None and accumCover.intersect(c) == 2:
                for j in range(i):
                    otherVn = self._inst[j]
                    oc = otherVn.getCover()
                    if oc is not None and oc.intersect(c) == 2:
                        if not otherVn.copyShadow(vn):
                            raise RuntimeError("HighVariable has internal intersection")
            if c is not None:
                accumCover.merge(c)

    def __repr__(self) -> str:
        return self.printInfo()


# =========================================================================
# HighEdge
# =========================================================================

class HighEdge:
    """A record for caching a Cover intersection test between two HighVariable objects."""

    def __init__(self, a: HighVariable, b: HighVariable) -> None:
        self.a = a
        self.b = b

    def __lt__(self, op2: HighEdge) -> bool:
        if self.a is op2.a:
            return id(self.b) < id(op2.b)
        return id(self.a) < id(op2.a)

    def __eq__(self, other) -> bool:
        return self.a is other.a and self.b is other.b

    def __hash__(self) -> int:
        return hash((id(self.a), id(self.b)))


# =========================================================================
# HighIntersectTest
# =========================================================================

class HighIntersectTest:
    """A cache of Cover intersection tests for HighVariables.

    The intersect() method returns the result of a full Cover intersection test.
    Results are cached so repeated calls don't need the full calculation.
    """

    def __init__(self, affectingOps=None) -> None:
        self._affectingOps = affectingOps
        # Per-HighVariable adjacency: _adj[id(a)][id(b)] = bool (intersection result)
        # _id_to_high maps id(h) -> HighVariable object for moveIntersectTests
        self._adj: dict = {}  # id(high) -> {id(neighbor): bool}
        self._id_to_high: dict = {}  # id(high) -> HighVariable
        self._blist: list = []  # reused scratch buffer for _blockIntersection

    @staticmethod
    def _gatherBlockVarnodes(a: HighVariable, blk: int, cb_outer, res: list) -> None:
        """Gather Varnode instances whose cover at blk intersects cb_outer > 1."""
        for vn in a._inst:
            c = vn._cover
            if c is not None:
                cb1 = c._cover.get(blk)
                if cb1 is not None and 1 < cb1.intersect(cb_outer):
                    res.append(vn)

    @staticmethod
    def _testBlockIntersection(a: HighVariable, blk: int, cb_outer, relOff: int, blist: list) -> bool:
        """Test instances for intersection; blist contains plain Varnode objects."""
        for vn in a._inst:
            c = vn._cover
            if c is None:
                continue
            cb1 = c._cover.get(blk)
            if cb1 is None or 2 > cb1.intersect(cb_outer):
                continue
            sz = vn._size
            for vn2 in blist:
                c2 = vn2._cover
                if c2 is not None:
                    cb_vn = c2._cover.get(blk)
                    if cb_vn is not None and 1 < cb_vn.intersect(cb1):
                        if sz == vn2._size:
                            # Inline copyShadow(vn, vn2) — return True if no shadow (real intersection)
                            _cs = vn; _cs2 = vn2
                            if _cs is not _cs2:
                                while _cs is not None and (_cs._flags & _VN_WRITTEN) and _cs._def._opcode_enum == _CPUI_COPY:
                                    _cs = _cs._def._inrefs[0]
                                    if _cs is _cs2: break
                                else:
                                    if _cs is None:
                                        return True
                                    while _cs2 is not None and (_cs2._flags & _VN_WRITTEN) and _cs2._def._opcode_enum == _CPUI_COPY:
                                        _cs2 = _cs2._def._inrefs[0]
                                        if _cs is _cs2: break
                                    else:
                                        return True
                        else:
                            if not vn.partialCopyShadow(vn2, relOff):
                                return True
        return False

    def _blockIntersection(self, a: HighVariable, b: HighVariable, blk: int,
                            aCover=None, bCover=None) -> bool:
        """Test if two HighVariables intersect on a given block."""
        blist = []
        if aCover is None:
            aCover = a.getCover()
        if bCover is None:
            bCover = b.getCover()
        cb_a = aCover._cover.get(blk)
        cb_b = bCover._cover.get(blk)
        if cb_a is None or cb_b is None:
            return False
        self._gatherBlockVarnodes(b, blk, cb_a, blist)
        if self._testBlockIntersection(a, blk, cb_b, 0, blist):
            return True
        if a._piece is not None:
            baseOff = a._piece.getOffset()
            for i in range(a._piece.numIntersection()):
                interPiece = a._piece.getIntersection(i)
                off = interPiece.getOffset() - baseOff
                if self._testBlockIntersection(interPiece.getHigh(), blk, cb_b, off, blist):
                    return True
        if b._piece is not None:
            bBaseOff = b._piece.getOffset()
            for i in range(b._piece.numIntersection()):
                blist2 = []
                bPiece = b._piece.getIntersection(i)
                bOff = bPiece.getOffset() - bBaseOff
                self._gatherBlockVarnodes(bPiece.getHigh(), blk, cb_a, blist2)
                if self._testBlockIntersection(a, blk, cb_b, -bOff, blist2):
                    return True
                if a._piece is not None:
                    aBaseOff = a._piece.getOffset()
                    for j in range(a._piece.numIntersection()):
                        aInterPiece = a._piece.getIntersection(j)
                        aOff = (aInterPiece.getOffset() - aBaseOff) - bOff
                        if aOff > 0 and aOff >= bPiece.getSize():
                            continue
                        if aOff < 0 and -aOff >= aInterPiece.getSize():
                            continue
                        if self._testBlockIntersection(aInterPiece.getHigh(), blk, cb_b, aOff, blist2):
                            return True
        return False

    def _purgeHigh(self, high: HighVariable) -> None:
        """Remove cached intersection tests for a given HighVariable."""
        hid = id(high)
        neighbors = self._adj.pop(hid, None)
        if neighbors is None:
            return
        # Remove reverse edges for each neighbor O(degree)
        for nbid in neighbors:
            nb_map = self._adj.get(nbid)
            if nb_map is not None:
                nb_map.pop(hid, None)
                if not nb_map:
                    del self._adj[nbid]

    def _testUntiedCallIntersection(self, tied: HighVariable, untied: HighVariable) -> bool:
        """Test if untied HighVariable intersects an address-tied one during a call."""
        if tied.isPersist():
            return False
        try:
            vn = tied.getTiedVarnode()
        except RuntimeError:
            return False
        if hasattr(vn, 'hasNoLocalAlias') and vn.hasNoLocalAlias():
            return False
        if self._affectingOps is not None:
            if hasattr(self._affectingOps, 'isPopulated') and not self._affectingOps.isPopulated():
                self._affectingOps.populate()
            uc = untied.getCover()
            if hasattr(uc, 'intersect') and hasattr(self._affectingOps, '__iter__'):
                return uc.intersect(self._affectingOps, vn)
        return False

    def updateHigh(self, a: HighVariable) -> bool:
        """Make sure given HighVariable's Cover is up-to-date."""
        if not (a._highflags & _HV_COVER_MASK):
            return True
        a.updateCover()
        self._purgeHigh(a)
        return False

    def intersection(self, a: HighVariable, b: HighVariable) -> bool:
        """Test the intersection of two HighVariables."""
        if a is b:
            return False
        # Inline updateHigh: ensure covers are up-to-date
        if a._highflags & _HV_COVER_MASK:
            a.updateCover()
            self._purgeHigh(a)
        if b._highflags & _HV_COVER_MASK:
            b.updateCover()
            self._purgeHigh(b)
        a_piece = a._piece; b_piece = b._piece
        aCover = a_piece._cover if a_piece is not None else a._internalCover
        bCover = b_piece._cover if b_piece is not None else b._internalCover
        if aCover is None or bCover is None:
            return False
        # Inline intersectList + common no-piece _blockIntersection path
        ac = aCover._cover
        c2 = bCover._cover
        no_piece = a_piece is None and b_piece is None
        a_inst = a._inst; b_inst = b._inst
        if no_piece and len(a_inst) == 1 and len(b_inst) == 1:
            # ---- Dominant fast path: single-instance no-piece ----
            # All 3 inner intersect checks already guaranteed by outer cb1.intersect(cb2)>=2.
            vn_a = a_inst[0]; vn_b = b_inst[0]
            if vn_a._size == vn_b._size:
                # Same-size subpath: inline copyShadow, no per-block branch
                if vn_a is not vn_b:
                    if len(ac) > len(c2): ac, c2 = c2, ac  # iterate smaller dict
                    for blk, cb1 in ac.items():
                        cb2 = c2.get(blk)
                        if cb2 is None:
                            continue
                        # Inline CoverBlock.intersect >= 2 (saves 4.95M fn-call overheads)
                        _us1 = cb1.ustart; _ue1 = cb1.ustop
                        _us2 = cb2.ustart; _ue2 = cb2.ustop
                        if _us1 <= _ue1:
                            if _us2 <= _ue2:
                                if _ue1 <= _us2 or _ue2 <= _us1: continue
                            else:
                                if _us1 >= _ue2 and _ue1 <= _us2: continue
                        else:
                            if _us2 <= _ue2:
                                if _us2 >= _ue1 and _ue2 <= _us1: continue
                        _va = vn_a
                        while (_va is not None) and (_va._flags & _VN_WRITTEN) and _va._def._opcode_enum == _CPUI_COPY:
                            _va = _va._def._inrefs[0]
                            if _va is vn_b: break
                        else:
                            _vb = vn_b
                            while (_vb is not None) and (_vb._flags & _VN_WRITTEN) and _vb._def._opcode_enum == _CPUI_COPY:
                                _vb = _vb._def._inrefs[0]
                                if _va is _vb: break
                            else:
                                return True
            else:
                # Different-size subpath: inline partialCopyShadow, hoist setup outside loop
                # relOff=0 guaranteed; sizes differ guaranteed; so s1 < s2 after reorder
                _ps1 = vn_a._size; _ps2 = vn_b._size
                if _ps1 < _ps2:
                    _psv = vn_a; _pop2 = vn_b
                else:
                    _psv = vn_b; _pop2 = vn_a; _ps1, _ps2 = _ps2, _ps1
                _pspc = _psv._loc.base
                _plb = (_ps2 - _ps1) if (_pspc is not None and (_pspc._flags & _ADDRSPACE_BIG_ENDIAN)) else 0
                if len(ac) > len(c2): ac, c2 = c2, ac  # iterate smaller dict
                for blk, cb1 in ac.items():
                    cb2 = c2.get(blk)
                    if cb2 is None:
                        continue
                    _us1 = cb1.ustart; _ue1 = cb1.ustop
                    _us2 = cb2.ustart; _ue2 = cb2.ustop
                    if _us1 <= _ue1:
                        if _us2 <= _ue2:
                            if _ue1 <= _us2 or _ue2 <= _us1: continue
                        else:
                            if _us1 >= _ue2 and _ue1 <= _us2: continue
                    else:
                        if _us2 <= _ue2:
                            if _us2 >= _ue1 and _ue2 <= _us1: continue
                    if not _psv.findSubpieceShadow(_plb, _pop2, 0):
                        if not _pop2.findPieceShadow(_plb, _psv):
                            return True
        elif no_piece:
            # Multi-instance no-piece path — all CoverBlock.intersect calls inlined
            for blk, cb1 in ac.items():
                cb2 = c2.get(blk)
                if cb2 is None:
                    continue
                # Inline cb1.intersect(cb2) < 2
                _u1s = cb1.ustart; _u1e = cb1.ustop
                _u2s = cb2.ustart; _u2e = cb2.ustop
                if _u1s <= _u1e:
                    if _u2s <= _u2e:
                        if _u1e <= _u2s or _u2e <= _u1s: continue
                    else:
                        if _u1s >= _u2e and _u1e <= _u2s: continue
                else:
                    if _u2s <= _u2e:
                        if _u2s >= _u1e and _u2e <= _u1s: continue
                for vn_a in a_inst:
                    ca = vn_a._cover
                    if ca is None:
                        continue
                    ca_blk = ca._cover.get(blk)
                    if ca_blk is None:
                        continue
                    # Inline ca_blk.intersect(cb2) < 2
                    _cas = ca_blk.ustart; _cae = ca_blk.ustop
                    if _cas <= _cae:
                        if _u2s <= _u2e:
                            if _cae <= _u2s or _u2e <= _cas: continue
                        else:
                            if _cas >= _u2e and _cae <= _u2s: continue
                    else:
                        if _u2s <= _u2e:
                            if _u2s >= _cae and _u2e <= _cas: continue
                    sz_a = vn_a._size
                    for vn_b in b_inst:
                        cb = vn_b._cover
                        if cb is None:
                            continue
                        cb_blk = cb._cover.get(blk)
                        if cb_blk is None:
                            continue
                        # Inline cb_blk.intersect(cb1) < 2
                        _cbs = cb_blk.ustart; _cbe = cb_blk.ustop
                        if _cbs <= _cbe:
                            if _u1s <= _u1e:
                                if _cbe <= _u1s or _u1e <= _cbs: continue
                            else:
                                if _cbs >= _u1e and _cbe <= _u1s: continue
                        else:
                            if _u1s <= _u1e:
                                if _u1s >= _cbe and _u1e <= _cbs: continue
                        # Inline cb_blk.intersect(ca_blk) < 2
                        if _cbs <= _cbe:
                            if _cas <= _cae:
                                if _cbe <= _cas or _cae <= _cbs: continue
                            else:
                                if _cbs >= _cae and _cbe <= _cas: continue
                        else:
                            if _cas <= _cae:
                                if _cas >= _cbe and _cae <= _cbs: continue
                        sz_b = vn_b._size
                        if sz_a == sz_b:
                            if not vn_a.copyShadow(vn_b):
                                return True
                        else:
                            # Inline partialCopyShadow(vn_a, vn_b, 0) — relOff=0, sizes differ
                            _pcs_spc = vn_a._loc.base
                            _pcs_big = (_pcs_spc._flags & _ADDRSPACE_BIG_ENDIAN) if _pcs_spc is not None else 0
                            if sz_a < sz_b:
                                _plb = (sz_b - sz_a) if _pcs_big else 0
                                if not vn_a.findSubpieceShadow(_plb, vn_b, 0):
                                    if not vn_b.findPieceShadow(_plb, vn_a):
                                        return True
                            else:
                                _plb = (sz_a - sz_b) if _pcs_big else 0
                                if not vn_b.findSubpieceShadow(_plb, vn_a, 0):
                                    if not vn_a.findPieceShadow(_plb, vn_b):
                                        return True
        else:
            # Has-piece path
            for blk, cb1 in aCover._cover.items():
                cb2 = c2.get(blk)
                if cb2 is None or cb1.intersect(cb2) < 2:
                    continue
                if self._blockIntersection(a, b, blk, aCover, bCover):
                    return True
        aTied = a.isAddrTied()
        if aTied != b.isAddrTied():
            if aTied:
                return self._testUntiedCallIntersection(a, b)
            return self._testUntiedCallIntersection(b, a)
        return False

    def moveIntersectTests(self, high1: HighVariable, high2: HighVariable) -> None:
        """No-op: cache removed, intersections are always recomputed."""
        pass

    def clear(self) -> None:
        """Clear any cached tests."""
        self._adj.clear()
        self._id_to_high.clear()
