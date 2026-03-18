"""Rules governing mapping of data-type to address for prototype models.

C++ ref: ``modelrules.hh`` / ``modelrules.cc``
"""
from __future__ import annotations

from typing import TYPE_CHECKING, List, Optional, Set

from ghidra.core.address import Address
from ghidra.core.error import DecoderError, LowlevelError
from ghidra.core.marshal import (
    ATTRIB_A, ATTRIB_ALIGN, ATTRIB_B, ATTRIB_FIRST, ATTRIB_INDEX,
    ATTRIB_LAST, ATTRIB_MINSIZE, ATTRIB_MAXSIZE, ATTRIB_NAME,
    ATTRIB_AFTER_BYTES, ATTRIB_AFTER_STORAGE, ATTRIB_FILL_ALTERNATE,
    ATTRIB_MATCHSIZE, ATTRIB_MAX_PRIMITIVES, ATTRIB_REVERSEJUSTIFY,
    ATTRIB_REVERSESIGNIF, ATTRIB_SIZES, ATTRIB_STACKSPILL, ATTRIB_STORAGE,
    ATTRIB_STRATEGY, ATTRIB_VOIDLOCK,
    ELEM_CONSUME, ELEM_CONSUME_EXTRA, ELEM_CONSUME_REMAINING,
    ELEM_CONVERT_TO_PTR, ELEM_DATATYPE, ELEM_DATATYPE_AT,
    ELEM_EXTRA_STACK, ELEM_GOTO_STACK, ELEM_HIDDEN_RETURN,
    ELEM_JOIN, ELEM_JOIN_DUAL_CLASS, ELEM_JOIN_PER_PRIMITIVE,
    ELEM_POSITION, ELEM_RULE, ELEM_VARARGS,
)
from ghidra.core.pcoderaw import VarnodeData
from ghidra.types.datatype import (
    TypeClass, MetaType,
    TYPE_UNKNOWN, TYPE_INT, TYPE_UINT, TYPE_BOOL, TYPE_CODE,
    TYPE_FLOAT, TYPE_PTR, TYPE_PTRREL, TYPE_ARRAY, TYPE_STRUCT, TYPE_UNION,
    TYPECLASS_GENERAL, TYPECLASS_FLOAT,
    string2metatype, string2typeclass, metatype2typeclass,
)

if TYPE_CHECKING:
    from ghidra.types.datatype import Datatype, TypeFactory
    from ghidra.fspec.fspec import (
        ParamEntry, ParamListStandard, ParameterPieces, PrototypePieces,
    )
    from ghidra.fspec.paramactive import ParamActive


# =========================================================================
# PrimitiveExtractor
# =========================================================================

class Primitive:
    """A primitive data-type and its offset within the containing data-type."""
    __slots__ = ('dt', 'offset')

    def __init__(self, dt: 'Datatype', offset: int) -> None:
        self.dt = dt
        self.offset = offset


class PrimitiveExtractor:
    """Extracts primitive elements of a data-type.

    Recursively collects formal primitive data-types of a composite,
    laying them out with offsets.

    C++ ref: ``PrimitiveExtractor``
    """
    unknown_element = 1
    unaligned = 2
    extra_space = 4
    invalid = 8
    union_invalid = 16

    def __init__(self, dt: 'Datatype', unionIllegal: bool,
                 offset: int = 0, maxPrimitives: int = 16) -> None:
        self.primitives: List[Primitive] = []
        self.flags: int = self.union_invalid if unionIllegal else 0
        if not self._extract(dt, maxPrimitives, offset):
            self.flags |= self.invalid

    def size(self) -> int:
        return len(self.primitives)

    def get(self, i: int) -> Primitive:
        return self.primitives[i]

    def isValid(self) -> bool:
        return (self.flags & self.invalid) == 0

    def containsUnknown(self) -> bool:
        return (self.flags & self.unknown_element) != 0

    def isAligned(self) -> bool:
        return (self.flags & self.unaligned) == 0

    def containsHoles(self) -> bool:
        return (self.flags & self.extra_space) != 0

    def _checkOverlap(self, res: List[Primitive], small: List[Primitive],
                      point: int, big: Primitive) -> int:
        endOff = big.offset + big.dt.getAlignSize()
        useSmall = big.dt.getMetatype() == TYPE_FLOAT
        while point < len(small):
            curOff = small[point].offset
            if curOff >= endOff:
                break
            curOff += small[point].dt.getAlignSize()
            if curOff > endOff:
                return -1
            if useSmall:
                res.append(small[point])
            point += 1
        if not useSmall:
            res.append(big)
        return point

    def _commonRefinement(self, first: List[Primitive],
                          second: List[Primitive]) -> bool:
        firstPoint = 0
        secondPoint = 0
        common: List[Primitive] = []
        while firstPoint < len(first) and secondPoint < len(second):
            fe = first[firstPoint]
            se = second[secondPoint]
            if (fe.offset < se.offset and
                    fe.offset + fe.dt.getAlignSize() <= se.offset):
                common.append(fe)
                firstPoint += 1
                continue
            if (se.offset < fe.offset and
                    se.offset + se.dt.getAlignSize() <= fe.offset):
                common.append(se)
                secondPoint += 1
                continue
            if fe.dt.getAlignSize() >= se.dt.getAlignSize():
                secondPoint = self._checkOverlap(common, second, secondPoint, fe)
                if secondPoint < 0:
                    return False
                firstPoint += 1
            else:
                firstPoint = self._checkOverlap(common, first, firstPoint, se)
                if firstPoint < 0:
                    return False
                secondPoint += 1
        while firstPoint < len(first):
            common.append(first[firstPoint])
            firstPoint += 1
        while secondPoint < len(second):
            common.append(second[secondPoint])
            secondPoint += 1
        first.clear()
        first.extend(common)
        return True

    def _handleUnion(self, dt: 'Datatype', maxP: int, offset: int) -> bool:
        if (self.flags & self.union_invalid) != 0:
            return False
        num = dt.numDepend()
        if num == 0:
            return False
        curField = dt.getField(0)
        common = PrimitiveExtractor(curField.type, False, offset + curField.offset, maxP)
        if not common.isValid():
            return False
        for i in range(1, num):
            curField = dt.getField(i)
            nxt = PrimitiveExtractor(curField.type, False, offset + curField.offset, maxP)
            if not nxt.isValid():
                return False
            if not self._commonRefinement(common.primitives, nxt.primitives):
                return False
        if len(self.primitives) + len(common.primitives) > maxP:
            return False
        self.primitives.extend(common.primitives)
        return True

    def _extract(self, dt: 'Datatype', maxP: int, offset: int) -> bool:
        meta = dt.getMetatype()
        if meta == TYPE_UNKNOWN:
            self.flags |= self.unknown_element
            # fallthrough
        if meta in (TYPE_UNKNOWN, TYPE_INT, TYPE_UINT, TYPE_BOOL,
                    TYPE_CODE, TYPE_FLOAT, TYPE_PTR, TYPE_PTRREL):
            if len(self.primitives) >= maxP:
                return False
            self.primitives.append(Primitive(dt, offset))
            return True
        if meta == TYPE_ARRAY:
            numEls = dt.numElements()
            base = dt.getBase()
            for i in range(numEls):
                if not self._extract(base, maxP, offset):
                    return False
                offset += base.getAlignSize()
            return True
        if meta == TYPE_UNION:
            return self._handleUnion(dt, maxP, offset)
        if meta != TYPE_STRUCT:
            return False
        expectedOff = offset
        for fld in dt.getFields():
            compDt = fld.type
            curOff = fld.offset + offset
            align_val = compDt.getAlignment()
            if align_val > 0 and curOff % align_val != 0:
                self.flags |= self.unaligned
            if align_val > 0:
                rem = expectedOff % align_val
                if rem != 0:
                    expectedOff += (align_val - rem)
            if expectedOff != curOff:
                self.flags |= self.extra_space
            if not self._extract(compDt, maxP, curOff):
                return False
            expectedOff = curOff + compDt.getAlignSize()
        return True


# =========================================================================
# DatatypeFilter hierarchy
# =========================================================================

class DatatypeFilter:
    """A filter selecting a specific class of data-type."""

    def clone(self) -> 'DatatypeFilter':
        raise NotImplementedError

    def filter(self, dt: 'Datatype') -> bool:
        raise NotImplementedError

    def decode(self, decoder) -> None:
        raise NotImplementedError

    @staticmethod
    def decodeFilter(decoder) -> 'DatatypeFilter':
        elemId = decoder.openElement(ELEM_DATATYPE)
        nm = decoder.readString(ATTRIB_NAME)
        if nm == "any":
            filt = SizeRestrictedFilter()
        elif nm == "homogeneous-float-aggregate":
            filt = HomogeneousAggregate(TYPE_FLOAT, maxPrim=4)
        else:
            meta = string2metatype(nm)
            filt = MetaTypeFilter(meta)
        filt.decode(decoder)
        decoder.closeElement(elemId)
        return filt


class SizeRestrictedFilter(DatatypeFilter):
    """Filter that tests for a range or enumerated list of sizes."""

    def __init__(self, minSize: int = 0, maxSize: int = 0) -> None:
        self.minSize: int = minSize
        self.maxSize: int = maxSize
        self.sizes: Set[int] = set()
        if self.maxSize == 0 and self.minSize >= 0:
            self.maxSize = 0x7fffffff

    def _initFromSizeList(self, s: str) -> None:
        parts = s.replace(',', ' ').split()
        for part in parts:
            val = int(part)
            if val <= 0:
                raise DecoderError("Bad filter size")
            self.sizes.add(val)
        if self.sizes:
            self.minSize = min(self.sizes)
            self.maxSize = max(self.sizes)

    def filterOnSize(self, dt: 'Datatype') -> bool:
        if self.maxSize == 0:
            return True
        if self.sizes:
            return dt.getSize() in self.sizes
        return self.minSize <= dt.getSize() <= self.maxSize

    def clone(self) -> 'SizeRestrictedFilter':
        c = SizeRestrictedFilter(self.minSize, self.maxSize)
        c.sizes = set(self.sizes)
        return c

    def filter(self, dt: 'Datatype') -> bool:
        return self.filterOnSize(dt)

    def decode(self, decoder) -> None:
        while True:
            attribId = decoder.getNextAttributeId()
            if attribId == 0:
                break
            if attribId == ATTRIB_MINSIZE.id:
                if self.sizes:
                    raise DecoderError('Mixing "sizes" with "minsize" and "maxsize"')
                self.minSize = decoder.readUnsignedInteger()
            elif attribId == ATTRIB_MAXSIZE.id:
                if self.sizes:
                    raise DecoderError('Mixing "sizes" with "minsize" and "maxsize"')
                self.maxSize = decoder.readUnsignedInteger()
            elif attribId == ATTRIB_SIZES.id:
                if self.minSize != 0 or self.maxSize != 0:
                    raise DecoderError('Mixing "sizes" with "minsize" and "maxsize"')
                self._initFromSizeList(decoder.readString())
        if self.maxSize == 0 and self.minSize >= 0:
            self.maxSize = 0x7fffffff


class MetaTypeFilter(SizeRestrictedFilter):
    """Filter on a single meta data-type."""

    def __init__(self, meta: MetaType, minSize: int = 0,
                 maxSize: int = 0) -> None:
        super().__init__(minSize, maxSize)
        self.metaType: MetaType = meta

    def clone(self) -> 'MetaTypeFilter':
        c = MetaTypeFilter(self.metaType, self.minSize, self.maxSize)
        c.sizes = set(self.sizes)
        return c

    def filter(self, dt: 'Datatype') -> bool:
        if dt.getMetatype() != self.metaType:
            return False
        return self.filterOnSize(dt)


class HomogeneousAggregate(SizeRestrictedFilter):
    """Filter on a homogeneous aggregate data-type."""

    def __init__(self, meta: MetaType, maxPrim: int = 4,
                 minSize: int = 0, maxSize: int = 0) -> None:
        super().__init__(minSize, maxSize)
        self.metaType: MetaType = meta
        self.maxPrimitives: int = maxPrim

    def clone(self) -> 'HomogeneousAggregate':
        c = HomogeneousAggregate(self.metaType, self.maxPrimitives,
                                 self.minSize, self.maxSize)
        c.sizes = set(self.sizes)
        return c

    def filter(self, dt: 'Datatype') -> bool:
        meta = dt.getMetatype()
        if meta != TYPE_ARRAY and meta != TYPE_STRUCT:
            return False
        prims = PrimitiveExtractor(dt, True, 0, self.maxPrimitives)
        if (not prims.isValid() or prims.size() == 0 or
                prims.containsUnknown() or not prims.isAligned() or
                prims.containsHoles()):
            return False
        base = prims.get(0).dt
        if base.getMetatype() != self.metaType:
            return False
        for i in range(1, prims.size()):
            if prims.get(i).dt is not base:
                return False
        return True

    def decode(self, decoder) -> None:
        super().decode(decoder)
        decoder.rewindAttributes()
        while True:
            attribId = decoder.getNextAttributeId()
            if attribId == 0:
                break
            if attribId == ATTRIB_MAX_PRIMITIVES.id:
                val = decoder.readUnsignedInteger()
                if val > 0:
                    self.maxPrimitives = val


# =========================================================================
# QualifierFilter hierarchy
# =========================================================================

class QualifierFilter:
    """A filter on some aspect of a specific function prototype."""

    def clone(self) -> 'QualifierFilter':
        raise NotImplementedError

    def filter(self, proto: 'PrototypePieces', pos: int) -> bool:
        raise NotImplementedError

    def decode(self, decoder) -> None:
        pass

    @staticmethod
    def decodeFilter(decoder) -> Optional['QualifierFilter']:
        elemId = decoder.peekElement()
        if elemId == ELEM_VARARGS.id:
            filt = VarargsFilter()
        elif elemId == ELEM_POSITION.id:
            filt = PositionMatchFilter(-1)
        elif elemId == ELEM_DATATYPE_AT.id:
            filt = DatatypeMatchFilter()
        else:
            return None
        filt.decode(decoder)
        return filt


class AndFilter(QualifierFilter):
    """Logically AND multiple QualifierFilters together."""

    def __init__(self, filters: List[QualifierFilter]) -> None:
        self.subQualifiers: List[QualifierFilter] = list(filters)

    def clone(self) -> 'AndFilter':
        return AndFilter([q.clone() for q in self.subQualifiers])

    def filter(self, proto: 'PrototypePieces', pos: int) -> bool:
        return all(q.filter(proto, pos) for q in self.subQualifiers)


class VarargsFilter(QualifierFilter):
    """Filter selecting optional (variable) arguments."""

    def __init__(self, first: int = -0x80000000, last: int = 0x7fffffff) -> None:
        self.firstPos: int = first
        self.lastPos: int = last

    def clone(self) -> 'VarargsFilter':
        return VarargsFilter(self.firstPos, self.lastPos)

    def filter(self, proto: 'PrototypePieces', pos: int) -> bool:
        fvas = getattr(proto, 'firstVarArgSlot', -1)
        if fvas < 0:
            return False
        pos -= fvas
        return self.firstPos <= pos <= self.lastPos

    def decode(self, decoder) -> None:
        elemId = decoder.openElement(ELEM_VARARGS)
        while True:
            attribId = decoder.getNextAttributeId()
            if attribId == 0:
                break
            if attribId == ATTRIB_FIRST.id:
                self.firstPos = decoder.readSignedInteger()
            elif attribId == ATTRIB_LAST.id:
                self.lastPos = decoder.readSignedInteger()
        decoder.closeElement(elemId)


class PositionMatchFilter(QualifierFilter):
    """Filter that selects for a particular parameter position."""

    def __init__(self, pos: int = -1) -> None:
        self.position: int = pos

    def clone(self) -> 'PositionMatchFilter':
        return PositionMatchFilter(self.position)

    def filter(self, proto: 'PrototypePieces', pos: int) -> bool:
        return pos == self.position

    def decode(self, decoder) -> None:
        elemId = decoder.openElement(ELEM_POSITION)
        self.position = decoder.readSignedInteger(ATTRIB_INDEX)
        decoder.closeElement(elemId)


class DatatypeMatchFilter(QualifierFilter):
    """Check if the function signature has a specific data-type at a position."""

    def __init__(self) -> None:
        self.position: int = -1
        self.typeFilter: Optional[DatatypeFilter] = None

    def clone(self) -> 'DatatypeMatchFilter':
        res = DatatypeMatchFilter()
        res.position = self.position
        if self.typeFilter is not None:
            res.typeFilter = self.typeFilter.clone()
        return res

    def filter(self, proto: 'PrototypePieces', pos: int) -> bool:
        if self.position < 0:
            dt = proto.outtype
        else:
            if self.position >= len(proto.intypes):
                return False
            dt = proto.intypes[self.position]
        return self.typeFilter.filter(dt)

    def decode(self, decoder) -> None:
        elemId = decoder.openElement(ELEM_DATATYPE_AT)
        self.position = decoder.readSignedInteger(ATTRIB_INDEX)
        self.typeFilter = DatatypeFilter.decodeFilter(decoder)
        decoder.closeElement(elemId)


# =========================================================================
# AssignAction hierarchy
# =========================================================================

class AssignAction:
    """An action that assigns an Address to a function prototype parameter."""

    success = 0
    fail = 1
    no_assignment = 2
    hiddenret_ptrparam = 3
    hiddenret_specialreg = 4
    hiddenret_specialreg_void = 5

    def __init__(self, res: 'ParamListStandard') -> None:
        self.resource: 'ParamListStandard' = res
        self.fillinOutputActive: bool = False

    def canAffectFillinOutput(self) -> bool:
        return self.fillinOutputActive

    def clone(self, newResource: 'ParamListStandard') -> 'AssignAction':
        raise NotImplementedError

    def assignAddress(self, dt: 'Datatype', proto: 'PrototypePieces',
                      pos: int, tlist: 'TypeFactory',
                      status: List[int],
                      res: 'ParameterPieces') -> int:
        raise NotImplementedError

    def fillinOutputMap(self, active: 'ParamActive') -> bool:
        return False

    def decode(self, decoder) -> None:
        raise NotImplementedError

    @staticmethod
    def decodeAction(decoder, res: 'ParamListStandard') -> 'AssignAction':
        elemId = decoder.peekElement()
        if elemId == ELEM_GOTO_STACK.id:
            action = GotoStack(res, _dummy=True)
        elif elemId == ELEM_JOIN.id:
            action = MultiSlotAssign(res, _defer_init=True)
        elif elemId == ELEM_CONSUME.id:
            action = ConsumeAs(TYPECLASS_GENERAL, res)
        elif elemId == ELEM_CONVERT_TO_PTR.id:
            action = ConvertToPointer(res)
        elif elemId == ELEM_HIDDEN_RETURN.id:
            action = HiddenReturnAssign(res, AssignAction.hiddenret_specialreg)
        elif elemId == ELEM_JOIN_PER_PRIMITIVE.id:
            action = MultiMemberAssign(TYPECLASS_GENERAL, False,
                                       res.isBigEndian(), res)
        elif elemId == ELEM_JOIN_DUAL_CLASS.id:
            action = MultiSlotDualAssign(res, _defer_init=True)
        else:
            raise DecoderError("Expecting model rule action")
        action.decode(decoder)
        return action

    @staticmethod
    def decodePrecondition(decoder, res: 'ParamListStandard') -> Optional['AssignAction']:
        elemId = decoder.peekElement()
        if elemId == ELEM_CONSUME_EXTRA.id:
            action = ConsumeExtra(res)
        else:
            return None
        action.decode(decoder)
        return action

    @staticmethod
    def decodeSideeffect(decoder, res: 'ParamListStandard') -> 'AssignAction':
        elemId = decoder.peekElement()
        if elemId == ELEM_CONSUME_EXTRA.id:
            action = ConsumeExtra(res)
        elif elemId == ELEM_EXTRA_STACK.id:
            action = ExtraStack(res)
        elif elemId == ELEM_CONSUME_REMAINING.id:
            action = ConsumeRemaining(res)
        else:
            raise DecoderError("Expecting model rule sideeffect")
        action.decode(decoder)
        return action

    @staticmethod
    def justifyPieces(pieces: List[VarnodeData], offset: int,
                      isBigEndian: bool, consumeMostSig: bool,
                      justifyRight: bool) -> None:
        addOffset = isBigEndian ^ consumeMostSig ^ justifyRight
        pos = 0 if justifyRight else len(pieces) - 1
        vn = pieces[pos]
        if addOffset:
            vn.offset += offset
        vn.size -= offset


# =========================================================================
# Concrete AssignAction subclasses
# =========================================================================

class GotoStack(AssignAction):
    """Assign from next available stack location."""

    def __init__(self, res: 'ParamListStandard', _dummy: bool = False) -> None:
        super().__init__(res)
        self.stackEntry: Optional['ParamEntry'] = None
        self.fillinOutputActive = True
        if not _dummy:
            self._initializeEntry()

    def _initializeEntry(self) -> None:
        self.stackEntry = self.resource.getStackEntry()
        if self.stackEntry is None:
            raise LowlevelError("Cannot find matching <pentry> for action: goto_stack")

    def clone(self, newResource: 'ParamListStandard') -> 'GotoStack':
        g = GotoStack(newResource)
        return g

    def assignAddress(self, dt, proto, pos, tlist, status, res) -> int:
        grp = self.stackEntry.getGroup()
        res.type = dt
        res.addr = self.stackEntry.getAddrBySlot(status[grp], dt.getSize(),
                                                  dt.getAlignment())
        res.flags = 0
        return self.success

    def fillinOutputMap(self, active) -> bool:
        count = 0
        for i in range(active.getNumTrials()):
            trial = active.getTrial(i)
            entry = trial.getEntry()
            if entry is None:
                break
            if entry is not self.stackEntry:
                return False
            count += 1
            if count > 1:
                return False
        return count == 1

    def decode(self, decoder) -> None:
        elemId = decoder.openElement(ELEM_GOTO_STACK)
        decoder.closeElement(elemId)
        self._initializeEntry()


class ConvertToPointer(AssignAction):
    """Convert parameter data-type to a pointer and assign storage for the pointer."""

    def __init__(self, res: 'ParamListStandard') -> None:
        super().__init__(res)
        self.space = res.getSpacebase()

    def clone(self, newResource: 'ParamListStandard') -> 'ConvertToPointer':
        return ConvertToPointer(newResource)

    def assignAddress(self, dt, proto, pos, tlist, status, res) -> int:
        spc = self.space
        if spc is None:
            spc = tlist.getArch().getDefaultDataSpace()
        pointersize = spc.getAddrSize()
        wordsize = spc.getWordSize()
        pointertp = tlist.getTypePointer(pointersize, dt, wordsize)
        from ghidra.fspec.fspec import ParameterPieces as PP
        responseCode = self.resource.assignAddress(pointertp, proto, pos, tlist,
                                                    status, res)
        res.flags = PP.indirectstorage
        return responseCode

    def decode(self, decoder) -> None:
        elemId = decoder.openElement(ELEM_CONVERT_TO_PTR)
        decoder.closeElement(elemId)


class MultiSlotAssign(AssignAction):
    """Consume multiple registers to pass a data-type."""

    def __init__(self, res: 'ParamListStandard', _defer_init: bool = False,
                 resourceType: TypeClass = TYPECLASS_GENERAL,
                 consumeFromStack: bool = True,
                 consumeMostSig: bool = False,
                 enforceAlignment: bool = False,
                 justifyRight: bool = False) -> None:
        super().__init__(res)
        self.resourceType: TypeClass = resourceType
        self.isBigEndian: bool = res.isBigEndian()
        self.fillinOutputActive = True
        listType = res.getType()
        from ghidra.fspec.fspec import ParamListStandard as PLS
        self.consumeFromStack: bool = (listType != PLS.p_register_out and
                                       listType != PLS.p_standard_out)
        self.consumeMostSig: bool = consumeMostSig
        self.enforceAlignment: bool = enforceAlignment
        self.justifyRight: bool = justifyRight
        if self.isBigEndian:
            self.consumeMostSig = True
            self.justifyRight = True
        self.tiles: List['ParamEntry'] = []
        self.stackEntry: Optional['ParamEntry'] = None
        if not _defer_init:
            self._initializeEntries()

    def _initializeEntries(self) -> None:
        self.resource.extractTiles(self.tiles, self.resourceType)
        self.stackEntry = self.resource.getStackEntry()
        if not self.tiles:
            raise LowlevelError("Could not find matching resources for action: join")
        if self.consumeFromStack and self.stackEntry is None:
            raise LowlevelError("Cannot find matching <pentry> for action: join")

    def clone(self, newResource: 'ParamListStandard') -> 'MultiSlotAssign':
        m = MultiSlotAssign.__new__(MultiSlotAssign)
        AssignAction.__init__(m, newResource)
        m.resourceType = self.resourceType
        m.isBigEndian = newResource.isBigEndian()
        m.fillinOutputActive = True
        m.consumeFromStack = self.consumeFromStack
        m.consumeMostSig = self.consumeMostSig
        m.enforceAlignment = self.enforceAlignment
        m.justifyRight = self.justifyRight
        m.tiles = []
        m.stackEntry = None
        m._initializeEntries()
        return m

    def assignAddress(self, dt, proto, pos, tlist, status, res) -> int:
        tmpStatus = list(status)
        pieces: List[VarnodeData] = []
        sizeLeft = dt.getSize()
        align = dt.getAlignment()
        it = 0
        if self.enforceAlignment:
            resourcesConsumed = 0
            while it < len(self.tiles):
                entry = self.tiles[it]
                if tmpStatus[entry.getGroup()] == 0:
                    regSize = entry.getSize()
                    if align <= regSize or (resourcesConsumed % align) == 0:
                        break
                    tmpStatus[entry.getGroup()] = -1
                resourcesConsumed += entry.getSize()
                it += 1
        while sizeLeft > 0 and it < len(self.tiles):
            entry = self.tiles[it]
            it += 1
            if tmpStatus[entry.getGroup()] != 0:
                continue
            trialSize = entry.getSize()
            addr = entry.getAddrBySlot(tmpStatus[entry.getGroup()], trialSize, align)
            tmpStatus[entry.getGroup()] = -1
            vd = VarnodeData()
            vd.space = addr.getSpace()
            vd.offset = addr.getOffset()
            vd.size = trialSize
            pieces.append(vd)
            sizeLeft -= trialSize
            align = 1
        if sizeLeft > 0:
            if not self.consumeFromStack:
                return self.fail
            grp = self.stackEntry.getGroup()
            addr = self.stackEntry.getAddrBySlot(tmpStatus[grp], sizeLeft, align,
                                                  self.justifyRight)
            if addr.isInvalid():
                return self.fail
            vd = VarnodeData()
            vd.space = addr.getSpace()
            vd.offset = addr.getOffset()
            vd.size = sizeLeft
            pieces.append(vd)
        elif sizeLeft < 0:
            if self.resourceType == TYPECLASS_FLOAT and len(pieces) == 1:
                manager = tlist.getArch()
                tmp = pieces[0]
                addr = manager.constructFloatExtensionAddress(
                    Address(tmp.space, tmp.offset), tmp.size, dt.getSize())
                tmp.space = addr.getSpace()
                tmp.offset = addr.getOffset()
                tmp.size = dt.getSize()
            else:
                AssignAction.justifyPieces(pieces, -sizeLeft, self.isBigEndian,
                                           self.consumeMostSig, self.justifyRight)
        status[:] = tmpStatus
        res.flags = 0
        res.type = dt
        if hasattr(res, 'assignAddressFromPieces'):
            res.assignAddressFromPieces(pieces, self.consumeMostSig, tlist.getArch())
        else:
            if pieces:
                res.addr = Address(pieces[0].space, pieces[0].offset)
        return self.success

    def fillinOutputMap(self, active) -> bool:
        count = 0
        curGroup = -1
        partial = -1
        for i in range(active.getNumTrials()):
            trial = active.getTrial(i)
            entry = trial.getEntry()
            if entry is None:
                break
            if entry.getType() != self.resourceType:
                return False
            if count == 0:
                if not entry.isFirstInClass():
                    return False
            else:
                if entry.getGroup() != curGroup + 1:
                    return False
            curGroup = entry.getGroup()
            if trial.getSize() != entry.getSize():
                if partial != -1:
                    return False
                partial = i
            count += 1
        if partial != -1:
            if self.justifyRight:
                if partial != 0:
                    return False
            else:
                if partial != count - 1:
                    return False
            trial = active.getTrial(partial)
            if self.justifyRight == self.consumeMostSig:
                if trial.getOffset() != 0:
                    return False
            else:
                if trial.getOffset() + trial.getSize() != trial.getEntry().getSize():
                    return False
        if count == 0:
            return False
        if self.consumeMostSig:
            active.setJoinReverse()
        return True

    def decode(self, decoder) -> None:
        elemId = decoder.openElement(ELEM_JOIN)
        while True:
            attribId = decoder.getNextAttributeId()
            if attribId == 0:
                break
            if attribId == ATTRIB_REVERSEJUSTIFY.id:
                if decoder.readBool():
                    self.justifyRight = not self.justifyRight
            elif attribId == ATTRIB_REVERSESIGNIF.id:
                if decoder.readBool():
                    self.consumeMostSig = not self.consumeMostSig
            elif attribId == ATTRIB_STORAGE.id:
                self.resourceType = string2typeclass(decoder.readString())
            elif attribId == ATTRIB_ALIGN.id:
                self.enforceAlignment = decoder.readBool()
            elif attribId == ATTRIB_STACKSPILL.id:
                self.consumeFromStack = decoder.readBool()
        decoder.closeElement(elemId)
        self._initializeEntries()


class MultiMemberAssign(AssignAction):
    """Consume a register per primitive member of an aggregate."""

    def __init__(self, resourceType: TypeClass, consumeFromStack: bool,
                 consumeMostSig: bool, res: 'ParamListStandard') -> None:
        super().__init__(res)
        self.resourceType: TypeClass = resourceType
        self.consumeFromStack: bool = consumeFromStack
        self.consumeMostSig: bool = consumeMostSig
        self.fillinOutputActive = True

    def clone(self, newResource: 'ParamListStandard') -> 'MultiMemberAssign':
        return MultiMemberAssign(self.resourceType, self.consumeFromStack,
                                 self.consumeMostSig, newResource)

    def assignAddress(self, dt, proto, pos, tlist, status, res) -> int:
        tmpStatus = list(status)
        pieces: List[VarnodeData] = []
        prims = PrimitiveExtractor(dt, False, 0, 16)
        if (not prims.isValid() or prims.size() == 0 or
                prims.containsUnknown() or not prims.isAligned() or
                prims.containsHoles()):
            return self.fail
        from ghidra.fspec.fspec import ParameterPieces
        param = ParameterPieces()
        for i in range(prims.size()):
            curType = prims.get(i).dt
            if self.resource.assignAddressFallback(
                    self.resourceType, curType,
                    not self.consumeFromStack, tmpStatus, param) == self.fail:
                return self.fail
            vd = VarnodeData()
            vd.space = param.addr.getSpace()
            vd.offset = param.addr.getOffset()
            vd.size = curType.getSize()
            pieces.append(vd)
        status[:] = tmpStatus
        res.flags = 0
        res.type = dt
        if hasattr(res, 'assignAddressFromPieces'):
            res.assignAddressFromPieces(pieces, self.consumeMostSig, tlist.getArch())
        else:
            if pieces:
                res.addr = Address(pieces[0].space, pieces[0].offset)
        return self.success

    def fillinOutputMap(self, active) -> bool:
        count = 0
        curGroup = -1
        for i in range(active.getNumTrials()):
            trial = active.getTrial(i)
            entry = trial.getEntry()
            if entry is None:
                break
            if entry.getType() != self.resourceType:
                return False
            if count == 0:
                if not entry.isFirstInClass():
                    return False
            else:
                if entry.getGroup() != curGroup + 1:
                    return False
            curGroup = entry.getGroup()
            if trial.getOffset() != 0:
                return False
            count += 1
        if count == 0:
            return False
        if self.consumeMostSig:
            active.setJoinReverse()
        return True

    def decode(self, decoder) -> None:
        elemId = decoder.openElement(ELEM_JOIN_PER_PRIMITIVE)
        while True:
            attribId = decoder.getNextAttributeId()
            if attribId == 0:
                break
            if attribId == ATTRIB_STORAGE.id:
                self.resourceType = string2typeclass(decoder.readString())
        decoder.closeElement(elemId)


class MultiSlotDualAssign(AssignAction):
    """Consume registers from two different storage classes."""

    def __init__(self, res: 'ParamListStandard', _defer_init: bool = False,
                 baseType: TypeClass = TYPECLASS_GENERAL,
                 altType: TypeClass = TYPECLASS_FLOAT,
                 consumeFromStack: bool = False,
                 consumeMostSig: bool = False,
                 justifyRight: bool = False,
                 fillAlternate: bool = False) -> None:
        super().__init__(res)
        self.isBigEndian: bool = res.isBigEndian()
        self.fillinOutputActive = True
        self.baseType: TypeClass = baseType
        self.altType: TypeClass = altType
        self.consumeFromStack: bool = consumeFromStack
        self.consumeMostSig: bool = consumeMostSig
        self.justifyRight: bool = justifyRight
        self.fillAlternate: bool = fillAlternate
        if self.isBigEndian:
            self.consumeMostSig = True
            self.justifyRight = True
        self.tileSize: int = 0
        self.baseTiles: List['ParamEntry'] = []
        self.altTiles: List['ParamEntry'] = []
        self.stackEntry: Optional['ParamEntry'] = None
        if not _defer_init:
            self._initializeEntries()

    def _initializeEntries(self) -> None:
        self.resource.extractTiles(self.baseTiles, self.baseType)
        self.resource.extractTiles(self.altTiles, self.altType)
        self.stackEntry = self.resource.getStackEntry()
        if not self.baseTiles or not self.altTiles:
            raise LowlevelError(
                "Could not find matching resources for action: join_dual_class")
        self.tileSize = self.baseTiles[0].getSize()
        if self.tileSize != self.altTiles[0].getSize():
            raise LowlevelError(
                "Storage class register sizes do not match for action: join_dual_class")
        if self.consumeFromStack and self.stackEntry is None:
            raise LowlevelError(
                "Cannot find matching stack resource for action: join_dual_class")

    def _getFirstUnused(self, it: int, tiles: List['ParamEntry'],
                        status: List[int]) -> int:
        while it < len(tiles):
            entry = tiles[it]
            if status[entry.getGroup()] == 0:
                return it
            it += 1
        return len(tiles)

    def _getTileClass(self, primitives: PrimitiveExtractor,
                      off: int, index_ref: List[int]) -> int:
        idx = index_ref[0]
        result = 1
        count = 0
        endBoundary = off + self.tileSize
        if idx >= primitives.size():
            return -1
        firstPrimitive = primitives.get(idx)
        while idx < primitives.size():
            element = primitives.get(idx)
            if element.offset < off:
                return -1
            if element.offset >= endBoundary:
                break
            if element.offset + element.dt.getSize() > endBoundary:
                return -1
            count += 1
            idx += 1
            storage = metatype2typeclass(element.dt.getMetatype())
            if storage != self.altType:
                result = 0
        if count == 0:
            return -1
        if self.fillAlternate:
            if count > 1:
                result = 0
            if firstPrimitive.dt.getSize() != self.tileSize:
                result = 0
        index_ref[0] = idx
        return result

    def clone(self, newResource: 'ParamListStandard') -> 'MultiSlotDualAssign':
        m = MultiSlotDualAssign.__new__(MultiSlotDualAssign)
        AssignAction.__init__(m, newResource)
        m.isBigEndian = newResource.isBigEndian()
        m.fillinOutputActive = True
        m.baseType = self.baseType
        m.altType = self.altType
        m.consumeFromStack = self.consumeFromStack
        m.consumeMostSig = self.consumeMostSig
        m.justifyRight = self.justifyRight
        m.fillAlternate = self.fillAlternate
        m.tileSize = 0
        m.baseTiles = []
        m.altTiles = []
        m.stackEntry = None
        m._initializeEntries()
        return m

    def assignAddress(self, dt, proto, pos, tlist, status, res) -> int:
        prims = PrimitiveExtractor(dt, False, 0, 1024)
        if not prims.isValid() or prims.size() == 0 or prims.containsHoles():
            return self.fail
        index_ref = [0]
        tmpStatus = list(status)
        pieces: List[VarnodeData] = []
        typeSize = dt.getSize()
        align = dt.getAlignment()
        sizeLeft = typeSize
        iterBase = 0
        iterAlt = 0
        while sizeLeft > 0:
            iterType = self._getTileClass(prims, typeSize - sizeLeft, index_ref)
            if iterType < 0:
                return self.fail
            if iterType == 0:
                iterBase = self._getFirstUnused(iterBase, self.baseTiles, tmpStatus)
                if iterBase == len(self.baseTiles):
                    if not self.consumeFromStack:
                        return self.fail
                    break
                entry = self.baseTiles[iterBase]
            else:
                iterAlt = self._getFirstUnused(iterAlt, self.altTiles, tmpStatus)
                if iterAlt == len(self.altTiles):
                    if not self.consumeFromStack:
                        return self.fail
                    break
                entry = self.altTiles[iterAlt]
            trialSize = entry.getSize()
            addr = entry.getAddrBySlot(tmpStatus[entry.getGroup()], trialSize, 1)
            tmpStatus[entry.getGroup()] = -1
            vd = VarnodeData()
            vd.space = addr.getSpace()
            vd.offset = addr.getOffset()
            vd.size = trialSize
            pieces.append(vd)
            sizeLeft -= trialSize
        if sizeLeft > 0:
            if not self.consumeFromStack:
                return self.fail
            grp = self.stackEntry.getGroup()
            addr = self.stackEntry.getAddrBySlot(tmpStatus[grp], sizeLeft, align,
                                                  self.justifyRight)
            if addr.isInvalid():
                return self.fail
            vd = VarnodeData()
            vd.space = addr.getSpace()
            vd.offset = addr.getOffset()
            vd.size = sizeLeft
            pieces.append(vd)
        if sizeLeft < 0:
            AssignAction.justifyPieces(pieces, -sizeLeft, self.isBigEndian,
                                       self.consumeMostSig, self.justifyRight)
        status[:] = tmpStatus
        res.flags = 0
        res.type = dt
        if hasattr(res, 'assignAddressFromPieces'):
            res.assignAddressFromPieces(pieces, self.consumeMostSig, tlist.getArch())
        else:
            if pieces:
                res.addr = Address(pieces[0].space, pieces[0].offset)
        return self.success

    def fillinOutputMap(self, active) -> bool:
        count = 0
        curGroup = -1
        partial = -1
        resType = TYPECLASS_GENERAL
        for i in range(active.getNumTrials()):
            trial = active.getTrial(i)
            entry = trial.getEntry()
            if entry is None:
                break
            if count == 0:
                resType = entry.getType()
                if resType != self.baseType and resType != self.altType:
                    return False
            elif entry.getType() != resType:
                return False
            if count == 0:
                if not entry.isFirstInClass():
                    return False
            else:
                if entry.getGroup() != curGroup + 1:
                    return False
            curGroup = entry.getGroup()
            if trial.getSize() != entry.getSize():
                if partial != -1:
                    return False
                partial = i
            count += 1
        if partial != -1:
            if self.justifyRight:
                if partial != 0:
                    return False
            else:
                if partial != count - 1:
                    return False
            trial = active.getTrial(partial)
            if self.justifyRight == self.consumeMostSig:
                if trial.getOffset() != 0:
                    return False
            else:
                if trial.getOffset() + trial.getSize() != trial.getEntry().getSize():
                    return False
        if count == 0:
            return False
        if self.consumeMostSig:
            active.setJoinReverse()
        return True

    def decode(self, decoder) -> None:
        elemId = decoder.openElement(ELEM_JOIN_DUAL_CLASS)
        while True:
            attribId = decoder.getNextAttributeId()
            if attribId == 0:
                break
            if attribId == ATTRIB_REVERSEJUSTIFY.id:
                if decoder.readBool():
                    self.justifyRight = not self.justifyRight
            elif attribId == ATTRIB_REVERSESIGNIF.id:
                if decoder.readBool():
                    self.consumeMostSig = not self.consumeMostSig
            elif attribId == ATTRIB_STORAGE.id or attribId == ATTRIB_A.id:
                self.baseType = string2typeclass(decoder.readString())
            elif attribId == ATTRIB_B.id:
                self.altType = string2typeclass(decoder.readString())
            elif attribId == ATTRIB_STACKSPILL.id:
                self.consumeFromStack = decoder.readBool()
            elif attribId == ATTRIB_FILL_ALTERNATE.id:
                self.fillAlternate = decoder.readBool()
        decoder.closeElement(elemId)
        self._initializeEntries()


class ConsumeAs(AssignAction):
    """Consume a parameter from a specific resource list."""

    def __init__(self, resourceType: TypeClass,
                 res: 'ParamListStandard') -> None:
        super().__init__(res)
        self.resourceType: TypeClass = resourceType
        self.fillinOutputActive = True

    def clone(self, newResource: 'ParamListStandard') -> 'ConsumeAs':
        return ConsumeAs(self.resourceType, newResource)

    def assignAddress(self, dt, proto, pos, tlist, status, res) -> int:
        return self.resource.assignAddressFallback(
            self.resourceType, dt, True, status, res)

    def fillinOutputMap(self, active) -> bool:
        count = 0
        for i in range(active.getNumTrials()):
            trial = active.getTrial(i)
            entry = trial.getEntry()
            if entry is None:
                break
            if entry.getType() != self.resourceType:
                return False
            if not entry.isFirstInClass():
                return False
            count += 1
            if count > 1:
                return False
            if trial.getOffset() != 0:
                return False
        return count > 0

    def decode(self, decoder) -> None:
        elemId = decoder.openElement(ELEM_CONSUME)
        self.resourceType = string2typeclass(decoder.readString(ATTRIB_STORAGE))
        decoder.closeElement(elemId)


class HiddenReturnAssign(AssignAction):
    """Allocate the return value as an input parameter."""

    def __init__(self, res: 'ParamListStandard', code: int) -> None:
        super().__init__(res)
        self.retCode: int = code

    def clone(self, newResource: 'ParamListStandard') -> 'HiddenReturnAssign':
        return HiddenReturnAssign(newResource, self.retCode)

    def assignAddress(self, dt, proto, pos, tlist, status, res) -> int:
        return self.retCode

    def decode(self, decoder) -> None:
        self.retCode = self.hiddenret_specialreg
        elemId = decoder.openElement(ELEM_HIDDEN_RETURN)
        while True:
            attribId = decoder.getNextAttributeId()
            if attribId == ATTRIB_VOIDLOCK.id:
                self.retCode = self.hiddenret_specialreg_void
            elif attribId == ATTRIB_STRATEGY.id:
                s = decoder.readString()
                if s == "normalparam":
                    self.retCode = self.hiddenret_ptrparam
                elif s == "special":
                    self.retCode = self.hiddenret_specialreg
                else:
                    raise DecoderError("Bad <hidden_return> strategy: " + s)
            else:
                break
        decoder.closeElement(elemId)


class ConsumeExtra(AssignAction):
    """Consume additional registers from an alternate resource list (side-effect)."""

    def __init__(self, res: 'ParamListStandard',
                 resourceType: TypeClass = TYPECLASS_GENERAL,
                 matchSize: bool = True) -> None:
        super().__init__(res)
        self.resourceType: TypeClass = resourceType
        self.matchSize: bool = matchSize
        self.tiles: List['ParamEntry'] = []

    def _initializeEntries(self) -> None:
        self.resource.extractTiles(self.tiles, self.resourceType)
        if not self.tiles:
            raise LowlevelError(
                "Could not find matching resources for action: consume_extra")

    def clone(self, newResource: 'ParamListStandard') -> 'ConsumeExtra':
        c = ConsumeExtra(newResource, self.resourceType, self.matchSize)
        c._initializeEntries()
        return c

    def assignAddress(self, dt, proto, pos, tlist, status, res) -> int:
        it = 0
        sizeLeft = dt.getSize()
        while sizeLeft > 0 and it < len(self.tiles):
            entry = self.tiles[it]
            it += 1
            if status[entry.getGroup()] != 0:
                continue
            status[entry.getGroup()] = -1
            sizeLeft -= entry.getSize()
            if not self.matchSize:
                break
        return self.success

    def decode(self, decoder) -> None:
        elemId = decoder.openElement(ELEM_CONSUME_EXTRA)
        while True:
            attribId = decoder.getNextAttributeId()
            if attribId == 0:
                break
            if attribId == ATTRIB_STORAGE.id:
                self.resourceType = string2typeclass(decoder.readString())
            elif attribId == ATTRIB_MATCHSIZE.id:
                self.matchSize = decoder.readBool()
        decoder.closeElement(elemId)
        self._initializeEntries()


class ExtraStack(AssignAction):
    """Consume stack resources as a side-effect."""

    def __init__(self, res: 'ParamListStandard',
                 afterStorage: TypeClass = TYPECLASS_GENERAL,
                 afterBytes: int = -1) -> None:
        super().__init__(res)
        self.afterBytes: int = afterBytes
        self.afterStorage: TypeClass = afterStorage
        self.stackEntry: Optional['ParamEntry'] = None

    def _initializeEntry(self) -> None:
        self.stackEntry = self.resource.getStackEntry()
        if self.stackEntry is None:
            raise LowlevelError(
                "Cannot find matching <pentry> for action: extra_stack")

    def clone(self, newResource: 'ParamListStandard') -> 'ExtraStack':
        e = ExtraStack(newResource, self.afterStorage, self.afterBytes)
        e._initializeEntry()
        return e

    def assignAddress(self, dt, proto, pos, tlist, status, res) -> int:
        if res.addr.getSpace() is self.stackEntry.getSpace():
            return self.success
        grp = self.stackEntry.getGroup()
        if self.afterBytes > 0:
            bytesConsumed = 0
            for entry in self.resource.entry:
                if entry.getGroup() == grp or entry.getType() != self.afterStorage:
                    continue
                if status[entry.getGroup()] != 0:
                    bytesConsumed += entry.getSize()
            if bytesConsumed < self.afterBytes:
                return self.success
        self.stackEntry.getAddrBySlot(status[grp], dt.getSize(), dt.getAlignment())
        return self.success

    def decode(self, decoder) -> None:
        elemId = decoder.openElement(ELEM_EXTRA_STACK)
        while True:
            attribId = decoder.getNextAttributeId()
            if attribId == 0:
                break
            if attribId == ATTRIB_AFTER_BYTES.id:
                self.afterBytes = decoder.readUnsignedInteger()
            elif attribId == ATTRIB_AFTER_STORAGE.id:
                self.afterStorage = string2typeclass(decoder.readString())
        decoder.closeElement(elemId)
        self._initializeEntry()


class ConsumeRemaining(AssignAction):
    """Consume all remaining registers from a resource list (side-effect)."""

    def __init__(self, res: 'ParamListStandard',
                 resourceType: TypeClass = TYPECLASS_GENERAL) -> None:
        super().__init__(res)
        self.resourceType: TypeClass = resourceType
        self.tiles: List['ParamEntry'] = []

    def _initializeEntries(self) -> None:
        self.resource.extractTiles(self.tiles, self.resourceType)
        if not self.tiles:
            raise LowlevelError(
                "Could not find matching resources for action: consume_remaining")

    def clone(self, newResource: 'ParamListStandard') -> 'ConsumeRemaining':
        c = ConsumeRemaining(newResource, self.resourceType)
        c._initializeEntries()
        return c

    def assignAddress(self, dt, proto, pos, tlist, status, res) -> int:
        for entry in self.tiles:
            if status[entry.getGroup()] != 0:
                continue
            status[entry.getGroup()] = -1
        return self.success

    def decode(self, decoder) -> None:
        elemId = decoder.openElement(ELEM_CONSUME_REMAINING)
        self.resourceType = string2typeclass(decoder.readString(ATTRIB_STORAGE))
        decoder.closeElement(elemId)
        self._initializeEntries()


# =========================================================================
# ModelRule
# =========================================================================

class ModelRule:
    """A rule controlling how parameters are assigned addresses.

    Combines a DatatypeFilter, optional QualifierFilter, and an AssignAction.

    C++ ref: ``ModelRule``
    """

    def __init__(self) -> None:
        self.filter: Optional[DatatypeFilter] = None
        self.qualifier: Optional[QualifierFilter] = None
        self.assign: Optional[AssignAction] = None
        self.preconditions: List[AssignAction] = []
        self.sideeffects: List[AssignAction] = []

    @classmethod
    def fromComponents(cls, typeFilter: DatatypeFilter,
                       action: AssignAction,
                       res: 'ParamListStandard') -> 'ModelRule':
        rule = cls()
        rule.filter = typeFilter.clone()
        rule.assign = action.clone(res)
        return rule

    @classmethod
    def copyFrom(cls, other: 'ModelRule',
                 res: 'ParamListStandard') -> 'ModelRule':
        rule = cls()
        if other.filter is not None:
            rule.filter = other.filter.clone()
        if other.qualifier is not None:
            rule.qualifier = other.qualifier.clone()
        if other.assign is not None:
            rule.assign = other.assign.clone(res)
        for pc in other.preconditions:
            rule.preconditions.append(pc.clone(res))
        for se in other.sideeffects:
            rule.sideeffects.append(se.clone(res))
        return rule

    def assignAddress(self, dt: 'Datatype', proto: 'PrototypePieces',
                      pos: int, tlist: 'TypeFactory',
                      status: List[int],
                      res: 'ParameterPieces') -> int:
        if not self.filter.filter(dt):
            return AssignAction.fail
        if self.qualifier is not None and not self.qualifier.filter(proto, pos):
            return AssignAction.fail
        tmpStatus = list(status)
        for pc in self.preconditions:
            pc.assignAddress(dt, proto, pos, tlist, tmpStatus, res)
        response = self.assign.assignAddress(dt, proto, pos, tlist, tmpStatus, res)
        if response != AssignAction.fail:
            status[:] = tmpStatus
            for se in self.sideeffects:
                se.assignAddress(dt, proto, pos, tlist, status, res)
        return response

    def fillinOutputMap(self, active: 'ParamActive') -> bool:
        return self.assign.fillinOutputMap(active)

    def canAffectFillinOutput(self) -> bool:
        return self.assign.canAffectFillinOutput()

    def decode(self, decoder, res: 'ParamListStandard') -> None:
        qualifiers: List[QualifierFilter] = []
        elemId = decoder.openElement(ELEM_RULE)
        self.filter = DatatypeFilter.decodeFilter(decoder)
        while True:
            qual = QualifierFilter.decodeFilter(decoder)
            if qual is None:
                break
            qualifiers.append(qual)
        if not qualifiers:
            self.qualifier = None
        elif len(qualifiers) == 1:
            self.qualifier = qualifiers[0]
        else:
            self.qualifier = AndFilter(qualifiers)
        while True:
            precond = AssignAction.decodePrecondition(decoder, res)
            if precond is None:
                break
            self.preconditions.append(precond)
        self.assign = AssignAction.decodeAction(decoder, res)
        while decoder.peekElement() != 0:
            self.sideeffects.append(AssignAction.decodeSideeffect(decoder, res))
        decoder.closeElement(elemId)
