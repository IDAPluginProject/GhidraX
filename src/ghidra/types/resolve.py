"""
Corresponds to: unionresolve.hh / unionresolve.cc

ResolvedUnion for tracking which union field is selected at each use point.
ScoreUnionFields for analyzing data-flow to resolve which union field is accessed.
When a Varnode has a union data-type, the decompiler must decide which field
is being accessed at each PcodeOp. This module tracks those decisions.
"""

from __future__ import annotations
from typing import Optional, Dict, Tuple, List, Set, TYPE_CHECKING

if TYPE_CHECKING:
    from ghidra.types.datatype import Datatype, TypeFactory

from ghidra.types.datatype import (
    TYPE_PTR, TYPE_STRUCT, TYPE_UNION, TYPE_ARRAY, TYPE_CODE, TYPE_FLOAT,
    TYPE_INT, TYPE_UINT, TYPE_BOOL, TYPE_UNKNOWN,
)


class ResolvedUnion:
    """A data-type resolved from an associated TypeUnion or TypeStruct.

    C++ ref: ResolvedUnion (unionresolve.hh)
    """

    def __init__(self, parent=None, fieldNum: int = -1, typegrp=None) -> None:
        self.resolve = None      # The resolved data-type
        self.baseType = None     # Union or Structure being resolved
        self.fieldNum: int = -1  # Index of field referenced by resolve
        self.lock: bool = False  # If true, resolution cannot be overridden

        if parent is None:
            self.fieldNum = fieldNum
            return

        if typegrp is None:
            # Constructor 1: ResolvedUnion(parent) — resolve to itself
            self.baseType = parent
            if self.baseType is not None and self.baseType.getMetatype() == TYPE_PTR:
                if hasattr(self.baseType, 'getPtrTo'):
                    self.baseType = self.baseType.getPtrTo()
            self.resolve = parent
            self.fieldNum = -1
        else:
            # Constructor 2: ResolvedUnion(parent, fldNum, typegrp)
            if hasattr(parent, 'getMetatype') and parent.getMetatype() == getattr(
                    __import__('ghidra.types.datatype', fromlist=['TYPE_PARTIALUNION']),
                    'TYPE_PARTIALUNION', -999):
                if hasattr(parent, 'getParentUnion'):
                    parent = parent.getParentUnion()
            self.baseType = parent
            self.fieldNum = fieldNum
            if fieldNum < 0:
                self.resolve = parent
            else:
                if parent.getMetatype() == TYPE_PTR and hasattr(parent, 'getPtrTo'):
                    field = parent.getPtrTo().getDepend(fieldNum)
                    self.resolve = typegrp.getTypePointer(
                        parent.getSize(), field,
                        parent.getWordSize() if hasattr(parent, 'getWordSize') else 1)
                else:
                    self.resolve = parent.getDepend(fieldNum)

    def getDatatype(self):
        return self.resolve

    def getBase(self):
        return self.baseType

    def getFieldNum(self) -> int:
        return self.fieldNum

    def isLocked(self) -> bool:
        return self.lock

    def setLock(self, val: bool) -> None:
        self.lock = val


class ResolveEdge:
    """A data-flow edge to which a resolved data-type can be assigned.

    C++ ref: ResolveEdge (unionresolve.hh)
    """

    def __init__(self, parent=None, op=None, slot: int = 0) -> None:
        self.typeId: int = 0
        self.opTime: int = 0
        self.encoding: int = slot

        if parent is not None and op is not None:
            self.opTime = op.getTime() if hasattr(op, 'getTime') else (
                op.getSeqNum().getTime() if hasattr(op, 'getSeqNum') else 0)
            mt = parent.getMetatype() if hasattr(parent, 'getMetatype') else -1
            if mt == TYPE_PTR:
                if hasattr(parent, 'getPtrTo'):
                    self.typeId = parent.getPtrTo().getId()
                self.encoding = slot + 0x1000
            elif mt == getattr(
                    __import__('ghidra.types.datatype', fromlist=['TYPE_PARTIALUNION']),
                    'TYPE_PARTIALUNION', -999):
                if hasattr(parent, 'getParentUnion'):
                    self.typeId = parent.getParentUnion().getId()
                else:
                    self.typeId = parent.getId()
            else:
                self.typeId = parent.getId()
        elif parent is not None:
            # Legacy constructor for backward compat
            self.opTime = parent  # opAddr
            self.encoding = slot

    def __lt__(self, other: ResolveEdge) -> bool:
        if self.typeId != other.typeId:
            return self.typeId < other.typeId
        if self.encoding != other.encoding:
            return self.encoding < other.encoding
        return self.opTime < other.opTime

    def __hash__(self) -> int:
        return hash((self.typeId, self.opTime, self.encoding))

    def __eq__(self, other) -> bool:
        if not isinstance(other, ResolveEdge):
            return NotImplemented
        return (self.typeId == other.typeId and
                self.opTime == other.opTime and
                self.encoding == other.encoding)


class UnionFacetSymbol:
    """A Symbol that represents a particular facet (field) of a union."""

    def __init__(self, sym=None, fieldNum: int = -1) -> None:
        self.symbol = sym
        self.fieldNum: int = fieldNum

    def getSymbol(self):
        return self.symbol

    def getFieldNum(self) -> int:
        return self.fieldNum


class UnionResolveMap:
    """Map from (Datatype, ResolveEdge) to ResolvedUnion.

    Tracks union field resolution decisions across the function.
    """

    def __init__(self) -> None:
        self._map: Dict[Tuple[int, int, int], ResolvedUnion] = {}

    def setUnionField(self, dt, op, slot: int, res: ResolvedUnion) -> None:
        dtid = id(dt) if dt is not None else 0
        opaddr = op.getSeqNum().getAddr().getOffset() if (op is not None and hasattr(op, 'getSeqNum')) else 0
        key = (dtid, opaddr, slot)
        self._map[key] = res

    def getUnionField(self, dt, op, slot: int) -> Optional[ResolvedUnion]:
        dtid = id(dt) if dt is not None else 0
        opaddr = op.getSeqNum().getAddr().getOffset() if (op is not None and hasattr(op, 'getSeqNum')) else 0
        key = (dtid, opaddr, slot)
        return self._map.get(key)

    def hasUnionField(self, dt, op, slot: int) -> bool:
        return self.getUnionField(dt, op, slot) is not None

    def clear(self) -> None:
        self._map.clear()

    def numResolutions(self) -> int:
        return len(self._map)


# ---------------------------------------------------------------------------
# ScoreUnionFields — full C++ port of unionresolve.cc
# ---------------------------------------------------------------------------

class ScoreUnionFields:
    """Analyze data-flow to resolve which field of a union data-type is being accessed.

    C++ ref: ScoreUnionFields (unionresolve.hh / unionresolve.cc)
    """

    threshold: int = 256
    maxPasses: int = 6
    maxTrials: int = 1024

    # Trial direction enum
    FIT_DOWN = 0
    FIT_UP = 1

    class Trial:
        """A trial data-type fitted to a specific place in the data-flow."""
        __slots__ = ('vn', 'op', 'inslot', 'direction', 'array', 'fitType', 'scoreIndex')

        def __init__(self, op_or_vn, slot_or_ct, ct_or_index, index_or_isArray, isArray_or_none=None):
            if isArray_or_none is not None:
                # Down trial: Trial(op, slot, ct, index, isArray)
                self.op = op_or_vn
                self.inslot = slot_or_ct
                self.direction = ScoreUnionFields.FIT_DOWN
                self.fitType = ct_or_index
                self.scoreIndex = index_or_isArray
                self.vn = op_or_vn.getIn(slot_or_ct)
                self.array = isArray_or_none
            else:
                # Up trial: Trial(vn, ct, index, isArray)
                self.vn = op_or_vn
                self.op = None
                self.inslot = -1
                self.direction = ScoreUnionFields.FIT_UP
                self.fitType = slot_or_ct
                self.scoreIndex = ct_or_index
                self.array = index_or_isArray

    class VisitMark:
        """A mark accumulated when a given Varnode is visited with a specific field index."""
        __slots__ = ('vn_id', 'index')

        def __init__(self, vn, index: int):
            self.vn_id = id(vn)
            self.index = index

        def __hash__(self):
            return hash((self.vn_id, self.index))

        def __eq__(self, other):
            return self.vn_id == other.vn_id and self.index == other.index

    def __init__(self, typegrp, parentType, op, slot, *, unionType=None, offset: int = 0):
        from ghidra.ir.op import OpCode
        self._OpCode = OpCode
        self.typegrp = typegrp
        self.scores: List[int] = []
        self.fields: List = []
        self.visited: Set[ScoreUnionFields.VisitMark] = set()
        self.trialCurrent: List[ScoreUnionFields.Trial] = []
        self.trialNext: List[ScoreUnionFields.Trial] = []
        self.result = ResolvedUnion(parentType)
        self.trialCount: int = 0

        if unionType is not None and slot is None:
            # Constructor 2: ScoreUnionFields(tgrp, unionType, offset, op)
            self._initSubpiece(typegrp, unionType, offset, op)
        elif unionType is not None and slot is not None:
            # Constructor 3: ScoreUnionFields(tgrp, unionType, offset, op, slot)
            self._initTruncation(typegrp, unionType, offset, op, slot)
        else:
            # Constructor 1: ScoreUnionFields(tgrp, parentType, op, slot)
            self._initStandard(typegrp, parentType, op, slot)

    def _initStandard(self, typegrp, parentType, op, slot: int):
        """C++ ref: ScoreUnionFields(TypeFactory&, Datatype*, PcodeOp*, int4)"""
        if self.testSimpleCases(op, slot, parentType):
            return

        wordSize = 0
        if parentType.getMetatype() == TYPE_PTR and hasattr(parentType, 'getWordSize'):
            wordSize = parentType.getWordSize()

        numFields = self.result.baseType.numDepend() if self.result.baseType is not None else 0
        self.scores = [0] * (numFields + 1)
        self.fields = [None] * (numFields + 1)

        if slot < 0:
            vn = op.getOut()
        else:
            vn = op.getIn(slot)

        if vn.getSize() != parentType.getSize():
            self.scores[0] -= 10
        else:
            if slot < 0:
                self.trialCurrent.append(self.Trial(vn, parentType, 0, False))
            else:
                self.trialCurrent.append(self.Trial(op, slot, parentType, 0, False))

        self.fields[0] = parentType
        self.visited.add(self.VisitMark(vn, 0))

        for i in range(numFields):
            fieldType = self.result.baseType.getDepend(i)
            isArray = False
            if wordSize != 0:
                if fieldType is not None and fieldType.getMetatype() == TYPE_ARRAY:
                    isArray = True
                if hasattr(typegrp, 'getTypePointerStripArray'):
                    fieldType = typegrp.getTypePointerStripArray(parentType.getSize(), fieldType, wordSize)
                else:
                    fieldType = typegrp.getTypePointer(parentType.getSize(), fieldType, wordSize)
            if fieldType is None or vn.getSize() != fieldType.getSize():
                self.scores[i + 1] -= 10
            elif slot < 0:
                self.trialCurrent.append(self.Trial(vn, fieldType, i + 1, isArray))
            else:
                self.trialCurrent.append(self.Trial(op, slot, fieldType, i + 1, isArray))
            self.fields[i + 1] = fieldType
            self.visited.add(self.VisitMark(vn, i + 1))

        self.run()
        self.computeBestIndex()

    def _initSubpiece(self, typegrp, unionType, offset: int, op):
        """C++ ref: ScoreUnionFields(TypeFactory&, TypeUnion*, int4, PcodeOp*)"""
        self.result = ResolvedUnion(unionType)
        vn = op.getOut()
        numFields = unionType.numDepend()
        self.scores = [0] * (numFields + 1)
        self.fields = [None] * (numFields + 1)
        self.fields[0] = unionType
        self.scores[0] = -10

        for i in range(numFields):
            unionField = unionType.getField(i)
            self.fields[i + 1] = unionField.type
            if unionField.type.getSize() != vn.getSize() or unionField.offset != offset:
                self.scores[i + 1] = -10
                continue
            self.newTrialsDown(vn, unionField.type, i + 1, False)

        self.trialCurrent, self.trialNext = self.trialNext, self.trialCurrent
        if len(self.trialCurrent) > 1:
            self.run()
        self.computeBestIndex()

    def _initTruncation(self, typegrp, unionType, offset: int, op, slot: int):
        """C++ ref: ScoreUnionFields(TypeFactory&, TypeUnion*, int4, PcodeOp*, int4)"""
        self.result = ResolvedUnion(unionType)
        vn = op.getOut() if slot < 0 else op.getIn(slot)
        numFields = unionType.numDepend()
        self.scores = [0] * (numFields + 1)
        self.fields = [None] * (numFields + 1)
        self.fields[0] = unionType
        self.scores[0] = -10

        for i in range(numFields):
            unionField = unionType.getField(i)
            self.fields[i + 1] = unionField.type
            ct = self.scoreTruncation(unionField.type, vn, offset - unionField.offset, i + 1)
            if ct is not None:
                if slot < 0:
                    self.trialCurrent.append(self.Trial(vn, ct, i + 1, False))
                else:
                    self.trialCurrent.append(self.Trial(op, slot, ct, i + 1, False))
                self.visited.add(self.VisitMark(vn, i + 1))

        if len(self.trialCurrent) > 1:
            self.run()
        self.computeBestIndex()

    def getResult(self) -> ResolvedUnion:
        return self.result

    # ---- Helper methods ----

    def testArrayArithmetic(self, op, inslot: int) -> bool:
        """C++ ref: ScoreUnionFields::testArrayArithmetic"""
        OC = self._OpCode
        opc = op.code()
        if opc == OC.CPUI_INT_ADD:
            vn = op.getIn(1 - inslot)
            if vn.isConstant():
                if self.result.baseType is not None and vn.getOffset() >= self.result.baseType.getSize():
                    return True
            elif vn.isWritten():
                multOp = vn.getDef()
                if multOp.code() == OC.CPUI_INT_MULT:
                    vn2 = multOp.getIn(1)
                    if vn2.isConstant() and self.result.baseType is not None and vn2.getOffset() >= self.result.baseType.getSize():
                        return True
        elif opc == OC.CPUI_PTRADD:
            vn = op.getIn(2)
            if self.result.baseType is not None and vn.getOffset() >= self.result.baseType.getSize():
                return True
        return False

    def testSimpleCases(self, op, inslot: int, parent) -> bool:
        """C++ ref: ScoreUnionFields::testSimpleCases"""
        OC = self._OpCode
        if hasattr(op, 'isMarker') and op.isMarker():
            return True
        if parent.getMetatype() == TYPE_PTR:
            if inslot < 0:
                return True
            if self.testArrayArithmetic(op, inslot):
                return True
        if op.code() != OC.CPUI_COPY:
            return False
        if inslot < 0:
            return False
        outvn = op.getOut()
        if outvn is not None and hasattr(outvn, 'isTypeLock') and outvn.isTypeLock():
            return False
        return True

    @staticmethod
    def scoreLockedType(ct, lockType) -> int:
        """C++ ref: ScoreUnionFields::scoreLockedType"""
        score = 0
        if lockType is ct:
            score += 5
        while ct.getMetatype() == TYPE_PTR:
            if lockType.getMetatype() != TYPE_PTR:
                break
            score += 5
            ct = ct.getPtrTo() if hasattr(ct, 'getPtrTo') else ct
            lockType = lockType.getPtrTo() if hasattr(lockType, 'getPtrTo') else lockType
        ctMeta = ct.getMetatype()
        vnMeta = lockType.getMetatype()
        if ctMeta == vnMeta:
            if ctMeta in (TYPE_STRUCT, TYPE_UNION, TYPE_ARRAY, TYPE_CODE):
                score += 10
            else:
                score += 3
        else:
            if (ctMeta == TYPE_INT and vnMeta == TYPE_UINT) or (ctMeta == TYPE_UINT and vnMeta == TYPE_INT):
                score -= 1
            else:
                score -= 5
            if ct.getSize() != lockType.getSize():
                score -= 2
        return score

    def scoreParameter(self, ct, callOp, paramSlot: int) -> int:
        """C++ ref: ScoreUnionFields::scoreParameter"""
        fd = callOp.getParent().getFuncdata() if hasattr(callOp.getParent(), 'getFuncdata') else None
        if fd is not None and hasattr(fd, 'getCallSpecs'):
            fc = fd.getCallSpecs(callOp)
            if fc is not None and hasattr(fc, 'isInputLocked') and fc.isInputLocked():
                if hasattr(fc, 'numParams') and fc.numParams() > paramSlot:
                    return self.scoreLockedType(ct, fc.getParam(paramSlot).getType())
        meta = ct.getMetatype()
        if meta in (TYPE_ARRAY, TYPE_STRUCT, TYPE_UNION, TYPE_CODE):
            return -1
        return 0

    def scoreReturnType(self, ct, callOp) -> int:
        """C++ ref: ScoreUnionFields::scoreReturnType"""
        fd = callOp.getParent().getFuncdata() if hasattr(callOp.getParent(), 'getFuncdata') else None
        if fd is not None and hasattr(fd, 'getCallSpecs'):
            fc = fd.getCallSpecs(callOp)
            if fc is not None and hasattr(fc, 'isOutputLocked') and fc.isOutputLocked():
                return self.scoreLockedType(ct, fc.getOutputType())
        meta = ct.getMetatype()
        if meta in (TYPE_ARRAY, TYPE_STRUCT, TYPE_UNION, TYPE_CODE):
            return -1
        return 0

    @staticmethod
    def derefPointer(ct, vn) -> tuple:
        """C++ ref: ScoreUnionFields::derefPointer — returns (resType, score)"""
        resType = None
        score = 0
        if ct.getMetatype() == TYPE_PTR:
            ptrto = ct.getPtrTo() if hasattr(ct, 'getPtrTo') else None
            while ptrto is not None and ptrto.getSize() > vn.getSize():
                sub = ptrto.getSubType(0)
                ptrto = sub[0] if isinstance(sub, tuple) else sub
            if ptrto is not None and ptrto.getSize() == vn.getSize():
                score = 10
                resType = ptrto
        else:
            score = -10
        return resType, score

    def newTrialsDown(self, vn, ct, scoreIndex: int, isArray: bool):
        """C++ ref: ScoreUnionFields::newTrialsDown"""
        mark = self.VisitMark(vn, scoreIndex)
        if mark in self.visited:
            return
        self.visited.add(mark)
        if hasattr(vn, 'isTypeLock') and vn.isTypeLock():
            self.scores[scoreIndex] += self.scoreLockedType(ct, vn.getType())
            return
        if hasattr(vn, 'beginDescend'):
            for desc_op in vn.beginDescend():
                slot = desc_op.getSlot(vn)
                self.trialNext.append(self.Trial(desc_op, slot, ct, scoreIndex, isArray))
        elif hasattr(vn, 'descend'):
            for desc_op in vn.descend():
                slot = desc_op.getSlot(vn)
                self.trialNext.append(self.Trial(desc_op, slot, ct, scoreIndex, isArray))

    def newTrials(self, op, slot: int, ct, scoreIndex: int, isArray: bool):
        """C++ ref: ScoreUnionFields::newTrials"""
        vn = op.getIn(slot)
        mark = self.VisitMark(vn, scoreIndex)
        if mark in self.visited:
            return
        self.visited.add(mark)
        if hasattr(vn, 'isTypeLock') and vn.isTypeLock():
            self.scores[scoreIndex] += self.scoreLockedType(ct, vn.getType())
            return
        self.trialNext.append(self.Trial(vn, ct, scoreIndex, isArray))
        desc_iter = vn.beginDescend() if hasattr(vn, 'beginDescend') else (
            vn.descend() if hasattr(vn, 'descend') else [])
        for readOp in desc_iter:
            inslot = readOp.getSlot(vn)
            if readOp is op and inslot == slot:
                continue
            self.trialNext.append(self.Trial(readOp, inslot, ct, scoreIndex, isArray))

    def scoreTrialDown(self, trial: Trial, lastLevel: bool):
        """C++ ref: ScoreUnionFields::scoreTrialDown"""
        if trial.direction == self.FIT_UP:
            return
        OC = self._OpCode
        resType = None
        meta = trial.fitType.getMetatype()
        score = 0
        opc = trial.op.code()

        if opc in (OC.CPUI_COPY, OC.CPUI_MULTIEQUAL, OC.CPUI_INDIRECT):
            resType = trial.fitType
        elif opc == OC.CPUI_LOAD:
            resType, score = self.derefPointer(trial.fitType, trial.op.getOut())
        elif opc == OC.CPUI_STORE:
            if trial.inslot == 1:
                ptrto, score = self.derefPointer(trial.fitType, trial.op.getIn(2))
                if ptrto is not None and not lastLevel:
                    self.newTrials(trial.op, 2, ptrto, trial.scoreIndex, trial.array)
            elif trial.inslot == 2:
                score = -5 if meta == TYPE_CODE else 1
        elif opc == OC.CPUI_CBRANCH:
            score = 10 if meta == TYPE_BOOL else -10
        elif opc == OC.CPUI_BRANCHIND:
            score = -5 if meta in (TYPE_PTR, TYPE_ARRAY, TYPE_STRUCT, TYPE_UNION, TYPE_CODE, TYPE_FLOAT) else 1
        elif opc in (OC.CPUI_CALL, OC.CPUI_CALLOTHER):
            if trial.inslot > 0:
                score = self.scoreParameter(trial.fitType, trial.op, trial.inslot - 1)
        elif opc == OC.CPUI_CALLIND:
            if trial.inslot == 0:
                if meta == TYPE_PTR:
                    ptrto = trial.fitType.getPtrTo() if hasattr(trial.fitType, 'getPtrTo') else None
                    score = 10 if (ptrto is not None and ptrto.getMetatype() == TYPE_CODE) else -10
            else:
                score = self.scoreParameter(trial.fitType, trial.op, trial.inslot - 1)
        elif opc == OC.CPUI_RETURN:
            if meta in (TYPE_ARRAY, TYPE_STRUCT, TYPE_UNION, TYPE_CODE):
                score = -1
        elif opc in (OC.CPUI_INT_EQUAL, OC.CPUI_INT_NOTEQUAL):
            if meta in (TYPE_ARRAY, TYPE_STRUCT, TYPE_UNION, TYPE_CODE, TYPE_FLOAT):
                score = -1
            else:
                score = 1
        elif opc in (OC.CPUI_INT_SLESS, OC.CPUI_INT_SLESSEQUAL):
            if meta in (TYPE_ARRAY, TYPE_STRUCT, TYPE_UNION, TYPE_CODE, TYPE_FLOAT):
                score = -5
            elif meta in (TYPE_PTR, TYPE_UNKNOWN, TYPE_UINT, TYPE_BOOL):
                score = -1
            else:
                score = 5
        elif opc in (OC.CPUI_INT_LESS, OC.CPUI_INT_LESSEQUAL):
            if meta in (TYPE_ARRAY, TYPE_STRUCT, TYPE_UNION, TYPE_CODE, TYPE_FLOAT):
                score = -5
            elif meta in (TYPE_PTR, TYPE_UNKNOWN, TYPE_UINT):
                score = 5
            elif meta == TYPE_INT:
                score = -5
        elif opc == OC.CPUI_INT_ZEXT:
            if meta == TYPE_UINT:
                score = 2
            elif meta in (TYPE_INT, TYPE_BOOL):
                score = 1
            elif meta == TYPE_UNKNOWN:
                score = 0
            else:
                score = -5
        elif opc == OC.CPUI_INT_SEXT:
            if meta == TYPE_INT:
                score = 2
            elif meta in (TYPE_UINT, TYPE_BOOL):
                score = 1
            elif meta == TYPE_UNKNOWN:
                score = 0
            else:
                score = -5
        elif opc in (OC.CPUI_INT_ADD, OC.CPUI_INT_SUB, OC.CPUI_PTRSUB):
            if meta == TYPE_PTR:
                if trial.inslot >= 0:
                    vn = trial.op.getIn(1 - trial.inslot)
                    if vn.isConstant():
                        if hasattr(trial.fitType, 'downChain'):
                            off = vn.getOffset()
                            r = trial.fitType.downChain(off, None, None, trial.array, self.typegrp)
                            resType = r
                            if resType is not None:
                                score = 5
                        else:
                            score = 5
                    else:
                        if trial.array:
                            score = 1
                            elSize = 1
                            if vn.isWritten():
                                multOp = vn.getDef()
                                if multOp.code() == OC.CPUI_INT_MULT:
                                    multVn = multOp.getIn(1)
                                    if multVn.isConstant():
                                        elSize = int(multVn.getOffset())
                            ptrto = trial.fitType.getPtrTo() if hasattr(trial.fitType, 'getPtrTo') else None
                            if ptrto is not None and ptrto.getAlignSize() == elSize:
                                score = 5
                                resType = trial.fitType
                        else:
                            score = 5
            elif meta in (TYPE_ARRAY, TYPE_STRUCT, TYPE_UNION, TYPE_CODE, TYPE_FLOAT):
                score = -5
            else:
                score = 1
        elif opc == OC.CPUI_INT_2COMP:
            if meta in (TYPE_ARRAY, TYPE_STRUCT, TYPE_UNION, TYPE_CODE, TYPE_FLOAT):
                score = -5
            elif meta in (TYPE_PTR, TYPE_UNKNOWN, TYPE_BOOL):
                score = -1
            elif meta == TYPE_INT:
                score = 5
        elif opc in (OC.CPUI_INT_NEGATE, OC.CPUI_INT_XOR, OC.CPUI_INT_AND, OC.CPUI_INT_OR):
            if meta in (TYPE_ARRAY, TYPE_STRUCT, TYPE_UNION, TYPE_CODE, TYPE_FLOAT):
                score = -5
            elif meta in (TYPE_PTR, TYPE_BOOL):
                score = -1
            elif meta in (TYPE_UINT, TYPE_UNKNOWN):
                score = 2
        elif opc in (OC.CPUI_INT_LEFT, OC.CPUI_INT_RIGHT):
            if trial.inslot == 0:
                if meta in (TYPE_ARRAY, TYPE_STRUCT, TYPE_UNION, TYPE_CODE, TYPE_FLOAT):
                    score = -5
                elif meta in (TYPE_PTR, TYPE_BOOL):
                    score = -1
                elif meta in (TYPE_UINT, TYPE_UNKNOWN):
                    score = 2
            else:
                if meta in (TYPE_ARRAY, TYPE_STRUCT, TYPE_UNION, TYPE_CODE, TYPE_FLOAT, TYPE_PTR):
                    score = -5
                else:
                    score = 1
        elif opc == OC.CPUI_INT_SRIGHT:
            if trial.inslot == 0:
                if meta in (TYPE_ARRAY, TYPE_STRUCT, TYPE_UNION, TYPE_CODE, TYPE_FLOAT):
                    score = -5
                elif meta in (TYPE_PTR, TYPE_BOOL, TYPE_UINT, TYPE_UNKNOWN):
                    score = -1
                else:
                    score = 2
            else:
                if meta in (TYPE_ARRAY, TYPE_STRUCT, TYPE_UNION, TYPE_CODE, TYPE_FLOAT, TYPE_PTR):
                    score = -5
                else:
                    score = 1
        elif opc == OC.CPUI_INT_MULT:
            if meta in (TYPE_ARRAY, TYPE_STRUCT, TYPE_UNION, TYPE_CODE, TYPE_FLOAT):
                score = -10
            elif meta in (TYPE_PTR, TYPE_BOOL):
                score = -2
            else:
                score = 5
        elif opc in (OC.CPUI_INT_DIV, OC.CPUI_INT_REM):
            if meta in (TYPE_ARRAY, TYPE_STRUCT, TYPE_UNION, TYPE_CODE, TYPE_FLOAT):
                score = -10
            elif meta in (TYPE_PTR, TYPE_BOOL):
                score = -2
            elif meta in (TYPE_UINT, TYPE_UNKNOWN):
                score = 5
        elif opc in (OC.CPUI_INT_SDIV, OC.CPUI_INT_SREM):
            if meta in (TYPE_ARRAY, TYPE_STRUCT, TYPE_UNION, TYPE_CODE, TYPE_FLOAT):
                score = -10
            elif meta in (TYPE_PTR, TYPE_BOOL):
                score = -2
            elif meta == TYPE_INT:
                score = 5
        elif opc in (OC.CPUI_BOOL_NEGATE, OC.CPUI_BOOL_AND, OC.CPUI_BOOL_XOR, OC.CPUI_BOOL_OR):
            if meta == TYPE_BOOL:
                score = 10
            elif meta in (TYPE_INT, TYPE_UINT, TYPE_UNKNOWN):
                score = -1
            else:
                score = -10
        elif opc in (OC.CPUI_FLOAT_EQUAL, OC.CPUI_FLOAT_NOTEQUAL, OC.CPUI_FLOAT_LESS,
                     OC.CPUI_FLOAT_LESSEQUAL, OC.CPUI_FLOAT_ADD, OC.CPUI_FLOAT_DIV,
                     OC.CPUI_FLOAT_MULT, OC.CPUI_FLOAT_SUB, OC.CPUI_FLOAT_NEG,
                     OC.CPUI_FLOAT_ABS, OC.CPUI_FLOAT_SQRT, OC.CPUI_FLOAT_FLOAT2FLOAT,
                     OC.CPUI_FLOAT_TRUNC, OC.CPUI_FLOAT_CEIL, OC.CPUI_FLOAT_FLOOR,
                     OC.CPUI_FLOAT_ROUND, OC.CPUI_FLOAT_NAN):
            score = 10 if meta == TYPE_FLOAT else -10
        elif opc == OC.CPUI_FLOAT_INT2FLOAT:
            if meta in (TYPE_ARRAY, TYPE_STRUCT, TYPE_UNION, TYPE_CODE, TYPE_FLOAT):
                score = -10
            elif meta == TYPE_PTR:
                score = -5
            elif meta == TYPE_INT:
                score = 5
        elif opc == OC.CPUI_PIECE:
            if meta in (TYPE_ARRAY, TYPE_STRUCT, TYPE_UNION, TYPE_CODE, TYPE_FLOAT):
                score = -5
        elif opc == OC.CPUI_SUBPIECE:
            offset = self._computeByteOffsetForComposite(trial.op)
            resType = self.scoreTruncation(trial.fitType, trial.op.getOut(), offset, trial.scoreIndex)
        elif opc == OC.CPUI_PTRADD:
            if meta == TYPE_PTR:
                if trial.inslot == 0:
                    ptrto = trial.fitType.getPtrTo() if hasattr(trial.fitType, 'getPtrTo') else None
                    if ptrto is not None and ptrto.getAlignSize() == trial.op.getIn(2).getOffset():
                        score = 10
                        resType = trial.fitType
                else:
                    score = -10
            elif meta in (TYPE_ARRAY, TYPE_STRUCT, TYPE_UNION, TYPE_CODE, TYPE_FLOAT):
                score = -5
            else:
                score = 1
        elif opc == OC.CPUI_SEGMENTOP:
            if trial.inslot == 2:
                if meta == TYPE_PTR:
                    score = 5
                elif meta in (TYPE_ARRAY, TYPE_STRUCT, TYPE_UNION, TYPE_CODE, TYPE_FLOAT):
                    score = -5
                else:
                    score = -1
            else:
                if meta in (TYPE_ARRAY, TYPE_STRUCT, TYPE_UNION, TYPE_CODE, TYPE_FLOAT, TYPE_PTR):
                    score = -2
        else:
            score = -10

        self.scores[trial.scoreIndex] += score
        if resType is not None and not lastLevel:
            self.newTrialsDown(trial.op.getOut(), resType, trial.scoreIndex, trial.array)

    def scoreTrialUp(self, trial: Trial, lastLevel: bool):
        """C++ ref: ScoreUnionFields::scoreTrialUp"""
        if trial.direction == self.FIT_DOWN:
            return
        OC = self._OpCode
        score = 0
        if not trial.vn.isWritten():
            if trial.vn.isConstant():
                self.scoreConstantFit(trial)
            return
        resType = None
        newslot = 0
        meta = trial.fitType.getMetatype()
        defop = trial.vn.getDef()
        opc = defop.code()

        if opc in (OC.CPUI_COPY, OC.CPUI_MULTIEQUAL, OC.CPUI_INDIRECT):
            resType = trial.fitType
            newslot = 0
        elif opc == OC.CPUI_LOAD:
            resType = self.typegrp.getTypePointer(defop.getIn(1).getSize(), trial.fitType, 1)
            newslot = 1
        elif opc in (OC.CPUI_CALL, OC.CPUI_CALLOTHER, OC.CPUI_CALLIND):
            score = self.scoreReturnType(trial.fitType, defop)
        elif opc in (OC.CPUI_INT_EQUAL, OC.CPUI_INT_NOTEQUAL, OC.CPUI_INT_SLESS,
                     OC.CPUI_INT_SLESSEQUAL, OC.CPUI_INT_LESS, OC.CPUI_INT_LESSEQUAL,
                     OC.CPUI_BOOL_NEGATE, OC.CPUI_BOOL_AND, OC.CPUI_BOOL_XOR, OC.CPUI_BOOL_OR,
                     OC.CPUI_FLOAT_EQUAL, OC.CPUI_FLOAT_NOTEQUAL, OC.CPUI_FLOAT_LESS,
                     OC.CPUI_FLOAT_LESSEQUAL, OC.CPUI_FLOAT_NAN):
            if meta == TYPE_BOOL:
                score = 10
            elif trial.fitType.getSize() == 1:
                score = 1
            else:
                score = -10
        elif opc in (OC.CPUI_INT_ADD, OC.CPUI_INT_SUB, OC.CPUI_PTRSUB):
            if meta == TYPE_PTR:
                score = 5
            elif meta in (TYPE_ARRAY, TYPE_STRUCT, TYPE_UNION, TYPE_CODE, TYPE_FLOAT):
                score = -5
            else:
                score = 1
        elif opc == OC.CPUI_INT_2COMP:
            if meta in (TYPE_ARRAY, TYPE_STRUCT, TYPE_UNION, TYPE_CODE, TYPE_FLOAT):
                score = -5
            elif meta in (TYPE_PTR, TYPE_UNKNOWN, TYPE_BOOL):
                score = -1
            elif meta == TYPE_INT:
                score = 5
        elif opc in (OC.CPUI_INT_NEGATE, OC.CPUI_INT_XOR, OC.CPUI_INT_AND, OC.CPUI_INT_OR):
            if meta in (TYPE_ARRAY, TYPE_STRUCT, TYPE_UNION, TYPE_CODE, TYPE_FLOAT):
                score = -5
            elif meta in (TYPE_PTR, TYPE_BOOL):
                score = -1
            elif meta in (TYPE_UINT, TYPE_UNKNOWN):
                score = 2
        elif opc in (OC.CPUI_INT_LEFT, OC.CPUI_INT_RIGHT):
            if meta in (TYPE_ARRAY, TYPE_STRUCT, TYPE_UNION, TYPE_CODE, TYPE_FLOAT):
                score = -5
            elif meta in (TYPE_PTR, TYPE_BOOL):
                score = -1
            elif meta in (TYPE_UINT, TYPE_UNKNOWN):
                score = 2
        elif opc == OC.CPUI_INT_SRIGHT:
            if meta in (TYPE_ARRAY, TYPE_STRUCT, TYPE_UNION, TYPE_CODE, TYPE_FLOAT):
                score = -5
            elif meta in (TYPE_PTR, TYPE_BOOL, TYPE_UINT, TYPE_UNKNOWN):
                score = -1
            else:
                score = 2
        elif opc == OC.CPUI_INT_MULT:
            if meta in (TYPE_ARRAY, TYPE_STRUCT, TYPE_UNION, TYPE_CODE, TYPE_FLOAT):
                score = -10
            elif meta in (TYPE_PTR, TYPE_BOOL):
                score = -2
            else:
                score = 5
        elif opc in (OC.CPUI_INT_DIV, OC.CPUI_INT_REM):
            if meta in (TYPE_ARRAY, TYPE_STRUCT, TYPE_UNION, TYPE_CODE, TYPE_FLOAT):
                score = -10
            elif meta in (TYPE_PTR, TYPE_BOOL):
                score = -2
            elif meta in (TYPE_UINT, TYPE_UNKNOWN):
                score = 5
        elif opc in (OC.CPUI_INT_SDIV, OC.CPUI_INT_SREM):
            if meta in (TYPE_ARRAY, TYPE_STRUCT, TYPE_UNION, TYPE_CODE, TYPE_FLOAT):
                score = -10
            elif meta in (TYPE_PTR, TYPE_BOOL):
                score = -2
            elif meta == TYPE_INT:
                score = 5
        elif opc in (OC.CPUI_FLOAT_ADD, OC.CPUI_FLOAT_DIV, OC.CPUI_FLOAT_MULT,
                     OC.CPUI_FLOAT_SUB, OC.CPUI_FLOAT_NEG, OC.CPUI_FLOAT_ABS,
                     OC.CPUI_FLOAT_SQRT, OC.CPUI_FLOAT_FLOAT2FLOAT,
                     OC.CPUI_FLOAT_CEIL, OC.CPUI_FLOAT_FLOOR, OC.CPUI_FLOAT_ROUND,
                     OC.CPUI_FLOAT_INT2FLOAT):
            score = 10 if meta == TYPE_FLOAT else -10
        elif opc == OC.CPUI_FLOAT_TRUNC:
            score = 2 if meta in (TYPE_INT, TYPE_UINT) else -2
        elif opc == OC.CPUI_PIECE:
            if meta in (TYPE_FLOAT, TYPE_BOOL):
                score = -5
            elif meta in (TYPE_CODE, TYPE_PTR):
                score = -2
        elif opc == OC.CPUI_SUBPIECE:
            if meta in (TYPE_INT, TYPE_UINT, TYPE_BOOL):
                score = 3 if defop.getIn(1).getOffset() == 0 else 1
            else:
                score = -5
        elif opc == OC.CPUI_PTRADD:
            if meta == TYPE_PTR:
                ptrto = trial.fitType.getPtrTo() if hasattr(trial.fitType, 'getPtrTo') else None
                if ptrto is not None and ptrto.getAlignSize() == defop.getIn(2).getOffset():
                    score = 10
                else:
                    score = 2
            elif meta in (TYPE_ARRAY, TYPE_STRUCT, TYPE_UNION, TYPE_CODE, TYPE_FLOAT):
                score = -5
            else:
                score = 1
        else:
            score = -10

        self.scores[trial.scoreIndex] += score
        if resType is not None and not lastLevel:
            self.newTrials(defop, newslot, resType, trial.scoreIndex, trial.array)

    def scoreTruncation(self, ct, vn, offset: int, scoreIndex: int):
        """C++ ref: ScoreUnionFields::scoreTruncation"""
        if ct.getMetatype() == TYPE_UNION:
            resType = None
            score = -10
            numDep = ct.numDepend()
            for i in range(numDep):
                field = ct.getField(i)
                if field.offset == offset and field.type.getSize() == vn.getSize():
                    score = 10
                    if self.result.baseType is ct:
                        score += 5
                    break
            self.scores[scoreIndex] += score
            return resType
        else:
            score = 10
            curOff = offset
            cur = ct
            while cur is not None and (curOff != 0 or cur.getSize() != vn.getSize()):
                curMeta = cur.getMetatype()
                if curMeta in (TYPE_INT, TYPE_UINT):
                    if cur.getSize() >= vn.getSize() + curOff:
                        score = 1
                        break
                sub = cur.getSubType(curOff)
                if isinstance(sub, tuple):
                    cur, curOff = sub
                else:
                    cur = sub
                    curOff = 0
            if cur is None:
                score = -10
            self.scores[scoreIndex] += score
            return cur

    def scoreConstantFit(self, trial: Trial):
        """C++ ref: ScoreUnionFields::scoreConstantFit"""
        size = trial.vn.getSize()
        val = trial.vn.getOffset()
        meta = trial.fitType.getMetatype()
        score = 0
        if meta == TYPE_BOOL:
            score = 2 if (size == 1 and val < 2) else -2
        elif meta == TYPE_FLOAT:
            score = -1
        elif meta in (TYPE_INT, TYPE_UINT, TYPE_PTR):
            if val == 0:
                score = 2
            else:
                if meta == TYPE_PTR:
                    score = -2  # Simplified: no pointer range check
                else:
                    score = 2
        else:
            score = -2
        self.scores[trial.scoreIndex] += score

    def runOneLevel(self, lastPass: bool):
        """C++ ref: ScoreUnionFields::runOneLevel"""
        for trial in self.trialCurrent:
            self.trialCount += 1
            if self.trialCount > self.maxTrials:
                return
            self.scoreTrialDown(trial, lastPass)
            self.scoreTrialUp(trial, lastPass)

    def computeBestIndex(self):
        """C++ ref: ScoreUnionFields::computeBestIndex"""
        if not self.scores:
            return
        bestScore = self.scores[0]
        bestIndex = 0
        for i in range(1, len(self.scores)):
            if self.scores[i] > bestScore:
                bestScore = self.scores[i]
                bestIndex = i
        self.result.fieldNum = bestIndex - 1  # Renormalize score index to field index
        if bestIndex < len(self.fields):
            self.result.resolve = self.fields[bestIndex]

    def run(self):
        """C++ ref: ScoreUnionFields::run"""
        self.trialCount = 0
        for pass_num in range(self.maxPasses):
            if not self.trialCurrent:
                break
            if self.trialCount > self.threshold:
                break
            if pass_num + 1 == self.maxPasses:
                self.runOneLevel(True)
            else:
                self.runOneLevel(False)
                self.trialCurrent, self.trialNext = self.trialNext, []

    @staticmethod
    def _computeByteOffsetForComposite(op) -> int:
        """Get the byte offset from a SUBPIECE op's constant input."""
        return int(op.getIn(1).getOffset()) if op.numInput() > 1 else 0
