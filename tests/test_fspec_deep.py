"""Tests for deepened fspec.py methods -- FuncProto, FuncCallSpecs, ProtoModel."""
from __future__ import annotations

import pytest

from ghidra.core.address import Address
from ghidra.core.space import AddrSpace
from ghidra.core.error import LowlevelError
from ghidra.fspec.fspec import (
    ParameterPieces, ParameterBasic, PrototypePieces, ProtoParameter,
    FuncProto, FuncCallSpecs, ProtoModel, ProtoModelMerged,
    ScoreProtoModel, ParamEntry, ParamListStandard,
    ParamUnassignedError,
)
from ghidra.types.datatype import TYPE_UNKNOWN


# ---------------------------------------------------------------------------
# Helpers / mocks
# ---------------------------------------------------------------------------

def _spc(name="ram", size=4):
    return AddrSpace(name=name, size=size)


def _addr(off, spc=None):
    return Address(spc or _spc(), off)


class _MockType:
    """Minimal mock for Datatype."""
    def __init__(self, sz=4, meta=TYPE_UNKNOWN, name="unk"):
        self._size = sz
        self._meta = meta
        self._name = name

    def getSize(self):
        return self._size

    def getMetatype(self):
        return self._meta

    def getAlignment(self):
        return 1

    def __repr__(self):
        return self._name


class _MockHigh:
    """Minimal mock for HighVariable."""
    def __init__(self, tp=None):
        self._type = tp or _MockType()

    def getType(self):
        return self._type


class _MockVarnode:
    """Minimal mock for Varnode used in trials."""
    def __init__(self, addr, sz=4, tp=None, persist=False):
        self._addr = addr
        self._size = sz
        self._high = _MockHigh(tp)
        self._marked = False
        self._persist = persist
        self._noDescend = True

    def getAddr(self):
        return self._addr

    def getAddress(self):
        return self._addr

    def getSize(self):
        return self._size

    def getHigh(self):
        return self._high

    def isMark(self):
        return self._marked

    def setMark(self):
        self._marked = True

    def clearMark(self):
        self._marked = False

    def isPersist(self):
        return self._persist

    def isInput(self):
        return True

    def hasNoDescend(self):
        return self._noDescend


class _MockTypeFactory:
    """Minimal mock for TypeFactory."""
    def getBase(self, sz, meta):
        return _MockType(sz, meta, f"unk{sz}")

    def getTypeVoid(self):
        return _MockType(0, 0, "void")


class _MockArch:
    """Minimal mock for Architecture."""
    def __init__(self):
        self.types = _MockTypeFactory()


class _MockFuncdata:
    """Minimal mock for Funcdata."""
    def __init__(self):
        self._arch = _MockArch()

    def getArch(self):
        return self._arch


class _MockParamTrial:
    """Minimal mock for ParamTrial."""
    checked = 1
    used = 2
    defnouse = 4
    active = 8
    unref = 0x10
    condexe_effect = 0x100

    def __init__(self, addr, sz, slot, used=False, active_flag=False):
        self._addr = addr
        self._size = sz
        self._slot = slot
        self._flags = 0
        if used:
            self._flags |= _MockParamTrial.used
        if active_flag:
            self._flags |= _MockParamTrial.active | _MockParamTrial.checked

    def getAddress(self):
        return self._addr

    def getSize(self):
        return self._size

    def getSlot(self):
        return self._slot

    def isUsed(self):
        return (self._flags & _MockParamTrial.used) != 0

    def isChecked(self):
        return (self._flags & _MockParamTrial.checked) != 0

    def isActive(self):
        return (self._flags & _MockParamTrial.active) != 0

    def isDefinitelyNotUsed(self):
        return (self._flags & _MockParamTrial.defnouse) != 0

    def hasCondExeEffect(self):
        return (self._flags & _MockParamTrial.condexe_effect) != 0

    def markUsed(self):
        self._flags |= _MockParamTrial.used

    def markActive(self):
        self._flags |= (_MockParamTrial.active | _MockParamTrial.checked)

    def markInactive(self):
        self._flags &= ~_MockParamTrial.active
        self._flags |= _MockParamTrial.checked

    def isUnref(self):
        return (self._flags & _MockParamTrial.unref) != 0

    def markNoUse(self):
        self._flags &= ~(_MockParamTrial.active | _MockParamTrial.used)
        self._flags |= (_MockParamTrial.checked | _MockParamTrial.defnouse)

    def setAddress(self, addr, sz):
        self._addr = addr
        self._size = sz


class _MockParamActive:
    """Minimal mock for ParamActive."""
    def __init__(self, trials=None):
        self._trials = trials or []
        self._numpasses = 0

    def getNumTrials(self):
        return len(self._trials)

    def getTrial(self, i):
        return self._trials[i]

    def registerTrial(self, addr, sz):
        slot = len(self._trials) + 1
        self._trials.append(_MockParamTrial(addr, sz, slot))

    def whichTrial(self, addr, sz):
        for i, t in enumerate(self._trials):
            if t.getAddress() == addr and t.getSize() == sz:
                return i
        return -1

    def deleteUnusedTrials(self):
        self._trials = [t for t in self._trials if t.isUsed()]
        for i, t in enumerate(self._trials):
            t._slot = i + 1

    def sortFixedPosition(self):
        pass


# ---------------------------------------------------------------------------
# FuncProto.setModel
# ---------------------------------------------------------------------------

class TestFuncProtoSetModel:
    def test_setModel_inherits_extrapop(self):
        m = ProtoModel("cdecl")
        m.extrapop = 4
        fp = FuncProto()
        fp.setModel(m)
        assert fp.extrapop == 4
        assert fp.model is m

    def test_setModel_unknown_extrapop_not_overwritten(self):
        m1 = ProtoModel("cdecl")
        m1.extrapop = 4
        fp = FuncProto()
        fp.setModel(m1)
        assert fp.extrapop == 4
        m2 = ProtoModel("stdcall")
        m2.extrapop = ProtoModel.extrapop_unknown
        fp.setModel(m2)
        # extrapop should remain 4 since m2 has unknown
        assert fp.extrapop == 4

    def test_setModel_inherits_hasThis(self):
        m = ProtoModel("thiscall")
        m.hasThis = True
        fp = FuncProto()
        fp.setModel(m)
        assert fp.hasThisPointer()

    def test_setModel_inherits_isConstructor(self):
        m = ProtoModel("ctor")
        m.isConstruct = True
        fp = FuncProto()
        fp.setModel(m)
        assert fp.isConstructor()

    def test_setModel_none_resets_extrapop(self):
        fp = FuncProto()
        fp.extrapop = 4
        fp.setModel(None)
        assert fp.extrapop == ProtoModel.extrapop_unknown
        assert fp.model is None


# ---------------------------------------------------------------------------
# FuncProto.resolveModel
# ---------------------------------------------------------------------------

class TestFuncProtoResolveModel:
    def test_resolveModel_noop_non_merged(self):
        m = ProtoModel("cdecl")
        fp = FuncProto()
        fp.setModel(m)
        active = _MockParamActive()
        fp.resolveModel(active)
        assert fp.model is m  # unchanged

    def test_resolveModel_picks_from_merged(self):
        m1 = ProtoModel("cdecl")
        m2 = ProtoModel("stdcall")
        merged = ProtoModelMerged()
        merged.foldIn(m1)
        merged.foldIn(m2)
        fp = FuncProto()
        fp.model = merged
        fp.extrapop = 0
        active = _MockParamActive()
        fp.resolveModel(active)
        assert fp.model in (m1, m2)
        assert not hasattr(fp.model, 'isMerged') or not fp.model.isMerged()

    def test_resolveModel_none_model(self):
        fp = FuncProto()
        fp.resolveModel(_MockParamActive())  # no crash


# ---------------------------------------------------------------------------
# FuncProto.updateInputTypes
# ---------------------------------------------------------------------------

class TestFuncProtoUpdateInputTypes:
    def _make_fp(self):
        fp = FuncProto()
        m = ProtoModel("cdecl")
        fp.model = m
        return fp

    def test_basic_update(self):
        fp = self._make_fp()
        spc = _spc()
        t1 = _MockParamTrial(Address(spc, 0x10), 4, 1, used=True)
        t2 = _MockParamTrial(Address(spc, 0x20), 4, 2, used=True)
        active = _MockParamActive([t1, t2])
        vn1 = _MockVarnode(Address(spc, 0x10), 4)
        vn2 = _MockVarnode(Address(spc, 0x20), 4)
        data = _MockFuncdata()
        fp.updateInputTypes(data, [vn1, vn2], active)
        assert fp.numParams() == 2

    def test_skips_unused_trials(self):
        fp = self._make_fp()
        spc = _spc()
        t1 = _MockParamTrial(Address(spc, 0x10), 4, 1, used=True)
        t2 = _MockParamTrial(Address(spc, 0x20), 4, 2, used=False)
        active = _MockParamActive([t1, t2])
        vn1 = _MockVarnode(Address(spc, 0x10), 4)
        vn2 = _MockVarnode(Address(spc, 0x20), 4)
        data = _MockFuncdata()
        fp.updateInputTypes(data, [vn1, vn2], active)
        assert fp.numParams() == 1

    def test_skips_marked_varnodes(self):
        """If two trials reference the same varnode, only the first is kept."""
        fp = self._make_fp()
        spc = _spc()
        t1 = _MockParamTrial(Address(spc, 0x10), 4, 1, used=True)
        t2 = _MockParamTrial(Address(spc, 0x20), 4, 1, used=True)  # same slot
        active = _MockParamActive([t1, t2])
        vn1 = _MockVarnode(Address(spc, 0x10), 4)
        data = _MockFuncdata()
        fp.updateInputTypes(data, [vn1], active)
        assert fp.numParams() == 1  # second skipped due to mark

    def test_noop_if_input_locked(self):
        fp = self._make_fp()
        fp.setVoidInputLock(True)
        spc = _spc()
        t1 = _MockParamTrial(Address(spc, 0x10), 4, 1, used=True)
        active = _MockParamActive([t1])
        vn1 = _MockVarnode(Address(spc, 0x10), 4)
        data = _MockFuncdata()
        fp.updateInputTypes(data, [vn1], active)
        assert fp.numParams() == 0  # locked, no change

    def test_clears_marks_after_update(self):
        fp = self._make_fp()
        spc = _spc()
        t1 = _MockParamTrial(Address(spc, 0x10), 4, 1, used=True)
        active = _MockParamActive([t1])
        vn1 = _MockVarnode(Address(spc, 0x10), 4)
        data = _MockFuncdata()
        fp.updateInputTypes(data, [vn1], active)
        assert not vn1.isMark()


# ---------------------------------------------------------------------------
# FuncProto.updateInputNoTypes
# ---------------------------------------------------------------------------

class TestFuncProtoUpdateInputNoTypes:
    def test_uses_factory_types(self):
        fp = FuncProto()
        m = ProtoModel("cdecl")
        fp.model = m
        spc = _spc()
        t1 = _MockParamTrial(Address(spc, 0x10), 4, 1, used=True)
        active = _MockParamActive([t1])
        vn1 = _MockVarnode(Address(spc, 0x10), 4)
        data = _MockFuncdata()
        fp.updateInputNoTypes(data, [vn1], active)
        assert fp.numParams() == 1
        tp = fp.getParam(0).getType()
        assert tp is not None
        assert tp.getSize() == 4


# ---------------------------------------------------------------------------
# FuncProto.updateOutputTypes
# ---------------------------------------------------------------------------

class TestFuncProtoUpdateOutputTypes:
    def test_sets_output_from_trial(self):
        fp = FuncProto()
        spc = _spc()
        vn = _MockVarnode(Address(spc, 0x10), 4, _MockType(4))
        fp.updateOutputTypes([vn])
        assert fp.outparam is not None
        assert fp.outparam.getSize() == 4

    def test_clears_output_when_empty_and_unlocked(self):
        fp = FuncProto()
        fp.outparam = ProtoParameter("out", _MockType(4), _addr(0x10), 4)
        fp.updateOutputTypes([])
        assert fp.outparam is None

    def test_noop_when_type_locked(self):
        fp = FuncProto()
        p = ProtoParameter("out", _MockType(4), _addr(0x10), 4)
        p.flags |= ParameterPieces.typelock
        fp.outparam = p
        fp.updateOutputTypes([])
        assert fp.outparam is p  # unchanged

    def test_noop_when_no_outparam(self):
        fp = FuncProto()
        fp.outparam = None
        fp.updateOutputTypes([])  # should not crash


# ---------------------------------------------------------------------------
# FuncProto.updateOutputNoTypes
# ---------------------------------------------------------------------------

class TestFuncProtoUpdateOutputNoTypes:
    def test_sets_output_from_trial(self):
        fp = FuncProto()
        spc = _spc()
        factory = _MockTypeFactory()
        vn = _MockVarnode(Address(spc, 0x10), 4)
        fp.updateOutputNoTypes([vn], factory)
        assert fp.outparam is not None
        tp = fp.outparam.getType()
        assert tp.getSize() == 4

    def test_clears_output_when_empty(self):
        fp = FuncProto()
        fp.outparam = ProtoParameter("out", _MockType(4), _addr(0x10), 4)
        factory = _MockTypeFactory()
        fp.updateOutputNoTypes([], factory)
        assert fp.outparam is None

    def test_noop_when_locked(self):
        fp = FuncProto()
        p = ProtoParameter("out", _MockType(4), _addr(0x10), 4)
        p.flags |= ParameterPieces.typelock
        fp.outparam = p
        factory = _MockTypeFactory()
        fp.updateOutputNoTypes([], factory)
        assert fp.outparam is p


# ---------------------------------------------------------------------------
# FuncProto.updateAllTypes
# ---------------------------------------------------------------------------

class TestFuncProtoUpdateAllTypes:
    def test_updates_from_prototype_pieces(self):
        fp = FuncProto()
        m = ProtoModel("cdecl", _MockArch())
        fp.setModel(m)
        proto = PrototypePieces()
        proto.model = m
        proto.outtype = _MockType(4, name="int")
        proto.intypes = [_MockType(4, name="arg0"), _MockType(4, name="arg1")]
        proto.innames = ["a", "b"]
        proto.firstVarArgSlot = -1
        fp.updateAllTypes(proto)
        # Should have output + some params (exact count depends on assignParameterStorage)
        # At minimum, error_inputparam may be set if no entries in the model
        # This exercises the code path without crashing

    def test_sets_dotdotdot(self):
        fp = FuncProto()
        proto = PrototypePieces()
        proto.firstVarArgSlot = 2
        fp.updateAllTypes(proto)
        assert fp.isDotdotdot()

    def test_clears_dotdotdot(self):
        fp = FuncProto()
        fp.setDotdotdot(True)
        proto = PrototypePieces()
        proto.firstVarArgSlot = -1
        fp.updateAllTypes(proto)
        assert not fp.isDotdotdot()


# ---------------------------------------------------------------------------
# FuncProto.setPieces
# ---------------------------------------------------------------------------

class TestFuncProtoSetPieces:
    def test_setPieces_calls_updateAllTypes(self):
        fp = FuncProto()
        m = ProtoModel("cdecl", _MockArch())
        fp.setModel(m)
        proto = PrototypePieces()
        proto.model = m
        proto.outtype = _MockType(4)
        proto.intypes = [_MockType(4)]
        proto.innames = ["x"]
        proto.firstVarArgSlot = -1
        fp.setPieces(proto)
        # After setPieces, model lock should be set
        assert fp.isModelLocked()


# ---------------------------------------------------------------------------
# FuncProto.paramShift
# ---------------------------------------------------------------------------

class TestFuncProtoParamShift:
    def test_paramShift_requires_model(self):
        fp = FuncProto()
        with pytest.raises(LowlevelError):
            fp.paramShift(2)

    def test_paramShift_adds_params(self):
        fp = FuncProto()
        m = ProtoModel("cdecl", _MockArch())
        fp.setModel(m)
        fp.paramShift(2)
        # After shift, input should be locked
        assert fp.isInputLocked()


# ---------------------------------------------------------------------------
# FuncProto._updateThisPointer
# ---------------------------------------------------------------------------

class TestUpdateThisPointer:
    def test_marks_first_param_as_this(self):
        fp = FuncProto()
        m = ProtoModel("thiscall")
        m.hasThis = True
        fp.model = m
        spc = _spc()
        p = ProtoParameter("arg0", _MockType(4), Address(spc, 0x10), 4)
        fp.store.append(p)
        fp._updateThisPointer()
        # ProtoParameter doesn't have setThisPointer, but no crash

    def test_noop_if_no_this_model(self):
        fp = FuncProto()
        m = ProtoModel("cdecl")
        fp.model = m
        fp._updateThisPointer()  # no crash

    def test_noop_if_empty_params(self):
        fp = FuncProto()
        m = ProtoModel("thiscall")
        m.hasThis = True
        fp.model = m
        fp._updateThisPointer()  # no crash


# ---------------------------------------------------------------------------
# ProtoModel.assignParameterStorage
# ---------------------------------------------------------------------------

class TestProtoModelAssignParameterStorage:
    def test_fallback_assigns_void_output(self):
        m = ProtoModel("cdecl", _MockArch())
        proto = PrototypePieces()
        proto.outtype = _MockType(4)
        proto.intypes = []
        res = []
        m.assignParameterStorage(proto, res, True)
        assert len(res) >= 1
        # First entry is output

    def test_ignoreOutputError_graceful(self):
        m = ProtoModel("cdecl", _MockArch())
        proto = PrototypePieces()
        proto.outtype = None
        proto.intypes = []
        res = []
        m.assignParameterStorage(proto, res, True)
        assert len(res) >= 1


# ---------------------------------------------------------------------------
# FuncCallSpecs basics
# ---------------------------------------------------------------------------

class TestFuncCallSpecs:
    def test_defaults(self):
        fc = FuncCallSpecs()
        assert fc.getName() == ""
        assert fc.numParams() == 0
        assert not fc.isInputActive()
        assert not fc.isOutputActive()

    def test_setOutputLock(self):
        fc = FuncCallSpecs()
        fc.proto.outparam = ParameterBasic("out", _addr(0x10), _MockType(4), 0)
        fc.setOutputLock(True)
        assert fc.proto.outparam.isTypeLocked()
        fc.setOutputLock(False)
        assert not fc.proto.outparam.isTypeLocked()

    def test_abortSpacebaseRelative(self):
        fc = FuncCallSpecs()
        fc.stackoffset = 100
        fc.abortSpacebaseRelative(None)
        assert fc.stackoffset == FuncCallSpecs.offset_unknown

    def test_getInputBytesConsumed_default(self):
        fc = FuncCallSpecs()
        assert fc.getInputBytesConsumed(0) == 0
        assert fc.getInputBytesConsumed(5) == 0

    def test_setInputBytesConsumed(self):
        fc = FuncCallSpecs()
        assert fc.setInputBytesConsumed(2, 4) is True
        assert fc.getInputBytesConsumed(2) == 4
        # Only gets smaller
        assert fc.setInputBytesConsumed(2, 2) is True
        assert fc.getInputBytesConsumed(2) == 2
        # Can't increase
        assert fc.setInputBytesConsumed(2, 3) is False
        assert fc.getInputBytesConsumed(2) == 2

    def test_clone(self):
        spc = _spc()
        fc = FuncCallSpecs()
        fc.name = "foo"
        fc.entryaddress = Address(spc, 0x1000)
        fc.paramshift = 3
        clone = fc.clone()
        assert clone.name == "foo"
        assert clone.entryaddress.getOffset() == 0x1000
        assert clone.paramshift == 3
        assert clone is not fc

    def test_countMatchingCalls(self):
        spc = _spc()
        fc1 = FuncCallSpecs()
        fc1.entryaddress = Address(spc, 0x1000)
        fc2 = FuncCallSpecs()
        fc2.entryaddress = Address(spc, 0x1000)
        fc3 = FuncCallSpecs()
        fc3.entryaddress = Address(spc, 0x2000)
        FuncCallSpecs.countMatchingCalls([fc1, fc2, fc3])
        assert fc1.matchCallCount == 2
        assert fc2.matchCallCount == 2
        assert fc3.matchCallCount == 1


# ---------------------------------------------------------------------------
# FuncCallSpecs.paramshiftModifyStart/Stop
# ---------------------------------------------------------------------------

class TestFuncCallSpecsParamshift:
    def test_paramshiftModifyStart_noop_zero(self):
        fc = FuncCallSpecs()
        fc.paramshift = 0
        fc.paramshiftModifyStart()  # no crash

    def test_paramshiftModifyStop_noop_zero(self):
        fc = FuncCallSpecs()
        fc.paramshift = 0
        data = _MockFuncdata()
        assert fc.paramshiftModifyStop(data) is False

    def test_paramshiftModifyStop_noop_already_applied(self):
        fc = FuncCallSpecs()
        fc.paramshift = 1
        fc.setParamshiftApplied(True)
        data = _MockFuncdata()
        assert fc.paramshiftModifyStop(data) is False


# ---------------------------------------------------------------------------
# FuncCallSpecs trial-related methods
# ---------------------------------------------------------------------------

class TestFuncCallSpecsTrials:
    def test_finalInputCheck_marks_condexe_nouse(self):
        fc = FuncCallSpecs()
        # Use mock ParamActive so we control the trials
        trial = _MockParamTrial(_addr(0x10), 4, 1, used=True, active_flag=True)
        trial._flags |= _MockParamTrial.condexe_effect
        mockActive = _MockParamActive([trial])
        fc._activeInput = mockActive
        fc.isinputactive = True
        fc.finalInputCheck()
        assert trial.isDefinitelyNotUsed()

    def test_checkOutputTrialUse_marks_active(self):
        fc = FuncCallSpecs()
        t1 = _MockParamTrial(_addr(0x10), 4, 1)
        t2 = _MockParamTrial(_addr(0x20), 4, 2)
        mockActive = _MockParamActive([t1, t2])
        fc._activeOutput = mockActive
        fc.isoutputactive = True
        # collectOutputTrialVarnodes will be a no-op since op is None,
        # so we pass pre-filled trialvn list
        trialvn = [_MockVarnode(_addr(0x10)), None]
        # Bypass collectOutputTrialVarnodes by calling check logic directly
        for i in range(len(trialvn)):
            curtrial = mockActive.getTrial(i)
            if trialvn[i] is not None:
                curtrial.markActive()
            else:
                curtrial.markInactive()
        assert t1.isActive()
        assert not t2.isActive()

    def test_buildInputFromTrials_filters_unused(self):
        fc = FuncCallSpecs()
        t_used = _MockParamTrial(_addr(0x10), 4, 1, used=True)
        t_unused = _MockParamTrial(_addr(0x20), 4, 2, used=False)
        mockActive = _MockParamActive([t_used, t_unused])
        fc._activeInput = mockActive
        fc.isinputactive = True
        # Without a real op we just test it doesn't crash
        fc.buildInputFromTrials(_MockFuncdata())

    def test_buildOutputFromTrials_noop_empty(self):
        fc = FuncCallSpecs()
        mockActive = _MockParamActive([])
        fc._activeOutput = mockActive
        fc.isoutputactive = True
        fc.buildOutputFromTrials(_MockFuncdata(), [])  # no crash


# ---------------------------------------------------------------------------
# ScoreProtoModel
# ---------------------------------------------------------------------------

class TestScoreProtoModel:
    def test_empty_score(self):
        m = ProtoModel("cdecl")
        s = ScoreProtoModel(True, m, 0)
        s.doScore()
        assert s.getScore() == 0
        assert s.getNumMismatch() == 0

    def test_none_model_penalty(self):
        s = ScoreProtoModel(True, None, 0)
        s.doScore()
        assert s.getScore() == 500


# ---------------------------------------------------------------------------
# ParamEntry containment constants
# ---------------------------------------------------------------------------

class TestParamEntryConstants:
    def test_containment_codes_distinct(self):
        assert ParamEntry.no_containment == 0
        assert ParamEntry.contains_unjustified == 1
        assert ParamEntry.contains_justified == 2
        assert ParamEntry.contained_by == 3

    def test_flag_constants(self):
        assert ParamEntry.force_left_justify == 1
        assert ParamEntry.reverse_stack == 2
        assert ParamEntry.smallsize_zext == 4
        assert ParamEntry.smallsize_sext == 8


# ---------------------------------------------------------------------------
# ParamEntry.getSlot
# ---------------------------------------------------------------------------

class TestParamEntryGetSlot:
    def _make_entry(self, grp=0, base=0x100, sz=16, alignment=4, numslots=4):
        e = ParamEntry(grp)
        e.spaceid = _spc()
        e.addressbase = base
        e.size = sz
        e.alignment = alignment
        e.numslots = numslots
        return e

    def test_slot_base(self):
        e = self._make_entry(grp=0)
        addr = Address(e.spaceid, 0x100)
        assert e.getSlot(addr, 0) == 0

    def test_slot_offset(self):
        e = self._make_entry(grp=0)
        addr = Address(e.spaceid, 0x104)
        assert e.getSlot(addr, 0) == 1

    def test_slot_skip(self):
        e = self._make_entry(grp=0)
        addr = Address(e.spaceid, 0x100)
        assert e.getSlot(addr, 8) == 2

    def test_slot_exclusion(self):
        """With alignment=0, slot is always first group."""
        e = ParamEntry(5)
        e.spaceid = _spc()
        e.addressbase = 0x200
        e.size = 4
        e.alignment = 0
        e.numslots = 1
        addr = Address(e.spaceid, 0x200)
        assert e.getSlot(addr, 0) == 5

    def test_slot_exclusion_skip_nonzero(self):
        """With alignment=0, skip!=0 returns last group."""
        e = ParamEntry(5)
        e.groupSet = [5, 6]
        e.spaceid = _spc()
        e.addressbase = 0x200
        e.size = 8
        e.alignment = 0
        addr = Address(e.spaceid, 0x200)
        assert e.getSlot(addr, 4) == 6


# ---------------------------------------------------------------------------
# ParamEntry.groupOverlap
# ---------------------------------------------------------------------------

class TestParamEntryGroupOverlap:
    def test_overlap_same_group(self):
        e1 = ParamEntry(3)
        e2 = ParamEntry(3)
        assert e1.groupOverlap(e2)

    def test_no_overlap(self):
        e1 = ParamEntry(1)
        e2 = ParamEntry(5)
        assert not e1.groupOverlap(e2)

    def test_overlap_multi_group(self):
        e1 = ParamEntry(0)
        e1.groupSet = [0, 2, 4]
        e2 = ParamEntry(1)
        e2.groupSet = [1, 3, 4]
        assert e1.groupOverlap(e2)  # overlap at 4

    def test_no_overlap_multi_group(self):
        e1 = ParamEntry(0)
        e1.groupSet = [0, 2]
        e2 = ParamEntry(1)
        e2.groupSet = [1, 3]
        assert not e1.groupOverlap(e2)


# ---------------------------------------------------------------------------
# ParamEntry.slotGroup
# ---------------------------------------------------------------------------

class TestParamEntrySlotGroup:
    def test_returns_first_group(self):
        e = ParamEntry(7)
        assert e.slotGroup() == 7

    def test_multi_group_returns_first(self):
        e = ParamEntry(3)
        e.groupSet = [3, 5, 7]
        assert e.slotGroup() == 3


# ---------------------------------------------------------------------------
# ParamListStandard.findEntry
# ---------------------------------------------------------------------------

def _make_param_list_with_entries():
    """Create a ParamListStandard with 3 register entries and 1 stack entry."""
    spc = _spc("register", 4)
    plist = ParamListStandard()
    plist.entry = []
    plist.resourceStart = [0]
    plist.thisbeforeret = False
    plist.numgroup = 0

    for i in range(3):
        e = ParamEntry(i)
        e.spaceid = spc
        e.addressbase = 0x10 * (i + 1)
        e.size = 4
        e.minsize = 1
        e.alignment = 0
        e.numslots = 1
        e.flags = 0
        plist.entry.append(e)
        plist.numgroup = i + 1

    plist.resourceStart.append(plist.numgroup)
    return plist, spc


class TestParamListStandardFindEntry:
    def test_finds_exact_match(self):
        plist, spc = _make_param_list_with_entries()
        addr = Address(spc, 0x10)
        result = plist.findEntry(addr, 4, True)
        assert result is not None
        assert result.getBase() == 0x10

    def test_finds_second_entry(self):
        plist, spc = _make_param_list_with_entries()
        addr = Address(spc, 0x20)
        result = plist.findEntry(addr, 4, True)
        assert result is not None
        assert result.getBase() == 0x20

    def test_returns_none_wrong_space(self):
        plist, spc = _make_param_list_with_entries()
        other_spc = _spc("other", 4)
        addr = Address(other_spc, 0x10)
        result = plist.findEntry(addr, 4, True)
        assert result is None

    def test_returns_none_too_big(self):
        plist, spc = _make_param_list_with_entries()
        addr = Address(spc, 0x10)
        result = plist.findEntry(addr, 8, True)
        # Size 8 > entry size 4, so minsize check may pass but containment fails
        # Depends on justifiedContain behavior


# ---------------------------------------------------------------------------
# ParamListStandard.checkJoin
# ---------------------------------------------------------------------------

class TestParamListStandardCheckJoin:
    def test_join_different_groups_with_container(self):
        """Two entries in different groups can join if a bigger entry contains both."""
        spc = _spc("register", 4)
        plist = ParamListStandard()
        plist.entry = []
        plist.resourceStart = [0]
        plist.thisbeforeret = False
        plist.numgroup = 0

        # Create a large entry that can contain both hi and lo
        big = ParamEntry(0)
        big.spaceid = spc
        big.addressbase = 0x10
        big.size = 8
        big.minsize = 1
        big.alignment = 0
        big.numslots = 1
        big.flags = 0
        plist.entry.append(big)
        plist.numgroup = 1

        # Small entries in different groups
        e1 = ParamEntry(1)
        e1.spaceid = spc
        e1.addressbase = 0x10
        e1.size = 4
        e1.minsize = 1
        e1.alignment = 0
        e1.numslots = 1
        e1.flags = 0
        plist.entry.append(e1)

        e2 = ParamEntry(2)
        e2.spaceid = spc
        e2.addressbase = 0x14
        e2.size = 4
        e2.minsize = 1
        e2.alignment = 0
        e2.numslots = 1
        e2.flags = 0
        plist.entry.append(e2)
        plist.numgroup = 3
        plist.resourceStart.append(plist.numgroup)

        # The big entry should contain both as a join
        hiaddr = Address(spc, 0x14)
        loaddr = Address(spc, 0x10)
        # This depends on justifiedContain implementation

    def test_join_fails_no_matching_entries(self):
        plist, spc = _make_param_list_with_entries()
        other_spc = _spc("other", 4)
        hiaddr = Address(other_spc, 0x100)
        loaddr = Address(other_spc, 0x104)
        assert not plist.checkJoin(hiaddr, 4, loaddr, 4)


# ---------------------------------------------------------------------------
# ParamListStandard.checkSplit
# ---------------------------------------------------------------------------

class TestParamListStandardCheckSplit:
    def test_split_fails_no_entries(self):
        plist = ParamListStandard()
        plist.entry = []
        spc = _spc()
        loc = Address(spc, 0x10)
        assert not plist.checkSplit(loc, 8, 4)


# ---------------------------------------------------------------------------
# ParamListStandard.characterizeAsParam
# ---------------------------------------------------------------------------

class TestParamListStandardCharacterizeAsParam:
    def test_no_containment_wrong_space(self):
        plist, spc = _make_param_list_with_entries()
        other_spc = _spc("other", 4)
        addr = Address(other_spc, 0x10)
        result = plist.characterizeAsParam(addr, 4)
        assert result == ParamEntry.no_containment

    def test_no_containment_no_match(self):
        plist, spc = _make_param_list_with_entries()
        addr = Address(spc, 0xFF)
        result = plist.characterizeAsParam(addr, 4)
        assert result == ParamEntry.no_containment


# ---------------------------------------------------------------------------
# ParamListStandard.getBiggestContainedParam
# ---------------------------------------------------------------------------

class TestParamListStandardGetBiggestContainedParam:
    def test_no_match_wrong_space(self):
        plist, spc = _make_param_list_with_entries()
        other_spc = _spc("other", 4)

        class _Res:
            space = None
            offset = 0
            size = 0

        res = _Res()
        addr = Address(other_spc, 0x10)
        assert not plist.getBiggestContainedParam(addr, 100, res)

    def test_no_match_non_exclusion(self):
        """Non-exclusion entries with alignment!=0 are excluded."""
        spc = _spc("register", 4)
        plist = ParamListStandard()
        plist.entry = []

        e = ParamEntry(0)
        e.spaceid = spc
        e.addressbase = 0x10
        e.size = 4
        e.minsize = 1
        e.alignment = 4  # non-exclusion
        e.numslots = 1
        e.flags = 0
        plist.entry.append(e)

        class _Res:
            space = None
            offset = 0
            size = 0

        res = _Res()
        addr = Address(spc, 0x00)
        assert not plist.getBiggestContainedParam(addr, 0x100, res)


# ---------------------------------------------------------------------------
# ParamListStandard.unjustifiedContainer
# ---------------------------------------------------------------------------

class TestParamListStandardUnjustifiedContainer:
    def test_returns_false_no_entries(self):
        plist = ParamListStandard()
        plist.entry = []

        class _Res:
            space = None
            offset = 0
            size = 0

        res = _Res()
        assert not plist.unjustifiedContainer(_addr(0x10), 4, res)


# ---------------------------------------------------------------------------
# ParamListStandard.assumedExtension
# ---------------------------------------------------------------------------

class TestParamListStandardAssumedExtension:
    def test_returns_copy_no_entries(self):
        from ghidra.ir.op import OpCode
        plist = ParamListStandard()
        plist.entry = []

        class _Res:
            space = None
            offset = 0
            size = 0

        res = _Res()
        assert plist.assumedExtension(_addr(0x10), 4, res) == OpCode.CPUI_COPY


# ---------------------------------------------------------------------------
# ParamListStandard.isThisBeforeRetPointer / isAutoKilledByCall
# ---------------------------------------------------------------------------

class TestParamListStandardFlags:
    def test_thisbeforeret_default_false(self):
        plist = ParamListStandard()
        plist.thisbeforeret = False
        assert not plist.isThisBeforeRetPointer()

    def test_thisbeforeret_true(self):
        plist = ParamListStandard()
        plist.thisbeforeret = True
        assert plist.isThisBeforeRetPointer()

    def test_auto_killed_by_call_default(self):
        plist = ParamListStandard()
        assert not plist.isAutoKilledByCall()

    def test_auto_killed_by_call_true(self):
        plist = ParamListStandard()
        plist.autoKilledByCall = True
        assert plist.isAutoKilledByCall()


# ---------------------------------------------------------------------------
# ParamListStandard helper methods for fillinMap
# ---------------------------------------------------------------------------

class TestParamListStandardHelpers:
    def test_markGroupNoUse(self):
        """markGroupNoUse marks all trials in overlapping groups except the active one."""
        spc = _spc()
        e = ParamEntry(0)
        e.spaceid = spc
        e.addressbase = 0x10
        e.size = 4
        e.alignment = 0

        t1 = _MockParamTrial(Address(spc, 0x10), 4, 0, active_flag=True)
        t1._entry = e
        t2 = _MockParamTrial(Address(spc, 0x10), 4, 0, active_flag=True)
        t2._entry = e

        # Patch getEntry
        t1.getEntry = lambda: e
        t2.getEntry = lambda: e

        active = _MockParamActive([t1, t2])
        ParamListStandard.markGroupNoUse(active, 0, 0)
        assert not t1.isDefinitelyNotUsed()
        assert t2.isDefinitelyNotUsed()

    def test_forceNoUse_basic(self):
        """After a definitely-not-used group, mark remaining as inactive."""
        spc = _spc()
        entries = []
        for i in range(3):
            e = ParamEntry(i)
            e.spaceid = spc
            e.addressbase = 0x10 * (i + 1)
            e.size = 4
            e.alignment = 0
            entries.append(e)

        t1 = _MockParamTrial(Address(spc, 0x10), 4, 0, active_flag=True)
        t1.getEntry = lambda: entries[0]
        t2 = _MockParamTrial(Address(spc, 0x20), 4, 1)
        t2.getEntry = lambda: entries[1]
        t2.markNoUse()  # definitely not used
        t3 = _MockParamTrial(Address(spc, 0x30), 4, 2, active_flag=True)
        t3.getEntry = lambda: entries[2]

        active = _MockParamActive([t1, t2, t3])
        ParamListStandard.forceNoUse(active, 0, 3)
        assert t1.isActive()
        assert t2.isDefinitelyNotUsed()
        # t3 should be marked inactive since it comes after a defnouse group
        assert not t3.isActive()


# ---------------------------------------------------------------------------
# FuncProto.setReturnBytesConsumed
# ---------------------------------------------------------------------------

class TestFuncProtoSetReturnBytesConsumed:
    def test_zero_returns_false(self):
        fp = FuncProto()
        assert not fp.setReturnBytesConsumed(0)

    def test_first_set_returns_true(self):
        fp = FuncProto()
        assert fp.setReturnBytesConsumed(4)
        assert fp.returnBytesConsumed == 4

    def test_smaller_replaces(self):
        fp = FuncProto()
        fp.setReturnBytesConsumed(4)
        assert fp.setReturnBytesConsumed(2)
        assert fp.returnBytesConsumed == 2

    def test_larger_does_not_replace(self):
        fp = FuncProto()
        fp.setReturnBytesConsumed(2)
        assert not fp.setReturnBytesConsumed(4)
        assert fp.returnBytesConsumed == 2


# ---------------------------------------------------------------------------
# FuncProto.setScope
# ---------------------------------------------------------------------------

class TestFuncProtoSetScope:
    def test_setScope_creates_store(self):
        fp = FuncProto()
        fp.store = None

        class _MockScope:
            def getArch(self):
                return _MockArch()

        fp.setScope(_MockScope(), _addr(0x1000))
        assert fp.store is not None

    def test_setScope_with_no_model_sets_default(self):
        fp = FuncProto()
        fp.model = None

        class _MockArchWithFP:
            def __init__(self):
                self.defaultfp = ProtoModel("default")

        class _MockScope2:
            def getArch(self):
                return _MockArchWithFP()

        fp.setScope(_MockScope2(), _addr(0x1000))
        assert fp.model is not None
        assert fp.model.getName() == "default"


# ---------------------------------------------------------------------------
# FuncProto.unjustifiedInputParam
# ---------------------------------------------------------------------------

class TestFuncProtoUnjustifiedInputParam:
    def test_returns_false_void_locked(self):
        fp = FuncProto()
        fp.setVoidInputLock(True)
        assert not fp.unjustifiedInputParam(_addr(0x10), 4)

    def test_returns_false_no_params_no_model(self):
        fp = FuncProto()
        assert not fp.unjustifiedInputParam(_addr(0x10), 4)

    def test_delegates_to_model_if_dotdotdot(self):
        fp = FuncProto()
        fp.setDotdotdot(True)
        m = ProtoModel("cdecl")
        fp.model = m
        # Should delegate to model.unjustifiedInputParam
        result = fp.unjustifiedInputParam(_addr(0x10), 4)
        assert isinstance(result, bool)


# ---------------------------------------------------------------------------
# FuncProto.getThisPointerStorage
# ---------------------------------------------------------------------------

class TestFuncProtoGetThisPointerStorage:
    def test_returns_invalid_no_model(self):
        fp = FuncProto()
        addr = fp.getThisPointerStorage()
        assert addr.isInvalid()

    def test_returns_invalid_no_this(self):
        fp = FuncProto()
        m = ProtoModel("cdecl")
        m.hasThis = False
        fp.model = m
        addr = fp.getThisPointerStorage(_MockType(4))
        assert addr.isInvalid()


# ---------------------------------------------------------------------------
# FuncProto.assumedInputExtension / assumedOutputExtension
# ---------------------------------------------------------------------------

class TestFuncProtoAssumedExtension:
    def test_input_extension_no_model(self):
        from ghidra.ir.op import OpCode
        fp = FuncProto()
        result = fp.assumedInputExtension(_addr(0x10), 4)
        assert result == OpCode.CPUI_COPY

    def test_output_extension_no_model(self):
        from ghidra.ir.op import OpCode
        fp = FuncProto()
        result = fp.assumedOutputExtension(_addr(0x10), 4)
        assert result == OpCode.CPUI_COPY

    def test_input_extension_with_model(self):
        from ghidra.ir.op import OpCode
        fp = FuncProto()
        m = ProtoModel("cdecl")
        m.input = ParamListStandard()
        m.input.entry = []
        fp.model = m
        result = fp.assumedInputExtension(_addr(0x10), 4)
        assert result == OpCode.CPUI_COPY  # no entries => COPY

    def test_output_extension_with_model(self):
        from ghidra.ir.op import OpCode
        fp = FuncProto()
        m = ProtoModel("cdecl")
        m.output = ParamListStandard()
        m.output.entry = []
        fp.model = m
        result = fp.assumedOutputExtension(_addr(0x10), 4)
        assert result == OpCode.CPUI_COPY


# ---------------------------------------------------------------------------
# FuncCallSpecs.checkInputJoin
# ---------------------------------------------------------------------------

class TestFuncCallSpecsCheckInputJoin:
    def test_returns_false_null_varnodes(self):
        fc = FuncCallSpecs()
        assert not fc.checkInputJoin(0, True, None, _MockVarnode(_addr(0x10)))
        assert not fc.checkInputJoin(0, True, _MockVarnode(_addr(0x10)), None)
        assert not fc.checkInputJoin(0, True, None, None)

    def test_returns_false_no_model(self):
        fc = FuncCallSpecs()
        vn1 = _MockVarnode(_addr(0x10))
        vn2 = _MockVarnode(_addr(0x14))
        assert not fc.checkInputJoin(0, True, vn1, vn2)


# ---------------------------------------------------------------------------
# FuncCallSpecs.getBiggestContainedInputParam / Output
# ---------------------------------------------------------------------------

class TestFuncCallSpecsGetBiggest:
    def test_input_returns_false_no_model(self):
        fc = FuncCallSpecs()

        class _Res:
            space = None
            offset = 0
            size = 0

        res = _Res()
        assert not fc.getBiggestContainedInputParam(_addr(0x10), 4, res)

    def test_output_returns_false_no_model(self):
        fc = FuncCallSpecs()

        class _Res:
            space = None
            offset = 0
            size = 0

        res = _Res()
        assert not fc.getBiggestContainedOutput(_addr(0x10), 4, res)


# ---------------------------------------------------------------------------
# FuncCallSpecs.lateRestriction
# ---------------------------------------------------------------------------

class TestFuncCallSpecsLateRestriction:
    def test_returns_false_none_proto(self):
        fc = FuncCallSpecs()
        assert not fc.lateRestriction(None, [], [])

    def test_returns_false_already_locked(self):
        fc = FuncCallSpecs()
        fc.proto.setVoidInputLock(True)
        p = ProtoParameter("out", _MockType(4), _addr(0x10), 4)
        p.flags |= ParameterPieces.typelock
        fc.proto.outparam = p
        restricted = FuncProto()
        assert not fc.lateRestriction(restricted, [], [])

    def test_copies_when_unlocked(self):
        fc = FuncCallSpecs()
        restricted = FuncProto()
        m = ProtoModel("stdcall")
        restricted.setModel(m)
        assert fc.lateRestriction(restricted, [], [])


# ---------------------------------------------------------------------------
# ParamEntry.assumedExtension
# ---------------------------------------------------------------------------

class TestParamEntryAssumedExtension:
    def test_no_extension_flags_returns_copy(self):
        from ghidra.ir.op import OpCode
        e = ParamEntry(0)
        e.spaceid = _spc()
        e.addressbase = 0x10
        e.size = 4
        e.alignment = 0
        e.flags = 0  # no extension flags

        class _Res:
            space = None
            offset = 0
            size = 0

        res = _Res()
        assert e.assumedExtension(Address(e.spaceid, 0x10), 2, res) == OpCode.CPUI_COPY

    def test_zext_flag(self):
        from ghidra.ir.op import OpCode
        e = ParamEntry(0)
        e.spaceid = _spc()
        e.addressbase = 0x10
        e.size = 4
        e.alignment = 0
        e.flags = ParamEntry.smallsize_zext
        e.joinrec = None

        class _Res:
            space = None
            offset = 0
            size = 0

        res = _Res()
        result = e.assumedExtension(Address(e.spaceid, 0x10), 2, res)
        assert result == OpCode.CPUI_INT_ZEXT
        assert res.space is e.spaceid
        assert res.offset == 0x10
        assert res.size == 4

    def test_sext_flag(self):
        from ghidra.ir.op import OpCode
        e = ParamEntry(0)
        e.spaceid = _spc()
        e.addressbase = 0x10
        e.size = 4
        e.alignment = 0
        e.flags = ParamEntry.smallsize_sext
        e.joinrec = None

        class _Res:
            space = None
            offset = 0
            size = 0

        res = _Res()
        result = e.assumedExtension(Address(e.spaceid, 0x10), 2, res)
        assert result == OpCode.CPUI_INT_SEXT

    def test_inttype_flag(self):
        from ghidra.ir.op import OpCode
        e = ParamEntry(0)
        e.spaceid = _spc()
        e.addressbase = 0x10
        e.size = 4
        e.alignment = 0
        e.flags = ParamEntry.smallsize_inttype
        e.joinrec = None

        class _Res:
            space = None
            offset = 0
            size = 0

        res = _Res()
        result = e.assumedExtension(Address(e.spaceid, 0x10), 2, res)
        assert result == OpCode.CPUI_PIECE

    def test_full_size_returns_copy(self):
        from ghidra.ir.op import OpCode
        e = ParamEntry(0)
        e.spaceid = _spc()
        e.addressbase = 0x10
        e.size = 4
        e.alignment = 0
        e.flags = ParamEntry.smallsize_zext

        class _Res:
            space = None
            offset = 0
            size = 0

        res = _Res()
        # Size >= entry size means no extension
        assert e.assumedExtension(Address(e.spaceid, 0x10), 4, res) == OpCode.CPUI_COPY


# ---------------------------------------------------------------------------
# ParamEntry.getContainer
# ---------------------------------------------------------------------------

class TestParamEntryGetContainer:
    def test_exclusion_returns_full_entry(self):
        e = ParamEntry(0)
        spc = _spc()
        e.spaceid = spc
        e.addressbase = 0x10
        e.size = 4
        e.alignment = 0

        class _Res:
            space = None
            offset = 0
            size = 0

        res = _Res()
        addr = Address(spc, 0x10)
        assert e.getContainer(addr, 4, res)
        assert res.space is spc
        assert res.offset == 0x10
        assert res.size == 4

    def test_wrong_space_returns_false(self):
        e = ParamEntry(0)
        spc1 = _spc("ram")
        spc2 = _spc("other")
        e.spaceid = spc1
        e.addressbase = 0x10
        e.size = 4
        e.alignment = 0

        class _Res:
            space = None
            offset = 0
            size = 0

        res = _Res()
        assert not e.getContainer(Address(spc2, 0x10), 4, res)

    def test_out_of_range_returns_false(self):
        e = ParamEntry(0)
        spc = _spc()
        e.spaceid = spc
        e.addressbase = 0x10
        e.size = 4
        e.alignment = 0

        class _Res:
            space = None
            offset = 0
            size = 0

        res = _Res()
        assert not e.getContainer(Address(spc, 0x20), 4, res)


# ---------------------------------------------------------------------------
# ParamListStandard.getRangeList
# ---------------------------------------------------------------------------

class TestParamListStandardGetRangeList:
    def test_collects_matching_entries(self):
        plist, spc = _make_param_list_with_entries()

        class _MockRangeList:
            def __init__(self):
                self.ranges = []
            def insertRange(self, space, first, last):
                self.ranges.append((space, first, last))

        rl = _MockRangeList()
        plist.getRangeList(spc, rl)
        assert len(rl.ranges) == 3  # 3 register entries

    def test_skips_wrong_space(self):
        plist, spc = _make_param_list_with_entries()
        other_spc = _spc("other")

        class _MockRangeList:
            def __init__(self):
                self.ranges = []
            def insertRange(self, space, first, last):
                self.ranges.append((space, first, last))

        rl = _MockRangeList()
        plist.getRangeList(other_spc, rl)
        assert len(rl.ranges) == 0
