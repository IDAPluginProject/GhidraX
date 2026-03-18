"""Tests for ghidra.fspec.modelrules – Python port of modelrules.cc."""
from __future__ import annotations

import pytest
import sys, os

sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', 'python'))

from ghidra.core.address import Address, AddrSpace
from ghidra.types.datatype import (
    MetaType, TypeClass,
    TYPE_INT, TYPE_UINT, TYPE_FLOAT, TYPE_STRUCT, TYPE_ARRAY,
    TYPE_UNKNOWN, TYPE_VOID, TYPE_PTR, TYPE_UNION, TYPE_BOOL, TYPE_CODE,
    TYPECLASS_GENERAL, TYPECLASS_FLOAT, TYPECLASS_PTR,
    string2typeclass, metatype2typeclass, string2metatype,
)
from ghidra.fspec.modelrules import (
    Primitive, PrimitiveExtractor,
    DatatypeFilter, SizeRestrictedFilter, MetaTypeFilter, HomogeneousAggregate,
    QualifierFilter, AndFilter, VarargsFilter, PositionMatchFilter,
    DatatypeMatchFilter,
    AssignAction, GotoStack, ConvertToPointer, MultiSlotAssign,
    MultiMemberAssign, MultiSlotDualAssign, ConsumeAs,
    HiddenReturnAssign, ConsumeExtra, ExtraStack, ConsumeRemaining,
    ModelRule,
)
from ghidra.fspec.fspec import ParamEntry, ParamListStandard, ParameterPieces, PrototypePieces


# =========================================================================
# Helpers – minimal Datatype stubs
# =========================================================================

class StubDatatype:
    """Minimal Datatype stub for testing."""
    def __init__(self, size: int, meta: MetaType = TYPE_INT,
                 align: int = 0, name: str = "stub"):
        self._size = size
        self._meta = meta
        self._align = align if align > 0 else size
        self._name = name

    def getSize(self) -> int:
        return self._size

    def getAlignSize(self) -> int:
        return self._align

    def getAlignment(self) -> int:
        return self._align

    def getMetatype(self) -> MetaType:
        return self._meta

    def getName(self) -> str:
        return self._name

    def numDepend(self) -> int:
        return 0

    def numElements(self) -> int:
        return 0

    def getFields(self):
        return []


class StubField:
    def __init__(self, tp, offset: int):
        self.type = tp
        self.offset = offset


class StubStructDatatype(StubDatatype):
    def __init__(self, size: int, fields: list):
        super().__init__(size, TYPE_STRUCT)
        self._fields = fields

    def getFields(self):
        return self._fields


class StubArrayDatatype(StubDatatype):
    def __init__(self, base, numEls: int):
        super().__init__(base.getSize() * numEls, TYPE_ARRAY)
        self._base = base
        self._numEls = numEls

    def numElements(self) -> int:
        return self._numEls

    def getBase(self):
        return self._base


class StubUnionDatatype(StubDatatype):
    def __init__(self, size: int, fields: list):
        super().__init__(size, TYPE_UNION)
        self._fields = fields

    def numDepend(self) -> int:
        return len(self._fields)

    def getField(self, i: int):
        return self._fields[i]


def _make_space(name: str = "ram", size: int = 4, big_endian: bool = False) -> AddrSpace:
    spc = AddrSpace.__new__(AddrSpace)
    spc._name = name
    spc._size = size
    spc._wordsize = 1
    spc._index = 1
    spc._type = 1  # IPTR_PROCESSOR
    spc._flags = AddrSpace.big_endian if big_endian else 0
    spc._delay = 0
    spc._deadcodedelay = 0
    return spc


def _make_param_list(entries=None, big_endian=False) -> ParamListStandard:
    """Build a minimal ParamListStandard with given entries."""
    pl = ParamListStandard()
    spc = _make_space(big_endian=big_endian)
    for e in (entries or []):
        pe = ParamEntry(group=e.get('group', 0))
        pe.spaceid = spc
        pe.addressbase = e.get('base', 0)
        pe.size = e.get('size', 4)
        pe.minsize = e.get('minsize', 1)
        pe.alignment = e.get('alignment', 0)  # 0 = exclusion (register)
        pe.type = e.get('type', TYPECLASS_GENERAL)
        if e.get('first', False):
            pe.flags |= ParamEntry.first_storage
        pl.addEntry(pe)
    pl.spacebase = spc
    return pl


# =========================================================================
# PrimitiveExtractor tests
# =========================================================================

class TestPrimitiveExtractor:
    def test_primitive_int(self):
        dt = StubDatatype(4, TYPE_INT)
        pe = PrimitiveExtractor(dt, False)
        assert pe.isValid()
        assert pe.size() == 1
        assert pe.get(0).dt is dt
        assert pe.get(0).offset == 0

    def test_primitive_float(self):
        dt = StubDatatype(8, TYPE_FLOAT)
        pe = PrimitiveExtractor(dt, False)
        assert pe.isValid()
        assert pe.size() == 1

    def test_struct_two_fields(self):
        f1 = StubDatatype(4, TYPE_INT)
        f2 = StubDatatype(4, TYPE_FLOAT)
        dt = StubStructDatatype(8, [StubField(f1, 0), StubField(f2, 4)])
        pe = PrimitiveExtractor(dt, False)
        assert pe.isValid()
        assert pe.size() == 2
        assert pe.get(0).dt is f1
        assert pe.get(0).offset == 0
        assert pe.get(1).dt is f2
        assert pe.get(1).offset == 4

    def test_array(self):
        base = StubDatatype(4, TYPE_FLOAT)
        dt = StubArrayDatatype(base, 3)
        pe = PrimitiveExtractor(dt, False)
        assert pe.isValid()
        assert pe.size() == 3
        for i in range(3):
            assert pe.get(i).offset == i * 4

    def test_void_invalid(self):
        dt = StubDatatype(0, TYPE_VOID)
        pe = PrimitiveExtractor(dt, False)
        assert not pe.isValid()

    def test_max_exceeded(self):
        dt = StubDatatype(4, TYPE_INT)
        pe = PrimitiveExtractor(dt, False, maxPrimitives=0)
        assert not pe.isValid()

    def test_unknown_flagged(self):
        dt = StubDatatype(4, TYPE_UNKNOWN)
        pe = PrimitiveExtractor(dt, False)
        assert pe.isValid()
        assert pe.containsUnknown()


# =========================================================================
# DatatypeFilter tests
# =========================================================================

class TestSizeRestrictedFilter:
    def test_no_restriction(self):
        f = SizeRestrictedFilter()
        assert f.filter(StubDatatype(4))
        assert f.filter(StubDatatype(100))

    def test_min_max(self):
        f = SizeRestrictedFilter(2, 8)
        assert f.filter(StubDatatype(4))
        assert not f.filter(StubDatatype(1))
        assert not f.filter(StubDatatype(16))

    def test_size_list(self):
        f = SizeRestrictedFilter()
        f._initFromSizeList("4, 8, 16")
        assert f.filter(StubDatatype(4))
        assert f.filter(StubDatatype(8))
        assert not f.filter(StubDatatype(3))

    def test_clone(self):
        f = SizeRestrictedFilter(1, 8)
        c = f.clone()
        assert c.minSize == 1
        assert c.maxSize == 8
        assert c is not f


class TestMetaTypeFilter:
    def test_matching(self):
        f = MetaTypeFilter(TYPE_INT)
        assert f.filter(StubDatatype(4, TYPE_INT))
        assert not f.filter(StubDatatype(4, TYPE_FLOAT))

    def test_with_size(self):
        f = MetaTypeFilter(TYPE_FLOAT, minSize=4, maxSize=8)
        assert f.filter(StubDatatype(4, TYPE_FLOAT))
        assert f.filter(StubDatatype(8, TYPE_FLOAT))
        assert not f.filter(StubDatatype(16, TYPE_FLOAT))

    def test_clone(self):
        f = MetaTypeFilter(TYPE_FLOAT, 2, 16)
        c = f.clone()
        assert c.metaType == TYPE_FLOAT
        assert c.minSize == 2


class TestHomogeneousAggregate:
    def test_float_array(self):
        f = HomogeneousAggregate(TYPE_FLOAT, maxPrim=4)
        base = StubDatatype(4, TYPE_FLOAT)
        dt = StubArrayDatatype(base, 3)
        assert f.filter(dt)

    def test_mixed_struct_rejected(self):
        f = HomogeneousAggregate(TYPE_FLOAT, maxPrim=4)
        f1 = StubDatatype(4, TYPE_FLOAT)
        f2 = StubDatatype(4, TYPE_INT)
        dt = StubStructDatatype(8, [StubField(f1, 0), StubField(f2, 4)])
        assert not f.filter(dt)

    def test_plain_int_rejected(self):
        f = HomogeneousAggregate(TYPE_FLOAT)
        assert not f.filter(StubDatatype(4, TYPE_INT))


# =========================================================================
# QualifierFilter tests
# =========================================================================

class TestVarargsFilter:
    def test_within_range(self):
        f = VarargsFilter(0, 10)
        proto = PrototypePieces()
        proto.firstVarArgSlot = 3
        assert f.filter(proto, 5)  # 5 - 3 = 2, in [0,10]
        assert not f.filter(proto, 2)  # 2 - 3 = -1, out of range

    def test_no_varargs(self):
        f = VarargsFilter()
        proto = PrototypePieces()
        proto.firstVarArgSlot = -1
        assert not f.filter(proto, 0)


class TestPositionMatchFilter:
    def test_match(self):
        f = PositionMatchFilter(2)
        proto = PrototypePieces()
        assert f.filter(proto, 2)
        assert not f.filter(proto, 0)

    def test_clone(self):
        f = PositionMatchFilter(5)
        c = f.clone()
        assert c.position == 5


class TestAndFilter:
    def test_all_pass(self):
        f = AndFilter([PositionMatchFilter(1), PositionMatchFilter(1)])
        proto = PrototypePieces()
        assert f.filter(proto, 1)

    def test_one_fails(self):
        f = AndFilter([PositionMatchFilter(1), PositionMatchFilter(2)])
        proto = PrototypePieces()
        assert not f.filter(proto, 1)


class TestDatatypeMatchFilter:
    def test_input_match(self):
        f = DatatypeMatchFilter()
        f.position = 0
        f.typeFilter = MetaTypeFilter(TYPE_FLOAT)
        proto = PrototypePieces()
        proto.intypes = [StubDatatype(4, TYPE_FLOAT)]
        proto.outtype = StubDatatype(4, TYPE_INT)
        assert f.filter(proto, 99)  # pos is ignored

    def test_output_match(self):
        f = DatatypeMatchFilter()
        f.position = -1
        f.typeFilter = MetaTypeFilter(TYPE_INT)
        proto = PrototypePieces()
        proto.outtype = StubDatatype(4, TYPE_INT)
        proto.intypes = []
        assert f.filter(proto, 0)


# =========================================================================
# string2typeclass / metatype2typeclass helpers
# =========================================================================

class TestTypeClassHelpers:
    def test_string2typeclass(self):
        assert string2typeclass("general") == TYPECLASS_GENERAL
        assert string2typeclass("float") == TYPECLASS_FLOAT
        assert string2typeclass("ptr") == TYPECLASS_PTR

    def test_metatype2typeclass(self):
        assert metatype2typeclass(TYPE_FLOAT) == TYPECLASS_FLOAT
        assert metatype2typeclass(TYPE_PTR) == TYPECLASS_PTR
        assert metatype2typeclass(TYPE_INT) == TYPECLASS_GENERAL


# =========================================================================
# AssignAction constants
# =========================================================================

class TestAssignActionConstants:
    def test_response_codes(self):
        assert AssignAction.success == 0
        assert AssignAction.fail == 1
        assert AssignAction.hiddenret_ptrparam == 3
        assert AssignAction.hiddenret_specialreg == 4


# =========================================================================
# GotoStack
# =========================================================================

class TestGotoStack:
    def test_basic_assign(self):
        pl = _make_param_list([
            {'group': 0, 'base': 0x100, 'size': 4, 'alignment': 4},  # stack entry
        ])
        gs = GotoStack(pl)
        dt = StubDatatype(4, TYPE_INT)
        proto = PrototypePieces()
        status = [0]
        res = ParameterPieces()
        code = gs.assignAddress(dt, proto, 0, None, status, res)
        assert code == AssignAction.success
        assert res.type is dt
        assert res.addr.getOffset() == 0x100


# =========================================================================
# ConsumeAs
# =========================================================================

class TestConsumeAs:
    def test_assign_from_register(self):
        pl = _make_param_list([
            {'group': 0, 'base': 0, 'size': 4, 'type': TYPECLASS_GENERAL,
             'first': True},
        ])
        ca = ConsumeAs(TYPECLASS_GENERAL, pl)
        dt = StubDatatype(4, TYPE_INT)
        proto = PrototypePieces()
        status = [0]
        res = ParameterPieces()
        code = ca.assignAddress(dt, proto, 0, None, status, res)
        assert code == AssignAction.success
        assert status[0] == -1  # consumed


# =========================================================================
# HiddenReturnAssign
# =========================================================================

class TestHiddenReturnAssign:
    def test_returns_code(self):
        pl = _make_param_list([])
        hra = HiddenReturnAssign(pl, AssignAction.hiddenret_specialreg)
        dt = StubDatatype(16)
        proto = PrototypePieces()
        res = ParameterPieces()
        code = hra.assignAddress(dt, proto, -1, None, [], res)
        assert code == AssignAction.hiddenret_specialreg


# =========================================================================
# ConsumeExtra
# =========================================================================

class TestConsumeExtra:
    def test_consume_matching_size(self):
        pl = _make_param_list([
            {'group': 0, 'base': 0, 'size': 4, 'type': TYPECLASS_GENERAL,
             'first': True},
            {'group': 1, 'base': 4, 'size': 4, 'type': TYPECLASS_GENERAL},
        ])
        ce = ConsumeExtra(pl, TYPECLASS_GENERAL, matchSize=True)
        ce._initializeEntries()
        dt = StubDatatype(8)
        proto = PrototypePieces()
        status = [0, 0]
        res = ParameterPieces()
        code = ce.assignAddress(dt, proto, 0, None, status, res)
        assert code == AssignAction.success
        assert status[0] == -1
        assert status[1] == -1


# =========================================================================
# ConsumeRemaining
# =========================================================================

class TestConsumeRemaining:
    def test_consumes_all(self):
        pl = _make_param_list([
            {'group': 0, 'base': 0, 'size': 4, 'type': TYPECLASS_GENERAL,
             'first': True},
            {'group': 1, 'base': 4, 'size': 4, 'type': TYPECLASS_GENERAL},
            {'group': 2, 'base': 8, 'size': 4, 'type': TYPECLASS_GENERAL},
        ])
        cr = ConsumeRemaining(pl, TYPECLASS_GENERAL)
        cr._initializeEntries()
        dt = StubDatatype(4)
        proto = PrototypePieces()
        status = [0, -1, 0]  # group 1 already consumed
        res = ParameterPieces()
        code = cr.assignAddress(dt, proto, 0, None, status, res)
        assert code == AssignAction.success
        assert status[0] == -1
        assert status[1] == -1  # unchanged
        assert status[2] == -1


# =========================================================================
# ModelRule
# =========================================================================

class TestModelRule:
    def test_filter_pass(self):
        rule = ModelRule()
        rule.filter = MetaTypeFilter(TYPE_INT)
        rule.assign = _StubAssignAction(AssignAction.success)
        proto = PrototypePieces()
        status = []
        res = ParameterPieces()
        code = rule.assignAddress(StubDatatype(4, TYPE_INT), proto, 0, None,
                                  status, res)
        assert code == AssignAction.success

    def test_filter_fail(self):
        rule = ModelRule()
        rule.filter = MetaTypeFilter(TYPE_FLOAT)
        rule.assign = _StubAssignAction(AssignAction.success)
        proto = PrototypePieces()
        code = rule.assignAddress(StubDatatype(4, TYPE_INT), proto, 0, None,
                                  [], ParameterPieces())
        assert code == AssignAction.fail

    def test_qualifier_fail(self):
        rule = ModelRule()
        rule.filter = SizeRestrictedFilter()  # passes everything
        rule.qualifier = PositionMatchFilter(5)
        rule.assign = _StubAssignAction(AssignAction.success)
        proto = PrototypePieces()
        code = rule.assignAddress(StubDatatype(4), proto, 0, None,
                                  [], ParameterPieces())
        assert code == AssignAction.fail

    def test_from_components(self):
        pl = _make_param_list([
            {'group': 0, 'base': 0, 'size': 4, 'type': TYPECLASS_GENERAL,
             'first': True},
        ])
        rule = ModelRule.fromComponents(
            MetaTypeFilter(TYPE_INT),
            ConsumeAs(TYPECLASS_GENERAL, pl),
            pl,
        )
        assert rule.filter is not None
        assert rule.assign is not None


class _StubAssignAction(AssignAction):
    """Stub for testing ModelRule without real resource lists."""
    def __init__(self, retcode: int):
        self.resource = None
        self.fillinOutputActive = False
        self._retcode = retcode

    def assignAddress(self, dt, proto, pos, tlist, status, res):
        return self._retcode

    def clone(self, newResource):
        return _StubAssignAction(self._retcode)


# =========================================================================
# ParamListStandard new methods
# =========================================================================

class TestParamListStandardNewMethods:
    def test_isBigEndian(self):
        pl = _make_param_list([], big_endian=True)
        # spacebase is set, so check its endianness
        assert pl.isBigEndian() == True

    def test_extractTiles(self):
        pl = _make_param_list([
            {'group': 0, 'base': 0, 'size': 4, 'alignment': 0,
             'type': TYPECLASS_GENERAL, 'first': True},
            {'group': 1, 'base': 0x100, 'size': 4, 'alignment': 4,
             'type': TYPECLASS_GENERAL},  # stack, not exclusion
            {'group': 2, 'base': 4, 'size': 4, 'alignment': 0,
             'type': TYPECLASS_FLOAT},
        ])
        tiles = []
        pl.extractTiles(tiles, TYPECLASS_GENERAL)
        assert len(tiles) == 1  # only group 0 is exclusion + GENERAL
        assert tiles[0].getGroup() == 0

    def test_getStackEntry(self):
        pl = _make_param_list([
            {'group': 0, 'base': 0, 'size': 4, 'alignment': 0},  # register
            {'group': 1, 'base': 0x100, 'size': 4, 'alignment': 4},  # stack
        ])
        se = pl.getStackEntry()
        assert se is not None
        assert se.getGroup() == 1

    def test_getStackEntry_none(self):
        pl = _make_param_list([
            {'group': 0, 'base': 0, 'size': 4, 'alignment': 0},
        ])
        assert pl.getStackEntry() is None

    def test_assignAddressFallback(self):
        pl = _make_param_list([
            {'group': 0, 'base': 0, 'size': 4, 'alignment': 0,
             'type': TYPECLASS_GENERAL, 'first': True},
        ])
        dt = StubDatatype(4, TYPE_INT)
        status = [0]
        res = ParameterPieces()
        code = pl.assignAddressFallback(TYPECLASS_GENERAL, dt, True, status, res)
        assert code == AssignAction.success
        assert status[0] == -1


# =========================================================================
# ParamEntry.getAddrBySlot
# =========================================================================

class TestParamEntryGetAddrBySlot:
    def test_exclusion_register(self):
        pe = ParamEntry(group=0)
        pe.spaceid = _make_space()
        pe.addressbase = 0x10
        pe.alignment = 0  # exclusion
        pe.size = 4
        addr = pe.getAddrBySlot(0, 4)
        assert addr.getOffset() == 0x10

    def test_stack_slot(self):
        pe = ParamEntry(group=0)
        pe.spaceid = _make_space()
        pe.addressbase = 0x100
        pe.alignment = 4
        pe.size = 256
        addr = pe.getAddrBySlot(0, 4)
        assert addr.getOffset() == 0x100
        addr2 = pe.getAddrBySlot(4, 4)
        assert addr2.getOffset() == 0x104


if __name__ == '__main__':
    pytest.main([__file__, '-v'])
