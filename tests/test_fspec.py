"""Tests for ghidra.fspec.fspec -- EffectRecord, ParameterPieces, ParameterBasic, ProtoStoreInternal."""
from __future__ import annotations

from ghidra.core.address import Address
from ghidra.core.space import AddrSpace
from ghidra.fspec.fspec import (
    EffectRecord, ParameterPieces, ParameterBasic,
    ProtoStoreInternal, PrototypePieces,
)


def _spc():
    return AddrSpace(name="ram", size=4)


def _addr(off):
    return Address(_spc(), off)


# ---------------------------------------------------------------------------
# EffectRecord
# ---------------------------------------------------------------------------

class TestEffectRecord:
    def test_defaults(self):
        er = EffectRecord()
        assert er.getType() == EffectRecord.unknown_effect
        assert er.getSize() == 0
        assert er.getAddress().isInvalid()

    def test_construction(self):
        er = EffectRecord(_addr(0x100), 4, EffectRecord.unaffected)
        assert er.getType() == EffectRecord.unaffected
        assert er.getAddress().getOffset() == 0x100
        assert er.getSize() == 4

    def test_type_constants(self):
        assert EffectRecord.unaffected == 1
        assert EffectRecord.killedbycall == 2
        assert EffectRecord.return_address == 3
        assert EffectRecord.unknown_effect == 4

    def test_set_type(self):
        er = EffectRecord()
        er.setType(EffectRecord.killedbycall)
        assert er.getType() == EffectRecord.killedbycall

    def test_equality(self):
        spc = _spc()
        a1 = Address(spc, 0x100)
        a2 = Address(spc, 0x100)
        er1 = EffectRecord(a1, 4, EffectRecord.unaffected)
        er2 = EffectRecord(a2, 4, EffectRecord.unaffected)
        assert er1 == er2

    def test_inequality(self):
        spc = _spc()
        er1 = EffectRecord(Address(spc, 0x100), 4, EffectRecord.unaffected)
        er2 = EffectRecord(Address(spc, 0x200), 4, EffectRecord.unaffected)
        assert er1 != er2


# ---------------------------------------------------------------------------
# ParameterPieces
# ---------------------------------------------------------------------------

class TestParameterPieces:
    def test_defaults(self):
        pp = ParameterPieces()
        assert pp.addr.isInvalid()
        assert pp.type is None
        assert pp.flags == 0

    def test_flag_constants(self):
        assert ParameterPieces.isthis == 1
        assert ParameterPieces.hiddenretparm == 2
        assert ParameterPieces.indirectstorage == 4
        assert ParameterPieces.namelock == 8
        assert ParameterPieces.typelock == 16
        assert ParameterPieces.sizelock == 32

    def test_swap_markup(self):
        a = ParameterPieces()
        b = ParameterPieces()
        a.type = "typeA"
        b.type = "typeB"
        a.swapMarkup(b)
        assert a.type == "typeB"
        assert b.type == "typeA"


# ---------------------------------------------------------------------------
# PrototypePieces
# ---------------------------------------------------------------------------

class TestPrototypePieces:
    def test_defaults(self):
        pp = PrototypePieces()
        assert pp.model is None
        assert pp.name == ""
        assert pp.outtype is None
        assert pp.intypes == []
        assert pp.innames == []
        assert pp.firstVarArgSlot == -1


# ---------------------------------------------------------------------------
# ParameterBasic
# ---------------------------------------------------------------------------

class TestParameterBasic:
    def test_defaults(self):
        pb = ParameterBasic()
        assert pb.getName() == ""
        assert pb.getType() is None
        assert pb.getAddress().isInvalid()
        assert pb.getSize() == 0
        assert pb.isNameUndefined() is True

    def test_construction(self):
        pb = ParameterBasic("param1", _addr(0x100), None, 0)
        assert pb.getName() == "param1"
        assert pb.getAddress().getOffset() == 0x100
        assert pb.isNameUndefined() is False

    def test_type_lock(self):
        pb = ParameterBasic(fl=ParameterPieces.typelock)
        assert pb.isTypeLocked() is True
        pb.setTypeLock(False)
        assert pb.isTypeLocked() is False
        pb.setTypeLock(True)
        assert pb.isTypeLocked() is True

    def test_name_lock(self):
        pb = ParameterBasic(fl=ParameterPieces.namelock)
        assert pb.isNameLocked() is True
        pb.setNameLock(False)
        assert pb.isNameLocked() is False

    def test_this_pointer(self):
        pb = ParameterBasic(fl=ParameterPieces.isthis)
        assert pb.isThisPointer() is True
        pb.setThisPointer(False)
        assert pb.isThisPointer() is False

    def test_indirect_storage(self):
        pb = ParameterBasic(fl=ParameterPieces.indirectstorage)
        assert pb.isIndirectStorage() is True

    def test_hidden_return(self):
        pb = ParameterBasic(fl=ParameterPieces.hiddenretparm)
        assert pb.isHiddenReturn() is True

    def test_clone(self):
        pb = ParameterBasic("x", _addr(0x50), None, ParameterPieces.typelock)
        clone = pb.clone()
        assert clone.getName() == "x"
        assert clone.isTypeLocked() is True
        assert clone is not pb


# ---------------------------------------------------------------------------
# ProtoStoreInternal
# ---------------------------------------------------------------------------

class TestProtoStoreInternal:
    def test_empty(self):
        ps = ProtoStoreInternal()
        assert ps.getNumInputs() == 0
        assert ps.getOutput() is None
        assert ps.getInput(0) is None

    def test_set_input(self):
        ps = ProtoStoreInternal()
        pp = ParameterPieces()
        pp.addr = _addr(0x100)
        ps.setInput(0, "arg0", pp)
        assert ps.getNumInputs() == 1
        inp = ps.getInput(0)
        assert inp is not None
        assert inp.getName() == "arg0"

    def test_set_output(self):
        ps = ProtoStoreInternal()
        pp = ParameterPieces()
        pp.addr = _addr(0x200)
        ps.setOutput(pp)
        out = ps.getOutput()
        assert out is not None

    def test_clear_input(self):
        ps = ProtoStoreInternal()
        pp = ParameterPieces()
        ps.setInput(0, "a", pp)
        ps.setInput(1, "b", pp)
        assert ps.getNumInputs() == 2
        ps.clearInput(0)
        assert ps.getNumInputs() == 1

    def test_clear_all_inputs(self):
        ps = ProtoStoreInternal()
        pp = ParameterPieces()
        ps.setInput(0, "a", pp)
        ps.setInput(1, "b", pp)
        ps.clearAllInputs()
        assert ps.getNumInputs() == 0

    def test_clear_output(self):
        ps = ProtoStoreInternal()
        pp = ParameterPieces()
        ps.setOutput(pp)
        ps.clearOutput()
        assert ps.getOutput() is None

    def test_clone(self):
        ps = ProtoStoreInternal()
        pp = ParameterPieces()
        pp.addr = _addr(0x100)
        ps.setInput(0, "x", pp)
        ps.setOutput(pp)
        clone = ps.clone()
        assert clone.getNumInputs() == 1
        assert clone.getOutput() is not None
        assert clone is not ps
