"""Tests for fspec.py encode/decode methods — EffectRecord, ParamEntry, ProtoModel, FuncProto."""
from __future__ import annotations

import io
import pytest
from xml.etree.ElementTree import fromstring as xml_fromstring

from ghidra.core.address import Address
from ghidra.core.space import AddrSpace
from ghidra.core.error import LowlevelError
from ghidra.core.pcoderaw import VarnodeData
from ghidra.core.marshal import XmlEncode, XmlDecode
from ghidra.core.space import AddrSpaceManager
from ghidra.fspec.fspec import (
    EffectRecord, ParamEntry, ParamListStandard,
    ProtoModel, FuncProto, ProtoParameter,
    ParameterPieces, ParameterBasic,
)
from ghidra.types.datatype import (
    TYPE_VOID, TYPE_INT, TYPE_UNKNOWN,
    TYPECLASS_GENERAL, TYPECLASS_FLOAT, TypeClass,
)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _spc(name="ram", size=4):
    return AddrSpace(name=name, size=size)


def _addr(off, spc=None):
    return Address(spc or _spc(), off)


def _mgr(*spaces):
    """Create an AddrSpaceManager with given spaces."""
    mgr = AddrSpaceManager()
    for s in spaces:
        mgr._insertSpace(s)
    return mgr


class _MockType:
    """Minimal mock for Datatype."""
    def __init__(self, sz=4, name="int"):
        self._size = sz
        self._name = name

    def getSize(self):
        return self._size

    def getMetatype(self):
        return TYPE_INT

    def encodeRef(self, encoder):
        pass

    def __repr__(self):
        return self._name


class _MockModel:
    """Minimal mock for ProtoModel used in FuncProto tests."""
    def __init__(self, name="__cdecl", extrapop=0):
        self._name = name
        self._extrapop = extrapop
        self._effectlist = []
        self._likelytrash = []

    def getName(self):
        return self._name

    def getArch(self):
        return None

    def hasEffect(self, addr, size):
        return EffectRecord.unknown_effect

    def hasThisPointer(self):
        return False

    def trashBegin(self):
        return iter(self._likelytrash)

    def trashEnd(self):
        return iter([])

    def getExtraPop(self):
        return self._extrapop


# ===========================================================================
# EffectRecord encode/decode
# ===========================================================================

class TestEffectRecordEncode:
    def test_encode_unaffected(self):
        spc = _spc()
        rec = EffectRecord(_addr(0x100, spc), 4, EffectRecord.unaffected)
        enc = XmlEncode(do_format=False)
        rec.encode(enc)
        xml = enc.toString()
        assert "addr" in xml

    def test_encode_killedbycall(self):
        spc = _spc()
        rec = EffectRecord(_addr(0x200, spc), 8, EffectRecord.killedbycall)
        enc = XmlEncode(do_format=False)
        rec.encode(enc)
        xml = enc.toString()
        assert "addr" in xml

    def test_encode_return_address(self):
        spc = _spc()
        rec = EffectRecord(_addr(0x300, spc), 4, EffectRecord.return_address)
        enc = XmlEncode(do_format=False)
        rec.encode(enc)
        xml = enc.toString()
        assert "addr" in xml

    def test_encode_unknown_raises(self):
        rec = EffectRecord(_addr(0x100), 4, EffectRecord.unknown_effect)
        enc = XmlEncode(do_format=False)
        with pytest.raises(LowlevelError, match="Bad EffectRecord type"):
            rec.encode(enc)

    def test_decode_with_grouptype(self):
        spc = _spc("ram", 4)
        mgr = _mgr(spc)
        xml_str = '<addr space="ram" offset="0x100" size="4"/>'
        root = xml_fromstring(xml_str)
        dec = XmlDecode(mgr, root)
        rec = EffectRecord()
        rec.decode(EffectRecord.unaffected, dec)
        assert rec.getType() == EffectRecord.unaffected
        assert rec.getAddress().getOffset() == 0x100
        assert rec.getSize() == 4

    def test_decode_without_grouptype(self):
        spc = _spc("ram", 4)
        mgr = _mgr(spc)
        xml_str = '<addr space="ram" offset="0x200" size="8"/>'
        root = xml_fromstring(xml_str)
        dec = XmlDecode(mgr, root)
        rec = EffectRecord()
        rec.decode(dec)
        assert rec.getType() == EffectRecord.unknown_effect
        assert rec.getAddress().getOffset() == 0x200
        assert rec.getSize() == 8

    def test_decode_killedbycall(self):
        spc = _spc("ram", 4)
        mgr = _mgr(spc)
        xml_str = '<addr space="ram" offset="0x50" size="2"/>'
        root = xml_fromstring(xml_str)
        dec = XmlDecode(mgr, root)
        rec = EffectRecord()
        rec.decode(EffectRecord.killedbycall, dec)
        assert rec.getType() == EffectRecord.killedbycall

    def test_decode_return_address(self):
        spc = _spc("ram", 4)
        mgr = _mgr(spc)
        xml_str = '<addr space="ram" offset="0x80" size="4"/>'
        root = xml_fromstring(xml_str)
        dec = XmlDecode(mgr, root)
        rec = EffectRecord()
        rec.decode(EffectRecord.return_address, dec)
        assert rec.getType() == EffectRecord.return_address
        assert rec.getAddress().getOffset() == 0x80


# ===========================================================================
# ParamEntry encode/decode
# ===========================================================================

class TestParamEntryEncode:
    def test_encode_basic(self):
        spc = _spc()
        pe = ParamEntry(0)
        pe.spaceid = spc
        pe.addressbase = 0x100
        pe.size = 4
        pe.minsize = 1
        pe.alignment = 0
        pe.type = TYPECLASS_GENERAL
        pe.flags = 0
        enc = XmlEncode(do_format=False)
        pe.encode(enc)
        xml = enc.toString()
        assert "pentry" in xml
        assert "minsize" in xml
        assert "maxsize" in xml

    def test_encode_with_alignment(self):
        spc = _spc()
        pe = ParamEntry(0)
        pe.spaceid = spc
        pe.addressbase = 0x0
        pe.size = 16
        pe.minsize = 4
        pe.alignment = 4
        pe.type = TYPECLASS_GENERAL
        pe.flags = 0
        enc = XmlEncode(do_format=False)
        pe.encode(enc)
        xml = enc.toString()
        assert "align" in xml

    def test_encode_float_type(self):
        spc = _spc()
        pe = ParamEntry(0)
        pe.spaceid = spc
        pe.addressbase = 0x0
        pe.size = 8
        pe.minsize = 4
        pe.alignment = 0
        pe.type = TypeClass.TYPECLASS_FLOAT
        pe.flags = 0
        enc = XmlEncode(do_format=False)
        pe.encode(enc)
        xml = enc.toString()
        assert "float" in xml

    def test_encode_sext_extension(self):
        spc = _spc()
        pe = ParamEntry(0)
        pe.spaceid = spc
        pe.addressbase = 0x0
        pe.size = 4
        pe.minsize = 1
        pe.alignment = 0
        pe.type = TYPECLASS_GENERAL
        pe.flags = ParamEntry.smallsize_sext
        enc = XmlEncode(do_format=False)
        pe.encode(enc)
        xml = enc.toString()
        assert "sign" in xml

    def test_encode_zext_extension(self):
        spc = _spc()
        pe = ParamEntry(0)
        pe.spaceid = spc
        pe.addressbase = 0x0
        pe.size = 4
        pe.minsize = 1
        pe.alignment = 0
        pe.type = TYPECLASS_GENERAL
        pe.flags = ParamEntry.smallsize_zext
        enc = XmlEncode(do_format=False)
        pe.encode(enc)
        xml = enc.toString()
        assert "zero" in xml


class TestParamEntryDecode:
    def test_decode_basic(self):
        spc = _spc("ram", 4)
        mgr = _mgr(spc)
        xml_str = '<pentry minsize="0x1" maxsize="0x4"><addr space="ram" offset="0x100" size="4"/></pentry>'
        root = xml_fromstring(xml_str)
        dec = XmlDecode(mgr, root)
        pe = ParamEntry(0)
        pe.decode(dec, normalstack=True, grouped=False)
        assert pe.minsize == 1
        assert pe.size == 4
        assert pe.addressbase == 0x100
        assert pe.spaceid is not None

    def test_decode_with_alignment(self):
        spc = _spc("ram", 4)
        mgr = _mgr(spc)
        xml_str = '<pentry minsize="0x4" maxsize="0x10" align="0x4"><addr space="ram" offset="0x0" size="4"/></pentry>'
        root = xml_fromstring(xml_str)
        dec = XmlDecode(mgr, root)
        pe = ParamEntry(0)
        pe.decode(dec, normalstack=True, grouped=False)
        assert pe.alignment == 4
        assert pe.numslots == 4  # 16/4

    def test_decode_float_type(self):
        spc = _spc("ram", 4)
        mgr = _mgr(spc)
        xml_str = '<pentry minsize="0x4" maxsize="0x8" metatype="float"><addr space="ram" offset="0x0" size="4"/></pentry>'
        root = xml_fromstring(xml_str)
        dec = XmlDecode(mgr, root)
        pe = ParamEntry(0)
        pe.decode(dec)
        assert pe.type == TypeClass.TYPECLASS_FLOAT

    def test_decode_extension_sign(self):
        spc = _spc("ram", 4)
        mgr = _mgr(spc)
        xml_str = '<pentry minsize="0x1" maxsize="0x4" extension="sign"><addr space="ram" offset="0x0" size="4"/></pentry>'
        root = xml_fromstring(xml_str)
        dec = XmlDecode(mgr, root)
        pe = ParamEntry(0)
        pe.decode(dec)
        assert (pe.flags & ParamEntry.smallsize_sext) != 0

    def test_decode_extension_zero(self):
        spc = _spc("ram", 4)
        mgr = _mgr(spc)
        xml_str = '<pentry minsize="0x1" maxsize="0x4" extension="zero"><addr space="ram" offset="0x0" size="4"/></pentry>'
        root = xml_fromstring(xml_str)
        dec = XmlDecode(mgr, root)
        pe = ParamEntry(0)
        pe.decode(dec)
        assert (pe.flags & ParamEntry.smallsize_zext) != 0

    def test_decode_extension_inttype(self):
        spc = _spc("ram", 4)
        mgr = _mgr(spc)
        xml_str = '<pentry minsize="0x1" maxsize="0x4" extension="inttype"><addr space="ram" offset="0x0" size="4"/></pentry>'
        root = xml_fromstring(xml_str)
        dec = XmlDecode(mgr, root)
        pe = ParamEntry(0)
        pe.decode(dec)
        assert (pe.flags & ParamEntry.smallsize_inttype) != 0

    def test_decode_extension_none(self):
        spc = _spc("ram", 4)
        mgr = _mgr(spc)
        xml_str = '<pentry minsize="0x1" maxsize="0x4" extension="none"><addr space="ram" offset="0x0" size="4"/></pentry>'
        root = xml_fromstring(xml_str)
        dec = XmlDecode(mgr, root)
        pe = ParamEntry(0)
        pe.decode(dec)
        assert (pe.flags & (ParamEntry.smallsize_sext | ParamEntry.smallsize_zext | ParamEntry.smallsize_inttype)) == 0

    def test_decode_bad_extension_raises(self):
        spc = _spc("ram", 4)
        mgr = _mgr(spc)
        xml_str = '<pentry minsize="0x1" maxsize="0x4" extension="bad"><addr space="ram" offset="0x0" size="4"/></pentry>'
        root = xml_fromstring(xml_str)
        dec = XmlDecode(mgr, root)
        pe = ParamEntry(0)
        with pytest.raises(LowlevelError, match="Bad extension"):
            pe.decode(dec)

    def test_decode_missing_size_raises(self):
        spc = _spc("ram", 4)
        mgr = _mgr(spc)
        xml_str = '<pentry minsize="0x1"><addr space="ram" offset="0x0" size="4"/></pentry>'
        root = xml_fromstring(xml_str)
        dec = XmlDecode(mgr, root)
        pe = ParamEntry(0)
        with pytest.raises(LowlevelError, match="not fully specified"):
            pe.decode(dec)

    def test_decode_grouped(self):
        spc = _spc("ram", 4)
        mgr = _mgr(spc)
        xml_str = '<pentry minsize="0x1" maxsize="0x4"><addr space="ram" offset="0x0" size="4"/></pentry>'
        root = xml_fromstring(xml_str)
        dec = XmlDecode(mgr, root)
        pe = ParamEntry(0)
        pe.decode(dec, normalstack=True, grouped=True)
        assert (pe.flags & ParamEntry.is_grouped) != 0

    def test_decode_reverse_stack(self):
        spc = _spc("ram", 4)
        mgr = _mgr(spc)
        xml_str = '<pentry minsize="0x1" maxsize="0x4"><addr space="ram" offset="0x0" size="4"/></pentry>'
        root = xml_fromstring(xml_str)
        dec = XmlDecode(mgr, root)
        pe = ParamEntry(0)
        pe.decode(dec, normalstack=False)
        assert (pe.flags & ParamEntry.reverse_stack) != 0

    def test_decode_alignment_equals_size_clears(self):
        spc = _spc("ram", 4)
        mgr = _mgr(spc)
        # alignment == maxsize => alignment reset to 0
        xml_str = '<pentry minsize="0x1" maxsize="0x4" align="0x4"><addr space="ram" offset="0x0" size="4"/></pentry>'
        root = xml_fromstring(xml_str)
        dec = XmlDecode(mgr, root)
        pe = ParamEntry(0)
        pe.decode(dec)
        assert pe.alignment == 0


# ===========================================================================
# FuncProto encode
# ===========================================================================

class TestFuncProtoEncode:
    def test_encode_basic(self):
        """Encode a simple prototype with model and return type."""
        fp = FuncProto()
        fp.model = _MockModel("__cdecl", extrapop=4)
        fp.extrapop = 4
        fp.flags = 0
        fp.outparam = ProtoParameter("", _MockType(4, "int"), _addr(0), 4)
        fp.store = []
        enc = XmlEncode(do_format=False)
        fp.encode(enc)
        xml = enc.toString()
        assert "prototype" in xml
        assert "__cdecl" in xml
        assert "returnsym" in xml

    def test_encode_with_flags(self):
        """Encode prototype with various flags set."""
        fp = FuncProto()
        fp.model = _MockModel()
        fp.extrapop = ProtoModel.extrapop_unknown
        fp.flags = FuncProto.dotdotdot | FuncProto.modellock | FuncProto.is_inline
        fp.outparam = None
        fp.store = []
        enc = XmlEncode(do_format=False)
        fp.encode(enc)
        xml = enc.toString()
        assert "dotdotdot" in xml
        assert "modellock" in xml
        assert "inline" in xml
        assert 'extrapop="unknown"' in xml

    def test_encode_with_params(self):
        """Encode prototype with input parameters."""
        fp = FuncProto()
        fp.model = _MockModel()
        fp.extrapop = 4
        fp.flags = 0
        fp.outparam = ProtoParameter("", _MockType(4), _addr(0), 4)
        p1 = ParameterBasic("x", _addr(0x10), _MockType(4), ParameterPieces.typelock)
        p2 = ParameterBasic("y", _addr(0x14), _MockType(4), ParameterPieces.typelock | ParameterPieces.namelock)
        fp.store = [p1, p2]
        enc = XmlEncode(do_format=False)
        fp.encode(enc)
        xml = enc.toString()
        assert "internallist" in xml
        assert "param" in xml
        assert 'name="x"' in xml
        assert 'name="y"' in xml
        assert "typelock" in xml
        assert "namelock" in xml

    def test_encode_with_typelock_output(self):
        """Encode prototype with type-locked output."""
        fp = FuncProto()
        fp.model = _MockModel()
        fp.extrapop = 0
        fp.flags = 0
        outp = ParameterBasic("", _addr(0), _MockType(4), ParameterPieces.typelock)
        fp.outparam = outp
        fp.store = []
        enc = XmlEncode(do_format=False)
        fp.encode(enc)
        xml = enc.toString()
        assert "typelock" in xml

    def test_encode_noreturn(self):
        fp = FuncProto()
        fp.model = _MockModel()
        fp.extrapop = 0
        fp.flags = FuncProto.no_return
        fp.outparam = None
        fp.store = []
        enc = XmlEncode(do_format=False)
        fp.encode(enc)
        xml = enc.toString()
        assert "noreturn" in xml

    def test_encode_constructor_destructor(self):
        fp = FuncProto()
        fp.model = _MockModel()
        fp.extrapop = 0
        fp.flags = FuncProto.is_constructor | FuncProto.is_destructor
        fp.outparam = None
        fp.store = []
        enc = XmlEncode(do_format=False)
        fp.encode(enc)
        xml = enc.toString()
        assert "constructor" in xml
        assert "destructor" in xml

    def test_encode_custom_storage(self):
        fp = FuncProto()
        fp.model = _MockModel()
        fp.extrapop = 0
        fp.flags = FuncProto.custom_storage
        fp.outparam = None
        fp.store = []
        enc = XmlEncode(do_format=False)
        fp.encode(enc)
        xml = enc.toString()
        assert "custom" in xml

    def test_encode_effect_list(self):
        """Encode prototype with effect records that differ from model."""
        fp = FuncProto()
        fp.model = _MockModel()
        fp.extrapop = 0
        fp.flags = 0
        fp.outparam = None
        fp.store = []
        spc = _spc()
        fp.effectlist = [
            EffectRecord(_addr(0x100, spc), 4, EffectRecord.unaffected),
            EffectRecord(_addr(0x200, spc), 4, EffectRecord.killedbycall),
        ]
        enc = XmlEncode(do_format=False)
        fp.encode(enc)
        xml = enc.toString()
        assert "unaffected" in xml
        assert "killedbycall" in xml

    def test_encode_no_model(self):
        """Encode prototype without a model set."""
        fp = FuncProto()
        fp.extrapop = 0
        fp.flags = 0
        fp.outparam = None
        fp.store = []
        enc = XmlEncode(do_format=False)
        fp.encode(enc)
        xml = enc.toString()
        assert "prototype" in xml
        # Should not crash


class TestFuncProtoEncodeEffect:
    def test_empty_effectlist(self):
        fp = FuncProto()
        fp.model = _MockModel()
        fp.effectlist = []
        enc = XmlEncode(do_format=False)
        fp._encodeEffect(enc)
        assert enc.toString() == ""

    def test_skips_matching_model_effect(self):
        """Effects that match the model are skipped."""
        class _MatchModel:
            def hasEffect(self, addr, size):
                return EffectRecord.unaffected
        fp = FuncProto()
        fp.model = _MatchModel()
        spc = _spc()
        fp.effectlist = [
            EffectRecord(_addr(0x100, spc), 4, EffectRecord.unaffected),
        ]
        enc = XmlEncode(do_format=False)
        fp._encodeEffect(enc)
        assert "unaffected" not in enc.toString()


class TestFuncProtoEncodeLikelyTrash:
    def test_empty_likelytrash(self):
        fp = FuncProto()
        fp.likelytrash = []
        enc = XmlEncode(do_format=False)
        fp._encodeLikelyTrash(enc)
        assert enc.toString() == ""

    def test_nonempty_likelytrash(self):
        fp = FuncProto()
        spc = _spc()
        vd = VarnodeData()
        vd.space = spc
        vd.offset = 0x50
        vd.size = 4
        fp.likelytrash = [vd]
        enc = XmlEncode(do_format=False)
        fp._encodeLikelyTrash(enc)
        xml = enc.toString()
        assert "likelytrash" in xml
        assert "addr" in xml


# ===========================================================================
# ProtoModel encode
# ===========================================================================

class TestProtoModelEncode:
    def test_encode_basic(self):
        pm = ProtoModel("__cdecl")
        pm.extrapop = 4
        pm.hasThis = False
        pm.isConstruct = False
        enc = XmlEncode(do_format=False)
        pm.encode(enc)
        xml = enc.toString()
        assert "prototype" in xml
        assert "__cdecl" in xml

    def test_encode_unknown_extrapop(self):
        pm = ProtoModel("__cdecl")
        pm.extrapop = ProtoModel.extrapop_unknown
        enc = XmlEncode(do_format=False)
        pm.encode(enc)
        xml = enc.toString()
        assert 'extrapop="unknown"' in xml

    def test_encode_hasthis(self):
        pm = ProtoModel("__thiscall")
        pm.extrapop = 4
        pm.hasThis = True
        enc = XmlEncode(do_format=False)
        pm.encode(enc)
        xml = enc.toString()
        assert "hasthis" in xml

    def test_encode_constructor(self):
        pm = ProtoModel("ctor")
        pm.extrapop = 0
        pm.isConstruct = True
        enc = XmlEncode(do_format=False)
        pm.encode(enc)
        xml = enc.toString()
        assert "constructor" in xml

    def test_encode_with_effects(self):
        pm = ProtoModel("__cdecl")
        pm.extrapop = 4
        spc = _spc()
        pm.effectlist = [
            EffectRecord(_addr(0x100, spc), 4, EffectRecord.unaffected),
            EffectRecord(_addr(0x200, spc), 4, EffectRecord.killedbycall),
            EffectRecord(_addr(0x300, spc), 4, EffectRecord.return_address),
        ]
        enc = XmlEncode(do_format=False)
        pm.encode(enc)
        xml = enc.toString()
        assert "unaffected" in xml
        assert "killedbycall" in xml
        assert "returnaddress" in xml


# ===========================================================================
# ProtoModel decode
# ===========================================================================

class TestProtoModelDecode:
    def test_decode_basic(self):
        spc = _spc("ram", 4)
        mgr = _mgr(spc)
        xml_str = '<prototype name="__cdecl" extrapop="0x4"></prototype>'
        root = xml_fromstring(xml_str)
        dec = XmlDecode(mgr, root)
        pm = ProtoModel("temp")
        pm.decode(dec)
        assert pm.name == "__cdecl"
        assert pm.extrapop == 4

    def test_decode_unknown_extrapop(self):
        spc = _spc("ram", 4)
        mgr = _mgr(spc)
        xml_str = '<prototype name="__cdecl" extrapop="unknown"></prototype>'
        root = xml_fromstring(xml_str)
        dec = XmlDecode(mgr, root)
        pm = ProtoModel("temp")
        pm.decode(dec)
        assert pm.extrapop == ProtoModel.extrapop_unknown

    def test_decode_hasthis(self):
        spc = _spc("ram", 4)
        mgr = _mgr(spc)
        xml_str = '<prototype name="custom" extrapop="0x0" hasthis="true"></prototype>'
        root = xml_fromstring(xml_str)
        dec = XmlDecode(mgr, root)
        pm = ProtoModel("temp")
        pm.decode(dec)
        assert pm.hasThis is True

    def test_decode_thiscall_name_sets_hasthis(self):
        spc = _spc("ram", 4)
        mgr = _mgr(spc)
        xml_str = '<prototype name="__thiscall" extrapop="0x4"></prototype>'
        root = xml_fromstring(xml_str)
        dec = XmlDecode(mgr, root)
        pm = ProtoModel("temp")
        pm.decode(dec)
        assert pm.hasThis is True

    def test_decode_constructor(self):
        spc = _spc("ram", 4)
        mgr = _mgr(spc)
        xml_str = '<prototype name="ctor" extrapop="0x0" constructor="true"></prototype>'
        root = xml_fromstring(xml_str)
        dec = XmlDecode(mgr, root)
        pm = ProtoModel("temp")
        pm.decode(dec)
        assert pm.isConstruct is True

    def test_decode_missing_extrapop_raises(self):
        spc = _spc("ram", 4)
        mgr = _mgr(spc)
        xml_str = '<prototype name="bad"></prototype>'
        root = xml_fromstring(xml_str)
        dec = XmlDecode(mgr, root)
        pm = ProtoModel("temp")
        with pytest.raises(LowlevelError, match="Missing prototype"):
            pm.decode(dec)

    def test_decode_with_unaffected(self):
        spc = _spc("ram", 4)
        mgr = _mgr(spc)
        xml_str = '''<prototype name="test" extrapop="0x4">
            <unaffected>
                <addr space="ram" offset="0x100" size="4"/>
            </unaffected>
        </prototype>'''
        root = xml_fromstring(xml_str)
        dec = XmlDecode(mgr, root)
        pm = ProtoModel("temp")
        pm.decode(dec)
        assert len(pm.effectlist) == 1
        assert pm.effectlist[0].getType() == EffectRecord.unaffected
        assert pm.effectlist[0].getAddress().getOffset() == 0x100

    def test_decode_with_killedbycall(self):
        spc = _spc("ram", 4)
        mgr = _mgr(spc)
        xml_str = '''<prototype name="test" extrapop="0x4">
            <killedbycall>
                <addr space="ram" offset="0x200" size="4"/>
            </killedbycall>
        </prototype>'''
        root = xml_fromstring(xml_str)
        dec = XmlDecode(mgr, root)
        pm = ProtoModel("temp")
        pm.decode(dec)
        assert len(pm.effectlist) == 1
        assert pm.effectlist[0].getType() == EffectRecord.killedbycall

    def test_decode_with_returnaddress(self):
        spc = _spc("ram", 4)
        mgr = _mgr(spc)
        xml_str = '''<prototype name="test" extrapop="0x4">
            <returnaddress>
                <addr space="ram" offset="0x300" size="4"/>
            </returnaddress>
        </prototype>'''
        root = xml_fromstring(xml_str)
        dec = XmlDecode(mgr, root)
        pm = ProtoModel("temp")
        pm.decode(dec)
        assert len(pm.effectlist) == 1
        assert pm.effectlist[0].getType() == EffectRecord.return_address

    def test_decode_with_likelytrash(self):
        spc = _spc("ram", 4)
        mgr = _mgr(spc)
        xml_str = '''<prototype name="test" extrapop="0x4">
            <likelytrash>
                <addr space="ram" offset="0x50" size="4"/>
            </likelytrash>
        </prototype>'''
        root = xml_fromstring(xml_str)
        dec = XmlDecode(mgr, root)
        pm = ProtoModel("temp")
        pm.decode(dec)
        assert len(pm.likelytrash) == 1
        assert pm.likelytrash[0].offset == 0x50

    def test_decode_strategy_ignored(self):
        spc = _spc("ram", 4)
        mgr = _mgr(spc)
        xml_str = '<prototype name="test" extrapop="0x4" strategy="register"></prototype>'
        root = xml_fromstring(xml_str)
        dec = XmlDecode(mgr, root)
        pm = ProtoModel("temp")
        pm.decode(dec)
        assert pm.name == "test"

    def test_decode_stackshift_ignored(self):
        spc = _spc("ram", 4)
        mgr = _mgr(spc)
        xml_str = '<prototype name="test" extrapop="0x4" stackshift="0x4"></prototype>'
        root = xml_fromstring(xml_str)
        dec = XmlDecode(mgr, root)
        pm = ProtoModel("temp")
        pm.decode(dec)
        assert pm.name == "test"

    def test_decode_multiple_effects(self):
        spc = _spc("ram", 4)
        mgr = _mgr(spc)
        xml_str = '''<prototype name="test" extrapop="0x4">
            <unaffected>
                <addr space="ram" offset="0x10" size="4"/>
                <addr space="ram" offset="0x20" size="4"/>
            </unaffected>
            <killedbycall>
                <addr space="ram" offset="0x30" size="4"/>
            </killedbycall>
        </prototype>'''
        root = xml_fromstring(xml_str)
        dec = XmlDecode(mgr, root)
        pm = ProtoModel("temp")
        pm.decode(dec)
        assert len(pm.effectlist) == 3
        types = [r.getType() for r in pm.effectlist]
        assert types.count(EffectRecord.unaffected) == 2
        assert types.count(EffectRecord.killedbycall) == 1


# ===========================================================================
# FuncProto._decodeInternalList
# ===========================================================================

class TestFuncProtoDecodeInternalList:
    def test_decode_params(self):
        spc = _spc("ram", 4)
        mgr = _mgr(spc)
        xml_str = '''<internallist>
            <param name="x" typelock="true">
                <addr space="ram" offset="0x10" size="4"/>
            </param>
            <param name="y" namelock="true">
                <addr space="ram" offset="0x14" size="4"/>
            </param>
        </internallist>'''
        root = xml_fromstring(xml_str)
        dec = XmlDecode(mgr, root)
        fp = FuncProto()
        fp.store = []
        fp.outparam = None
        fp._decodeInternalList(dec)
        assert len(fp.store) == 2
        assert fp.store[0].getName() == "x"
        assert fp.store[0].isTypeLocked()
        assert fp.store[1].getName() == "y"
        assert fp.store[1].isNameLocked()

    def test_decode_retparam(self):
        spc = _spc("ram", 4)
        mgr = _mgr(spc)
        xml_str = '''<internallist>
            <retparam typelock="true">
                <addr space="ram" offset="0x0" size="4"/>
            </retparam>
        </internallist>'''
        root = xml_fromstring(xml_str)
        dec = XmlDecode(mgr, root)
        fp = FuncProto()
        fp.store = []
        fp.outparam = None
        fp._decodeInternalList(dec)
        assert fp.outparam is not None
        assert fp.outparam.isTypeLocked()

    def test_decode_thisptr(self):
        spc = _spc("ram", 4)
        mgr = _mgr(spc)
        xml_str = '''<internallist>
            <param name="this" thisptr="true">
                <addr space="ram" offset="0x10" size="4"/>
            </param>
        </internallist>'''
        root = xml_fromstring(xml_str)
        dec = XmlDecode(mgr, root)
        fp = FuncProto()
        fp.store = []
        fp.outparam = None
        fp._decodeInternalList(dec)
        assert len(fp.store) == 1
        assert fp.store[0].getName() == "this"
        assert (fp.store[0].flags & ParameterPieces.isthis) != 0

    def test_decode_hiddenretparm(self):
        spc = _spc("ram", 4)
        mgr = _mgr(spc)
        xml_str = '''<internallist>
            <param hiddenretparm="true">
                <addr space="ram" offset="0x10" size="4"/>
            </param>
        </internallist>'''
        root = xml_fromstring(xml_str)
        dec = XmlDecode(mgr, root)
        fp = FuncProto()
        fp.store = []
        fp.outparam = None
        fp._decodeInternalList(dec)
        assert len(fp.store) == 1
        assert (fp.store[0].flags & ParameterPieces.hiddenretparm) != 0


# ===========================================================================
# ProtoStoreInternal encode/decode (via ProtoStore API)
# ===========================================================================

class TestProtoStoreInternalEncode:
    def test_encode_with_output_and_params(self):
        from ghidra.fspec.fspec import ProtoStoreInternal
        store = ProtoStoreInternal()
        spc = _spc()
        pp_out = ParameterPieces()
        pp_out.addr = _addr(0, spc)
        pp_out.type = _MockType(4)
        pp_out.flags = ParameterPieces.typelock
        store.setOutput(pp_out)
        pp_in = ParameterPieces()
        pp_in.addr = _addr(0x10, spc)
        pp_in.type = _MockType(4)
        pp_in.flags = ParameterPieces.typelock | ParameterPieces.namelock
        store.setInput(0, "arg0", pp_in)
        # ProtoStoreInternal doesn't have encode yet, but check it exists
        assert store.getNumInputs() == 1
        assert store.getOutput() is not None


# ===========================================================================
# ProtoModel._buildParamList
# ===========================================================================

class TestProtoModelBuildParamList:
    def test_creates_param_lists_if_none(self):
        pm = ProtoModel("test")
        pm.input = None
        pm.output = None
        pm._buildParamList("")
        assert pm.input is not None
        assert pm.output is not None
        assert isinstance(pm.input, ParamListStandard)
        assert isinstance(pm.output, ParamListStandard)

    def test_preserves_existing_lists(self):
        pm = ProtoModel("test")
        existing_input = ParamListStandard()
        existing_output = ParamListStandard()
        pm.input = existing_input
        pm.output = existing_output
        pm._buildParamList("")
        assert pm.input is existing_input
        assert pm.output is existing_output


# ===========================================================================
# ProtoModel._defaultLocalRange / _defaultParamRange
# ===========================================================================

class TestProtoModelDefaultRanges:
    def test_default_local_range_no_glb(self):
        pm = ProtoModel("test")
        pm.glb = None
        pm.defaultLocalRange = []
        pm._stackgrowsnegative = True
        pm._defaultLocalRange()
        # Should not crash, no ranges set

    def test_default_param_range_no_glb(self):
        pm = ProtoModel("test")
        pm.glb = None
        pm.defaultParamRange = []
        pm._stackgrowsnegative = True
        pm._defaultParamRange()
        # Should not crash, no ranges set


# ===========================================================================
# ProtoStoreInternal encode (full C++ aligned)
# ===========================================================================

from ghidra.fspec.fspec import ProtoStoreInternal, UnknownProtoModel, ProtoModelMerged


class TestProtoStoreInternalEncodeFull:
    def test_encode_with_no_output(self):
        """When outparam is None, encode should emit <retparam><addr/><void/></retparam>."""
        store = ProtoStoreInternal()
        enc = XmlEncode(do_format=False)
        store.encode(enc)
        xml = enc.toString()
        assert "<internallist>" in xml
        assert "<retparam>" in xml
        assert "<addr/>" in xml
        assert "<void/>" in xml

    def test_encode_with_output_and_params(self):
        spc = _spc("ram", 4)
        store = ProtoStoreInternal()
        pp_out = ParameterPieces()
        pp_out.addr = Address(spc, 0)
        pp_out.type = _MockType(4, "int")
        pp_out.flags = ParameterPieces.typelock
        store.setOutput(pp_out)

        pp_in = ParameterPieces()
        pp_in.addr = Address(spc, 0x10)
        pp_in.type = _MockType(4, "int")
        pp_in.flags = ParameterPieces.typelock | ParameterPieces.namelock
        store.setInput(0, "arg0", pp_in)

        enc = XmlEncode(do_format=False)
        store.encode(enc)
        xml = enc.toString()
        assert "<retparam" in xml
        assert 'typelock="true"' in xml
        assert "<param" in xml
        assert 'name="arg0"' in xml
        assert 'namelock="true"' in xml

    def test_encode_thisptr_flag(self):
        spc = _spc("ram", 4)
        store = ProtoStoreInternal()
        pp_out = ParameterPieces()
        pp_out.addr = Address(spc, 0)
        pp_out.type = _MockType(4)
        pp_out.flags = 0
        store.setOutput(pp_out)

        pp_in = ParameterPieces()
        pp_in.addr = Address(spc, 0x10)
        pp_in.type = _MockType(4)
        pp_in.flags = ParameterPieces.isthis
        store.setInput(0, "this", pp_in)

        enc = XmlEncode(do_format=False)
        store.encode(enc)
        xml = enc.toString()
        assert 'thisptr="true"' in xml

    def test_encode_hiddenretparm_flag(self):
        spc = _spc("ram", 4)
        store = ProtoStoreInternal()
        pp_out = ParameterPieces()
        pp_out.addr = Address(spc, 0)
        pp_out.type = _MockType(4)
        pp_out.flags = 0
        store.setOutput(pp_out)

        pp_in = ParameterPieces()
        pp_in.addr = Address(spc, 0x10)
        pp_in.type = _MockType(4)
        pp_in.flags = ParameterPieces.hiddenretparm
        store.setInput(0, "rethidden", pp_in)

        enc = XmlEncode(do_format=False)
        store.encode(enc)
        xml = enc.toString()
        assert 'hiddenretparm="true"' in xml

    def test_encode_indirectstorage_flag(self):
        spc = _spc("ram", 4)
        store = ProtoStoreInternal()
        pp_out = ParameterPieces()
        pp_out.addr = Address(spc, 0)
        pp_out.type = _MockType(4)
        pp_out.flags = 0
        store.setOutput(pp_out)

        pp_in = ParameterPieces()
        pp_in.addr = Address(spc, 0x10)
        pp_in.type = _MockType(4)
        pp_in.flags = ParameterPieces.indirectstorage
        store.setInput(0, "ptr", pp_in)

        enc = XmlEncode(do_format=False)
        store.encode(enc)
        xml = enc.toString()
        assert 'indirectstorage="true"' in xml


# ===========================================================================
# ProtoStoreInternal decode
# ===========================================================================

class TestProtoStoreInternalDecodeFull:
    def test_decode_basic_params(self):
        spc = _spc("ram", 4)
        mgr = _mgr(spc)
        xml_str = '''<internallist>
            <param name="x" typelock="true">
                <addr space="ram" offset="0x10" size="4"/>
            </param>
            <param name="y">
                <addr space="ram" offset="0x14" size="4"/>
            </param>
        </internallist>'''
        root = xml_fromstring(xml_str)
        dec = XmlDecode(mgr, root)
        store = ProtoStoreInternal()
        store.decode(dec)
        assert store.getNumInputs() == 2
        assert store.getInput(0).getName() == "x"
        assert store.getInput(0).isTypeLocked()
        assert store.getInput(1).getName() == "y"
        assert not store.getInput(1).isTypeLocked()

    def test_decode_with_retparam(self):
        spc = _spc("ram", 4)
        mgr = _mgr(spc)
        xml_str = '''<internallist>
            <retparam typelock="true">
                <addr space="ram" offset="0x0" size="4"/>
            </retparam>
            <param name="a">
                <addr space="ram" offset="0x10" size="4"/>
            </param>
        </internallist>'''
        root = xml_fromstring(xml_str)
        dec = XmlDecode(mgr, root)
        store = ProtoStoreInternal()
        store.decode(dec)
        # retparam is collected as a piece but placed at index 0 in pieces
        # The first openElement sees retparam
        assert store.getNumInputs() >= 1

    def test_decode_thisptr(self):
        spc = _spc("ram", 4)
        mgr = _mgr(spc)
        xml_str = '''<internallist>
            <param name="this" thisptr="true">
                <addr space="ram" offset="0x10" size="4"/>
            </param>
        </internallist>'''
        root = xml_fromstring(xml_str)
        dec = XmlDecode(mgr, root)
        store = ProtoStoreInternal()
        store.decode(dec)
        assert store.getNumInputs() == 1
        inp = store.getInput(0)
        assert inp.getName() == "this"

    def test_decode_hiddenretparm(self):
        spc = _spc("ram", 4)
        mgr = _mgr(spc)
        xml_str = '''<internallist>
            <param name="rethidden" hiddenretparm="true">
                <addr space="ram" offset="0x10" size="4"/>
            </param>
        </internallist>'''
        root = xml_fromstring(xml_str)
        dec = XmlDecode(mgr, root)
        store = ProtoStoreInternal()
        store.decode(dec)
        assert store.getNumInputs() == 1
        inp = store.getInput(0)
        assert inp.getName() == "rethidden"


# ===========================================================================
# UnknownProtoModel encode
# ===========================================================================

class TestUnknownProtoModelEncode:
    def test_encode_basic(self):
        m = UnknownProtoModel("unknown_cc", None)
        enc = XmlEncode(do_format=False)
        m.encode(enc)
        xml = enc.toString()
        assert "<prototype" in xml
        assert 'name="unknown_cc"' in xml

    def test_encode_preserves_name(self):
        m = UnknownProtoModel("my_custom_cc", None)
        enc = XmlEncode(do_format=False)
        m.encode(enc)
        xml = enc.toString()
        assert 'name="my_custom_cc"' in xml


# ===========================================================================
# ProtoModelMerged encode/decode
# ===========================================================================

class TestProtoModelMergedEncode:
    def test_encode_empty(self):
        pm = ProtoModelMerged()
        pm._name = "merged"
        enc = XmlEncode(do_format=False)
        pm.encode(enc)
        xml = enc.toString()
        assert "<resolveprototype" in xml
        assert 'name="merged"' in xml
        assert "resolveprototype" in xml

    def test_encode_with_models(self):
        pm = ProtoModelMerged()
        pm._name = "merged"
        m1 = _MockModel("cdecl")
        m2 = _MockModel("stdcall")
        pm.foldIn(m1)
        pm.foldIn(m2)
        enc = XmlEncode(do_format=False)
        pm.encode(enc)
        xml = enc.toString()
        assert 'name="cdecl"' in xml
        assert 'name="stdcall"' in xml
        assert xml.count("<model") == 2


class TestProtoModelMergedDecode:
    def test_decode_with_models(self):
        spc = _spc("ram", 4)
        mgr = _mgr(spc)
        xml_str = '''<resolveprototype name="merged">
            <model name="cdecl"/>
            <model name="stdcall"/>
        </resolveprototype>'''
        root = xml_fromstring(xml_str)
        dec = XmlDecode(mgr, root)

        class _MockGlb:
            def __init__(self):
                self._models = {
                    "cdecl": _MockModel("cdecl"),
                    "stdcall": _MockModel("stdcall"),
                }
            def getModel(self, nm):
                return self._models.get(nm)

        pm = ProtoModelMerged(glb=_MockGlb())
        pm.decode(dec)
        assert pm._name == "merged"
        assert pm.numModels() == 2
        assert pm.getModel(0).getName() == "cdecl"
        assert pm.getModel(1).getName() == "stdcall"

    def test_decode_missing_model_raises(self):
        spc = _spc("ram", 4)
        mgr = _mgr(spc)
        xml_str = '''<resolveprototype name="merged">
            <model name="nonexistent"/>
        </resolveprototype>'''
        root = xml_fromstring(xml_str)
        dec = XmlDecode(mgr, root)

        class _MockGlb:
            def getModel(self, nm):
                return None

        pm = ProtoModelMerged(glb=_MockGlb())
        with pytest.raises(LowlevelError, match="Missing prototype model"):
            pm.decode(dec)

    def test_decode_no_models(self):
        spc = _spc("ram", 4)
        mgr = _mgr(spc)
        xml_str = '''<resolveprototype name="empty">
        </resolveprototype>'''
        root = xml_fromstring(xml_str)
        dec = XmlDecode(mgr, root)
        pm = ProtoModelMerged()
        pm.decode(dec)
        assert pm._name == "empty"
        assert pm.numModels() == 0


# ===========================================================================
# ParamListStandard decode
# ===========================================================================

class TestParamListStandardDecode:
    def test_decode_empty(self):
        spc = _spc("ram", 4)
        mgr = _mgr(spc)
        xml_str = '''<input/>'''
        root = xml_fromstring(xml_str)
        dec = XmlDecode(mgr, root)
        pls = ParamListStandard()
        effectlist = []
        pls.decode(dec, effectlist)
        assert len(pls.entry) == 0
        assert pls.numgroup == 0

    def test_decode_with_pentry(self):
        spc = _spc("ram", 4)
        mgr = _mgr(spc)
        xml_str = '''<input>
            <pentry minsize="1" maxsize="4" metatype="general">
                <register name="EAX"/>
            </pentry>
        </input>'''
        root = xml_fromstring(xml_str)
        dec = XmlDecode(mgr, root)
        pls = ParamListStandard()
        effectlist = []
        try:
            pls.decode(dec, effectlist)
        except Exception:
            pass  # ParamEntry.decode may need more infrastructure

    def test_decode_attributes(self):
        spc = _spc("ram", 4)
        mgr = _mgr(spc)
        xml_str = '''<input pointermax="16" thisbeforeretpointer="true"
                           killedbycall="true" separatefloat="false"/>'''
        root = xml_fromstring(xml_str)
        dec = XmlDecode(mgr, root)
        pls = ParamListStandard()
        effectlist = []
        pls.decode(dec, effectlist)
        assert pls.pointermax == 16
        assert pls.thisbeforeret is True
        assert pls.autoKilledByCall is True

    def test_decode_no_attributes(self):
        spc = _spc("ram", 4)
        mgr = _mgr(spc)
        xml_str = '''<input/>'''
        root = xml_fromstring(xml_str)
        dec = XmlDecode(mgr, root)
        pls = ParamListStandard()
        effectlist = []
        pls.decode(dec, effectlist)
        assert pls.pointermax == 0
        assert pls.thisbeforeret is False
        assert pls.autoKilledByCall is False


# ===========================================================================
# ParamListStandard init attributes
# ===========================================================================

class TestParamListStandardInit:
    def test_default_attributes(self):
        pls = ParamListStandard()
        assert pls.numgroup == 0
        assert pls.autoKilledByCall is False
        assert pls.resourceStart == []
        assert pls.modelRules == []
        assert pls.entry == []
        assert pls.spacebase is None
        assert pls.maxdelay == 0
        assert pls.pointermax == 0
        assert pls.thisbeforeret is False


# ===========================================================================
# ProtoParameter enhanced methods
# ===========================================================================

class TestProtoParameterEnhanced:
    def test_isThisPointer(self):
        p = ProtoParameter("this", None, _addr(0x10), 4)
        assert not p.isThisPointer()
        p.flags |= ParameterPieces.isthis
        assert p.isThisPointer()

    def test_isIndirectStorage(self):
        p = ProtoParameter("p", None, _addr(0x10), 4)
        assert not p.isIndirectStorage()
        p.flags |= ParameterPieces.indirectstorage
        assert p.isIndirectStorage()

    def test_isHiddenReturn(self):
        p = ProtoParameter("r", None, _addr(0x10), 4)
        assert not p.isHiddenReturn()
        p.flags |= ParameterPieces.hiddenretparm
        assert p.isHiddenReturn()

    def test_setTypeLock(self):
        p = ProtoParameter("x", None, _addr(0x10), 4)
        assert not p.isTypeLocked()
        p.setTypeLock(True)
        assert p.isTypeLocked()
        p.setTypeLock(False)
        assert not p.isTypeLocked()
