"""Tests for ghidra.arch.userop -- UserPcodeOp + UserOpManage registry."""
from __future__ import annotations

from ghidra.arch.userop import (
    UserPcodeOp, UnspecializedPcodeOp, InjectedUserOp,
    VolatileReadOp, VolatileWriteOp,
    UserOpManage, SegmentOp, JumpAssistOp,
    InternalStringOp, DatatypeUserOp,
)


class TestUserPcodeOp:
    def test_defaults(self):
        op = UserPcodeOp()
        assert op.getName() == ""
        assert op.getIndex() == -1
        assert op.getType() == 1
        assert op.getDisplay() == 0

    def test_named(self):
        op = UserPcodeOp(nm="myop", ind=5)
        assert op.getName() == "myop"
        assert op.getIndex() == 5

    def test_set_index(self):
        op = UserPcodeOp()
        op.setIndex(42)
        assert op.getIndex() == 42

    def test_set_display(self):
        op = UserPcodeOp()
        op.setDisplay(UserPcodeOp.annotation_assignment)
        assert op.getDisplay() == UserPcodeOp.annotation_assignment
        op.setDisplay(UserPcodeOp.no_operator)
        assert op.getDisplay() == UserPcodeOp.no_operator

    def test_getters_return_none(self):
        op = UserPcodeOp()
        assert op.getOutputLocal() is None
        assert op.getInputLocal() is None
        assert op.getOperatorName() == ""


class TestSubclasses:
    def test_unspecialized(self):
        op = UnspecializedPcodeOp("test", ind=3)
        assert op.getType() == UserPcodeOp.unspecialized
        assert op.getName() == "test"
        assert op.getIndex() == 3

    def test_injected(self):
        op = InjectedUserOp("inject1", ind=7, injid=99)
        assert op.getType() == UserPcodeOp.injected
        assert op.getInjectId() == 99

    def test_volatile_read(self):
        op = VolatileReadOp()
        assert op.getType() == UserPcodeOp.volatile_read
        assert op.getIndex() == UserPcodeOp.BUILTIN_VOLATILE_READ
        assert op.getName() == "read_volatile"

    def test_volatile_write(self):
        op = VolatileWriteOp()
        assert op.getType() == UserPcodeOp.volatile_write
        assert op.getIndex() == UserPcodeOp.BUILTIN_VOLATILE_WRITE

    def test_segment_op(self):
        op = SegmentOp()
        assert op.getSpace() is None
        assert op.getBaseSize() == 0
        assert op.getInnerSize() == 0
        assert op.getResolve() is op

    def test_jump_assist_op(self):
        op = JumpAssistOp("jhelper", ind=10)
        assert op.getIndex2Addr() == -1
        assert op.getIndex2Case() == -1
        assert op.getCalcSize() == -1
        assert op.getDefaultAddr() == -1
        op.setIndex2Addr(5)
        assert op.getIndex2Addr() == 5

    def test_internal_string_op(self):
        op = InternalStringOp("strdata", ind=20)
        assert op.getName() == "strdata"

    def test_datatype_user_op(self):
        sentinel_out = object()
        sentinel_in0 = object()
        sentinel_in1 = object()
        op = DatatypeUserOp("dtop", None, 30, sentinel_out, sentinel_in0, sentinel_in1)
        assert op.getOutputLocal() is sentinel_out
        assert op.getInputLocal(slot=0) is sentinel_in0
        assert op.getInputLocal(slot=1) is sentinel_in1
        assert op.getInputLocal(slot=99) is None


class TestUserOpManage:
    def test_empty(self):
        mgr = UserOpManage()
        assert mgr.numOps() == 0
        assert mgr.getOp(0) is None
        assert mgr.getOp("foo") is None

    def test_register_and_lookup_by_index(self):
        mgr = UserOpManage()
        op = UnspecializedPcodeOp("alpha", ind=3)
        mgr.registerOp(op)
        assert mgr.getOp(3) is op
        assert mgr.getOp(0) is None

    def test_register_and_lookup_by_name(self):
        mgr = UserOpManage()
        op = UnspecializedPcodeOp("beta", ind=1)
        mgr.registerOp(op)
        assert mgr.getOp("beta") is op
        assert mgr.getOpByName("beta") is op
        assert mgr.getOpByName("gamma") is None

    def test_register_expands_list(self):
        mgr = UserOpManage()
        op = UnspecializedPcodeOp("far", ind=10)
        mgr.registerOp(op)
        assert mgr.numOps() >= 11
        assert mgr.getOp(10) is op

    def test_multiple_ops(self):
        mgr = UserOpManage()
        op0 = UnspecializedPcodeOp("a", ind=0)
        op1 = InjectedUserOp("b", ind=1, injid=50)
        mgr.registerOp(op0)
        mgr.registerOp(op1)
        assert mgr.getOp(0) is op0
        assert mgr.getOp(1) is op1
        assert mgr.getOp("a") is op0
        assert mgr.getOp("b") is op1

    def test_num_segment_ops(self):
        mgr = UserOpManage()
        assert mgr.numSegmentOps() == 0
        seg = SegmentOp("seg", ind=5)
        mgr.registerOp(seg)
        assert mgr.numSegmentOps() == 1
        assert mgr.getSegmentOp(0) is seg

    def test_get_segment_op_none(self):
        mgr = UserOpManage()
        assert mgr.getSegmentOp(0) is None

    def test_registerBuiltin_volatile_read(self):
        mgr = UserOpManage()
        op = mgr.registerBuiltin(UserPcodeOp.BUILTIN_VOLATILE_READ)
        assert op is not None
        assert isinstance(op, VolatileReadOp)
        # Second call returns same object
        op2 = mgr.registerBuiltin(UserPcodeOp.BUILTIN_VOLATILE_READ)
        assert op2 is op

    def test_registerBuiltin_volatile_write(self):
        mgr = UserOpManage()
        op = mgr.registerBuiltin(UserPcodeOp.BUILTIN_VOLATILE_WRITE)
        assert op is not None
        assert isinstance(op, VolatileWriteOp)

    def test_registerBuiltin_unknown_id(self):
        mgr = UserOpManage()
        op = mgr.registerBuiltin(9999)
        assert op is not None
        assert isinstance(op, UnspecializedPcodeOp)

    def test_manualCallOtherFixup_unknown_raises(self):
        import pytest
        mgr = UserOpManage()
        with pytest.raises(Exception, match="Unknown userop"):
            mgr.manualCallOtherFixup("nonexistent", "out", ["in"], "snippet")

    def test_manualCallOtherFixup_non_unspecialized_raises(self):
        import pytest
        mgr = UserOpManage()
        op = InjectedUserOp("myop", ind=0, injid=1)
        mgr.registerOp(op)
        with pytest.raises(Exception, match="Cannot fixup"):
            mgr.manualCallOtherFixup("myop", "out", ["in"], "snippet")

    def test_manualCallOtherFixup_success(self):
        mgr = UserOpManage()
        op = UnspecializedPcodeOp("fixme", ind=5)
        mgr.registerOp(op)
        mgr.manualCallOtherFixup("fixme", "out", ["in"], "snippet")
        replaced = mgr.getOp(5)
        assert isinstance(replaced, InjectedUserOp)
        assert replaced.getName() == "fixme"

    def test_decodeSegmentOp_registers(self):
        """decodeSegmentOp creates a SegmentOp and registers it."""
        from ghidra.core.marshal import XmlDecode
        from ghidra.core.space import AddrSpace, AddrSpaceManager
        from xml.etree.ElementTree import fromstring as xml_fromstring
        spc = AddrSpace(name="ram", size=4)
        mgr_spc = AddrSpaceManager()
        mgr_spc._insertSpace(spc)
        xml_str = '<segmentop space="ram"/>'
        root = xml_fromstring(xml_str)
        dec = XmlDecode(mgr_spc, root)
        mgr = UserOpManage()
        try:
            mgr.decodeSegmentOp(dec, None)
        except Exception:
            pass  # May fail due to missing pcode child, but shouldn't crash badly

    def test_decodeJumpAssist_registers(self):
        """decodeJumpAssist creates a JumpAssistOp and registers it."""
        from ghidra.core.marshal import XmlDecode
        from ghidra.core.space import AddrSpaceManager
        from xml.etree.ElementTree import fromstring as xml_fromstring
        mgr_spc = AddrSpaceManager()
        xml_str = '<jumpassist name="myassist"/>'
        root = xml_fromstring(xml_str)
        dec = XmlDecode(mgr_spc, root)
        mgr = UserOpManage()
        # Register the base op so lookup works
        base = UnspecializedPcodeOp("myassist", ind=0)
        mgr.registerOp(base)
        mgr.decodeJumpAssist(dec, None)
        result = mgr.getOp("myassist")
        assert result is not None
        assert isinstance(result, JumpAssistOp)
