"""Tests for ghidra.transform.unify — constraint unification system."""
from __future__ import annotations

import io
from types import SimpleNamespace

from ghidra.transform.unify import (
    UnifyDatatype, UnifyState,
    RHSConstant, ConstantNamed, ConstantAbsolute,
    ConstantNZMask, ConstantConsumed, ConstantOffset,
    ConstantIsConstant, ConstantHeritageKnown, ConstantVarnodeSize,
    TraverseConstraint, TraverseCountState, TraverseDescendState, TraverseGroupState,
    UnifyConstraint,
    DummyOpConstraint, DummyVarnodeConstraint, DummyConstConstraint,
    ConstraintBoolean, ConstraintVarConst, ConstraintNamedExpression,
    ConstraintOpCopy, ConstraintOpcode, ConstraintOpCompare,
    ConstraintOpInput, ConstraintOpInputAny, ConstraintOpOutput,
    ConstraintParamConstVal, ConstraintParamConst,
    ConstraintVarnodeCopy, ConstraintVarCompare,
    ConstraintDef, ConstraintDescend, ConstraintLoneDescend, ConstraintOtherInput,
    ConstraintGroup, ConstraintOr,
    ConstraintNewOp, ConstraintNewUniqueOut,
    ConstraintSetInput, ConstraintSetInputConstVal,
    ConstraintRemoveInput, ConstraintSetOpcode,
    UnifyCPrinter,
)


# ---------------------------------------------------------------------------
# Helpers — lightweight mocks for IR objects
# ---------------------------------------------------------------------------

def _make_vn(*, offset=0, size=4, is_const=False, is_written=False,
             nzmask=0xFFFFFFFF, consume=0xFFFF, heritage_known=True,
             def_op=None, descend=None):
    """Create a minimal varnode-like object."""
    vn = SimpleNamespace(
        getOffset=lambda: offset, getSize=lambda: size,
        isConstant=lambda: is_const, isWritten=lambda: is_written,
        getNZMask=lambda: nzmask, getConsume=lambda: consume,
        isHeritageKnown=lambda: heritage_known,
        getDef=lambda: def_op,
        loneDescend=lambda: descend[0] if descend and len(descend) == 1 else None,
        getDescend=lambda: descend or [],
    )
    return vn


def _make_op(code=10, inputs=None, output=None, addr=0x1000):
    """Create a minimal PcodeOp-like object."""
    _inputs = inputs or []
    op = SimpleNamespace(
        code=lambda: code,
        numInput=lambda: len(_inputs),
        getIn=lambda i: _inputs[i],
        getOut=lambda: output,
        getAddr=lambda: addr,
    )
    # getSlot: find which slot a particular varnode occupies
    op.getSlot = lambda vn: _inputs.index(vn)
    return op


# ---------------------------------------------------------------------------
# UnifyDatatype
# ---------------------------------------------------------------------------

class TestUnifyDatatype:
    def test_default_type(self):
        ud = UnifyDatatype()
        assert ud.getType() == UnifyDatatype.op_type

    def test_set_op(self):
        ud = UnifyDatatype()
        sentinel = object()
        ud.setOp(sentinel)
        assert ud.getType() == UnifyDatatype.op_type
        assert ud.getOp() is sentinel

    def test_set_varnode(self):
        ud = UnifyDatatype()
        sentinel = object()
        ud.setVarnode(sentinel)
        assert ud.getType() == UnifyDatatype.var_type
        assert ud.getVarnode() is sentinel

    def test_set_block(self):
        ud = UnifyDatatype()
        sentinel = object()
        ud.setBlock(sentinel)
        assert ud.getType() == UnifyDatatype.block_type
        assert ud.getBlock() is sentinel

    def test_set_constant(self):
        ud = UnifyDatatype()
        ud.setConstant(42)
        assert ud.getType() == UnifyDatatype.const_type
        assert ud.getConstant() == 42

    def test_base_names(self):
        assert UnifyDatatype(UnifyDatatype.op_type).getBaseName() == "op"
        assert UnifyDatatype(UnifyDatatype.var_type).getBaseName() == "vn"
        assert UnifyDatatype(UnifyDatatype.const_type).getBaseName() == "cn"
        assert UnifyDatatype(UnifyDatatype.block_type).getBaseName() == "bl"

    def test_print_var_decl(self):
        printer = SimpleNamespace(
            printIndent=lambda s: s.write("  "),
            getName=lambda i: f"slot{i}")
        buf = io.StringIO()
        UnifyDatatype(UnifyDatatype.op_type).printVarDecl(buf, 0, printer)
        assert "PcodeOp *" in buf.getvalue()
        buf = io.StringIO()
        UnifyDatatype(UnifyDatatype.var_type).printVarDecl(buf, 1, printer)
        assert "Varnode *" in buf.getvalue()


# ---------------------------------------------------------------------------
# TraverseConstraint hierarchy
# ---------------------------------------------------------------------------

class TestTraverseCountState:
    def test_step_once(self):
        t = TraverseCountState(0)
        t.initialize(1)
        assert t.step() is True
        assert t.getState() == 0
        assert t.step() is False

    def test_step_multiple(self):
        t = TraverseCountState(0)
        t.initialize(3)
        for i in range(3):
            assert t.step() is True
            assert t.getState() == i
        assert t.step() is False


class TestTraverseDescendState:
    def test_iterate(self):
        op1 = _make_op(code=1)
        op2 = _make_op(code=2)
        vn = _make_vn(descend=[op1, op2])
        t = TraverseDescendState(0)
        t.initialize(vn)
        assert t.step() is True
        assert t.getCurrentOp() is op1
        assert t.step() is True
        assert t.getCurrentOp() is op2
        assert t.step() is False


class TestTraverseGroupState:
    def test_basic(self):
        tg = TraverseGroupState(0)
        sub = TraverseCountState(1)
        tg.addTraverse(sub)
        assert tg.getSubTraverse(0) is sub
        tg.setCurrentIndex(5)
        assert tg.getCurrentIndex() == 5
        tg.setState(1)
        assert tg.getState() == 1


# ---------------------------------------------------------------------------
# UnifyState
# ---------------------------------------------------------------------------

class TestUnifyState:
    def test_empty(self):
        s = UnifyState()
        assert s.size() == 0

    def test_data_auto_expands(self):
        s = UnifyState()
        d = s.data(10)
        assert isinstance(d, UnifyDatatype)
        assert s.size() >= 11

    def test_set_and_get(self):
        s = UnifyState()
        s.data(1)  # ensure size
        ud = UnifyDatatype()
        ud.setConstant(99)
        s.setData(1, ud)
        assert s.getData(1).getConstant() == 99

    def test_resize(self):
        s = UnifyState()
        s.data(9)
        s.resize(3)
        assert s.size() == 3

    def test_clear(self):
        s = UnifyState()
        s.data(4)
        s.clear()
        assert s.size() == 0
        assert s.getFunction() is None

    def test_set_function(self):
        s = UnifyState()
        sentinel = object()
        s.setFunction(sentinel)
        assert s.getFunction() is sentinel

    def test_initialize_varnode(self):
        s = UnifyState()
        s.data(0)
        vn = _make_vn()
        s.initializeVarnode(0, vn)
        assert s.data(0).getVarnode() is vn

    def test_initialize_op(self):
        s = UnifyState()
        s.data(0)
        op = _make_op()
        s.initializeOp(0, op)
        assert s.data(0).getOp() is op


# ---------------------------------------------------------------------------
# RHSConstant hierarchy
# ---------------------------------------------------------------------------

class TestConstantAbsolute:
    def test_value(self):
        c = ConstantAbsolute(42)
        assert c.getConstant(UnifyState()) == 42
        assert c.getVal() == 42

    def test_clone(self):
        c = ConstantAbsolute(100)
        c2 = c.clone()
        assert c2.getConstant(UnifyState()) == 100
        assert c2 is not c

    def test_write_expression(self):
        c = ConstantAbsolute(0xFF)
        buf = io.StringIO()
        c.writeExpression(buf, None)
        assert "ff" in buf.getvalue()


class TestConstantNamed:
    def test_get_constant(self):
        state = UnifyState()
        state.data(2).setConstant(77)
        c = ConstantNamed(2)
        assert c.getConstant(state) == 77

    def test_clone(self):
        c = ConstantNamed(5)
        c2 = c.clone()
        assert c2.getId() == 5
        assert c2 is not c


class TestConstantVarnodeProperties:
    def test_nzmask(self):
        state = UnifyState()
        state.data(0).setVarnode(_make_vn(nzmask=0xABCD))
        assert ConstantNZMask(0).getConstant(state) == 0xABCD

    def test_consumed(self):
        state = UnifyState()
        state.data(0).setVarnode(_make_vn(consume=0x1234))
        assert ConstantConsumed(0).getConstant(state) == 0x1234

    def test_offset(self):
        state = UnifyState()
        state.data(0).setVarnode(_make_vn(offset=0x400))
        assert ConstantOffset(0).getConstant(state) == 0x400

    def test_is_constant(self):
        state = UnifyState()
        state.data(0).setVarnode(_make_vn(is_const=True))
        assert ConstantIsConstant(0).getConstant(state) == 1
        state.data(1).setVarnode(_make_vn(is_const=False))
        assert ConstantIsConstant(1).getConstant(state) == 0

    def test_heritage_known(self):
        state = UnifyState()
        state.data(0).setVarnode(_make_vn(heritage_known=True))
        assert ConstantHeritageKnown(0).getConstant(state) == 1

    def test_varnode_size(self):
        state = UnifyState()
        state.data(0).setVarnode(_make_vn(size=8))
        assert ConstantVarnodeSize(0).getConstant(state) == 8

    def test_clones(self):
        for cls, idx in [(ConstantNZMask, 0), (ConstantConsumed, 1),
                         (ConstantOffset, 2), (ConstantIsConstant, 3),
                         (ConstantHeritageKnown, 4), (ConstantVarnodeSize, 5)]:
            c = cls(idx)
            c2 = c.clone()
            assert type(c2) is cls
            assert c2 is not c


# ---------------------------------------------------------------------------
# UnifyConstraint base
# ---------------------------------------------------------------------------

class TestUnifyConstraint:
    def test_default_step_false(self):
        c = UnifyConstraint()
        # Need traverse state first
        state = UnifyState()
        state.registerTraverseConstraint(TraverseCountState(0))
        c.initialize(state)
        assert c.step(state) is False

    def test_set_id(self):
        c = UnifyConstraint()
        box = [5]
        c.setId(box)
        assert c.getId() == 5
        assert box[0] == 6

    def test_copy_id(self):
        c1 = UnifyConstraint()
        c1._uniqid = 3
        c1._maxnum = 7
        c2 = UnifyConstraint()
        c2._copyid(c1)
        assert c2.getId() == 3
        assert c2.getMaxNum() == 7


# ---------------------------------------------------------------------------
# Dummy constraints
# ---------------------------------------------------------------------------

class TestDummyConstraints:
    def test_dummy_op(self):
        d = DummyOpConstraint(2)
        assert d.isDummy() is True
        assert d.getBaseIndex() == 2
        typelist = [UnifyDatatype() for _ in range(3)]
        d.collectTypes(typelist)
        assert typelist[2].getType() == UnifyDatatype.op_type

    def test_dummy_varnode(self):
        d = DummyVarnodeConstraint(1)
        assert d.isDummy() is True
        typelist = [UnifyDatatype() for _ in range(2)]
        d.collectTypes(typelist)
        assert typelist[1].getType() == UnifyDatatype.var_type

    def test_dummy_const(self):
        d = DummyConstConstraint(0)
        assert d.isDummy() is True
        typelist = [UnifyDatatype()]
        d.collectTypes(typelist)
        assert typelist[0].getType() == UnifyDatatype.const_type

    def test_clones(self):
        for cls, arg in [(DummyOpConstraint, 0), (DummyVarnodeConstraint, 1),
                         (DummyConstConstraint, 2)]:
            c = cls(arg)
            c2 = c.clone()
            assert type(c2) is cls
            assert c2 is not c


# ---------------------------------------------------------------------------
# Pattern-matching constraints with mock IR
# ---------------------------------------------------------------------------

def _build_state_with_traverse(n_slots: int, n_traverse: int):
    """Build a UnifyState manually (no container)."""
    s = UnifyState()
    for _ in range(n_slots):
        s.data(n_slots - 1)
    for i in range(n_traverse):
        s.registerTraverseConstraint(TraverseCountState(i))
    return s


class TestConstraintOpcode:
    def test_match(self):
        op = _make_op(code=42)
        state = _build_state_with_traverse(1, 1)
        state.data(0).setOp(op)
        c = ConstraintOpcode(0, [42])
        c._uniqid = 0
        c.initialize(state)
        assert c.step(state) is True

    def test_no_match(self):
        op = _make_op(code=99)
        state = _build_state_with_traverse(1, 1)
        state.data(0).setOp(op)
        c = ConstraintOpcode(0, [42])
        c._uniqid = 0
        c.initialize(state)
        assert c.step(state) is False

    def test_multi_opcodes(self):
        op = _make_op(code=55)
        state = _build_state_with_traverse(1, 1)
        state.data(0).setOp(op)
        c = ConstraintOpcode(0, [42, 55, 60])
        c._uniqid = 0
        c.initialize(state)
        assert c.step(state) is True

    def test_clone(self):
        c = ConstraintOpcode(0, [1, 2])
        c2 = c.clone()
        assert isinstance(c2, ConstraintOpcode)
        assert c2.getOpCodes() == [1, 2]


class TestConstraintOpCompare:
    def test_same_true(self):
        op = _make_op()
        state = _build_state_with_traverse(2, 1)
        state.data(0).setOp(op)
        state.data(1).setOp(op)
        c = ConstraintOpCompare(0, 1, True)
        c._uniqid = 0
        c.initialize(state)
        assert c.step(state) is True

    def test_same_false(self):
        op1 = _make_op()
        op2 = _make_op()
        state = _build_state_with_traverse(2, 1)
        state.data(0).setOp(op1)
        state.data(1).setOp(op2)
        c = ConstraintOpCompare(0, 1, True)
        c._uniqid = 0
        c.initialize(state)
        assert c.step(state) is False


class TestConstraintOpInput:
    def test_get_input(self):
        vn0 = _make_vn(offset=100)
        vn1 = _make_vn(offset=200)
        op = _make_op(inputs=[vn0, vn1])
        state = _build_state_with_traverse(3, 1)
        state.data(0).setOp(op)
        c = ConstraintOpInput(0, 2, 1)
        c._uniqid = 0
        c.initialize(state)
        assert c.step(state) is True
        assert state.data(2).getVarnode() is vn1


class TestConstraintOpOutput:
    def test_get_output(self):
        out_vn = _make_vn(offset=300)
        op = _make_op(output=out_vn)
        state = _build_state_with_traverse(2, 1)
        state.data(0).setOp(op)
        c = ConstraintOpOutput(0, 1)
        c._uniqid = 0
        c.initialize(state)
        assert c.step(state) is True
        assert state.data(1).getVarnode() is out_vn


class TestConstraintOpCopy:
    def test_copy(self):
        op = _make_op()
        state = _build_state_with_traverse(2, 1)
        state.data(0).setOp(op)
        c = ConstraintOpCopy(0, 1)
        c._uniqid = 0
        c.initialize(state)
        assert c.step(state) is True
        assert state.data(1).getOp() is op


class TestConstraintVarnodeCopy:
    def test_copy(self):
        vn = _make_vn()
        state = _build_state_with_traverse(2, 1)
        state.data(0).setVarnode(vn)
        c = ConstraintVarnodeCopy(0, 1)
        c._uniqid = 0
        c.initialize(state)
        assert c.step(state) is True
        assert state.data(1).getVarnode() is vn


class TestConstraintVarCompare:
    def test_same(self):
        vn = _make_vn()
        state = _build_state_with_traverse(2, 1)
        state.data(0).setVarnode(vn)
        state.data(1).setVarnode(vn)
        c = ConstraintVarCompare(0, 1, True)
        c._uniqid = 0
        c.initialize(state)
        assert c.step(state) is True

    def test_different(self):
        vn1, vn2 = _make_vn(), _make_vn()
        state = _build_state_with_traverse(2, 1)
        state.data(0).setVarnode(vn1)
        state.data(1).setVarnode(vn2)
        c = ConstraintVarCompare(0, 1, False)
        c._uniqid = 0
        c.initialize(state)
        assert c.step(state) is True


class TestConstraintDef:
    def test_written(self):
        def_op = _make_op(code=5)
        vn = _make_vn(is_written=True, def_op=def_op)
        state = _build_state_with_traverse(2, 1)
        state.data(1).setVarnode(vn)
        c = ConstraintDef(0, 1)
        c._uniqid = 0
        c.initialize(state)
        assert c.step(state) is True
        assert state.data(0).getOp() is def_op

    def test_not_written(self):
        vn = _make_vn(is_written=False)
        state = _build_state_with_traverse(2, 1)
        state.data(1).setVarnode(vn)
        c = ConstraintDef(0, 1)
        c._uniqid = 0
        c.initialize(state)
        assert c.step(state) is False


class TestConstraintLoneDescend:
    def test_lone(self):
        user_op = _make_op(code=7)
        vn = _make_vn(descend=[user_op])
        state = _build_state_with_traverse(2, 1)
        state.data(1).setVarnode(vn)
        c = ConstraintLoneDescend(0, 1)
        c._uniqid = 0
        c.initialize(state)
        assert c.step(state) is True
        assert state.data(0).getOp() is user_op

    def test_no_descend(self):
        vn = _make_vn(descend=[])
        state = _build_state_with_traverse(2, 1)
        state.data(1).setVarnode(vn)
        c = ConstraintLoneDescend(0, 1)
        c._uniqid = 0
        c.initialize(state)
        assert c.step(state) is False


class TestConstraintOtherInput:
    def test_other(self):
        vn0 = _make_vn(offset=100)
        vn1 = _make_vn(offset=200)
        op = _make_op(inputs=[vn0, vn1])
        state = _build_state_with_traverse(3, 1)
        state.data(0).setOp(op)
        state.data(1).setVarnode(vn0)
        c = ConstraintOtherInput(0, 1, 2)
        c._uniqid = 0
        c.initialize(state)
        assert c.step(state) is True
        assert state.data(2).getVarnode() is vn1


class TestConstraintParamConstVal:
    def test_match(self):
        cvn = _make_vn(offset=42, size=4, is_const=True)
        op = _make_op(inputs=[cvn])
        state = _build_state_with_traverse(1, 1)
        state.data(0).setOp(op)
        c = ConstraintParamConstVal(0, 0, 42)
        c._uniqid = 0
        c.initialize(state)
        assert c.step(state) is True

    def test_no_match_value(self):
        cvn = _make_vn(offset=99, size=4, is_const=True)
        op = _make_op(inputs=[cvn])
        state = _build_state_with_traverse(1, 1)
        state.data(0).setOp(op)
        c = ConstraintParamConstVal(0, 0, 42)
        c._uniqid = 0
        c.initialize(state)
        assert c.step(state) is False

    def test_not_constant(self):
        vn = _make_vn(is_const=False)
        op = _make_op(inputs=[vn])
        state = _build_state_with_traverse(1, 1)
        state.data(0).setOp(op)
        c = ConstraintParamConstVal(0, 0, 0)
        c._uniqid = 0
        c.initialize(state)
        assert c.step(state) is False


class TestConstraintParamConst:
    def test_extract(self):
        cvn = _make_vn(offset=0xBEEF, is_const=True)
        op = _make_op(inputs=[cvn])
        state = _build_state_with_traverse(2, 1)
        state.data(0).setOp(op)
        c = ConstraintParamConst(0, 0, 1)
        c._uniqid = 0
        c.initialize(state)
        assert c.step(state) is True
        assert state.data(1).getConstant() == 0xBEEF


class TestConstraintNamedExpression:
    def test_store(self):
        state = _build_state_with_traverse(2, 1)
        state.data(0).setConstant(10)
        expr = ConstantNamed(0)
        c = ConstraintNamedExpression(1, expr)
        c._uniqid = 0
        c.initialize(state)
        assert c.step(state) is True
        assert state.data(1).getConstant() == 10


# ---------------------------------------------------------------------------
# ConstraintGroup
# ---------------------------------------------------------------------------

class TestConstraintGroup:
    def _make_group(self):
        """Build a group: check opcode=42 at slot 0, then get input 0 -> slot 1."""
        g = ConstraintGroup()
        g.addConstraint(ConstraintOpcode(0, [42]))
        g.addConstraint(ConstraintOpInput(0, 1, 0))
        id_box = [0]
        g.setId(id_box)
        return g

    def test_match(self):
        vn = _make_vn(offset=0x100)
        op = _make_op(code=42, inputs=[vn])
        g = self._make_group()
        state = UnifyState(g)
        state.data(0).setOp(op)
        g.initialize(state)
        assert g.step(state) is True
        assert state.data(1).getVarnode() is vn

    def test_no_match(self):
        op = _make_op(code=99, inputs=[_make_vn()])
        g = self._make_group()
        state = UnifyState(g)
        state.data(0).setOp(op)
        g.initialize(state)
        assert g.step(state) is False

    def test_clone(self):
        g = self._make_group()
        g2 = g.clone()
        assert g2 is not g
        assert g2.numConstraints() == 2

    def test_merge_in(self):
        g1 = ConstraintGroup()
        g1.addConstraint(ConstraintOpcode(0, [1]))
        g2 = ConstraintGroup()
        g2.addConstraint(ConstraintOpcode(1, [2]))
        g1.mergeIn(g2)
        assert g1.numConstraints() == 2

    def test_remove_dummy(self):
        g = ConstraintGroup()
        g.addConstraint(DummyOpConstraint(0))
        g.addConstraint(ConstraintOpcode(0, [42]))
        g.removeDummy()
        assert g.numConstraints() == 1


# ---------------------------------------------------------------------------
# ConstraintOr
# ---------------------------------------------------------------------------

class TestConstraintOr:
    def test_or_first_matches(self):
        # Two alternatives: code=42 or code=55
        g1 = ConstraintGroup()
        g1.addConstraint(ConstraintOpcode(0, [42]))
        g2 = ConstraintGroup()
        g2.addConstraint(ConstraintOpcode(0, [55]))
        cor = ConstraintOr()
        cor.addConstraint(g1)
        cor.addConstraint(g2)
        id_box = [0]
        cor.setId(id_box)
        state = UnifyState(cor)
        op = _make_op(code=42)
        state.data(0).setOp(op)
        cor.initialize(state)
        assert cor.step(state) is True

    def test_or_second_matches(self):
        g1 = ConstraintGroup()
        g1.addConstraint(ConstraintOpcode(0, [42]))
        g2 = ConstraintGroup()
        g2.addConstraint(ConstraintOpcode(0, [55]))
        cor = ConstraintOr()
        cor.addConstraint(g1)
        cor.addConstraint(g2)
        id_box = [0]
        cor.setId(id_box)
        state = UnifyState(cor)
        op = _make_op(code=55)
        state.data(0).setOp(op)
        cor.initialize(state)
        assert cor.step(state) is True

    def test_or_none_matches(self):
        g1 = ConstraintGroup()
        g1.addConstraint(ConstraintOpcode(0, [42]))
        g2 = ConstraintGroup()
        g2.addConstraint(ConstraintOpcode(0, [55]))
        cor = ConstraintOr()
        cor.addConstraint(g1)
        cor.addConstraint(g2)
        id_box = [0]
        cor.setId(id_box)
        state = UnifyState(cor)
        op = _make_op(code=99)
        state.data(0).setOp(op)
        cor.initialize(state)
        assert cor.step(state) is False


# ---------------------------------------------------------------------------
# UnifyCPrinter
# ---------------------------------------------------------------------------

class TestUnifyCPrinter:
    def test_basic_print(self):
        g = ConstraintGroup()
        g.addConstraint(DummyOpConstraint(0))
        id_box = [0]
        g.setId(id_box)
        printer = UnifyCPrinter()
        printer.initializeBasic(g)
        buf = io.StringIO()
        printer.print(buf)
        txt = buf.getvalue()
        assert "return true;" in txt

    def test_name_override(self):
        g = ConstraintGroup()
        g.addConstraint(DummyOpConstraint(0))
        id_box = [0]
        g.setId(id_box)
        printer = UnifyCPrinter()
        printer.initializeBasic(g)
        printer.addNames({"myOp": 0})
        assert printer.getName(0) == "myOp"

    def test_indent_and_abort(self):
        printer = UnifyCPrinter()
        printer._printingtype = 0
        printer._depth = 0
        buf = io.StringIO()
        printer.printAbort(buf)
        assert "return 0;" in buf.getvalue()
