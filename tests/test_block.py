"""Tests for ghidra.block.block -- FlowBlock, BlockBasic, BlockGraph, structured blocks."""
from __future__ import annotations

import io

from ghidra.block.block import (
    BlockEdge, FlowBlock, BlockBasic, BlockGraph,
    BlockCopy, BlockGoto, BlockCondition, BlockIf,
    BlockWhileDo, BlockDoWhile, BlockInfLoop, BlockSwitch, BlockList,
    BlockMultiGoto,
)
from ghidra.core.address import Address
from ghidra.core.space import AddrSpace


def _spc():
    return AddrSpace(name="ram", size=4)


# ---------------------------------------------------------------------------
# BlockEdge
# ---------------------------------------------------------------------------

class TestBlockEdge:
    def test_defaults(self):
        e = BlockEdge()
        assert e.label == 0
        assert e.point is None
        assert e.reverse_index == 0

    def test_construction(self):
        fb = FlowBlock()
        e = BlockEdge(fb, lab=5, rev=2)
        assert e.point is fb
        assert e.label == 5
        assert e.reverse_index == 2


# ---------------------------------------------------------------------------
# FlowBlock basics
# ---------------------------------------------------------------------------

class TestFlowBlock:
    def test_defaults(self):
        fb = FlowBlock()
        assert fb.getIndex() == 0
        assert fb.getParent() is None
        assert fb.getImmedDom() is None
        assert fb.sizeIn() == 0
        assert fb.sizeOut() == 0
        assert fb.getFlags() == 0

    def test_set_flag(self):
        fb = FlowBlock()
        fb.setFlag(FlowBlock.f_entry_point)
        assert fb.isEntryPoint()
        fb.clearFlag(FlowBlock.f_entry_point)
        assert not fb.isEntryPoint()

    def test_mark(self):
        fb = FlowBlock()
        assert not fb.isMark()
        fb.setMark()
        assert fb.isMark()
        fb.clearMark()
        assert not fb.isMark()

    def test_type_constants(self):
        assert FlowBlock.t_plain == 0
        assert FlowBlock.t_basic == 1
        assert FlowBlock.t_graph == 2
        assert FlowBlock.t_copy == 3
        assert FlowBlock.t_if == 8
        assert FlowBlock.t_whiledo == 9
        assert FlowBlock.t_dowhile == 10
        assert FlowBlock.t_switch == 11
        assert FlowBlock.t_infloop == 12


class TestFlowBlockEdgeOps:
    def test_add_in_edge(self):
        a = FlowBlock()
        b = FlowBlock()
        b.addInEdge(a)
        assert b.sizeIn() == 1
        assert b.getIn(0) is a
        assert a.sizeOut() == 1
        assert a.getOut(0) is b

    def test_reverse_index_consistency(self):
        a = FlowBlock()
        b = FlowBlock()
        c = FlowBlock()
        b.addInEdge(a)
        b.addInEdge(c)
        assert b.getInRevIndex(0) == 0
        assert b.getInRevIndex(1) == 0
        assert a.getOutRevIndex(0) == 0
        assert c.getOutRevIndex(0) == 1

    def test_remove_in_edge(self):
        a = FlowBlock()
        b = FlowBlock()
        c = FlowBlock()
        c.addInEdge(a)
        c.addInEdge(b)
        assert c.sizeIn() == 2
        c.removeInEdge(0)
        assert c.sizeIn() == 1
        assert c.getIn(0) is b

    def test_swap_edges(self):
        src = FlowBlock()
        t1 = FlowBlock()
        t2 = FlowBlock()
        t1.addInEdge(src)
        t2.addInEdge(src)
        assert src.getOut(0) is t1
        assert src.getOut(1) is t2
        src.swapEdges()
        assert src.getOut(0) is t2
        assert src.getOut(1) is t1

    def test_get_in_index(self):
        a = FlowBlock()
        b = FlowBlock()
        c = FlowBlock()
        c.addInEdge(a)
        c.addInEdge(b)
        assert c.getInIndex(a) == 0
        assert c.getInIndex(b) == 1
        assert c.getInIndex(c) == -1

    def test_get_out_index(self):
        a = FlowBlock()
        b = FlowBlock()
        c = FlowBlock()
        b.addInEdge(a)
        c.addInEdge(a)
        assert a.getOutIndex(b) == 0
        assert a.getOutIndex(c) == 1
        assert a.getOutIndex(a) == -1

    def test_edge_flags(self):
        a = FlowBlock()
        b = FlowBlock()
        b.addInEdge(a)
        a.setOutEdgeFlag(0, FlowBlock.f_loop_edge)
        assert a.isLoopOut(0)
        assert b.isLoopIn(0)
        a.clearOutEdgeFlag(0, FlowBlock.f_loop_edge)
        assert not a.isLoopOut(0)


class TestFlowBlockHelpers:
    def test_type_to_name(self):
        assert FlowBlock.typeToName(FlowBlock.t_basic) == "basic"
        assert FlowBlock.typeToName(FlowBlock.t_graph) == "graph"
        assert FlowBlock.typeToName(FlowBlock.t_if) == "properif"
        assert FlowBlock.typeToName(FlowBlock.t_whiledo) == "whiledo"
        assert FlowBlock.typeToName(FlowBlock.t_switch) == "switch"
        assert FlowBlock.typeToName(999) == ""

    def test_name_to_type(self):
        assert FlowBlock.nameToType("graph") == FlowBlock.t_graph
        assert FlowBlock.nameToType("copy") == FlowBlock.t_copy
        assert FlowBlock.nameToType("unknown") == FlowBlock.t_plain

    def test_compare_block_index(self):
        a = FlowBlock()
        b = FlowBlock()
        a._index = 1
        b._index = 5
        assert FlowBlock.compareBlockIndex(a, b)
        assert not FlowBlock.compareBlockIndex(b, a)

    def test_print_tree(self):
        fb = FlowBlock()
        fb._index = 42
        buf = io.StringIO()
        fb.printTree(buf, 0)
        assert "42" in buf.getvalue()

    def test_dominates(self):
        a = FlowBlock()
        b = FlowBlock()
        a._index = 0
        b._index = 1
        b._immed_dom = a
        assert a.dominates(b)
        assert not b.dominates(a)

    def test_calc_depth(self):
        a = FlowBlock()
        b = FlowBlock()
        c = FlowBlock()
        a._index = 0
        b._index = 1
        c._index = 2
        b._parent = a
        c._parent = b
        assert a.calcDepth(c) == 2
        assert a.calcDepth(b) == 1
        assert a.calcDepth(a) == 0

    def test_get_front_leaf(self):
        fb = FlowBlock()
        assert fb.getFrontLeaf() is None  # t_plain has no subBlock

    def test_has_loop_in_out(self):
        a = FlowBlock()
        b = FlowBlock()
        b.addInEdge(a)
        assert not a.hasLoopOut()
        assert not b.hasLoopIn()
        a.setOutEdgeFlag(0, FlowBlock.f_loop_edge)
        assert a.hasLoopOut()
        assert b.hasLoopIn()


# ---------------------------------------------------------------------------
# BlockBasic
# ---------------------------------------------------------------------------

class TestBlockBasic:
    def test_type(self):
        bb = BlockBasic()
        assert bb.getType() == FlowBlock.t_basic

    def test_ops(self):
        bb = BlockBasic()
        assert bb.emptyOp()

        class _FakeOp:
            def __init__(self): self._parent = None
            def setParent(self, p): self._parent = p

        op = _FakeOp()
        bb.addOp(op)
        assert not bb.emptyOp()
        assert bb.firstOp() is op
        assert bb.lastOp() is op

    def test_exit_leaf(self):
        bb = BlockBasic()
        assert bb.getExitLeaf() is bb

    def test_sub_block_none(self):
        bb = BlockBasic()
        assert bb.subBlock(0) is None


# ---------------------------------------------------------------------------
# BlockGraph
# ---------------------------------------------------------------------------

class TestBlockGraph:
    def test_type(self):
        bg = BlockGraph()
        assert bg.getType() == FlowBlock.t_graph

    def test_add_block(self):
        bg = BlockGraph()
        bb = BlockBasic()
        bg.addBlock(bb)
        assert bg.getSize() == 1
        assert bg.getBlock(0) is bb
        assert bb.getParent() is bg

    def test_multiple_blocks(self):
        bg = BlockGraph()
        bb1 = BlockBasic()
        bb2 = BlockBasic()
        bg.addBlock(bb1)
        bg.addBlock(bb2)
        assert bg.getSize() == 2


# ---------------------------------------------------------------------------
# Structured block types
# ---------------------------------------------------------------------------

class TestBlockCopy:
    def test_type(self):
        bc = BlockCopy()
        assert bc.getType() == FlowBlock.t_copy

    def test_copy_ref(self):
        bb = BlockBasic()
        bc = BlockCopy(bb)
        assert bc.subBlock(0) is bb
        assert bc._copy is bb


class TestBlockGoto:
    def test_type(self):
        bg = BlockGoto()
        assert bg.getType() == FlowBlock.t_goto


class TestBlockCondition:
    def test_type(self):
        bc = BlockCondition()
        assert bc.getType() == FlowBlock.t_condition


class TestBlockIf:
    def test_type(self):
        bi = BlockIf()
        assert bi.getType() == FlowBlock.t_if


class TestBlockWhileDo:
    def test_type(self):
        bw = BlockWhileDo()
        assert bw.getType() == FlowBlock.t_whiledo


class TestBlockDoWhile:
    def test_type(self):
        bd = BlockDoWhile()
        assert bd.getType() == FlowBlock.t_dowhile


class TestBlockInfLoop:
    def test_type(self):
        bi = BlockInfLoop()
        assert bi.getType() == FlowBlock.t_infloop


class TestBlockSwitch:
    def test_type(self):
        bs = BlockSwitch()
        assert bs.getType() == FlowBlock.t_switch


class TestBlockList:
    def test_type(self):
        bl = BlockList()
        assert bl.getType() == FlowBlock.t_ls


class TestBlockMultiGoto:
    def test_type(self):
        bm = BlockMultiGoto()
        assert bm.getType() == FlowBlock.t_multigoto
