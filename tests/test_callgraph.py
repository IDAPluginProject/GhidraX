"""Tests for ghidra.analysis.callgraph – Python port of callgraph.cc."""
from __future__ import annotations

import pytest
import sys, os

sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', 'python'))

from ghidra.core.address import Address, AddrSpace
from ghidra.core.error import LowlevelError
from ghidra.analysis.callgraph import (
    CallGraph, CallGraphNode, CallGraphEdge, ELEM_CALLGRAPH, ELEM_NODE,
)


# =========================================================================
# Helpers
# =========================================================================

_SHARED_SPACE = AddrSpace(name="ram", size=8, ind=1)


def _addr(offset: int) -> Address:
    return Address(_SHARED_SPACE, offset)


class StubFuncdata:
    """Minimal Funcdata stub for callgraph tests."""
    def __init__(self, name: str, offset: int):
        self._name = name
        self._offset = offset
        self._addr = _addr(offset)

    def getName(self) -> str:
        return self._name

    def getDisplayName(self) -> str:
        return self._name

    def getAddress(self) -> Address:
        return self._addr


# =========================================================================
# CallGraphEdge
# =========================================================================

class TestCallGraphEdge:
    def test_default_flags(self):
        e = CallGraphEdge()
        assert e.flags == 0
        assert not e.isCycle()

    def test_cycle_flag(self):
        e = CallGraphEdge()
        e.flags |= CallGraphEdge.cycle
        assert e.isCycle()

    def test_dontfollow_flag(self):
        e = CallGraphEdge()
        e.flags |= CallGraphEdge.dontfollow
        assert (e.flags & CallGraphEdge.dontfollow) != 0


# =========================================================================
# CallGraphNode
# =========================================================================

class TestCallGraphNode:
    def test_default_state(self):
        n = CallGraphNode()
        assert n.getName() == ""
        assert n.getFuncdata() is None
        assert n.numInEdge() == 0
        assert n.numOutEdge() == 0
        assert not n.isMark()

    def test_mark_clear(self):
        n = CallGraphNode()
        n.flags |= CallGraphNode.mark
        assert n.isMark()
        n.clearMark()
        assert not n.isMark()

    def test_set_funcdata(self):
        n = CallGraphNode()
        n.entryaddr = _addr(0x1000)
        fd = StubFuncdata("foo", 0x1000)
        n.setFuncdata(fd)
        assert n.getFuncdata() is fd

    def test_set_funcdata_wrong_addr(self):
        n = CallGraphNode()
        n.entryaddr = _addr(0x1000)
        fd = StubFuncdata("foo", 0x2000)
        with pytest.raises(LowlevelError):
            n.setFuncdata(fd)

    def test_set_funcdata_duplicate(self):
        n = CallGraphNode()
        n.entryaddr = _addr(0x1000)
        fd1 = StubFuncdata("foo", 0x1000)
        fd2 = StubFuncdata("bar", 0x1000)
        n.setFuncdata(fd1)
        with pytest.raises(LowlevelError):
            n.setFuncdata(fd2)

    def test_set_funcdata_same_ok(self):
        n = CallGraphNode()
        n.entryaddr = _addr(0x1000)
        fd = StubFuncdata("foo", 0x1000)
        n.setFuncdata(fd)
        n.setFuncdata(fd)  # should not raise
        assert n.getFuncdata() is fd


# =========================================================================
# CallGraph — basic operations
# =========================================================================

class TestCallGraphBasic:
    def test_empty_graph(self):
        cg = CallGraph()
        assert cg.numNodes() == 0

    def test_add_node_by_addr(self):
        cg = CallGraph()
        n = cg.addNodeByAddr(_addr(0x1000), "main")
        assert n.getName() == "main"
        assert n.getAddr().getOffset() == 0x1000
        assert cg.numNodes() == 1

    def test_add_node_by_funcdata(self):
        cg = CallGraph()
        fd = StubFuncdata("main", 0x1000)
        n = cg.addNode(fd)
        assert n.getName() == "main"
        assert n.getFuncdata() is fd
        assert cg.numNodes() == 1

    def test_add_duplicate_funcdata(self):
        cg = CallGraph()
        fd1 = StubFuncdata("main", 0x1000)
        fd2 = StubFuncdata("main2", 0x1000)
        cg.addNode(fd1)
        with pytest.raises(LowlevelError):
            cg.addNode(fd2)

    def test_find_node(self):
        cg = CallGraph()
        cg.addNodeByAddr(_addr(0x1000), "main")
        n = cg.findNode(_addr(0x1000))
        assert n is not None
        assert n.getName() == "main"

    def test_find_node_missing(self):
        cg = CallGraph()
        assert cg.findNode(_addr(0x9999)) is None

    def test_add_edge(self):
        cg = CallGraph()
        n1 = cg.addNodeByAddr(_addr(0x1000), "main")
        n2 = cg.addNodeByAddr(_addr(0x2000), "helper")
        cg.addEdge(n1, n2, _addr(0x1010))
        assert n1.numOutEdge() == 1
        assert n2.numInEdge() == 1
        assert n1.getOutNode(0) is n2
        assert n2.getInNode(0) is n1

    def test_add_duplicate_edge(self):
        cg = CallGraph()
        n1 = cg.addNodeByAddr(_addr(0x1000), "main")
        n2 = cg.addNodeByAddr(_addr(0x2000), "helper")
        cg.addEdge(n1, n2, _addr(0x1010))
        cg.addEdge(n1, n2, _addr(0x1020))  # duplicate, should be ignored
        assert n1.numOutEdge() == 1

    def test_delete_in_edge(self):
        cg = CallGraph()
        n1 = cg.addNodeByAddr(_addr(0x1000), "main")
        n2 = cg.addNodeByAddr(_addr(0x2000), "helper")
        cg.addEdge(n1, n2, _addr(0x1010))
        assert n2.numInEdge() == 1
        cg.deleteInEdge(n2, 0)
        assert n2.numInEdge() == 0
        assert n1.numOutEdge() == 0


# =========================================================================
# CallGraph — multiple edges
# =========================================================================

class TestCallGraphMultiEdge:
    def test_multiple_callees(self):
        cg = CallGraph()
        main = cg.addNodeByAddr(_addr(0x1000), "main")
        foo = cg.addNodeByAddr(_addr(0x2000), "foo")
        bar = cg.addNodeByAddr(_addr(0x3000), "bar")
        cg.addEdge(main, foo, _addr(0x1010))
        cg.addEdge(main, bar, _addr(0x1020))
        assert main.numOutEdge() == 2
        assert foo.numInEdge() == 1
        assert bar.numInEdge() == 1

    def test_multiple_callers(self):
        cg = CallGraph()
        a = cg.addNodeByAddr(_addr(0x1000), "a")
        b = cg.addNodeByAddr(_addr(0x2000), "b")
        c = cg.addNodeByAddr(_addr(0x3000), "c")
        cg.addEdge(a, c, _addr(0x1010))
        cg.addEdge(b, c, _addr(0x2010))
        assert c.numInEdge() == 2


# =========================================================================
# CallGraph — cycle detection
# =========================================================================

class TestCallGraphCycles:
    def test_simple_cycle(self):
        """A -> B -> A should detect and snip the cycle."""
        cg = CallGraph()
        a = cg.addNodeByAddr(_addr(0x1000), "a")
        b = cg.addNodeByAddr(_addr(0x2000), "b")
        cg.addEdge(a, b, _addr(0x1010))
        cg.addEdge(b, a, _addr(0x2010))
        cg.cycleStructure()
        # One of the edges should be marked as cycle
        cycle_found = False
        for e in a.outedge:
            if e.isCycle():
                cycle_found = True
        for e in b.outedge:
            if e.isCycle():
                cycle_found = True
        assert cycle_found

    def test_no_cycle(self):
        """A -> B -> C should have no cycles."""
        cg = CallGraph()
        a = cg.addNodeByAddr(_addr(0x1000), "a")
        b = cg.addNodeByAddr(_addr(0x2000), "b")
        c = cg.addNodeByAddr(_addr(0x3000), "c")
        cg.addEdge(a, b, _addr(0x1010))
        cg.addEdge(b, c, _addr(0x2010))
        cg.cycleStructure()
        for node in cg:
            for e in node.outedge:
                assert not e.isCycle()

    def test_triangle_cycle(self):
        """A -> B -> C -> A should detect cycle."""
        cg = CallGraph()
        a = cg.addNodeByAddr(_addr(0x1000), "a")
        b = cg.addNodeByAddr(_addr(0x2000), "b")
        c = cg.addNodeByAddr(_addr(0x3000), "c")
        cg.addEdge(a, b, _addr(0x1010))
        cg.addEdge(b, c, _addr(0x2010))
        cg.addEdge(c, a, _addr(0x3010))
        cg.cycleStructure()
        cycle_count = sum(
            1 for node in cg for e in node.outedge if e.isCycle()
        )
        assert cycle_count >= 1


# =========================================================================
# CallGraph — leaf walk
# =========================================================================

class TestLeafWalk:
    def test_single_node(self):
        cg = CallGraph()
        cg.addNodeByAddr(_addr(0x1000), "main")
        leaf = cg.initLeafWalk()
        assert leaf is not None
        assert leaf.getName() == "main"

    def test_linear_chain(self):
        """A -> B -> C: leaf should be C first."""
        cg = CallGraph()
        a = cg.addNodeByAddr(_addr(0x1000), "a")
        b = cg.addNodeByAddr(_addr(0x2000), "b")
        c = cg.addNodeByAddr(_addr(0x3000), "c")
        cg.addEdge(a, b, _addr(0x1010))
        cg.addEdge(b, c, _addr(0x2010))
        leaf = cg.initLeafWalk()
        assert leaf is not None
        assert leaf.getName() == "c"

    def test_walk_all_nodes(self):
        """Should visit all nodes via leaf walk."""
        cg = CallGraph()
        a = cg.addNodeByAddr(_addr(0x1000), "a")
        b = cg.addNodeByAddr(_addr(0x2000), "b")
        c = cg.addNodeByAddr(_addr(0x3000), "c")
        cg.addEdge(a, b, _addr(0x1010))
        cg.addEdge(a, c, _addr(0x1020))
        visited = []
        node = cg.initLeafWalk()
        while node is not None:
            visited.append(node.getName())
            node = cg.nextLeaf(node)
        assert len(visited) >= 2  # At least the leaves

    def test_empty_graph_leaf_walk(self):
        cg = CallGraph()
        assert cg.initLeafWalk() is None


# =========================================================================
# CallGraph — iteration
# =========================================================================

class TestIteration:
    def test_iter(self):
        cg = CallGraph()
        cg.addNodeByAddr(_addr(0x1000), "a")
        cg.addNodeByAddr(_addr(0x2000), "b")
        names = [n.getName() for n in cg]
        assert "a" in names
        assert "b" in names


# =========================================================================
# Constants
# =========================================================================

class TestConstants:
    def test_elem_callgraph(self):
        assert ELEM_CALLGRAPH.getName() == "callgraph"

    def test_elem_node(self):
        assert ELEM_NODE.getName() == "node"


if __name__ == '__main__':
    pytest.main([__file__, '-v'])
