"""
CallGraph / CallGraphNode / CallGraphEdge: Call graph construction and analysis.
Corresponds to callgraph.hh / callgraph.cc.

Provides a directed graph of function calls with cycle detection, spanning tree
construction, and leaf-first iteration ordering.
"""
from __future__ import annotations

from typing import Dict, List, Optional, Iterator, TYPE_CHECKING

from ghidra.core.address import Address
from ghidra.core.error import LowlevelError
from ghidra.core.marshal import (
    ATTRIB_NAME, ELEM_EDGE,
    ElementId,
)

if TYPE_CHECKING:
    from ghidra.core.marshal import Encoder, Decoder
    from ghidra.analysis.funcdata import Funcdata

ELEM_CALLGRAPH = ElementId("callgraph", 226)
ELEM_NODE = ElementId("node", 227)


class CallGraphEdge:
    """An edge in the call graph connecting caller to callee."""

    cycle: int = 1
    dontfollow: int = 2

    def __init__(self) -> None:
        self.from_node: Optional[CallGraphNode] = None
        self.to_node: Optional[CallGraphNode] = None
        self.callsiteaddr: Address = Address()
        self.complement: int = 0
        self.flags: int = 0

    def isCycle(self) -> bool:
        return (self.flags & CallGraphEdge.cycle) != 0

    def getCallSiteAddr(self) -> Address:
        return self.callsiteaddr

    def encode(self, encoder: Encoder) -> None:
        encoder.openElement(ELEM_EDGE)
        self.from_node.getAddr().encode(encoder)
        self.to_node.getAddr().encode(encoder)
        self.callsiteaddr.encode(encoder)
        encoder.closeElement(ELEM_EDGE)

    @staticmethod
    def decode(decoder: Decoder, graph: CallGraph) -> None:
        elemId = decoder.openElement(ELEM_EDGE)
        fromaddr = Address.decode(decoder)
        toaddr = Address.decode(decoder)
        siteaddr = Address.decode(decoder)
        decoder.closeElement(elemId)

        fromnode = graph.findNode(fromaddr)
        if fromnode is None:
            raise LowlevelError("Could not find from node")
        tonode = graph.findNode(toaddr)
        if tonode is None:
            raise LowlevelError("Could not find to node")
        graph.addEdge(fromnode, tonode, siteaddr)


class CallGraphNode:
    """A node in the call graph representing a single function."""

    mark: int = 1
    onlycyclein: int = 2
    currentcycle: int = 4
    entrynode: int = 8

    def __init__(self) -> None:
        self.entryaddr: Address = Address()
        self.name: str = ""
        self.fd: Optional[Funcdata] = None
        self.inedge: List[CallGraphEdge] = []
        self.outedge: List[CallGraphEdge] = []
        self.parentedge: int = -1
        self.flags: int = 0

    def clearMark(self) -> None:
        self.flags &= ~CallGraphNode.mark

    def isMark(self) -> bool:
        return (self.flags & CallGraphNode.mark) != 0

    def getAddr(self) -> Address:
        return self.entryaddr

    def getName(self) -> str:
        return self.name

    def getFuncdata(self) -> Optional[Funcdata]:
        return self.fd

    def numInEdge(self) -> int:
        return len(self.inedge)

    def getInEdge(self, i: int) -> CallGraphEdge:
        return self.inedge[i]

    def getInNode(self, i: int) -> CallGraphNode:
        return self.inedge[i].from_node

    def numOutEdge(self) -> int:
        return len(self.outedge)

    def getOutEdge(self, i: int) -> CallGraphEdge:
        return self.outedge[i]

    def getOutNode(self, i: int) -> CallGraphNode:
        return self.outedge[i].to_node

    def setFuncdata(self, f: Funcdata) -> None:
        if self.fd is not None and self.fd is not f:
            raise LowlevelError("Multiple functions at one address in callgraph")
        if f.getAddress() != self.entryaddr:
            raise LowlevelError("Setting function data at wrong address in callgraph")
        self.fd = f

    def encode(self, encoder: Encoder) -> None:
        encoder.openElement(ELEM_NODE)
        if self.name:
            encoder.writeString(ATTRIB_NAME, self.name)
        self.entryaddr.encode(encoder)
        encoder.closeElement(ELEM_NODE)

    @staticmethod
    def decode(decoder: Decoder, graph: CallGraph) -> None:
        elemId = decoder.openElement(ELEM_NODE)
        name = ""
        while True:
            attribId = decoder.getNextAttributeId()
            if attribId == 0:
                break
            if attribId == ATTRIB_NAME:
                name = decoder.readString()
        addr = Address.decode(decoder)
        decoder.closeElement(elemId)
        graph.addNodeByAddr(addr, name)


class _LeafIterator:
    """Helper for spanning-tree leaf walk."""
    __slots__ = ('node', 'outslot')

    def __init__(self, node: CallGraphNode) -> None:
        self.node: CallGraphNode = node
        self.outslot: int = 0


LeafIterator = _LeafIterator


class CallGraph:
    """Directed graph of function calls with cycle detection and leaf-first ordering."""

    def __init__(self, glb=None) -> None:
        self.glb = glb
        self._graph: Dict[Address, CallGraphNode] = {}
        self._seeds: List[CallGraphNode] = []

    # ------------------------------------------------------------------
    # Node management
    # ------------------------------------------------------------------

    def addNode(self, f_or_addr, nm: str = "") -> CallGraphNode:
        """Add a node by Funcdata or by address/name.

        This preserves the C++ overload pair:
        - addNode(Funcdata *f)
        - addNode(const Address &addr,const string &nm)
        """
        if hasattr(f_or_addr, "getAddress"):
            f = f_or_addr
            addr = f.getAddress()
            node = self._graph.get(addr)
            if node is None:
                node = CallGraphNode()
                node.entryaddr = addr
                self._graph[addr] = node
            if node.fd is not None and node.fd is not f:
                raise LowlevelError(
                    "Functions with duplicate entry points: "
                    + f.getName() + " " + node.fd.getName()
                )
            node.entryaddr = addr
            node.name = f.getDisplayName() if hasattr(f, 'getDisplayName') else f.getName()
            node.fd = f
            return node

        addr = f_or_addr
        node = self._graph.get(addr)
        if node is None:
            node = CallGraphNode()
            self._graph[addr] = node
        node.entryaddr = addr
        node.name = nm
        return node

    def addNodeByAddr(self, addr: Address, nm: str) -> CallGraphNode:
        return self.addNode(addr, nm)

    def findNode(self, addr: Address) -> Optional[CallGraphNode]:
        """Find the node at the given address, or return None."""
        return self._graph.get(addr)

    # ------------------------------------------------------------------
    # Edge management
    # ------------------------------------------------------------------

    def _insertBlankEdge(self, node: CallGraphNode, slot: int) -> CallGraphEdge:
        """Insert a blank edge at the given slot in the node's outedge list."""
        edge = CallGraphEdge()
        node.outedge.insert(slot, edge)
        # Fix complement indices for shifted edges
        for i in range(slot + 1, len(node.outedge)):
            e = node.outedge[i]
            if e.to_node is not None:
                e.to_node.inedge[e.complement].complement = i
        return node.outedge[slot]

    def insertBlankEdge(self, node: CallGraphNode, slot: int) -> CallGraphEdge:
        return self._insertBlankEdge(node, slot)

    def addEdge(self, from_node: CallGraphNode, to_node: CallGraphNode,
                addr: Address) -> None:
        """Add an edge from from_node to to_node at the given call site address."""
        # Check if edge already exists
        slot = 0
        for i, e in enumerate(from_node.outedge):
            if e.to_node is to_node:
                return  # Already have this edge
            if to_node.entryaddr < e.to_node.entryaddr:
                slot = i
                break
        else:
            slot = len(from_node.outedge)

        fromedge = self._insertBlankEdge(from_node, slot)
        toi = len(to_node.inedge)
        toedge = CallGraphEdge()
        to_node.inedge.append(toedge)

        fromedge.from_node = from_node
        fromedge.to_node = to_node
        fromedge.callsiteaddr = addr
        fromedge.complement = toi

        toedge.from_node = from_node
        toedge.to_node = to_node
        toedge.callsiteaddr = addr
        toedge.complement = slot

    def deleteInEdge(self, node: CallGraphNode, i: int) -> None:
        """Delete the i-th incoming edge from node."""
        fromi = node.inedge[i].complement
        from_node = node.inedge[i].from_node

        # Shift inedges
        for j in range(i + 1, len(node.inedge)):
            node.inedge[j - 1] = node.inedge[j]
            if node.inedge[j - 1].complement >= fromi:
                node.inedge[j - 1].complement -= 1
        node.inedge.pop()

        # Shift outedges of the from node
        for j in range(fromi + 1, len(from_node.outedge)):
            from_node.outedge[j - 1] = from_node.outedge[j]
            if from_node.outedge[j - 1].complement >= i:
                from_node.outedge[j - 1].complement -= 1
        from_node.outedge.pop()

    # ------------------------------------------------------------------
    # Cycle detection
    # ------------------------------------------------------------------

    def _snipEdge(self, node: CallGraphNode, i: int) -> None:
        """Mark the i-th outgoing edge of node as a cycle edge."""
        node.outedge[i].flags |= CallGraphEdge.cycle | CallGraphEdge.dontfollow
        toi = node.outedge[i].complement
        to = node.outedge[i].to_node
        to.inedge[toi].flags |= CallGraphEdge.cycle

        only_cycle = True
        for e in to.inedge:
            if (e.flags & CallGraphEdge.cycle) == 0:
                only_cycle = False
                break
        if only_cycle:
            to.flags |= CallGraphNode.onlycyclein

    def snipEdge(self, node: CallGraphNode, i: int) -> None:
        self._snipEdge(node, i)

    def _snipCycles(self, root: CallGraphNode) -> None:
        """Snip any cycles reachable from root using DFS."""
        root.flags |= CallGraphNode.currentcycle
        stack: List[_LeafIterator] = [_LeafIterator(root)]

        while stack:
            cur = stack[-1].node
            st = stack[-1].outslot
            if st >= len(cur.outedge):
                cur.flags &= ~CallGraphNode.currentcycle
                stack.pop()
            else:
                stack[-1].outslot += 1
                if (cur.outedge[st].flags & CallGraphEdge.cycle) != 0:
                    continue
                nxt = cur.outedge[st].to_node
                if (nxt.flags & CallGraphNode.currentcycle) != 0:
                    self._snipEdge(cur, st)
                    continue
                elif (nxt.flags & CallGraphNode.mark) != 0:
                    cur.outedge[st].flags |= CallGraphEdge.dontfollow
                    continue
                nxt.parentedge = cur.outedge[st].complement
                nxt.flags |= CallGraphNode.currentcycle | CallGraphNode.mark
                stack.append(_LeafIterator(nxt))

    def snipCycles(self, node: CallGraphNode) -> None:
        self._snipCycles(node)

    def _clearMarks(self) -> None:
        for node in self._graph.values():
            node.clearMark()

    def clearMarks(self) -> None:
        self._clearMarks()

    def _findNoEntry(self, seeds: List[CallGraphNode]) -> bool:
        """Find root nodes with no non-cycle in-edges. Return True if all covered."""
        lownode: Optional[CallGraphNode] = None
        allcovered = True
        newseeds = False

        for node in self._graph.values():
            if node.isMark():
                continue
            if len(node.inedge) == 0 or (node.flags & CallGraphNode.onlycyclein) != 0:
                seeds.append(node)
                node.flags |= CallGraphNode.mark | CallGraphNode.entrynode
                newseeds = True
            else:
                allcovered = False
                if lownode is None:
                    lownode = node
                elif node.numInEdge() < lownode.numInEdge():
                    lownode = node

        if not newseeds and not allcovered and lownode is not None:
            seeds.append(lownode)
            lownode.flags |= CallGraphNode.mark | CallGraphNode.entrynode

        return allcovered

    def findNoEntry(self, seeds: List[CallGraphNode]) -> bool:
        return self._findNoEntry(seeds)

    def cycleStructure(self) -> None:
        """Build spanning tree and snip cycles to produce seed list."""
        if self._seeds:
            return
        walked = 0
        while True:
            allcovered = self._findNoEntry(self._seeds)
            while walked < len(self._seeds):
                rootnode = self._seeds[walked]
                rootnode.parentedge = walked
                self._snipCycles(rootnode)
                walked += 1
            if allcovered:
                break
        self._clearMarks()

    # ------------------------------------------------------------------
    # Leaf-first iteration
    # ------------------------------------------------------------------

    def _popPossible(self, node: CallGraphNode) -> tuple[Optional[CallGraphNode], int]:
        """Pop up to the parent in the spanning tree."""
        if (node.flags & CallGraphNode.entrynode) != 0:
            return None, node.parentedge
        outslot = node.inedge[node.parentedge].complement
        return node.inedge[node.parentedge].from_node, outslot

    def popPossible(self, node: CallGraphNode) -> tuple[Optional[CallGraphNode], int]:
        return self._popPossible(node)

    def _pushPossible(self, node: Optional[CallGraphNode],
                      outslot: int) -> Optional[CallGraphNode]:
        """Push down to the next child in the spanning tree."""
        if node is None:
            if outslot >= len(self._seeds):
                return None
            return self._seeds[outslot]
        while outslot < len(node.outedge):
            if (node.outedge[outslot].flags & CallGraphEdge.dontfollow) != 0:
                outslot += 1
            else:
                return node.outedge[outslot].to_node
        return None

    def pushPossible(self, node: Optional[CallGraphNode],
                     outslot: int) -> Optional[CallGraphNode]:
        return self._pushPossible(node, outslot)

    def initLeafWalk(self) -> Optional[CallGraphNode]:
        """Initialize leaf-first traversal. Returns the first leaf node."""
        self.cycleStructure()
        if not self._seeds:
            return None
        node = self._seeds[0]
        while True:
            pushnode = self._pushPossible(node, 0)
            if pushnode is None:
                break
            node = pushnode
        return node

    def nextLeaf(self, node: CallGraphNode) -> Optional[CallGraphNode]:
        """Get the next leaf node in the traversal."""
        node, outslot = self._popPossible(node)
        outslot += 1
        while True:
            pushnode = self._pushPossible(node, outslot)
            if pushnode is None:
                break
            node = pushnode
            outslot = 0
        return node

    # ------------------------------------------------------------------
    # Iteration helpers
    # ------------------------------------------------------------------

    def __iter__(self) -> Iterator[CallGraphNode]:
        return iter(self._graph.values())

    def begin(self):
        return iter(self._graph.items())

    def end(self):
        return None

    def numNodes(self) -> int:
        return len(self._graph)

    def iterateFunctionsAddrOrder(self, scope) -> None:
        iterator = scope.begin() if hasattr(scope, "begin") else iter(scope)
        for entry in iterator:
            sym = entry.getSymbol() if hasattr(entry, "getSymbol") else entry
            if sym is None:
                continue
            fsym = sym if hasattr(sym, "getFunction") else None
            if fsym is not None:
                func = fsym.getFunction()
                if func is not None:
                    self.addNode(func)

    def iterateScopesRecursive(self, scope) -> None:
        if scope is None or not scope.isGlobal():
            return
        self.iterateFunctionsAddrOrder(scope)
        if hasattr(scope, "childrenBegin"):
            child_iter = scope.childrenBegin()
        else:
            child_iter = iter(getattr(scope, "children", {}).values())
        for child in child_iter:
            self.iterateScopesRecursive(child)

    def buildAllNodes(self) -> None:
        if self.glb is None or getattr(self.glb, "symboltab", None) is None:
            return
        scope = self.glb.symboltab.getGlobalScope()
        self.iterateScopesRecursive(scope)

    def buildEdges(self, fd: Funcdata) -> None:
        from ghidra.fspec.fspec import ProtoModel

        fdnode = self.findNode(fd.getAddress())
        if fdnode is None:
            raise LowlevelError("Function is missing from callgraph")
        if fd.getFuncProto().getModelExtraPop() == ProtoModel.extrapop_unknown:
            fd.fillinExtrapop()

        numcalls = fd.numCalls()
        for i in range(numcalls):
            fs = fd.getCallSpecs(i)
            if fs is None:
                continue
            addr = fs.getEntryAddress()
            if addr.isInvalid():
                continue
            tonode = self.findNode(addr)
            if tonode is None:
                name = self.glb.nameFunction(addr) if self.glb is not None else ""
                tonode = self.addNode(addr, name)
            self.addEdge(fdnode, tonode, fs.getOp().getAddr())

    # ------------------------------------------------------------------
    # Serialization
    # ------------------------------------------------------------------

    def encode(self, encoder: Encoder) -> None:
        encoder.openElement(ELEM_CALLGRAPH)
        for node in self._graph.values():
            node.encode(encoder)
        for node in self._graph.values():
            for e in node.inedge:
                e.encode(encoder)
        encoder.closeElement(ELEM_CALLGRAPH)

    def decode(self, decoder: Decoder) -> None:
        elemId = decoder.openElement(ELEM_CALLGRAPH)
        while True:
            subId = decoder.peekElement()
            if subId == 0:
                break
            if subId == ELEM_EDGE:
                CallGraphEdge.decode(decoder, self)
            else:
                CallGraphNode.decode(decoder, self)
        decoder.closeElement(elemId)

    def decoder(self, decoder: Decoder) -> None:
        self.decode(decoder)
