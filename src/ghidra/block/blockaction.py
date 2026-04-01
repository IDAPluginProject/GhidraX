"""
Corresponds to: blockaction.hh / blockaction.cc

Actions and classes for structuring the control-flow graph.
"""

from __future__ import annotations


class FloatingEdge:
    """An edge persisting while graph is manipulated.

    The original FlowBlock nodes that define the end-points of the edge may get
    collapsed, but the edge may still exist between higher level components.
    """
    def __init__(self, top=None, bottom=None):
        self.top = top
        self.bottom = bottom

    def getTop(self):
        return self.top

    def getBottom(self):
        return self.bottom

    def setTop(self, t) -> None:
        self.top = t

    def setBottom(self, b) -> None:
        self.bottom = b

    def getCurrentEdge(self, outedge_ref: list, graph):
        """Get the current form of the edge.

        Returns the FlowBlock that currently represents the top of the edge.
        outedge_ref[0] is set to the output edge index.
        """
        while self.top.getParent() is not graph:
            self.top = self.top.getParent()
        while self.bottom.getParent() is not graph:
            self.bottom = self.bottom.getParent()
        outedge = self.top.getOutIndex(self.bottom)
        if outedge < 0:
            return None
        outedge_ref[0] = outedge
        return self.top


class LoopBody:
    """A description of the body of a loop.

    Following Tarjan, assuming there are no irreducible edges, a loop body is defined
    by the head (or entry-point) and 1 or more tails, which each have a back edge
    into the head.
    """
    def __init__(self, head=None):
        self.head = head
        self.tails: list = []
        self.depth: int = 0
        self.uniquecount: int = 0
        self.exitblock = None
        self.exitedges: list = []  # List of FloatingEdge
        self.immed_container = None

    def addTail(self, bl):
        self.tails.append(bl)

    def getHead(self):
        return self.head

    def getExitBlock(self):
        return self.exitblock

    def update(self, graph):
        """Update loop body to current view. Returns the active tail or None."""
        while self.head.getParent() is not graph:
            self.head = self.head.getParent()
        for i in range(len(self.tails)):
            bottom = self.tails[i]
            while bottom.getParent() is not graph:
                bottom = bottom.getParent()
            self.tails[i] = bottom
            if bottom is not self.head:
                return bottom
        for i in range(self.head.sizeOut() - 1, -1, -1):
            if self.head.getOut(i) is self.head:
                return self.head
        return None

    def findBase(self, body: list):
        """Mark the body FlowBlocks of this loop."""
        self.head.setMark()
        body.append(self.head)
        for j in range(len(self.tails)):
            tail = self.tails[j]
            if not tail.isMark():
                tail.setMark()
                body.append(tail)
        self.uniquecount = len(body)
        i = 1
        while i < len(body):
            curblock = body[i]
            i += 1
            sizein = curblock.sizeIn()
            for k in range(sizein):
                if curblock.isGotoIn(k):
                    continue
                bl = curblock.getIn(k)
                if bl.isMark():
                    continue
                bl.setMark()
                body.append(bl)

    def extend(self, body: list):
        """Extend body (to blocks that never exit)."""
        trial = []
        i = 0
        while i < len(body):
            bl = body[i]
            i += 1
            sizeout = bl.sizeOut()
            for j in range(sizeout):
                if bl.isGotoOut(j):
                    continue
                curbl = bl.getOut(j)
                if curbl.isMark():
                    continue
                if curbl is self.exitblock:
                    continue
                count = curbl.getVisitCount()
                if count == 0:
                    trial.append(curbl)
                count += 1
                curbl.setVisitCount(count)
                if count == curbl.sizeIn():
                    curbl.setMark()
                    body.append(curbl)
        for t in trial:
            t.setVisitCount(0)

    def findExit(self, body: list):
        """Choose the exit block for this loop."""
        trialexit = []
        for j in range(len(self.tails)):
            tail = self.tails[j]
            sizeout = tail.sizeOut()
            for i in range(sizeout):
                if tail.isGotoOut(i):
                    continue
                curbl = tail.getOut(i)
                if not curbl.isMark():
                    if self.immed_container is None:
                        self.exitblock = curbl
                        return
                    trialexit.append(curbl)
        for i in range(len(body)):
            bl = body[i]
            if 0 < i < self.uniquecount:
                continue
            sizeout = bl.sizeOut()
            for j in range(sizeout):
                if bl.isGotoOut(j):
                    continue
                curbl = bl.getOut(j)
                if not curbl.isMark():
                    if self.immed_container is None:
                        self.exitblock = curbl
                        return
                    trialexit.append(curbl)
        self.exitblock = None
        if not trialexit:
            return
        if self.immed_container is not None:
            extension = []
            self.extendToContainer(self.immed_container, extension)
            for bl in trialexit:
                if bl.isMark():
                    self.exitblock = bl
                    break
            LoopBody.clearMarks(extension)

    def orderTails(self):
        """Find preferred tail."""
        if len(self.tails) <= 1:
            return
        if self.exitblock is None:
            return
        for prefindex in range(len(self.tails)):
            trial = self.tails[prefindex]
            sizeout = trial.sizeOut()
            found = False
            for j in range(sizeout):
                if trial.getOut(j) is self.exitblock:
                    found = True
                    break
            if found:
                break
        else:
            return
        if prefindex == 0:
            return
        self.tails[prefindex] = self.tails[0]
        self.tails[0] = trial

    def labelExitEdges(self, body: list):
        """Label edges that exit the loop."""
        toexitblock = []
        for i in range(self.uniquecount, len(body)):
            curblock = body[i]
            sizeout = curblock.sizeOut()
            for k in range(sizeout):
                if curblock.isGotoOut(k):
                    continue
                bl = curblock.getOut(k)
                if bl is self.exitblock:
                    toexitblock.append(curblock)
                    continue
                if not bl.isMark():
                    self.exitedges.append(FloatingEdge(curblock, bl))
        if self.head is not None:
            sizeout = self.head.sizeOut()
            for k in range(sizeout):
                if self.head.isGotoOut(k):
                    continue
                bl = self.head.getOut(k)
                if bl is self.exitblock:
                    toexitblock.append(self.head)
                    continue
                if not bl.isMark():
                    self.exitedges.append(FloatingEdge(self.head, bl))
        for i in range(len(self.tails) - 1, -1, -1):
            curblock = self.tails[i]
            if curblock is self.head:
                continue
            sizeout = curblock.sizeOut()
            for k in range(sizeout):
                if curblock.isGotoOut(k):
                    continue
                bl = curblock.getOut(k)
                if bl is self.exitblock:
                    toexitblock.append(curblock)
                    continue
                if not bl.isMark():
                    self.exitedges.append(FloatingEdge(curblock, bl))
        for bl in toexitblock:
            self.exitedges.append(FloatingEdge(bl, self.exitblock))

    def labelContainments(self, body: list, looporder: list):
        """Label containment relationships between loops."""
        containlist = []
        for i in range(len(body)):
            curblock = body[i]
            if curblock is not self.head:
                subloop = LoopBody.find(curblock, looporder)
                if subloop is not None:
                    containlist.append(subloop)
                    subloop.depth += 1
        for lb in containlist:
            if lb.immed_container is None or lb.immed_container.depth < self.depth:
                lb.immed_container = self

    def emitLikelyEdges(self, likely: list, graph):
        """Collect likely unstructured edges."""
        while self.head.getParent() is not graph:
            self.head = self.head.getParent()
        if self.exitblock is not None:
            while self.exitblock.getParent() is not graph:
                self.exitblock = self.exitblock.getParent()
        for i in range(len(self.tails)):
            tail = self.tails[i]
            while tail.getParent() is not graph:
                tail = tail.getParent()
            self.tails[i] = tail
            if tail is self.exitblock:
                self.exitblock = None
        holdin = None
        holdout = None
        it = 0
        total = len(self.exitedges)
        while it < total:
            outedge_ref = [0]
            inbl = self.exitedges[it].getCurrentEdge(outedge_ref, graph)
            it += 1
            if inbl is None:
                continue
            outbl = inbl.getOut(outedge_ref[0])
            if it == total:
                if outbl is self.exitblock:
                    holdin = inbl
                    holdout = outbl
                    break
            likely.append(FloatingEdge(inbl, outbl))
        for i in range(len(self.tails) - 1, -1, -1):
            if holdin is not None and i == 0:
                likely.append(FloatingEdge(holdin, holdout))
            tail = self.tails[i]
            sizeout = tail.sizeOut()
            for j in range(sizeout):
                bl = tail.getOut(j)
                if bl is self.head:
                    likely.append(FloatingEdge(tail, self.head))

    def setExitMarks(self, graph):
        """Mark all the exits to this loop."""
        for edge in self.exitedges:
            outedge_ref = [0]
            inloop = edge.getCurrentEdge(outedge_ref, graph)
            if inloop is not None:
                inloop.setLoopExit(outedge_ref[0])

    def clearExitMarks(self, graph):
        """Clear the mark on all the exits to this loop."""
        for edge in self.exitedges:
            outedge_ref = [0]
            inloop = edge.getCurrentEdge(outedge_ref, graph)
            if inloop is not None:
                inloop.clearLoopExit(outedge_ref[0])

    def __lt__(self, op2):
        return self.depth > op2.depth

    def extendToContainer(self, container, body: list):
        """Extend body to include everything in the container loop."""
        i = 0
        if not container.head.isMark():
            container.head.setMark()
            body.append(container.head)
            i = 1
        for j in range(len(container.tails)):
            tail = container.tails[j]
            if not tail.isMark():
                tail.setMark()
                body.append(tail)
        if self.head is not container.head:
            sizein = self.head.sizeIn()
            for k in range(sizein):
                if self.head.isGotoIn(k):
                    continue
                bl = self.head.getIn(k)
                if bl.isMark():
                    continue
                bl.setMark()
                body.append(bl)
        while i < len(body):
            curblock = body[i]
            i += 1
            sizein = curblock.sizeIn()
            for k in range(sizein):
                if curblock.isGotoIn(k):
                    continue
                bl = curblock.getIn(k)
                if bl.isMark():
                    continue
                bl.setMark()
                body.append(bl)

    @staticmethod
    def clearMarks(body: list):
        for bl in body:
            bl.clearMark()

    @staticmethod
    def mergeIdenticalHeads(looporder: list):
        i = 0
        curbody = looporder[i]
        j = i + 1
        while j < len(looporder):
            nextbody = looporder[j]
            j += 1
            if nextbody.head is curbody.head:
                curbody.addTail(nextbody.tails[0])
                nextbody.head = None
            else:
                i += 1
                looporder[i] = nextbody
                curbody = nextbody
        del looporder[i + 1:]

    @staticmethod
    def compare_ends(a, b) -> bool:
        """Compare the head then tail."""
        aindex = a.head.getIndex()
        bindex = b.head.getIndex()
        if aindex != bindex:
            return aindex < bindex
        aindex = a.tails[0].getIndex()
        bindex = b.tails[0].getIndex()
        return aindex < bindex

    @staticmethod
    def compare_head(a, looptop) -> int:
        aindex = a.head.getIndex()
        bindex = looptop.getIndex()
        if aindex != bindex:
            return -1 if aindex < bindex else 1
        return 0

    @staticmethod
    def find(looptop, looporder: list):
        """Find a LoopBody by its head using binary search."""
        lo, hi = 0, len(looporder) - 1
        while lo <= hi:
            mid = (lo + hi) // 2
            comp = LoopBody.compare_head(looporder[mid], looptop)
            if comp == 0:
                return looporder[mid]
            if comp < 0:
                lo = mid + 1
            else:
                hi = mid - 1
        return None


class TraceDAG:
    """Algorithm for selecting unstructured edges based on Directed Acyclic Graphs.

    With the exception of back edges in loops, structured code tends to form a DAG.
    This class traces edges with this structure. Paths can recursively split at any
    point, starting a new active BranchPoint, but the BranchPoint can't be retired
    until all paths come back together.
    """

    class BranchPoint:
        """A node in the control-flow graph with multiple outgoing edges in the DAG."""
        def __init__(self, parenttrace=None):
            if parenttrace is None:
                self.parent = None
                self.depth = 0
                self.pathout = -1
                self.ismark = False
                self.top = None
                self.paths = []
            else:
                self.parent = parenttrace.top
                self.depth = self.parent.depth + 1
                self.pathout = parenttrace.pathout
                self.ismark = False
                self.top = parenttrace.destnode
                self.paths = []
                self._createTraces()

        def _createTraces(self):
            sizeout = self.top.sizeOut()
            for i in range(sizeout):
                if not self.top.isLoopDAGOut(i):
                    continue
                self.paths.append(TraceDAG.BlockTrace(self, len(self.paths), i))

        def markPath(self):
            cur = self
            while cur is not None:
                cur.ismark = not cur.ismark
                cur = cur.parent

        def distance(self, op2):
            cur = op2
            while cur is not None:
                if cur.ismark:
                    return (self.depth - cur.depth) + (op2.depth - cur.depth)
                cur = cur.parent
            return self.depth + op2.depth + 1

        def getPathStart(self, i):
            res = 0
            sizeout = self.top.sizeOut()
            for j in range(sizeout):
                if not self.top.isLoopDAGOut(j):
                    continue
                if res == i:
                    return self.top.getOut(j)
                res += 1
            return None

    class BlockTrace:
        """A trace of a single path out of a BranchPoint."""
        f_active = 1
        f_terminal = 2

        def __init__(self, top_bp, po, eo_or_bl=None):
            self.flags = 0
            self.top = top_bp
            self.pathout = po
            self.derivedbp = None
            self.activeiter_index = -1
            if isinstance(eo_or_bl, int):
                self.bottom = top_bp.top
                self.destnode = self.bottom.getOut(eo_or_bl)
                self.edgelump = 1
            else:
                self.bottom = None
                self.destnode = eo_or_bl
                self.edgelump = 1

        def isActive(self) -> bool:
            return (self.flags & TraceDAG.BlockTrace.f_active) != 0

        def isTerminal(self) -> bool:
            return (self.flags & TraceDAG.BlockTrace.f_terminal) != 0

    class BadEdgeScore:
        """Record for scoring a BlockTrace for suitability as an unstructured branch."""
        def __init__(self):
            self.exitproto = None
            self.trace = None
            self.distance = -1
            self.terminal = 0
            self.siblingedge = 0

        def compareFinal(self, op2) -> bool:
            """Return True if self is LESS likely to be the bad edge than op2."""
            if self.siblingedge != op2.siblingedge:
                return op2.siblingedge < self.siblingedge
            if self.terminal != op2.terminal:
                return self.terminal < op2.terminal
            if self.distance != op2.distance:
                return self.distance < op2.distance
            return self.trace.top.depth < op2.trace.top.depth

        def sortKey(self):
            topindex = self.trace.top.top.getIndex() if self.trace.top.top is not None else -1
            return (self.exitproto.getIndex(), topindex, self.trace.pathout)

    def __init__(self, likelygoto: list):
        self._likelygoto = likelygoto
        self._rootlist: list = []
        self._branchlist: list = []
        self._activecount: int = 0
        self._missedactivecount: int = 0
        self._activetrace: list = []
        self._current_activeiter: int = 0
        self._finishblock = None

    def addRoot(self, root):
        self._rootlist.append(root)

    def setFinishBlock(self, bl):
        self._finishblock = bl

    def _removeTrace(self, trace):
        """Remove the indicated BlockTrace, adding it to likelygoto."""
        self._likelygoto.append(FloatingEdge(trace.bottom, trace.destnode))
        trace.destnode.setVisitCount(trace.destnode.getVisitCount() + trace.edgelump)
        parentbp = trace.top
        if trace.bottom is not parentbp.top:
            trace.flags |= TraceDAG.BlockTrace.f_terminal
            trace.bottom = None
            trace.destnode = None
            trace.edgelump = 0
            return
        self._removeActive(trace)
        size = len(parentbp.paths)
        for i in range(trace.pathout + 1, size):
            movedtrace = parentbp.paths[i]
            movedtrace.pathout -= 1
            derivedbp = movedtrace.derivedbp
            if derivedbp is not None:
                derivedbp.pathout -= 1
            parentbp.paths[i - 1] = movedtrace
        parentbp.paths.pop()

    def _processExitConflict(self, start_idx, end_idx, badedgelist):
        """Process a set of conflicting BlockTrace objects that go to the same exit point."""
        s = start_idx
        while s < end_idx:
            startbp = badedgelist[s].trace.top
            it = s + 1
            if it < end_idx:
                startbp.markPath()
                while it < end_idx:
                    if startbp is badedgelist[it].trace.top:
                        badedgelist[s].siblingedge += 1
                        badedgelist[it].siblingedge += 1
                    dist = startbp.distance(badedgelist[it].trace.top)
                    if badedgelist[s].distance == -1 or badedgelist[s].distance > dist:
                        badedgelist[s].distance = dist
                    if badedgelist[it].distance == -1 or badedgelist[it].distance > dist:
                        badedgelist[it].distance = dist
                    it += 1
                startbp.markPath()
            s += 1

    def _selectBadEdge(self):
        """Select the most likely unstructured edge from active BlockTraces."""
        badedgelist = []
        for trace in self._activetrace:
            if trace.isTerminal():
                continue
            if trace.top.top is None and trace.bottom is None:
                continue
            score = TraceDAG.BadEdgeScore()
            score.trace = trace
            score.exitproto = trace.destnode
            score.distance = -1
            score.siblingedge = 0
            score.terminal = 1 if trace.destnode.sizeOut() == 0 else 0
            badedgelist.append(score)
        badedgelist.sort(key=lambda s: s.sortKey())
        i = 0
        start_i = 0
        curbl = badedgelist[0].exitproto
        samenodecount = 1
        i = 1
        while i < len(badedgelist):
            if curbl is badedgelist[i].exitproto:
                samenodecount += 1
                i += 1
            else:
                if samenodecount > 1:
                    self._processExitConflict(start_i, i, badedgelist)
                curbl = badedgelist[i].exitproto
                start_i = i
                samenodecount = 1
                i += 1
        if samenodecount > 1:
            self._processExitConflict(start_i, i, badedgelist)
        maxidx = 0
        for i in range(1, len(badedgelist)):
            if badedgelist[maxidx].compareFinal(badedgelist[i]):
                maxidx = i
        return badedgelist[maxidx].trace

    def _insertActive(self, trace):
        """Move a BlockTrace into the active category."""
        self._activetrace.append(trace)
        trace.activeiter_index = len(self._activetrace) - 1
        trace.flags |= TraceDAG.BlockTrace.f_active
        self._activecount += 1

    def _removeActive(self, trace):
        """Remove a BlockTrace from the active category."""
        idx = self._activetrace.index(trace)
        self._activetrace.pop(idx)
        for i in range(idx, len(self._activetrace)):
            self._activetrace[i].activeiter_index = i
        trace.flags &= ~TraceDAG.BlockTrace.f_active
        self._activecount -= 1

    def _checkOpen(self, trace) -> bool:
        """Check if we can push the given BlockTrace into its next node."""
        if trace.isTerminal():
            return False
        isroot = False
        if trace.top.depth == 0:
            if trace.bottom is None:
                return True
            isroot = True
        bl = trace.destnode
        if bl is self._finishblock and not isroot:
            return False
        ignore = trace.edgelump + bl.getVisitCount()
        count = 0
        for i in range(bl.sizeIn()):
            if bl.isLoopDAGIn(i):
                count += 1
                if count > ignore:
                    return False
        return True

    def _openBranch(self, trace) -> int:
        """Open a new BranchPoint along a given BlockTrace. Returns new active index."""
        newbranch = TraceDAG.BranchPoint(trace)
        trace.derivedbp = newbranch
        if len(newbranch.paths) == 0:
            trace.derivedbp = None
            trace.flags |= TraceDAG.BlockTrace.f_terminal
            trace.bottom = None
            trace.destnode = None
            trace.edgelump = 0
            return self._activetrace.index(trace)
        self._removeActive(trace)
        self._branchlist.append(newbranch)
        for p in newbranch.paths:
            self._insertActive(p)
        return newbranch.paths[0].activeiter_index

    def _checkRetirement(self, trace, exitblock_ref) -> bool:
        """Check if a given BlockTrace can be retired."""
        if trace.pathout != 0:
            return False
        bp = trace.top
        if bp.depth == 0:
            for p in bp.paths:
                if not p.isActive():
                    return False
                if not p.isTerminal():
                    return False
            return True
        outblock = None
        for p in bp.paths:
            if not p.isActive():
                return False
            if p.isTerminal():
                continue
            if outblock is p.destnode:
                continue
            if outblock is not None:
                return False
            outblock = p.destnode
        exitblock_ref[0] = outblock
        return True

    def _retireBranch(self, bp, exitblock) -> int:
        """Retire a BranchPoint, updating its parent BlockTrace. Returns new active index."""
        edgeout_bl = None
        edgelump_sum = 0
        for p in bp.paths:
            if not p.isTerminal():
                edgelump_sum += p.edgelump
                if edgeout_bl is None:
                    edgeout_bl = p.bottom
            self._removeActive(p)
        if bp.depth == 0:
            return 0
        if bp.parent is not None:
            parenttrace = bp.parent.paths[bp.pathout]
            parenttrace.derivedbp = None
            if edgeout_bl is None:
                parenttrace.flags |= TraceDAG.BlockTrace.f_terminal
                parenttrace.bottom = None
                parenttrace.destnode = None
                parenttrace.edgelump = 0
            else:
                parenttrace.bottom = edgeout_bl
                parenttrace.destnode = exitblock
                parenttrace.edgelump = edgelump_sum
            self._insertActive(parenttrace)
            return parenttrace.activeiter_index
        return 0

    def _clearVisitCount(self):
        for edge in self._likelygoto:
            edge.getBottom().setVisitCount(0)

    def initialize(self):
        """Create the initial BranchPoint and BlockTrace objects."""
        rootBranch = TraceDAG.BranchPoint()
        self._branchlist.append(rootBranch)
        for i in range(len(self._rootlist)):
            newtrace = TraceDAG.BlockTrace(rootBranch, len(rootBranch.paths), self._rootlist[i])
            rootBranch.paths.append(newtrace)
            self._insertActive(newtrace)

    def pushBranches(self):
        """Push the trace through, removing edges as necessary."""
        self._current_activeiter = 0
        self._missedactivecount = 0
        while self._activecount > 0:
            if self._current_activeiter >= len(self._activetrace):
                self._current_activeiter = 0
            curtrace = self._activetrace[self._current_activeiter]
            if self._missedactivecount >= self._activecount:
                badtrace = self._selectBadEdge()
                self._removeTrace(badtrace)
                self._current_activeiter = 0
                self._missedactivecount = 0
            else:
                exitblock_ref = [None]
                if self._checkRetirement(curtrace, exitblock_ref):
                    self._current_activeiter = self._retireBranch(curtrace.top, exitblock_ref[0])
                    self._missedactivecount = 0
                elif self._checkOpen(curtrace):
                    self._current_activeiter = self._openBranch(curtrace)
                    self._missedactivecount = 0
                else:
                    self._missedactivecount += 1
                    self._current_activeiter += 1
        self._clearVisitCount()


class ConditionalJoin:
    """Discover and eliminate split conditions.

    A split condition is when a conditional expression is duplicated across two
    blocks that would otherwise merge.
    """

    class MergePair:
        """A pair of Varnode objects that have been split (and should be merged)."""
        def __init__(self, s1, s2):
            self.side1 = s1
            self.side2 = s2

        def __lt__(self, op2):
            s1 = self.side1.getCreateIndex()
            s2 = op2.side1.getCreateIndex()
            if s1 != s2:
                return s1 < s2
            return self.side2.getCreateIndex() < op2.side2.getCreateIndex()

        def __eq__(self, op2):
            return (self.side1.getCreateIndex() == op2.side1.getCreateIndex() and
                    self.side2.getCreateIndex() == op2.side2.getCreateIndex())

        def __hash__(self):
            return hash((self.side1.getCreateIndex(), self.side2.getCreateIndex()))

    def __init__(self, data):
        self._data = data
        self._block1 = None
        self._block2 = None
        self._exita = None
        self._exitb = None
        self._a_in1 = 0
        self._a_in2 = 0
        self._b_in1 = 0
        self._b_in2 = 0
        self._cbranch1 = None
        self._cbranch2 = None
        self._joinblock = None
        self._mergeneed = {}

    def _findDups(self) -> bool:
        """Search for duplicate conditional expressions."""
        self._cbranch1 = self._block1.lastOp()
        if self._cbranch1.code() != 7:  # CPUI_CBRANCH
            return False
        self._cbranch2 = self._block2.lastOp()
        if self._cbranch2.code() != 7:  # CPUI_CBRANCH
            return False
        if self._cbranch1.isBooleanFlip():
            return False
        if self._cbranch2.isBooleanFlip():
            return False
        vn1 = self._cbranch1.getIn(1)
        vn2 = self._cbranch2.getIn(1)
        if vn1 is vn2:
            return True
        if not vn1.isWritten():
            return False
        if not vn2.isWritten():
            return False
        if vn1.isSpacebase():
            return False
        if vn2.isSpacebase():
            return False
        buf1 = [None, None]
        buf2 = [None, None]
        from ghidra.core.expression import functionalEqualityLevel
        res = functionalEqualityLevel(vn1, vn2, buf1, buf2)
        if res < 0:
            return False
        if res > 1:
            return False
        op1 = vn1.getDef()
        from ghidra.core.opcodes import OpCode
        if op1.code() == OpCode.CPUI_SUBPIECE:
            return False
        if op1.code() == OpCode.CPUI_COPY:
            return False
        self._mergeneed[ConditionalJoin.MergePair(vn1, vn2)] = None
        return True

    def _checkExitBlock(self, exit_bl, in1, in2):
        """Look for additional Varnode pairs in an exit block that need to be merged."""
        for op in exit_bl.beginOp():
            if op.code() == 56:  # CPUI_MULTIEQUAL
                vn1 = op.getIn(in1)
                vn2 = op.getIn(in2)
                if vn1 is not vn2:
                    self._mergeneed[ConditionalJoin.MergePair(vn1, vn2)] = None
            elif op.code() != 1:  # CPUI_COPY
                break

    def _cutDownMultiequals(self, exit_bl, in1, in2):
        """Substitute new joined Varnode in the given exit block."""
        lo, hi = (in1, in2) if in1 < in2 else (in2, in1)
        for op in list(exit_bl.beginOp()):
            if op.code() == 56:  # CPUI_MULTIEQUAL
                vn1 = op.getIn(in1)
                vn2 = op.getIn(in2)
                if vn1 is vn2:
                    self._data.opRemoveInput(op, hi)
                else:
                    subvn = self._mergeneed[ConditionalJoin.MergePair(vn1, vn2)]
                    self._data.opRemoveInput(op, hi)
                    self._data.opSetInput(op, subvn, lo)
                if op.numInput() == 1:
                    self._data.opUninsert(op)
                    self._data.opSetOpcode(op, 1)  # CPUI_COPY
                    self._data.opInsertBegin(op, exit_bl)
            elif op.code() != 1:  # CPUI_COPY
                break

    def _setupMultiequals(self):
        """Create a new Varnode and its defining MULTIEQUAL for each MergePair."""
        for pair, val in self._mergeneed.items():
            if val is not None:
                continue
            vn1 = pair.side1
            vn2 = pair.side2
            multi = self._data.newOp(2, self._cbranch1.getAddr())
            self._data.opSetOpcode(multi, 56)  # CPUI_MULTIEQUAL
            outvn = self._data.newUniqueOut(vn1.getSize(), multi)
            self._data.opSetInput(multi, vn1, 0)
            self._data.opSetInput(multi, vn2, 1)
            self._mergeneed[pair] = outvn
            self._data.opInsertEnd(multi, self._joinblock)

    def _moveCbranch(self):
        """Remove the other CBRANCH."""
        vn1 = self._cbranch1.getIn(1)
        vn2 = self._cbranch2.getIn(1)
        self._data.opUninsert(self._cbranch1)
        self._data.opInsertEnd(self._cbranch1, self._joinblock)
        if vn1 is not vn2:
            vn = self._mergeneed[ConditionalJoin.MergePair(vn1, vn2)]
        else:
            vn = vn1
        self._data.opSetInput(self._cbranch1, vn, 1)
        self._data.opDestroy(self._cbranch2)

    def match(self, b1, b2) -> bool:
        """Test blocks for the merge condition."""
        self._block1 = b1
        self._block2 = b2
        if self._block2 is self._block1:
            return False
        if self._block1.sizeOut() != 2:
            return False
        if self._block2.sizeOut() != 2:
            return False
        self._exita = self._block1.getOut(0)
        self._exitb = self._block1.getOut(1)
        if self._exita is self._exitb:
            return False
        if self._block2.getOut(0) is not self._exita:
            return False
        if self._block2.getOut(1) is not self._exitb:
            return False
        self._a_in2 = self._block2.getOutRevIndex(0)
        self._b_in2 = self._block2.getOutRevIndex(1)
        self._a_in1 = self._block1.getOutRevIndex(0)
        self._b_in1 = self._block1.getOutRevIndex(1)
        if not self._findDups():
            self.clear()
            return False
        self._checkExitBlock(self._exita, self._a_in1, self._a_in2)
        self._checkExitBlock(self._exitb, self._b_in1, self._b_in2)
        return True

    def execute(self):
        """All the conditions have been met. Go ahead and do the join."""
        self._joinblock = self._data.nodeJoinCreateBlock(
            self._block1, self._block2, self._exita, self._exitb,
            self._a_in1 > self._a_in2, self._b_in1 > self._b_in2,
            self._cbranch1.getAddr())
        self._setupMultiequals()
        self._moveCbranch()
        self._cutDownMultiequals(self._exita, self._a_in1, self._a_in2)
        self._cutDownMultiequals(self._exitb, self._b_in1, self._b_in2)

    def clear(self):
        self._mergeneed.clear()


class CollapseStructure:
    """Build a code structure from a control-flow graph.

    This class manages the main control-flow structuring algorithm:
      - Start with a control-flow graph of basic blocks.
      - Repeatedly apply structure element searches and collapse.
      - If stuck, remove appropriate edges marking them as unstructured.
    """

    def __init__(self, graph):
        self._graph = graph
        self._finaltrace: bool = False
        self._likelylistfull: bool = False
        self._likelygoto: list = []
        self._likelyiter: int = 0
        self._loopbody: list = []  # list of LoopBody
        self._loopbodyiter: int = 0
        self._dataflow_changecount: int = 0

    def getChangeCount(self) -> int:
        return self._dataflow_changecount

    def collapseAll(self):
        """Collapse everything in the control-flow graph to isolated blocks."""
        self._finaltrace = False
        self._graph.clearVisitCount()
        self.orderLoopBodies()
        self.collapseConditions()
        isolated_count = self.collapseInternal(None)
        while isolated_count < self._graph.getSize():
            targetbl = self.selectGoto()
            isolated_count = self.collapseInternal(targetbl)

    def collapseInternal(self, targetbl) -> int:
        """The main collapsing loop."""
        while True:
            while True:
                change = False
                index = 0
                isolated_count = 0
                while index < self._graph.getSize():
                    if targetbl is None:
                        bl = self._graph.getBlock(index)
                        index += 1
                    else:
                        bl = targetbl
                        change = True
                        targetbl = None
                        index = self._graph.getSize()
                    if bl.sizeIn() == 0 and bl.sizeOut() == 0:
                        isolated_count += 1
                        continue
                    if self.ruleBlockGoto(bl):
                        change = True
                        continue
                    if self.ruleBlockCat(bl):
                        change = True
                        continue
                    if self.ruleBlockProperIf(bl):
                        change = True
                        continue
                    if self.ruleBlockIfElse(bl):
                        change = True
                        continue
                    if self.ruleBlockWhileDo(bl):
                        change = True
                        continue
                    if self.ruleBlockDoWhile(bl):
                        change = True
                        continue
                    if self.ruleBlockInfLoop(bl):
                        change = True
                        continue
                    if self.ruleBlockSwitch(bl):
                        change = True
                        continue
                if not change:
                    break
            fullchange = False
            for index in range(self._graph.getSize()):
                bl = self._graph.getBlock(index)
                if self.ruleBlockIfNoExit(bl):
                    fullchange = True
                    break
                if self.ruleCaseFallthru(bl):
                    fullchange = True
                    break
            if not fullchange:
                break
        return isolated_count

    def collapseConditions(self):
        """Simplify conditionals.

        C++ ref: CollapseStructure::collapseConditions — re-checks graph.getSize()
        on every iteration so mid-loop block merges don't produce out-of-range access.
        """
        change = True
        while change:
            change = False
            i = 0
            while i < self._graph.getSize():
                if self.ruleBlockOr(self._graph.getBlock(i)):
                    change = True
                i += 1

    def ruleBlockGoto(self, bl) -> bool:
        """Attempt to apply the BlockGoto structure."""
        sizeout = bl.sizeOut()
        for i in range(sizeout):
            if bl.isGotoOut(i):
                if bl.isSwitchOut():
                    self._graph.newBlockMultiGoto(bl, i)
                    return True
                if sizeout == 2:
                    if not bl.isGotoOut(1):
                        if bl.negateCondition(True):
                            self._dataflow_changecount += 1
                    self._graph.newBlockIfGoto(bl)
                    return True
                if sizeout == 1:
                    self._graph.newBlockGoto(bl)
                    return True
        return False

    def ruleBlockCat(self, bl) -> bool:
        """Attempt to apply a BlockList structure."""
        if bl.sizeOut() != 1:
            return False
        if bl.isSwitchOut():
            return False
        if bl.sizeIn() == 1 and bl.getIn(0).sizeOut() == 1:
            return False
        outblock = bl.getOut(0)
        if outblock is bl:
            return False
        if outblock.sizeIn() != 1:
            return False
        if not bl.isDecisionOut(0):
            return False
        if outblock.isSwitchOut():
            return False
        nodes = [bl, outblock]
        while outblock.sizeOut() == 1:
            outbl2 = outblock.getOut(0)
            if outbl2 is bl:
                break
            if outbl2.sizeIn() != 1:
                break
            if not outblock.isDecisionOut(0):
                break
            if outbl2.isSwitchOut():
                break
            outblock = outbl2
            nodes.append(outblock)
        self._graph.newBlockList(nodes)
        return True

    def ruleBlockOr(self, bl) -> bool:
        """Attempt to apply a BlockCondition structure."""
        if bl.sizeOut() != 2:
            return False
        if bl.isGotoOut(0):
            return False
        if bl.isGotoOut(1):
            return False
        if bl.isSwitchOut():
            return False
        for i in range(2):
            orblock = bl.getOut(i)
            if orblock is bl:
                continue
            if orblock.sizeIn() != 1:
                continue
            if orblock.sizeOut() != 2:
                continue
            if orblock.isInteriorGotoTarget():
                continue
            if orblock.isSwitchOut():
                continue
            if bl.isBackEdgeOut(i):
                continue
            if orblock.isComplex():
                continue
            clauseblock = bl.getOut(1 - i)
            if clauseblock is bl:
                continue
            if clauseblock is orblock:
                continue
            j = -1
            for jj in range(2):
                if clauseblock is orblock.getOut(jj):
                    j = jj
                    break
            if j < 0:
                continue
            if orblock.getOut(1 - j) is bl:
                continue
            if i == 1:
                if bl.negateCondition(True):
                    self._dataflow_changecount += 1
            if j == 0:
                if orblock.negateCondition(True):
                    self._dataflow_changecount += 1
            self._graph.newBlockCondition(bl, orblock)
            return True
        return False

    def ruleBlockProperIf(self, bl) -> bool:
        """Attempt to apply a 2 component form of BlockIf."""
        if bl.sizeOut() != 2:
            return False
        if bl.isSwitchOut():
            return False
        if bl.getOut(0) is bl:
            return False
        if bl.getOut(1) is bl:
            return False
        if bl.isGotoOut(0):
            return False
        if bl.isGotoOut(1):
            return False
        for i in range(2):
            clauseblock = bl.getOut(i)
            if clauseblock.sizeIn() != 1:
                continue
            if clauseblock.sizeOut() != 1:
                continue
            if clauseblock.isSwitchOut():
                continue
            if not bl.isDecisionOut(i):
                continue
            if clauseblock.isGotoOut(0):
                continue
            outblock = clauseblock.getOut(0)
            if outblock is not bl.getOut(1 - i):
                continue
            if i == 0:
                if bl.negateCondition(True):
                    self._dataflow_changecount += 1
            self._graph.newBlockIf(bl, clauseblock)
            return True
        return False

    def ruleBlockIfElse(self, bl) -> bool:
        """Attempt to apply a 3 component form of BlockIf."""
        if bl.sizeOut() != 2:
            return False
        if bl.isSwitchOut():
            return False
        if not bl.isDecisionOut(0):
            return False
        if not bl.isDecisionOut(1):
            return False
        tc = bl.getTrueOut()
        fc = bl.getFalseOut()
        if tc.sizeIn() != 1:
            return False
        if fc.sizeIn() != 1:
            return False
        if tc.sizeOut() != 1:
            return False
        if fc.sizeOut() != 1:
            return False
        outblock = tc.getOut(0)
        if outblock is bl:
            return False
        if outblock is not fc.getOut(0):
            return False
        if tc.isSwitchOut():
            return False
        if fc.isSwitchOut():
            return False
        if tc.isGotoOut(0):
            return False
        if fc.isGotoOut(0):
            return False
        self._graph.newBlockIfElse(bl, tc, fc)
        return True

    def ruleBlockIfNoExit(self, bl) -> bool:
        """Attempt to apply BlockIf where the body does not exit."""
        if bl.sizeOut() != 2:
            return False
        if bl.isSwitchOut():
            return False
        if bl.getOut(0) is bl:
            return False
        if bl.getOut(1) is bl:
            return False
        if bl.isGotoOut(0):
            return False
        if bl.isGotoOut(1):
            return False
        for i in range(2):
            clauseblock = bl.getOut(i)
            if clauseblock.sizeIn() != 1:
                continue
            if clauseblock.sizeOut() != 0:
                continue
            if clauseblock.isSwitchOut():
                continue
            if not bl.isDecisionOut(i):
                continue
            if i == 0:
                if bl.negateCondition(True):
                    self._dataflow_changecount += 1
            self._graph.newBlockIf(bl, clauseblock)
            return True
        return False

    def ruleBlockWhileDo(self, bl) -> bool:
        """Attempt to apply the BlockWhileDo structure."""
        if bl.sizeOut() != 2:
            return False
        if bl.isSwitchOut():
            return False
        if bl.getOut(0) is bl:
            return False
        if bl.getOut(1) is bl:
            return False
        if bl.isInteriorGotoTarget():
            return False
        if bl.isGotoOut(0):
            return False
        if bl.isGotoOut(1):
            return False
        for i in range(2):
            clauseblock = bl.getOut(i)
            if clauseblock.sizeIn() != 1:
                continue
            if clauseblock.sizeOut() != 1:
                continue
            if clauseblock.isSwitchOut():
                continue
            if clauseblock.getOut(0) is not bl:
                continue
            overflow = bl.isComplex()
            if (i == 0) != overflow:
                if bl.negateCondition(True):
                    self._dataflow_changecount += 1
            newbl = self._graph.newBlockWhileDo(bl, clauseblock)
            if overflow:
                newbl.setOverflowSyntax()
            return True
        return False

    def ruleBlockDoWhile(self, bl) -> bool:
        """Attempt to apply the BlockDoWhile structure."""
        if bl.sizeOut() != 2:
            return False
        if bl.isSwitchOut():
            return False
        if bl.isGotoOut(0):
            return False
        if bl.isGotoOut(1):
            return False
        for i in range(2):
            if bl.getOut(i) is not bl:
                continue
            if i == 0:
                if bl.negateCondition(True):
                    self._dataflow_changecount += 1
            self._graph.newBlockDoWhile(bl)
            return True
        return False

    def ruleBlockInfLoop(self, bl) -> bool:
        """Attempt to apply the BlockInfLoop structure."""
        if bl.sizeOut() != 1:
            return False
        if bl.isGotoOut(0):
            return False
        if bl.getOut(0) is not bl:
            return False
        self._graph.newBlockInfLoop(bl)
        return True

    def checkSwitchSkips(self, switchbl, exitblock) -> bool:
        """Check for switch edges that go straight to the exit block."""
        if exitblock is None:
            return True
        sizeout = switchbl.sizeOut()
        defaultnottoexit = False
        anyskiptoexit = False
        for edgenum in range(sizeout):
            if switchbl.getOut(edgenum) is exitblock:
                if not switchbl.isDefaultBranch(edgenum):
                    anyskiptoexit = True
            else:
                if switchbl.isDefaultBranch(edgenum):
                    defaultnottoexit = True
        if not anyskiptoexit:
            return True
        from ghidra.block.block import FlowBlock
        if not defaultnottoexit and switchbl.getType() == FlowBlock.t_multigoto:
            if switchbl.hasDefaultGoto():
                defaultnottoexit = True
        if not defaultnottoexit:
            return True
        for edgenum in range(sizeout):
            if switchbl.getOut(edgenum) is exitblock:
                if not switchbl.isDefaultBranch(edgenum):
                    switchbl.setGotoBranch(edgenum)
        return False

    def ruleBlockSwitch(self, bl) -> bool:
        """Attempt to apply the BlockSwitch structure."""
        if not bl.isSwitchOut():
            return False
        exitblock = None
        sizeout = bl.sizeOut()
        for i in range(sizeout):
            curbl = bl.getOut(i)
            if curbl is bl:
                exitblock = curbl
                break
            if curbl.sizeOut() > 1:
                exitblock = curbl
                break
            if curbl.sizeIn() > 1:
                exitblock = curbl
                break
        if exitblock is None:
            for i in range(sizeout):
                curbl = bl.getOut(i)
                if curbl.isGotoIn(0):
                    return False
                if curbl.isSwitchOut():
                    return False
                if curbl.sizeOut() == 1:
                    if curbl.isGotoOut(0):
                        return False
                    if exitblock is not None:
                        if exitblock is not curbl.getOut(0):
                            return False
                    else:
                        exitblock = curbl.getOut(0)
        else:
            for i in range(exitblock.sizeIn()):
                if exitblock.isGotoIn(i):
                    return False
            for i in range(exitblock.sizeOut()):
                if exitblock.isGotoOut(i):
                    return False
            for i in range(sizeout):
                curbl = bl.getOut(i)
                if curbl is exitblock:
                    continue
                if curbl.sizeIn() > 1:
                    return False
                if curbl.isGotoIn(0):
                    return False
                if curbl.sizeOut() > 1:
                    return False
                if curbl.sizeOut() == 1:
                    if curbl.isGotoOut(0):
                        return False
                    if curbl.getOut(0) is not exitblock:
                        return False
                if curbl.isSwitchOut():
                    return False
        if not self.checkSwitchSkips(bl, exitblock):
            return True
        cases = [bl]
        for i in range(sizeout):
            curbl = bl.getOut(i)
            if curbl is exitblock:
                continue
            cases.append(curbl)
        self._graph.newBlockSwitch(cases, exitblock is not None)
        return True

    def ruleCaseFallthru(self, bl) -> bool:
        """Attempt to find one switch case falling through to another."""
        if not bl.isSwitchOut():
            return False
        sizeout = bl.sizeOut()
        nonfallthru = 0
        fallthru = []
        for i in range(sizeout):
            curbl = bl.getOut(i)
            if curbl is bl:
                return False
            if curbl.sizeIn() > 2 or curbl.sizeOut() > 1:
                nonfallthru += 1
            elif curbl.sizeOut() == 1:
                target = curbl.getOut(0)
                if target.sizeIn() == 2 and target.sizeOut() <= 1:
                    inslot = curbl.getOutRevIndex(0)
                    if target.getIn(1 - inslot) is bl:
                        fallthru.append(curbl)
            if nonfallthru > 1:
                return False
        if not fallthru:
            return False
        for curbl in fallthru:
            curbl.setGotoBranch(0)
        return True

    def selectGoto(self):
        """Select an edge to mark as unstructured."""
        while self.updateLoopBody():
            while self._likelyiter < len(self._likelygoto):
                outedge_ref = [0]
                startbl = self._likelygoto[self._likelyiter].getCurrentEdge(outedge_ref, self._graph)
                self._likelyiter += 1
                if startbl is not None:
                    startbl.setGotoBranch(outedge_ref[0])
                    return startbl
        if not self.clipExtraRoots():
            raise RuntimeError("Could not finish collapsing block structure")
        return None

    def labelLoops(self, looporder: list):
        """Identify all the loops in this graph."""
        for i in range(self._graph.getSize()):
            bl = self._graph.getBlock(i)
            sizein = bl.sizeIn()
            for j in range(sizein):
                if bl.isBackEdgeIn(j):
                    loopbottom = bl.getIn(j)
                    self._loopbody.append(LoopBody(bl))
                    curbody = self._loopbody[-1]
                    curbody.addTail(loopbottom)
                    looporder.append(curbody)
        from functools import cmp_to_key
        looporder.sort(key=cmp_to_key(lambda a, b: -1 if LoopBody.compare_ends(a, b) else (1 if LoopBody.compare_ends(b, a) else 0)))

    def orderLoopBodies(self):
        """Identify and label all loop structure for this graph."""
        looporder = []
        self.labelLoops(looporder)
        if self._loopbody:
            oldsize = len(looporder)
            LoopBody.mergeIdenticalHeads(looporder)
            if oldsize != len(looporder):
                self._loopbody = [lb for lb in self._loopbody if lb.getHead() is not None]
            for lb in self._loopbody:
                body = []
                lb.findBase(body)
                lb.labelContainments(body, looporder)
                LoopBody.clearMarks(body)
            self._loopbody.sort()
            for lb in self._loopbody:
                body = []
                lb.findBase(body)
                lb.findExit(body)
                lb.orderTails()
                lb.extend(body)
                lb.labelExitEdges(body)
                LoopBody.clearMarks(body)
        self._likelylistfull = False
        self._loopbodyiter = 0

    def updateLoopBody(self) -> bool:
        """Find likely unstructured edges within the innermost loop body."""
        if self._finaltrace:
            return False
        loopbottom = None
        looptop = None
        while self._loopbodyiter < len(self._loopbody):
            curBody = self._loopbody[self._loopbodyiter]
            loopbottom = curBody.update(self._graph)
            if loopbottom is not None:
                looptop = curBody.getHead()
                if loopbottom is looptop:
                    self._likelygoto.clear()
                    self._likelygoto.append(FloatingEdge(looptop, looptop))
                    self._likelyiter = 0
                    self._likelylistfull = True
                    return True
                if not self._likelylistfull or self._likelyiter < len(self._likelygoto):
                    break
            self._loopbodyiter += 1
            self._likelylistfull = False
            loopbottom = None
        if self._likelylistfull and self._likelyiter < len(self._likelygoto):
            return True
        self._likelygoto.clear()
        tracer = TraceDAG(self._likelygoto)
        if loopbottom is not None:
            tracer.addRoot(looptop)
            tracer.setFinishBlock(loopbottom)
            self._loopbody[self._loopbodyiter].setExitMarks(self._graph)
        else:
            for i in range(self._graph.getSize()):
                bl = self._graph.getBlock(i)
                if bl.sizeIn() == 0:
                    tracer.addRoot(bl)
        tracer.initialize()
        tracer.pushBranches()
        self._likelylistfull = True
        if loopbottom is not None:
            self._loopbody[self._loopbodyiter].emitLikelyEdges(self._likelygoto, self._graph)
            self._loopbody[self._loopbodyiter].clearExitMarks(self._graph)
        elif not self._likelygoto:
            self._finaltrace = True
            return False
        self._likelyiter = 0
        return True

    def onlyReachableFromRoot(self, root, body: list):
        """Find blocks only reachable from root."""
        trial = []
        root.setMark()
        body.append(root)
        i = 0
        while i < len(body):
            bl = body[i]
            i += 1
            sizeout = bl.sizeOut()
            for j in range(sizeout):
                curbl = bl.getOut(j)
                if curbl.isMark():
                    continue
                count = curbl.getVisitCount()
                if count == 0:
                    trial.append(curbl)
                count += 1
                curbl.setVisitCount(count)
                if count == curbl.sizeIn():
                    curbl.setMark()
                    body.append(curbl)
        for t in trial:
            t.setVisitCount(0)

    def markExitsAsGotos(self, body: list) -> int:
        """Mark edges exiting the body as unstructured gotos."""
        changecount = 0
        for bl in body:
            sizeout = bl.sizeOut()
            for j in range(sizeout):
                curbl = bl.getOut(j)
                if not curbl.isMark():
                    bl.setGotoBranch(j)
                    changecount += 1
        return changecount

    def clipExtraRoots(self) -> bool:
        """Mark edges between root components as unstructured gotos."""
        for i in range(1, self._graph.getSize()):
            bl = self._graph.getBlock(i)
            if bl.sizeIn() != 0:
                continue
            body = []
            self.onlyReachableFromRoot(bl, body)
            count = self.markExitsAsGotos(body)
            LoopBody.clearMarks(body)
            if count != 0:
                return True
        return False


# =========================================================================
# Action subclasses for block structuring have been consolidated into
# ghidra.transform.coreaction2 (proper Action subclasses).
# The canonical implementations are:
#   ActionBlockStructure, ActionFinalStructure, ActionReturnSplit,
#   ActionNodeJoin, ActionPreferComplement, ActionStructureTransform,
#   ActionNormalizeBranches
# =========================================================================
