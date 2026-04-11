"""
Corresponds to: graph.hh / graph.cc

Graph algorithms for control-flow analysis beyond Heritage SSA.
Interval analysis, dominance frontier refinement, loop detection,
and DAG-based structuring support.
"""

from __future__ import annotations
from typing import List, Optional, Set, Dict, Tuple, TextIO

from ghidra.core.opcodes import OpCode
from ghidra.core.space import IPTR_FSPEC, IPTR_IOP


class DomInfo:
    """Dominance information for a single node in the CFG."""
    __slots__ = ('idom', 'dfrontier', 'depth', 'index', 'semi', 'label', 'ancestor', 'parent')

    def __init__(self, idx: int = -1) -> None:
        self.idom: int = -1
        self.dfrontier: List[int] = []
        self.depth: int = 0
        self.index: int = idx
        self.semi: int = idx
        self.label: int = idx
        self.ancestor: int = -1
        self.parent: int = -1


class DominatorTree:
    """Compute and store the dominator tree for a control-flow graph.

    Uses the Lengauer-Tarjan algorithm for O(n * alpha(n)) dominators,
    then computes dominance frontiers.
    """

    def __init__(self, numnodes: int = 0) -> None:
        self._info: List[DomInfo] = [DomInfo(i) for i in range(numnodes)]
        self._order: List[int] = []  # DFS order
        self._numnodes: int = numnodes

    def getIdom(self, idx: int) -> int:
        if 0 <= idx < len(self._info):
            return self._info[idx].idom
        return -1

    def getDFrontier(self, idx: int) -> List[int]:
        if 0 <= idx < len(self._info):
            return self._info[idx].dfrontier
        return []

    def getDepth(self, idx: int) -> int:
        if 0 <= idx < len(self._info):
            return self._info[idx].depth
        return 0

    def dominates(self, a: int, b: int) -> bool:
        """Check if node a dominates node b."""
        cur = b
        while cur >= 0:
            if cur == a:
                return True
            cur = self.getIdom(cur)
        return False

    def computeDominators(self, graph, entry: int) -> None:
        """Compute dominators using Cooper-Harvey-Kennedy algorithm.

        This is a simpler iterative algorithm that works well in practice.
        graph must support: getSize(), getBlock(i), sizeIn()/getIn()/sizeOut()/getOut()
        """
        n = graph.getSize() if hasattr(graph, 'getSize') else 0
        if n == 0:
            return
        self._numnodes = n
        self._info = [DomInfo(i) for i in range(n)]

        # Build reverse post-order via DFS
        visited = [False] * n
        rpo = []

        def dfs(idx):
            visited[idx] = True
            bl = graph.getBlock(idx)
            for i in range(bl.sizeOut()):
                succ = bl.getOut(i)
                sidx = succ.getIndex() if hasattr(succ, 'getIndex') else -1
                if 0 <= sidx < n and not visited[sidx]:
                    dfs(sidx)
            rpo.append(idx)

        dfs(entry)
        rpo.reverse()
        self._order = rpo

        # Build rpo index map
        rpo_num = [-1] * n
        for i, idx in enumerate(rpo):
            rpo_num[idx] = i

        # Initialize
        doms = [-1] * n
        doms[entry] = entry

        def intersect(b1, b2):
            while b1 != b2:
                while rpo_num[b1] > rpo_num[b2]:
                    b1 = doms[b1]
                while rpo_num[b2] > rpo_num[b1]:
                    b2 = doms[b2]
            return b1

        # Iterate until stable
        changed = True
        while changed:
            changed = False
            for idx in rpo:
                if idx == entry:
                    continue
                bl = graph.getBlock(idx)
                new_idom = -1
                for i in range(bl.sizeIn()):
                    pred = bl.getIn(i)
                    pidx = pred.getIndex() if hasattr(pred, 'getIndex') else -1
                    if pidx < 0 or pidx >= n:
                        continue
                    if doms[pidx] == -1:
                        continue
                    if new_idom == -1:
                        new_idom = pidx
                    else:
                        new_idom = intersect(pidx, new_idom)
                if new_idom != -1 and doms[idx] != new_idom:
                    doms[idx] = new_idom
                    changed = True

        # Store results
        for i in range(n):
            self._info[i].idom = doms[i] if doms[i] != i else -1

        # Compute depths
        def computeDepth(idx):
            if self._info[idx].depth > 0 or idx == entry:
                return self._info[idx].depth
            parent = self._info[idx].idom
            if parent < 0:
                return 0
            self._info[idx].depth = computeDepth(parent) + 1
            return self._info[idx].depth

        for i in range(n):
            computeDepth(i)

    def computeDFrontier(self, graph) -> None:
        """Compute dominance frontiers for all nodes."""
        n = self._numnodes
        for i in range(n):
            self._info[i].dfrontier = []

        for idx in range(n):
            bl = graph.getBlock(idx)
            if bl.sizeIn() < 2:
                continue
            for i in range(bl.sizeIn()):
                pred = bl.getIn(i)
                pidx = pred.getIndex() if hasattr(pred, 'getIndex') else -1
                if pidx < 0 or pidx >= n:
                    continue
                runner = pidx
                while runner >= 0 and runner != self._info[idx].idom:
                    if idx not in self._info[runner].dfrontier:
                        self._info[runner].dfrontier.append(idx)
                    runner = self._info[runner].idom


class LoopDetector:
    """Detect natural loops in a control-flow graph.

    A natural loop is defined by a back edge (tail -> head) where
    head dominates tail. The loop body is all nodes that can reach
    tail without going through head.
    """

    def __init__(self) -> None:
        self._loops: List[Tuple[int, List[int]]] = []  # (head, [body nodes])

    def detect(self, graph, domtree: DominatorTree) -> None:
        """Find all natural loops in the graph."""
        self._loops.clear()
        n = graph.getSize() if hasattr(graph, 'getSize') else 0
        for idx in range(n):
            bl = graph.getBlock(idx)
            for i in range(bl.sizeOut()):
                succ = bl.getOut(i)
                sidx = succ.getIndex() if hasattr(succ, 'getIndex') else -1
                if sidx < 0 or sidx >= n:
                    continue
                # Check for back edge: succ dominates idx
                if domtree.dominates(sidx, idx):
                    body = self._findLoopBody(graph, sidx, idx, n)
                    self._loops.append((sidx, body))

    def _findLoopBody(self, graph, head: int, tail: int, n: int) -> List[int]:
        """Find all nodes in the loop body via reverse DFS from tail to head."""
        body = {head}
        if head == tail:
            return list(body)
        stack = [tail]
        while stack:
            node = stack.pop()
            if node in body:
                continue
            body.add(node)
            bl = graph.getBlock(node)
            for i in range(bl.sizeIn()):
                pred = bl.getIn(i)
                pidx = pred.getIndex() if hasattr(pred, 'getIndex') else -1
                if 0 <= pidx < n and pidx not in body:
                    stack.append(pidx)
        return sorted(body)

    def getLoops(self) -> List[Tuple[int, List[int]]]:
        return self._loops

    def numLoops(self) -> int:
        return len(self._loops)

    def isInLoop(self, nodeIdx: int) -> bool:
        for head, body in self._loops:
            if nodeIdx in body:
                return True
        return False

    def getLoopHead(self, nodeIdx: int) -> int:
        for head, body in self._loops:
            if nodeIdx in body:
                return head
        return -1


class IntervalGraph:
    """Interval-based graph analysis for reducibility testing.

    An interval I(h) with header h is the maximal single-entry subgraph
    such that any cycle in the subgraph passes through h.
    """

    def __init__(self) -> None:
        self._intervals: List[Tuple[int, Set[int]]] = []  # (header, {nodes})
        self._isReducible: bool = True

    def compute(self, graph, entry: int) -> None:
        """Compute intervals starting from the entry node."""
        self._intervals.clear()
        n = graph.getSize() if hasattr(graph, 'getSize') else 0
        if n == 0:
            return

        inInterval = [-1] * n
        headers = [entry]
        processed = set()

        while headers:
            h = headers.pop(0)
            if h in processed:
                continue
            processed.add(h)

            # Build interval I(h)
            interval = {h}
            inInterval[h] = len(self._intervals)
            worklist = []

            # Add successors of h
            bl = graph.getBlock(h)
            for i in range(bl.sizeOut()):
                succ = bl.getOut(i)
                sidx = succ.getIndex() if hasattr(succ, 'getIndex') else -1
                if 0 <= sidx < n and sidx != h:
                    worklist.append(sidx)

            changed = True
            while changed:
                changed = False
                new_worklist = []
                for m in worklist:
                    if m in interval:
                        continue
                    # Check if all predecessors of m are in the interval
                    mbl = graph.getBlock(m)
                    allInInterval = True
                    for j in range(mbl.sizeIn()):
                        pred = mbl.getIn(j)
                        pidx = pred.getIndex() if hasattr(pred, 'getIndex') else -1
                        if 0 <= pidx < n and pidx not in interval:
                            allInInterval = False
                            break
                    if allInInterval and inInterval[m] < 0:
                        interval.add(m)
                        inInterval[m] = len(self._intervals)
                        changed = True
                        # Add successors of m
                        mbl2 = graph.getBlock(m)
                        for j in range(mbl2.sizeOut()):
                            succ = mbl2.getOut(j)
                            sidx = succ.getIndex() if hasattr(succ, 'getIndex') else -1
                            if 0 <= sidx < n and sidx not in interval:
                                new_worklist.append(sidx)
                    else:
                        new_worklist.append(m)
                worklist = new_worklist

            self._intervals.append((h, interval))

            # Remaining worklist entries become new headers
            for m in worklist:
                if inInterval[m] < 0 and m not in processed:
                    headers.append(m)

        # Check reducibility: all edges go within or between intervals properly
        self._isReducible = all(inInterval[i] >= 0 for i in range(n))

    def isReducible(self) -> bool:
        return self._isReducible

    def numIntervals(self) -> int:
        return len(self._intervals)

    def getInterval(self, idx: int) -> Tuple[int, Set[int]]:
        return self._intervals[idx] if 0 <= idx < len(self._intervals) else (-1, set())


class SCCDetector:
    """Tarjan's algorithm for finding Strongly Connected Components."""

    def __init__(self) -> None:
        self._sccs: List[List[int]] = []

    def compute(self, graph) -> None:
        """Find all SCCs in the graph."""
        self._sccs.clear()
        n = graph.getSize() if hasattr(graph, 'getSize') else 0
        if n == 0:
            return

        index_counter = [0]
        stack = []
        on_stack = [False] * n
        index = [-1] * n
        lowlink = [-1] * n

        def strongconnect(v):
            index[v] = index_counter[0]
            lowlink[v] = index_counter[0]
            index_counter[0] += 1
            stack.append(v)
            on_stack[v] = True

            bl = graph.getBlock(v)
            for i in range(bl.sizeOut()):
                succ = bl.getOut(i)
                w = succ.getIndex() if hasattr(succ, 'getIndex') else -1
                if w < 0 or w >= n:
                    continue
                if index[w] == -1:
                    strongconnect(w)
                    lowlink[v] = min(lowlink[v], lowlink[w])
                elif on_stack[w]:
                    lowlink[v] = min(lowlink[v], index[w])

            if lowlink[v] == index[v]:
                scc = []
                while True:
                    w = stack.pop()
                    on_stack[w] = False
                    scc.append(w)
                    if w == v:
                        break
                self._sccs.append(scc)

        for v in range(n):
            if index[v] == -1:
                strongconnect(v)

    def getSCCs(self) -> List[List[int]]:
        return self._sccs

    def numSCCs(self) -> int:
        return len(self._sccs)

    def isInCycle(self, nodeIdx: int) -> bool:
        for scc in self._sccs:
            if len(scc) > 1 and nodeIdx in scc:
                return True
        return False


_BLOCK_ATTRIBUTES = (
    "\n// Attributes\n"
    "*CMD=DefineAttribute,\n"
    "        Name=SizeOut,\n"
    "        Type=String,\n"
    "        Category=Vertices;\n\n"
    "*CMD=DefineAttribute,\n"
    "        Name=SizeIn,\n"
    "        Type=String,\n"
    "        Category=Vertices;\n\n"
    "*CMD=DefineAttribute,\n"
    "        Name=Internal,\n"
    "        Type=String,\n"
    "        Category=Vertices;\n\n"
    "*CMD=DefineAttribute,\n"
    "        Name=Index,\n"
    "        Type=String,\n"
    "        Category=Vertices;\n\n"
    "*CMD=DefineAttribute,\n"
    "        Name=Start,\n"
    "        Type=String,\n"
    "        Category=Vertices;\n\n"
    "*CMD=DefineAttribute,\n"
    "        Name=Stop,\n"
    "        Type=String,\n"
    "        Category=Vertices;\n\n"
    "*CMD=SetKeyAttribute,\n"
    "        Category=Vertices,"
    "        Name=Index;\n\n"
)

_BLOCK_PROPERTIES = (
    "\n// AutomaticArrangement\n"
    "  *CMD = AlterLocalPreferences, Name = AutomaticArrangement,\n"
    "  ~ReplaceAllParams = TRUE,\n"
    "  EnableAutomaticArrangement=true,\n"
    "  OnlyActOnVerticesWithoutCoordsIfOff=false,\n"
    "  DontUpdateMediumWithUserArrangement=false,\n"
    "  UserAddedArrangmentParams=({ServiceName=SimpleHierarchyFromSources,ServiceParams={~SkipPromptForParams=true}}),\n"
    "  SmallSize=50,\n"
    "  DontUpdateLargeWithUserArrangement=true,\n"
    "  NewVertexActionIfOff=ArrangeByMDS,\n"
    "  MediumSizeArrangement=SimpleHierarchyFromSources,\n"
    "  SmallSizeArrangement=SimpleHierarchyFromSources,\n"
    "  MediumSize=800,\n"
    "  LargeSizeArrangement=ArrangeInCircle,\n"
    "  DontUpdateSmallWithUserArrangement=false,\n"
    "  ActionSizeGainIfOff=1.0;\n"
    "\n// VertexColors\n"
    "  *CMD = AlterLocalPreferences, Name = VertexColors,\n"
    "  ~ReplaceAllParams = TRUE,\n"
    "  Mapping=({DisplayChoice=Red,AttributeValue=0},\n"
    "  {DisplayChoice=Blue,AttributeValue=1},\n"
    "  {DisplayChoice=Yellow,AttributeValue=2}),\n"
    "  ChoiceForValueNotCovered=Purple,\n"
    "  Extraction=CompleteValue,\n"
    "  ExtractionParams={},\n"
    "  AttributeName=SizeOut,\n"
    "  ChoiceForMissingValue=Purple,\n"
    "  CanOverride=true,\n"
    "  OverrideAttributeName=Color,\n"
    "  UsingRange=false;\n"
    "\n//     VertexIcons\n"
    "  *CMD = AlterLocalPreferences, Name = VertexIcons,\n"
    "  ~ReplaceAllParams = TRUE,\n"
    "  Mapping=({DisplayChoice=Square,AttributeValue=0}),\n"
    "  ChoiceForValueNotCovered=Circle,\n"
    "  Extraction=CompleteValue,\n"
    "  ExtractionParams={},\n"
    "  AttributeName=SizeIn,\n"
    "  ChoiceForMissingValue=Circle,\n"
    "  CanOverride=true,\n"
    "  OverrideAttributeName=Icon,\n"
    "  UsingRange=false;\n"
    "\n//     VertexLabels\n"
    "  *CMD = AlterLocalPreferences, Name = VertexLabels,\n"
    "  ~ReplaceAllParams = TRUE,\n"
    "  Center=({MaxLines=4,SqueezeLinesTogether=true,TreatBackSlashNAsNewLine=false,FontSize=10,Format=StandardFormat,IncludeBackground=false,BackgroundColor=Black,AttributeName=Start,UseSpecialFontName=false,SpecialColor=Black,SpecialFontName=SansSerif,UseSpecialColor=false,LabelAlignment=Center,MaxWidth=100}),\n"
    "  East=(),\n"
    "  SouthEast=(),\n"
    "  North=(),\n"
    "  West=(),\n"
    "  SouthWest=(),\n"
    "  NorthEast=(),\n"
    "  South=(),\n"
    "  NorthWest=();\n"
)


_DATAFLOW_AUTOMATIC_ARRANGEMENT = (
    "\n// AutomaticArrangement\n"
    "  *CMD = AlterLocalPreferences, Name = AutomaticArrangement,\n"
    "  ~ReplaceAllParams = TRUE,\n"
    "  EnableAutomaticArrangement=true,\n"
    "  OnlyActOnVerticesWithoutCoordsIfOff=false,\n"
    "  DontUpdateMediumWithUserArrangement=false,\n"
    "  UserAddedArrangmentParams=({ServiceName=SimpleHierarchyFromSources,ServiceParams={~SkipPromptForParams=true}}),\n"
    "  SmallSize=50,\n"
    "  DontUpdateLargeWithUserArrangement=true,\n"
    "  NewVertexActionIfOff=ArrangeByMDS,\n"
    "  MediumSizeArrangement=SimpleHierarchyFromSources,\n"
    "  SmallSizeArrangement=SimpleHierarchyFromSources,\n"
    "  MediumSize=800,\n"
    "  LargeSizeArrangement=ArrangeInCircle,\n"
    "  DontUpdateSmallWithUserArrangement=false,\n"
    "  ActionSizeGainIfOff=1.0;\n"
)


_DATAFLOW_VERTEX_COLORS = (
    "\n// VertexColors\n"
    "  *CMD = AlterLocalPreferences, Name = VertexColors,\n"
    "  ~ReplaceAllParams = TRUE,\n"
    "  Mapping=({DisplayChoice=Magenta,AttributeValue=branch},\n"
    "  {DisplayChoice=Blue,AttributeValue=register},\n"
    "  {DisplayChoice=Black,AttributeValue=unique},\n"
    "  {DisplayChoice=DarkGreen,AttributeValue=const},\n"
    "  {DisplayChoice=DarkOrange,AttributeValue=ram},\n"
    "  {DisplayChoice=Orange,AttributeValue=stack}),\n"
    "  ChoiceForValueNotCovered=Red,\n"
    "  Extraction=CompleteValue,\n"
    "  ExtractionParams={},\n"
    "  AttributeName=SubClass,\n"
    "  ChoiceForMissingValue=Red,\n"
    "  CanOverride=true,\n"
    "  OverrideAttributeName=Color,\n"
    "  UsingRange=false;\n"
)


_DATAFLOW_VERTEX_ICONS = (
    "\n//     VertexIcons\n"
    "  *CMD = AlterLocalPreferences, Name = VertexIcons,\n"
    "  ~ReplaceAllParams = TRUE,\n"
    "  Mapping=({DisplayChoice=Circle,AttributeValue=var},\n"
    "  {DisplayChoice=Square,AttributeValue=op}),\n"
    "  ChoiceForValueNotCovered=Circle,\n"
    "  Extraction=CompleteValue,\n"
    "  ExtractionParams={},\n"
    "  AttributeName=Type,\n"
    "  ChoiceForMissingValue=Circle,\n"
    "  CanOverride=true,\n"
    "  OverrideAttributeName=Icon,\n"
    "  UsingRange=false;\n"
)


_DATAFLOW_VERTEX_LABELS = (
    "\n//     VertexLabels\n"
    "  *CMD = AlterLocalPreferences, Name = VertexLabels,\n"
    "  ~ReplaceAllParams = TRUE,\n"
    "  Center=({SpecialColor=Black,SpecialFontName=SansSerif,Format=StandardFormat,UseSpecialFontName=false,LabelAlignment=Center,TreatBackSlashNAsNewLine=false,MaxLines=4,FontSize=10,IncludeBackground=false,SqueezeLinesTogether=true,BackgroundColor=Black,UseSpecialColor=false,AttributeName=Name,MaxWidth=100}),\n"
    "  East=(),\n"
    "  SouthEast=(),\n"
    "  North=(),\n"
    "  West=(),\n"
    "  SouthWest=(),\n"
    "  NorthEast=(),\n"
    "  South=(),\n"
    "  NorthWest=();\n"
)


_DATAFLOW_ATTRIBUTES = (
    "\n// Attributes\n"
    "*CMD=DefineAttribute,\n"
    "        Name=SubClass,\n"
    "        Type=String,\n"
    "        Category=Vertices;\n\n"
    "*CMD=DefineAttribute,\n"
    "        Name=Type,\n"
    "        Type=String,\n"
    "        Category=Vertices;\n\n"
    "*CMD=DefineAttribute,\n"
    "        Name=Internal,\n"
    "        Type=String,\n"
    "        Category=Vertices;\n\n"
    "*CMD=DefineAttribute,\n"
    "        Name=Name,\n"
    "        Type=String,\n"
    "        Category=Vertices;\n\n"
    "*CMD=DefineAttribute,\n"
    "        Name=Address,\n"
    "        Type=String,\n"
    "        Category=Vertices;\n\n"
    "*CMD=DefineAttribute,\n"
    "        Name=Name,\n"
    "        Type=String,\n"
    "        Category=Edges;\n\n"
    "*CMD=SetKeyAttribute,\n"
    "        Category=Vertices,"
    "        Name=Internal;\n\n"
)


def _get_dataflow_bounds(op) -> tuple[int, int]:
    start = 0
    stop = op.numInput()
    opcode = op.code()
    if opcode in (OpCode.CPUI_LOAD, OpCode.CPUI_STORE, OpCode.CPUI_BRANCH, OpCode.CPUI_CALL):
        start = 1
    elif opcode == OpCode.CPUI_INDIRECT:
        stop = 1
    return start, stop


def _print_varnode_vertex(vn, out: TextIO) -> None:
    if vn is None or vn.isMark():
        return
    spc = vn.getSpace()
    if spc is None:
        return
    tp = spc.getType()
    if tp == IPTR_FSPEC or tp == IPTR_IOP:
        return

    raw = vn.printRawNoMarkup()
    raw_text = raw[0] if isinstance(raw, tuple) else str(raw)
    out.write(f"v{vn.getCreateIndex()} {spc.getName()} var {raw_text}")

    op = vn.getDef()
    if op is not None:
        out.write(f" {op.getAddr().getOffset():x}")
    elif vn.isInput():
        out.write(" i")
    else:
        out.write(" <na>")
    out.write("\n")
    vn.setMark()


def _print_op_vertex(op, out: TextIO) -> None:
    if op.isBranch():
        subclass = "branch"
    elif op.isCall():
        subclass = "call"
    elif op.isMarker():
        subclass = "marker"
    else:
        subclass = "basic"
    opname = op.getOpName() if op.getOpName() else "unkop"
    out.write(f"o{op.getTime()} {subclass} op {opname} {op.getAddr().getOffset():x}\n")


def _dump_varnode_vertex(data, out: TextIO) -> None:
    ops = list(data.beginOpAlive())
    out.write(
        "\n\n// Add Vertices\n"
        "*CMD=*COLUMNAR_INPUT,\n"
        "  Command=AddVertices,\n"
        "  Parsing=WhiteSpace,\n"
        "  Fields=({Name=Internal, Location=1},\n"
        "          {Name=SubClass, Location=2},\n"
        "          {Name=Type, Location=3},\n"
        "          {Name=Name, Location=4},\n"
        "          {Name=Address, Location=5});\n\n"
        "//START:varnodes\n"
    )
    for op in ops:
        _print_varnode_vertex(op.getOut(), out)
        start, stop = _get_dataflow_bounds(op)
        for i in range(start, stop):
            _print_varnode_vertex(op.getIn(i), out)
    out.write("*END_COLUMNS\n")
    for op in ops:
        out_vn = op.getOut()
        if out_vn is not None:
            out_vn.clearMark()
        for i in range(op.numInput()):
            in_vn = op.getIn(i)
            if in_vn is not None:
                in_vn.clearMark()


def _dump_op_vertex(data, out: TextIO) -> None:
    out.write(
        "\n\n// Add Vertices\n"
        "*CMD=*COLUMNAR_INPUT,\n"
        "  Command=AddVertices,\n"
        "  Parsing=WhiteSpace,\n"
        "  Fields=({Name=Internal, Location=1},\n"
        "          {Name=SubClass, Location=2},\n"
        "          {Name=Type, Location=3},\n"
        "          {Name=Name, Location=4},\n"
        "          {Name=Address, Location=5});\n\n"
        "//START:opnodes\n"
    )
    for op in data.beginOpAlive():
        _print_op_vertex(op, out)
    out.write("*END_COLUMNS\n")


def _print_dataflow_edges(op, out: TextIO) -> None:
    vn = op.getOut()
    if vn is not None:
        out.write(f"o{op.getTime()} v{vn.getCreateIndex()} output\n")

    start, stop = _get_dataflow_bounds(op)
    for i in range(start, stop):
        vn = op.getIn(i)
        if vn is None:
            continue
        spc = vn.getSpace()
        if spc is None:
            continue
        tp = spc.getType()
        if tp != IPTR_FSPEC and tp != IPTR_IOP:
            out.write(f"v{vn.getCreateIndex()} o{op.getTime()} input\n")


def _dump_dataflow_edges(data, out: TextIO) -> None:
    out.write(
        "\n\n// Add Edges\n"
        "*CMD=*COLUMNAR_INPUT,\n"
        "  Command=AddEdges,\n"
        "  Parsing=WhiteSpace,\n"
        "  Fields=({Name=*FromKey, Location=1},\n"
        "          {Name=*ToKey, Location=2},\n"
        "          {Name=Name, Location=3});\n\n"
        "//START:edges\n"
    )
    for op in data.beginOpAlive():
        _print_dataflow_edges(op, out)
    out.write("*END_COLUMNS\n")


def dump_dataflow_graph(data, out: TextIO) -> None:
    """Serialize the data-flow graph in Renoir format.

    C++ ref: ``dump_dataflow_graph``
    """
    out.write(f"*CMD=NewGraphWindow, WindowName={data.getName()}-dataflow;\n")
    out.write(f"*CMD=*NEXUS,Name={data.getName()}-dataflow;\n")
    out.write(_DATAFLOW_AUTOMATIC_ARRANGEMENT)
    out.write(_DATAFLOW_VERTEX_COLORS)
    out.write(_DATAFLOW_VERTEX_ICONS)
    out.write(_DATAFLOW_VERTEX_LABELS)
    out.write(_DATAFLOW_ATTRIBUTES)
    _dump_varnode_vertex(data, out)
    _dump_op_vertex(data, out)
    _dump_dataflow_edges(data, out)


def _print_block_vertex(block, out: TextIO) -> None:
    out.write(
        f" {block.sizeOut()} {block.sizeIn()} {block.getIndex()} "
        f"{block.getStart().getOffset():x} {block.getStop().getOffset():x}\n"
    )


def _print_block_edge(block, out: TextIO) -> None:
    for i in range(block.sizeIn()):
        out.write(f"{block.getIn(i).getIndex()} {block.getIndex()}\n")


def _dump_block_vertex(graph, out: TextIO, falsenode: bool) -> None:
    out.write(
        "\n\n// Add Vertices\n"
        "*CMD=*COLUMNAR_INPUT,\n"
        "  Command=AddVertices,\n"
        "  Parsing=WhiteSpace,\n"
        "  Fields=({Name=SizeOut, Location=1},\n"
        "          {Name=SizeIn, Location=2},\n"
        "          {Name=Internal, Location=3},\n"
        "          {Name=Index, Location=4},\n"
        "          {Name=Start, Location=5},\n"
        "          {Name=Stop, Location=6});\n\n"
    )
    if falsenode:
        out.write("-1 0 0 -1 0 0\n")
    for i in range(graph.getSize()):
        _print_block_vertex(graph.getBlock(i), out)
    out.write("*END_COLUMNS\n")


def _dump_block_edges(graph, out: TextIO) -> None:
    out.write(
        "\n\n// Add Edges\n"
        "*CMD=*COLUMNAR_INPUT,\n"
        "  Command=AddEdges,\n"
        "  Parsing=WhiteSpace,\n"
        "  Fields=({Name=*FromKey, Location=1},\n"
        "          {Name=*ToKey, Location=2});\n\n"
    )
    for i in range(graph.getSize()):
        _print_block_edge(graph.getBlock(i), out)
    out.write("*END_COLUMNS\n")


def _print_dom_edge(block, out: TextIO, falsenode: bool) -> None:
    dom = block.getImmedDom()
    if dom is not None:
        out.write(f"{dom.getIndex()} {block.getIndex()}\n")
    elif falsenode:
        out.write(f"-1 {block.getIndex()}\n")


def _dump_dom_edges(graph, out: TextIO, falsenode: bool) -> None:
    out.write(
        "\n\n// Add Edges\n"
        "*CMD=*COLUMNAR_INPUT,\n"
        "  Command=AddEdges,\n"
        "  Parsing=WhiteSpace,\n"
        "  Fields=({Name=*FromKey, Location=1},\n"
        "          {Name=*ToKey, Location=2});\n\n"
    )
    for i in range(graph.getSize()):
        _print_dom_edge(graph.getBlock(i), out, falsenode)
    out.write("*END_COLUMNS\n")


def _dump_block_attributes(out: TextIO) -> None:
    out.write(_BLOCK_ATTRIBUTES)


def _dump_block_properties(out: TextIO) -> None:
    out.write(_BLOCK_PROPERTIES)


def dump_controlflow_graph(name: str, graph, out: TextIO) -> None:
    """Serialize the control-flow graph in Renoir format.

    C++ ref: ``dump_controlflow_graph``
    """
    out.write(f"*CMD=NewGraphWindow, WindowName={name}-controlflow;\n")
    out.write(f"*CMD=*NEXUS,Name={name}-controlflow;\n")
    _dump_block_properties(out)
    _dump_block_attributes(out)
    _dump_block_vertex(graph, out, False)
    _dump_block_edges(graph, out)


def dump_dom_graph(name: str, graph, out: TextIO) -> None:
    """Serialize the dominator graph in Renoir format.

    C++ ref: ``dump_dom_graph``
    """
    count = 0
    for i in range(graph.getSize()):
        if graph.getBlock(i).getImmedDom() is None:
            count += 1
    falsenode = count > 1
    out.write(f"*CMD=NewGraphWindow, WindowName={name}-dom;\n")
    out.write(f"*CMD=*NEXUS,Name={name}-dom;\n")
    _dump_block_properties(out)
    _dump_block_attributes(out)
    _dump_block_vertex(graph, out, falsenode)
    _dump_dom_edges(graph, out, falsenode)
