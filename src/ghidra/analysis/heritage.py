"""
Corresponds to: heritage.hh / heritage.cc

Utilities for building Static Single Assignment (SSA) form.
Core classes: LocationMap, MemRange, TaskList, PriorityQueue, HeritageInfo, LoadGuard, Heritage.
"""

from __future__ import annotations

from typing import TYPE_CHECKING, Optional, List, Dict, Tuple
from collections import defaultdict
from bisect import bisect_left, bisect_right

from ghidra.core.address import Address, calc_mask
from ghidra.core.space import AddrSpace, IPTR_CONSTANT, IPTR_SPACEBASE, IPTR_INTERNAL, IPTR_PROCESSOR, IPTR_IOP
from ghidra.core.opcodes import OpCode

if TYPE_CHECKING:
    from ghidra.ir.varnode import Varnode
    from ghidra.ir.op import PcodeOp
    from ghidra.block.block import FlowBlock, BlockBasic, BlockGraph
    from ghidra.analysis.funcdata import Funcdata
    from ghidra.fspec.fspec import FuncCallSpecs


# =========================================================================
# LocationMap
# =========================================================================

class LocationMap:
    """Map object tracking which address ranges have been heritaged.

    Keeps track of when each address range was entered in SSA form.
    An address range is added using add(), which includes the particular
    pass when it was entered. The map can be queried using findPass().
    """

    class SizePass:
        __slots__ = ('size', 'pass_')
        def __init__(self, size: int = 0, pass_: int = 0):
            self.size = size
            self.pass_ = pass_

    def __init__(self) -> None:
        self._map: Dict[Address, LocationMap.SizePass] = {}
        self._by_base: dict = {}  # base → {addr: SizePass} for fast same-space lookup

    def add(self, addr: Address, size: int, pass_: int, intersect_ref: list = None) -> Address:
        """Mark new address as heritaged. Returns the key of the containing entry.

        intersect_ref[0] is set to:
          0 if only intersection is with range from the same pass
          1 if there is a partial intersection with something old
          2 if the range is contained in an old range
        """
        if intersect_ref is None:
            intersect_ref = [0]
        intersect_ref[0] = 0

        addr_base = addr.base
        addr_off = addr.offset
        highest = addr_base._highest

        # Only iterate same-base entries via _by_base index (avoids O(N) base-check filter)
        base_bucket = self._by_base.get(addr_base)
        if base_bucket:
            to_delete = None  # Deferred deletions — avoids list(items()) copy
            for existing_addr, sp in base_bucket.items():
                ex_off = existing_addr.offset
                dist = addr_off - ex_off
                if dist < 0 or dist > highest:
                    dist = -1
                if dist == -1 or dist >= sp.size:
                    dist2 = ex_off - addr_off
                    if dist2 < 0 or dist2 > highest or dist2 >= size:
                        continue
                    end1 = addr_off + size
                    end2 = ex_off + sp.size
                    new_end = end1 if end1 > end2 else end2
                    size = new_end - addr_off
                    if sp.pass_ < pass_:
                        intersect_ref[0] = 1
                        pass_ = sp.pass_
                    if to_delete is None:
                        to_delete = [existing_addr]
                    else:
                        to_delete.append(existing_addr)
                    continue

                if dist + size <= sp.size:
                    intersect_ref[0] = 2 if sp.pass_ < pass_ else 0
                    return existing_addr

                new_size = dist + size
                if sp.pass_ < pass_:
                    intersect_ref[0] = 1
                    pass_ = sp.pass_
                addr = existing_addr
                addr_off = ex_off
                size = new_size
                if to_delete is None:
                    to_delete = [existing_addr]
                else:
                    to_delete.append(existing_addr)
            if to_delete:
                for ea in to_delete:
                    del base_bucket[ea]
                    del self._map[ea]

        sp = LocationMap.SizePass(size, pass_)
        self._map[addr] = sp
        if base_bucket is None:
            base_bucket = {}
            self._by_base[addr_base] = base_bucket
        base_bucket[addr] = sp
        return addr


    def findPass(self, addr: Address) -> int:
        """Look up if/how given address was heritaged. Returns pass number or -1."""
        result = self.find(addr)
        if result is None:
            return -1
        return result[1].pass_

    def erase(self, addr: Address) -> None:
        if addr in self._map:
            del self._map[addr]
            bb = self._by_base.get(addr.base)
            if bb is not None and addr in bb:
                del bb[addr]

    def clear(self) -> None:
        self._map.clear()
        self._by_base.clear()

    def begin(self):
        return iter(self._map.items())

    def end(self):
        return None

    def __iter__(self):
        return iter(self._map.items())


# =========================================================================
# MemRange
# =========================================================================

class MemRange:
    """An address range to be processed during heritage."""
    new_addresses = 1
    old_addresses = 2

    def __init__(self, addr: Address, size: int, flags: int = 0):
        self.addr = addr
        self.size = size
        self.flags = flags

    def newAddresses(self) -> bool:
        return (self.flags & MemRange.new_addresses) != 0

    def oldAddresses(self) -> bool:
        return (self.flags & MemRange.old_addresses) != 0

    def clearProperty(self, val: int) -> None:
        self.flags &= ~val


# =========================================================================
# TaskList
# =========================================================================

class TaskList:
    """A list of address ranges that need to be converted to SSA form.

    The disjoint list of ranges are built up and processed in a single pass.
    """

    def __init__(self) -> None:
        self._list: List[MemRange] = []

    def add(self, addr: Address, size: int, fl: int) -> None:
        """Add a range to the list (merging if overlapping with any existing entry).

        C++ LocationMap is a sorted map that naturally deduplicates.
        We search the entire list to find an existing entry that overlaps
        the new range and merge into it rather than creating a duplicate.
        """
        spc = addr.getSpace()
        off = addr.getOffset()
        for entry in self._list:
            if entry.addr.getSpace() is not spc:
                continue
            e_off = entry.addr.getOffset()
            e_end = e_off + entry.size
            # Check overlap: [off, off+size) intersects [e_off, e_end)
            if off < e_end and (off + size) > e_off:
                # Merge: extend entry to cover both ranges
                new_off = min(off, e_off)
                new_end = max(off + size, e_end)
                entry.addr = Address(spc, new_off)
                entry.size = new_end - new_off
                entry.flags |= fl
                return
            # Also merge if ranges are identical
            if off == e_off and size == entry.size:
                entry.flags |= fl
                return
        self._list.append(MemRange(addr, size, fl))

    def insert(self, pos: int, addr: Address, size: int, fl: int) -> int:
        """Insert a disjoint range at position pos."""
        self._list.insert(pos, MemRange(addr, size, fl))
        return pos

    def erase(self, idx: int) -> int:
        del self._list[idx]
        return idx

    def begin(self):
        return iter(self._list)

    def end(self):
        return None

    def clear(self) -> None:
        self._list.clear()

    def sort(self) -> None:
        """Sort ranges by address to match C++ sorted map iteration order."""
        self._list.sort(key=lambda m: (id(m.addr.getSpace()), m.addr.getOffset()))

    def __iter__(self):
        return iter(self._list)

    def __len__(self):
        return len(self._list)

    def __getitem__(self, idx):
        return self._list[idx]


# =========================================================================
# PriorityQueue
# =========================================================================

class PriorityQueue:
    """Priority queue for the phi-node placement algorithm.

    Implemented as a set of stacks with an associated priority.
    """

    def __init__(self) -> None:
        self._queue: List[List[FlowBlock]] = []
        self._curdepth: int = -2

    def reset(self, maxdepth: int) -> None:
        """Reset to an empty queue."""
        self._queue = [[] for _ in range(maxdepth + 1)]
        self._curdepth = -1

    def insert(self, bl: FlowBlock, depth: int) -> None:
        """Insert a block into the queue given its priority."""
        while len(self._queue) <= depth:
            self._queue.append([])
        self._queue[depth].append(bl)
        if depth > self._curdepth:
            self._curdepth = depth

    def extract(self) -> Optional[FlowBlock]:
        """Retrieve the highest priority block."""
        if self._curdepth < 0:
            return None
        res = self._queue[self._curdepth].pop()
        while self._curdepth >= 0 and not self._queue[self._curdepth]:
            self._curdepth -= 1
        return res

    def empty(self) -> bool:
        return self._curdepth == -1


# =========================================================================
# HeritageInfo
# =========================================================================

class HeritageInfo:
    """Information about heritage passes performed for a specific address space."""

    def __init__(self, spc: Optional[AddrSpace] = None) -> None:
        if spc is None:
            self.space: Optional[AddrSpace] = None
            self.delay: int = 0
            self.deadcodedelay: int = 0
            self.hasCallPlaceholders: bool = False
        elif not spc.isHeritaged():
            self.space = None
            self.delay = spc.getDelay()
            self.deadcodedelay = spc.getDeadcodeDelay()
            self.hasCallPlaceholders = False
        else:
            self.space = spc
            self.delay = spc.getDelay()
            self.deadcodedelay = spc.getDeadcodeDelay()
            self.hasCallPlaceholders = (spc.getType() == IPTR_SPACEBASE)
        self.deadremoved: int = 0
        self.warningissued: bool = False
        self.loadGuardSearch: bool = False

    def isHeritaged(self) -> bool:
        return self.space is not None

    def getSpace(self) -> Optional[AddrSpace]:
        return self.space

    def getDelay(self) -> int:
        return self.delay

    def getDeadcodeDelay(self) -> int:
        return self.deadcodedelay

    def isWarningIssued(self) -> bool:
        return self.warningissued

    def setWarningIssued(self, val: bool) -> None:
        self.warningissued = val

    def isLoadGuardSearch(self) -> bool:
        return self.loadGuardSearch

    def setLoadGuardSearch(self, val: bool) -> None:
        self.loadGuardSearch = val

    def reset(self) -> None:
        self.deadremoved = 0
        if self.space is not None:
            self.hasCallPlaceholders = (self.space.getType() == IPTR_SPACEBASE)
        self.warningissued = False
        self.loadGuardSearch = False


# =========================================================================
# LoadGuard
# =========================================================================

class LoadGuard:
    """Description of a LOAD operation that needs to be guarded.

    Heritage maintains a list of CPUI_LOAD ops that reference the stack
    dynamically. These can potentially alias stack Varnodes.
    """

    def __init__(self) -> None:
        self.op: Optional[PcodeOp] = None
        self.spc: Optional[AddrSpace] = None
        self.pointerBase: int = 0
        self.minimumOffset: int = 0
        self.maximumOffset: int = 0
        self.step: int = 0
        self.analysisState: int = 0  # 0=unanalyzed, 1=analyzed(partial), 2=analyzed(full)

    def set(self, o, s: AddrSpace, off: int) -> None:
        """Set a new unanalyzed LOAD guard that initially guards everything."""
        self.op = o
        self.spc = s
        self.pointerBase = off
        self.minimumOffset = 0
        self.maximumOffset = s.getHighest() if s else 0xFFFFFFFFFFFFFFFF
        self.step = 0
        self.analysisState = 0

    def getOp(self):
        return self.op

    def getMinimum(self) -> int:
        return self.minimumOffset

    def getMaximum(self) -> int:
        return self.maximumOffset

    def getStep(self) -> int:
        return self.step

    def isGuarded(self, addr: Address) -> bool:
        """Does this guard apply to the given address?"""
        if addr.getSpace() is not self.spc:
            return False
        off = addr.getOffset()
        return self.minimumOffset <= off <= self.maximumOffset

    def establishRange(self, valueSet) -> None:
        """Establish the range of stack offsets that might be accessed.

        C++ ref: LoadGuard::establishRange
        """
        rng = valueSet.getRange()
        rangeSize = rng.getSize()
        if rng.isEmpty():
            self.minimumOffset = self.pointerBase
            size = 0x1000
        elif rng.isFull() or rangeSize > 0xFFFFFF:
            self.minimumOffset = self.pointerBase
            size = 0x1000
            self.analysisState = 1
        else:
            self.step = rng.getStep() if rangeSize == 3 else 0
            size = 0x1000
            if valueSet.isLeftStable():
                self.minimumOffset = rng.getMin()
            elif valueSet.isRightStable():
                if self.pointerBase < rng.getEnd():
                    self.minimumOffset = self.pointerBase
                    size = rng.getEnd() - self.pointerBase
                else:
                    self.minimumOffset = rng.getMin()
                    size = rangeSize * rng.getStep()
            else:
                self.minimumOffset = self.pointerBase
        maxAddr = self.spc.getHighest() if self.spc else 0xFFFFFFFFFFFFFFFF
        if self.minimumOffset > maxAddr:
            self.minimumOffset = maxAddr
            self.maximumOffset = self.minimumOffset
        else:
            maxSize = (maxAddr - self.minimumOffset) + 1
            if size > maxSize:
                size = maxSize
            self.maximumOffset = self.minimumOffset + size - 1

    def finalizeRange(self, valueSet) -> None:
        """Finalize the range using a converged value set.

        C++ ref: LoadGuard::finalizeRange
        """
        self.analysisState = 1
        rng = valueSet.getRange()
        rangeSize = rng.getSize()
        if rangeSize == 0x100 or rangeSize == 0x10000:
            if self.step == 0:
                rangeSize = 0
        if 1 < rangeSize < 0xFFFFFF:
            self.analysisState = 2
            if rangeSize > 2:
                self.step = rng.getStep()
            self.minimumOffset = rng.getMin()
            self.maximumOffset = (rng.getEnd() - 1) & rng.getMask()
            if self.maximumOffset < self.minimumOffset:
                maxAddr = self.spc.getHighest() if self.spc else 0xFFFFFFFFFFFFFFFF
                self.maximumOffset = maxAddr
                self.analysisState = 1
        maxAddr = self.spc.getHighest() if self.spc else 0xFFFFFFFFFFFFFFFF
        if self.minimumOffset > maxAddr:
            self.minimumOffset = maxAddr
        if self.maximumOffset > maxAddr:
            self.maximumOffset = maxAddr

    def isRangeLocked(self) -> bool:
        return self.analysisState == 2

    def isValid(self, opc) -> bool:
        """Return True if the record still describes an active LOAD."""
        if self.op is None:
            return False
        if hasattr(self.op, 'isDead') and self.op.isDead():
            return False
        return self.op.code() == opc


class Heritage:
    """Manage the construction of Static Single Assignment (SSA) form.

    With a specific function (Funcdata), this class links the Varnode and
    PcodeOp objects into the formal data-flow graph structure, SSA form.
    The full structure can be built over multiple passes.

    The two big aspects of SSA construction are phi-node placement, performed
    by placeMultiequals(), and the renaming algorithm, performed by rename().

    Phi-node placement algorithm from Bilardi and Pingali.
    Renaming algorithm from Cytron, Ferrante, Rosen, Wegman, Zadeck (1991).
    """

    # Extra boolean properties on basic blocks for Augmented Dominator Tree
    boundary_node = 1
    mark_node = 2
    merged_node = 4

    def __init__(self, fd: Optional[Funcdata] = None) -> None:
        self._fd: Optional[Funcdata] = fd
        self._pass: int = 0
        self._maxdepth: int = -1

        self._globaldisjoint = LocationMap()
        self._disjoint = TaskList()
        self._domchild: List[List] = []
        self._augment: List[List] = []
        self._flags: List[int] = []
        self._depth: List[int] = []

        self._pq = PriorityQueue()
        self._merge: List = []
        self._infolist: List[HeritageInfo] = []
        self._loadGuard: List[LoadGuard] = []
        self._storeGuard: List[LoadGuard] = []
        self._loadCopyOps: List = []

    # ----------------------------------------------------------------
    # Info management
    # ----------------------------------------------------------------

    def getInfo(self, spc: AddrSpace) -> Optional[HeritageInfo]:
        """Get the heritage status for the given address space."""
        idx = spc.getIndex()
        if idx < len(self._infolist):
            return self._infolist[idx]
        return None

    def clearInfoList(self) -> None:
        """Reset heritage status for all address spaces."""
        for info in self._infolist:
            info.reset()

    def buildInfoList(self) -> None:
        """Initialize information for each space."""
        if self._infolist:
            return
        if self._fd is None:
            return
        arch = self._fd.getArch() if hasattr(self._fd, 'getArch') else None
        if arch is None:
            return
        num = arch.numSpaces() if hasattr(arch, 'numSpaces') else 0
        for i in range(num):
            spc = arch.getSpace(i)
            if spc is None:
                self._infolist.append(HeritageInfo(None))
            else:
                self._infolist.append(HeritageInfo(spc))

    def forceRestructure(self) -> None:
        """Force regeneration of basic block structures."""
        self._maxdepth = -1

    # ----------------------------------------------------------------
    # Public query accessors
    # ----------------------------------------------------------------

    def getPass(self) -> int:
        return self._pass

    def heritagePass(self, addr: Address) -> int:
        """Get the pass number when the given address was heritaged, or -1."""
        return self._globaldisjoint.findPass(addr)

    def numHeritagePasses(self, spc: AddrSpace) -> int:
        """Get number of heritage passes performed for the given space."""
        info = self.getInfo(spc)
        if info is None or not info.isHeritaged():
            return self._pass
        return self._pass - info.delay

    def seenDeadCode(self, spc: AddrSpace) -> None:
        """Inform system of dead code removal in given space."""
        info = self.getInfo(spc)
        if info is not None:
            info.deadremoved = 1

    def getDeadCodeDelay(self, spc: AddrSpace) -> int:
        """Get pass delay for heritaging the given space."""
        info = self.getInfo(spc)
        if info is not None:
            return info.deadcodedelay
        return 0

    def setDeadCodeDelay(self, spc: AddrSpace, delay: int) -> None:
        """Set delay for a specific space."""
        info = self.getInfo(spc)
        if info is not None:
            info.deadcodedelay = delay

    def deadRemovalAllowed(self, spc: AddrSpace) -> bool:
        """Return True if it is safe to remove dead code."""
        info = self.getInfo(spc)
        if info is not None:
            return self._pass > info.deadcodedelay
        return False

    def deadRemovalAllowedSeen(self, spc: AddrSpace) -> bool:
        """Check if dead code removal is safe and mark that removal has happened."""
        info = self.getInfo(spc)
        if info is None:
            return False
        res = self._pass > info.deadcodedelay
        if res:
            info.deadremoved = 1
        return res

    def getLoadGuards(self) -> List[LoadGuard]:
        return self._loadGuard

    def getStoreGuards(self) -> List[LoadGuard]:
        return self._storeGuard

    def getStoreGuard(self, op) -> Optional[LoadGuard]:
        """Get LoadGuard record associated with given PcodeOp."""
        for guard in self._storeGuard:
            if guard.op is op:
                return guard
        return None

    # ----------------------------------------------------------------
    # Dominator tree construction
    # ----------------------------------------------------------------

    def _buildDominatorTree(self) -> None:
        """Build the dominator tree using the iterative algorithm (Cooper, Harvey, Kennedy)."""
        graph = self._fd.getBasicBlocks()
        n = graph.getSize()
        if n == 0:
            return
        entry = graph.getEntryBlock()
        if entry is None:
            return
        # Initialize: every block's idom = None except entry
        for i in range(n):
            bl = graph.getBlock(i)
            bl.setImmedDom(None)
        entry.setImmedDom(entry)
        # Compute RPO (reverse post-order)
        rpo = []
        visited = set()
        stack = [(entry, False)]
        while stack:
            bl, processed = stack.pop()
            if processed:
                rpo.append(bl)
                continue
            if id(bl) in visited:
                continue
            visited.add(id(bl))
            stack.append((bl, True))
            for i in range(bl.sizeOut() - 1, -1, -1):
                s = bl.getOut(i)
                if id(s) not in visited:
                    stack.append((s, False))
        rpo.reverse()
        rpo_index = {id(bl): i for i, bl in enumerate(rpo)}

        def intersect(b1, b2):
            f1, f2 = rpo_index.get(id(b1), n), rpo_index.get(id(b2), n)
            while f1 != f2:
                while f1 > f2:
                    b1 = b1.getImmedDom()
                    f1 = rpo_index.get(id(b1), n) if b1 else n
                while f2 > f1:
                    b2 = b2.getImmedDom()
                    f2 = rpo_index.get(id(b2), n) if b2 else n
            return b1

        changed = True
        while changed:
            changed = False
            for bl in rpo:
                if bl is entry:
                    continue
                new_idom = None
                for j in range(bl.sizeIn()):
                    pred = bl.getIn(j)
                    if pred.getImmedDom() is None:
                        continue
                    if new_idom is None:
                        new_idom = pred
                    else:
                        new_idom = intersect(new_idom, pred)
                if new_idom is not None and bl.getImmedDom() is not new_idom:
                    bl.setImmedDom(new_idom)
                    changed = True
        entry.setImmedDom(None)  # Entry has no dominator
        self._domchildren = {}
        for bl in rpo:
            idom = bl.getImmedDom()
            if idom is not None:
                self._domchildren.setdefault(id(idom), []).append(bl)

    # ----------------------------------------------------------------
    # Guard methods (data-flow across calls/stores/loads/returns)
    # ----------------------------------------------------------------

    def guard(self, addr: Address, size: int, guardPerformed: bool,
              read: list, write: list, inputvars: list) -> None:
        """Normalize p-code ops so that phi-node placement and renaming works.

        For reads smaller than the range, add SUBPIECE. For writes smaller,
        add PIECE. If guardPerformed, add INDIRECTs for CALL/STORE/LOAD effects.
        """
        from ghidra.ir.varnode import Varnode as VnCls
        for i, vn in enumerate(read):
            descs = list(vn.beginDescend())
            if not descs:
                continue
            if vn.getSize() < size:
                read[i] = vn = self.normalizeReadSize(vn, descs[0], addr, size)
            vn.setActiveHeritage()
        for i, vn in enumerate(write):
            if vn.getSize() < size:
                write[i] = vn = self.normalizeWriteSize(vn, addr, size)
            vn.setActiveHeritage()
        if guardPerformed:
            fl = 0
            if hasattr(self._fd, 'getScopeLocal'):
                scope = self._fd.getScopeLocal()
                if hasattr(scope, 'queryProperties'):
                    fl_ref = [0]
                    scope.queryProperties(addr, size, Address(), fl_ref)
                    fl = fl_ref[0] if isinstance(fl_ref[0], int) else fl
            self.guardCalls(fl, addr, size, write)
            self.guardReturns(fl, addr, size, write)
            # Only guard stores/loads if high pointer is possible
            glb = self._fd.getArch() if hasattr(self._fd, 'getArch') else None
            if glb is None or not hasattr(glb, 'highPtrPossible') or glb.highPtrPossible(addr, size):
                self.guardStores(addr, size, write)
                self.guardLoads(fl, addr, size, write)

    def guardInput(self, addr: Address, size: int, inputvars: list) -> None:
        """Make sure existing inputs for the given range fill it entirely."""
        if not inputvars:
            return
        if len(inputvars) == 1 and inputvars[0].getSize() == size:
            return
        # Fill holes with new input Varnodes
        cur = addr.getOffset()
        end = cur + size
        newinput = []
        i = 0
        while cur < end:
            if i < len(inputvars):
                vn = inputvars[i]
                if vn.getOffset() > cur:
                    sz = vn.getOffset() - cur
                    newvn = self._fd.newVarnode(sz, Address(addr.getSpace(), cur))
                    newvn = self._fd.setInputVarnode(newvn)
                    newinput.append(newvn)
                    cur += sz
                else:
                    newinput.append(vn)
                    cur += vn.getSize()
                    i += 1
            else:
                sz = end - cur
                newvn = self._fd.newVarnode(sz, Address(addr.getSpace(), cur))
                newvn = self._fd.setInputVarnode(newvn)
                newinput.append(newvn)
                cur += sz
        if len(newinput) <= 1:
            return
        for vn in newinput:
            vn.setWriteMask()
        newout = self._fd.newVarnode(size, addr)
        result = self.concatPieces(newinput, None, newout)
        if result is not None:
            result.setActiveHeritage()

    def guardCalls(self, fl: int, addr: Address, size: int, write: list) -> None:
        """Guard CALL/CALLIND ops in preparation for renaming algorithm.

        For each call site, determine the effect on the given address range
        and insert appropriate INDIRECT or INDIRECT-creation ops. Also handle
        active input/output parameter analysis paths.

        C++ ref: ``Heritage::guardCalls``
        """
        if self._fd is None or not hasattr(self._fd, 'numCalls'):
            return
        from ghidra.ir.varnode import Varnode as VnCls
        holdind = (fl & VnCls.addrtied) != 0
        for i in range(self._fd.numCalls()):
            fc = self._fd.getCallSpecs(i)
            if fc is None:
                continue
            # Skip if call already has an assignment matching exactly
            callOp = fc.getOp()
            if hasattr(callOp, 'isAssignment') and callOp.isAssignment():
                outvn = callOp.getOut()
                if outvn is not None and outvn.getAddr() == addr and outvn.getSize() == size:
                    continue

            spc = addr.getSpace()
            off = addr.getOffset()
            tryregister = True
            if spc.getType() == IPTR_SPACEBASE:
                from ghidra.fspec.fspec import FuncCallSpecs as _FCS
                sboff = fc.getSpacebaseOffset() if hasattr(fc, 'getSpacebaseOffset') else None
                if sboff is not None and sboff != _FCS.offset_unknown:
                    off = spc.wrapOffset(off - sboff) if hasattr(spc, 'wrapOffset') else (off - sboff)
                else:
                    tryregister = False
            transAddr = Address(spc, off)

            effecttype = 'unknown'
            if hasattr(fc, 'hasEffect'):
                effecttype = fc.hasEffect(transAddr, size)

            possibleoutput = False

            # Active output path
            if hasattr(fc, 'isOutputActive') and fc.isOutputActive() and tryregister:
                active = fc.getActiveOutput() if hasattr(fc, 'getActiveOutput') else None
                if active is not None and hasattr(fc, 'characterizeAsOutput'):
                    from ghidra.fspec.fspec import ParamEntry
                    outputCharacter = fc.characterizeAsOutput(transAddr, size)
                    if outputCharacter != ParamEntry.no_containment:
                        if effecttype != 'killedbycall' and hasattr(fc, 'isAutoKilledByCall') and fc.isAutoKilledByCall():
                            effecttype = 'killedbycall'
                        if outputCharacter == ParamEntry.contained_by:
                            if self.tryOutputOverlapGuard(fc, addr, transAddr, size, write):
                                effecttype = 'unaffected'
                        else:
                            if hasattr(active, 'whichTrial') and active.whichTrial(transAddr, size) < 0:
                                active.registerTrial(transAddr, size)
                                possibleoutput = True
            elif hasattr(fc, 'isStackOutputLock') and fc.isStackOutputLock() and tryregister:
                if hasattr(fc, 'characterizeAsOutput'):
                    from ghidra.fspec.fspec import ParamEntry
                    outputCharacter = fc.characterizeAsOutput(transAddr, size)
                    if outputCharacter != ParamEntry.no_containment:
                        effecttype = 'unknown'
                        if self.tryOutputStackGuard(fc, addr, transAddr, size, outputCharacter, write):
                            effecttype = 'unaffected'

            # Active input path
            if hasattr(fc, 'isInputActive') and fc.isInputActive() and tryregister:
                if hasattr(fc, 'characterizeAsInputParam'):
                    from ghidra.fspec.fspec import ParamEntry
                    inputCharacter = fc.characterizeAsInputParam(transAddr, size)
                    if inputCharacter == ParamEntry.contains_justified:
                        active = fc.getActiveInput() if hasattr(fc, 'getActiveInput') else None
                        if active is not None and hasattr(active, 'whichTrial') and active.whichTrial(transAddr, size) < 0:
                            active.registerTrial(transAddr, size)
                            vn = self._fd.newVarnode(size, addr)
                            vn.setActiveHeritage()
                            self._fd.opInsertInput(callOp, vn, callOp.numInput())
                    elif inputCharacter == ParamEntry.contained_by:
                        self.guardCallOverlappingInput(fc, addr, transAddr, size)

            # Insert INDIRECT ops based on effect type
            if effecttype in ('unknown', 'return_address'):
                if hasattr(self._fd, 'newIndirectOp'):
                    indop = self._fd.newIndirectOp(callOp, addr, size, 0)
                    if indop is not None:
                        indop.getIn(0).setActiveHeritage()
                        indop.getOut().setActiveHeritage()
                        write.append(indop.getOut())
                        if holdind:
                            indop.getOut().setAddrForce()
                        if effecttype == 'return_address' and hasattr(indop.getOut(), 'setReturnAddress'):
                            indop.getOut().setReturnAddress()
            elif effecttype == 'killedbycall':
                if hasattr(self._fd, 'newIndirectCreation'):
                    indop = self._fd.newIndirectCreation(callOp, addr, size, possibleoutput)
                    if indop is not None:
                        indop.getOut().setActiveHeritage()
                        write.append(indop.getOut())

    def guardStores(self, addr: Address, size: int, write: list) -> None:
        """Guard STORE ops in preparation for the renaming algorithm."""
        if self._fd is None:
            return
        if not hasattr(self._fd, 'beginOp'):
            return
        spc = addr.getSpace()
        for op in list(self._fd.beginOp(OpCode.CPUI_STORE)):
            if hasattr(op, 'isDead') and op.isDead():
                continue
            in0 = op.getIn(0)
            # In C++, STORE input[0] is always a constant encoding the target space ID.
            # Skip if input[0] is not a constant — raw p-code hasn't resolved the space yet.
            if not in0.isConstant():
                continue
            storeSpc = in0.getSpaceFromConst() if hasattr(in0, 'getSpaceFromConst') else None
            if storeSpc is spc or (hasattr(spc, 'getContain') and spc.getContain() is storeSpc):
                if hasattr(self._fd, 'newIndirectOp'):
                    indop = self._fd.newIndirectOp(op, addr, size, 0)
                    if indop is not None:
                        indop.getIn(0).setActiveHeritage()
                        indop.getOut().setActiveHeritage()
                        write.append(indop.getOut())

    def guardLoads(self, fl: int, addr: Address, size: int, write: list) -> None:
        """Guard LOAD ops in preparation for the renaming algorithm."""
        from ghidra.ir.varnode import Varnode as VnCls
        if (fl & VnCls.addrtied) == 0:
            return
        i = 0
        while i < len(self._loadGuard):
            guard = self._loadGuard[i]
            if not guard.isValid(OpCode.CPUI_LOAD):
                del self._loadGuard[i]
                continue
            i += 1
            if guard.spc is not addr.getSpace():
                continue
            if addr.getOffset() < guard.minimumOffset or addr.getOffset() > guard.maximumOffset:
                continue
            if hasattr(self._fd, 'newOp'):
                copyop = self._fd.newOp(1, guard.op.getAddr())
                vn = self._fd.newVarnodeOut(size, addr, copyop)
                vn.setActiveHeritage()
                vn.setAddrForce()
                self._fd.opSetOpcode(copyop, OpCode.CPUI_COPY)
                invn = self._fd.newVarnode(size, addr)
                invn.setActiveHeritage()
                self._fd.opSetInput(copyop, invn, 0)
                self._fd.opInsertBefore(copyop, guard.op)
                self._loadCopyOps.append(copyop)

    def guardReturns(self, fl: int, addr: Address, size: int, write: list) -> None:
        """Guard global data-flow at RETURN ops in preparation for renaming.

        If there is an active output (return value being determined), check if
        the address range could be a return value and insert an input Varnode
        on each RETURN. Then, if the address is persistent, insert a COPY guard
        to enforce data-flow up to the function's exit.

        C++ ref: ``Heritage::guardReturns``
        """
        from ghidra.ir.varnode import Varnode as VnCls
        if not hasattr(self._fd, 'beginOp'):
            return
        # Active output path: check if this range could be a return value
        active = self._fd.getActiveOutput() if hasattr(self._fd, 'getActiveOutput') else None
        if active is not None:
            proto = self._fd.getFuncProto() if hasattr(self._fd, 'getFuncProto') else None
            if proto is not None and hasattr(proto, 'characterizeAsOutput'):
                from ghidra.fspec.fspec import ParamEntry
                outputCharacter = proto.characterizeAsOutput(addr, size)
                if outputCharacter == ParamEntry.contained_by:
                    self.guardReturnsOverlapping(addr, size)
                elif outputCharacter != ParamEntry.no_containment:
                    active.registerTrial(addr, size)
                    for op in self._fd.beginOp(OpCode.CPUI_RETURN):
                        if hasattr(op, 'isDead') and op.isDead():
                            continue
                        if hasattr(op, 'getHaltType') and op.getHaltType() != 0:
                            continue
                        invn = self._fd.newVarnode(size, addr)
                        invn.setActiveHeritage()
                        self._fd.opInsertInput(op, invn, op.numInput())
        # Persist path: force data-flow to persist through returns
        if (fl & VnCls.persist) == 0:
            return
        for op in self._fd.beginOp(OpCode.CPUI_RETURN):
            if hasattr(op, 'isDead') and op.isDead():
                continue
            if hasattr(self._fd, 'newOp'):
                copyop = self._fd.newOp(1, op.getAddr())
                vn = self._fd.newVarnodeOut(size, addr, copyop)
                vn.setAddrForce()
                vn.setActiveHeritage()
                self._fd.opSetOpcode(copyop, OpCode.CPUI_COPY)
                if hasattr(self._fd, 'markReturnCopy'):
                    self._fd.markReturnCopy(copyop)
                invn = self._fd.newVarnode(size, addr)
                invn.setActiveHeritage()
                self._fd.opSetInput(copyop, invn, 0)
                self._fd.opInsertBefore(copyop, op)

    def guardReturnsOverlapping(self, addr: Address, size: int) -> None:
        """Guard data-flow at RETURN ops, where range properly contains return storage.

        The RETURN ops need to take a new input because of the potential of a return value,
        but the range is too big so it must be truncated to fit via SUBPIECE.

        C++ ref: ``Heritage::guardReturnsOverlapping``
        """
        if self._fd is None:
            return
        proto = self._fd.getFuncProto() if hasattr(self._fd, 'getFuncProto') else None
        if proto is None:
            return
        if not hasattr(proto, 'getBiggestContainedOutput'):
            return
        vData = type('VData', (), {'space': None, 'offset': 0, 'size': 0})()
        if not proto.getBiggestContainedOutput(addr, size, vData):
            return
        truncAddr = Address(vData.space, vData.offset)
        active = self._fd.getActiveOutput() if hasattr(self._fd, 'getActiveOutput') else None
        if active is not None and hasattr(active, 'registerTrial'):
            active.registerTrial(truncAddr, vData.size)
        # Calculate truncation offset
        offset = vData.offset - addr.getOffset()
        if hasattr(vData.space, 'isBigEndian') and vData.space.isBigEndian():
            offset = (size - vData.size) - offset
        for op in self._fd.beginOp(OpCode.CPUI_RETURN):
            if hasattr(op, 'isDead') and op.isDead():
                continue
            if hasattr(op, 'getHaltType') and op.getHaltType() != 0:
                continue
            invn = self._fd.newVarnode(size, addr)
            subOp = self._fd.newOp(2, op.getAddr())
            self._fd.opSetOpcode(subOp, OpCode.CPUI_SUBPIECE)
            self._fd.opSetInput(subOp, invn, 0)
            self._fd.opSetInput(subOp, self._fd.newConstant(4, offset), 1)
            self._fd.opInsertBefore(subOp, op)
            retVal = self._fd.newVarnodeOut(vData.size, truncAddr, subOp)
            invn.setActiveHeritage()
            self._fd.opInsertInput(op, retVal, op.numInput())

    def guardCallOverlappingInput(self, fc, addr: Address, transAddr: Address, size: int) -> None:
        """Guard address range larger than any single parameter at a call.

        Constructs a SUBPIECE to pull out the potential parameter from
        the larger heritage range.

        C++ ref: ``Heritage::guardCallOverlappingInput``
        """
        if not hasattr(fc, 'getBiggestContainedInputParam'):
            return
        vData = type('VData', (), {'space': None, 'offset': 0, 'size': 0})()
        if not fc.getBiggestContainedInputParam(transAddr, size, vData):
            return
        active = fc.getActiveInput() if hasattr(fc, 'getActiveInput') else None
        truncAddr = Address(vData.space, vData.offset)
        diff = truncAddr.getOffset() - transAddr.getOffset()
        truncAddr = addr + diff  # Convert to caller's perspective
        if active is not None and hasattr(active, 'whichTrial'):
            if active.whichTrial(truncAddr, size) >= 0:
                return  # Already a trial
        truncateAmount = addr.justifiedContain(size, truncAddr, vData.size, False)
        op = fc.getOp()
        subpieceOp = self._fd.newOp(2, op.getAddr())
        self._fd.opSetOpcode(subpieceOp, OpCode.CPUI_SUBPIECE)
        wholeVn = self._fd.newVarnode(size, addr)
        wholeVn.setActiveHeritage()
        self._fd.opSetInput(subpieceOp, wholeVn, 0)
        self._fd.opSetInput(subpieceOp, self._fd.newConstant(4, truncateAmount), 1)
        vn = self._fd.newVarnodeOut(vData.size, truncAddr, subpieceOp)
        self._fd.opInsertBefore(subpieceOp, op)
        if active is not None and hasattr(active, 'registerTrial'):
            active.registerTrial(truncAddr, vData.size)
        self._fd.opInsertInput(op, vn, op.numInput())

    def guardOutputOverlap(self, callOp, addr: Address, size: int, retAddr: Address, retSize: int, write: list) -> None:
        """Insert created INDIRECT ops to guard the output of a call.

        The potential return storage is an indirect creation at this stage, and the
        guarded range properly contains the return storage. We split the full range
        into 2 or 3 Varnodes, each via an INDIRECT, then concatenate via PIECE.

        C++ ref: ``Heritage::guardOutputOverlap``
        """
        sizeFront = retAddr.getOffset() - addr.getOffset()
        sizeBack = size - retSize - sizeFront
        indOp = self._fd.newIndirectCreation(callOp, retAddr, retSize, True)
        vnCollect = indOp.getOut()
        insertPoint = callOp
        if sizeFront != 0:
            indOpFront = self._fd.newIndirectCreation(indOp, addr, sizeFront, False)
            newFront = indOpFront.getOut()
            concatFront = self._fd.newOp(2, indOp.getAddr())
            slotNew = 0 if (hasattr(retAddr, 'isBigEndian') and retAddr.isBigEndian()) else 1
            self._fd.opSetOpcode(concatFront, OpCode.CPUI_PIECE)
            self._fd.opSetInput(concatFront, newFront, slotNew)
            self._fd.opSetInput(concatFront, vnCollect, 1 - slotNew)
            vnCollect = self._fd.newVarnodeOut(sizeFront + retSize, addr, concatFront)
            self._fd.opInsertAfter(concatFront, insertPoint)
            insertPoint = concatFront
        if sizeBack != 0:
            addrBack = retAddr + retSize
            indOpBack = self._fd.newIndirectCreation(callOp, addrBack, sizeBack, False)
            newBack = indOpBack.getOut()
            concatBack = self._fd.newOp(2, indOp.getAddr())
            slotNew = 1 if (hasattr(retAddr, 'isBigEndian') and retAddr.isBigEndian()) else 0
            self._fd.opSetOpcode(concatBack, OpCode.CPUI_PIECE)
            self._fd.opSetInput(concatBack, newBack, slotNew)
            self._fd.opSetInput(concatBack, vnCollect, 1 - slotNew)
            vnCollect = self._fd.newVarnodeOut(size, addr, concatBack)
            self._fd.opInsertAfter(concatBack, insertPoint)
        vnCollect.setActiveHeritage()
        write.append(vnCollect)

    def tryOutputOverlapGuard(self, fc, addr, transAddr, size, write) -> bool:
        """Try to guard an address range larger than the possible output storage.

        C++ ref: ``Heritage::tryOutputOverlapGuard``
        """
        if not hasattr(fc, 'getBiggestContainedOutput'):
            return False
        vData = type('VData', (), {'space': None, 'offset': 0, 'size': 0})()
        if not fc.getBiggestContainedOutput(transAddr, size, vData):
            return False
        active = fc.getActiveOutput() if hasattr(fc, 'getActiveOutput') else None
        truncAddr = Address(vData.space, vData.offset)
        diff = truncAddr.getOffset() - transAddr.getOffset()
        truncAddr = addr + diff  # Convert to caller's perspective
        if active is not None and hasattr(active, 'whichTrial'):
            if active.whichTrial(truncAddr, size) >= 0:
                return False  # Trial already exists
        self.guardOutputOverlap(fc.getOp(), addr, size, truncAddr, vData.size, write)
        if active is not None and hasattr(active, 'registerTrial'):
            active.registerTrial(truncAddr, vData.size)
        return True

    def tryOutputStackGuard(self, fc, addr, transAddr, size, outputCharacter, write) -> bool:
        """Guard a stack range against a call that returns a value overlapping that range.

        C++ ref: ``Heritage::tryOutputStackGuard``
        """
        from ghidra.fspec.fspec import ParamEntry
        callOp = fc.getOp()
        if outputCharacter == ParamEntry.contained_by:
            vData = type('VData', (), {'space': None, 'offset': 0, 'size': 0})()
            if not hasattr(fc, 'getBiggestContainedOutput'):
                return False
            if not fc.getBiggestContainedOutput(transAddr, size, vData):
                return False
            truncAddr = Address(vData.space, vData.offset)
            diff = truncAddr.getOffset() - transAddr.getOffset()
            truncAddr = addr + diff
            self.guardOutputOverlapStack(callOp, addr, size, truncAddr, vData.size, write)
            return True
        # Reaching here, output exists and contains the heritage range
        retOut = fc.getOutput() if hasattr(fc, 'getOutput') else None
        if retOut is None:
            return False
        retAddr = retOut.getAddress() if hasattr(retOut, 'getAddress') else None
        if retAddr is None:
            return False
        diff = addr.getOffset() - transAddr.getOffset()
        retAddr = retAddr + diff  # Translate to caller perspective
        retSize = retOut.getSize() if hasattr(retOut, 'getSize') else size
        outvn = callOp.getOut()
        vnFinal = None
        if outvn is None:
            outvn = self._fd.newVarnodeOut(retSize, retAddr, callOp)
            vnFinal = outvn
        if size < retSize:
            subPiece = self._fd.newOp(2, callOp.getAddr())
            self._fd.opSetOpcode(subPiece, OpCode.CPUI_SUBPIECE)
            truncateAmount = retAddr.justifiedContain(retSize, addr, size, False)
            self._fd.opSetInput(subPiece, self._fd.newConstant(4, truncateAmount), 1)
            self._fd.opSetInput(subPiece, outvn, 0)
            vnFinal = self._fd.newVarnodeOut(size, addr, subPiece)
            self._fd.opInsertAfter(subPiece, callOp)
        if vnFinal is not None:
            vnFinal.setActiveHeritage()
            write.append(vnFinal)
        return True

    def guardOutputOverlapStack(self, callOp, addr, size, retAddr, retSize, write) -> None:
        """Guard a stack range that properly contains the return value storage for a call.

        The pieces on either side of the return storage are extracted via SUBPIECE,
        they flow through the call via INDIRECT, then rejoin with the return via PIECE.

        C++ ref: ``Heritage::guardOutputOverlapStack``
        """
        sizeFront = retAddr.getOffset() - addr.getOffset()
        sizeBack = size - retSize - sizeFront
        insertPoint = callOp
        vnCollect = callOp.getOut()
        if vnCollect is None:
            vnCollect = self._fd.newVarnodeOut(retSize, retAddr, callOp)
        if sizeFront != 0:
            newInput = self._fd.newVarnode(size, addr)
            newInput.setActiveHeritage()
            subPiece = self._fd.newOp(2, callOp.getAddr())
            self._fd.opSetOpcode(subPiece, OpCode.CPUI_SUBPIECE)
            truncateAmount = addr.justifiedContain(size, addr, sizeFront, False)
            self._fd.opSetInput(subPiece, self._fd.newConstant(4, truncateAmount), 1)
            self._fd.opSetInput(subPiece, newInput, 0)
            indOpFront = self._fd.newIndirectOp(callOp, addr, sizeFront, 0)
            self._fd.opSetOutput(subPiece, indOpFront.getIn(0))
            self._fd.opInsertBefore(subPiece, callOp)
            newFront = indOpFront.getOut()
            concatFront = self._fd.newOp(2, callOp.getAddr())
            slotNew = 0 if (hasattr(retAddr, 'isBigEndian') and retAddr.isBigEndian()) else 1
            self._fd.opSetOpcode(concatFront, OpCode.CPUI_PIECE)
            self._fd.opSetInput(concatFront, newFront, slotNew)
            self._fd.opSetInput(concatFront, vnCollect, 1 - slotNew)
            vnCollect = self._fd.newVarnodeOut(sizeFront + retSize, addr, concatFront)
            self._fd.opInsertAfter(concatFront, insertPoint)
            insertPoint = concatFront
        if sizeBack != 0:
            newInput = self._fd.newVarnode(size, addr)
            newInput.setActiveHeritage()
            addrBack = retAddr + retSize
            subPiece = self._fd.newOp(2, callOp.getAddr())
            self._fd.opSetOpcode(subPiece, OpCode.CPUI_SUBPIECE)
            truncateAmount = addr.justifiedContain(size, addrBack, sizeBack, False)
            self._fd.opSetInput(subPiece, self._fd.newConstant(4, truncateAmount), 1)
            self._fd.opSetInput(subPiece, newInput, 0)
            indOpBack = self._fd.newIndirectOp(callOp, addrBack, sizeBack, 0)
            self._fd.opSetOutput(subPiece, indOpBack.getIn(0))
            self._fd.opInsertBefore(subPiece, callOp)
            newBack = indOpBack.getOut()
            concatBack = self._fd.newOp(2, callOp.getAddr())
            slotNew = 1 if (hasattr(retAddr, 'isBigEndian') and retAddr.isBigEndian()) else 0
            self._fd.opSetOpcode(concatBack, OpCode.CPUI_PIECE)
            self._fd.opSetInput(concatBack, newBack, slotNew)
            self._fd.opSetInput(concatBack, vnCollect, 1 - slotNew)
            vnCollect = self._fd.newVarnodeOut(size, addr, concatBack)
            self._fd.opInsertAfter(concatBack, insertPoint)
        vnCollect.setActiveHeritage()
        write.append(vnCollect)

    # ----------------------------------------------------------------
    # Collect and normalize
    # ----------------------------------------------------------------

    def collect(self, memrange: MemRange, read: list, write: list,
                inputvars: list, remove: list,
                _sorted_idx: dict = None) -> int:
        """Collect free reads, writes, and inputs in the given address range.

        Returns the maximum size of a write.
        """
        read.clear()
        write.clear()
        inputvars.clear()
        remove.clear()
        if self._fd is None:
            return 0
        maxsize = 0
        target_spc = memrange.addr.getSpace()
        range_off = memrange.addr.offset
        range_end = range_off + memrange.size
        _WM = 0x02    # Varnode.writemask (addlflags)
        _WR = 0x10    # Varnode.written (flags)
        _IP = 0x08    # Varnode.input (flags)
        _HK = 0x26    # Varnode.insert|constant|annotation (isHeritageKnown mask)
        _OP_MARKER = 0x40     # PcodeOp.marker flag
        _OP_RETCPY = 0x80000  # PcodeOp.return_copy flag
        if _sorted_idx is not None:
            # Fast path: binary search using parallel offset list (Python 3.9 compatible)
            spc_entry = _sorted_idx.get(id(target_spc))
            if spc_entry is not None:
                sorted_offsets, sorted_vns = spc_entry
                # All varnodes with offset < range_end can potentially overlap
                hi = bisect_right(sorted_offsets, range_end - 1)
                # Start from varnodes with offset >= range_off - 128 (max varnode size bound)
                lo = bisect_left(sorted_offsets, range_off - 128)
                lo = max(0, lo)
                for i in range(lo, hi):
                    vn_off, vn_sz, vn = sorted_vns[i]
                    if vn_off + vn_sz <= range_off:
                        continue  # Doesn't reach range start
                    if vn._addlflags & _WM:
                        continue
                    vn_flags = vn._flags
                    if vn_flags & _WR:
                        op = vn._def
                        op_flags = op._flags
                        if op_flags & (_OP_MARKER | _OP_RETCPY):
                            if vn_sz < memrange.size:
                                remove.append(vn)
                                continue
                            memrange.clearProperty(MemRange.new_addresses)
                        if vn_sz > maxsize:
                            maxsize = vn_sz
                        write.append(vn)
                    elif not (vn_flags & _HK) and vn._descend:
                        read.append(vn)
                    elif vn_flags & _IP:
                        inputvars.append(vn)
                return maxsize
        # Fallback: linear scan via space index (vn objects stored directly)
        vbank = self._fd._vbank
        spc_bucket = vbank._space_varnodes.get(id(target_spc), ())
        for vn in spc_bucket:
            vn_off = vn._loc.offset
            vn_sz = vn._size
            if vn_off + vn_sz <= range_off or vn_off >= range_end:
                continue
            vn_flags = vn._flags
            if vn._addlflags & _WM:
                continue
            if vn_flags & _WR:
                op = vn._def
                op_flags = op._flags
                if op_flags & (_OP_MARKER | _OP_RETCPY):
                    if vn_sz < memrange.size:
                        remove.append(vn)
                        continue
                    memrange.clearProperty(MemRange.new_addresses)
                if vn_sz > maxsize:
                    maxsize = vn_sz
                write.append(vn)
            elif not (vn_flags & _HK) and vn._descend:
                read.append(vn)
            elif vn_flags & _IP:
                inputvars.append(vn)
        return maxsize

    def normalizeReadSize(self, vn, op, addr: Address, size: int):
        """Normalize the size of a read Varnode, prior to heritage."""
        if not hasattr(self._fd, 'newOp'):
            return vn
        newop = self._fd.newOp(2, op.getAddr())
        self._fd.opSetOpcode(newop, OpCode.CPUI_SUBPIECE)
        vn1 = self._fd.newVarnode(size, addr)
        overlap = vn.overlap(addr, size)
        addrSize = addr.getAddrSize() if hasattr(addr, 'getAddrSize') else 4
        vn2 = self._fd.newConstant(addrSize, overlap if overlap >= 0 else 0)
        self._fd.opSetInput(newop, vn1, 0)
        self._fd.opSetInput(newop, vn2, 1)
        self._fd.opSetOutput(newop, vn)
        if hasattr(newop.getOut(), 'setWriteMask'):
            newop.getOut().setWriteMask()
        self._fd.opInsertBefore(newop, op)
        return vn1

    def normalizeWriteSize(self, vn, addr: Address, size: int):
        """Normalize the size of a written Varnode, prior to heritage.

        Given a Varnode that is written that does not match the (larger) size
        of the address range currently being linked, create the missing pieces
        and concatenate everything into a new Varnode of the correct size.
        """
        if not hasattr(self._fd, 'newOp'):
            return vn

        op = vn.getDef()
        if op is None:
            return vn

        overlap = vn.overlap(addr, size) if hasattr(vn, 'overlap') else 0
        if overlap < 0:
            overlap = 0
        mostsigsize = size - (overlap + vn.getSize())

        mostvn = None
        leastvn = None
        bigendian = addr.isBigEndian() if hasattr(addr, 'isBigEndian') else False

        # Create most significant piece if needed
        if mostsigsize > 0:
            if bigendian:
                pieceaddr = addr
            else:
                pieceaddr = addr + (overlap + vn.getSize())

            isCall = op.isCall() if hasattr(op, 'isCall') else False
            if isCall and self.callOpIndirectEffect(pieceaddr, mostsigsize, op):
                newop = self._fd.newIndirectCreation(op, pieceaddr, mostsigsize, False)
                mostvn = newop.getOut()
            else:
                newop = self._fd.newOp(2, op.getAddr())
                mostvn = self._fd.newVarnodeOut(mostsigsize, pieceaddr, newop)
                big = self._fd.newVarnode(size, addr)
                big.setActiveHeritage()
                self._fd.opSetOpcode(newop, OpCode.CPUI_SUBPIECE)
                self._fd.opSetInput(newop, big, 0)
                addrSize = addr.getAddrSize() if hasattr(addr, 'getAddrSize') else 4
                self._fd.opSetInput(newop, self._fd.newConstant(addrSize, overlap + vn.getSize()), 1)
                self._fd.opInsertBefore(newop, op)

        # Create least significant piece if needed
        if overlap > 0:
            if bigendian:
                pieceaddr = addr + (size - overlap)
            else:
                pieceaddr = addr

            isCall = op.isCall() if hasattr(op, 'isCall') else False
            if isCall and self.callOpIndirectEffect(pieceaddr, overlap, op):
                newop = self._fd.newIndirectCreation(op, pieceaddr, overlap, False)
                leastvn = newop.getOut()
            else:
                newop = self._fd.newOp(2, op.getAddr())
                leastvn = self._fd.newVarnodeOut(overlap, pieceaddr, newop)
                big = self._fd.newVarnode(size, addr)
                big.setActiveHeritage()
                self._fd.opSetOpcode(newop, OpCode.CPUI_SUBPIECE)
                self._fd.opSetInput(newop, big, 0)
                addrSize2 = addr.getAddrSize() if hasattr(addr, 'getAddrSize') else 4
                self._fd.opSetInput(newop, self._fd.newConstant(addrSize2, 0), 1)
                self._fd.opInsertBefore(newop, op)

        # Concatenate least significant piece with vn
        if overlap > 0 and leastvn is not None:
            newop = self._fd.newOp(2, op.getAddr())
            if bigendian:
                midvn = self._fd.newVarnodeOut(overlap + vn.getSize(), vn.getAddr(), newop)
            else:
                midvn = self._fd.newVarnodeOut(overlap + vn.getSize(), addr, newop)
            self._fd.opSetOpcode(newop, OpCode.CPUI_PIECE)
            self._fd.opSetInput(newop, vn, 0)
            self._fd.opSetInput(newop, leastvn, 1)
            self._fd.opInsertAfter(newop, op)
        else:
            midvn = vn

        # Concatenate most significant piece
        if mostsigsize > 0 and mostvn is not None:
            newop = self._fd.newOp(2, op.getAddr())
            bigout = self._fd.newVarnodeOut(size, addr, newop)
            self._fd.opSetOpcode(newop, OpCode.CPUI_PIECE)
            self._fd.opSetInput(newop, mostvn, 0)
            self._fd.opSetInput(newop, midvn, 1)
            defop = midvn.getDef() if midvn is not vn else op
            if defop is not None:
                self._fd.opInsertAfter(newop, defop)
        else:
            bigout = midvn

        vn.setWriteMask()
        return bigout

    def concatPieces(self, vnlist: list, insertop, finalvn):
        """Concatenate a list of Varnodes together using PIECE ops."""
        if not vnlist or not hasattr(self._fd, 'newOp'):
            return finalvn
        if len(vnlist) == 1:
            return vnlist[0]
        preexist = vnlist[0]
        bigendian = preexist.getAddr().isBigEndian() if hasattr(preexist.getAddr(), 'isBigEndian') else False
        opaddr = self._fd.getAddress() if insertop is None else insertop.getAddr()
        bl = self._fd.getBasicBlocks().getStartBlock() if insertop is None else insertop.getParent()
        for i in range(1, len(vnlist)):
            vn = vnlist[i]
            newop = self._fd.newOp(2, opaddr)
            self._fd.opSetOpcode(newop, OpCode.CPUI_PIECE)
            if i == len(vnlist) - 1:
                newvn = finalvn
                self._fd.opSetOutput(newop, newvn)
            else:
                newvn = self._fd.newUniqueOut(preexist.getSize() + vn.getSize(), newop)
            if bigendian:
                self._fd.opSetInput(newop, preexist, 0)
                self._fd.opSetInput(newop, vn, 1)
            else:
                self._fd.opSetInput(newop, vn, 0)
                self._fd.opSetInput(newop, preexist, 1)
            if insertop is None and bl is not None:
                self._fd.opInsertBegin(newop, bl)
            elif insertop is not None:
                self._fd.opInsertBefore(newop, insertop)
            preexist = newvn
        return preexist

    def splitPieces(self, vnlist: list, insertop, addr: Address, size: int, startvn) -> None:
        """Build a set of Varnode piece expressions at the given location."""
        if not vnlist or not hasattr(self._fd, 'newOp'):
            return
        bigendian = addr.isBigEndian() if hasattr(addr, 'isBigEndian') else False
        baseoff = addr.getOffset() + size if bigendian else addr.getOffset()
        opaddr = self._fd.getAddress() if insertop is None else insertop.getAddr()
        bl = self._fd.getBasicBlocks().getStartBlock() if insertop is None else insertop.getParent()
        for vn in vnlist:
            newop = self._fd.newOp(2, opaddr)
            self._fd.opSetOpcode(newop, OpCode.CPUI_SUBPIECE)
            if bigendian:
                diff = baseoff - (vn.getOffset() + vn.getSize())
            else:
                diff = vn.getOffset() - baseoff
            self._fd.opSetInput(newop, startvn, 0)
            self._fd.opSetInput(newop, self._fd.newConstant(4, diff), 1)
            self._fd.opSetOutput(newop, vn)
            if insertop is None and bl is not None:
                self._fd.opInsertBegin(newop, bl)
            elif insertop is not None:
                self._fd.opInsertAfter(newop, insertop)

    @staticmethod
    def buildRefinement(refine: list, addr: Address, vnlist: list) -> None:
        """Build a refinement array given an address range and a list of Varnodes."""
        for vn in vnlist:
            curaddr = vn.getAddr()
            sz = vn.getSize()
            diff = curaddr.getOffset() - addr.getOffset()
            if 0 <= diff < len(refine):
                refine[diff] = 1
            endpos = diff + sz
            if 0 <= endpos < len(refine):
                refine[endpos] = 1

    @staticmethod
    def remove13Refinement(refine: list) -> None:
        """If we see 1-3 or 3-1 pieces in the partition, replace with a 4."""
        if not refine:
            return
        pos = 0
        lastsize = refine[pos]
        if lastsize == 0:
            return
        pos += lastsize
        while pos < len(refine):
            cursize = refine[pos]
            if cursize == 0:
                break
            if (lastsize == 1 and cursize == 3) or (lastsize == 3 and cursize == 1):
                refine[pos - lastsize] = 4
                lastsize = 4
                pos += cursize
            else:
                lastsize = cursize
                pos += lastsize

    def splitByRefinement(self, vn, addr: Address, refine: list, split: list) -> None:
        """Split up a Varnode by the given refinement array.

        The refinement array has one entry per byte. Non-zero entries indicate
        element sizes. The Varnode is split into pieces matching those boundaries.

        C++ ref: ``Heritage::splitByRefinement``
        """
        curaddr = vn.getAddr()
        sz = vn.getSize()
        spc = curaddr.getSpace()
        diff = (curaddr.getOffset() - addr.getOffset()) & calc_mask(spc.getAddrSize()) if hasattr(spc, 'getAddrSize') else (curaddr.getOffset() - addr.getOffset())
        if diff >= len(refine):
            return
        cutsz = refine[diff]
        if cutsz == 0 or sz <= cutsz:
            return  # Already refined
        split.append(self._fd.newVarnode(cutsz, curaddr))
        sz -= cutsz
        while sz > 0:
            curaddr = curaddr + cutsz
            diff = (curaddr.getOffset() - addr.getOffset()) & calc_mask(spc.getAddrSize()) if hasattr(spc, 'getAddrSize') else (curaddr.getOffset() - addr.getOffset())
            if diff >= len(refine):
                cutsz = sz
            else:
                cutsz = refine[diff]
            if cutsz > sz:
                cutsz = sz
            if cutsz <= 0:
                break
            split.append(self._fd.newVarnode(cutsz, curaddr))
            sz -= cutsz

    def refineRead(self, vn, addr: Address, refine: list) -> None:
        """Split up a free Varnode based on the given refinement.

        If the Varnode overlaps the refinement, replace it with covering pieces
        concatenated via PIECE ops. The original Varnode is replaced with a
        temporary holding the concatenated result.

        C++ ref: ``Heritage::refineRead``
        """
        newvn = []
        self.splitByRefinement(vn, addr, refine, newvn)
        if not newvn:
            return
        replacevn = self._fd.newUnique(vn.getSize()) if hasattr(self._fd, 'newUnique') else None
        if replacevn is None:
            return
        op = vn.loneDescend() if hasattr(vn, 'loneDescend') else None
        if op is None:
            return
        slot = op.getSlot(vn) if hasattr(op, 'getSlot') else 0
        self.concatPieces(newvn, op, replacevn)
        self._fd.opSetInput(op, replacevn, slot)
        if vn.hasNoDescend():
            self._fd.deleteVarnode(vn)

    def refineWrite(self, vn, addr: Address, refine: list) -> None:
        """Split up an output Varnode based on the given refinement.

        If the Varnode overlaps the refinement, replace it with covering pieces
        each defined by a SUBPIECE op. The original Varnode is replaced with
        a temporary.

        C++ ref: ``Heritage::refineWrite``
        """
        newvn = []
        self.splitByRefinement(vn, addr, refine, newvn)
        if not newvn:
            return
        replacevn = self._fd.newUnique(vn.getSize()) if hasattr(self._fd, 'newUnique') else None
        if replacevn is None:
            return
        defop = vn.getDef()
        self._fd.opSetOutput(defop, replacevn)
        self.splitPieces(newvn, defop, vn.getAddr(), vn.getSize(), replacevn)
        self._fd.totalReplace(vn, replacevn)
        self._fd.deleteVarnode(vn)

    def refineInput(self, vn, addr: Address, refine: list) -> None:
        """Split up a known input Varnode based on the given refinement.

        If the Varnode overlaps the refinement, replace it with covering pieces
        each defined by a SUBPIECE op.

        C++ ref: ``Heritage::refineInput``
        """
        newvn = []
        self.splitByRefinement(vn, addr, refine, newvn)
        if not newvn:
            return
        self.splitPieces(newvn, None, vn.getAddr(), vn.getSize(), vn)
        vn.setWriteMask()

    def refinement(self, idx: int, readvars: list, writevars: list, inputvars: list) -> int:
        """Find the common refinement of all reads and writes and split them.

        Matching C++, this modifies the disjoint task list: erases the original
        MemRange at *idx* and inserts refined sub-ranges in its place.

        Returns the index of the first sub-range (so the caller can re-collect),
        or -1 if no non-trivial refinement was found.

        C++ ref: ``Heritage::refinement``
        """
        memrange = self._disjoint[idx]
        size = memrange.size
        if size > 1024:
            return -1
        addr = memrange.addr
        refine = [0] * (size + 1)  # Fencepost
        self.buildRefinement(refine, addr, readvars)
        self.buildRefinement(refine, addr, writevars)
        self.buildRefinement(refine, addr, inputvars)
        refine.pop()  # Remove fencepost
        # Convert boundary points to partition sizes
        lastpos = 0
        for curpos in range(1, size):
            if refine[curpos] != 0:
                refine[lastpos] = curpos - lastpos
                lastpos = curpos
        if lastpos == 0:
            return -1  # No non-trivial refinements
        refine[lastpos] = size - lastpos
        self.remove13Refinement(refine)
        for vn in readvars:
            self.refineRead(vn, addr, refine)
        for vn in writevars:
            self.refineWrite(vn, addr, refine)
        for vn in inputvars:
            self.refineInput(vn, addr, refine)

        # Alter the disjoint cover to reflect our refinement (C++ heritage.cc:1920-1938)
        flags = memrange.flags
        self._disjoint.erase(idx)
        # Also update globaldisjoint
        giter = self._globaldisjoint.find(addr) if hasattr(self._globaldisjoint, 'find') else None
        curPass = 0
        if giter is not None:
            curPass = giter.get('pass', 0) if isinstance(giter, dict) else 0
            if hasattr(self._globaldisjoint, 'erase'):
                self._globaldisjoint.erase(giter)
        cut = 0
        sz = refine[cut]
        curaddr = addr
        res_idx = self._disjoint.insert(idx, curaddr, sz, flags)
        if hasattr(self._globaldisjoint, 'add'):
            self._globaldisjoint.add(curaddr, sz, curPass, [0])
        cut += sz
        curaddr = Address(addr.getSpace(), addr.getOffset() + cut)
        insert_pos = idx + 1
        while cut < size:
            sz = refine[cut]
            self._disjoint.insert(insert_pos, curaddr, sz, flags)
            if hasattr(self._globaldisjoint, 'add'):
                self._globaldisjoint.add(curaddr, sz, curPass, [0])
            cut += sz
            curaddr = Address(addr.getSpace(), addr.getOffset() + cut)
            insert_pos += 1
        return res_idx

    def callOpIndirectEffect(self, addr: Address, size: int, op) -> bool:
        """Determine if the address range is affected by the given call p-code op."""
        if op.code() in (OpCode.CPUI_CALL, OpCode.CPUI_CALLIND):
            if hasattr(self._fd, 'getCallSpecs'):
                fc = self._fd.getCallSpecs(op)
                if fc is None:
                    return True
                if hasattr(fc, 'hasEffectTranslate'):
                    return fc.hasEffectTranslate(addr, size) != 'unaffected'
            return True
        return False

    def bumpDeadcodeDelay(self, spc: AddrSpace) -> None:
        """Increase the heritage delay for the given AddrSpace and request a restart."""
        if spc.getType() not in (IPTR_PROCESSOR, IPTR_SPACEBASE):
            return
        if spc.getDelay() != spc.getDeadcodeDelay():
            return
        if hasattr(self._fd, 'getOverride'):
            override = self._fd.getOverride()
            if hasattr(override, 'hasDeadcodeDelay') and override.hasDeadcodeDelay(spc):
                return
            if hasattr(override, 'insertDeadcodeDelay'):
                override.insertDeadcodeDelay(spc, spc.getDeadcodeDelay() + 1)
        if hasattr(self._fd, 'setRestartPending'):
            self._fd.setRestartPending(True)

    def removeRevisitedMarkers(self, remove: list, addr: Address, size: int) -> None:
        """Remove deprecated MULTIEQUAL/INDIRECT/COPY ops, preparing to re-heritage.

        If a previous Varnode was heritaged through a MULTIEQUAL or INDIRECT op, but now
        a larger range containing the Varnode is being heritaged, we throw away the op,
        letting the data-flow for the new larger range determine the data-flow for the
        old Varnode. The original Varnode is redefined as the output of a SUBPIECE
        of a larger free Varnode.

        C++ ref: ``Heritage::removeRevisitedMarkers``
        """
        info = self.getInfo(addr.getSpace())
        if info is not None and info.deadremoved > 0:
            self.bumpDeadcodeDelay(addr.getSpace())
            if not info.warningissued:
                info.warningissued = True
                if hasattr(self._fd, 'warningHeader'):
                    self._fd.warningHeader(f"Heritage AFTER dead removal. Revisit: {addr}")

        for vn in remove:
            op = vn.getDef()
            if op is None:
                continue
            bl = op.getParent()
            opc = op.code()

            # Determine insertion position (the op AFTER which we insert the SUBPIECE)
            insertAfterOp = None
            if opc == OpCode.CPUI_INDIRECT:
                # Insert SUBPIECE after target of INDIRECT
                iopVn = op.getIn(1)
                from ghidra.ir.op import PcodeOp as PcodeOpCls
                targetOp = None
                if hasattr(PcodeOpCls, 'getOpFromConst'):
                    targetOp = PcodeOpCls.getOpFromConst(iopVn.getAddr())
                if targetOp is not None and not (hasattr(targetOp, 'isDead') and targetOp.isDead()):
                    insertAfterOp = targetOp
                else:
                    insertAfterOp = op  # Fallback: after the INDIRECT itself
                if hasattr(vn, 'clearAddrForce'):
                    vn.clearAddrForce()
            elif opc == OpCode.CPUI_MULTIEQUAL:
                # Insert SUBPIECE after all MULTIEQUALs in block
                insertAfterOp = op
                if bl is not None and hasattr(bl, 'getOpList'):
                    found = False
                    for blop in bl.getOpList():
                        if found:
                            if blop.code() == OpCode.CPUI_MULTIEQUAL:
                                insertAfterOp = blop
                            else:
                                break
                        elif blop is op:
                            found = True
            else:
                # Remove return form COPY
                if hasattr(self._fd, 'opUnlink'):
                    self._fd.opUnlink(op)
                continue

            # Calculate overlap offset
            offset = vn.overlap(addr, size) if hasattr(vn, 'overlap') else 0
            if offset < 0:
                offset = 0

            # Uninsert the old op, replace with SUBPIECE from larger free varnode
            if hasattr(self._fd, 'opUninsert'):
                self._fd.opUninsert(op)

            newInputs = []
            big = self._fd.newVarnode(size, addr)
            big.setActiveHeritage()
            newInputs.append(big)
            newInputs.append(self._fd.newConstant(4, offset))

            self._fd.opSetOpcode(op, OpCode.CPUI_SUBPIECE)
            if hasattr(op, 'setAllInput'):
                op.setAllInput(newInputs)
            else:
                self._fd.opSetInput(op, newInputs[0], 0)
                self._fd.opSetInput(op, newInputs[1], 1)

            # Insert at the correct position
            if bl is not None and insertAfterOp is not None:
                self._fd.opInsertAfter(op, insertAfterOp)
            elif bl is not None:
                self._fd.opInsertBegin(op, bl)

            vn.setWriteMask()

    def clearStackPlaceholders(self, info: HeritageInfo) -> None:
        """Clear any placeholder LOADs associated with calls."""
        if self._fd is None:
            return
        if hasattr(self._fd, 'numCalls'):
            for i in range(self._fd.numCalls()):
                fc = self._fd.getCallSpecs(i)
                if fc is not None and hasattr(fc, 'abortSpacebaseRelative'):
                    fc.abortSpacebaseRelative(self._fd)
        info.hasCallPlaceholders = False

    def processJoins(self) -> None:
        """Split join-space Varnodes into their real components.

        Any free Varnode in join-space is split into its real register pieces
        using PIECE ops. Written join-space Varnodes are split via SUBPIECE.
        This ensures join-space addresses play no role in the heritage process.

        C++ ref: ``Heritage::processJoins``
        """
        arch = self._fd.getArch() if hasattr(self._fd, 'getArch') else None
        if arch is None:
            return
        joinspace = arch.getJoinSpace() if hasattr(arch, 'getJoinSpace') else None
        if joinspace is None:
            return
        if not hasattr(self._fd, 'beginLoc'):
            return
        # Collect varnodes in join-space
        vnlist = []
        for vn in list(self._fd.beginLoc(joinspace)) if hasattr(self._fd, 'beginLoc') else []:
            if vn.getSpace() is not joinspace:
                break
            vnlist.append(vn)
        for vn in vnlist:
            if not hasattr(arch, 'findJoin'):
                continue
            joinrec = arch.findJoin(vn.getOffset())
            if joinrec is None:
                continue
            piecespace = joinrec.getPiece(0).space if hasattr(joinrec, 'getPiece') else None
            if hasattr(joinrec, 'getUnified'):
                unified = joinrec.getUnified()
                if unified.size != vn.getSize():
                    raise Exception("Joined varnode does not match size of record")
            if vn.isFree():
                if hasattr(joinrec, 'isFloatExtension') and joinrec.isFloatExtension():
                    self._floatExtensionRead(vn, joinrec)
                else:
                    self._splitJoinRead(vn, joinrec)
            info = self.getInfo(piecespace) if piecespace is not None else None
            if info is None:
                continue
            if self._pass != info.delay:
                continue
            if hasattr(joinrec, 'isFloatExtension') and joinrec.isFloatExtension():
                self._floatExtensionWrite(vn, joinrec)
            else:
                self._splitJoinWrite(vn, joinrec)

    def _splitJoinLevel(self, lastcombo: list, nextlev: list, joinrec) -> None:
        """Perform one level of Varnode splitting to match a JoinRecord.

        Split all pieces in lastcombo, putting them into nextlev in order,
        to get closer to the representation described by the JoinRecord.
        nextlev contains the two split pieces for each Varnode in lastcombo.
        If a Varnode is not split this level, an extra None is put into
        nextlev to maintain the 2-1 mapping.

        C++ ref: ``Heritage::splitJoinLevel``
        """
        numpieces = joinrec.numPieces()
        recnum = 0
        for curvn in lastcombo:
            if recnum >= numpieces:
                break
            if curvn.getSize() == joinrec.getPiece(recnum).size:
                nextlev.append(curvn)
                nextlev.append(None)
                recnum += 1
            else:
                sizeaccum = 0
                j = recnum
                while j < numpieces:
                    sizeaccum += joinrec.getPiece(j).size
                    j += 1
                    if sizeaccum == curvn.getSize():
                        break
                numinhalf = (j - recnum) // 2  # Will be at least 1
                sizeaccum = 0
                for k in range(numinhalf):
                    sizeaccum += joinrec.getPiece(recnum + k).size
                if numinhalf == 1:
                    p = joinrec.getPiece(recnum)
                    mosthalf = self._fd.newVarnode(sizeaccum, Address(p.space, p.offset))
                else:
                    mosthalf = self._fd.newUnique(sizeaccum)
                if (j - recnum) == 2:
                    vdata = joinrec.getPiece(recnum + 1)
                    leasthalf = self._fd.newVarnode(vdata.size, Address(vdata.space, vdata.offset))
                else:
                    leasthalf = self._fd.newUnique(curvn.getSize() - sizeaccum)
                nextlev.append(mosthalf)
                nextlev.append(leasthalf)
                recnum = j

    def _splitJoinRead(self, vn, joinrec) -> None:
        """Construct pieces for a join-space Varnode read by an operation.

        Given a splitting specification (JoinRecord) and a Varnode, build a
        concatenation expression (out of PIECE operations) that constructs
        the Varnode out of the specified Varnode pieces.

        C++ ref: ``Heritage::splitJoinRead``
        """
        if not hasattr(joinrec, 'numPieces'):
            return
        op = vn.loneDescend() if hasattr(vn, 'loneDescend') else None
        if op is None:
            return
        isPrimitive = True
        if vn.isTypeLock() and hasattr(vn, 'getType') and vn.getType() is not None:
            if hasattr(vn.getType(), 'isPrimitiveWhole'):
                isPrimitive = vn.getType().isPrimitiveWhole()

        lastcombo = [vn]
        while len(lastcombo) < joinrec.numPieces():
            nextlev = []
            self._splitJoinLevel(lastcombo, nextlev, joinrec)
            for i in range(len(lastcombo)):
                curvn = lastcombo[i]
                mosthalf = nextlev[2 * i]
                leasthalf = nextlev[2 * i + 1]
                if leasthalf is None:
                    continue  # Varnode didn't get split this level
                concat = self._fd.newOp(2, op.getAddr())
                self._fd.opSetOpcode(concat, OpCode.CPUI_PIECE)
                self._fd.opSetOutput(concat, curvn)
                self._fd.opSetInput(concat, mosthalf, 0)
                self._fd.opSetInput(concat, leasthalf, 1)
                self._fd.opInsertBefore(concat, op)
                if isPrimitive:
                    if hasattr(mosthalf, 'setPrecisHi'):
                        mosthalf.setPrecisHi()
                    if hasattr(leasthalf, 'setPrecisLo'):
                        leasthalf.setPrecisLo()
                else:
                    if hasattr(self._fd, 'opMarkNoCollapse'):
                        self._fd.opMarkNoCollapse(concat)
                op = concat  # Keep op as earliest in concatenation construction
            lastcombo = [v for v in nextlev if v is not None]

    def _splitJoinWrite(self, vn, joinrec) -> None:
        """Split a written join-space Varnode into specified pieces.

        Given a splitting specification (JoinRecord) and a Varnode, build a
        series of expressions that construct the specified Varnode pieces
        using SUBPIECE ops.

        C++ ref: ``Heritage::splitJoinWrite``
        """
        if not hasattr(joinrec, 'numPieces'):
            return
        op = vn.getDef() if vn.isWritten() else None
        bb = self._fd.getBasicBlocks().getBlock(0) if hasattr(self._fd, 'getBasicBlocks') else None
        isPrimitive = True
        if vn.isTypeLock() and hasattr(vn, 'getType') and vn.getType() is not None:
            if hasattr(vn.getType(), 'isPrimitiveWhole'):
                isPrimitive = vn.getType().isPrimitiveWhole()

        lastcombo = [vn]
        while len(lastcombo) < joinrec.numPieces():
            nextlev = []
            self._splitJoinLevel(lastcombo, nextlev, joinrec)
            for i in range(len(lastcombo)):
                curvn = lastcombo[i]
                mosthalf = nextlev[2 * i]
                leasthalf = nextlev[2 * i + 1]
                if leasthalf is None:
                    continue  # Varnode didn't get split this level
                # SUBPIECE for most-significant half
                if vn.isInput() and bb is not None:
                    split = self._fd.newOp(2, bb.getStart())
                elif op is not None:
                    split = self._fd.newOp(2, op.getAddr())
                else:
                    continue
                self._fd.opSetOpcode(split, OpCode.CPUI_SUBPIECE)
                self._fd.opSetOutput(split, mosthalf)
                self._fd.opSetInput(split, curvn, 0)
                self._fd.opSetInput(split, self._fd.newConstant(4, leasthalf.getSize()), 1)
                if op is None and bb is not None:
                    self._fd.opInsertBegin(split, bb)
                else:
                    self._fd.opInsertAfter(split, op)
                op = split  # Keep op as latest in split construction
                # SUBPIECE for least-significant half
                split2 = self._fd.newOp(2, op.getAddr())
                self._fd.opSetOpcode(split2, OpCode.CPUI_SUBPIECE)
                self._fd.opSetOutput(split2, leasthalf)
                self._fd.opSetInput(split2, curvn, 0)
                self._fd.opSetInput(split2, self._fd.newConstant(4, 0), 1)
                self._fd.opInsertAfter(split2, op)
                if isPrimitive:
                    if hasattr(mosthalf, 'setPrecisHi'):
                        mosthalf.setPrecisHi()
                    if hasattr(leasthalf, 'setPrecisLo'):
                        leasthalf.setPrecisLo()
                op = split2  # Keep op as latest in split construction
            lastcombo = [v for v in nextlev if v is not None]

    def _floatExtensionRead(self, vn, joinrec) -> None:
        """Create float truncation into a free lower precision join-space Varnode.

        Given a Varnode with logically lower precision, as given by a float
        extension record (JoinRecord), create the real full-precision Varnode
        and define the lower precision Varnode as a truncation (FLOAT2FLOAT).

        C++ ref: ``Heritage::floatExtensionRead``
        """
        op = vn.loneDescend() if hasattr(vn, 'loneDescend') else None
        if op is None:
            return
        trunc = self._fd.newOp(1, op.getAddr())
        vdata = joinrec.getPiece(0)  # Float extensions have exactly 1 piece
        bigvn = self._fd.newVarnode(vdata.size, Address(vdata.space, vdata.offset))
        self._fd.opSetOpcode(trunc, OpCode.CPUI_FLOAT_FLOAT2FLOAT)
        self._fd.opSetOutput(trunc, vn)
        self._fd.opSetInput(trunc, bigvn, 0)
        self._fd.opInsertBefore(trunc, op)

    def _floatExtensionWrite(self, vn, joinrec) -> None:
        """Create float extension from a lower precision join-space Varnode.

        Given a Varnode with logically lower precision, as given by a float
        extension record (JoinRecord), create the full precision Varnode
        specified by the record, making it defined by an extension (FLOAT2FLOAT).

        C++ ref: ``Heritage::floatExtensionWrite``
        """
        op = vn.getDef() if vn.isWritten() else None
        bb = self._fd.getBasicBlocks().getBlock(0)
        if vn.isInput():
            ext = self._fd.newOp(1, bb.getStart())
        elif op is not None:
            ext = self._fd.newOp(1, op.getAddr())
        else:
            return
        vdata = joinrec.getPiece(0)  # Float extensions have exactly 1 piece
        self._fd.opSetOpcode(ext, OpCode.CPUI_FLOAT_FLOAT2FLOAT)
        self._fd.newVarnodeOut(vdata.size, Address(vdata.space, vdata.offset), ext)
        self._fd.opSetInput(ext, vn, 0)
        if op is None:
            self._fd.opInsertBegin(ext, bb)
        else:
            self._fd.opInsertAfter(ext, op)

    def generateLoadGuard(self, node, op, spc: AddrSpace) -> None:
        """Generate a guard record given an indexed LOAD into a stack space."""
        if hasattr(op, 'usesSpacebasePtr') and not op.usesSpacebasePtr():
            guard = LoadGuard()
            guard.set(op, spc, node.get('offset', 0) if isinstance(node, dict) else 0)
            self._loadGuard.append(guard)
            if hasattr(self._fd, 'opMarkSpacebasePtr'):
                self._fd.opMarkSpacebasePtr(op)

    def generateStoreGuard(self, node, op, spc: AddrSpace) -> None:
        """Generate a guard record given an indexed STORE to a stack space."""
        if hasattr(op, 'usesSpacebasePtr') and not op.usesSpacebasePtr():
            guard = LoadGuard()
            guard.set(op, spc, node.get('offset', 0) if isinstance(node, dict) else 0)
            self._storeGuard.append(guard)
            if hasattr(self._fd, 'opMarkSpacebasePtr'):
                self._fd.opMarkSpacebasePtr(op)

    def protectFreeStores(self, spc: AddrSpace, freeStores: list) -> bool:
        """Identify any STORE ops that use a free pointer from a given address space.

        Walk through all STORE ops. For each, trace the pointer input back
        through COPYs and constant INT_ADDs. If the base pointer is free and
        lives in the given space, mark the STORE as spacebase and add it to
        the freeStores list.

        C++ ref: ``Heritage::protectFreeStores``
        """
        if not hasattr(self._fd, 'beginOp'):
            return False
        hasNew = False
        for op in self._fd.beginOp(OpCode.CPUI_STORE):
            if hasattr(op, 'isDead') and op.isDead():
                continue
            vn = op.getIn(1)
            while vn.isWritten():
                defOp = vn.getDef()
                opc = defOp.code()
                if opc == OpCode.CPUI_COPY:
                    vn = defOp.getIn(0)
                elif opc == OpCode.CPUI_INT_ADD and defOp.getIn(1).isConstant():
                    vn = defOp.getIn(0)
                else:
                    break
            if vn.isFree() and vn.getSpace() is spc:
                if hasattr(self._fd, 'opMarkSpacebasePtr'):
                    self._fd.opMarkSpacebasePtr(op)
                freeStores.append(op)
                hasNew = True
        return hasNew

    def discoverIndexedStackPointers(self, spc: AddrSpace, freeStores: list, checkFreeStores: bool) -> bool:
        """Trace input stack-pointer to any indexed loads.

        Follow the stack pointer input through INT_ADD, COPY, INDIRECT,
        MULTIEQUAL ops. When a LOAD or STORE is reached through a path
        containing a non-constant index or MULTIEQUAL, generate a load/store
        guard. If unknown stack storage is detected and checkFreeStores is
        True, also protect free stores.

        C++ ref: ``Heritage::discoverIndexedStackPointers``
        """
        if not hasattr(spc, 'numSpacebase') or spc.numSpacebase() == 0:
            return False
        if not hasattr(self._fd, 'findVarnodeInput'):
            return False

        NONCONSTANT_INDEX = 1
        MULTIEQUAL_FLAG = 2
        markedVn = []
        unknownStackStorage = False

        for i in range(spc.numSpacebase()):
            stackPointer = spc.getSpacebase(i)
            spInput = self._fd.findVarnodeInput(stackPointer.size, Address(stackPointer.space, stackPointer.offset))
            if spInput is None:
                continue
            # DFS path: (varnode, offset, traversals, descend_iter)
            descends = list(spInput.getDescend()) if hasattr(spInput, 'getDescend') else []
            path = [(spInput, 0, 0, iter(descends))]
            while path:
                curVn, curOffset, curTraversals, curIter = path[-1]
                try:
                    op = next(curIter)
                except StopIteration:
                    path.pop()
                    continue
                outVn = op.getOut()
                if outVn is not None and hasattr(outVn, 'isMark') and outVn.isMark():
                    continue
                opc = op.code()
                if opc == OpCode.CPUI_INT_ADD:
                    otherSlot = 1 - op.getSlot(curVn) if hasattr(op, 'getSlot') else 1
                    otherVn = op.getIn(otherSlot)
                    if otherVn.isConstant():
                        newOffset = (curOffset + otherVn.getOffset()) & calc_mask(spc.getAddrSize()) if hasattr(spc, 'getAddrSize') else curOffset + otherVn.getOffset()
                        newDescends = list(outVn.getDescend()) if hasattr(outVn, 'getDescend') else []
                        if newDescends:
                            if hasattr(outVn, 'setMark'):
                                outVn.setMark()
                            markedVn.append(outVn)
                            path.append((outVn, newOffset, curTraversals, iter(newDescends)))
                        elif hasattr(outVn, 'getSpace') and outVn.getSpace() is not None and outVn.getSpace().getType() == IPTR_SPACEBASE:
                            unknownStackStorage = True
                    else:
                        newDescends = list(outVn.getDescend()) if hasattr(outVn, 'getDescend') else []
                        if newDescends:
                            if hasattr(outVn, 'setMark'):
                                outVn.setMark()
                            markedVn.append(outVn)
                            path.append((outVn, curOffset, curTraversals | NONCONSTANT_INDEX, iter(newDescends)))
                        elif hasattr(outVn, 'getSpace') and outVn.getSpace() is not None and outVn.getSpace().getType() == IPTR_SPACEBASE:
                            unknownStackStorage = True
                elif opc in (OpCode.CPUI_COPY, OpCode.CPUI_INDIRECT):
                    if outVn is not None:
                        newDescends = list(outVn.getDescend()) if hasattr(outVn, 'getDescend') else []
                        if newDescends:
                            if hasattr(outVn, 'setMark'):
                                outVn.setMark()
                            markedVn.append(outVn)
                            path.append((outVn, curOffset, curTraversals, iter(newDescends)))
                        elif hasattr(outVn, 'getSpace') and outVn.getSpace() is not None and outVn.getSpace().getType() == IPTR_SPACEBASE:
                            unknownStackStorage = True
                elif opc == OpCode.CPUI_MULTIEQUAL:
                    if outVn is not None:
                        newDescends = list(outVn.getDescend()) if hasattr(outVn, 'getDescend') else []
                        if newDescends:
                            if hasattr(outVn, 'setMark'):
                                outVn.setMark()
                            markedVn.append(outVn)
                            path.append((outVn, curOffset, curTraversals | MULTIEQUAL_FLAG, iter(newDescends)))
                        elif hasattr(outVn, 'getSpace') and outVn.getSpace() is not None and outVn.getSpace().getType() == IPTR_SPACEBASE:
                            unknownStackStorage = True
                elif opc == OpCode.CPUI_LOAD:
                    if curTraversals != 0:
                        self.generateLoadGuard({'offset': curOffset}, op, spc)
                elif opc == OpCode.CPUI_STORE:
                    if op.getIn(1) is curVn:
                        if curTraversals != 0:
                            self.generateStoreGuard({'offset': curOffset}, op, spc)
                        else:
                            if hasattr(self._fd, 'opMarkSpacebasePtr'):
                                self._fd.opMarkSpacebasePtr(op)

        for vn in markedVn:
            if hasattr(vn, 'clearMark'):
                vn.clearMark()
        if unknownStackStorage and checkFreeStores:
            return self.protectFreeStores(spc, freeStores)
        return False

    def reprocessFreeStores(self, spc: AddrSpace, freeStores: list) -> None:
        """Revisit STOREs with free pointers now that a heritage pass has completed.

        Regenerate STORE LoadGuard records then cross-reference with STOREs that were
        originally free to see if they actually needed a LoadGuard. If not, the STORE
        is unmarked and INDIRECTs it has caused are removed.

        C++ ref: ``Heritage::reprocessFreeStores``
        """
        if self._fd is None:
            return
        # Clear spacebase ptr marks on all free stores
        for op in freeStores:
            if hasattr(self._fd, 'opClearSpacebasePtr'):
                self._fd.opClearSpacebasePtr(op)
        # Re-discover indexed stack pointers
        self.discoverIndexedStackPointers(spc, freeStores, False)
        # For each store that is no longer marked, remove unnecessary INDIRECTs
        for op in freeStores:
            if hasattr(op, 'usesSpacebasePtr') and op.usesSpacebasePtr():
                continue  # Appropriately marked
            # Walk backwards through INDIRECTs inserted just before this STORE
            indOp = op.previousOp() if hasattr(op, 'previousOp') else None
            while indOp is not None:
                if indOp.code() != OpCode.CPUI_INDIRECT:
                    break
                iopVn = indOp.getIn(1)
                if not hasattr(iopVn, 'getSpace') or iopVn.getSpace() is None:
                    break
                from ghidra.core.space import IPTR_IOP
                if iopVn.getSpace().getType() != IPTR_IOP:
                    break
                from ghidra.ir.op import PcodeOp
                if hasattr(PcodeOp, 'getOpFromConst'):
                    if op is not PcodeOp.getOpFromConst(iopVn.getAddr()):
                        break
                nextOp = indOp.previousOp() if hasattr(indOp, 'previousOp') else None
                if indOp.getOut().getSpace() is spc:
                    self._fd.totalReplace(indOp.getOut(), indOp.getIn(0))
                    self._fd.opDestroy(indOp)
                indOp = nextOp

    def findAddressForces(self, copySinks: list, forces: list) -> None:
        """Find PcodeOps that define values flowing to address-forced sinks.

        Walk backwards from COPY sinks through artificial ops (COPY, MULTIEQUAL,
        INDIRECT-store) that preserve the address. Non-artificial ops that define
        values reaching the sinks are collected as 'forces'.

        C++ ref: ``Heritage::findAddressForces``
        """
        # Mark the sinks
        for op in copySinks:
            if hasattr(op, 'setMark'):
                op.setMark()
        # BFS backwards from sinks
        pos = 0
        while pos < len(copySinks):
            op = copySinks[pos]
            addr = op.getOut().getAddr()
            pos += 1
            maxIn = op.numInput()
            for i in range(maxIn):
                vn = op.getIn(i)
                if not vn.isWritten():
                    continue
                if hasattr(vn, 'isAddrForce') and vn.isAddrForce():
                    continue  # Already address forced
                newOp = vn.getDef()
                if hasattr(newOp, 'isMark') and newOp.isMark():
                    continue  # Already visited
                if hasattr(newOp, 'setMark'):
                    newOp.setMark()
                opc = newOp.code()
                isArtificial = False
                if opc == OpCode.CPUI_COPY or opc == OpCode.CPUI_MULTIEQUAL:
                    isArtificial = True
                    for j in range(newOp.numInput()):
                        inVn = newOp.getIn(j)
                        if addr != inVn.getAddr():
                            isArtificial = False
                            break
                elif opc == OpCode.CPUI_INDIRECT and (hasattr(newOp, 'isIndirectStore') and newOp.isIndirectStore()):
                    inVn = newOp.getIn(0)
                    if addr == inVn.getAddr():
                        isArtificial = True
                if isArtificial:
                    copySinks.append(newOp)
                else:
                    forces.append(newOp)

    def propagateCopyAway(self, op) -> None:
        """Eliminate a COPY sink preserving its data-flow."""
        if hasattr(self._fd, 'totalReplace') and hasattr(self._fd, 'opDestroy'):
            inVn = op.getIn(0)
            while inVn.isWritten():
                nextOp = inVn.getDef()
                if nextOp.code() != OpCode.CPUI_COPY:
                    break
                nextIn = nextOp.getIn(0)
                if nextIn.getAddr() != inVn.getAddr():
                    break
                inVn = nextIn
            self._fd.totalReplace(op.getOut(), inVn)
            self._fd.opDestroy(op)

    def handleNewLoadCopies(self) -> None:
        """Mark the boundary of artificial ops introduced by load guards.

        After renaming, run through all new COPY sinks from load guards and mark
        boundary Varnodes (whose data-flow along all paths traverses only
        COPY/INDIRECT/MULTIEQUAL ops and hits a load guard). Then eliminate the
        original COPY sinks.

        C++ ref: ``Heritage::handleNewLoadCopies``
        """
        if not self._loadCopyOps:
            return
        forces = []
        copySinkSize = len(self._loadCopyOps)
        self.findAddressForces(self._loadCopyOps, forces)
        if forces:
            # Build range list from load guards
            loadRanges = None
            try:
                from ghidra.core.rangelist import RangeList
                loadRanges = RangeList()
                for guard in self._loadGuard:
                    loadRanges.insertRange(guard.spc, guard.minimumOffset, guard.maximumOffset)
            except (ImportError, AttributeError):
                loadRanges = None
            # Mark boundary ops as address forced
            for op in forces:
                vn = op.getOut()
                if loadRanges is not None and hasattr(loadRanges, 'inRange'):
                    if loadRanges.inRange(vn.getAddr(), 1):
                        vn.setAddrForce()
                if hasattr(op, 'clearMark'):
                    op.clearMark()
        # Eliminate original COPY sinks
        for i in range(copySinkSize):
            op = self._loadCopyOps[i]
            self.propagateCopyAway(op)
        # Clear marks on remaining artificial COPYs
        for i in range(copySinkSize, len(self._loadCopyOps)):
            op = self._loadCopyOps[i]
            if hasattr(op, 'clearMark'):
                op.clearMark()
        self._loadCopyOps.clear()

    def analyzeNewLoadGuards(self) -> None:
        """Make final determination of what range new LoadGuards are protecting.

        Walk backwards through unanalyzed load and store guards. If a
        ValueSetSolver is available, use it to narrow the guarded ranges.
        Otherwise, mark all unanalyzed guards as having full range.

        C++ ref: ``Heritage::analyzeNewLoadGuards``
        """
        nothingToDo = True
        if self._loadGuard and hasattr(self._loadGuard[-1], 'analysisState'):
            if self._loadGuard[-1].analysisState == 0:
                nothingToDo = False
        if self._storeGuard and hasattr(self._storeGuard[-1], 'analysisState'):
            if self._storeGuard[-1].analysisState == 0:
                nothingToDo = False
        if nothingToDo:
            return
        # Collect unanalyzed guards from the back
        loadStart = len(self._loadGuard)
        for i in range(len(self._loadGuard) - 1, -1, -1):
            guard = self._loadGuard[i]
            if hasattr(guard, 'analysisState') and guard.analysisState != 0:
                break
            loadStart = i
        storeStart = len(self._storeGuard)
        for i in range(len(self._storeGuard) - 1, -1, -1):
            guard = self._storeGuard[i]
            if hasattr(guard, 'analysisState') and guard.analysisState != 0:
                break
            storeStart = i
        # Without ValueSetSolver, just finalize all unanalyzed guards with full range
        for i in range(loadStart, len(self._loadGuard)):
            guard = self._loadGuard[i]
            if hasattr(guard, 'analysisState'):
                if guard.analysisState == 0:
                    guard.analysisState = 2  # Mark as finalized (full range)
        for i in range(storeStart, len(self._storeGuard)):
            guard = self._storeGuard[i]
            if hasattr(guard, 'analysisState'):
                if guard.analysisState == 0:
                    guard.analysisState = 2  # Mark as finalized (full range)

    # ----------------------------------------------------------------
    # ADT and phi-node placement
    # ----------------------------------------------------------------

    def buildADT(self) -> None:
        """Build the augmented dominator tree (Bilardi-Pingali algorithm).

        Assumes the dominator tree is already built. Computes the augment
        array which stores, for each block, the list of blocks in its
        dominance frontier that need phi-nodes. Also computes boundary
        nodes to limit the recursive walk during phi-node placement.
        """
        graph = self._fd.getBasicBlocks()
        size = graph.getSize()
        if size == 0:
            return

        # Step 1: Build dominator tree
        self._buildDominatorTree()

        # Build domchild from the dominator tree
        self._domchild = [[] for _ in range(size)]
        for i in range(size):
            bl = graph.getBlock(i)
            idom = bl.getImmedDom() if hasattr(bl, 'getImmedDom') else None
            if idom is not None:
                pidx = idom.getIndex()
                if 0 <= pidx < size:
                    self._domchild[pidx].append(bl)

        # Compute depth via BFS from root
        self._depth = [0] * size
        self._maxdepth = 0
        stack = [(0, 0)]
        while stack:
            idx, d = stack.pop()
            self._depth[idx] = d
            if d > self._maxdepth:
                self._maxdepth = d
            for child in self._domchild[idx]:
                stack.append((child.getIndex(), d + 1))

        # Step 2: Initialize augment and flags
        self._augment = [[] for _ in range(size)]
        self._flags = [0] * size

        # Step 3: Find up-edges and compute boundary nodes
        a = [0] * size
        b = [0] * size
        t = [0] * size
        z = [0] * size
        upstart = []
        upend = []

        for i in range(size):
            x = graph.getBlock(i)
            for child in self._domchild[i]:
                for k in range(child.sizeIn()):
                    u = child.getIn(k)
                    idom = child.getImmedDom() if hasattr(child, 'getImmedDom') else None
                    if u is not idom:  # u->child is an up-edge
                        upstart.append(u)
                        upend.append(child)
                        b[u.getIndex()] += 1
                        t[x.getIndex()] += 1

        # Bottom-up pass to determine boundary nodes
        for i in range(size - 1, -1, -1):
            k_sum = 0
            l_sum = 0
            for child in self._domchild[i]:
                cidx = child.getIndex()
                k_sum += a[cidx]
                l_sum += z[cidx]
            a[i] = b[i] - t[i] + k_sum
            z[i] = 1 + l_sum
            if len(self._domchild[i]) == 0 or z[i] > a[i] + 1:
                self._flags[i] |= Heritage.boundary_node
                z[i] = 1

        # Compute z[] for path compression
        z[0] = -1
        for i in range(1, size):
            bl = graph.getBlock(i)
            idom = bl.getImmedDom() if hasattr(bl, 'getImmedDom') else None
            if idom is not None:
                j = idom.getIndex()
                if (self._flags[j] & Heritage.boundary_node) != 0:
                    z[i] = j
                else:
                    z[i] = z[j]

        # Build the augment array from up-edges
        for i in range(len(upstart)):
            v = upend[i]
            idom = v.getImmedDom() if hasattr(v, 'getImmedDom') else None
            j = idom.getIndex() if idom is not None else 0
            k = upstart[i].getIndex()
            while j < k:  # while idom(v) properly dominates u
                self._augment[k].append(v)
                k = z[k]

        # Sort each augment list by idom index ascending.
        # C++ visitIncr uses `break` when idom(v).index >= j, which assumes
        # augment entries are sorted by idom index.  In C++ this is guaranteed
        # by DFS block ordering; Python block indices may differ, so we must
        # sort explicitly.
        for lst in self._augment:
            if len(lst) > 1:
                lst.sort(key=lambda v: v.getImmedDom().getIndex()
                         if v.getImmedDom() is not None else 0)

    def visitIncr(self, qnode, vnode) -> None:
        """The heart of the phi-node placement algorithm."""
        i = vnode.getIndex()
        j = qnode.getIndex()
        if i >= len(self._augment):
            return
        for v in self._augment[i]:
            if v.getImmedDom() is not None and v.getImmedDom().getIndex() < j:
                k = v.getIndex()
                if k < len(self._flags):
                    if (self._flags[k] & Heritage.merged_node) == 0:
                        self._merge.append(v)
                        self._flags[k] |= Heritage.merged_node
                    if (self._flags[k] & Heritage.mark_node) == 0:
                        self._flags[k] |= Heritage.mark_node
                        self._pq.insert(v, self._depth[k] if k < len(self._depth) else 0)
            else:
                break
        if i < len(self._flags) and (self._flags[i] & Heritage.boundary_node) == 0:
            children = self._domchild[i] if i < len(self._domchild) else []
            for child in children:
                cidx = child.getIndex()
                if cidx < len(self._flags) and (self._flags[cidx] & Heritage.mark_node) == 0:
                    self.visitIncr(qnode, child)

    def calcMultiequals(self, write: list) -> None:
        """Calculate blocks that should contain MULTIEQUALs for one address range."""
        self._pq.reset(self._maxdepth if self._maxdepth >= 0 else 0)
        self._merge.clear()
        graph = self._fd.getBasicBlocks()
        for vn in write:
            if vn.getDef() is None:
                continue
            bl = vn.getDef().getParent()
            if bl is None:
                continue
            j = bl.getIndex()
            if j < len(self._flags) and (self._flags[j] & Heritage.mark_node) != 0:
                continue
            self._pq.insert(bl, self._depth[j] if j < len(self._depth) else 0)
            if j < len(self._flags):
                self._flags[j] |= Heritage.mark_node
        # Make sure start node is in input
        if 0 < len(self._flags) and (self._flags[0] & Heritage.mark_node) == 0:
            self._pq.insert(graph.getBlock(0), self._depth[0] if self._depth else 0)
            self._flags[0] |= Heritage.mark_node
        while not self._pq.empty():
            bl = self._pq.extract()
            self.visitIncr(bl, bl)
        for i in range(len(self._flags)):
            self._flags[i] &= ~(Heritage.mark_node | Heritage.merged_node)

    def placeMultiequals(self) -> None:
        """Perform phi-node placement for the current set of address ranges."""
        # Sort ranges by address to match C++ sorted-map iteration order.
        # This ensures INDIRECTs at call sites are created in address order.
        self._disjoint.sort()
        readvars: list = []
        writevars: list = []
        inputvars: list = []
        removevars: list = []
        # Build sorted-by-offset index for collect() binary search (one build, N binary searches)
        # Format: {spc_id: (sorted_offsets_list, sorted_entries_list)} for Python 3.9 compatible bisect
        _sorted_idx: dict = {}
        if self._fd is not None:
            vbank = self._fd._vbank
            for spc_id, vn_set in vbank._space_varnodes.items():
                entries = [(vn._loc.offset, vn._size, vn) for vn in vn_set]
                if entries:
                    entries.sort(key=lambda x: (x[0], x[1]))
                    sorted_offsets = [e[0] for e in entries]
                    _sorted_idx[spc_id] = (sorted_offsets, entries)
        # Use index-based iteration because refinement can modify the list
        idx = 0
        while idx < len(self._disjoint):
            memrange = self._disjoint[idx]
            maxsize = self.collect(memrange, readvars, writevars, inputvars, removevars, _sorted_idx)
            size = memrange.size
            # C++ refinement: split large ranges into sub-ranges (heritage.cc placeMultiequals)
            if size > 4 and maxsize < size:
                ref_idx = self.refinement(idx, readvars, writevars, inputvars)
                if ref_idx >= 0:
                    idx = ref_idx
                    memrange = self._disjoint[idx]
                    self.collect(memrange, readvars, writevars, inputvars, removevars, _sorted_idx)
                    size = memrange.size
            if not readvars:
                if not writevars and not inputvars:
                    idx += 1
                    continue
                if memrange.addr.getSpace().getType() == IPTR_INTERNAL or memrange.oldAddresses():
                    idx += 1
                    continue
            if removevars:
                self.removeRevisitedMarkers(removevars, memrange.addr, size)
            self.guardInput(memrange.addr, size, inputvars)
            self.guard(memrange.addr, size, memrange.newAddresses(), readvars, writevars, inputvars)
            self.calcMultiequals(writevars)
            for bl in self._merge:
                numinputs = bl.sizeIn()
                multiop = self._fd.newOp(numinputs, bl.getStart())
                vnout = self._fd.newVarnodeOut(size, memrange.addr, multiop)
                vnout.setActiveHeritage()
                self._fd.opSetOpcode(multiop, OpCode.CPUI_MULTIEQUAL)
                for j in range(numinputs):
                    vnin = self._fd.newVarnode(size, memrange.addr)
                    self._fd.opSetInput(multiop, vnin, j)
                self._fd.opInsertBegin(multiop, bl)
            idx += 1
        self._merge.clear()

    def rename(self) -> None:
        """Perform the renaming algorithm for the current set of address ranges."""
        varstack: Dict[Address, List] = defaultdict(list)
        entry = self._fd.getBasicBlocks().getBlock(0)
        if entry is not None:
            self.renameRecurse(entry, varstack)
        self._disjoint.clear()

    def renameRecurse(self, bl, varstack: dict) -> None:
        """The heart of the renaming algorithm.

        From the given block, recursively walk the dominance tree. At each
        block, visit PcodeOps in execution order looking for Varnodes that
        need to be renamed.
        """
        writelist = []
        ops = list(bl.getOpList())

        for op in ops:
            if op.code() != OpCode.CPUI_MULTIEQUAL:
                for slot, vnin in enumerate(op._inrefs):
                    if vnin is None or vnin.isHeritageKnown():
                        continue
                    if not vnin.isActiveHeritage():
                        continue
                    vnin.clearActiveHeritage()
                    addr_key = vnin.getAddr()
                    stack = varstack[addr_key]
                    if not stack:
                        vnnew = self._fd.newVarnode(vnin.getSize(), vnin.getAddr())
                        vnnew = self._fd.setInputVarnode(vnnew)
                        stack.append(vnnew)
                    else:
                        vnnew = stack[-1]
                    # Check for INDIRECT at-same-time issue
                    if vnnew.isWritten() and vnnew.getDef().code() == OpCode.CPUI_INDIRECT:
                        from ghidra.ir.op import PcodeOp as PcodeOpCls
                        iop_addr = vnnew.getDef()._inrefs[1].getAddr()
                        if PcodeOpCls.getOpFromConst(iop_addr) is op:
                            if len(stack) == 1:
                                vnnew2 = self._fd.newVarnode(vnin.getSize(), vnin.getAddr())
                                vnnew2 = self._fd.setInputVarnode(vnnew2)
                                stack.insert(0, vnnew2)
                                vnnew = vnnew2
                            else:
                                vnnew = stack[-2]
                    self._fd.opSetInput(op, vnnew, slot)
                    if vnin.hasNoDescend():
                        self._fd.deleteVarnode(vnin)
            # Push writes onto stack
            vnout = op.getOut()
            if vnout is None:
                continue
            if not vnout.isActiveHeritage():
                continue
            vnout.clearActiveHeritage()
            varstack[vnout.getAddr()].append(vnout)
            writelist.append(vnout)

        # Process MULTIEQUAL inputs in successor blocks
        for i in range(bl.sizeOut()):
            subbl = bl.getOut(i)
            slot = bl.getOutRevIndex(i)
            for multiop in subbl.getOpList():
                if multiop.code() != OpCode.CPUI_MULTIEQUAL:
                    break
                inrefs = multiop._inrefs
                if slot >= len(inrefs):
                    continue
                vnin = inrefs[slot]
                if vnin.isHeritageKnown():
                    continue
                addr_key = vnin.getAddr()
                stack = varstack[addr_key]
                if not stack:
                    vnnew = self._fd.newVarnode(vnin.getSize(), vnin.getAddr())
                    vnnew = self._fd.setInputVarnode(vnnew)
                    stack.append(vnnew)
                else:
                    vnnew = stack[-1]
                self._fd.opSetInput(multiop, vnnew, slot)
                if vnin.hasNoDescend():
                    self._fd.deleteVarnode(vnin)

        # Recurse to dominator tree children
        bl_idx = bl.getIndex()
        children = self._domchild[bl_idx] if bl_idx < len(self._domchild) else []
        for child in children:
            self.renameRecurse(child, varstack)

        # Pop this block's writes off the stack
        for vnout in writelist:
            addr_key = vnout.getAddr()
            if varstack[addr_key]:
                varstack[addr_key].pop()

    # ----------------------------------------------------------------
    # Main heritage entry point
    # ----------------------------------------------------------------

    def heritage(self) -> None:
        """Perform one pass of heritage (SSA construction).

        From any address space that is active for this pass, free Varnodes
        are collected and then fully integrated into SSA form. Reads are
        connected to writes, inputs are identified, and phi-nodes are placed.

        C++ ref: ``Heritage::heritage``
        """
        if self._fd is None:
            return
        graph = self._fd.getBasicBlocks()
        if graph.getSize() == 0:
            return

        if self._maxdepth == -1:
            self.buildADT()

        self.processJoins()

        reprocessStackCount = 0
        stackSpace = None
        freeStores: list = []

        # For each heritaged address space
        for info in self._infolist:
            if not info.isHeritaged():
                continue
            if self._pass < info.delay:
                continue
            if info.hasCallPlaceholders:
                self.clearStackPlaceholders(info)
            if not info.loadGuardSearch:
                info.loadGuardSearch = True
                if self.discoverIndexedStackPointers(info.space, freeStores, True):
                    reprocessStackCount += 1
                    stackSpace = info.space

            needwarning = False
            warnvn = None
            # Collect free varnodes in this space — use space index to avoid full scan
            _vbank = self._fd._vbank
            _spc_bucket = _vbank._space_varnodes.get(id(info.space), ())
            _VN_WR = 0x10; _VN_IP = 0x08; _VN_UNAFF = 0x10000
            for vn in list(_spc_bucket):
                if not (vn._flags & _VN_WR) and vn.hasNoDescend() and not vn.isUnaffected() and not vn.isInput():
                    continue
                if vn.isWriteMask():
                    continue
                intersect_ref = [0]
                self._globaldisjoint.add(vn.getAddr(), vn.getSize(), self._pass, intersect_ref)
                prev = intersect_ref[0]
                if prev == 0:
                    self._disjoint.add(vn.getAddr(), vn.getSize(), MemRange.new_addresses)
                elif prev == 2:
                    if vn.isHeritageKnown():
                        continue
                    if vn.hasNoDescend():
                        continue
                    if not needwarning and info.deadremoved > 0:
                        isJumpRecov = hasattr(self._fd, 'isJumptableRecoveryOn') and self._fd.isJumptableRecoveryOn()
                        if not isJumpRecov:
                            needwarning = True
                            self.bumpDeadcodeDelay(vn.getSpace())
                            warnvn = vn
                    self._disjoint.add(vn.getAddr(), vn.getSize(), MemRange.old_addresses)
                else:
                    if not needwarning and info.deadremoved > 0:
                        isJumpRecov = hasattr(self._fd, 'isJumptableRecoveryOn') and self._fd.isJumptableRecoveryOn()
                        if not isJumpRecov:
                            if vn.isHeritageKnown():
                                continue
                            needwarning = True
                            self.bumpDeadcodeDelay(vn.getSpace())
                            warnvn = vn
                    self._disjoint.add(vn.getAddr(), vn.getSize(),
                                       MemRange.old_addresses | MemRange.new_addresses)

            if needwarning and not info.warningissued:
                info.warningissued = True
                if hasattr(self._fd, 'warningHeader') and warnvn is not None:
                    msg = f"Heritage AFTER dead removal. Example location: {warnvn}"
                    self._fd.warningHeader(msg)

        self.placeMultiequals()
        self.rename()
        if reprocessStackCount > 0 and stackSpace is not None:
            self.reprocessFreeStores(stackSpace, freeStores)
        self.analyzeNewLoadGuards()
        self.handleNewLoadCopies()
        self._pass += 1

    def clear(self) -> None:
        """Reset all analysis of heritage."""
        self._disjoint.clear()
        self._globaldisjoint.clear()
        self._domchild = []
        self._augment = []
        self._flags = []
        self._depth = []
        self._merge = []
        self.clearInfoList()
        self._loadGuard.clear()
        self._storeGuard.clear()
        self._maxdepth = -1
        self._pass = 0

    def __repr__(self) -> str:
        return f"Heritage(pass={self._pass})"
